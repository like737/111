"""
本地代理拦截服务（HTTP + HTTPS/CONNECT）

工作原理:
  浏览器走系统代理(127.0.0.1:8888)后, 每个请求先经过本模块:
    * HTTP 请求: 拿到**完整 URL** → 交给判定引擎 → 命中就返回拦截页(请求不会发往目标站);
    * HTTPS 请求: 浏览器先发 CONNECT host:443 → 按**域名**判定 → 命中直接断开并返回 403
      （不需要安装任何证书; 代价是浏览器会显示它自己的错误页, 而不是我们的拦截页）。
  未命中的请求: 原样转发; 若配置了上游代理(如你自己的 127.0.0.1:10808), 则转发给它,
  这样不会顶掉你原有的科学上网工具。

设计取舍:
  * 纯标准库实现（socket/select/threading）, 不引入任何新依赖;
  * 判定异常 → 默认放行（fail-open）, 避免代理故障导致上不了网;
  * localhost/127.0.0.1 默认直连不判定, 避免代理把自己绕进去。
"""

import select
import socket
import threading
import time
from urllib.parse import urlsplit

from . import urlutil
from .blockpage import render_block_page


class ProxyServer:
    def __init__(self, engine, store, settings, api_base="http://127.0.0.1:8899", verbose=True):
        self.engine = engine
        self.store = store
        self.settings = settings
        self.api_base = api_base.rstrip("/")
        self.verbose = verbose
        self.host = str(settings.get("proxy.host", "127.0.0.1"))
        self.port = int(settings.get("proxy.port", 8888) or 8888)
        self._sock = None
        self._thread = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.stats = {"connections": 0, "blocked": 0, "tunnels": 0, "errors": 0,
                      "started_at": None}

    # ================= 生命周期 =================
    def start(self):
        """启动监听（返回 (ok, 消息)）"""
        if self.is_running():
            return True, "代理已在运行"
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind((self.host, self.port))
            self._sock.listen(128)
            self._sock.settimeout(1.0)
        except OSError as exc:
            self._sock = None
            return False, "代理端口 %s:%d 无法监听: %s" % (self.host, self.port, exc)
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="guard-proxy", daemon=True)
        self._thread.start()
        self.stats["started_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        ok, msg = self.verify()
        if ok and self.verbose:
            print("[guard] 本地代理已启动: %s:%d（把浏览器/系统代理指向它即可生效）"
                  % (self.host, self.port))
        return ok, msg

    def stop(self):
        self._stop.set()
        try:
            if self._sock:
                self._sock.close()
        except Exception:
            pass
        self._sock = None
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        return True, "代理已停止"

    def is_running(self):
        return self._sock is not None

    def verify(self):
        """自检: 端口是否真的可连"""
        try:
            probe = socket.create_connection((self.host, self.port), timeout=2)
            probe.close()
            return True, "代理端口正常 (%s:%d)" % (self.host, self.port)
        except OSError as exc:
            return False, "代理端口无法连接: %s" % exc

    def _loop(self):
        while not self._stop.is_set():
            try:
                conn, addr = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with self._lock:
                self.stats["connections"] += 1
            threading.Thread(target=self._handle, args=(conn, addr),
                             name="guard-proxy-conn", daemon=True).start()

    # ================= 单连接处理 =================
    def _handle(self, conn, addr):
        try:
            conn.settimeout(30)
            head, rest = self._read_head(conn)
            if not head:
                return
            first_line = head.split(b"\r\n", 1)[0].decode("latin-1", "replace")
            parts = first_line.split()
            if len(parts) < 2:
                return
            method, target = parts[0].upper(), parts[1]
            if method == "CONNECT":
                self._handle_connect(conn, target)
            else:
                self._handle_http(conn, method, target, head, rest)
        except Exception as exc:
            with self._lock:
                self.stats["errors"] += 1
            self._send_simple(conn, "502 Bad Gateway", "代理处理出错: %s" % exc)
        finally:
            try:
                conn.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass
            try:
                conn.close()
            except Exception:
                pass

    def _read_head(self, conn):
        """读取请求头（读到空行为止）, 返回 (头部字节, 已读到的正文字节)"""
        limit = int(self.settings.get("proxy.max_header_bytes", 65536) or 65536)
        data = b""
        while b"\r\n\r\n" not in data:
            if len(data) > limit:
                raise ValueError("请求头过长")
            chunk = conn.recv(4096)
            if not chunk:
                return (data, b"") if data else (b"", b"")
            data += chunk
        head, _, rest = data.partition(b"\r\n\r\n")
        return head + b"\r\n\r\n", rest

    # ================= HTTP =================
    def _handle_http(self, conn, method, target, head, rest):
        url = self._absolute_url(target, head)
        if not url:
            self._send_simple(conn, "400 Bad Request", "无法从请求中解析出目标地址")
            return
        host = urlutil.host_of(url)
        bypass = bool(self.settings.get("proxy.bypass_localhost", True)) \
            and urlutil.is_local_host(host)
        if bypass:
            self._forward(conn, url, head, rest)
            return

        decision = self.engine.judge(url, mode="url")
        scheme = (urlsplit(url).scheme or "http").lower()
        if decision.get("blocked"):
            self._block(conn, decision, kind="http", scheme=scheme)
            return
        self.store.count("allowed")
        if bool(self.settings.get("log.log_all_requests", False)):
            self.store.log_access(url, "allowed", reason=decision.get("reason") or "",
                                  source=decision.get("source") or "",
                                  category=decision.get("category") or "")
        self._forward(conn, url, head, rest)

    @staticmethod
    def _absolute_url(target, head):
        """把请求行里的目标还原成完整 URL（支持绝对形式与 origin 形式）"""
        if target.lower().startswith(("http://", "https://")):
            return target
        host = ""
        for line in head.split(b"\r\n")[1:]:
            if not line:
                break
            name, _, value = line.partition(b":")
            if name.strip().lower() == b"host":
                host = value.strip().decode("latin-1", "replace")
                break
        if not host:
            return ""
        path = target if target.startswith("/") else "/" + target.lstrip("/")
        return "http://%s%s" % (host, path)

    def _block(self, conn, decision, kind="http", scheme="http"):
        """命中: 返回拦截页（请求不会到达目标站点）"""
        body = render_block_page(decision, api_base=self.api_base, kind=kind).encode("utf-8")
        self._send_simple(conn, "403 Forbidden", body,
                          content_type="text/html; charset=utf-8",
                          extra=["X-Guard-Blocked: 1"])
        self.store.count("blocked", scheme=scheme)
        self.store.log_access(decision.get("url") or "", "blocked",
                              host=decision.get("host") or "",
                              reason=decision.get("reason") or "",
                              category=decision.get("category") or "",
                              source=decision.get("source") or "",
                              extra={"entry": decision.get("entry") or "",
                                     "level": decision.get("level") or "", "kind": kind})
        with self._lock:
            self.stats["blocked"] += 1
        if self.verbose:
            print("[guard] 已拦截(%s): %s  原因: %s"
                  % (kind, decision.get("url"), decision.get("reason")))

    @staticmethod
    def _send_simple(conn, status, body, content_type="text/html; charset=utf-8", extra=None):
        """返回一个完整响应（不论 body 是 str 还是 bytes）"""
        if isinstance(body, str):
            body = body.encode("utf-8")
        header_text = (body.startswith(b"<!DOCTYPE") or body.startswith(b"<"))
        if not header_text and content_type == "text/html; charset=utf-8":
            body = ("<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">"
                    "<title>guard</title></head><body style=\"font-family:Segoe UI,Microsoft YaHei;"
                    "padding:40px\"><h2>%s</h2></body></html>" % body.decode("utf-8", "replace")
                    ).encode("utf-8")
        lines = ["HTTP/1.1 %s" % status,
                 "Content-Type: %s" % content_type,
                 "Content-Length: %d" % len(body),
                 "Cache-Control: no-store, no-cache, must-revalidate, max-age=0",
                 "Pragma: no-cache",
                 "Connection: close"]
        lines.extend(extra or [])
        try:
            conn.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body)
        except Exception:
            pass

    # ================= HTTPS（CONNECT 隧道） =================
    def _handle_connect(self, conn, target):
        host, _, port_text = target.partition(":")
        host = (host or "").strip().strip("[]")
        try:
            port = int(port_text) if port_text else 443
        except ValueError:
            port = 443
        if not host:
            self._send_simple(conn, "400 Bad Request", "CONNECT 缺少目标主机")
            return
        if bool(self.settings.get("proxy.bypass_localhost", True)) and urlutil.is_local_host(host):
            self._tunnel(conn, host, port)
            return

        url = "https://%s%s/" % (host, "" if port == 443 else ":%d" % port)
        decision = self.engine.judge(url, mode="host")
        if decision.get("blocked") and bool(self.settings.get("block.block_https_tunnel", True)):
            self._block(conn, decision, kind="https", scheme="https")
            return
        self.store.count("allowed")
        if bool(self.settings.get("log.log_all_requests", False)):
            self.store.log_access(url, "allowed", host=host,
                                  reason=decision.get("reason") or "",
                                  source=decision.get("source") or "")
        self._tunnel(conn, host, port)

    def _tunnel(self, conn, host, port):
        """建立隧道（若配了上游代理则经它转发, 从而不影响你原有的科学上网）"""
        timeout = float(self.settings.get("proxy.connect_timeout", 8) or 8)
        upstream = self._upstream_for(host)
        if upstream:
            try:
                remote = socket.create_connection(upstream, timeout=timeout)
                remote.settimeout(timeout)
                remote.sendall(("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n"
                                % (host, port, host, port)).encode("latin-1"))
                upstream_head = b""
                while b"\r\n\r\n" not in upstream_head and len(upstream_head) < 65536:
                    chunk = remote.recv(4096)
                    if not chunk:
                        break
                    upstream_head += chunk
                if not upstream_head.startswith(b"HTTP/1.1 200") \
                        and not upstream_head.startswith(b"HTTP/1.0 200"):
                    conn.sendall(upstream_head or b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                    remote.close()
                    return
                remote.settimeout(None)
            except OSError as exc:
                self._send_simple(conn, "502 Bad Gateway", "上游代理不可用: %s" % exc)
                return
        else:
            try:
                remote = socket.create_connection((host, port), timeout=timeout)
                remote.settimeout(None)
            except OSError as exc:
                self._send_simple(conn, "502 Bad Gateway",
                                  "无法连接 %s:%d（%s）" % (host, port, exc))
                return
        try:
            conn.sendall(b"HTTP/1.1 200 Connection Established\r\n"
                         b"Proxy-Agent: eyilianjie-guard\r\n\r\n")
        except OSError:
            remote.close()
            return
        with self._lock:
            self.stats["tunnels"] += 1
        self._relay(conn, remote)

    # ================= 转发 =================
    def _forward(self, conn, url, head, rest):
        parts = urlsplit(url)
        host = parts.hostname or ""
        scheme = (parts.scheme or "http").lower()
        port = parts.port or (443 if scheme == "https" else 80)
        if not host:
            self._send_simple(conn, "400 Bad Request", "目标地址无效")
            return
        timeout = float(self.settings.get("proxy.connect_timeout", 8) or 8)
        upstream = self._upstream_for(host)
        try:
            if upstream:
                remote = socket.create_connection(upstream, timeout=timeout)
                remote.sendall(head + rest)          # 保持绝对 URI, 交给上游代理处理
            else:
                remote = socket.create_connection((host, port), timeout=timeout)
                remote.sendall(self._to_origin_form(head) + rest)
            remote.settimeout(None)
        except OSError as exc:
            self._send_simple(conn, "502 Bad Gateway",
                              "无法连接 %s:%d（%s）" % (host, port, exc))
            return
        self._relay(conn, remote)

    @staticmethod
    def _to_origin_form(head):
        """直连转发时: 绝对 URI 改写成 origin 形式, 并去掉 Proxy-Connection 头"""
        lines = head.split(b"\r\n")
        if lines:
            parts = lines[0].split()
            if len(parts) >= 3 and parts[1].lower().startswith((b"http://", b"https://")):
                split = urlsplit(parts[1].decode("latin-1", "replace"))
                path = split.path or "/"
                if split.query:
                    path += "?" + split.query
                parts[1] = path.encode("latin-1", "replace")
                lines[0] = b" ".join(parts)
        kept = [line for line in lines if not line.lower().startswith(b"proxy-connection:")]
        return b"\r\n".join(kept)

    def _upstream_for(self, host):
        """是否需要走上游代理（未配置则直连）"""
        upstream = str(self.settings.get("proxy.upstream_proxy", "") or "").strip()
        if not upstream:
            return None
        host = (host or "").lower()
        for item in str(self.settings.get("proxy.upstream_bypass", "") or "").split(","):
            item = item.strip().lower()
            if item and (host == item or host.endswith("." + item)):
                return None
        if ":" not in upstream:
            upstream += ":8080"
        host_part, _, port_part = upstream.rpartition(":")
        try:
            return (host_part.strip(), int(port_part))
        except ValueError:
            return None

    @staticmethod
    def _relay(client, remote):
        """双向转发直到任一端关闭"""
        socks = [client, remote]
        try:
            client.setblocking(False)
            remote.setblocking(False)
            while True:
                try:
                    readable, _, _ = select.select(socks, [], [], 300)
                except (OSError, ValueError):
                    return
                if not readable:
                    return
                for sock in list(readable):
                    other = remote if sock is client else client
                    try:
                        data = sock.recv(65536)
                    except (BlockingIOError, InterruptedError):
                        continue
                    except OSError:
                        return
                    if not data:
                        try:
                            other.shutdown(socket.SHUT_WR)
                        except Exception:
                            pass
                        socks = [item for item in socks if item is not sock]
                        if len(socks) < 2:
                            return
                        continue
                    try:
                        other.sendall(data)
                    except OSError:
                        return
        finally:
            for sock in (client, remote):
                try:
                    sock.close()
                except Exception:
                    pass

