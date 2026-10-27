"""
环境体检: `python -m guard doctor`

专门解释这一类让人抓狂的问题 —— **"日志明明打印了 http://127.0.0.1:5000 ，浏览器就是打不开"**。

常见真凶（本机实测遇到过）:
  * Windows 上同一端口允许"具体地址"和"通配地址"同时绑定, 而且 **127.0.0.1:5000 优先于 0.0.0.0:5000**。
    罗技 G HUB 的 CS_GO_Arx_Applet.exe 之类外设/游戏联动小程序就会占掉 127.0.0.1:5000，
    于是绑 0.0.0.0 的 Flask 收不到 127.0.0.1 的请求（启动不报错, 但浏览器连不上）。
  * `python web_app.py` 默认 debug=True → Werkzeug reloader 起两个进程, 容易和别的实例抢端口。
  * 系统代理指向 guard:8888 但 guard 没在运行 → 所有网页都打不开。

只读检查, 不改任何设置。
"""

import os
import socket
import subprocess

from . import VERSION

_NAME_CACHE = {}
_CREATE_NO_WINDOW = 0x08000000

WEB_PORT_DEFAULT = 5000      # eyilianjie Web (web_app.py 里 run_web 的默认端口)
PROXY_PORT_DEFAULT = 8888    # guard 代理
API_PORT_DEFAULT = 8899      # guard 控制台

OK = "[OK] "
WARN = "[! ] "
BAD = "[X ] "


# ---------------------------------------------------------------- 基础工具
def _decode(raw):
    if isinstance(raw, str):
        return raw
    for enc in ("utf-8", "gbk", "latin-1"):
        try:
            return raw.decode(enc)
        except Exception:
            continue
    return raw.decode("utf-8", "replace")


def _proc_name(pid):
    """取进程名（用 ctypes, 不额外起进程, 避免控制台闪窗和编码问题）"""
    if pid in _NAME_CACHE:
        return _NAME_CACHE[pid]
    name = "?"
    try:
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        handle = kernel32.OpenProcess(0x1000, False, int(pid))  # PROCESS_QUERY_LIMITED_INFORMATION
        if handle:
            try:
                buf = ctypes.create_unicode_buffer(1024)
                size = wintypes.DWORD(len(buf))
                if kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
                    name = os.path.basename(buf.value) or "?"
            finally:
                kernel32.CloseHandle(handle)
    except Exception:
        pass
    _NAME_CACHE[pid] = name
    return name


def listeners(port=None):
    """列出 TCP 监听项: [{'addr':.., 'port':.., 'pid':.., 'ipv6':bool}]"""
    rows = []
    for ipv6 in (False, True):
        args = ["netstat", "-ano", "-p", "tcp6" if ipv6 else "tcp"]
        try:
            out = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                 creationflags=_CREATE_NO_WINDOW).stdout
        except Exception:
            continue
        for line in _decode(out).splitlines():
            parts = line.split()
            if len(parts) < 4 or parts[0].upper() != "TCP" or parts[-2].upper() != "LISTENING":
                continue
            local = parts[1]
            if ":" not in local:
                continue
            addr, _, port_s = local.rpartition(":")
            try:
                local_port = int(port_s)
                pid = int(parts[-1])
            except ValueError:
                continue
            addr = addr.strip("[]") or "0.0.0.0"
            if port is not None and local_port != port:
                continue
            rows.append({"addr": addr, "port": local_port, "pid": pid, "ipv6": ipv6})
    return rows


def _split(rows):
    """区分 '具体地址'(127.0.0.1/::1) 与 '通配地址'(0.0.0.0/::)"""
    specific = [r for r in rows if r["addr"] in ("127.0.0.1", "::1")]
    wildcard = [r for r in rows if r["addr"] in ("0.0.0.0", "::")]
    other = [r for r in rows if r not in specific and r not in wildcard]
    return specific, wildcard, other


def http_probe(url, timeout=3.0):
    """真发一个请求, 返回 (可打开?, 说明, 内容开头)"""
    import urllib.error
    import urllib.request
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "guard-doctor/%s" % VERSION})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(200)
            head = body.decode("utf-8", "replace").replace("\n", " ").replace("\r", " ")[:60]
            return (resp.status < 500), "HTTP %s" % resp.status, head
    except urllib.error.HTTPError as exc:
        return exc.code < 500, "HTTP %s" % exc.code, ""
    except Exception as exc:
        return False, "%s: %s" % (type(exc).__name__, exc), ""


def _sysproxy():
    """读注册表里的系统代理设置（只读）"""
    info = {"ProxyEnable": 0, "ProxyServer": "", "ProxyOverride": ""}
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings") as key:
            for name in info:
                try:
                    info[name] = winreg.QueryValueEx(key, name)[0]
                except OSError:
                    pass
    except Exception:
        pass
    return info


def _lan_ip():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except Exception:
        return ""


# ---------------------------------------------------------------- 主流程
def run(settings=None, web_port=None):
    from .settings import load as load_settings
    conf = settings or load_settings()
    if web_port is None:
        try:
            web_port = int(os.environ.get("EY_PORT") or WEB_PORT_DEFAULT)
        except ValueError:
            web_port = WEB_PORT_DEFAULT
    proxy_port = int(conf.get("proxy.port", PROXY_PORT_DEFAULT) or PROXY_PORT_DEFAULT)
    api_port = int(conf.get("api.port", API_PORT_DEFAULT) or API_PORT_DEFAULT)
    guard_server = "%s:%d" % (conf.get("proxy.host", "127.0.0.1") or "127.0.0.1", proxy_port)

    problems = []
    print("=" * 78)
    print("  guard 环境体检 (v%s) —— 只读检查, 不改任何设置" % VERSION)
    print("  检查端口: eyilianjie Web %d · guard 代理 %d · guard 控制台 %d" % (web_port, proxy_port, api_port))
    print("=" * 78)

    # ---------- [1] 端口占用 ----------
    print("\n[1] 端口监听情况（同一端口上 127.0.0.1 比 0.0.0.0 优先！）")
    for port, role in ((web_port, "eyilianjie Web"), (proxy_port, "guard 代理"), (api_port, "guard 控制台")):
        rows = listeners(port)
        if not rows:
            if port == web_port:
                print("  %-9s %-14s 没有进程在监听 → Web 还没启动" % ("%d:" % port, role))
            else:
                print("  %-9s %-14s 没有进程在监听 → guard 没在运行" % ("%d:" % port, role))
            continue
        specific, wildcard, _other = _split(rows)
        print("  %-9s %-14s 共 %d 个监听 socket" % ("%d:" % port, role, len(rows)))
        for row in rows:
            print("      %-16s PID %-7d %s%s" % (row["addr"], row["pid"], _proc_name(row["pid"]),
                                                 "  (IPv6)" if row["ipv6"] else ""))
        py_wildcard = [r for r in wildcard if "python" in _proc_name(r["pid"]).lower()]
        alien_specific = [r for r in specific if "python" not in _proc_name(r["pid"]).lower()]
        if alien_specific and py_wildcard:
            for row in alien_specific:
                print("  " + BAD + "就是它！ `%s:%d` 被 %s (PID %d) 占着, 而 %s 只绑了 `%s:%d`。"
                      % (row["addr"], port, _proc_name(row["pid"]), row["pid"], role,
                         py_wildcard[0]["addr"], port))
                print("          规则: 访问 127.0.0.1 时 Windows 优先用这个具体地址 → 你的服务收不到请求")
                print("          （启动日志照样打印 http://127.0.0.1:%d, 但浏览器连不上/一直转圈）" % port)
                if port == web_port:
                    print("          解决① 结束它:   Stop-Process -Id %d -Force" % row["pid"])
                    print("          解决② 换端口:   python run_guarded.py --port 5080  (或设 EY_PORT=5080)")
            problems.append("端口 %d: 127.0.0.1 被 %s 抢占" % (port, _proc_name(alien_specific[0]["pid"])))
        wild_pids = sorted({r["pid"] for r in wildcard})
        if len(wild_pids) > 1:
            names = ", ".join("%s(%d)" % (_proc_name(p), p) for p in wild_pids)
            print("  " + WARN + "有 %d 个进程同时绑在 0.0.0.0:%d: %s" % (len(wild_pids), port, names))
            print("          重复实例（Windows 的 SO_REUSEADDR 会让它们抢同一个端口, 行为随机）")
            print("          建议只留一个: Stop-Process -Id %s" % ",".join(str(p) for p in wild_pids[1:]))
            problems.append("端口 %d: 重复实例 %s" % (port, wild_pids))
        if specific and wildcard and not alien_specific:
            print("  " + WARN + "该端口同时存在 127.0.0.1 与 0.0.0.0 监听（127.0.0.1 优先, 一般无碍）")

    # ---------- [2] 实际访问 ----------
    print("\n[2] 实际访问测试（真发 HTTP 请求）")
    web_url = "http://127.0.0.1:%d/" % web_port
    ok_web, note_web, head_web = http_probe(web_url)
    print("  %s%-30s %s" % (OK if ok_web else BAD, web_url, note_web))
    if head_web:
        print("        返回内容开头: %s" % head_web)
    if ok_web:
        print("  " + OK + "Web 界面可以打开")
    else:
        lan = _lan_ip()
        if lan:
            ok_lan, note_lan, _ = http_probe("http://%s:%d/" % (lan, web_port))
            print("  %s%-30s %s" % (OK if ok_lan else WARN, "http://%s:%d/" % (lan, web_port), note_lan))
            if ok_lan:
                print("        局域网地址能开 / 127.0.0.1 打不开 → 就是上面 [1] 里的地址抢占问题")
                print("        应急: 先用 http://%s:%d/ 打开界面" % (lan, web_port))
        problems.append("127.0.0.1:%d 无法打开" % web_port)
    api_url = "http://127.0.0.1:%d/guard/status" % api_port
    ok_api, note_api, _ = http_probe(api_url)
    print("  %s%-30s %s" % (OK if ok_api else WARN, api_url, note_api))
    if ok_api:
        print("        guard 正在运行, 控制台: http://127.0.0.1:%d/" % api_port)

    # ---------- [3] 系统代理一致性 ----------
    print("\n[3] 系统代理设置（guard 只在自己被开启时才碰它）")
    proxy = _sysproxy()
    enabled = int(proxy.get("ProxyEnable") or 0)
    server = proxy.get("ProxyServer") or ""
    print("      ProxyEnable   = %d" % enabled)
    print("      ProxyServer   = %s" % (server or "(空)"))
    print("      ProxyOverride = %s" % (proxy.get("ProxyOverride") or "(空)"))
    if enabled == 1:
        if server == guard_server:
            if ok_api:
                print("  " + OK + "系统代理指向 guard(%s) 且 guard 在运行 → 全浏览器拦截生效中" % guard_server)
            else:
                print("  " + BAD + "系统代理指向 guard(%s) 但 guard 没在运行 → 所有网页都打不开！" % guard_server)
                print("          解决: `python -m guard sysproxy off` 关掉系统代理, 或重新启动 guard")
                problems.append("系统代理指向 guard 但 guard 未运行")
        else:
            print("  " + WARN + "系统代理由其它程序管理(%s), guard 没接管 → 不影响使用" % server)
    else:
        print("  " + OK + "系统代理未启用（浏览器不会自动走 guard 代理; 要拦全部网页请在控制台点开启,"
              " 或只用油猴脚本）")

    # ---------- 结论 ----------
    print("\n" + "=" * 78)
    if problems:
        print("  结论: 发现 %d 个问题, 按上面 [X]/[!] 的建议处理" % len(problems))
        for item in problems:
            print("    - %s" % item)
    else:
        print("  结论: 一切正常 ✅")
    print("=" * 78)
    return 1 if problems else 0
