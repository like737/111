"""
隔离自测（Phase 0 验收）—— `python -m guard selftest`

原则（对应"先测试、不要直接配到我的 eyilianjie 里"）:
  * **不**修改系统代理、**不**改 hosts、**不**写 eyilianjie 任何文件;
  * 代理/控制台使用测试端口（默认 18888/18889）, 数据写在系统临时目录, 不污染 guard/data;
  * 结束时对 eyilianjie 全部现有文件做 SHA256 前后比对, 用证据说明"零改动"。

覆盖: 判定引擎（黑名单/成人规则/可信站点/本机）、检测日志只读联动、动态集与放行名单、
     代理真实拦截（HTTP 403 + 拦截页 / HTTPS CONNECT 403 / 本机直连绕过 / 隧道转发）、
     控制台接口、判定延迟、端口释放。
"""

import hashlib
import json
import os
import shutil
import socket
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import quote as urllib_quote, urlsplit

from . import GUARD_DIR, PROJECT_ROOT
from .api import GuardApi
from .engine import Engine
from .logwatch import LOG_FILE as EY_LOG_FILE
from .logwatch import LogWatcher
from .proxy import ProxyServer
from .proxyctl import SysProxyCtl
from .settings import Settings
from .store import Store

SKIP_DIRS = {"guard", ".venv", "__pycache__", ".git", ".idea"}
# 本次交付在项目根新增的文件（预期存在, 不算"被改动")
EXPECTED_NEW = {"run_guarded.py", "卸载_guard.bat", "安装_Edge扩展.bat", "GUARD_README.md"}


def snapshot(root, max_size=50 * 1024 * 1024):
    """对目录下所有文件做 SHA256 快照（跳过 guard/ 与缓存目录）"""
    files = {}
    for base, dirs, names in os.walk(root):
        dirs[:] = [item for item in dirs if item not in SKIP_DIRS]
        for name in names:
            path = os.path.join(base, name)
            try:
                if os.path.getsize(path) > max_size:
                    continue
                with open(path, "rb") as handle:
                    files[os.path.relpath(path, root)] = hashlib.sha256(handle.read()).hexdigest()
            except OSError:
                continue
    return files


class Report:
    def __init__(self):
        self.items = []

    def check(self, name, ok, detail=""):
        self.items.append((bool(ok), name, detail))
        flag = "PASS" if ok else "FAIL"
        print("  [%s] %-46s %s" % (flag, name, detail))
        return bool(ok)

    def skip(self, name, detail=""):
        self.items.append((True, name + "（跳过）", detail))
        print("  [SKIP] %-46s %s" % (name, detail))
        return True

    def passed(self):
        return sum(1 for ok, _n, _d in self.items if ok)

    def failed(self):
        return [item for item in self.items if not item[0]]

    def summary(self):
        total = len(self.items)
        bad = len(self.failed())
        return total, self.passed(), bad


# ================= 测试用小工具 =================
class _OriginHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"LOCAL-ORIGIN-OK"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        return


def start_origin(port):
    httpd = ThreadingHTTPServer(("127.0.0.1", port), _OriginHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


def http_via_proxy(proxy_port, url, timeout=12):
    """通过代理发一个 HTTP 请求（绝对 URI 形式）, 返回原始响应字节"""
    parts = urlsplit(url)
    sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout)
    request = ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: guard-selftest\r\n"
               "Connection: close\r\n\r\n" % (url, parts.netloc))
    sock.sendall(request.encode("latin-1"))
    data = b""
    sock.settimeout(timeout)
    try:
        while True:
            chunk = sock.recv(65536)
            if not chunk or len(data) > 3 * 1024 * 1024:
                break
            data += chunk
    except socket.timeout:
        pass
    finally:
        try:
            sock.close()
        except Exception:
            pass
    return data


def connect_via_proxy(proxy_port, host, port, timeout=12):
    """通过代理发 CONNECT, 返回 (响应头文本, socket)"""
    sock = socket.create_connection(("127.0.0.1", proxy_port), timeout=timeout)
    sock.sendall(("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n"
                  % (host, port, host, port)).encode("latin-1"))
    head = b""
    sock.settimeout(timeout)
    try:
        while b"\r\n\r\n" not in head and len(head) < 65536:
            chunk = sock.recv(4096)
            if not chunk:
                break
            head += chunk
    except socket.timeout:
        pass
    return head.decode("latin-1", "replace"), sock


def percentile(values, ratio):
    if not values:
        return 0.0
    ordered = sorted(values)
    index = int(round((len(ordered) - 1) * ratio))
    return ordered[max(0, min(index, len(ordered) - 1))]


def status_of(raw_response):
    """从原始响应里取状态码"""
    try:
        first_line = raw_response.split(b"\r\n", 1)[0].decode("latin-1")
        return int(first_line.split()[1])
    except Exception:
        return 0


def head_status(head_text):
    """从 CONNECT 响应头里取状态码"""
    try:
        return int(head_text.split()[1])
    except Exception:
        return 0


def api_get(base, path, timeout=10):
    """GET guard 接口, 返回 (状态码, 文本)"""
    import urllib.request
    try:
        with urllib.request.urlopen(base + path, timeout=timeout) as resp:
            return resp.getcode(), resp.read().decode("utf-8", "replace")
    except Exception as exc:
        return 0, str(exc)


def api_post(base, path, data, timeout=10, headers=None):
    """POST guard 接口, 返回解析后的 JSON（失败返回 {'ok': False}）

    headers: 额外请求头（例如写接口需要的自定义头 X-Guard-Request）。
    """
    import json as _json
    import urllib.parse
    import urllib.request
    try:
        body = urllib.parse.urlencode(data).encode("utf-8")
        request = urllib.request.Request(base + path, data=body, method="POST",
                                         headers=headers or {})
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            return _json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


class _TestSettings(Settings):
    """自测专用配置对象: save() 写到临时文件, **绝不覆盖 guard\\data\\config.json**"""

    def __init__(self, data=None, save_to=None):
        super(_TestSettings, self).__init__(data)
        self._save_to = save_to

    def save(self):
        import json
        if not self._save_to:
            return
        try:
            with open(self._save_to, "w", encoding="utf-8") as handle:
                json.dump(self.data, handle, ensure_ascii=False, indent=2)
        except Exception:
            pass


class _StubProxyCtl(object):
    """自测专用系统代理桩: 只在内存里记录, **绝不读写真实注册表/系统代理**"""

    def __init__(self, server="127.0.0.1:8888", previous_server="127.0.0.1:0"):
        self.server = server
        self.previous_server = previous_server
        self.active = False
        self.calls = []

    def status(self):
        return {"supported": True, "enabled": self.active,
                "server": self.server if self.active else self.previous_server,
                "autoconfig": "", "enabled_by_us": self.active, "active": self.active,
                "mismatch": False, "previous": {"ProxyServer": self.previous_server},
                "our_server": self.server}

    def enable(self, server=None, bypass=None):
        self.active = True
        self.calls.append("enable")
        return True, "【自测桩】系统代理已开启 → %s" % (server or self.server)

    def disable(self):
        self.active = False
        self.calls.append("disable")
        return True, "【自测桩】系统代理已还原"


class _ConsoleRuntime(object):
    """自测专用运行时: 给 Web 控制台（control.apply）提供最小接口。

    只借用现成的 engine/store/proxy/api; 系统代理换成桩; patch_detector 与
    runtime.py 里的实现保持一致（包装 detector.detect）。
    """

    def __init__(self, settings, engine, store, proxy, api, proxyctl=None, verbose=False):
        self.settings = settings
        self.engine = engine
        self.store = store
        self.proxy = proxy
        self.api = api
        self.proxyctl = proxyctl or _StubProxyCtl()
        self.logwatcher = None
        self.verbose = verbose
        self.patched = []
        self._orig = {}

    def patch_detector(self, detector):
        if detector is None or getattr(detector, "_guard_patched", False):
            return False
        original = detector.detect
        runtime = self

        def guarded_detect(url, *args, **kwargs):
            result = original(url, *args, **kwargs)
            try:
                runtime.on_detection(url, result)
            except Exception:
                pass
            return result

        self._orig[id(detector)] = (detector, "detect", original)
        detector.detect = guarded_detect
        detector._guard_patched = True
        self.patched.append("detector.detect")
        return True

    def unpatch_all(self):
        for detector, name, original in list(self._orig.values()):
            try:
                setattr(detector, name, original)
                if hasattr(detector, "_guard_patched"):
                    delattr(detector, "_guard_patched")
            except Exception:
                pass
        self._orig.clear()
        self.patched = []

    def on_detection(self, url, result):
        return None


def run_selftest(base_settings, port=18888):
    """执行隔离自测, 返回进程退出码（0 = 全部通过）"""
    import re

    report = Report()
    api_port = port + 1
    origin_port = port + 2
    api_base = "http://127.0.0.1:%d" % api_port
    temp_dir = os.path.join(tempfile.gettempdir(), "guard_selftest_%d" % port)
    shutil.rmtree(temp_dir, ignore_errors=True)      # 每轮都用干净的数据目录, 避免上轮残留
    os.makedirs(temp_dir, exist_ok=True)

    settings = _TestSettings(base_settings.as_dict(),
                             save_to=os.path.join(temp_dir, "selftest_config.json"))
    # 自测必须自包含: 不管用户当前把总开关放在什么状态, 都按"开启拦截"来测
    settings.set("enabled", True, save=False)
    settings.set("proxy.host", "127.0.0.1", save=False)
    settings.set("proxy.port", port, save=False)
    settings.set("proxy.upstream_proxy", "", save=False)
    settings.set("proxy.bypass_localhost", True, save=False)
    settings.set("api.host", "127.0.0.1", save=False)
    settings.set("api.port", api_port, save=False)

    print("=" * 78)
    print("  guard 隔离自测（不修改系统代理 / hosts / eyilianjie 文件）")
    print("  代理端口 %d · 控制台端口 %d · 测试数据目录 %s" % (port, api_port, temp_dir))
    print("=" * 78)

    before = snapshot(PROJECT_ROOT)
    ey_log_before = ""
    if os.path.exists(EY_LOG_FILE):
        with open(EY_LOG_FILE, "rb") as handle:
            ey_log_before = hashlib.sha256(handle.read()).hexdigest()

    store = Store(data_dir=temp_dir, max_log=200)
    engine = Engine(settings, store)
    proxyctl = SysProxyCtl(settings, verbose=False)
    proxy = ProxyServer(engine, store, settings, api_base=api_base, verbose=False)
    logwatch_state = os.path.join(temp_dir, "logwatch_state.json")
    logwatch = LogWatcher(engine, store, interval=2.0, import_history=True, verbose=False,
                          state_file=logwatch_state)
    api = GuardApi(engine, store, settings, proxy=proxy, proxyctl=proxyctl,
                   logwatcher=logwatch, verbose=False)
    if not engine.ready:
        report.check("引擎初始化", False, str(engine.error))
        return 1

    proxy.start()
    api.start()
    origin = start_origin(origin_port)

    # 选一个黑名单里的"纯域名"条目做测试目标
    domain_re = re.compile(r"^[a-z0-9][a-z0-9.\-]*\.[a-z]{2,}$")
    test_domain = ""
    for key in (engine.detector._blacklist or {}):
        if domain_re.match(str(key).lower()):
            test_domain = str(key).lower()
            break
    if "pornvideotop.com" in (engine.detector._blacklist or {}):
        test_domain = "pornvideotop.com"
    blocked_url = "http://%s/" % test_domain

    # ---------------- A. 测试前提 ----------------
    print("\n[A] 测试前提")
    report.check("A1 取到黑名单测试条目", bool(test_domain), "测试目标: %s" % blocked_url)

    # ---------------- B. 判定引擎 ----------------
    print("\n[B] 判定引擎（全部本地规则, 不联网）")
    decision = engine.judge(blocked_url, use_cache=False)
    report.check("B1 黑名单命中 → 拦截", bool(decision.get("blocked")),
                 "source=%s category=%s level=%s"
                 % (decision.get("source"), decision.get("category"), decision.get("level")))

    rules = engine._utils.load_adult_keywords() if engine._utils else {}
    adult_domain, adult_reason = "", ""
    for brand in (list(rules.get("adult_brands") or []) + list(rules.get("domain_strong") or [])
                  + list(rules.get("gambling") or [])):
        candidate = str(brand).strip().lower()
        if not candidate:
            continue
        host = candidate if "." in candidate else "%s.com" % candidate
        probe = engine._adult_rule("http://%s/" % host, host)
        if probe.get("block"):
            adult_domain, adult_reason = host, probe.get("reason") or ""
            break
    report.check("B2 成人/赌博规则 → 拦截", bool(adult_domain), adult_reason or "未找到样本")

    safe = engine.judge("https://www.baidu.com/", use_cache=False)
    report.check("B3 可信站点 → 放行", not safe.get("blocked"),
                 "source=%s reason=%s" % (safe.get("source"), safe.get("reason")))

    local = engine.judge("http://127.0.0.1:%d/" % origin_port, use_cache=False)
    report.check("B4 本机地址 → 放行", (not local.get("blocked")) and local.get("source") == "local",
                 "source=%s" % local.get("source"))

    unknown = engine.judge("https://www.wikipedia.org/", use_cache=False)
    report.check("B5 正常站点 → 放行", not unknown.get("blocked"),
                 "source=%s reason=%s" % (unknown.get("source"), unknown.get("reason")))

    # ---------------- C. 检测日志只读联动 ----------------
    print("\n[C] 检测日志联动（只读 eyilianjie\\detection_log.json）")
    imported = logwatch.scan(force=True)
    report.check("C1 扫描日志并导入恶意条目", imported > 0,
                 "本次导入 %d 条 URL（域名累计 %s 条）"
                 % (imported, logwatch.stats.get("imported_hosts")))
    ey_log_after = ""
    if os.path.exists(EY_LOG_FILE):
        with open(EY_LOG_FILE, "rb") as handle:
            ey_log_after = hashlib.sha256(handle.read()).hexdigest()
    report.check("C2 检测日志未被修改", bool(ey_log_before) and ey_log_before == ey_log_after,
                 "SHA256 %s…" % (ey_log_before[:16] or "(日志不存在)"))
    learned_host = next(iter(store.dynamic_hosts), "")
    if learned_host:
        learned = engine.judge("http://%s/" % learned_host, use_cache=False)
        report.check("C3 已检出即真封（动态集生效）",
                     bool(learned.get("blocked")) and str(learned.get("source")).startswith("dynamic"),
                     "%s → source=%s" % (learned_host, learned.get("source")))
    else:
        report.skip("C3 已检出即真封（动态集生效）", "日志里暂无可导入的恶意条目")

    # ---------------- D. 动态集 / 放行名单（走控制台接口） ----------------
    print("\n[D] 动态拦截集与放行名单（控制台接口）")
    test_dyn = "http://guard-selftest-dynamic.example.com/x"
    api_post(api_base, "/guard/block", {"url": test_dyn})
    dyn = engine.judge(test_dyn, use_cache=False)
    report.check("D1 手动加入拦截 → 立即生效",
                 bool(dyn.get("blocked")) and dyn.get("source") == "dynamic_manual",
                 "source=%s" % dyn.get("source"))

    api_post(api_base, "/guard/allow", {"url": test_dyn})
    allowed = engine.judge(test_dyn, use_cache=False)
    report.check("D2 加入放行名单 → 立即放行", not allowed.get("blocked"),
                 "source=%s" % allowed.get("source"))

    api_post(api_base, "/guard/remove", {"url": test_dyn})
    store.remove_allow(test_dyn)
    engine.invalidate()
    cleaned = engine.judge(test_dyn, use_cache=False)
    report.check("D3 移除后恢复原状（无残留）", not cleaned.get("blocked"),
                 "source=%s（应为 none/heuristic 且未拦截）" % cleaned.get("source"))

    # D4-D6: 方案 D 的「检测即真封」运行时挂载（用假检测器验证, 不碰 eyilianjie 文件）
    from .runtime import GuardRuntime

    class _FakeResult(object):
        is_malicious = True
        blacklist_match = True
        score = 0

    class _FakeDetector(object):
        def __init__(self):
            self.calls = 0

        def detect(self, url, use_api=False):
            self.calls += 1
            return _FakeResult()

    patch_url = "http://guard-selftest-patch.example.net/a"
    report.check("D4 patch 前：该地址未被拦截",
                 not engine.judge(patch_url, use_cache=False).get("blocked"), patch_url)
    runtime_like = GuardRuntime.__new__(GuardRuntime)     # 复用已有 engine/store, 不重建
    runtime_like.settings = settings
    runtime_like.engine = engine
    runtime_like.store = store
    runtime_like.verbose = False
    runtime_like.patched = []
    runtime_like._originals = {}
    fake = _FakeDetector()
    runtime_like.patch_detector(fake)
    fake.detect(patch_url)                                # 模拟 eyilianjie 的一次"恶意"检测
    patched = engine.judge(patch_url, use_cache=False)
    report.check("D5 检测即真封：检测后立刻被拦截",
                 bool(patched.get("blocked")) and patched.get("source") == "dynamic_log",
                 "source=%s reason=%s" % (patched.get("source"), patched.get("reason")))
    store.remove_dynamic(patch_url)
    engine.invalidate()
    runtime_like.unpatch_all()
    report.check("D6 取消挂载后还原原方法（可完全回退）",
                 not hasattr(fake, "_guard_patched") and fake.detect(patch_url) is not None,
                 "调用次数 %d" % fake.calls)

    # ---------------- E. 代理真实拦截 ----------------
    print("\n[E] 代理层真实拦截（HTTP / HTTPS）")
    raw = http_via_proxy(port, blocked_url)
    body = raw.decode("utf-8", "replace")
    report.check("E1 HTTP 黑名单请求 → 403 拦截页",
                 status_of(raw) == 403 and "该链接已被拦截" in body and test_domain in body,
                 "状态 %s, 页面 %d 字节" % (status_of(raw), len(raw)))

    raw = http_via_proxy(port, "http://127.0.0.1:%d/" % origin_port)
    report.check("E2 本机地址直连绕过（没有误拦自己）",
                 status_of(raw) == 200 and b"LOCAL-ORIGIN-OK" in raw,
                 "状态 %s" % status_of(raw))

    head, sock = connect_via_proxy(port, test_domain, 443)
    try:
        sock.close()
    except Exception:
        pass
    report.check("E3 HTTPS(CONNECT) 黑名单域名 → 403（无需证书）",
                 head_status(head) == 403, head.split("\r\n")[0])

    head, sock = connect_via_proxy(port, "127.0.0.1", origin_port)
    tunnel_ok = False
    if head_status(head) == 200:
        try:
            sock.sendall(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            data = b""
            sock.settimeout(8)
            while b"LOCAL-ORIGIN-OK" not in data and len(data) < 65536:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
            tunnel_ok = b"LOCAL-ORIGIN-OK" in data
        except Exception:
            tunnel_ok = False
    try:
        sock.close()
    except Exception:
        pass
    report.check("E4 CONNECT 隧道转发正常（放行流量不受影响）",
                 head_status(head) == 200 and tunnel_ok, head.split("\r\n")[0])

    online = False
    try:
        probe = socket.create_connection(("example.com", 80), timeout=4)
        probe.close()
        online = True
    except OSError:
        online = False
    if online:
        raw = http_via_proxy(port, "http://example.com/")
        report.check("E5 外网正常 URL 透传（未被误拦）",
                     status_of(raw) in (200, 301, 302), "状态 %s" % status_of(raw))
    else:
        report.skip("E5 外网正常 URL 透传", "当前无外网连接")

    # ---------------- F. 控制台接口 ----------------
    print("\n[F] guard 控制台接口（油猴脚本也走这些接口）")
    code, text = api_get(api_base, "/guard/status")
    ok_status = False
    try:
        payload = json.loads(text)
        ok_status = (code == 200 and (payload.get("proxy") or {}).get("running") is True
                     and (payload.get("engine") or {}).get("ready") is True)
    except Exception:
        ok_status = False
    report.check("F1 GET /guard/status", ok_status, "HTTP %s" % code)

    code, text = api_get(api_base, "/guard/check?url=" + urllib_quote(blocked_url))
    check_ok = False
    try:
        payload = json.loads(text)
        check_ok = (code == 200 and payload.get("blocked") is True
                    and (payload.get("decision") or {}).get("source") == "blacklist")
    except Exception:
        check_ok = False
    report.check("F2 GET /guard/check（油猴脚本判定接口）", check_ok, "HTTP %s" % code)

    code, text = api_get(api_base, "/guard/blockpage?url=" + urllib_quote(blocked_url))
    report.check("F3 GET /guard/blockpage（丰富拦截页）",
                 code == 200 and "为什么被拦" in text and "判定依据" in text
                 and "加入放行名单" in text, "HTTP %s, %d 字节" % (code, len(text)))

    code, text = api_get(api_base, "/guard/logs?limit=5")
    logs_ok = False
    try:
        logs_ok = code == 200 and len((json.loads(text) or {}).get("logs") or []) > 0
    except Exception:
        logs_ok = False
    report.check("F4 GET /guard/logs（拦截记录）", logs_ok, "HTTP %s" % code)

    code, text = api_get(api_base, "/")
    report.check("F5 GET /（控制台首页可正常渲染）",
                 code == 200 and "guard 控制台" in text and "运行开关" in text,
                 "HTTP %s, %d 字节" % (code, len(text)))

    # F6~F8 —— 浏览器扩展（拦截页「误报？加入放行名单」）依赖的接口。
    # 8899 侧以前没有 /guard/state 与 /guard/entry, 导致扩展探测不到后端、写放行必失败。
    code, text = api_get(api_base, "/guard/state?logs=1")
    state_ok = False
    try:
        payload = json.loads(text)
        state_ok = (code == 200 and payload.get("available") is True
                    and isinstance(payload.get("enabled"), bool)
                    and isinstance(payload.get("modes"), list))
    except Exception:
        state_ok = False
    report.check("F6 GET /guard/state（扩展/弹窗靠它探测后端）", state_ok, "HTTP %s" % code)

    ext_url = "guard-extension-write-test.example"
    api_post(api_base, "/guard/block", {"url": ext_url})       # 先加黑, 这样"放行"有可验证的效果
    ext_blocked = bool(engine.judge("http://%s/" % ext_url).get("blocked"))
    ext_write = api_post(api_base, "/guard/entry", {"action": "allow", "url": ext_url},
                         headers={"X-Guard-Request": "1"})
    ext_allowed = not bool(engine.judge("http://%s/" % ext_url).get("blocked"))
    ext_revert = api_post(api_base, "/guard/entry", {"action": "remove_allow", "url": ext_url},
                          headers={"X-Guard-Request": "1"})
    write_note = str(ext_write.get("ok"))
    if not ext_write.get("ok"):
        write_note += "(%s)" % str(ext_write.get("reason") or ext_write.get("error") or "")[:40]
    report.check("F7 POST /guard/entry（扩展写放行名单的接口）",
                 ext_blocked and bool(ext_write.get("ok")) and ext_allowed and bool(ext_revert.get("ok")),
                 "加黑=%s → 写=%s → 即时放行=%s → 复原=%s"
                 % (ext_blocked, write_note, ext_allowed, ext_revert.get("ok")))

    no_header = api_post(api_base, "/guard/entry", {"action": "allow", "url": ext_url})
    report.check("F8 写接口拒绝没有自定义头的请求（同上, guard 控制台侧）",
                 no_header.get("ok") is False and "403" in str(no_header.get("error") or ""),
                 str(no_header.get("error") or "")[:70])

    # ---------------- G. 性能 ----------------
    print("\n[G] 判定性能（本地规则, 无网络请求）")
    target = "https://www.wikipedia.org/"
    cold, warm = [], []
    for _ in range(10):
        engine.invalidate()
        start = time.perf_counter()
        engine.judge(target, use_cache=False)
        cold.append((time.perf_counter() - start) * 1000)
    engine.judge(target)
    for _ in range(200):
        start = time.perf_counter()
        engine.judge(target)
        warm.append((time.perf_counter() - start) * 1000)
    report.check("G1 冷判定延迟（未命中缓存）", percentile(cold, 0.95) < 500.0,
                 "p50 %.1fms · p95 %.1fms" % (percentile(cold, 0.5), percentile(cold, 0.95)))
    report.check("G2 缓存命中延迟", percentile(warm, 0.95) < 5.0,
                 "p50 %.3fms · p95 %.3fms" % (percentile(warm, 0.5), percentile(warm, 0.95)))

    # ---------------- I. Web 端拦截控制台（点【开始拦截】才生效） ----------------
    print("\n[I] Web 端拦截控制台（融入 eyilianjie 页面, 点【开始拦截】才拦）")
    from . import control as guard_control
    import web_app

    saved_keys = ["enabled", "block_via_proxy"] + list(guard_control.RULE_KEYS)
    saved_values = {key: base_settings.get(key) for key in saved_keys}

    console = _ConsoleRuntime(settings, engine, store, proxy, api)
    web_app.attach_guard(console)
    client = web_app.app.test_client()

    page = client.get("/guard")
    html = page.data.decode("utf-8", "replace")
    report.check("I1 GET /guard 控制台页面可渲染",
                 page.status_code == 200 and "开始拦截" in html and "拦截方式" in html,
                 "HTTP %s, %d 字节" % (page.status_code, len(html)))

    home = client.get("/").data.decode("utf-8", "replace")
    report.check("I2 导航栏「拦截」入口与状态徽章已注入（其它页面也有）",
                 'href="/guard"' in home and "guardNavBadge" in home,
                 "首页 %d 字节" % len(home))

    bad = client.post("/guard/apply", json={"enabled": True})
    report.check("I3 写接口拒绝没有自定义头的请求（防本机跨站伪造）",
                 bad.status_code == 403,
                 "HTTP %s · %s" % (bad.status_code, (bad.get_json() or {}).get("reason", "")))

    blocked_before = bool(engine.judge("http://pornvideotop.com/").get("blocked"))

    values = {"enabled": True, "block_via_proxy": True, "detect_block": True}
    for key in guard_control.RULE_KEYS:
        values[key] = True
    good = client.post("/guard/apply", json=values,
                       headers={web_app.GUARD_WRITE_HEADER: "1"})
    payload = good.get_json() or {}
    state = payload.get("state") or {}
    report.check("I4 点【开始拦截】→ 立即生效（挂检测即真封 + 开系统代理）",
                 good.status_code == 200 and payload.get("ok")
                 and state.get("enabled") and state.get("detector_patched"),
                 (payload.get("message") or "")[:78])

    # 全部判定规则都取消勾选（逐项覆盖, 避免漏项 —— 之前就是漏了 ml_hint 才被测出来）
    off = {"enabled": True, "block_via_proxy": True, "detect_block": True}
    for key in guard_control.RULE_KEYS:
        off[key] = False
    client.post("/guard/apply", json=off, headers={web_app.GUARD_WRITE_HEADER: "1"})
    blocked_after_off = bool(engine.judge("http://pornvideotop.com/").get("blocked"))
    report.check("I5 取消勾选后同一条 URL 立刻放行（配置即时生效）",
                 blocked_before and not blocked_after_off,
                 "勾选前=%s → 取消后=%s" % (blocked_before, blocked_after_off))

    # 手动拦截 / 移除: 只用"检测日志联动(动态集)"这一条通道, 结果完全确定
    entry_modes = {"enabled": True, "block_via_proxy": True, "detect_block": True}
    for key in guard_control.RULE_KEYS:
        entry_modes[key] = False
    entry_modes["block.dynamic_from_log"] = True
    client.post("/guard/apply", json=entry_modes, headers={web_app.GUARD_WRITE_HEADER: "1"})

    entry = client.post("/guard/entry", json={"action": "block", "url": "guard-console-test.example"},
                        headers={web_app.GUARD_WRITE_HEADER: "1"})
    entry_blocked = bool(engine.judge("http://guard-console-test.example/").get("blocked"))
    guard_control.entry(console, "remove", "guard-console-test.example")
    entry_released = not bool(engine.judge("http://guard-console-test.example/").get("blocked"))
    report.check("I6 控制台手动拦截 / 移除（HTTP 接口）",
                 (entry.get_json() or {}).get("ok") and entry_blocked and entry_released,
                 "拦截=%s → 移除后=%s" % (entry_blocked, entry_released))

    check = client.get("/guard/check?url=http%3A%2F%2Fpornvideotop.com%2F").get_json() or {}
    report.check("I7 页面里的「手测 URL」接口", check.get("ok"),
                 "blocked=%s source=%s" % ((check.get("decision") or {}).get("blocked"),
                                           (check.get("decision") or {}).get("source")))

    client.post("/guard/apply", json={"enabled": False}, headers={web_app.GUARD_WRITE_HEADER: "1"})
    calls = list(console.proxyctl.calls)
    report.check("I8 点【停止拦截】→ 关闭系统代理并放行一切（自测用桩, 未碰真实注册表）",
                 "enable" in calls and calls[-1] == "disable"
                 and not bool(engine.judge("http://pornvideotop.com/").get("blocked"))
                 and (console.proxyctl.status().get("active") is False),
                 "系统代理调用: %s" % calls)

    # I9 静态防回归: 扩展拦截页写放行名单时, 必须带自定义头（否则 5000/8899 都 403,
    #    用户看到的就是"加入放行失败"); 同时必须保留老版 guard 的 /guard/allow 回退。
    ext_js = os.path.join(GUARD_DIR, "extension", "blocked.js")
    try:
        with open(ext_js, "r", encoding="utf-8") as fp:
            ext_text = fp.read()
    except OSError:
        ext_text = ""
    report.check("I9 扩展拦截页写请求带自定义头且有老后端回退（防回归）",
                 "X-Guard-Request" in ext_text and "/guard/entry" in ext_text
                 and "/guard/allow" in ext_text,
                 ext_js)

    # I10 手动拦截撞上放行名单 → 必须给明确原因（放行优先, 否则用户"加了拦截却永远拦不住"）
    conflict_url = "http://guard-allow-conflict.example/"
    store.add_allow(conflict_url, note="自测: 冲突检查")
    engine.invalidate()
    ok_conflict, conflict_msg = guard_control.entry(console, "block", conflict_url)
    store.remove_allow(conflict_url)
    engine.invalidate()
    report.check("I10 手动拦截撞上放行名单 → 明确提示（而不是假装成功）",
                 (ok_conflict is False) and ("放行名单" in str(conflict_msg)),
                 "ok=%s · %s" % (ok_conflict, conflict_msg))

    # I11 web_app 本进程没有运行时 → 自动转发给独立 guard 控制台(8899)
    #     自测里用猴子补丁禁掉"懒启动", 否则测试进程会去抢真实的 8888/8899。
    fwd_url = "http://guard-forward-test.example/"
    original_guarantee = web_app.guarantee_guard
    web_app.guarantee_guard = lambda: None
    web_app.app.config['GUARD_REMOTE_BASE'] = api_base       # 指向自测临时起的 8899 接口
    web_app.attach_guard(None)
    try:
        fwd_resp = client.post("/guard/entry", json={"action": "allow", "url": fwd_url},
                               headers={web_app.GUARD_WRITE_HEADER: "1"})
        fwd_data = fwd_resp.get_json() or {}
        fwd_landed = store.is_allowed(fwd_url)               # 真落到"那一份"的 store 里了吗
        fwd_state = client.get("/guard/state?logs=1").get_json() or {}
        report.check("I11 Web 端没有运行时 → 自动转发给独立 guard 控制台",
                     fwd_resp.status_code == 200 and bool(fwd_data.get("ok"))
                     and bool(fwd_data.get("forwarded")) and fwd_landed
                     and bool(fwd_state.get("forwarded")),
                     "HTTP %s · forwarded=%s · 落到 8899 侧=%s · state.forwarded=%s"
                     % (fwd_resp.status_code, fwd_data.get("forwarded"), fwd_landed,
                        fwd_state.get("forwarded")))
        store.remove_allow(fwd_url)
        engine.invalidate()
    finally:
        web_app.guarantee_guard = original_guarantee
        web_app.app.config.pop('GUARD_REMOTE_BASE', None)
        web_app.attach_guard(console)

    # I11b 本机已有 guard 在跑时, guarantee_guard 不能再启第二份（否则双方抢 8888/8899,
    #      结果是"控制台/代理都没绑上"的半残运行时 —— 页面显示已开启, 实际什么都没拦）
    original_alive = web_app._guard_api_alive
    web_app._guard_api_alive = lambda conf, timeout=0.8: True
    web_app.attach_guard(None)
    try:
        duplicated = web_app.guarantee_guard()
        dup_error = web_app._guard_error
    finally:
        web_app._guard_api_alive = original_alive
        web_app.attach_guard(console)
    report.check("I11b 已有 guard 在跑 → 不重复启动第二份（避免抢端口）",
                 duplicated is None and ("已有 guard" in str(dup_error)), str(dup_error))

    # I12 静态防回归: 扩展在 guard 未运行时必须"显式提示", 不能静默放行
    bg_js = os.path.join(GUARD_DIR, "extension", "background.js")
    popup_js = os.path.join(GUARD_DIR, "extension", "popup.js")
    try:
        with open(bg_js, "r", encoding="utf-8") as fp:
            bg_text = fp.read()
        with open(popup_js, "r", encoding="utf-8") as fp:
            popup_text = fp.read()
    except OSError:
        bg_text = popup_text = ""
    report.check("I12 扩展「guard 未运行」不再是静默放行（防回归）",
                 "guardDown" in bg_text and "guard 未运行" in bg_text
                 and "downBanner" in popup_text,
                 "background.js + popup.js")

    # I13 放行名单"看得见 + 撤得掉"：只输入裸域名也必须删掉 https:// 形式的 URL 条目。
    #     （以前 remove_allow 只做字面比对: 名单里存 https://www.x/，输入 www.x 会被补成
    #       http:// → host 删掉了、URL 条目还在 → 用户看到"移除了却还在放行"。）
    demo_host = "www.guard-allow-demo.example"
    demo_url = "https://%s/" % demo_host
    store.add_allow(demo_url, note="自测: 放行名单可见性")
    store.add_allow("https://%s/chat/" % demo_host, note="自测: 同域第二个条目")
    engine.invalidate()
    allow_state = guard_control.ui_state(console, 1).get("allow") or {}
    visible = (demo_host in (allow_state.get("hosts") or [])) and \
              (demo_url in (allow_state.get("urls") or []))
    removed_allow = store.remove_allow(demo_host)          # ← 只输入裸域名
    engine.invalidate()
    left = store.allow_entries()
    gone = (not [k for k in (left.get("hosts") or []) if demo_host in k]) and \
           (not [k for k in (left.get("urls") or []) if demo_host in k])
    report.check("I13 放行名单可查 + 裸域名也能撤干净（含 https URL 条目）",
                 visible and bool(removed_allow.get("ok")) and gone,
                 "可见=%s · 移除=%d 条(%s) · 有残留=%s"
                 % (visible, len(removed_allow.get("removed") or []),
                    "、".join(removed_allow.get("removed") or []), not gone))

    # I14 撤销放行的两个入口都在：8899 的 /guard/remove_allow 路由 + CLI 的 unallow
    unallow_url = "http://guard-unallow-route.example/"
    api_post(api_base, "/guard/allow", {"url": unallow_url})
    removed_route = api_post(api_base, "/guard/remove_allow", {"url": unallow_url})
    still_allowed = store.is_allowed(unallow_url)
    parser_has_unallow = False
    try:
        from .cli import build_parser
        parser_has_unallow = "unallow" in build_parser().format_help()
    except Exception:
        parser_has_unallow = False
    report.check("I14 撤销放行的入口齐全（8899 的 /guard/remove_allow + CLI unallow）",
                 bool(removed_route.get("ok")) and not still_allowed and parser_has_unallow,
                 "路由 ok=%s · 删后仍放行=%s · CLI unallow=%s"
                 % (removed_route.get("ok"), still_allowed, parser_has_unallow))

    # I15 页面内联 JS 语法校验（node --check）：这些 JS 写在 Python 三引号字符串里，
    #     一个反斜杠写错就会变成真实换行 / 语法错误 → 整页按钮全部失效。
    #     用 node 做权威校验（比自研扫描器准）；本机没装 node 就跳过（不阻塞自测）。
    import re
    import subprocess

    def _node_check_js(label, code):
        node = shutil.which("node") or shutil.which("node.exe")
        if not node:
            return None
        path = os.path.join(tempfile.gettempdir(), "guard_js_check_%s.js" % label)
        with open(path, "w", encoding="utf-8") as fp:
            fp.write(code)
        try:
            proc = subprocess.run([node, "--check", path], capture_output=True, timeout=30)
            return proc.returncode == 0, (proc.stderr or b"").decode("utf-8", "replace").strip()
        except Exception as exc:
            return False, str(exc)
        finally:
            try:
                os.remove(path)
            except OSError:
                pass

    try:
        from .api import _DASH_JS                  # guard 控制台页面的内联 JS（已解析过的真值）
        with open(os.path.join(PROJECT_ROOT, "templates", "guard.html"),
                  "r", encoding="utf-8") as fp:
            page_src = fp.read()
        page_js = "\n".join(re.findall(r"<script>(.*?)</script>", page_src, re.S))
        js_reports = [(label, _node_check_js(label, code))
                      for label, code in (("dash", _DASH_JS), ("page", page_js))]
        if all(item[1] is None for item in js_reports):
            report.skip("I15 页面内联 JS 语法（node --check）", "本机没有 node, 已跳过")
        else:
            broken = [(label, res[1]) for label, res in js_reports if res and not res[0]]
            detail = " | ".join("%s: %s" % (label, (msg.splitlines()[-1] if msg else "语法错误"))
                                for label, msg in broken)
            report.check("I15 页面内联 JS 语法（node --check，写错转义会让整页按钮失效）",
                         not broken, detail or "两段都通过")
    except Exception as exc:
        report.check("I15 页面内联 JS 语法（node --check）", False, "检查失败: %s" % exc)

    # I16 名单版本号：名单一变它就变（浏览器扩展靠它在"加入拦截"后立刻丢掉旧判定缓存）
    version_before = store.rules_version()
    store.add_dynamic("http://guard-version-test.example/", reason="自测: 版本号",
                      category="手动拦截", source="manual")
    engine.invalidate()
    time.sleep(0.03)                                  # 让文件时间戳确定地变化
    version_after_add = store.rules_version()
    store.remove_dynamic("http://guard-version-test.example/")
    engine.invalidate()
    time.sleep(0.03)
    version_after_remove = store.rules_version()
    report.check("I16 名单版本号随名单变化（扩展靠它立刻失效缓存）",
                 bool(version_before) and version_after_add != version_before
                 and version_after_remove != version_after_add,
                 "%s → %s → %s" % (version_before, version_after_add, version_after_remove))

    # I17 /guard/rules_version 两个后端都可用（极轻接口, 扩展每次导航前比对它）
    code, text = api_get(api_base, "/guard/rules_version")
    api_version_ok = False
    try:
        payload = json.loads(text)
        api_version_ok = (code == 200 and payload.get("ok") is True
                          and bool(payload.get("rules_version")))
    except Exception:
        api_version_ok = False
    web_version = client.get("/guard/rules_version").get_json() or {}
    report.check("I17 GET /guard/rules_version（8899 与 Web 端都可用）",
                 api_version_ok and bool(web_version.get("rules_version")),
                 "8899: HTTP %s · Web 端 ok=%s" % (code, web_version.get("ok")))

    # I18 静态防回归: 扩展必须"比对名单版本 + 「放行」结论只短缓存"
    report.check("I18 扩展会按名单版本立刻失效缓存（防回归）",
                 "rules_version" in bg_text and "ALLOW_TTL_MS" in bg_text
                 and "syncRulesVersion" in bg_text,
                 "background.js")

    # I20 警告档（8-A）：未达拦截线但信号可疑 → blocked=False + warn=True
    #     验证方式：临时把警告线放宽到"必然命中"（warn_score=0 / warn_prob=0），
    #     确认 warn 分支生效且不拦；再还原默认配置，确认正常站不会误入警告档。
    prev_enabled = settings.get("enabled")
    prev_warn_score = settings.get("block.warn_score") or 40
    prev_warn_prob = settings.get("block.warn_prob") or 0.90
    settings.set("enabled", True, save=False)
    settings.set("block.warn_score", 0, save=False)
    settings.set("block.warn_prob", 0.0, save=False)
    engine.invalidate()
    relaxed = engine.judge("https://www.example.com/", use_cache=False)
    settings.set("block.warn_score", prev_warn_score, save=False)
    settings.set("block.warn_prob", prev_warn_prob, save=False)
    engine.invalidate()
    normal = engine.judge("https://www.example.com/", use_cache=False)
    settings.set("enabled", prev_enabled, save=False)
    engine.invalidate()
    report.check("I20 警告档：可疑但未到拦截线 → warn=True（不拦、只提示）",
                 (not relaxed.get("blocked")) and bool(relaxed.get("warn"))
                 and (not normal.get("warn")) and (not normal.get("blocked")),
                 "放宽配置 → warn=%s ｜ 默认配置 → warn=%s（来源 %s）"
                 % (relaxed.get("warn"), normal.get("warn"), normal.get("source")))

    # I21 检测日志联动改为"增量导入"：同一份日志第二轮不再重复导入
    #     （否则页面上删掉的条目会在下次启动时被历史重新加回来）
    second_import = logwatch.scan(force=True)
    report.check("I21 日志联动增量导入（不重复处理历史）", second_import == 0,
                 "第二轮导入 %d 条 · 水位 %s"
                 % (second_import, logwatch.last_ts or "-"))

    # I22 模拟重启：新进程读取同一份水位后，已删除的条目不会被重新加回来
    victim = next(iter(store.dynamic_urls), "")
    if victim:
        store.remove_dynamic(victim)
        restarted = LogWatcher(engine, store, interval=2.0, import_history=True,
                               verbose=False, state_file=logwatch_state)
        reimported = restarted.scan(force=True)
        came_back = store.match_dynamic(victim) is not None
        report.check("I22 重启后已删除的条目不会再出现", reimported == 0 and not came_back,
                     "重启导入 %d 条 · %s → %s"
                     % (reimported, victim, "又被加回" if came_back else "保持已移除"))
    else:
        report.skip("I22 重启后已删除的条目不会再出现", "日志里暂无可导入的恶意条目")

    # I23 复用 web_app 的 detector 时，guard 不得置空检测日志入口
    #     （曾经的 bug: attach() 把 reporter.log_detection 换成空函数 →
    #       首页「最近检测 / 统计摘要」停止更新，刷新也无效）
    try:
        web_app_detector = getattr(web_app, "detector", None)
        Engine(settings, store, detector=web_app_detector, verbose=False)
        log_fn = getattr(getattr(web_app_detector, "reporter", None), "log_detection", None)
        kept = getattr(log_fn, "__self__", None) is not None
        report.check("I23 guard 挂载后仍保留 web 端检测日志入口", kept,
                     "reporter.log_detection=%r" % (log_fn,))
    except Exception as exc:
        report.check("I23 guard 挂载后仍保留 web 端检测日志入口", False, "异常: %s" % exc)

    # I24 / I25 Reporter 文件增量重读 + 统计脏数据容错
    class _RepCfg(object):
        def __init__(self, path):
            self._path = path

        def get(self, *keys):
            if keys == ("logging", "log_file"):
                return self._path
            if keys == ("logging", "max_log_entries"):
                return 1000
            return None

    class _RepResult(object):
        def __init__(self, url, score=10, malicious=False):
            self.url = url
            self.score = score
            self.is_malicious = malicious

        def to_dict(self):
            return {"url": self.url, "score": self.score, "is_malicious": self.is_malicious,
                    "timestamp": "2020-01-01T00:00:00", "details": [], "risk_level": "安全"}

    from reporter import Reporter as _Reporter
    rep_path = os.path.join(temp_dir, "reporter_shared.json")
    try:
        rep_a = _Reporter(_RepCfg(rep_path))
        rep_a.log_detection(_RepResult("https://rep-a.example/"))
        rep_b = _Reporter(_RepCfg(rep_path))
        rep_b.log_detection(_RepResult("https://rep-b.example/"))
        shared = rep_a.get_statistics()
        report.check("I24 Reporter 跨实例可见（文件变更后自动重读）",
                     shared.get("total_detections") == 2,
                     "A 视角条数=%s（期望 2）" % shared.get("total_detections"))

        with open(rep_path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
        payload.append({"url": "https://bad.example/", "timestamp": None, "score": "x"})
        with open(rep_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False)
        dirty = rep_b.get_statistics()
        report.check("I25 统计对脏数据容错（不因单条坏记录失败）",
                     dirty.get("total_detections") == 3 and dirty.get("recent_24h") == 0,
                     "条数=%s · recent_24h=%s"
                     % (dirty.get("total_detections"), dirty.get("recent_24h")))
    except Exception as exc:
        report.check("I24 Reporter 跨实例可见（文件变更后自动重读）", False, "异常: %s" % exc)
        report.skip("I25 统计对脏数据容错（不因单条坏记录失败）", "前置 I24 异常")

    # 收尾: 还原被自测改动的开关 + 摘下 detector 包装（guard 配置本身写的是临时文件, 不受影响）
    for key, value in saved_values.items():
        settings.set(key, value, save=False)
    console.unpatch_all()
    web_app.attach_guard(None)

    # ---------------- H. 零改动校验与收尾 ----------------
    print("\n[H] 零改动校验与收尾")
    proxy.stop()
    api.stop()
    try:
        origin.shutdown()
    except Exception:
        pass
    released = False
    try:
        probe = socket.create_connection(("127.0.0.1", port), timeout=2)
        probe.close()
    except OSError:
        released = True
    report.check("H1 停止后代理端口已释放", released, "端口 %d" % port)

    after = snapshot(PROJECT_ROOT)
    changed = [key for key in before if key in after and before[key] != after[key]]
    missing = [key for key in before if key not in after]
    new_files = sorted(key for key in after if key not in before)
    unexpected = [key for key in new_files if os.path.dirname(key) == "" and key not in EXPECTED_NEW]
    report.check("H2 eyilianjie 现有文件零改动（SHA256 比对）",
                 not changed and not missing,
                 "比对 %d 个文件, 改动 %d 个, 缺失 %d 个" % (len(before), len(changed), len(missing)))
    report.check("H3 未产生意外新增文件（guard\\ 与入口脚本除外）", not unexpected,
                 "；".join(unexpected) if unexpected else "无")
    report.check("H4 本次交付新增文件（预期）", True,
                 "；".join(new_files) if new_files else "无（guard\\ 目录内文件不计入）")

    total, passed, failed = report.summary()
    print("\n" + "=" * 78)
    print("  自测总结: %d/%d 通过, %d 失败" % (passed, total, failed))
    if failed:
        print("  失败项:")
        for _ok, name, detail in report.failed():
            print("    [FAIL] %s  %s" % (name, detail))
    print("  测试数据目录（可直接删除）: %s" % temp_dir)
    print("=" * 78)
    return 0 if failed == 0 else 1
