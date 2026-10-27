"""
guard 控制台 + 本地 API（默认 127.0.0.1:8899, 纯标准库 http.server）

对外接口（页面内 fetch、油猴脚本 GM_xmlhttpRequest、浏览器扩展都可用, 已开 CORS）:
  GET  /                     控制台页面（统计 / 动态拦截集 / 放行名单 / 最近记录 / 开关）
  GET  /guard/status         运行状态 + 统计 (JSON)
  GET  /guard/state?logs=20  与 Web 端 /guard/state 同构的状态 (JSON) ← 扩展/弹窗/自检页用它
  GET  /guard/check?url=...  判定一个 URL (JSON)     ← 油猴脚本/扩展调用这个
  GET  /guard/blockpage?...  渲染拦截页 (HTML)
  GET  /guard/logs?limit=50  最近的拦截/放行记录 (JSON)
  POST /guard/block|allow|remove|clear_dynamic|sysproxy
  POST /guard/entry          {action, url} 统一入口（需 X-Guard-Request: 1, 与 Web 端同语义）
安全: 只监听 127.0.0.1; /guard/entry 额外要求自定义头, 用于拒绝本机跨站伪造的写请求。
"""

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

from . import GUARD_DIR, VERSION
from .blockpage import render_block_page


def control_modes_for_ui(api):
    """「拦截方式」清单（含当前取值）; guard.control 不可用时返回空列表, 不影响状态接口"""
    try:
        from . import control
        return control.modes_for_ui(getattr(api, "runtime", None), api.settings)
    except Exception:
        return []


class GuardApi:
    def __init__(self, engine, store, settings, proxy=None, proxyctl=None,
                 logwatcher=None, runtime=None, verbose=True):
        self.engine = engine
        self.store = store
        self.settings = settings
        self.proxy = proxy
        self.proxyctl = proxyctl
        self.logwatcher = logwatcher
        self.runtime = runtime
        self.verbose = verbose
        self.host = str(settings.get("api.host", "127.0.0.1"))
        self.port = int(settings.get("api.port", 8899) or 8899)
        self._httpd = None
        self._thread = None
        self.base_url = "http://%s:%d" % (self.host, self.port)

    # ================= 生命周期 =================
    def start(self):
        if self.is_running():
            return True, "控制台已在运行"
        api = self

        class _Server(ThreadingHTTPServer):
            daemon_threads = True
            allow_reuse_address = True
            api = None

        try:
            self._httpd = _Server((self.host, self.port), _Handler)
        except OSError as exc:
            self._httpd = None
            return False, "控制台端口 %s:%d 无法监听: %s" % (self.host, self.port, exc)
        self._httpd.api = api
        self._thread = threading.Thread(target=self._httpd.serve_forever,
                                        name="guard-api", daemon=True)
        self._thread.start()
        if self.verbose:
            print("[guard] 控制台已启动: %s/" % self.base_url)
        return True, "控制台已启动"

    def stop(self):
        if self._httpd:
            try:
                self._httpd.shutdown()
                self._httpd.server_close()
            except Exception:
                pass
        self._httpd = None
        return True, "控制台已停止"

    def is_running(self):
        return self._httpd is not None

    # ================= 状态 =================
    def status(self):
        data = {
            "version": VERSION,
            "base_url": self.base_url,
            "guard_dir": GUARD_DIR,
            "proxy": {
                "running": bool(self.proxy and self.proxy.is_running()),
                "host": self.settings.get("proxy.host"),
                "port": self.settings.get("proxy.port"),
                "upstream_proxy": self.settings.get("proxy.upstream_proxy") or "",
                "stats": dict(self.proxy.stats) if self.proxy else {},
            },
            "api": {"running": self.is_running(), "host": self.host, "port": self.port},
            "engine": self.engine.stats(),
            "store": self.store.stats(),
            "enabled": bool(self.settings.get("enabled", True)),
            "block_via_proxy": bool(self.settings.get("block_via_proxy", True)),
            "modes": control_modes_for_ui(self),
            "sysproxy": (self.proxyctl.status() if self.proxyctl else {"enabled": False}),
            "block": self.settings.get("block"),
            "settings_file": os.path.join(GUARD_DIR, "data", "config.json"),
        }
        if self.logwatcher is not None:
            data["logwatch"] = dict(self.logwatcher.stats)
        return data


class _Handler(BaseHTTPRequestHandler):
    server_version = "eyilianjie-guard/" + VERSION

    # ---------- 基础工具 ----------
    def log_message(self, fmt, *args):        # 静音默认访问日志
        return

    @property
    def api(self):
        return self.server.api

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        # 自定义写头必须出现在这里, 否则浏览器预检(OPTIONS)会拒掉扩展/页面的写请求
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Guard-Request")

    def _send(self, status, body_bytes, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body_bytes)))
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
        self._cors()
        self.end_headers()
        try:
            self.wfile.write(body_bytes)
        except Exception:
            pass

    def send_json(self, data, status=200):
        self._send(status, json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8"),
                   "application/json; charset=utf-8")

    def send_html(self, html, status=200):
        self._send(status, html.encode("utf-8"), "text/html; charset=utf-8")

    @staticmethod
    def _form(data):
        out = {}
        for key, values in (data or {}).items():
            out[key] = (values[0] if isinstance(values, list) and values else values)
        return out

    def _query(self):
        parts = urlsplit(self.path)
        return (parts.path.rstrip("/") or "/"), self._form(parse_qs(parts.query))

    def _body(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        raw = self.rfile.read(length) if length > 0 else b""
        ctype = (self.headers.get("Content-Type") or "").lower()
        if "json" in ctype:
            try:
                data = json.loads(raw.decode("utf-8") or "{}") or {}
                return self._form({k: [v] for k, v in data.items()})
            except Exception:
                return {}
        return self._form(parse_qs(raw.decode("utf-8", "replace")))

    # ---------- 路由 ----------
    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        path, query = self._query()
        api = self.api
        try:
            if path in ("/", "/index.html", "/guard"):
                self.send_html(_dashboard_html(api))
            elif path == "/guard/status":
                self.send_json(api.status())
            elif path == "/guard/state":
                # 与 Web 端 /guard/state 同构（浏览器扩展、扩展弹窗、扩展自检页都依赖它;
                # 以前只有 Web 端有, 导致扩展探测不到本控制台）
                from . import control
                try:
                    limit = int(query.get("logs") or 20)
                except (TypeError, ValueError):
                    limit = 20
                state = control.ui_state(getattr(api, "runtime", None), limit)
                state["available"] = True
                self.send_json(state)
            elif path == "/guard/rules_version":
                # 极轻接口: 只回"名单版本号"（文件名指纹）。浏览器扩展每次导航前比对它,
                # 一变就丢自己的判定缓存 → 页面上刚加入拦截, 下一次访问立刻生效。
                self.send_json({"ok": True, "rules_version": api.store.rules_version()})
            elif path == "/guard/check":
                self.send_json(self._check(query))
            elif path == "/guard/blockpage":
                self.send_html(self._blockpage(query))
            elif path == "/guard/logs":
                try:
                    limit = int(query.get("limit") or 50)
                except (TypeError, ValueError):
                    limit = 50
                self.send_json({"ok": True, "logs": api.store.recent_logs(limit)})
            else:
                self.send_json({"ok": False, "error": "未知路径: %s" % path}, 404)
        except Exception as exc:
            self.send_json({"ok": False, "error": str(exc)}, 500)

    def do_POST(self):
        path, _ignored = self._query()
        api = self.api
        form = self._body()
        url = (form.get("url") or "").strip()
        try:
            if path == "/guard/block":
                if not url:
                    self.send_json({"ok": False, "reason": "url 不能为空"}, 400)
                    return
                conflict = api.store.match_allow(url)
                if conflict:
                    self.send_json({"ok": False,
                                    "reason": "已在放行名单中: %s —— 放行优先于一切拦截, "
                                              "请先移除放行再拦截" % conflict}, 409)
                    return
                result = api.store.add_dynamic(url, reason="手动加入 guard 拦截名单",
                                               category=form.get("category") or "手动拦截",
                                               source="manual")
                api.engine.invalidate()
                self.send_json({"ok": True, "result": result})
            elif path == "/guard/allow":
                if not url:
                    self.send_json({"ok": False, "reason": "url 不能为空"}, 400)
                    return
                result = api.store.add_allow(url, note=form.get("note") or "")
                api.engine.invalidate()
                self.send_json(dict(result, ok=bool(result.get("ok"))))
            elif path == "/guard/entry":
                # 与 Web 端 /guard/entry 同语义的统一入口（浏览器扩展的「误报？加入放行名单」走这里）
                if self.headers.get("X-Guard-Request") != "1":
                    self.send_json({"ok": False,
                                    "reason": "缺少 X-Guard-Request 请求头（跨站请求会被拒绝）"}, 403)
                    return
                target = getattr(api, "runtime", None)
                if target is None:
                    # 没有完整 runtime 时（例如只跑 API 组件 / 隔离自测）用 store+engine 顶替:
                    # control.entry 只用到这两个成员
                    from types import SimpleNamespace
                    target = SimpleNamespace(store=api.store, engine=api.engine)
                from . import control
                ok, message = control.entry(target, (form.get("action") or "").strip(), url)
                self.send_json({"ok": bool(ok), "message": message})
            elif path == "/guard/remove":
                result = api.store.remove_dynamic(url)
                api.engine.invalidate()
                self.send_json(dict(result, ok=bool(result.get("ok"))))
            elif path in ("/guard/remove_allow", "/guard/unallow"):
                # 撤销放行（放行优先于一切拦截, 所以"拦不住"时先看这里）
                if not url:
                    self.send_json({"ok": False, "reason": "url 不能为空"}, 400)
                    return
                result = api.store.remove_allow(url)
                api.engine.invalidate()
                self.send_json(dict(result, ok=bool(result.get("ok"))))
            elif path == "/guard/clear_dynamic":
                result = api.store.clear_dynamic()
                api.engine.invalidate()
                self.send_json(dict(result, ok=True))
            elif path == "/guard/sysproxy":
                enable = str(form.get("enable", "")).strip().lower() in ("1", "true", "on", "yes")
                if api.proxyctl is None:
                    self.send_json({"ok": False, "reason": "系统代理控制不可用"}, 500)
                    return
                ok, msg = (api.proxyctl.enable() if enable else api.proxyctl.disable())
                api.settings.set("block_via_proxy", bool(enable), save=True)
                api.engine.invalidate()
                self.send_json({"ok": bool(ok), "message": msg, "status": api.proxyctl.status()})
            elif path == "/guard/config":
                # 与 Web 控制台同一套逻辑: 改总开关 / 各「拦截方式」（立刻生效）
                from . import control
                target = getattr(api, "runtime", None)
                if target is None:
                    self.send_json({"ok": False, "reason": "运行时不可用"}, 500)
                    return
                values = dict(form)
                if "enabled" not in values:
                    values["enabled"] = "1"
                ok, msg, state = control.apply(target, values, enable_sysproxy=True)
                self.send_json({"ok": bool(ok), "message": msg,
                                "state": state or {}, "status": api.status()})
            else:
                self.send_json({"ok": False, "error": "未知路径: %s" % path}, 404)
        except Exception as exc:
            self.send_json({"ok": False, "error": str(exc)}, 500)

    # ---------- 具体功能 ----------
    def _check(self, query):
        url = (query.get("url") or "").strip()
        if not url:
            return {"ok": False, "error": "缺少 url 参数"}
        mode = (query.get("mode") or "url").strip().lower()
        decision = self.api.engine.judge(url, mode=("host" if mode == "host" else "url"))
        return {"ok": True, "blocked": bool(decision.get("blocked")), "decision": decision,
                "blockpage": "%s/guard/blockpage?url=%s" % (self.api.base_url, url)}

    def _blockpage(self, query):
        url = (query.get("url") or "").strip()
        kind = (query.get("kind") or "userscript").strip().lower()
        mode = "host" if (query.get("mode") or "").strip().lower() == "host" else "url"
        decision = self.api.engine.judge(url, mode=mode)
        if not url:
            decision = dict(decision, url="(未提供目标地址)")
        return render_block_page(decision, api_base=self.api.base_url, kind=kind)


_DASH_CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:"Segoe UI","Microsoft YaHei",system-ui,sans-serif;background:#12121a;
color:#eef0f5;min-height:100vh;padding:26px 18px 60px}
.wrap{max-width:1080px;margin:0 auto}
.hero{display:flex;gap:16px;align-items:center;padding:22px 24px;border-radius:18px;
background:linear-gradient(135deg,rgba(220,53,69,.20),rgba(90,120,255,.16));
border:1px solid rgba(255,255,255,.09)}
.hero img,.hero svg{width:52px;height:52px}
.hero h1{font-size:21px}
.hero p{color:#b9bccb;font-size:13px;margin-top:5px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-top:16px}
.card{background:rgba(30,32,42,.85);border:1px solid rgba(255,255,255,.08);border-radius:16px;padding:16px 18px}
.card h3{font-size:12.5px;color:#9aa0b4;font-weight:600;letter-spacing:.6px;margin-bottom:9px}
.card .big{font-size:26px;font-weight:700}
.card .sub{font-size:12px;color:#8f94a8;margin-top:6px;line-height:1.6}
section{margin-top:20px}
section h2{font-size:15px;margin-bottom:10px;color:#cdd2e2}
table{width:100%;border-collapse:collapse;font-size:12.6px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid rgba(255,255,255,.07);vertical-align:top;word-break:break-all}
th{color:#98a0b6;font-weight:600;font-size:11.8px;text-transform:uppercase;letter-spacing:.4px}
tr:last-child td{border-bottom:none}
.badge{display:inline-block;padding:4px 10px;border-radius:999px;font-size:12px;border:1px solid rgba(255,255,255,.12)}
.badge.ok{background:rgba(25,135,84,.20);border-color:rgba(25,135,84,.5)}
.badge.no{background:rgba(220,53,69,.18);border-color:rgba(220,53,69,.5)}
.badge.warn{background:rgba(255,193,7,.14);border-color:rgba(255,193,7,.45)}
.row{display:flex;flex-wrap:wrap;gap:10px;align-items:center}
button,.btn{font:inherit;font-size:13px;padding:9px 15px;border-radius:10px;cursor:pointer;
border:1px solid rgba(255,255,255,.14);background:rgba(255,255,255,.07);color:#f1f2f7}
button:hover{background:rgba(255,255,255,.14)}
.btn.red{background:linear-gradient(135deg,#dc3545,#a52833);border-color:transparent;font-weight:600}
.btn.green{background:linear-gradient(135deg,#198754,#146c43);border-color:transparent;font-weight:600}
input[type=text]{flex:1;min-width:240px;padding:10px 12px;border-radius:10px;font-size:13px;
background:rgba(0,0,0,.35);border:1px solid rgba(255,255,255,.16);color:#fff}
code{background:rgba(0,0,0,.35);padding:2px 6px;border-radius:6px;font-family:Consolas,Menlo,monospace}
.muted{color:#8f94a8;font-size:12.4px;line-height:1.75}
a{color:#9ecbff;text-decoration:none}
"""

_DASH_SHIELD = """<svg viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
<path d="M32 4l22 8v18c0 14-9.4 24.6-22 30C19.4 54.6 10 44 10 30V12l22-8z"
 fill="rgba(90,120,255,.20)" stroke="#7d95ff" stroke-width="2.5"/>
<path d="M22 32.5l7.2 7.2L43 25" stroke="#b9c7ff" stroke-width="4"
 stroke-linecap="round" stroke-linejoin="round"/></svg>"""


def _esc(value):
    from html import escape
    return escape(str(value), quote=True)


def _card(title, big, sub=""):
    return ('<div class="card"><h3>%s</h3><div class="big">%s</div>'
            '<div class="sub">%s</div></div>' % (_esc(title), big, sub))


def _dashboard_html(api):
    """控制台页面（每次请求实时渲染, 数据来自内存与 guard/data）"""
    status = api.status()
    proxy = status.get("proxy") or {}
    sysproxy = status.get("sysproxy") or {}
    counters = (status.get("store") or {}).get("counters") or {}
    engine_info = (status.get("engine") or {}).get("info") or {}
    sys_on = bool(sysproxy.get("enabled"))
    parts = [
        "<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">",
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
        "<title>eyilianjie guard 控制台</title><style>", _DASH_CSS, "</style></head><body>",
        "<div class=\"wrap\">",
        "<div class=\"hero\">", _DASH_SHIELD,
        "<div><h1>eyilianjie guard 控制台 <span class=\"badge %s\">%s</span></h1>" % (
            "ok" if proxy.get("running") else "no",
            "代理运行中" if proxy.get("running") else "代理未运行"),
        "<p>真拦截层: 浏览器/系统代理指向 <code>%s:%s</code> 后, 检测判定为恶意的链接"
        "在任何页面都打不开 · 数据目录 <code>%s</code></p></div></div>" % (
            _esc(proxy.get("host")), _esc(proxy.get("port")), _esc(status.get("guard_dir"))),
        "<div class=\"grid\">",
        _card("判定次数", counters.get("judged", 0),
              "放行 %s · 拦截 %s · 异常 %s" % (counters.get("allowed", 0),
                                              counters.get("blocked", 0),
                                              counters.get("judge_errors", 0))),
        _card("已拦截", counters.get("blocked", 0),
              "HTTP %s · HTTPS %s" % (counters.get("blocked_http", 0),
                                      counters.get("blocked_https", 0))),
        _card("动态拦截集", "%s" % ((status.get("store") or {}).get("dynamic_hosts", 0) +
                                   (status.get("store") or {}).get("dynamic_urls", 0)),
              "域名 %s · URL %s（含来自 eyilianjie 检测记录的条目）" % (
                  (status.get("store") or {}).get("dynamic_hosts", 0),
                  (status.get("store") or {}).get("dynamic_urls", 0))),
        _card("eyilianjie 黑名单", engine_info.get("blacklist_size", 0),
              "白名单 %s 条 · ML: %s" % (engine_info.get("whitelist_size", 0),
                                        _esc(engine_info.get("ml_describe") or "无"))),
        "</div>",
    ]
    parts.append(_dash_switches(api, proxy, sysproxy, sys_on))
    parts.append(_dash_allow(api))
    parts.append(_dash_dynamic(api))
    parts.append(_dash_logs(api))
    parts.append(_dash_actions(api))
    parts.append(_dash_footer(api))
    parts.append("</div></body></html>")
    return "".join(parts)


def _dash_switches(api, proxy, sysproxy, sys_on):
    watch = api.logwatcher.stats if api.logwatcher is not None else {}
    return (
        "<section><h2>运行开关</h2><div class=\"card\"><div class=\"row\">"
        "<span class=\"badge %s\">系统代理: %s</span>"
        "<span class=\"badge %s\">本地代理 %s:%s</span>"
        "<span class=\"badge warn\">上游代理: %s</span>"
        "<button class=\"btn green\" onclick=\"guardToggleProxy(true)\">开启系统代理（走 guard）</button>"
        "<button class=\"btn red\" onclick=\"guardToggleProxy(false)\">关闭系统代理（还原）</button>"
        "<button class=\"btn\" onclick=\"location.reload()\">刷新</button>"
        "</div><div class=\"muted\" style=\"margin-top:10px\">"
        "开启后: Edge / Chrome / IE 等走系统代理的浏览器全部经过 guard；"
        "关闭则完全还原（guard 会记住开启前的设置, 不会破坏你原有的代理软件配置）。"
        "%s</div></div></section>" % (
            "ok" if sys_on else "no", "已开启" if sys_on else "未开启",
            "ok" if proxy.get("running") else "no",
            _esc(proxy.get("host")), _esc(proxy.get("port")),
            _esc(proxy.get("upstream_proxy") or "未设置（直连）"),
            ("<br>检测日志联动: 已扫描 %s 次, 累计导入 %s 条 URL / %s 条域名; 最近扫描 %s"
             % (_esc(watch.get("scans")), _esc(watch.get("imported_urls")),
                _esc(watch.get("imported_hosts")), _esc(watch.get("last_scan"))))
            if watch else ""))


def _dash_allow(api):
    """放行名单：页面上要能"看得见 + 一条一条撤掉"

    为什么单列一块: 放行优先于一切拦截, 是"我明明加了拦截却拦不住"的头号原因,
    以前页面上完全看不到它。
    """
    entries = api.store.allow_entries()
    rows = [(key, "域名") for key in entries.get("hosts") or []]
    rows += [(key, "URL") for key in entries.get("urls") or []]
    body = []
    for key, level in rows:
        body.append(
            "<tr><td>%s</td><td><span class=\"badge\">%s</span></td>"
            "<td><button type=\"button\" data-entry=\"%s\" "
            "onclick=\"guardRemoveAllow(this.getAttribute('data-entry'))\">移除</button></td></tr>"
            % (_esc(key), _esc(level), _esc(key)))
    if not body:
        body.append("<tr><td colspan=\"3\" class=\"muted\">放行名单是空的"
                    "（拦截页上的「误报？加入放行名单」会写进这里）。</td></tr>")
    return (
        "<section><h2>放行名单（这些地址会绕开一切拦截）</h2><div class=\"card\">"
        "<div class=\"row\" style=\"margin-bottom:10px\"><span class=\"badge warn\">共 %d 条</span>"
        "<span class=\"muted\">放行优先于一切拦截 —— 想拦某个地址却拦不住，先看它是不是在这里。</span>"
        "</div><table><thead><tr><th>条目</th><th>类型</th><th>操作</th></tr></thead>"
        "<tbody>%s</tbody></table></div></section>" % (len(rows), "".join(body)))


def _dash_dynamic(api):
    store = api.store
    rows = []
    for key, meta in list(store.dynamic_hosts.items())[-200:]:
        rows.append((key, "域名", meta))
    for key, meta in list(store.dynamic_urls.items())[-200:]:
        rows.append((key, "URL", meta))
    rows.sort(key=lambda item: (item[2] or {}).get("ts") or "", reverse=True)
    rows = rows[:12]
    body = []
    for key, level, meta in rows:
        body.append(
            "<tr><td>%s<br><span class=\"badge\">%s</span></td><td>%s<br><span class=\"muted\">%s</span></td>"
            "<td>%s</td><td><button type=\"button\" data-entry=\"%s\" "
            "onclick=\"guardRemove(this.getAttribute('data-entry'))\">移除</button></td></tr>" % (
                _esc(key), _esc(level), _esc((meta or {}).get("reason") or ""),
                _esc((meta or {}).get("source") or ""), _esc((meta or {}).get("ts") or ""),
                _esc(key)))
    if not body:
        body.append("<tr><td colspan=\"4\" class=\"muted\">暂无动态拦截条目。"
                    "在 eyilianjie 里检测到恶意链接后, 这里会自动多出对应条目（这就是"
                    "「检测说拦了, 别的页面也真打不开」的来源）。</td></tr>")
    return (
        "<section><h2>动态拦截集（来自 eyilianjie 检测结果 / 手动加入）</h2>"
        "<div class=\"card\"><div class=\"row\" style=\"margin-bottom:10px\">"
        "<span class=\"badge warn\">共 %d 条</span>"
        "<button onclick=\"guardClearDynamic()\">清空动态集</button></div>"
        "<table><thead><tr><th>条目</th><th>原因 / 来源</th><th>记录时间</th><th>操作</th></tr></thead>"
        "<tbody>%s</tbody></table></div></section>" % (
            len(store.dynamic_hosts) + len(store.dynamic_urls), "".join(body)))


def _dash_logs(api):
    logs = api.store.recent_logs(12)
    rows = []
    for item in logs:
        action = item.get("action") or ""
        rows.append(
            "<tr><td>%s</td><td><span class=\"badge %s\">%s</span></td><td>%s</td><td>%s</td><td>%s</td></tr>" % (
                _esc(item.get("time")), "no" if action == "blocked" else "ok",
                _esc("拦截" if action == "blocked" else "放行"),
                _esc(item.get("url") or ""), _esc(item.get("reason") or ""),
                _esc(item.get("source") or "")))
    if not rows:
        rows.append("<tr><td colspan=\"5\" class=\"muted\">暂无记录（默认只记录被拦截的请求; "
                    "如需记录全部请求, 把 guard/data/config.json 里 log.log_all_requests 设为 true）</td></tr>")
    return (
        "<section><h2>最近拦截 / 放行记录</h2><div class=\"card\">"
        "<table><thead><tr><th>时间</th><th>动作</th><th>目标</th><th>原因</th><th>来源</th></tr></thead>"
        "<tbody>%s</tbody></table></div></section>" % "".join(rows))


def _dash_actions(api):
    script_path = os.path.join(GUARD_DIR, "userscript", "eyilianjie_guard.user.js")
    return (
        "<section><h2>手动操作</h2><div class=\"card\">"
        "<div class=\"row\" style=\"margin-bottom:10px\">"
        "<input type=\"text\" id=\"blockInput\" placeholder=\"输入要拦截的 URL 或域名（会整站拦截）\">"
        "<button class=\"btn red\" onclick=\"guardAdd('block')\">加入拦截</button></div>"
        "<div class=\"row\">"
        "<input type=\"text\" id=\"allowInput\" placeholder=\"输入要放行 / 要撤销放行的 URL 或域名\">"
        "<button class=\"btn green\" onclick=\"guardAdd('allow')\">加入放行</button>"
        "<button class=\"btn\" onclick=\"guardRemoveAllowInput()\">移除放行</button></div>"
        "<div class=\"muted\" style=\"margin-top:12px\">"
        "浏览器脚本（推荐一起装, 点击链接前就能拦, 而且能显示拦截页）:<br>"
        "<code>%s</code><br>"
        "在浏览器里安装 Tampermonkey 后新建脚本, 把该文件内容粘进去保存即可。"
        "脚本默认调用 <code>%s</code>, 若改过 guard 端口请同步修改脚本里的 <code>GUARD_API</code>。</div>"
        "</div></section>" % (_esc(script_path), _esc(api.base_url)))


def _dash_footer(api):
    return ("<section><h2>说明</h2><div class=\"card\"><div class=\"muted\">"
            "1) guard 只**新增文件**, 没有修改 eyilianjie 的任何现有文件; 黑名单 / 检测日志 / 配置"
            "都只读, 数据只写在自己的 <code>guard\\data</code> 里。<br>"
            "2) 判定顺序: guard 放行名单 → eyilianjie 白名单 → 动态拦截集（检测记录联动 / 手动）→"
            " eyilianjie 黑名单 → 成人规则 → ML 通道 → 启发式规则。<br>"
            "3) HTTPS 是在 CONNECT 阶段按域名拦截的（不需要证书）; 命中时浏览器会显示自己的错误页,"
            " 这是不装根证书的必然结果 —— 想连 HTTPS 也看到自定义拦截页, 用油猴脚本那条通道。<br>"
            "4) 需要临时停用拦截: 关闭系统代理, 或直接关掉本进程。<br>"
            "5) 命令行: <code>python -m guard status|check &lt;url&gt;|allow &lt;url&gt;|unallow &lt;url&gt;|"
            "block &lt;url&gt;|remove &lt;url&gt;|sysproxy on|off|selftest</code><br>"
            "（注意 <code>remove</code> 删的是「动态拦截集」, 撤销放行要用 <code>unallow</code>）"
            "</div></div></section>"
            "<script>" + _DASH_JS + "</script>")


_DASH_JS = """
function guardPost(path, data, reload){
  var body = Object.keys(data).map(function(k){
    return encodeURIComponent(k) + '=' + encodeURIComponent(data[k]); }).join('&');
  fetch(path, {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:body})
    .then(function(r){ return r.json(); })
    .then(function(j){
      if (!j.ok) { alert('操作失败: ' + (j.reason || j.error || '未知')); return; }
      if (j.message) alert(j.message);
      if (reload !== false) location.reload();
    })
    .catch(function(e){ alert('请求失败: ' + e); });
}
function guardAdd(kind){
  var id = (kind === 'block') ? 'blockInput' : 'allowInput';
  var el = document.getElementById(id);
  var value = (el && el.value || '').trim();
  if (!value) { alert('请输入 URL 或域名'); return; }
  guardPost('/guard/' + kind, {url: value});
}
function guardRemove(entry){
  if (!confirm('从动态拦截集移除: ' + entry + ' ?')) return;
  guardPost('/guard/remove', {url: entry});
}
function guardRemoveAllow(entry){
  if (!confirm('从放行名单移除: ' + entry + ' ?\\n（移除后它会重新参与拦截判定）')) return;
  guardPost('/guard/remove_allow', {url: entry});
}
function guardRemoveAllowInput(){
  var el = document.getElementById('allowInput');
  var value = (el && el.value || '').trim();
  if (!value) { alert('请输入要撤销放行的 URL 或域名'); return; }
  guardRemoveAllow(value);
}
function guardClearDynamic(){
  if (!confirm('清空动态拦截集? (eyilianjie 检测日志里已有的恶意记录会保留在日志里, 下次日志更新时会再次导入)')) return;
  guardPost('/guard/clear_dynamic', {});
}
function guardToggleProxy(on){
  guardPost('/guard/sysproxy', {enable: on ? '1' : '0'});
}
document.addEventListener('keydown', function(e){
  if (e.key === 'Enter' && (e.target.id === 'blockInput' || e.target.id === 'allowInput')) {
    guardAdd(e.target.id === 'blockInput' ? 'block' : 'allow');
  }
});
"""
