"""
拦截开关 / 「拦截方式」的统一控制层。

Web 端控制台（templates/guard.html + web_app.py 里的 /guard 路由）和 guard 自己的
控制台/API（127.0.0.1:8899）都调用这里, 保证两边行为完全一致。

为什么"点一下就能立刻生效"（不需要重启任何进程）:
  * guard 的判定引擎**每次判定都重新读配置**（engine.py:143/181/195/210/224/225、
    proxy.py:252 都是 `settings.get("...")`）, 所以改完配置只需清一次判定缓存;
  * "检测即真封"是运行时给 `detector.detect` 挂的一层包装, 可以随时挂上/摘下;
  * 系统代理是 HKCU 注册表项, 由 proxyctl 开关（免管理员, 可逐项还原原值）。
"""

from . import VERSION
from .settings import load as load_settings

# ---------------------------------------------------------------------------
# 「拦截方式」清单: Web 上勾的就是这些
#   kind=proxy    本地代理通道（决定是否把系统代理指向 guard）
#   kind=detector 运行时挂载（检测即真封）
#   kind=rule     判定规则开关（直接写进 guard 配置的 block.* 键）
# ---------------------------------------------------------------------------
MODES = [
    {
        "key": "block_via_proxy", "kind": "proxy", "label": "本地代理拦截",
        "hint": "浏览器流量走 guard 代理（127.0.0.1:8888）：HTTP 按完整 URL 拦，"
                "HTTPS 在连接阶段按域名拦（不需要装证书）。勾上它并点「开始拦截」会"
                "自动把系统代理指向 guard；取消则还原你原来的代理设置。",
    },
    {
        "key": "detect_block", "kind": "detector", "label": "检测即真封",
        "hint": "eyilianjie 里一旦判为恶意，该链接立刻写入 guard 拦截集："
                "换个页面 / 直接在地址栏打开也打不开（不是只在页面上提示）。",
    },
    {
        "key": "block.blacklist", "kind": "rule", "label": "黑名单（18 万条）",
        "hint": "命中 eyilianjie 黑名单（含精确 / 后缀 / 关键词 6 级匹配）即拦。",
    },
    {
        "key": "block.adult", "kind": "rule", "label": "成人 / 赌博关键词规则",
        "hint": "域名命中成人、赌博类关键词（如 porn、casino）即拦，不依赖黑名单。",
    },
    {
        "key": "block.heuristic", "kind": "rule", "label": "启发式规则（恶意模式库）",
        "hint": "复用 eyilianjie 的启发式判定（可疑 TLD、诱导词、恶意 URL 模式等）。",
    },
    {
        "key": "block.ml_convict", "kind": "rule", "label": "ML 通道（拦截档）",
        "hint": "机器学习「参与拦截」的模型（当前是路径模型 path_model）达阈值即拦。",
    },
    {
        "key": "block.ml_hint", "kind": "rule", "label": "ML 通道（提示档也拦）",
        "hint": "默认关闭。开启后，只用于提示的模型（域名模型）也会参与拦截 —— 更严，误报也会变多。",
    },
    {
        "key": "block.dynamic_from_log", "kind": "rule", "label": "检测日志联动",
        "hint": "每 2 秒只读扫描 eyilianjie 的 detection_log.json，把历史上判过恶意的目标并入拦截集。",
    },
    {
        "key": "block.block_https_tunnel", "kind": "rule", "label": "HTTPS 隧道拦截",
        "hint": "在 HTTPS 连接(CONNECT)阶段按域名拦截（浏览器会显示自己的错误页）。关掉 = HTTPS 全部放行。",
    },
]

RULE_KEYS = [m["key"] for m in MODES if m["kind"] == "rule"]


def _bool(value, default=False):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ("1", "true", "on", "yes", "y", "t")


def _sysproxy_status(settings, proxyctl=None):
    if proxyctl is not None:
        try:
            return proxyctl.status()
        except Exception:
            pass
    try:
        from .proxyctl import SysProxyCtl
        return SysProxyCtl(settings, verbose=False).status()
    except Exception as exc:
        return {"supported": False, "enabled": False, "error": str(exc)}


def snapshot(runtime=None, settings=None):
    """当前「拦截方式」的勾选状态: {mode_key: bool, "enabled": bool}"""
    conf = settings if settings is not None else (
        runtime.settings if runtime is not None else load_settings())
    detector = None
    if runtime is not None:
        detector = getattr(getattr(runtime, "engine", None), "detector", None)
    patched = bool(getattr(detector, "_guard_patched", False)) if detector is not None else False
    sp = _sysproxy_status(conf, getattr(runtime, "proxyctl", None))
    proxy_on = bool(sp.get("active"))       # 以注册表实际生效为准（不是"我们以为开了"）

    out = {"enabled": bool(conf.get("enabled", True))}
    for key in RULE_KEYS:
        out[key] = bool(conf.get(key, True))
    # 「本地代理拦截」勾的是"用户意图"（持久化在 guard 配置里）；
    # 实际是否生效看系统代理状态（sysproxy_active / sysproxy.enabled_by_us）。
    out["block_via_proxy"] = bool(conf.get("block_via_proxy", True))
    out["sysproxy_active"] = proxy_on
    out["detect_block"] = patched
    return out


def modes_for_ui(runtime=None, settings=None):
    """把 MODES 元数据与当前取值合成一份给前端渲染的列表"""
    values = snapshot(runtime, settings)
    items = []
    for mode in MODES:
        item = dict(mode)
        item["value"] = values.get(mode["key"], False)
        item["group"] = "拦截通道" if mode["kind"] != "rule" else "判定规则"
        items.append(item)
    return items


def ui_state(runtime=None, logs_limit=20):
    """给 Web 页面 / API 用的统一状态结构（guard 未运行时也能给出合理值）"""
    conf = runtime.settings if runtime is not None else load_settings()
    values = snapshot(runtime, conf)
    state = {
        "version": VERSION,
        "available": True,
        "running": bool(runtime is not None and getattr(runtime.api, "is_running", lambda: False)()),
        "enabled": values.get("enabled", False),
        "detector_patched": values.get("detect_block", False),
        "modes": modes_for_ui(runtime, conf),
        "sysproxy": _sysproxy_status(conf, getattr(runtime, "proxyctl", None)),
        "proxy": {"host": conf.get("proxy.host"), "port": conf.get("proxy.port"),
                  "upstream_proxy": conf.get("proxy.upstream_proxy") or ""},
        "api_base": "http://%s:%s" % (conf.get("api.host", "127.0.0.1"),
                                      conf.get("api.port", 8899)),
        "counters": {}, "engine": {}, "store": {}, "logwatch": {}, "logs": [],
        # 放行名单 / 动态拦截集（页面上要"看得见 + 点一下就能撤"）
        "allow": {"hosts": [], "urls": []},
        "dynamic": {"count": 0, "entries": []},
        "rules_version": "",
    }
    if runtime is None:
        return state
    try:
        full = runtime.api.status()
    except Exception as exc:
        state["error"] = str(exc)
        return state
    for key in ("proxy", "store", "engine"):
        if isinstance(full.get(key), dict):
            state[key] = full[key]
    if isinstance(full.get("sysproxy"), dict):
        state["sysproxy"] = full["sysproxy"]
    if isinstance(full.get("logwatch"), dict):
        state["logwatch"] = full["logwatch"]
    state["counters"] = (full.get("store") or {}).get("counters") or {}
    try:
        state["logs"] = runtime.store.recent_logs(int(logs_limit))
    except Exception:
        state["logs"] = []
    try:
        state["allow"] = runtime.store.allow_entries()
    except Exception:
        state["allow"] = {"hosts": [], "urls": []}
    try:
        state["dynamic"] = runtime.store.dynamic_entries()
    except Exception:
        state["dynamic"] = {"count": 0, "entries": []}
    try:
        state["rules_version"] = runtime.store.rules_version()
    except Exception:
        state["rules_version"] = ""
    return state


# ---------------------------------------------------------------- 应用勾选
def ensure_components(runtime):
    """按需启动 guard 的运行组件（本地代理 / 控制台 / 检测日志联动）。

    为什么需要: 如果 guard 是以 `enabled=false` 启动的（或只跑了 web_app.py），
    "点开始拦截"必须先让代理真的在监听，否则把系统代理指过去 = 浏览器流量打到
    没人监听的端口（表现为所有网页打不开）。幂等: 已在运行就直接返回。
    """
    steps = []
    proxy = getattr(runtime, "proxy", None)
    if proxy is not None and not proxy.is_running():
        try:
            ok, msg = proxy.start()
            steps.append(msg)
        except Exception as exc:
            steps.append("本地代理启动失败: %s" % exc)
    api = getattr(runtime, "api", None)
    if api is not None and not api.is_running():
        try:
            api.start()
        except Exception as exc:
            steps.append("控制台启动失败: %s" % exc)
    watcher = getattr(runtime, "logwatcher", None)
    if watcher is not None:
        try:
            if watcher.ident is None:          # 线程只能 start 一次
                watcher.start()
            watcher.scan()
        except Exception as exc:
            steps.append("检测日志联动启动失败: %s" % exc)
    return [s for s in steps if s]


def apply(runtime, values, enable_sysproxy=True):
    """把 Web 上的勾选落到运行时（立刻生效）。

    values: {"enabled": bool, "block_via_proxy": bool, "detect_block": bool,
             "block.blacklist": bool, ...}（缺省项保持原值）
    返回 (ok, message, state)
    """
    if runtime is None:
        return False, "拦截层未启动", None
    conf = runtime.settings
    enabled = _bool(values.get("enabled"), True)

    # 0) 先确保拦截组件在运行（幂等）—— 这样后面把系统代理指过来时一定有人在监听
    steps = []
    if enabled:
        steps.extend(ensure_components(runtime))
    proxy_obj = getattr(runtime, "proxy", None)
    proxy_ok = True if proxy_obj is None else bool(proxy_obj.is_running())

    # 1) 总开关 + 判定规则（只写 guard 自己的配置, 不碰 eyilianjie 的 config.json）
    conf.set("enabled", enabled, save=False)
    changed = []
    for key in RULE_KEYS:
        if key in values:
            want = _bool(values.get(key), True)
            if bool(conf.get(key, True)) != want:
                changed.append("%s→%s" % (key.split(".")[-1], "开" if want else "关"))
            conf.set(key, want, save=False)
    # 「本地代理拦截」: 记住用户意图（下次打开页面仍是这个选择）
    want_proxy = _bool(values.get("block_via_proxy"), bool(conf.get("block_via_proxy", True)))
    conf.set("block_via_proxy", want_proxy, save=False)
    conf.save()

    # 2) 检测即真封: 挂上 / 摘下 detector.detect 的包装
    detector = getattr(getattr(runtime, "engine", None), "detector", None)
    if detector is not None:
        if enabled and _bool(values.get("detect_block"), True):
            if runtime.patch_detector(detector):
                steps.append("已开启「检测即真封」")
        elif getattr(detector, "_guard_patched", False):
            runtime.unpatch_all()
            steps.append("已关闭「检测即真封」")

    # 3) 系统代理（guard 会先记录原值, 关闭时还原）
    if enable_sysproxy and runtime.proxyctl is not None:
        if enabled and want_proxy:
            if not proxy_ok:
                steps.append("本地代理没能启动, 已跳过开启系统代理（避免浏览器流量打到没人监听的端口）")
            else:
                _ok, msg = runtime.proxyctl.enable()
                steps.append(msg)
        else:
            _ok, msg = runtime.proxyctl.disable()
            steps.append(msg)

    # 4) 清判定缓存 → 立刻按新配置判定
    runtime.engine.invalidate()
    if changed:
        steps.insert(0, "已更新: " + "、".join(changed))
    if not enabled:
        steps.insert(0, "拦截已停止（判定直接放行）")
    return True, " · ".join([s for s in steps if s]) or "已是最新状态", ui_state(runtime, 20)


# ---------------------------------------------------------------- 名单管理
def entry(runtime, action, url):
    """动态拦截集 / 放行名单的增删（Web 端与 API 共用）"""
    if runtime is None:
        return False, "拦截层未启动"
    url = (url or "").strip()
    if not url and action != "clear_dynamic":
        return False, "请输入 URL 或域名"
    if action == "block":
        conflict = None
        try:
            conflict = runtime.store.match_allow(url)
        except Exception:
            conflict = None
        if conflict:
            # 放行优先于一切拦截: 不提示的话用户会看到"已加入拦截"却永远拦不住
            return False, ("已在放行名单中: %s —— guard 的放行优先于一切拦截，"
                           "请先在放行名单里移除它，再重新加入拦截" % conflict)
        runtime.store.add_dynamic(url, reason="从 Web 控制台手动加入拦截",
                                  category="手动拦截", source="manual")
        runtime.engine.invalidate()
        return True, ("已加入拦截: %s%s（浏览器侧最多 5 秒内生效；想立刻生效，"
                      "点扩展弹窗里的「清空判定缓存」）") % (url, _entry_note(runtime))
    if action == "allow":
        runtime.store.add_allow(url, note="从 Web 控制台放行")
        runtime.engine.invalidate()
        return True, "已放行: %s" % url
    if action == "remove":
        runtime.store.remove_dynamic(url)
        runtime.engine.invalidate()
        return True, "已从动态拦截集移除: %s" % url
    if action == "remove_allow":
        result = runtime.store.remove_allow(url)
        runtime.engine.invalidate()
        removed = list(result.get("removed") or [])
        if not removed:
            return False, "放行名单里没有这条记录: %s（可能已经移除过，或地址写错了）" % url
        return True, "已从放行名单移除 %d 条: %s" % (len(removed), "、".join(removed))
    if action == "clear_dynamic":
        runtime.store.clear_dynamic()
        runtime.engine.invalidate()
        return True, "已清空动态拦截集"
    return False, "未知操作: %s" % action


def _entry_note(runtime):
    """加完拦截后的"为什么可能还没生效"提醒（总开关 / 系统代理）。

    很多"我明明加了拦截却拦不住"其实是这两个原因之一 —— 直接在操作结果里说清楚。
    """
    tips = []
    try:
        if not bool(runtime.settings.get("enabled", True)):
            tips.append("拦截总开关当前是「已停止」，要真正生效请点【开始拦截】")
    except Exception:
        pass
    try:
        proxyctl = getattr(runtime, "proxyctl", None)
        if (proxyctl is not None
                and bool(runtime.settings.get("block_via_proxy", True))
                and not bool(proxyctl.status().get("active"))):
            tips.append("系统代理还没指向 guard（浏览器请求目前不经过它）")
    except Exception:
        pass
    return ("（提示: %s）" % "；".join(tips)) if tips else ""
