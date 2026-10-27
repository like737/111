"""
命令行入口: `python -m guard <命令>`

命令:
  run [--sysproxy] [--no-api] [--no-logwatch]   启动拦截层（前台, Ctrl+C 停止）
  status                                        查看运行状态（优先问正在运行的 guard）
  check <url> [--host]                          判定一个 URL
  block <url> / allow <url> / remove <url>      手动加黑 / 放行 / 从动态集移除
  sysproxy on|off|status                        系统代理开关
  doctor                                        环境体检: 端口被谁占了 / 为什么打不开
  selftest [--port 18888]                       隔离自测（不碰系统设置, 用于验收）
  userscript                                    打印油猴脚本路径与安装说明
"""

import argparse
import json
import os
import urllib.parse
import urllib.request

from . import GUARD_DIR, VERSION


def _api_base(settings):
    return "http://%s:%d" % (settings.get("api.host", "127.0.0.1"),
                             int(settings.get("api.port", 8899) or 8899))


def _api_request(settings, path, data=None, timeout=3.0):
    """调用运行中的 guard 控制台接口; 失败返回 None"""
    url = _api_base(settings) + path
    try:
        if data is None:
            with urllib.request.urlopen(url, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        body = urllib.parse.urlencode(data).encode("utf-8")
        req = urllib.request.Request(url, data=body, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None


def _print(obj):
    print(json.dumps(obj, ensure_ascii=False, indent=2))


def build_parser():
    parser = argparse.ArgumentParser(prog="python -m guard",
                                     description="eyilianjie guard —— 真拦截层 (v%s)" % VERSION)
    sub = parser.add_subparsers(dest="cmd")

    p_run = sub.add_parser("run", help="启动代理+控制台（前台运行）")
    p_run.add_argument("--sysproxy", action="store_true", help="同时开启系统代理")
    p_run.add_argument("--no-api", action="store_true", help="不启动控制台")
    p_run.add_argument("--no-logwatch", action="store_true", help="不启动检测日志联动")

    sub.add_parser("status", help="查看运行状态")

    p_check = sub.add_parser("check", help="判定一个 URL")
    p_check.add_argument("url")
    p_check.add_argument("--host", action="store_true", help="只按域名判定（模拟 HTTPS CONNECT）")

    for name, help_text in (("block", "手动加入拦截（写动态拦截集）"),
                            ("allow", "加入放行名单（会绕开一切拦截）"),
                            ("remove", "从动态拦截集移除"),
                            ("unallow", "从放行名单移除（撤销放行）")):
        item = sub.add_parser(name, help=help_text)
        item.add_argument("url")

    p_sp = sub.add_parser("sysproxy", help="系统代理开关")
    p_sp.add_argument("action", choices=["on", "off", "status"])

    p_test = sub.add_parser("selftest", help="隔离自测（不修改系统设置）")
    p_test.add_argument("--port", type=int, default=18888, help="测试用代理端口（默认 18888）")

    p_doc = sub.add_parser("doctor", help="环境体检: 为什么打不开 / 端口被谁占了")
    p_doc.add_argument("--web-port", type=int, default=None,
                       help="eyilianjie Web 端口（默认 5000, 或环境变量 EY_PORT）")

    sub.add_parser("userscript", help="油猴脚本路径与安装说明")
    return parser


def main(argv=None):
    # 控制台编码兜底: 中文/符号在 GBK 控制台或重定向到文件时会抛 UnicodeEncodeError
    try:
        import sys as _sys
        if hasattr(_sys.stdout, "reconfigure"):
            _sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            _sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    from .settings import load as load_settings
    parser = build_parser()
    args = parser.parse_args(argv)
    settings = load_settings()
    return _dispatch(args, parser, settings)


def _dispatch(args, parser, settings):
    if args.cmd in (None,):
        parser.print_help()
        return 0

    if args.cmd == "run":
        import time
        from .runtime import GuardRuntime
        runtime = GuardRuntime(settings)
        print(runtime.banner())
        results = runtime.start(enable_sysproxy=args.sysproxy,
                                start_api=not args.no_api,
                                start_logwatch=not args.no_logwatch)
        for name, (ok, msg) in results.items():
            print("[guard] %-9s %s" % (name + ":", msg))
        print("[guard] 按 Ctrl+C 停止（停止时会按配置把系统代理还原）")
        try:
            while True:
                time.sleep(1.0)
        except KeyboardInterrupt:
            print()
        runtime.stop()
        return 0

    if args.cmd == "selftest":
        from .selftest import run_selftest
        return run_selftest(settings, port=args.port)

    if args.cmd == "doctor":
        from .doctor import run as doctor_run
        return doctor_run(settings, web_port=args.web_port)

    if args.cmd == "userscript":
        path = os.path.join(GUARD_DIR, "userscript", "eyilianjie_guard.user.js")
        print("油猴脚本: %s" % path)
        print("安装: 浏览器装 Tampermonkey → 新建脚本 → 粘贴该文件内容 → 保存")
        print("脚本内 GUARD_API 默认: %s" % _api_base(settings))
        return 0

    if args.cmd == "status":
        remote = _api_request(settings, "/guard/status")
        if remote:
            _print(remote)
            return 0
        from .proxyctl import SysProxyCtl
        _print({"api": {"running": False, "base": _api_base(settings)},
                "hint": "guard 当前没有运行（控制台接口不可达）; 用 python -m guard run 启动",
                "sysproxy": SysProxyCtl(settings).status()})
        return 0

    if args.cmd == "check":
        url = args.url
        if args.host:
            parsed = urllib.parse.urlsplit(url if "://" in url else "http://" + url)
            url = "https://%s/" % (parsed.hostname or "")
        remote = _api_request(settings, "/guard/check?url=" + urllib.parse.quote(url))
        if remote:
            _print(remote)
            return 1 if remote.get("blocked") else 0
        from .engine import Engine
        from .store import Store
        store = Store()
        engine = Engine(settings, store)
        decision = engine.judge(url, mode=("host" if args.host else "url"))
        _print(decision)
        return 1 if decision.get("blocked") else 0

    if args.cmd in ("block", "allow", "remove", "unallow"):
        remote = _api_request(settings, "/guard/" + args.cmd, {"url": args.url})
        if remote:
            _print(remote)
            return 0 if remote.get("ok", True) else 1
        from .store import Store
        store = Store()
        if args.cmd == "block":
            _print(store.add_dynamic(args.url, reason="命令行手动拦截",
                                     category="手动拦截", source="manual"))
            return 0
        if args.cmd == "allow":
            _print(store.add_allow(args.url, note="命令行放行"))
            return 0
        if args.cmd == "unallow":
            result = store.remove_allow(args.url)
            _print(result)
            return 0 if result.get("ok") else 1
        _print(store.remove_dynamic(args.url))
        return 0

    if args.cmd == "sysproxy":
        from .proxyctl import SysProxyCtl
        ctl = SysProxyCtl(settings)
        if args.action == "status":
            _print(ctl.status())
            return 0
        ok, msg = (ctl.enable() if args.action == "on" else ctl.disable())
        print(("[OK] " if ok else "[失败] ") + msg)
        _print(ctl.status())
        return 0 if ok else 1

    parser.print_help()
    return 0
