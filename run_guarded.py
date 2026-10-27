"""
带拦截启动 eyilianjie（方案 D 入口）—— **不改 web_app.py 一行**

它做三件事:
  1) 导入 web_app（只建立 app / config / detector, 不会启动服务）;
  2) 启动 guard: 本地代理(8888) + 控制台(8899) + 检测日志联动;
  3) 在内存里给 detector.detect 包一层: 一旦判定为恶意 → 立刻写进 guard 动态拦截集,
     于是"检测说已拦截"的链接, 在任何浏览器/任何页面都真的打不开。

启动方式:  python run_guarded.py        （原来的 `python web_app.py` 行为完全不变）
停止:      在这个窗口按 Ctrl+C（会按配置把系统代理还原）
"""

import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from guard import VERSION                      # noqa: E402
from guard import settings as guard_settings   # noqa: E402
from guard.runtime import GuardRuntime         # noqa: E402


def _port_owner(port):
    """谁占着这个端口（127.0.0.1 或 0.0.0.0 都算）; 没人占返回 None"""
    try:
        from guard.doctor import _proc_name, listeners
    except Exception:
        return None
    rows = [r for r in listeners(port) if r["addr"] in ("127.0.0.1", "0.0.0.0", "::", "::1")]
    if not rows:
        return None
    row = rows[0]
    name = _proc_name(row["pid"])
    other = [r for r in rows if r["addr"] not in ("127.0.0.1", "0.0.0.0", "::", "::1")]
    if other:
        name += "/%s" % _proc_name(other[0]["pid"])
    return "%s (PID %d)" % (name, row["pid"])


def _can_bind(host, port):
    import socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind((host, port))
        return True
    except OSError:
        return False
    finally:
        sock.close()


def _avoid_port_conflict(port):
    """避开\"服务启动了但 127.0.0.1 打不开\"的坑。

    两种真实会踩的情况（都能在这里被自动躲开）:
      * 外设/游戏软件（实测: 罗技 G HUB 的 CS_GO_Arx_Applet.exe）占了 127.0.0.1:5000。
        Windows 上具体地址 127.0.0.1 优先于通配地址 0.0.0.0, 于是 eyilianjie 绑的
        0.0.0.0:5000 收不到 127.0.0.1 的请求 —— 日志照打, 浏览器就是打不开。
      * 已经跑着另一个 eyilianjie 实例（例如手动 python web_app.py）: Windows 的
        SO_REUSEADDR 允许两个进程都绑 0.0.0.0:5000, 请求落到谁身上随机。
    """
    owner = _port_owner(port)
    if owner is None and _can_bind("127.0.0.1", port):
        return port, None
    for candidate in (5080, 5001, 8080, 8090):
        if _port_owner(candidate) is None and _can_bind("127.0.0.1", candidate):
            return candidate, ("端口 %d 已被 %s 占用" % (port, owner or "其它程序"))
    return port, ("端口 %d 已被 %s 占用, 且没找到可用备用端口（仍按原端口启动, 可能打不开）"
                  % (port, owner or "其它程序"))


def main():
    # 端口: 默认 5000（与 eyilianjie 原行为一致）。
    #   显式指定（--port / EY_PORT）→ 完全按你说的来, 不自动改;
    #   没显式指定        → 如果 5000 被别的程序抢了, 自动换到可用端口并打印原因,
    #                       避免出现\"日志说启动了但 http://127.0.0.1:5000 打不开\"。
    explicit = False
    port = 5000
    if os.environ.get("EY_PORT"):
        try:
            port = int(os.environ["EY_PORT"])
            explicit = True
        except ValueError:
            print("[guard] 环境变量 EY_PORT 不是合法端口, 忽略")
    if "--port" in sys.argv:
        try:
            port = int(sys.argv[sys.argv.index("--port") + 1])
            explicit = True
        except (IndexError, ValueError):
            print("[guard] --port 参数无效, 继续使用 %d" % port)

    cfg = guard_settings.load()
    print("=" * 64)
    print("  eyilianjie + guard v%s —— 检测即真封（方案 C+D）" % VERSION)
    print("=" * 64)
    print("  提示: 控制台 %s/ 可一键开启/关闭系统代理、查看拦截记录"
          % ("http://%s:%d" % (cfg.get("api.host", "127.0.0.1"),
                               int(cfg.get("api.port", 8899) or 8899))))

    if not explicit:
        chosen, why = _avoid_port_conflict(port)
        if why:
            print("[guard] %s" % why)
        if chosen != port:
            print("[guard] 已自动改用 %d → 请访问 http://127.0.0.1:%d/  （想固定端口: %s）"
                  % (chosen, chosen, "python run_guarded.py --port <端口>"))
            port = chosen
    else:
        owner = _port_owner(port)
        if owner or not _can_bind("127.0.0.1", port):
            print("[guard] 注意: 你指定的端口 %d 已被 %s 占用 —— Windows 上 127.0.0.1 优先于 0.0.0.0,"
                  "\n        浏览器访问 http://127.0.0.1:%d/ 可能打不开（诊断: python -m guard doctor）"
                  % (port, owner or "其它程序", port))
    print("[guard] Web 入口: http://127.0.0.1:%d/" % port)

    # 1) 载入 eyilianjie（模块级只建 app/config/detector; web_app.py 末尾有 __main__ 守卫）
    import web_app
    print("[guard] 已载入 eyilianjie（web_app.py 未被修改, 黑名单 %d 条）"
          % len(getattr(web_app.detector, "_blacklist", {}) or {}))

    # 2) 组装 guard（复用 web_app.detector, 不重复加载黑名单与模型）
    runtime = GuardRuntime(cfg, detector=web_app.detector)
    print(runtime.banner())
    if bool(cfg.get("enabled", True)):
        results = runtime.start(enable_sysproxy=False)
        for name, (ok, msg) in results.items():
            print("[guard] %-9s %s" % (name + ":", msg))
    else:
        print("[guard] 总开关当前是关闭状态（guard\\data\\config.json 的 enabled=false）: "
              "本次不主动启动拦截组件")
        print("[guard] 想拦的时候不用改配置 —— 打开 Web 端 → 导航栏「拦截」→ 点【开始拦截】，"
              "会在运行时把代理/控制台/日志联动一起启动")

    # 3) 检测即真封（只有总开关开启时才挂; 关闭状态下 Web 端点【开始拦截】会自动挂上）
    if bool(cfg.get("enabled", True)):
        runtime.patch_detector(web_app.detector)
    else:
        print("[guard] 「检测即真封」暂未挂载（点【开始拦截】时会自动挂上）")

    # 3.5) 把运行时交给 Web 端: 页面上的「拦截控制台」直接复用它
    #      （不注册就会让 Web 端再启动一份 guard, 那样代理端口会冲突）
    web_app.attach_guard(runtime)

    # 4) 用 eyilianjie 原本的方式启动 Web 服务
    #    （debug=False: Werkzeug 的 reloader 会起两个进程, 会抢代理端口）
    try:
        web_app.run_web(host="0.0.0.0", port=port, debug=False)
    except KeyboardInterrupt:
        pass
    finally:
        runtime.stop()


if __name__ == "__main__":
    main()
