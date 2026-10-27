"""
运行时编排: 组装并启停 guard 的全部组件

同时提供"检测即真封"的运行时挂载（方案 D 的核心）:
  `patch_detector(detector)` 会把 eyilianjie 的 `Detector.detect()` 包一层 ——
  原文照旧返回（不改变它的行为与返回值）, 但一旦判定为恶意,
  立刻把目标写进 guard 自己的动态拦截集 → 浏览器再用任何方式打开都打不开。
  这是纯内存包装: 不改 web_app.py / detector.py, 不写 eyilianjie 任何文件。
"""

import time

from . import GUARD_DIR, PROJECT_ROOT, VERSION, urlutil
from .api import GuardApi
from .engine import Engine
from .logwatch import LogWatcher
from .proxy import ProxyServer
from .proxyctl import SysProxyCtl
from .settings import Settings
from .store import Store


class GuardRuntime:
    def __init__(self, settings=None, detector=None, verbose=True):
        self.settings = settings or Settings().load()
        self.verbose = verbose
        self._bootstrap_config_file()
        self.store = Store(max_log=int(self.settings.get("log.max_entries", 2000) or 2000))
        self.engine = Engine(self.settings, self.store, detector=detector, verbose=verbose)
        self.proxyctl = SysProxyCtl(self.settings, verbose=verbose)
        self.proxy = ProxyServer(self.engine, self.store, self.settings,
                                 api_base=self.api_base, verbose=verbose)
        self.logwatcher = LogWatcher(
            self.engine, self.store,
            interval=float(self.settings.get("logwatch.interval", 2.0) or 2.0),
            import_history=bool(self.settings.get("logwatch.import_history", True)),
            history_limit=int(self.settings.get("logwatch.max_entries", 20000) or 20000),
            verbose=verbose)
        self.api = GuardApi(self.engine, self.store, self.settings, proxy=self.proxy,
                            proxyctl=self.proxyctl, logwatcher=self.logwatcher,
                            runtime=self, verbose=verbose)
        self.patched = []
        self._originals = {}
        self.started_at = None

    # ================= 基础信息 =================
    def _bootstrap_config_file(self):
        """首次启动时把默认配置写到 guard\\data\\config.json（方便用户直接查看/修改）"""
        from .settings import CONFIG_FILE
        import os
        if not os.path.exists(CONFIG_FILE):
            self.settings.save()

    @property
    def api_base(self):
        return "http://%s:%d" % (self.settings.get("api.host", "127.0.0.1"),
                                 int(self.settings.get("api.port", 8899) or 8899))

    def banner(self):
        info = self.engine.info or {}
        lines = [
            "=" * 62,
            "  eyilianjie guard v%s —— 真拦截层（方案 C+D+F）" % VERSION,
            "=" * 62,
            "  eyilianjie 目录: %s" % PROJECT_ROOT,
            "  guard 目录    : %s" % GUARD_DIR,
            "  判定组件      : 黑名单 %s 条 | ML: %s" % (
                info.get("blacklist_size", "?"), info.get("ml_describe") or "无"),
            "  本地代理      : %s:%s" % (self.settings.get("proxy.host"),
                                        self.settings.get("proxy.port")),
            "  控制台        : %s/" % self.api_base,
            "=" * 62,
        ]
        return "\n".join(lines)

    # ================= 启停 =================
    def start(self, enable_sysproxy=False, start_proxy=True, start_api=True,
              start_logwatch=True):
        """启动各组件; 返回 {组件: (ok, 消息)}"""
        results = {}
        if start_proxy:
            results["proxy"] = self.proxy.start()
        if start_api:
            results["api"] = self.api.start()
        if start_logwatch:
            self.logwatcher.start()
            try:
                self.logwatcher.scan(force=True)     # 先把 eyilianjie 已有检测结果并进来
            except Exception as exc:
                print("[guard] 首次扫描检测日志失败(忽略): %s" % exc)
        if enable_sysproxy:
            ok, msg = self.proxyctl.enable()
            results["sysproxy"] = (ok, msg)
            print("[guard] %s" % msg)
        self.started_at = time.strftime("%Y-%m-%d %H:%M:%S")
        return results

    def stop(self, disable_sysproxy=None):
        """停止各组件（默认按配置把系统代理还原）"""
        if disable_sysproxy is None:
            disable_sysproxy = bool(self.settings.get("sysproxy.restore_on_exit", True)) \
                and bool(self.proxyctl.status().get("enabled_by_us"))
        if disable_sysproxy:
            ok, msg = self.proxyctl.disable()
            print("[guard] %s" % msg)
        try:
            self.logwatcher.stop()
        except Exception:
            pass
        try:
            self.proxy.stop()
        except Exception:
            pass
        try:
            self.api.stop()
        except Exception:
            pass
        self.unpatch_all()
        self.store.flush()
        if self.verbose:
            print("[guard] 已停止（拦截规则与记录保存在 guard\\data, 下次启动继续生效）")

    def status(self):
        return self.api.status()

    # ================= 方案 D: 检测即真封 =================
    def patch_detector(self, detector):
        """包装 detector.detect: 判定为恶意 → 立刻进 guard 动态拦截集"""
        if detector is None or getattr(detector, "_guard_patched", False):
            return False
        original = detector.detect
        runtime = self

        def guarded_detect(url, use_api=False, *args, **kwargs):
            result = original(url, use_api=use_api, *args, **kwargs)
            try:
                runtime.on_detection(url, result)
            except Exception as exc:                    # 联动失败绝不影响检测本身
                print("[guard] 检测结果联动失败(不影响检测): %s" % exc)
            return result

        self._originals[id(detector)] = (detector, "detect", original)
        detector.detect = guarded_detect
        detector._guard_patched = True
        self.patched.append("detector.detect")
        if self.verbose:
            print("[guard] 已挂载「检测即真封」: eyilianjie 一判恶意, 该链接立刻进入 guard 拦截集")
        return True

    def unpatch_all(self):
        for detector, name, original in list(self._originals.values()):
            try:
                setattr(detector, name, original)
                if hasattr(detector, "_guard_patched"):
                    delattr(detector, "_guard_patched")
            except Exception:
                pass
        self._originals.clear()
        self.patched = []

    def on_detection(self, url, result):
        """把 eyilianjie 的一次「恶意」检测结论并入动态拦截集（只写 guard 自己的数据）"""
        if not getattr(result, "is_malicious", False):
            return None
        url = (url or "").strip()
        if not url:
            return None
        host = urlutil.host_of(url)
        try:
            if self.store.is_allowed(url, host):
                # 放行优先于一切拦截: 已在放行名单里的目标不再写入拦截集
                # （否则它会以"检测联动"身份重新出现在页面的动态拦截集里）
                return None
        except Exception:
            pass
        trusted = self.engine.is_trusted(host)
        reason = "eyilianjie 判定为恶意"
        if getattr(result, "blacklist_match", False):
            reason += "（命中黑名单）"
        score = getattr(result, "score", None)
        if score is not None:
            reason += " · 评分 %s" % score
        category = "黑名单" if getattr(result, "blacklist_match", False) else "eyilianjie 判定"
        added = self.store.add_dynamic(url, reason=reason, category=category,
                                       source="eyilianjie", host_level=not trusted,
                                       trusted=trusted, note="来自「检测即真封」")
        self.engine.invalidate()
        if self.verbose and added.get("added"):
            print("[guard] 检测即真封: %s → 已加入拦截集（%d 条）"
                  % (url, len(added["added"])))
        return added
