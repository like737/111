"""
判定引擎 —— **只读复用** eyilianjie 的判定能力（黑名单 / 启发式 / 成人规则 / ML 通道）

零侵入做法（全部只在 guard 进程的内存里生效, 不写 eyilianjie 任何文件）:
  * `Config.CONFIG_FILE`、`Detector.BLACKLIST_FILE/WHITELIST_FILE` 这几个"相对 CWD 的路径常量"
    改成绝对路径 → 从任意工作目录都能正确读取（但不改动源文件）;
  * 只调 `match_blacklist() / match_whitelist() / analyzer.analyze() / ml_channel.predict()`
    这些**不写日志**的方法;
  * 独立进程（`python -m guard run`）里自建 detector 时才把 `reporter.log_detection` 置空;
    **复用 web_app / run_guarded 的 detector 时绝不置空** —— 否则 web 端检测记录会停止写入，
    首页「最近检测 / 统计摘要」将不再更新;
  * 绝不调用 `detector.detect()`（它会写 detection_log.json、做 DNS 与 AI 请求, 既慢又会改文件）。
"""

import os
import sys
import threading
import time
from urllib.parse import urlsplit

from . import DATA_DIR, PROJECT_ROOT
from . import urlutil

# 判定来源 → 中文说明（拦截页与日志共用）
SOURCE_LABELS = {
    "blacklist": "命中 eyilianjie 黑名单",
    "adult": "成人/赌博内容规则",
    "heuristic": "启发式规则命中",
    "ml": "机器学习模型判定",
    "ml-hint": "机器学习模型（仅提示档, 已按配置拦截）",
    "dynamic_log": "来自 eyilianjie 的检测结果（已检出即拦截）",
    "dynamic_manual": "手动加入拦截",
    "allowlist": "guard 放行名单",
    "whitelist": "eyilianjie 白名单",
    "local": "本机地址",
    "none": "未命中任何规则",
    "error": "判定异常",
    "disabled": "拦截未启用",
}


def _now():
    return time.strftime("%Y-%m-%d %H:%M:%S")


class Engine:
    """guard 的判定引擎（线程安全, 带结果缓存）"""

    def __init__(self, settings, store, detector=None, verbose=True):
        self.settings = settings
        self.store = store
        self.detector = None
        self.analyzer = None
        self.ml_channel = None
        self._utils = None
        self.ready = False
        self.error = ""
        self.info = {}
        self._cache = {}
        self._cache_lock = threading.RLock()
        self._store_stamp_last = None        # 名单文件指纹（别的进程改过 → 自动丢缓存）
        self.verbose = verbose
        if detector is not None:
            self.attach(detector)
        else:
            self.build()

    # ================= 只读挂载 eyilianjie =================
    @staticmethod
    def _patch_paths():
        """把 eyilianjie 里"相对 CWD 的路径常量"改成绝对路径（仅本进程内存）"""
        if PROJECT_ROOT not in sys.path:
            sys.path.insert(0, PROJECT_ROOT)
        import config as ey_config
        import detector as ey_detector
        ey_config.Config.CONFIG_FILE = os.path.join(PROJECT_ROOT, "config.json")
        ey_detector.Detector.BLACKLIST_FILE = os.path.join(PROJECT_ROOT, "data", "blacklist.json")
        ey_detector.Detector.WHITELIST_FILE = os.path.join(PROJECT_ROOT, "data", "whitelist.json")
        return ey_config, ey_detector

    def build(self):
        """自建一套 eyilianjie 判定组件（仅涉独立进程 `python -m guard run` 时使用）"""
        try:
            ey_config, ey_detector = self._patch_paths()
            cfg = ey_config.Config()                      # 只读加载 eyilianjie/config.json
            # 仅改内存: 即便日后有人误调 detect(), 日志也只落在 guard 自己的目录
            logging_section = cfg.all_config.setdefault("logging", {})
            logging_section["log_file"] = os.path.join(DATA_DIR, "eyilianjie_log_mirror.json")
            detector = ey_detector.Detector(cfg)
            detector.reporter.log_detection = lambda result: None
            self.attach(detector)
        except Exception as exc:
            self.error = "初始化 eyilianjie 判定组件失败: %s" % exc
            print("[guard] " + self.error)
        return self

    def attach(self, detector):
        """复用已经存在的 Detector 实例（run_guarded.py 就是复用 web_app.detector）"""
        try:
            if PROJECT_ROOT not in sys.path:
                sys.path.insert(0, PROJECT_ROOT)
            self.detector = detector
            self.analyzer = getattr(detector, "analyzer", None)
            self.ml_channel = getattr(detector, "ml_channel", None)
            import utils as ey_utils
            self._utils = ey_utils
            # 注意: 这里**不能**把 detector.reporter.log_detection 置空。
            # 本方法复用的是 web_app / run_guarded 的同一个 detector 实例，
            # 置空会让 web 端检测不再写入 detection_log.json —— 首页「最近检测 / 统计摘要」
            # 从此停更（刷新也无效）。guard 自己不调用 detect()，不会产生日志；
            # 需要静音的只有独立进程自建 detector 的 build()（已在那里处理）。
            blacklist = getattr(detector, "_blacklist", {}) or {}
            ml_ok = bool(self.ml_channel is not None and getattr(self.ml_channel, "available", False))
            self.info = {
                "blacklist_size": len(blacklist),
                "whitelist_size": len(getattr(detector, "_whitelist", {}) or {}),
                "ml_available": ml_ok,
                "ml_describe": (self.ml_channel.describe() if ml_ok else "无可用模型"),
            }
            self.ready = True
            if self.verbose:
                print("[guard] 已挂载 eyilianjie 判定组件: 黑名单 %d 条 | ML: %s"
                      % (self.info["blacklist_size"], self.info["ml_describe"] or "无"))
        except Exception as exc:
            self.error = "挂载判定组件失败: %s" % exc
            print("[guard] " + self.error)
        return self

    def is_trusted(self, host):
        """eyilianjie 认可的可信站点（用于避免"误判一条链接就封整站"）"""
        try:
            return bool(self._utils and self._utils.is_trusted_host(host))
        except Exception:
            return False

    # ================= 对外判定接口 =================
    def judge(self, url, mode="url", use_cache=True):
        """判定一个 URL（mode='url' 完整URL / 'host' 仅域名, 用于 HTTPS CONNECT）

        返回 dict: blocked / reason / source / category / entry / level / score / details / ml
        """
        url = (url or "").strip()
        host = urlutil.host_of(url)
        if not host:
            return self._decision(False, url, host, "无法解析URL", source="error",
                                  error="invalid url")
        if not bool(self.settings.get("enabled", True)):
            return self._decision(False, url, host, "guard 拦截未启用", source="disabled")
        key = (mode, urlutil.norm_url(url))
        if use_cache:
            self._sync_store_stamp()          # 别人刚放过行/加过黑 → 先丢缓存再查
            hit = self._cache_get(key)
            if hit is not None:
                return dict(hit, cached=True)
        try:
            decision = self._judge_uncached(url, host, mode)
        except Exception as exc:                       # 判定异常: 默认放行, 绝不因此断网
            self.store.count("judge_error")
            fail_open = bool(self.settings.get("block.fail_open", True))
            decision = self._decision(not fail_open, url, host,
                                      "判定异常: %s" % exc, source="error", error=str(exc))
        if use_cache:
            self._cache_put(key, decision)
        return decision

    def _judge_uncached(self, url, host, mode="url"):
        cfg = self.settings
        heuristic_score = None

        # 0) 本机地址 / 放行名单 / eyilianjie 白名单 —— 三者优先放行
        if urlutil.is_local_host(host):
            return self._decision(False, url, host, "本机地址, 不做拦截判定", source="local")
        if self.store.is_allowed(url, host):
            return self._decision(False, url, host, "命中 guard 放行名单", source="allowlist")
        if self.detector is not None:
            try:
                wl = self.detector.match_whitelist(url)
            except Exception:
                wl = None
            if wl:
                return self._decision(False, url, host,
                                      "eyilianjie 白名单: %s" % (wl.get("entry") or ""),
                                      source="whitelist", entry=wl.get("entry") or "",
                                      level=wl.get("level") or "")

        # 1) guard 动态拦截集（来自 eyilianjie 检测结果 / 手动加黑 / 拦截页回写）
        if bool(cfg.get("block.dynamic_from_log", True)):
            dyn = self.store.match_dynamic(url, host)
            if dyn:
                is_manual = (dyn.get("source") == "manual")
                return self._decision(
                    True, url, host, dyn.get("reason") or "命中 guard 动态拦截集",
                    source=("dynamic_manual" if is_manual else "dynamic_log"),
                    category=dyn.get("category") or "",
                    entry=dyn.get("matched_key") or "", level=dyn.get("matched_level") or "",
                    details=["命中动态条目: %s" % (dyn.get("matched_key") or ""),
                             "条目来源: %s" % (dyn.get("source") or "未知"),
                             "记录时间: %s" % (dyn.get("ts") or "")])

        # 2) eyilianjie 黑名单（18 万条, 6 级匹配, 文件改动自动热同步）
        if self.detector is not None and bool(cfg.get("block.blacklist", True)):
            try:
                hit = self.detector.match_blacklist(url)
            except Exception as exc:
                hit = None
                print("[guard] 黑名单匹配异常: %s" % exc)
            if hit:
                return self._decision(
                    True, url, host, "命中黑名单（分类: %s）" % (hit.get("category") or "未知"),
                    source="blacklist", category=hit.get("category") or "",
                    entry=hit.get("entry") or "", level=hit.get("level") or "",
                    details=["黑名单条目: %s" % (hit.get("entry") or "")[:200],
                             "匹配方式: %s" % (hit.get("level") or "")])

        # 3) 成人/赌博内容（与 eyilianjie 同一套词库: 域名级命中直接拦）
        if bool(cfg.get("block.adult", True)):
            adult = self._adult_rule(url, host)
            if adult.get("block"):
                return self._decision(True, url, host, adult["reason"], source="adult",
                                      category="色情/赌博", details=adult.get("details") or [])

        # 4) ML 通道（域名模型 + 路径模型; 只信"参与拦截"的通道）
        ml = self._ml_judge(url)
        if ml.get("block"):
            return self._decision(True, url, host, ml["reason"], source="ml",
                                  category="机器学习判定", details=ml.get("details") or [],
                                  ml=ml.get("raw") or {})

        # 5) 启发式规则（含恶意/钓鱼模式库、可疑域名库、可疑TLD 等）
        run_heuristic = bool(cfg.get("block.heuristic", True))
        if mode == "host" and not bool(cfg.get("block.heuristic_on_tunnel", True)):
            run_heuristic = False
        if run_heuristic and self.analyzer is not None:
            res = self.analyzer.analyze(url, use_api=False)
            heuristic_score = res.get("score")
            if res.get("is_malicious"):
                return self._decision(
                    True, url, host,
                    "启发式规则判定为恶意（危险加分 %s, 阈值 %s）"
                    % (res.get("score"), res.get("threshold")),
                    source="heuristic", category="恶意URL",
                    score=res.get("score"), threshold=res.get("threshold"),
                    details=list(res.get("details") or [])[:8], ml=ml.get("raw") or {})

        # ---- 三档判定（8-A）----
        #   拦截：命中任意规则（上面已 return）
        #   警告：ML 域名概率落在 [warn_prob, 拦截阈值) 或 启发式评分落在 [warn_score, 阈值)
        #   放行：其余
        raw = ml.get("raw") or {}
        # 注意：这里不能用 `x or 默认值` —— 配置里合法的 0 会被当成"未设置"
        try:
            warn_prob = float(cfg.get("block.warn_prob", 0.90))
        except (TypeError, ValueError):
            warn_prob = 0.90
        if warn_prob < 0:
            warn_prob = 0.90
        try:
            warn_score = int(cfg.get("block.warn_score", 40))
        except (TypeError, ValueError):
            warn_score = 40
        try:
            score_thr = int(cfg.get("block.heuristic_threshold", 60))
        except (TypeError, ValueError):
            score_thr = 60

        warn_reason = ""
        domain_prob = ((raw.get("models") or {}).get("domain") or {}).get("prob")
        if domain_prob is not None:
            try:
                if float(domain_prob) >= warn_prob:
                    warn_reason = ("ML 域名模型概率 %.3f 落在警告区间 [%.2f, 拦截阈值)，"
                                   "只给提示、不直接拦截" % (float(domain_prob), warn_prob))
            except (TypeError, ValueError):
                pass
        if not warn_reason and heuristic_score is not None:
            try:
                if warn_score <= int(heuristic_score) < score_thr:
                    warn_reason = ("启发式评分 %d 落在警告区间 [%d, %d)，只给提示、不直接拦截"
                                   % (int(heuristic_score), warn_score, score_thr))
            except (TypeError, ValueError):
                pass

        if warn_reason:
            return self._decision(False, url, host, warn_reason, source="warn",
                                  score=heuristic_score,
                                  details=list(ml.get("details") or [])[:4],
                                  ml=raw, warn=True)
        return self._decision(False, url, host, "未命中任何规则", source="none",
                              details=list(ml.get("details") or [])[:4], ml=raw)

    # ================= 单个规则 =================
    def _adult_rule(self, url, host):
        """成人/赌博规则: 镜像 analyzer._check_adult_content 的强命中判定

        只拦"域名级强命中"(domain_strong / adult_brands / gambling),
        弱标签(domain_weak)与路径命中只作提示 —— 与 eyilianjie 的评分口径保持一致,
        避免误伤 sexeducation.com 这类正常站点。
        """
        out = {"block": False, "reason": "", "details": []}
        if self._utils is None or self.is_trusted(host):
            return out
        try:
            parts = urlsplit(urlutil.ensure_scheme(url))
            hits = self._utils.match_adult_keywords(host, parts.path or "", parts.query or "")
        except Exception:
            return out
        strong = (list(hits.get("domain_strong") or [])
                  + list(hits.get("adult_brands") or [])
                  + list(hits.get("gambling") or []))
        if strong:
            out["block"] = True
            out["reason"] = "域名命中成人/赌博类关键词: %s" % "、".join(strong[:5])
            out["details"] = ["命中关键词: %s" % "、".join(strong[:8]),
                              "规则口径: 域名级命中 → 直接拦截（与 eyilianjie 共用 data/adult_keywords.json）"]
        return out

    def _ml_judge(self, url):
        """ML 通道: 只信 enforce 模式下"参与拦截"的通道（当前=路径模型）"""
        out = {"block": False, "reason": "", "details": [], "raw": None}
        if self.ml_channel is None or not getattr(self.ml_channel, "available", False):
            return out
        ml_mode = "shadow"
        try:
            ml_mode = str(self.detector.config.get("detection", "ml_mode") or "shadow").lower()
            if self.detector.config.get("detection", "enable_ml_check") is False:
                return out
        except Exception:
            pass
        try:
            ml = self.ml_channel.predict(url)
        except Exception as exc:
            print("[guard] ML 判定异常(忽略): %s" % exc)
            return out
        if not ml or not ml.get("ok"):
            return out
        details = list(self.ml_channel.detail_lines(url, ml) or [])
        convict = list(ml.get("convict") or [])
        hint = list(ml.get("hint") or [])
        if ml_mode == "enforce" and convict and bool(self.settings.get("block.ml_convict", True)):
            out["block"] = True
            out["reason"] = "ML 通道高置信判定（参与拦截的通道: %s）" % "、".join(convict)
            out["details"] = details
        elif ml_mode == "enforce" and hint and bool(self.settings.get("block.ml_hint", False)):
            out["block"] = True
            out["reason"] = "ML 通道高置信判定（仅提示档, 已按 guard 配置拦截: %s）" % "、".join(hint)
            out["details"] = details
        models = {}
        for name, item in (ml.get("models") or {}).items():
            if isinstance(item, dict):
                models[name] = {"prob": item.get("prob"), "threshold": item.get("threshold"),
                                "high": item.get("high")}
        out["raw"] = {"prob": ml.get("prob"), "models": models,
                      "convict": convict, "hint": hint, "mode": ml_mode}
        return out

    # ================= 结果与缓存 =================
    @staticmethod
    def _decision(blocked, url, host, reason, source="", category="", entry="", level="",
                  score=None, threshold=None, details=None, ml=None, error="", warn=False):
        return {"blocked": bool(blocked), "warn": bool(warn), "url": url, "host": host,
                "reason": reason or "", "source": source or "none",
                "source_label": SOURCE_LABELS.get(source or "none", source or ""),
                "category": category or "", "entry": entry or "", "level": level or "",
                "score": score, "threshold": threshold,
                "details": list(details or []), "ml": ml or {}, "error": error or "",
                "checked_at": _now(), "cached": False}

    def _store_stamp(self):
        """放行名单 / 动态拦截集文件的指纹（mtime + 大小）"""
        stamp = []
        for path in (getattr(self.store, "allow_file", ""), getattr(self.store, "dynamic_file", "")):
            try:
                stat = os.stat(path)
                stamp.append((stat.st_mtime_ns, stat.st_size))
            except OSError:
                stamp.append(None)
        return tuple(stamp)

    def _sync_store_stamp(self):
        """名单文件被别的进程改过 → 丢掉本进程的判定缓存。

        为什么需要: 8899 控制台 与 5000 Web 端 各自有一个 runtime/缓存（cache.ttl 默认
        60 秒）, 在 A 里点"加入放行"只清得掉 A 的缓存, B 最长 60 秒内还会照旧拦 ——
        这里用文件指纹把那个窗口收掉（只多两次 os.stat, 微秒级）。
        """
        stamp = self._store_stamp()
        with self._cache_lock:
            if self._store_stamp_last is not None and stamp != self._store_stamp_last and self._cache:
                self._cache.clear()
            self._store_stamp_last = stamp

    def _cache_get(self, key):
        try:
            ttl = float(self.settings.get("cache.ttl", 60) or 0)
        except (TypeError, ValueError):
            ttl = 60.0
        with self._cache_lock:
            item = self._cache.get(key)
            if not item:
                return None
            ts, decision = item
            if ttl > 0 and (time.time() - ts) > ttl:
                self._cache.pop(key, None)
                return None
        return decision

    def _cache_put(self, key, decision):
        try:
            max_size = int(self.settings.get("cache.max", 5000) or 5000)
        except (TypeError, ValueError):
            max_size = 5000
        with self._cache_lock:
            self._cache[key] = (time.time(), decision)
            if len(self._cache) > max_size:
                items = sorted(self._cache.items(), key=lambda kv: kv[1][0])
                for old_key, _ in items[:max(1, len(self._cache) - max_size)]:
                    self._cache.pop(old_key, None)

    def invalidate(self):
        """规则变化（加黑/放行/日志联动）后清空判定缓存, 保证立即生效"""
        with self._cache_lock:
            self._cache.clear()

    def stats(self):
        with self._cache_lock:
            cache_size = len(self._cache)
        return {"ready": self.ready, "error": self.error, "cache_size": cache_size,
                "info": dict(self.info)}

