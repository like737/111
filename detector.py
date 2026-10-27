"""
检测协调器 - 整合多种检测方法，对外提供统一的检测接口
"""

import json
import os
import time
from typing import Dict, List, Optional, Callable, Tuple
from datetime import datetime
from urllib.parse import urlunparse

from analyzer import URLAnalyzer
from utils import (
    compute_url_hash, is_valid_url, extract_domain,
    extract_url_features, is_ip_address, check_domain_resolves,
    similarity_ratio,        # 手动添加黑名单时用于与已有条目做相似度比较
)
from reporter import Reporter
from deepseek_analyzer import DeepSeekAnalyzer

class DetectionResult:
    """检测结果的数据类"""
    
    def __init__(self, url: str, analyzer_result: Dict, 
                 blacklist_match: bool = False, api_result: Optional[Dict] = None,
                 ml_result: Optional[Dict] = None):
        self.url = url
        self.url_hash = compute_url_hash(url)
        self.timestamp = datetime.now().isoformat()
        self.analyzer_result = analyzer_result
        self.blacklist_match = blacklist_match
        self.api_result = api_result
        self.is_malicious = analyzer_result.get("is_malicious", False) or blacklist_match
        self.score = analyzer_result.get("score", 0)
        self.risk_level = analyzer_result.get("risk_level", "未知")
        self.details = analyzer_result.get("details", [])
        self.domain = extract_domain(url)   # ← 加上这一行！
        # ML 检测通道结果(影子模式下仅记录; 供日志与页面展示)
        _ml = ml_result or {}
        self.ml_prob = _ml.get("prob")                                      # 恶意概率 0~1, 不可用时 None
        self.ml_verdict = _ml.get("verdict", 0) if _ml.get("ok") else 0     # 1 = 模型判恶意
        self.ml_high = bool(_ml.get("high"))                                # 是否达到高置信门限
        self.ml_mode = _ml.get("mode")                                      # shadow / enforce
        _models = _ml.get("models") or {}
        # 方案A: 各通道概率分开展示/记录(域名模型 / 路径模型)
        self.ml_domain_prob = (_models.get("domain") or {}).get("prob")
        self.ml_path_prob = (_models.get("path") or {}).get("prob")
        self.ml_convict = list(_ml.get("convict") or [])                    # 参与定罪(拦截)的通道
        self.ml_hint = list(_ml.get("hint") or [])                          # 仅提示的通道
        self.ml_thresholds = dict(_ml.get("thresholds") or {})              # 各通道阈值(供页面判定)

        
        if blacklist_match and not self.details:
            self.details.append("⛔ 命中黑名单记录")
    
    def to_dict(self) -> Dict:
        return {
            "url": self.url,
            "url_hash": self.url_hash,
            "timestamp": self.timestamp,
            "is_malicious": self.is_malicious,
            "score": self.score,
            "risk_level": self.risk_level,
            "details": self.details,
            "blacklist_match": self.blacklist_match,
            "domain": self.domain,
            # ML 检测通道字段(新增, 不影响既有字段与读取逻辑)
            "ml_prob": self.ml_prob,
            "ml_verdict": self.ml_verdict,
            "ml_high": self.ml_high,
            "ml_mode": self.ml_mode,
            "ml_domain_prob": self.ml_domain_prob,
            "ml_path_prob": self.ml_path_prob,
            "ml_convict": self.ml_convict,
        }
    
    def __str__(self) -> str:
        lines = [
            "=" * 60,
            f"🔗 URL: {self.url}",
            f"📊 风险评分: {self.score}/100",
            f"🏷️  风险等级: {self.risk_level}",
            f"🔍 判定结果: {'⚠️ 恶意链接!' if self.is_malicious else '✅ 安全链接'}",
            "-" * 60,
        ]
        if self.details:
            lines.append("📋 检测详情:")
            lines.extend(f"   {d}" for d in self.details)
        lines.append("=" * 60)
        return "\n".join(lines)

class Detector:
    """
    恶意URL检测器 - 整合多种检测手段
    
    检测流程:
    1. URL格式验证
    2. 黑名单匹配
    3. 启发式分析
    4. DNS检查 (可选)
    5. 外部API查询 (可选)
    """
    
    BLACKLIST_FILE = "data/blacklist.json"
    WHITELIST_FILE = "data/whitelist.json"
    # 黑名单文件热同步间隔(秒): 外部导入脚本/手工编辑写入后,
    # 运行中的进程最多在这么长时间内自动感知并重新加载(无需重启)
    BLACKLIST_SYNC_INTERVAL = 2.0
    
    def __init__(self, config=None, verbose=True):
        from config import Config
        # verbose: 是否打印"已加载黑名单/ML 通道"等启动信息
        #          （web_app 默认传 False，终端只保留一行启动提示）
        self.verbose = bool(verbose)
        self.config = config or Config(verbose=self.verbose)
        self.analyzer = URLAnalyzer(self.config.all_config.get("detection", {}))
        self.reporter = Reporter(self.config)
        # 用户手动添加的条目(按添加顺序记录, 用于在黑名单页面"置顶"显示)
        self._user_added: List[str] = []
        self._blacklist = self._load_blacklist()
        # 黑名单多级匹配索引(支持 规范化/忽略协议/忽略查询参数/父路径/域名 匹配)
        self._blacklist_norm: Dict[str, Tuple[str, str, str]] = {}
        self._blacklist_domain: Dict[str, Tuple[str, str]] = {}
        # 主机索引: host → 该主机下的所有条目
        # (用户手动添加时, 用它快速找出"同域名"的已有条目做比较)
        self._blacklist_host: Dict[str, List[str]] = {}
        self._blacklist_index_size = -1
        # 启动阶段预热索引(6万条约 1 秒), 避免首次检测时才构建导致响应变慢
        self._rebuild_blacklist_index()
        # 黑名单文件热同步: 记录初始指纹与检查时间(外部导入后自动重新加载, 无需重启)
        self._blacklist_sync_sig = self._blacklist_signature()
        self._blacklist_sync_checked_at = time.time()
        self._whitelist = self._load_whitelist()
        # 白名单多级匹配索引(匹配规则与黑名单一致)
        self._whitelist_norm: Dict[str, Tuple[str, str]] = {}
        self._whitelist_domain: Dict[str, str] = {}
        self._whitelist_index_size = -1
        self._rebuild_whitelist_index()
        self._on_detection_callbacks = []
        
        # 初始化 DeepSeek 分析器
        deepseek_key = self.config.get("api_keys", "deepseek") or ""
        self.deepseek_analyzer = DeepSeekAnalyzer(deepseek_key)
        # 初始化 ML 检测通道(方案A: 域名模型 + 路径模型 并行)
        #   设计原则: 任何失败(文件缺失/依赖缺失/格式错误)都只跳过该通道,
        #   使检测流程与"未接入 ML"时完全一致, 绝不抛异常影响 AI/启发式检测。
        self.ml_channel = None
        self.ml_model = None          # 兼容旧引用(单模型时代)
        if self.config.get("detection", "enable_ml_check"):
            try:
                from ml_url_model import MLChannel
                import time as _time
                _t0 = _time.time()
                self.ml_channel = MLChannel(self.config, verbose=self.verbose)
                self.ml_channel.load()
                self.ml_model = self.ml_channel      # 旧字段保留, 指向通道
                if self.verbose:
                    print("[检测器] ML 通道: 模式=%s | %s (加载 %.1fs)"
                          % (self.config.get("detection", "ml_mode") or "shadow",
                             self.ml_channel.describe() or '无可用模型', _time.time() - _t0))
            except Exception as e:
                self.ml_channel = None
                self.ml_model = None
                print("[检测器] ML 通道不可用(%s), 已跳过; 启发式/AI 检测不受影响" % e)


    
    def _blacklist_signature(self):
        """黑名单文件的"指纹"(修改时间+大小), 用于判断是否被外部改动"""
        try:
            st = os.stat(self.BLACKLIST_FILE)
            return (st.st_mtime_ns, st.st_size)
        except OSError:
            return None

    def _sync_blacklist_if_changed(self):
        """黑名单文件热同步: 外部导入脚本/手工编辑写入后, 运行中的进程自动重新加载

        - 用 (修改时间, 大小) 判断变化, 每 BLACKLIST_SYNC_INTERVAL 秒最多检查一次
          (os.stat 开销极小, 但仍做节流, 避免每条URL检测都产生磁盘调用);
        - 解析失败(例如文件正在被写入)时保留内存中的原数据, 绝不影响检测流程。
        """
        now = time.time()
        if now - getattr(self, '_blacklist_sync_checked_at', 0.0) < self.BLACKLIST_SYNC_INTERVAL:
            return
        self._blacklist_sync_checked_at = now
        sig = self._blacklist_signature()
        if sig is None or sig == getattr(self, '_blacklist_sync_sig', None):
            return
        try:
            new_data = self._load_blacklist()
            if not new_data and self._blacklist:
                raise ValueError('重新加载得到空数据, 疑似文件正在写入, 本次跳过')
            self._blacklist = new_data
            self._rebuild_blacklist_index()
            self._blacklist_sync_sig = sig
            print('[检测器] 检测到黑名单文件变化, 已自动热加载: %d 条' % len(self._blacklist))
        except Exception as e:
            print('[检测器] 黑名单热加载失败(保留原有数据): %s' % e)

    def _load_blacklist(self) -> Dict[str, str]:
        """加载黑名单，返回 {url: category}"""
        blacklist_path = self.BLACKLIST_FILE
        if os.path.exists(blacklist_path):
            try:
                with open(blacklist_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        # 兼容旧格式：纯URL列表 → 默认分类为"恶意URL"
                        blacklist_dict = {url: "恶意URL" for url in data}
                        if self.verbose:
                            print(f"[检测器] 已加载黑名单: {len(blacklist_dict)} 条记录 (旧格式转换)")
                        return blacklist_dict
                    else:
                        blacklist_dict = data.get("entries", {}) if "entries" in data else {}
                        # 读取"手动添加"记录(老文件没有这个字段 → 保持为空, 内容不受影响)
                        stored = data.get("user_added")
                        if isinstance(stored, list):
                            self._user_added = [str(x) for x in stored if str(x) in blacklist_dict]
                        if self.verbose:
                            summary = f"[检测器] 已加载黑名单: {len(blacklist_dict)} 条记录"
                            if self._user_added:
                                summary += f" (其中手动添加 {len(self._user_added)} 条, 将置顶显示)"
                            print(summary)
                        return blacklist_dict
            except Exception as e:
                print(f"[检测器] 加载黑名单失败: {e}")
        return {}

    # ========== 黑名单多级匹配(提高命中率) ==========
    @staticmethod
    def _normalize_url(url: str) -> str:
        """URL 规范化: 小写协议与主机名、去默认端口、去 fragment、去末尾斜杠

        http://Evil.COM:80/a/  ->  http://evil.com/a
        """
        raw = (url or "").strip()
        if not raw:
            return ""
        features = extract_url_features(raw)      # 内部会自动补 http://
        hostname = (features.get("hostname") or "").lower()
        if not hostname:
            return raw.lower()
        scheme = (features.get("scheme") or "http").lower()
        port = features.get("port")
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            port = None
        netloc = hostname if not port else f"{hostname}:{port}"
        path = features.get("path") or "/"
        if not path.startswith("/"):
            path = "/" + path
        if len(path) > 1:
            path = path.rstrip("/") or "/"
        query = features.get("query") or ""
        return urlunparse((scheme, netloc, path, "", query, ""))

    @staticmethod
    def _split_entry(entry: str) -> Tuple[str, str, str]:
        """把条目拆成 (hostname, path, query)，用于判断是否为"纯域名"条目"""
        features = extract_url_features((entry or "").strip())
        host = (features.get("hostname") or "").lower()
        path = features.get("path") or ""
        query = features.get("query") or ""
        return host, path, query

    @classmethod
    def _match_keys(cls, url: str, include_parent_paths: bool = True) -> List[Tuple[str, str]]:
        """生成匹配查表键(从严格到宽松, 黑名单/白名单通用)，返回 [(key, 匹配级别), ...]

        级别名称会显示在检测详情里，便于看出是"精确命中"还是"宽松命中"。
        include_parent_paths 只在"查询侧"(match_*_list)传 True:
        索引侧(建表)必须传 False, 否则名单里的文件条目
        (https://evil.com/dir/file.zip) 会产生父路径键, 导致同目录下
        其它文件(https://evil.com/dir/other.zip)被误判。
        """
        keys: List[Tuple[str, str]] = []
        raw = (url or "").strip()
        if not raw:
            return keys
        keys.append((raw, "精确匹配"))
        norm = cls._normalize_url(raw)
        if norm:
            keys.append((norm, "规范化匹配"))
            no_scheme = norm.split("://", 1)[-1]
            keys.append((no_scheme, "忽略协议匹配"))
            keys.append((no_scheme.split("?", 1)[0], "忽略查询参数匹配"))

            # 父路径逐级匹配(仅查询侧启用: 名单收录"目录"时, 其下文件也能命中)
            if include_parent_paths:
                scheme, sep, rest = norm.partition("://")
                if sep:
                    host_part, _, path_only = rest.split("?", 1)[0].partition("/")
                    segments = [seg for seg in path_only.split("/") if seg]
                    while len(segments) > 1:
                        segments.pop()
                        parent_path = "/".join(segments)
                        keys.append(("{0}://{1}/{2}".format(scheme, host_part, parent_path), "父路径匹配"))
                        keys.append(("{0}/{1}".format(host_part, parent_path), "父路径匹配(忽略协议)"))

        # 去重但保留顺序(越严格越先命中)
        seen = set()
        result = []
        for key, level in keys:
            if key and key not in seen:
                seen.add(key)
                result.append((key, level))
        return result

    def _rebuild_blacklist_index(self):
        """重建黑名单匹配索引(加载/增删黑名单后刷新)

        - URL级索引: 支持"规范化 / 忽略协议 / 忽略查询参数 / 父路径"的匹配
        - 域名级索引: 只收录"纯域名"条目(如 free-money.tk)，命中该域名自身及其所有子域名；
          带路径的条目(如 https://raw.githubusercontent.com/a/b.zip)不会被升级为整域封禁，
          避免把整个共享站点误判为恶意。
        - 主机级索引: host → 该主机下的所有条目(手动添加黑名单时用于"同域名比较")
        """
        url_index: Dict[str, Tuple[str, str, str]] = {}
        domain_index: Dict[str, Tuple[str, str]] = {}
        host_index: Dict[str, List[str]] = {}
        for entry, category in self._blacklist.items():
            for key, level in self._match_keys(entry, include_parent_paths=False):
                if key not in url_index:
                    url_index[key] = (entry, category, level)
            host, path, query = self._split_entry(entry)
            if host:
                host_index.setdefault(host, []).append(entry)
            if host and (not path or path == "/") and not query and host not in domain_index:
                domain_index[host] = (entry, category)
        self._blacklist_norm = url_index
        self._blacklist_domain = domain_index
        self._blacklist_host = host_index
        self._blacklist_index_size = len(self._blacklist)

    def match_blacklist(self, url: str) -> Optional[Dict]:
        """在黑名单中多级匹配URL: 命中返回详情字典, 未命中返回 None

        匹配级别(从严格到宽松):
          1. 精确匹配          http://evil.com/a?x=1
          2. 规范化匹配        大小写 / 默认端口 / 末尾斜杠 / fragment 差异
          3. 忽略协议匹配      http / https 差异
          4. 忽略查询参数匹配  ?a=1 这类参数差异
          5. 父路径匹配        名单收录的是目录(https://evil.com/bad)时,
                               其下文件(https://evil.com/bad/x.php)同样命中
          6. 域名匹配          黑名单里存在"纯域名"条目时, 覆盖其子域名与任意路径
        """
        # 黑名单文件被外部改动(导入脚本/手工编辑)时热加载, 保证运行中的进程与文件一致
        self._sync_blacklist_if_changed()
        # 黑名单被外部直接修改(如清空)时自动重建索引
        if self._blacklist_index_size != len(self._blacklist):
            self._rebuild_blacklist_index()

        for key, level in self._match_keys(url):
            hit = self._blacklist_norm.get(key)
            if hit:
                entry, category, _ = hit
                return {"category": category, "entry": entry, "level": level, "key": key}

        # 域名级匹配: 逐级剥离子域名查表(至少保留两级域名)
        host, _, _ = self._split_entry(url)
        if host:
            labels = host.split(".")
            for i in range(0, max(1, len(labels) - 1)):
                candidate = ".".join(labels[i:])
                hit = self._blacklist_domain.get(candidate)
                if hit:
                    entry, category = hit
                    return {"category": category, "entry": entry, "level": "域名匹配", "key": candidate}
        return None

    def is_in_blacklist(self, url: str) -> bool:
        """检查URL是否命中黑名单(多级匹配)"""
        return self.match_blacklist(url) is not None

    def get_blacklist_category(self, url: str) -> str:
        """获取URL的黑名单分类(多级匹配)"""
        hit = self.match_blacklist(url)
        return hit["category"] if hit else "未知"
    
    def _save_blacklist(self):
        """保存黑名单到文件"""
        os.makedirs("data", exist_ok=True)
        try:
            data = {
                "entries": self._blacklist,
                # 新增字段: 手动添加的条目列表(仅用于置顶排序), entries 内容原样保留
                "user_added": self._user_added,
                "updated_at": datetime.now().isoformat(),
                "total": len(self._blacklist)
            }
            with open(self.BLACKLIST_FILE, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            # 黑名单已变更，刷新多级匹配索引
            self._rebuild_blacklist_index()
            # 更新文件指纹: 避免下一次检查把自己刚保存的内容误判为"外部改动"
            self._blacklist_sync_sig = self._blacklist_signature()
        except Exception as e:
            print(f"[检测器] 保存黑名单失败: {e}")

    # ========== 手动添加黑名单(新规则: 置顶 + 与已有条目比较) ==========
    def add_to_blacklist(self, url: str, category: str = "恶意URL") -> Dict:
        """手动添加URL到黑名单(新规则)

        规则:
        1. 添加前先与现有黑名单比较(compare_with_blacklist):
           若判定为"完全重复"(多级匹配命中), 不重复写入、不覆盖原分类,
           只把已有条目提到置顶列表;
        2. 添加成功或已存在, 都会把该条目记为"手动添加", 在黑名单页面**置顶**显示
           (最新添加的在最前); 黑名单里原有的条目内容一律不改动;
        3. 返回比较结果, 供Web端提示"是否重复 / 同域名有多少条 / 哪些条目相似"。

        Returns:
            {"added": bool, "entry": str, "duplicate": {...}|None,
             "similar": [{"entry","category","reason"}...], "same_host_count": int}
        """
        url = (url or "").strip()
        comparison = self.compare_with_blacklist(url)
        comparison["entry"] = url
        comparison["added"] = False
        if not url:
            return comparison

        duplicate = comparison["duplicate"]
        if duplicate:
            # 已存在: 保留原条目与原分类不动, 仅置顶
            existing = duplicate["entry"]
            comparison["entry"] = existing
            self._promote_user_entry(existing)
            self._save_blacklist()
            print(f"[检测器] 黑名单中已存在该URL(匹配方式: {duplicate['level']}): {existing}，已置顶")
            return comparison

        self._blacklist[url] = category
        self._promote_user_entry(url)
        self._save_blacklist()
        comparison["added"] = True
        extra = f"，该域名下已有 {comparison['same_host_count']} 条记录" if comparison["same_host_count"] else ""
        print(f"[检测器] 已将URL加入黑名单并置顶: {url} ({category}){extra}")
        return comparison

    def remove_from_blacklist(self, url: str):
        """从黑名单中移除URL(同时清掉它的"手动添加/置顶"记录)"""
        if url in self._blacklist:
            del self._blacklist[url]
        if url in self._user_added:
            self._user_added.remove(url)
        self._save_blacklist()
        print(f"[检测器] 已将URL从黑名单移除: {url}")

    # ========== 黑名单查询 / 按条目移除(Web 端"输入链接查黑名单"用) ==========
    def lookup_blacklist(self, url: str) -> Dict:
        """查询某个链接是否在黑名单里(复用多级匹配), 返回可直接展示的详情

        Returns:
            {"input": 原始输入, "matched": 是否命中, "hits": [命中/同域名条目...],
             "host": 解析出的主机, "total": 黑名单总条数}

        说明:
            - hits[i] = {"entry","category","level"}；level 为匹配方式
              (精确/规范化/忽略协议/忽略查询参数/父路径/域名 匹配);
            - 除命中项外, 还会附上"同域名下的其它条目"(便于判断是整域封禁还是单条封禁);
            - 只读操作, 不会修改黑名单。
        """
        url = (url or "").strip()
        total = len(self._blacklist)
        if not url:
            return {"input": url, "matched": False, "hits": [], "host": "", "total": total}

        hits: List[Dict] = []
        seen = set()
        hit = self.match_blacklist(url)          # 内部会自动热同步文件变化
        if hit:
            hits.append({"entry": hit["entry"], "category": hit["category"],
                         "level": hit["level"]})
            seen.add(hit["entry"])
        host, _, _ = self._split_entry(url)
        for entry in (self._blacklist_host.get(host, []) if host else []):
            if entry in seen:
                continue
            seen.add(entry)
            hits.append({"entry": entry, "category": self._blacklist.get(entry, ""),
                         "level": "同域名条目"})
        return {"input": url, "matched": bool(hit), "hits": hits[:20], "host": host,
                "total": len(self._blacklist)}

    def remove_blacklist_entry(self, entry: str) -> Dict:
        """按"条目原文"从黑名单移除(供查询结果里的一键移除使用)

        Returns: {"removed": bool, "entry": str, "category": str, "total": int, "reason": str}
        """
        entry = (entry or "").strip()
        if not entry:
            return {"removed": False, "entry": "", "reason": "条目为空"}
        if entry not in self._blacklist:
            return {"removed": False, "entry": entry,
                    "reason": "该条目不在黑名单中(可能已被移除, 或输入的不是条目原文)"}
        category = self._blacklist.get(entry, "")
        self.remove_from_blacklist(entry)        # 复用现有逻辑(含保存/索引刷新/置顶清理)
        return {"removed": True, "entry": entry, "category": category,
                "total": len(self._blacklist), "reason": ""}
    
    
   
    
    # ========== 手动添加相关的辅助方法 ==========
    def _promote_user_entry(self, entry: str):
        """把条目记为"最近手动添加"并置于置顶列表最前

        (内部 append + 读取时 reversed, 所以最后添加的排最前)
        """
        if entry in self._user_added:
            self._user_added.remove(entry)
        self._user_added.append(entry)

    def get_user_added_urls(self) -> List[str]:
        """返回手动添加的URL列表(最新在最前), 供页面标记与置顶显示"""
        self._sync_blacklist_if_changed()          # 外部导入后自动同步(无需重启)
        return [entry for entry in reversed(self._user_added) if entry in self._blacklist]

    def compare_with_blacklist(self, url: str, max_similar: int = 5) -> Dict:
        """把一条URL与现有黑名单做比较(手动添加黑名单前调用)

        比较分三层:
          1. 完全重复 —— 复用多级匹配(精确/规范化/忽略协议/忽略查询/父路径/域名);
          2. 高度相似 —— 同域名条目里 URL 相似度 >= 0.9 的(疑似同一批变体);
          3. 同域名   —— 该域名下已收录的其它条目(共享站点常有多条记录)。
        性能: 只在"同域名"候选里算相似度, 且最多扫描前 200 条, 不会因为
        黑名单有 6 万条而变慢。

        Returns:
            {"duplicate": {"entry","category","level"}|None,
             "similar": [{"entry","category","reason"}...],
             "same_host_count": int}
        """
        result: Dict = {"duplicate": None, "similar": [], "same_host_count": 0}
        url = (url or "").strip()
        if not url:
            return result

        result["duplicate"] = self.match_blacklist(url)

        host, _, _ = self._split_entry(url)
        candidates = self._blacklist_host.get(host) or []
        result["same_host_count"] = len(candidates)
        if not candidates:
            return result

        norm_url = self._normalize_url(url)
        duplicate_entry = result["duplicate"]["entry"] if result["duplicate"] else None
        similar: List[Dict[str, str]] = []
        same_host: List[Dict[str, str]] = []
        for entry in candidates[:200]:
            if entry == duplicate_entry:
                continue
            item = {
                "entry": entry,
                "category": self._blacklist.get(entry, "恶意URL"),
                "reason": "同域名",
            }
            if norm_url and similarity_ratio(norm_url, self._normalize_url(entry)) >= 0.9:
                item["reason"] = "高度相似(疑似同一批变体)"
                similar.append(item)
            elif len(same_host) < max_similar:
                same_host.append(item)
        result["similar"] = (similar[:max_similar] + same_host)[:max_similar]
        return result

    def _load_whitelist(self) -> set:
        """加载白名单"""
        whitelist_path = self.WHITELIST_FILE
        if os.path.exists(whitelist_path):
            try:
                with open(whitelist_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    urls = data.get("urls", []) if isinstance(data, dict) else data
                    if self.verbose:
                        print(f"[检测器] 已加载白名单: {len(urls)} 条记录")
                    return set(urls)
            except Exception as e:
                print(f"[检测器] 加载白名单失败: {e}")
        return set()
    
    def _save_whitelist(self):
        """保存白名单到文件"""
        os.makedirs("data", exist_ok=True)
        try:
            with open(self.WHITELIST_FILE, 'w', encoding='utf-8') as f:
                json.dump({"urls": list(self._whitelist), "updated_at": datetime.now().isoformat()},
                         f, ensure_ascii=False, indent=2)
            # 白名单已变更，刷新多级匹配索引
            self._rebuild_whitelist_index()
        except Exception as e:
            print(f"[检测器] 保存白名单失败: {e}")
    
    def add_to_whitelist(self, url: str):
        """添加URL到白名单"""
        self._whitelist.add(url)
        self._save_whitelist()
        print(f"[检测器] 已将URL加入白名单: {url}")
    
    def remove_from_whitelist(self, url: str):
        """从白名单移除URL"""
        self._whitelist.discard(url)
        self._save_whitelist()
        print(f"[检测器] 已将URL从白名单移除: {url}")
    
    # ========== 白名单多级匹配(规则与黑名单一致) ==========
    def _rebuild_whitelist_index(self):
        """重建白名单匹配索引(加载/增删白名单后刷新)

        - URL级索引: 支持"规范化 / 忽略协议 / 忽略查询参数"匹配
        - 域名级索引: 收录"纯域名/根路径"条目(如 example.com)，
          使该域名自身及其所有子域名、任意路径都被视为安全
        """
        url_index: Dict[str, Tuple[str, str]] = {}
        domain_index: Dict[str, str] = {}
        for entry in self._whitelist:
            for key, level in self._match_keys(entry, include_parent_paths=False):
                if key not in url_index:
                    url_index[key] = (entry, level)
            host, path, query = self._split_entry(entry)
            if host and (not path or path == "/") and not query and host not in domain_index:
                domain_index[host] = entry
        self._whitelist_norm = url_index
        self._whitelist_domain = domain_index
        self._whitelist_index_size = len(self._whitelist)

    def match_whitelist(self, url: str) -> Optional[Dict]:
        """在白名单中多级匹配URL: 命中返回详情字典, 未命中返回 None

        匹配级别与黑名单完全一致(从严格到宽松):
          精确匹配 / 规范化匹配 / 忽略协议匹配 / 忽略查询参数匹配 /
          父路径匹配(名单收录目录时, 其下路径同样命中) / 域名匹配
        """
        if self._whitelist_index_size != len(self._whitelist):
            self._rebuild_whitelist_index()

        for key, level in self._match_keys(url):
            hit = self._whitelist_norm.get(key)
            if hit:
                entry, _ = hit
                return {"entry": entry, "level": level, "key": key}

        # 域名级匹配: 逐级剥离子域名查表(至少保留两级域名)
        host, _, _ = self._split_entry(url)
        if host:
            labels = host.split(".")
            for i in range(0, max(1, len(labels) - 1)):
                candidate = ".".join(labels[i:])
                hit = self._whitelist_domain.get(candidate)
                if hit:
                    return {"entry": hit, "level": "域名匹配", "key": candidate}
        return None

    def is_in_whitelist(self, url: str) -> bool:
        """检查URL是否命中白名单(多级匹配)"""
        return self.match_whitelist(url) is not None
    
    def get_whitelist(self, limit: int = 200) -> List[str]:
        """获取白名单列表"""
        sorted_list = sorted(list(self._whitelist))
        if len(sorted_list) > limit:
            return sorted_list[-limit:]
        return sorted_list
    
    def get_whitelist_count(self) -> int:
        return len(self._whitelist)
    def on_detection(self, callback: Callable[[DetectionResult], None]):
        """注册检测回调函数"""
        self._on_detection_callbacks.append(callback)
    
    def _notify_callbacks(self, result: DetectionResult):
        """通知所有注册的回调"""
        for callback in self._on_detection_callbacks:
            try:
                callback(result)
            except Exception as e:
                print(f"[检测器] 回调执行失败: {e}")
    
    def detect(self, url: str, use_api: bool = False) -> DetectionResult:
        """
        对URL进行全面的恶意检测
        
        Args:
            url: 待检测的URL
            use_api: 是否使用外部API检测
            
        Returns:
            DetectionResult 检测结果对象
        """
        # 1. 验证URL格式
        if not url or not is_valid_url(url):
            return DetectionResult(
                url=url or "空",
                analyzer_result={
                    "score": 0,
                    "risk_level": "无效URL",
                    "risk_color": "dark",
                    "details": ["❌ URL格式无效"],
                    "is_malicious": True,
                }
            )
        
        # 1.5 白名单检查 → 100分（最安全）
        # 1.5 白名单检查 → 100分（最安全）
        #     多级匹配: 精确 / 规范化 / 忽略协议 / 忽略查询参数 / 域名
        whitelist_hit = self.match_whitelist(url)
        if whitelist_hit:
            wl_details = ["✅ 该URL位于白名单中，已通过安全检测"]
            if whitelist_hit["entry"] != url:
                wl_details.append(f"⇢ 匹配方式: {whitelist_hit['level']}，对应条目: {whitelist_hit['entry'][:120]}")
            return DetectionResult(
                url=url,
                analyzer_result={
                    "score": 100,
                    "risk_level": "白名单(安全)",
                    "risk_color": "primary",
                    "details": wl_details,
                    "is_malicious": False,
                },
                blacklist_match=False
            )
        
        # 2. 黑名单检查 → 0分（最危险）
        #    多级匹配: 精确 / 规范化 / 忽略协议 / 忽略查询参数 / 域名
        blacklist_hit = self.match_blacklist(url)
        blacklist_match = blacklist_hit is not None
        if blacklist_hit:
            category = blacklist_hit["category"]
            entry = blacklist_hit["entry"]
            hit_details = [f"⛔ 该URL命中黑名单，分类: {category}"]
            if entry != url:
                hit_details.append(f"⇢ 匹配方式: {blacklist_hit['level']}，对应条目: {entry[:120]}")
            return DetectionResult(
                url=url,
                analyzer_result={
                    "score": 0,
                    "risk_level": f"黑名单({category})",
                    "risk_color": "dark",
                    "details": hit_details,
                    "is_malicious": True,
                },
                blacklist_match=True
            )
        
        # 3. 启发式分析 → 原始分数(0-100, 越高越危险) → 新评分(越低越危险)
        #    传入 use_api: 分析器据此判断"安全链接 + 未启用AI"时是否精简检测详情
        analyzer_result = self.analyzer.analyze(url, use_api=use_api)
        raw_score = analyzer_result.get("score", 0)
        
        # 判定阈值来自设置页的"风险评分阈值"(默认 60)，由分析器统一给出，
        # 这样"是否恶意"与"评分换算"用的是同一个分界点(夹紧到 1-99 防止除零)
        try:
            threshold = int(analyzer_result.get("threshold", 60))
        except (TypeError, ValueError):
            threshold = 60
        threshold = max(1, min(99, threshold))

        # 3.5 DNS 解析检查 (可选, 由 detection.enable_dns_check 开关控制)
        #     域名无法解析是钓鱼站已下线的常见特征, 解析失败则在原始分上加 15
        if self.config.get("detection", "enable_dns_check"):
            dns_delta, dns_details = self._check_dns(url)
            if dns_delta:
                raw_score = max(0, min(100, raw_score + dns_delta))
                analyzer_result["score"] = raw_score
            analyzer_result["details"].extend(dns_details)

        # 3.6 安全链接的精简说明行("未启用AI辅助检测…")放到 DNS 检查结论之后。
        #     检测器的详情顺序: 关键结论 → 真实提示(⚠/ℹ) → DNS结论 → 说明行 → AI分析
        condense_note = analyzer_result.get("condense_note")
        if condense_note:
            analyzer_result["details"].append(condense_note)

        if raw_score >= threshold:
            # 原始危险(threshold ~ 100) → 新评分1-69(危险)
            new_score = 69 - int(((raw_score - threshold) / (100 - threshold)) * 68)
            new_score = max(1, min(69, new_score))
            is_malicious = True
            risk_level = "危险"
            risk_color = "danger"
        else:
            # 原始安全(0 ~ threshold-1) → 新评分70-99(安全)
            safe_span = max(1, threshold - 1)
            new_score = 99 - int((raw_score / safe_span) * 29) if raw_score > 0 else 99
            new_score = max(70, min(99, new_score))
            is_malicious = False
            risk_level = "安全"
            risk_color = "success"
        
        # 更新分析结果中的评分
        analyzer_result["score"] = new_score
        analyzer_result["is_malicious"] = is_malicious
        analyzer_result["risk_level"] = risk_level
        analyzer_result["risk_color"] = risk_color
        
        # 4. API检查 (可选) — DeepSeek AI 分析
        #    需同时满足: 调用方允许(use_api=True) 且 设置页开启 enable_api_check
        #    (未配置密钥时 _check_with_api 内部会自动跳过)
        api_result = None
        if use_api and self.config.get("detection", "enable_api_check"):
            api_result = self._check_with_api(url)
            
            # 如果 DeepSeek 返回了有效结果，融合到最终评分中
            if api_result and "error" not in api_result and "score" in api_result:
                ds_score = api_result["score"]
                ds_malicious = api_result.get("is_malicious", False)
                ds_reasons = api_result.get("reasons", [])
                
                # 将 DeepSeek 评分映射到当前评分体系 (0-100, 越低越危险)
                # DeepSeek 返回的 score 也是 0-100, 越低越危险
                new_score = int((new_score + ds_score) / 2)  # 取平均
                
                # 如果 DeepSeek 判定为恶意，增强判定
                if ds_malicious:
                    is_malicious = True
                    if risk_level == "安全":
                        risk_level = "可疑"
                        risk_color = "warning"
                
                # 添加 DeepSeek 的分析理由到详情
                for reason in ds_reasons:
                    analyzer_result["details"].append(f"🤖 [DeepSeek] {reason}")
                
                analyzer_result["details"].append(f"🤖 DeepSeek AI 评分: {ds_score}/100")
                
                # 更新分析结果
                analyzer_result["score"] = new_score
                analyzer_result["is_malicious"] = is_malicious
                analyzer_result["risk_level"] = risk_level
                analyzer_result["risk_color"] = risk_color
        
        # (ML 检测通道见下, 结果整合在其后)
        # 4.5 ML 检测通道(方案A: 域名模型 + 路径模型 并行) —— 与启发式引擎/DeepSeek 并行运行
        #     位置说明: 刻意放在 DeepSeek 融合"之后", 这样 AI 融合用到的三个量
        #     (new_score / is_malicious / risk_level) 完全不受 ML 影响;
        #     ML 自身只做"追加详情行 + (enforce 下按通道)提升判定", 绝不改动 0-100 分体系。
        ml_result = None
        if getattr(self, "ml_channel", None) is not None and self.ml_channel.available:
            ml_mode = str(self.config.get("detection", "ml_mode") or "shadow").lower()
            ml_result = self.ml_channel.predict(url)
            ml_result["mode"] = ml_mode
            if ml_result.get("ok"):
                # 每个通道一行(文案不含 "DeepSeek", 避免影响 Web 的 AI 徽章判定)
                for line in self.ml_channel.detail_lines(url, ml_result):
                    analyzer_result["details"].append(line)
                convict = list(ml_result.get("convict") or [])
                hint = list(ml_result.get("hint") or [])
                if ml_mode == "enforce" and convict:
                    # 该通道配置了 trigger_intercept=true → 允许单独定罪(参与拦截)
                    is_malicious = True
                    if risk_level == "安全":
                        risk_level = "可疑"
                        risk_color = "warning"
                    analyzer_result["details"].append(
                        "[ML] 高置信通道(%s): 由 ML 通道提升为「可疑」(参与拦截判定)"
                        % "、".join(convict))
                elif ml_mode == "enforce" and hint:
                    # 只提示不拦截(例如域名模型当前指标未达标, 采用"仅提示"档)
                    if risk_level == "安全":
                        risk_level = "可疑"
                        risk_color = "warning"
                    analyzer_result["details"].append(
                        "[ML] 高置信通道(%s): 仅提示, 当前未参与拦截" % "、".join(hint))
                # 影子模式: 以上分支都不执行, 只追加详情 → 行为与接入前完全一致
                analyzer_result["is_malicious"] = is_malicious
                analyzer_result["risk_level"] = risk_level
                analyzer_result["risk_color"] = risk_color


        # 5. 整合结果
        result = DetectionResult(url, analyzer_result, blacklist_match, api_result, ml_result)
        
        # 6. 记录日志
        self.reporter.log_detection(result)
        
        # 7. 通知回调
        self._notify_callbacks(result)
        
        return result
    
    def batch_detect(self, urls: List[str]) -> List[DetectionResult]:
        """批量检测多个URL"""
        return [self.detect(url) for url in urls]
    
    def _check_dns(self, url: str, timeout: float = 2.0) -> Tuple[int, List[str]]:
        """DNS 解析检查 — 域名无法解析时给出可疑加分

        许多钓鱼/恶意域名上线数小时~数天后就会被删除, 这类"域名不存在"的
        链接是明显的可疑信号; 能正常解析的域名不加分。

        Args:
            url: 待检测URL
            timeout: 单次解析超时(秒), 取较小值避免拖慢Web端检测

        Returns:
            (加分, 详情列表); IP直连或解析正常时加分为 0
        """
        features = extract_url_features(url)
        hostname = (features.get("hostname") or "").strip()
        if not hostname:
            return 0, []

        # IP 直连没有域名可解析, 该情况已由 _check_ip_address 计分, 此处跳过
        if is_ip_address(hostname):
            return 0, ["ℹ 目标为IP直连，跳过DNS解析检查"]

        if check_domain_resolves(hostname, timeout=timeout):
            return 0, [f"✅ 域名 {hostname} 可正常解析"]

        return 15, [f"⚠ 域名无法解析({hostname})，可能为已失效的钓鱼/恶意域名"]

    def _check_with_api(self, url: str) -> Optional[Dict]:
        """
        使用外部API检测 — 优先使用 DeepSeek AI 分析
        """
        deepseek_key = self.config.get("api_keys", "deepseek") or ""
        
        if deepseek_key:
            print(f"[检测器] 正在调用 DeepSeek AI 分析: {url[:50]}...")
            result = self.deepseek_analyzer.analyze(url)
            if "error" not in result:
                return result
            else:
                print(f"[检测器] DeepSeek 分析失败: {result['error']}")
        
        return {"message": "未配置有效的API密钥，跳过API检测"}
    def import_blacklist_from_urls(self, urls: List[str], default_category: str = "恶意URL") -> int:
        """从URL列表导入黑名单"""
        count = 0
        for url in urls:
            url = url.strip()
            if url and url not in self._blacklist:
                self._blacklist[url] = default_category
                count += 1
        if count > 0:
            self._save_blacklist()
        print(f"[检测器] 导入 {count} 条新黑名单记录")
        return count

    

    def import_from_public_feeds(self) -> Dict[str, int]:
        """从公开威胁情报源下载黑名单"""
        import urllib.request
        import ssl
        
        results = {}
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        
        feeds = [
            {"name": "URLhaus 恶意URL", "url": "https://urlhaus.abuse.ch/downloads/text/", "parser": "urlhaus", "category": "恶意URL"},
            {"name": "OpenPhish 钓鱼网站", "url": "https://openphish.com/feed.txt", "parser": "plain", "category": "钓鱼网站"},
        ]
        
        for feed in feeds:
            try:
                print(f"[检测器] 正在从 {feed['name']} 下载黑名单...")
                req = urllib.request.Request(feed['url'], headers={'User-Agent': 'Mozilla/5.0'})
                with urllib.request.urlopen(req, timeout=15, context=ssl_ctx) as response:
                    content = response.read().decode('utf-8', errors='ignore')
                    
                urls = []
                for line in content.split('\n'):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        if feed['parser'] == 'urlhaus' and '://' not in line:
                            line = 'http://' + line
                        urls.append(line)
                
                count = self.import_blacklist_from_urls(urls, feed['category'])
                results[feed['name']] = count
                print(f"[检测器] ✅ {feed['name']}: 新增 {count} 条 ({feed['category']})")
                
            except Exception as e:
                print(f"[检测器] ❌ {feed['name']} 下载失败: {e}")
                results[feed['name']] = -1
        
        return results

    def import_seed_blacklist(self) -> int:
        """导入内置种子黑名单"""
        seed_urls = [
            "free-money.tk", "win-prize.ml", "secure-login.ga",
            "account-verify.cf", "banking-update.gq",
            "free-prize.xyz", "you-win.top", "claim-gift.work",
            "login-verify.date", "secure-update.download",
            "apple-id-verify.ml", "paypal-security.ga",
            "netflix-update.tk", "amazon-account.gq",
            "download-free-software.tk", "crack-keygen.ga",
        ]
        count = 0
        for url in seed_urls:
            if url not in self._blacklist:
                self._blacklist[url] = "恶意URL"  # ← dict 用 key=value 赋值
                count += 1
        if count > 0:
            self._save_blacklist()
            print(f"[检测器] 已导入 {count} 条种子黑名单")
        return count

    def get_blacklist_count(self) -> int:
        self._sync_blacklist_if_changed()          # 外部导入后自动同步(无需重启)

        return len(self._blacklist)

    def get_blacklist(self, limit: int = 1000) -> List[Dict[str, str]]:
        self._sync_blacklist_if_changed()          # 外部导入后自动同步(无需重启)
        """获取黑名单列表，返回 [(url, category), ...]

        新规则: 用户手动添加的条目**置顶**显示(最新添加的在最前),
        其余条目维持原有行为(按URL字母序取末尾 limit 条),
        因此黑名单原有的内容与展示顺序逻辑都不受影响。
        """
        pinned = [(entry, self._blacklist[entry]) for entry in reversed(self._user_added)
                  if entry in self._blacklist]
        pinned_set = set(self._user_added)
        rest = [(url, category) for url, category in sorted(self._blacklist.items())
                if url not in pinned_set]
        remaining = max(0, limit - len(pinned))
        if remaining and len(rest) > remaining:
            rest = rest[-remaining:]
        elif not remaining:
            rest = []
        return pinned[:limit] + rest