"""
URL分析模块 - 核心启发式分析引擎
对URL进行多维度特征分析，计算安全风险评分
"""

import re
import math
from urllib.parse import unquote
from typing import Dict, List, Tuple, Optional

from utils import (
    extract_url_features, is_shortened_url, is_ip_address,
    count_subdomains, is_suspicious_tld, tld_risk_score, extract_domain,
    # 新增工具: 位置化关键词 / 信任域 / 仿冒域名 / 随机域名 / 文件类型 / 模式库
    analyze_suspicious_keywords, is_trusted_host, get_registered_domain,
    get_domain_label, simplified_letters,
    similarity_ratio, levenshtein_distance, is_dga_like_label,
    is_ip_like_hostname, is_free_hosting, classify_extension,
    match_pattern_library, DANGEROUS_SCHEMES, TRUSTED_DOMAINS,
    match_adult_keywords, SUSPICIOUS_KEYWORDS,
)

class URLAnalyzer:
    """
    URL分析器 - 使用多种启发式方法分析URL的安全性

    评分维度(每项返回"危险加分", 累加后夹紧到 0-100):
    - URL结构异常     长度 / 特殊字符 / @符号 / 编码混淆
    - 域名信誉        可疑TLD / IP直连 / 免费主机 / 随机域名(DGA)
    - 仿冒域名        品牌仿冒 / 同形字 / punycode / 品牌出现在子域或路径
    - 关键词匹配      位置加权(域名 > 路径 > 查询参数)
    - 下载与跳转      高危扩展名 / 内嵌协议或域名 / 短链接
    - 模式库匹配      data/malicious_patterns.json + suspicious_domains.json
    - 组合放大        多个独立维度同时命中时额外加分
    分数越高越危险, 是否判定为恶意由 detection.heuristic_threshold 决定。
    """

    # 已知的合法大型网站域名(命中注册域或子域时大幅降低误报)
    SAFE_DOMAINS = TRUSTED_DOMAINS

    # 常见品牌域名, 用于检测域名仿冒
    BRAND_DOMAINS = {
        "google", "gmail", "youtube", "facebook", "instagram", "whatsapp",
        "twitter", "linkedin", "tiktok", "telegram", "discord", "steam",
        "microsoft", "outlook", "hotmail", "office365", "onedrive", "windows",
        "apple", "icloud", "itunes", "amazon", "netflix", "spotify", "paypal",
        "binance", "coinbase", "metamask", "blockchain", "wallet", "visa",
        "mastercard", "chase", "wellsfargo", "citibank", "hsbc", "barclays",
        "dhl", "fedex", "usps", "ups", "aliexpress", "alibaba", "dropbox",
        "adobe", "cloudflare", "roblox", "epicgames", "minecraft",
        # 中文/国内品牌
        "taobao", "tmall", "alipay", "wechat", "weixin", "tencent", "qq",
        "baidu", "jd", "pinduoduo", "douyin", "meituan", "didi", "xiaomi",
        "huawei", "bilibili", "zhihu", "weibo", "12306", "unionpay",
        "icbc", "ccb", "abchina", "boc", "cmb", "pingan",
        "支付宝", "微信", "淘宝", "天猫", "京东", "银行", "银联",
    }

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        # 预计算品牌的同形字归一化形式(g00gle→google), 避免每次检测重复计算
        self._normalized_brands = {simplified_letters(b): b for b in self.BRAND_DOMAINS}

    def analyze(self, url: str, use_api: Optional[bool] = None) -> Dict:
        """
        对URL进行全面分析，返回详细的评分报告

        Args:
            url: 待分析的URL
            use_api: 本次检测是否启用了AI辅助检测(由检测器传入)。
                     判定为"安全链接"且未启用AI时, 只输出最关键的几项检测结论
                     (例如"未命中已知恶意/钓鱼模式库"), 避免详情列表过长;
                     传 None 时按配置项 detection.enable_api_check 判断。

        Returns:
            包含评分、风险等级、详细分析的报告字典

        说明:
            - score 为各规则"危险加分"的累加值(0-100, 越高越危险);
            - is_malicious 的裁决线由配置项 detection.heuristic_threshold 决定
              （可在设置页调整，默认 60），并通过 threshold 字段一并返回，
              供检测器换算 Web 端评分时使用同一个分界点;
            - matched_rules 记录本次命中的规则维度, trusted_host 标记是否可信站点,
              便于排查"一条URL为什么被判高分"(也可用于后续调参)。
        """
        # 本次检测是否会真正调用AI(用于决定"安全链接"是否精简检测详情)
        ai_enabled = (self._switch("enable_api_check", False) if use_api is None
                      else (bool(use_api) and self._switch("enable_api_check", False)))

        features = extract_url_features(url)
        if not features:
            return {
                "score": 100,
                "risk_level": "高风险",
                "risk_color": "red",
                "details": ["无法解析URL"],
                "is_malicious": True,
                "matched_rules": ["invalid_url"],
            }

        details: List[str] = []
        score = 0
        matched_rules: List[str] = []

        hostname = features.get("hostname", "")
        # 可信站点(常见合法站点/教育政府域): 用于跳过强误报规则并降低最终分
        trusted = is_trusted_host(hostname)

        def hit(rule: str, points: int, passed_detail: str = "") -> int:
            """记录命中的规则维度并累加分数(供最后的组合放大使用)

            passed_detail: 该项"检查通过"时写入检测详情的说明。
            这样"安全链接"也能像"恶意链接"一样逐条展示完整检测过程 ——
            关闭AI辅助检测时尤其明显(否则详情里几乎只有"未发现异常特征")。
            """
            nonlocal score
            if points > 0:
                matched_rules.append(rule)
                score += points
            elif passed_detail:
                details.append(passed_detail)
            return points

        # ========== 1. 非网络协议(强特征, 单项即可越阈值) ==========
        scheme = features.get("scheme", "")
        if scheme in DANGEROUS_SCHEMES:
            details.append("⛔ 使用了非网络协议 {}://，常见于XSS/本地文件读取攻击".format(scheme))
            hit("dangerous_scheme", 60)
        else:
            details.append("✅ 协议正常（{}），不是 javascript:/data: 这类伪造协议".format(scheme or "http"))

        # ========== 2. 结构与字符特征 ==========
        hit("url_length", self._check_url_length(url, features, details),
            "✅ URL 长度正常（共 {} 个字符）".format(len(url)))
        if self._switch("check_ip_url"):
            hit("ip_host", self._check_ip_address(features, details),
                "✅ 主机是域名而非IP直连（{}）".format(hostname or "未知"))
        if self._switch("check_suspicious_tlds"):
            hit("suspicious_tld", self._check_suspicious_tld(features, details),
                "✅ 顶级域名 .{} 不在高风险域名名单中".format(features.get("tld") or "无"))
        if self._switch("check_shortened_urls"):
            hit("shortener", self._check_shortened_url(features, details),
                "✅ 未使用短链接跳转服务")
        hit("subdomain", self._check_excessive_subdomains(features, details),
            "✅ 子域名层级正常（共 {} 级）".format(count_subdomains(hostname)))
        hit("special_chars", self._check_special_chars(url, features, details),
            "✅ 未发现非法字符或异常连字符")
        hit("at_symbol", self._check_at_symbol(url, features, details),
            "✅ 主机部分不含@符号（未使用地址隐藏手法）")
        hit("no_https", self._check_https(features, details),
            "✅ 已使用 HTTPS 加密连接")
        hit("port", self._check_suspicious_port(features, details),
            "✅ 使用常规端口（{}）".format(features.get("port") or "默认 80/443"))
        hit("encoded", self._check_encoded_chars(url, features, details),
            "✅ 未发现异常URL编码（无混淆痕迹）")

        # ========== 3. 可疑关键词(按出现位置加权, 降低正常站点误报) ==========
        if self._switch("check_suspicious_keywords"):
            hit("keywords", self._check_suspicious_keywords(url, features, details, trusted),
                "✅ 未在域名/路径/参数中发现可疑关键词")

        # ========== 4. 仿冒域名/随机域名/免费主机/危险下载/内嵌地址/模式库 ==========
        if self._switch("check_typosquatting"):
            hit("typosquatting", self._check_typosquatting(features, details, trusted),
                "✅ 域名主体'{}'与已知品牌无同形字或近似拼写关系".format(
                    get_domain_label(hostname) or hostname or "未知"))
        if self._switch("check_deceptive_domain"):
            hit("deceptive_domain", self._check_deceptive_domain(features, details, trusted),
                "✅ 域名结构正常（非 punycode 编码，品牌词未出现在子域名/路径中）")
            hit("free_hosting", self._check_free_hosting(features, details, trusted),
                "✅ 未托管在免费主机/动态DNS上")
        if self._switch("check_dga"):
            hit("dga", self._check_dga_domain(features, details, trusted),
                "✅ 域名字符分布正常，不具备批量注册(DGA)特征")
        if self._switch("check_dangerous_extension"):
            hit("dangerous_extension", self._check_dangerous_extension(features, details),
                "✅ 链接未指向可执行/脚本类高危文件")
        hit("embedded_url", self._check_embedded_url(url, features, details),
            "✅ URL 内未嵌套其它地址（无跳转伪装）")
        if self._switch("check_malicious_patterns"):
            hit("pattern_library", self._check_malicious_patterns(features, details),
                "✅ 未命中已知恶意/钓鱼模式库")
        # 「域名 × 路径」组合信号（钓鱼 / 恶意下载的典型形态）
        hit("combo", self._check_domain_path_combo(features, details, trusted),
            "✅ 域名与路径未构成组合风险")
        if self._switch("check_adult_content"):
            hit("adult_content", self._check_adult_content(features, details, trusted),
                "✅ 未发现成人/赌博类内容特征")



        # 可信站点提示: 让用户知道为什么某些正常站点的个例特征被忽略
        if trusted:
            details.append("✅ 域名属于可信站点名单（{}），已按白名单策略降低风险分".format(
                get_registered_domain(hostname) or hostname))

        # ========== 5. 组合放大: 多个独立维度同时命中 ==========
        #     单一弱特征(如缺少HTTPS)不该定罪, 但"仿冒域名+危险下载+内嵌地址"
        #     这种多特征互相印证的情况, 综合风险应显著高于各项之和的平均。
        strong_rules = {
            "dangerous_scheme", "typosquatting", "deceptive_domain",
            "pattern_library", "embedded_url", "dangerous_extension",
            "at_symbol", "ip_host",
        }
        strong_hits = strong_rules.intersection(matched_rules)
        if len(strong_hits) >= 2:
            score += 15
            details.append("⚠ {}项独立恶意特征同时命中，综合风险显著提高".format(len(strong_hits)))
        elif strong_hits and len(matched_rules) >= 2:
            # 强特征 + 其它可疑特征(明文HTTP、路径关键词等)互相印证, 综合风险提高
            score += 10
            details.append("⚠ 命中强特征({})并伴随其它可疑特征，综合风险提高".format(
                "、".join(sorted(strong_hits))))
        elif len(matched_rules) >= 4:
            score += 8
            details.append("ℹ 共命中{}项可疑特征，综合风险提高".format(len(matched_rules)))

        # 归一化分数到 0-100
        final_score = max(0, min(100, score))

        # 可信站点降权: 避免正常站点的"个例特征"被判成恶意
        # (强特征仍可能让分数留在阈值之上, 属于有意保留的保守策略)
        if trusted and final_score > 0:
            final_score = max(0, final_score - 40)

        # 判定阈值: 取自设置页的"风险评分阈值"(detection.heuristic_threshold)
        threshold = self._get_threshold()

        # 确定风险等级
        risk_level, risk_color = self._get_risk_level(final_score)

        # 结论行: 只在判定为恶意时追加。
        # 安全链接不再显示"✅ 综合评分 … 判定为安全链接"(按要求精简,
        # 前面的关键结论已足以说明它是安全的)。
        condense_note = ""
        if final_score >= threshold:
            details.append("⛔ 综合评分 {}/100 达到判定阈值 {}，判定为恶意链接".format(final_score, threshold))
        else:
            # 安全链接: 无论是否启用AI辅助检测, 详情都只保留最关键的几项。
            # 精简说明行不直接放进 details, 而是通过 condense_note 返回给检测器,
            # 由它在 DNS 检查结论("✅ 域名 xxx 可正常解析")之后插入 —— 阅读顺序更自然。
            details = self._condense_safe_details(details, matched_rules)
            condense_note = ("ℹ 安全链接仅展示关键检测结论（逐项检查过程已省略，AI分析见下方）" if ai_enabled
                             else "ℹ 未启用AI辅助检测，安全链接仅展示关键检测结论（逐项检查过程已省略）")

        return {
            "score": final_score,
            "risk_level": risk_level,
            "risk_color": risk_color,
            "details": details,
            # 分数达到阈值即判定为恶意(阈值越小越严格)
            "is_malicious": final_score >= threshold,
            "threshold": threshold,
            "url": url,
            "domain": extract_domain(url),
            "matched_rules": matched_rules,
            "trusted_host": trusted,
            # 安全链接精简后的说明行(可为空串): 由检测器在DNS检查结论之后追加,
            # 这样"未启用AI辅助检测…"会排在"✅ 域名 xxx 可正常解析"之后
            "condense_note": condense_note,
        }

    def _check_url_length(self, url: str, features: Dict, details: List) -> int:
        """检查URL长度 - 超长URL往往是攻击特征"""
        max_len = self.config.get("max_url_length", 2000)
        if len(url) > max_len:
            details.append("⚠ URL长度异常: 超过{}字符".format(max_len))
            return 15
        elif len(url) > 1000:
            details.append("⚠ URL较长: {}字符".format(len(url)))
            return 8
        elif len(url) > 500:
            details.append("ℹ URL略长: {}字符".format(len(url)))
            return 3
        return 0

    @staticmethod
    def _is_private_or_reserved(hostname: str) -> bool:
        """内网/保留地址判定（家用路由、NAS、公司内网、IPv6 本地地址…）

        这类"IP 直连"是正常行为, 不该算可疑；注意十进制整数写法也要解出来判断
        （3232235777 = 192.168.1.1）。
        """
        import ipaddress
        host = (hostname or "").strip("[]").strip().lower()
        if not host:
            return False
        ip = None
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            if host.isdigit():
                try:
                    ip = ipaddress.ip_address(int(host))
                except ValueError:
                    return False
            else:
                return False
        return bool(ip.is_private or ip.is_loopback or ip.is_link_local
                    or ip.is_reserved or ip.is_multicast or ip.is_unspecified)

    def _check_ip_address(self, features: Dict, details: List) -> int:
        """检查是否使用 IP 地址代替域名（分级）

        IP 直连在民用浏览里本来就罕见, 是"隐藏真实站点身份"的典型手法:
          * 内网/保留地址        → 0 分（家用路由 / NAS 管理页很常见, 不该算可疑）
          * 公网点分十进制      → 45 分（再配可疑端口 / 路径关键词就能越过阈值 60）
          * 非标准写法(整数/十六进制/八进制) → 60 分（明确是绕过检测的手法, 单独定罪）
        """
        hostname = features.get("hostname", "")
        if not hostname:
            return 0
        if self._is_private_or_reserved(hostname):
            return 0
        if is_ip_address(hostname):
            details.append("⚠ 使用公网 IP 直连（正常网站几乎不会这样），疑似隐藏真实站点身份")
            return 45
        if is_ip_like_hostname(hostname):
            # 非标准写法(十进制/十六进制/八进制/IPv6 字面量)比点分十进制更可疑
            details.append("⚠ 使用非标准写法的 IP({})，疑似绕过检测".format(hostname))
            return 60
        return 0

    def _check_suspicious_tld(self, features: Dict, details: List) -> int:
        """检查是否使用可疑的顶级域名（分级：恶意富集倍数越高, 分越高）

        分值来自 data/tld_risk.json（按 lift 分 20/12/6）; 没有该文件时回退到内置表（12 分）。
        最高 20 分仍远低于判定阈值 60 —— 只参与评分, 不会单独定罪。
        """
        hostname = features.get("hostname", "")
        score, lift, tld = tld_risk_score(hostname)
        if score > 0:
            details.append("⚠ 使用高风险顶级域名(.{}): 恶意富集 {:.0f} 倍（数据驱动）".format(
                tld, lift))
            return score
        if is_suspicious_tld(hostname):
            details.append("⚠ 使用可疑顶级域名(.{}), 常被恶意站点使用".format(
                hostname.split('.')[-1]))
            return 12
        return 0

    def _check_shortened_url(self, features: Dict, details: List) -> int:
        """检查是否为短链接"""
        url = features.get("full_url", "")
        if is_shortened_url(url):
            details.append("⚠ 检测到URL短链接，可能隐藏真实目的地")
            return 10
        return 0

    def _check_excessive_subdomains(self, features: Dict, details: List) -> int:
        """检查子域名数量是否过多

        注意: IP 地址没有"子域"概念（8.8.8.8 会被数成 2 级子域 +5 分）,
        这类由 ip_host 规则单独负责, 这里要跳过, 否则 IP 直连的分数会虚高。
        """
        hostname = features.get("hostname", "")
        if is_ip_address(hostname) or is_ip_like_hostname(hostname):
            return 0
        sub_count = count_subdomains(hostname)
        if sub_count >= 4:
            details.append("⚠ 子域名过多({}级), 可能为伪装域名".format(sub_count))
            return 12
        elif sub_count >= 2:
            details.append("ℹ 子域名较多({}级)".format(sub_count))
            return 5
        return 0

    def _check_special_chars(self, url: str, features: Dict, details: List) -> int:
        """检查URL中的特殊字符

        修正说明: 原实现里 '@' 在此处加 10 分、_check_at_symbol 又加 10 分,
        同一特征被重复计分(原注释却写着"不重复加分")。现在 '@' 只由
        _check_at_symbol 判断, 且只针对主机部分 —— 查询参数里的 '@'
        (如 ?mail=a@b.com)属于正常写法, 不应计分。
        """
        hostname = features.get("hostname", "")
        score = 0

        # 域名中的连字符过多(仿冒域名常见形式: secure-login-verify.tk)
        # 收紧（实测这条规则在正常站上的命中率是恶意站的 3 倍）: 现代合法站也常用连字符,
        # 只有"连字符多 + 域名里带敏感词"才给高分, 否则只给少量分。
        # 注意: punycode 的 "xn--" 前缀不是"仿冒连字符", 先剔除再数
        dash_count = hostname.replace("xn--", "").count('-')
        if dash_count > 2:
            sensitive = any(word in hostname for word in SUSPICIOUS_KEYWORDS if len(word) >= 4)
            if sensitive:
                details.append("⚠ 域名包含多个连字符且含敏感词，疑似仿冒域名")
                score += 8
            elif dash_count >= 4:
                details.append("ℹ 域名包含较多连字符")
                score += 3

        # URL中的非法/危险符号
        special_chars = ['<', '>', '"', "'", '{', '}', '|', '\\', '^', '`']
        for char in special_chars:
            if char in url:
                details.append("⚠ URL包含非法字符: '{}'".format(char))
                score += 5
                break

        return score

    def _check_suspicious_keywords(self, url: str, features: Dict, details: List, trusted: bool = False) -> int:
        """检查可疑关键词(按出现位置加权)

        位置权重: 域名 8分/个(上限24) > 路径 5分/个(上限15) > 查询参数 2分/个(上限6)。
        这样既保留"URL含 login/verify 等词"的检出能力, 又避免把
        github.com/login、google.com/search?q=paypal 这类正常地址判成可疑:
        - 可信站点完全跳过路径与查询参数中的关键词;
        - 其它站点若关键词只出现在查询参数里, 也只会加很少的分。
        """
        hits = analyze_suspicious_keywords(url)
        domain_hits, path_hits, query_hits = hits["domain"], hits["path"], hits["query"]

        score = min(24, len(domain_hits) * 8)
        if not trusted:
            score += min(15, len(path_hits) * 5)
            score += min(6, len(query_hits) * 2)

        if score > 0:
            shown = ", ".join((domain_hits + path_hits + query_hits)[:5])
            where = []
            if domain_hits:
                where.append("域名")
            if path_hits and not trusted:
                where.append("路径")
            if query_hits and not trusted:
                where.append("参数")
            details.append("⚠ 检测到可疑关键词({}): {}".format("/".join(where), shown))
        return score

    def _check_typosquatting(self, features: Dict, details: List, trusted: bool = False) -> int:
        """检测域名仿冒(typosquatting / 同形字 / 品牌拼接)

        三种手段(取分值最高的一项, 不叠加):
        1. 同形字归一化: g00gle.com、аpple.com(西里尔字母) → google/apple;
        2. 编辑距离: gooogle.com、paypa1.com、app1e.com 这类"只差一两个字符";
        3. 品牌拼接: paypal-secure-login.com、appleid-verify.com 这类
           "品牌词+诱导词"的域名(只对长度>=4的品牌词启用, 避免 jd/qq 等短词误报)。
        可信站点直接跳过。
        """
        hostname = features.get("hostname", "").lower()
        if trusted or not hostname:
            return 0

        label = get_domain_label(hostname)
        if not label:
            return 0
        # 归一化: 先合并易混淆的字母组合(rn→m), 再替换同形字(0→o、1→l)
        normalized_label = simplified_letters(label)

        candidates = []
        for brand_norm, brand in self._normalized_brands.items():
            if label == brand and normalized_label == brand_norm:
                continue        # 品牌自身的正常写法, 不是仿冒

            # 1) 同形字还原后与品牌完全一致(g00gle / аpple / paypa1)
            #    这类域名不可能是品牌的官方域名, 属于强证据, 单项 55 分
            if normalized_label == brand_norm:
                candidates.append((55, "域名'{}'与品牌'{}'同形(混用了数字或形近字符)".format(label, brand)))
                continue

            # 2) 品牌词被拼进域名(paypal-secure-login / appleid-verify)
            #    只对长度>=5的品牌词启用, 避免 visa/ups/jd 这类短品牌误报
            if len(brand) >= 5 and brand in label:
                candidates.append((35, "域名'{}'包含品牌词'{}'但并非其官方域名".format(label, brand)))
                continue

            # 3) 编辑距离很近的拼写仿冒(gooogle / paypa1 / app1e)
            if len(brand) >= 5:
                distance = levenshtein_distance(brand_norm, normalized_label, max_distance=2)
                if 1 <= distance <= 2:
                    candidates.append((45 if distance == 1 else 30,
                                       "域名'{}'与品牌'{}'仅相差{}个字符".format(label, brand, distance)))

        if not candidates:
            return 0
        score, reason = max(candidates, key=lambda item: item[0])
        details.append("⚠ 疑似域名仿冒: {}".format(reason))
        return score

    def _check_at_symbol(self, url: str, features: Dict, details: List) -> int:
        """检查主机部分的@符号 - 浏览器会忽略@之前的内容

        例如 http://www.google.com@evil.com/ 看起来像 google 域名, 实际访问的
        是 evil.com —— 这是明确的地址欺骗(正常URL不会这样写), 因此单项给 45 分。
        只检查主机部分(netloc), 查询参数里的 '@'(?mail=a@b.com)属于正常写法。
        """
        netloc = (features.get("netloc") or "").split("#")[0]
        if "@" in netloc:
            details.append("⚠ 主机部分包含@符号，@ 之后的域名才是真实访问地址")
            return 45
        return 0

    def _check_deceptive_domain(self, features: Dict, details: List, trusted: bool = False) -> int:
        """检测欺骗性域名结构: punycode 同形域名 / 品牌名被放进子域名

        两种典型钓鱼结构:
        - xn--80ak6aa92e.com          punycode 编码, 用于伪装西里尔/希腊字母同形域名;
        - paypal.com.secure-login.xyz 把品牌放到子域名, 真实注册域名是 secure-login.xyz,
          用户扫一眼很容易以为在访问 paypal.com。
        可疑程度取分值最高的一项, 不叠加。
        """
        if trusted:
            return 0
        hostname = features.get("hostname", "")
        if not hostname:
            return 0

        candidates = []

        # 1) punycode 子域名: 只有"解码后像某个品牌"才算同形字钓鱼
        #    （合法国际化域名 xn--fiqs8s(=中国)、以及 .xn--p1ai(=俄语 .рф) 这类
        #      后缀都不应计分 —— 之前一刀切 18 分, 实测把一整批合法 IDN 站判成可疑）
        labels = [x for x in hostname.split(".") if x]
        suspicious_puny = []
        for lab in labels[:-1]:
            if not lab.startswith("xn--"):
                continue
            try:
                import codecs
                # xn-- 之后就是 punycode 编码内容; 用 punycode codec 解码最稳
                # （idna codec 对单个 label / 部分字符会抛异常）
                decoded = codecs.decode(lab[4:].encode("ascii"), "punycode")
            except Exception:
                continue
            if not decoded:
                continue
            # 同形字的本质是"看起来像、码点不同"（如西里尔 аррӏе vs 拉丁 apple）,
            # 直接算编辑距离会是 0 相似度 —— 必须先做同形字归一化再比。
            normalized = simplified_letters(decoded)
            near = [b for b in self.BRAND_DOMAINS
                    if len(b) >= 4 and similarity_ratio(normalized, b) >= 0.75]
            if near:
                suspicious_puny.append((lab, near[0]))
        if suspicious_puny:
            candidates.append((20, "使用 punycode(xn--)子域名伪装成 '{}'".format(
                suspicious_puny[0][1])))

        # 2) 品牌词出现在子域名中, 而注册域名里并没有该品牌
        registered = get_registered_domain(hostname)
        subdomain_part = hostname[:len(hostname) - len(registered)].lower() if registered else hostname
        brand_in_sub = [b for b in self.BRAND_DOMAINS if len(b) >= 4 and b in subdomain_part]
        if brand_in_sub:
            candidates.append((20, "品牌词'{}'被放在子域名中，真实注册域名是'{}'".format(
                brand_in_sub[0], registered or hostname)))

        # 3) 路径里出现品牌词(evil.com/paypal/login), 且注册域名本身不是该品牌
        path = (features.get("path") or "").lower()
        brand_in_path = [b for b in self.BRAND_DOMAINS if len(b) >= 4 and b in path]
        if brand_in_path and not any(b in registered.lower() for b in brand_in_path):
            candidates.append((10, "路径中出现品牌词'{}'，可能伪装成该品牌页面".format(brand_in_path[0])))

        if not candidates:
            return 0
        score, reason = max(candidates, key=lambda item: item[0])
        details.append("⚠ 可疑域名结构: {}".format(reason))
        return score

    def _check_free_hosting(self, features: Dict, details: List, trusted: bool = False) -> int:
        """检查是否托管在免费主机/动态DNS(短命钓鱼站高发区)

        单项只加 8 分(不少正常博客/小站也在用), 主要作用是与关键词、
        仿冒域名规则叠加, 让"免费主机 + 诱导关键词"的组合更容易越过阈值。
        """
        hostname = features.get("hostname", "")
        if trusted or not hostname:
            return 0
        if is_free_hosting(hostname):
            details.append("ℹ 站点托管在免费主机/动态DNS({})上，可信度较低".format(
                get_registered_domain(hostname)))
            return 8
        return 0

    def _check_dga_domain(self, features: Dict, details: List, trusted: bool = False) -> int:
        """检测随机生成域名(DGA)/批量注册域名

        判据(命中2项以上): 主体长度>=10、数字占比>=30%、元音比例<=22%、
        连续辅音>=4、字符熵>=3.3、包含4位以上连续数字。
        例: xjkqvzmtb3q9w.com、kq7f2m9xzt.xyz —— 正常品牌域名不会命中。
        """
        hostname = features.get("hostname", "")
        if trusted or not hostname:
            return 0
        label = get_domain_label(hostname)
        if not is_dga_like_label(label):
            return 0
        # 收紧（实测这条规则在正常站上的命中率反而比恶意站高）:
        #   纯字母的长词（欧洲语言常见, 如 zahranicneonlinecasinobonusbezvkladu）不算 DGA;
        #   必须"含数字"或"元音极少"才认定, 并把分值从 12 降到 8。
        chars = [c for c in label if c.isalnum()]
        if not chars:
            return 0
        digit_ratio = sum(c.isdigit() for c in chars) / float(len(chars))
        vowel_ratio = sum(c in "aeiou" for c in chars) / float(len(chars))
        if digit_ratio < 0.15 and vowel_ratio > 0.12:
            return 0
        details.append("⚠ 域名'{}'形似随机生成(数字/辅音比例异常)，常见于批量注册的恶意域名".format(label))
        return 8

    def _check_dangerous_extension(self, features: Dict, details: List) -> int:
        """检查链接是否指向高危可执行/脚本文件(挂马下载的典型形式)"""
        ext, level = classify_extension(features.get("path", ""))
        if level == "high":
            details.append("⚠ 链接指向可执行/脚本文件(.{})，下载运行风险极高".format(ext))
            return 18
        if level == "medium":
            details.append("ℹ 链接指向宏文档/镜像等文件(.{})，请确认来源".format(ext))
            return 8
        return 0

    def _check_embedded_url(self, url: str, features: Dict, details: List) -> int:
        """检测URL中内嵌的协议/地址(多层跳转与地址欺骗)

        - http://good.com/http://evil.com/login   路径里又嵌了一个完整地址;
        - http://good.com/login@evil.com/x        路径里的 '@' 会让部分组件误判主机;
        这两种写法正常URL都不会出现, 因此单项给 45 / 30 分;
        而正常的跳转参数(?url=https://good.com)只做提示、不加分, 避免误伤。
        """
        path = features.get("path", "") or ""
        query = features.get("query", "") or ""

        if re.search(r"https?://", path, re.IGNORECASE):
            details.append("⚠ URL路径中嵌套了完整的 http(s) 地址，可能是跳转欺骗")
            return 45
        if "@" in path:
            details.append("⚠ URL路径中包含@符号，可能是伪造的地址")
            return 30
        if "//" in path:
            details.append("ℹ URL路径中出现双斜杠，可能是路径混淆写法")
            return 5
        if re.search(r"https?%3a%2f%2f", query, re.IGNORECASE):
            details.append("ℹ 查询参数中以URL编码形式携带了外部地址，注意跳转目标")
            return 5
        return 0

    def _check_domain_path_combo(self, features: Dict, details: List,
                                 trusted: bool = False) -> int:
        """「域名 × 路径」组合信号（单看任一侧都不够，组合起来才是典型恶意形态）

        A) 品牌词域名（注册域标签含品牌词，但不是品牌自己的域）+ 登录/验证类路径 → 40 分
           例：paypal-verify.xyz/login、appleid-verify.com/account
           （paypal.com/login 不算 —— 注册域标签就是品牌本身）
        B) 危险扩展名 + 下载/诱导词 → 30 分
           例：example.com/download/setup.exe、files.xyz/free/crack.msi
        C) 路径段是长随机串（≥16 位且字母数字混合）→ 20 分
           例：evil.com/a8f3k2j9x0q7m5n2p（恶意重定向 / 载荷）

        最高 40 分 —— 不单独定罪（阈值 60），但和 TLD/关键词/IP 等信号叠加即可越线。
        可信站点跳过。
        """
        if trusted:
            return 0
        host = features.get("hostname", "")
        path = (features.get("path") or "").lower()
        query = (features.get("query") or "").lower()
        if not host or (not path and not query):
            return 0
        registered = (get_registered_domain(host) or host).lower()
        reg_label = registered.split(".")[0] if registered else ""

        best, reason = 0, ""

        # A) 品牌词域名 + 登录类路径
        login_words = ("login", "signin", "sign-in", "verify", "verification",
                       "account", "password", "unlock", "authorize", "auth")
        brands = [b for b in self.BRAND_DOMAINS if len(b) >= 4 and b in host]
        hit_login = [w for w in login_words if w in path or w in query]
        if brands and hit_login and reg_label != brands[0]:
            best = 40
            reason = ("域名含品牌词 '{}' 但注册域是 '{}'，路径又是登录/验证动作 '{}'"
                      .format(brands[0], registered, hit_login[0]))

        # B) 危险扩展名 + 下载/诱导词
        if best < 30:
            last_segment = path.split("?")[0].rsplit("/", 1)[-1]
            ext = ("." + last_segment.rsplit(".", 1)[-1]) if "." in last_segment else ""
            danger_ext = (".exe", ".msi", ".scr", ".bat", ".cmd", ".ps1", ".vbs",
                          ".hta", ".jar", ".apk", ".dmg", ".iso", ".lnk")
            download_words = ("download", "setup", "install", "installer", "update",
                              "free", "crack", "keygen", "patch", "activation",
                              "loader", "下载", "破解", "绿色")
            if ext in danger_ext and any(w in path or w in query for w in download_words):
                best = 30
                reason = "路径是危险文件 {} 且含下载/诱导词".format(ext)

        # C) 路径长随机串
        if best < 20:
            for segment in [s for s in path.split("/") if s]:
                core = segment.split(".")[0]
                if len(core) >= 16:
                    letters = sum(c.isalpha() for c in core)
                    digits = sum(c.isdigit() for c in core)
                    if letters >= 8 and digits >= 4:
                        best = 20
                        reason = "路径含长随机串 '{}…'".format(core[:12])
                        break

        if best:
            details.append("⚠ 组合信号({} 分): {}".format(best, reason))
        return best

    def _check_adult_content(self, features: Dict, details: List, trusted: bool = False) -> int:
        """成人/赌博类内容检测（分档：按证据强度给不同分值）

        分档设计（C2）:
          * 知名成人品牌（pornhub / xvideos …）      → 85 分（证据最强，单独定罪）
          * 赌博类（casino / bet365 …）              → 80 分
          * 成人强词（porn / xxx / hentai …）        → 75 分
          * 弱词（sex / adult / jav，仅整标签匹配）   → 45 分（需配合其它信号）
          * 路径 / 参数命中                          → 25 分（仅提示）
          * 组合：成人/赌博命中 **且** TLD 恶意富集 lift≥20 → 再 +10

        为什么不再"一票 85"：一条规则直接越过阈值，会把其它 17 条规则的分数完全
        掩盖（评分退化成开关）。分档后既保留"强证据直接定罪"，又让弱证据能被其它
        信号补足；后续按类别调阈值、做组合规则才有依据。

        误伤防护（保持原设计）:
          - 可信站点直接跳过；
          - 弱词只做"完整域名标签"匹配 → sexeducation.com / adultlearning.com 不命中；
          - 词表在 data/adult_keywords.json，可随时增删而不必改代码。
        """
        if trusted:
            return 0
        hostname = features.get("hostname", "")
        hits = match_adult_keywords(hostname, features.get("path", ""),
                                    features.get("query", ""))
        if not hits:
            return 0

        brands = list(hits.get("adult_brands") or [])
        gambling = list(hits.get("gambling") or [])
        strong = list(hits.get("domain_strong") or [])
        weak = list(hits.get("domain_weak") or [])
        adult_path = list(hits.get("path") or [])

        if brands:
            details.append("⛔ 域名命中知名成人品牌: {}".format("、".join(brands[:3])))
            score = 85
        elif gambling:
            details.append("⛔ 域名命中赌博类关键词: {}".format("、".join(gambling[:3])))
            score = 80
        elif strong:
            details.append("⛔ 域名命中成人强关键词: {}".format("、".join(strong[:3])))
            score = 75
        elif weak:
            details.append("⚠ 域名含敏感标签: {}（证据较弱，需其它信号配合）".format(
                "、".join(weak[:3])))
            score = 45
        elif adult_path:
            details.append("ℹ 路径/参数含成人内容关键词: {}".format("、".join(adult_path[:3])))
            score = 25
        else:
            return 0

        # 组合加分：域名"弱标签" + 路径/参数成人词 同现 → +10（两个独立信号互相印证）
        # 刻意不复用"可疑 TLD"作为组合条件 —— 那是 suspicious_tld 规则负责的信号，
        # 复用它会让同一个特征被计两次分（实测 sex.xxx 会因此虚高 10 分）。
        if weak and adult_path:
            score += 10
            details.append("⚠ 域名敏感标签 + 路径成人关键词 同时命中，证据加强(+10)")

        return min(100, score)


    def _check_malicious_patterns(self, features: Dict, details: List) -> int:
        """与模式库比对(data/malicious_patterns.json + suspicious_domains.json)

        这是"不依赖AI"的传统检测核心之一: 用人工整理的钓鱼/恶意软件/诈骗
        模式匹配URL, 命中已知可疑域名时权重最高(35分);
        同一次检测取命中项里的最高分, 不做叠加。
        """
        hits = match_pattern_library(
            features.get("hostname", ""),
            features.get("path", ""),
            features.get("query", ""),
        )
        if not hits:
            return 0

        if "known_domain" in hits:
            details.append("⛔ 命中已知可疑域名库: {}".format(", ".join(hits["known_domain"])))
            return 35

        weights = {"phishing": 25, "malware": 25, "suspicious_domain_pattern": 25, "deception": 15}
        score = 0
        parts = []
        for category, matched in hits.items():
            score = max(score, weights.get(category, 12))
            parts.append("{}: {}".format(category, ", ".join(matched[:3])))
        if score:
            details.append("⚠ 命中恶意/钓鱼模式库({})".format("; ".join(parts)))
        return score

    def _check_https(self, features: Dict, details: List) -> int:
        """检查是否使用HTTPS"""
        if features.get("scheme") != "https":
            details.append("ℹ 未使用HTTPS加密连接")
            return 5
        return 0

    def _check_suspicious_port(self, features: Dict, details: List) -> int:
        """检查是否使用非标准端口"""
        port = features.get("port")
        if port and port not in (80, 443, 8080, 8443):
            details.append("⚠ 使用非标准端口: {}".format(port))
            return 8
        return 0

    def _check_encoded_chars(self, url: str, features: Dict, details: List) -> int:
        """检查URL编码混淆"""
        decoded = unquote(url)
        if decoded != url:
            # 计算编码字符的比例
            encoded_count = url.count('%')
            if encoded_count > 5:
                details.append("⚠ URL包含大量编码字符({}处), 可能为混淆攻击".format(encoded_count))
                return 10
            elif encoded_count > 2:
                details.append("ℹ URL包含编码字符({}处)".format(encoded_count))
                return 3
        return 0

    @staticmethod
    def _string_similarity(s1: str, s2: str) -> float:
        """计算两个字符串的相似度(0~1)

        原实现使用字符集合的 Jaccard 相似度, 对"顺序"和"长度差异"不敏感
        (gooogle 与 google 会被判得偏高, goo1gle 又偏低), 现已改为
        基于编辑距离的 similarity_ratio, 更能反映"看起来像不像"。
        """
        return similarity_ratio(s1, s2)

    @staticmethod
    def _condense_safe_details(details: List[str], matched_rules: List[str]) -> List[str]:
        """安全链接的详情精简: 只保留最关键的几项检测结论

        适用场景: 判定为"安全链接"时(**无论是否启用AI辅助检测**)。
        保留原则:
          1. 真实的风险提示/警告(⚠ 警告、ℹ 提示)一律保留 —— 否则会掩盖
             "未使用HTTPS""使用短链接""非标准端口"这类有用信息;
          2. 通过项只保留最关键、最有说服力的几条(例如"未命中已知恶意/钓鱼模式库");
          3. 可信站点说明原样保留。

        注意: "未启用AI辅助检测…"这类说明行**不在这里返回** ——
        它由 analyze() 通过 condense_note 交给检测器, 在 DNS 检查结论
        ("✅ 域名 xxx 可正常解析")之后追加; DeepSeek 的分析理由(🤖 开头)
        同样由检测器在之后追加, 因此都会排在关键结论下方。

        压缩后典型结果(约 6 条):
            ✅ 未命中已知恶意/钓鱼模式库
            ✅ 未发现域名仿冒/欺骗特征（同形字、punycode、品牌置于子域名）
            ✅ 域名信誉正常（非高风险TLD、非IP直连、非免费主机/动态域名）
            ✅ 未发现可疑关键词、高危文件下载或地址隐藏/内嵌跳转
            ✅ URL 结构与字符组成正常
            ✅ 域名属于可信站点名单（仅可信站点才出现）
        """
        hits = set(matched_rules)

        # 1) 保留所有非"通过"类详情(⚠ 警告 / ℹ 提示)
        kept = [d for d in details if not str(d).startswith("✅")]

        # 2) 只为"未命中的关键维度"补充通过结论
        highlights: List[str] = []
        if "pattern_library" not in hits:
            highlights.append("✅ 未命中已知恶意/钓鱼模式库")
        if not ({"typosquatting", "deceptive_domain"} & hits):
            highlights.append("✅ 未发现域名仿冒/欺骗特征（同形字、punycode、品牌置于子域名）")
        if not ({"suspicious_tld", "ip_host", "free_hosting", "dga"} & hits):
            highlights.append("✅ 域名信誉正常（非高风险TLD、非IP直连、非免费主机/动态域名）")
        if not ({"keywords", "dangerous_extension", "embedded_url", "at_symbol"} & hits):
            highlights.append("✅ 未发现可疑关键词、高危文件下载或地址隐藏/内嵌跳转")
        if not ({"url_length", "special_chars", "encoded"} & hits):
            highlights.append("✅ URL 结构与字符组成正常（长度、字符集、编码均无异常）")

        # 3) 可信站点说明: 原样保留
        #    (安全链接不输出"综合评分…判定为安全链接"这类结论行, 已按要求去掉)
        trusted_note = [d for d in details if "可信站点名单" in str(d)]

        # 精简说明行由 analyze() 以 condense_note 形式返回, 交由检测器插到DNS结论之后
        return highlights + kept + trusted_note

    def _switch(self, key: str, default: bool = True) -> bool:
        """读取检测设置里的规则开关(未配置时按 default 处理)

        这些开关对应设置页的"检测设置"区域 / config.json 的 detection 节点:
            check_ip_url              IP直连检查
            check_suspicious_tlds     可疑顶级域名检查
            check_shortened_urls      短链接检查
            check_suspicious_keywords 可疑关键词检查
            check_typosquatting       域名仿冒检查
            check_deceptive_domain    欺骗性域名结构(punycode/品牌置于子域名/免费主机)
            check_dga                 随机生成域名(DGA)检查
            check_dangerous_extension 高危可执行/脚本文件下载检查
            check_malicious_patterns  与 data/*.json 模式库比对
        关闭某个开关即跳过对应规则(该规则不再加分)。
        同时兼容 "true/false"、"1/0"、"yes/no"、"on/off" 字符串写法，
        以便直接手工编辑 config.json 时也能正确判断。
        """
        value = self.config.get(key, default)
        if value is None:                 # 未配置或显式写 null 时按默认值处理
            return default
        if isinstance(value, str):
            return value.strip().lower() in ("1", "true", "yes", "on")
        return bool(value)

    def _get_threshold(self) -> int:
        """读取"风险评分阈值"(设置页可调), 缺省 60

        该阈值只作为"是否判定为恶意"的裁决线, 不改变各规则的加分,
        因此同一个URL的原始分不变, 只是判定的松紧随阈值变化。
        夹紧到 1-99: 取 0 会让安全区间无法换算, 取 100 会让危险区间除零。
        """
        try:
            value = int(self.config.get("heuristic_threshold", 60))
        except (TypeError, ValueError):
            return 60
        return max(1, min(99, value))

    @staticmethod
    def _get_risk_level(score: int) -> Tuple[str, str]:
        """根据评分确定风险等级和颜色"""
        if score >= 80:
            return "极高风险", "red"
        elif score >= 60:
            return "高风险", "red"
        elif score >= 40:
            return "中等风险", "yellow"
        elif score >= 20:
            return "低风险", "blue"
        else:
            return "安全", "green"