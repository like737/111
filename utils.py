"""
工具模块 - 提供URL解析、格式化等通用工具函数
"""

import re
import os
import math
import json
import hashlib
import socket
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse
from datetime import datetime

# 已知的URL短链接服务域名
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "shorturl.at",
    "buff.ly", "ow.ly", "is.gd", "cli.gs", "mcaf.ee",
    "rebrandly", "cutt.ly", "shorte.st", "bl.ink", "shortcm.xyz",
    "2.gp", "gg.gg", "v.gd", "tiny.cc", "tr.im",
    "su.pr", "x.co", "adf.ly", "bc.vc", "7zag.ru",
    # 补充: 常见的短链/跳转服务(钓鱼常把它当作跳板, 隐藏真实目的地)
    "bit.do", "t.ly", "rb.gy", "short.io", "surl.li", "urlz.fr",
    "shrtco.de", "soo.gd", "clck.ru", "u.to", "qps.ru",
    "po.st", "db.tt", "qr.ae", "cur.lv", "s.id", "u.nu",
    "tinu.be", "shorturl.gg", "za.gl", "ouo.io", "shrinkme.io",
}

# 可疑顶级域名
SUSPICIOUS_TLDS = {
    # 免费/低门槛 TLD(Freenom 系), 恶意注册比例极高
    "tk", "ml", "ga", "cf", "gq",
    # 新通用顶级域, 常被批量注册用于钓鱼与垃圾推广
    "xyz", "top", "work", "date", "download", "bid", "loan", "win",
    "review", "trade", "science", "accountant", "party", "racing",
    "men", "mom", "click", "link", "webcam", "stream", "gdn",
    "icu", "cyber", "rest", "bar", "casa", "email", "country",
    "kim", "cricket", "faith", "ren", "wang", "xin", "buzz",
    "monster", "quest", "sbs", "surf", "loan", "mom",
}

# 可疑关键词(英文 + 中文; 中文关键词在中文钓鱼站里出现频率很高)
SUSPICIOUS_KEYWORDS = [
    r"login", r"signin", r"sign-in", r"logon", r"logout-?verify",
    r"verify", r"verification", r"secure", r"account", r"update",
    r"confirm", r"banking", r"password", r"passwd", r"credential",
    r"authenticate", r"wallet", r"free-?prize", r"win-?money",
    r"gift-?card", r"lottery", r"inheritance", r"paypal",
    r"refund", r"bonus", r"investment", r"crypto-?currency",
    r"token", r"2fa", r"identity", r"ssn", r"security",
    r"unlock", r"suspend", r"recovery", r"billing", r"invoice",
    r"card-?number", r"id-?verify", r"kyc", r"airdrop", r"giveaway",
    # 中文钓鱼/诈骗常见词
    r"登录", r"登陆", r"验证", r"认证", r"实名", r"身份证",
    r"银行卡", r"密码", r"账户", r"账号", r"解冻", r"冻结",
    r"中奖", r"领奖", r"返利", r"退费", r"补贴", r"红包",
]

# 免费主机 / 动态DNS 域名: 注册门槛低, 常被用于短命钓鱼站
FREE_HOSTING_DOMAINS = {
    "000webhostapp.com", "duckdns.org", "no-ip.org", "no-ip.biz",
    "no-ip.info", "hopto.org", "zapto.org", "sytes.net", "ddns.net",
    "myftp.org", "myftp.biz", "bounceme.net", "redirectme.net",
    "serveftp.com", "webhop.me", "3utilities.com", "ngrok.io",
    "ngrok-free.app", "serveo.net", "localtunnel.me", "telebit.io",
    "pagekite.me", "portmap.io", "trycloudflare.com", "workers.dev",
    "repl.co", "glitch.me", "herokuapp.com", "firebaseapp.com",
    "weebly.com", "wixsite.com", "webflow.io", "myshopify.com",
}

# 高危可执行/脚本类文件扩展名(仅匹配URL路径部分, 避免把域名中的 .com 误判)
# 注意: 不含 ".js" —— 正常站点的脚本文件极其常见, 误报代价过高
DANGEROUS_EXTENSIONS = {
    "exe", "scr", "vbe", "vbs", "wsf", "wsh", "hta", "bat", "cmd",
    "pif", "msi", "msp", "dll", "cpl", "reg", "lnk", "jar", "apk",
    "ps1", "psm1", "sct", "jse",
}

# 中风险扩展名: 宏文档/镜像/自解压包等, 常见于"安装包投毒", 但正常下载站也会使用
MODERATE_RISK_EXTENSIONS = {
    "chm", "inf", "iso", "img", "vhd", "xlsm", "docm", "pptm", "ace", "arj",
}

# 非网络协议(伪协议): 常见于XSS/本地文件窃取, 不应被当作普通URL访问
DANGEROUS_SCHEMES = {
    "javascript", "data", "vbscript", "file", "about", "blob",
    "chrome", "ms-msdt", "search-ms", "shell", "res", "jar",
}

# 常见同形字/易混淆字符映射(用于识别 g00gle.com、аpple.com 这类仿冒域名)
HOMOGLYPH_MAP = {
    # 西里尔字母 / 希腊字母 → 拉丁字母
    "а": "a", "в": "b", "е": "e", "к": "k", "м": "m", "н": "h",
    "о": "o", "р": "p", "с": "c", "т": "t", "у": "y", "х": "x",
    "ѕ": "s", "і": "i", "ј": "j", "ԁ": "d", "ɡ": "g", "ⅰ": "i",
    "α": "a", "β": "b", "ε": "e", "ι": "i", "κ": "k", "ν": "v",
    "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "ѵ": "v",
    # 数字/符号 → 字母
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "6": "b",
    "7": "t", "8": "b", "9": "g", "$": "s", "@": "a", "!": "i",
    "|": "l",
}

# 内部数据文件(模式库), 路径相对本项目目录, 保证跨工作目录可用
_DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
MALICIOUS_PATTERNS_FILE = os.path.join(_DATA_DIR, "malicious_patterns.json")
SUSPICIOUS_DOMAINS_FILE = os.path.join(_DATA_DIR, "suspicious_domains.json")
TLD_RISK_FILE = os.path.join(_DATA_DIR, "tld_risk.json")
ADULT_KEYWORDS_FILE = os.path.join(_DATA_DIR, "adult_keywords.json")


# 数据文件缺失时的内置回退(保证算法在没有 data/ 目录时依然可用)
_FALLBACK_PATTERNS = {
    "phishing": [
        "login*verify", "signin*secure", "account*update", "banking*confirm",
        "paypal*security", "appleid*verify", "office365*login",
    ],
    "malware": ["setup*.exe", "installer*.exe", "crack*.exe", "keygen*.exe"],
    "deception": ["free-*", "win-*prize", "lottery*winner", "claim*prize"],
}
_FALLBACK_SUSPICIOUS_DOMAINS = {
    "free-money.tk", "win-prize.ml", "secure-login.ga",
    "account-verify.cf", "banking-update.gq",
}
_FALLBACK_ADULT_KEYWORDS = {
    "domain_strong": ["porn", "xxx", "hentai", "nsfw", "escort", "onlyfans", "色情"],
    "adult_brands": ["pornhub", "xvideos", "xnxx", "xhamster", "chaturbate"],
    "gambling": ["casino", "betting", "sportsbook", "roulette", "博彩", "赌场"],
    "domain_weak": ["sex", "adult", "jav"],
    "path": ["porn", "xxx", "hentai", "nsfw", "casino"],
}


def extract_url_features(url: str) -> dict:
    """提取URL的各种特征用于分析

    1. 缺少协议头时自动补 http://(如 evil.com/a → http://evil.com/a);
    2. 端口非法时(如 :99999、:abc、javascript:alert(1))降级为 None —
       urllib 的 parsed.port 在端口越界/非数字时会抛 ValueError,
       原实现没做保护, 会让整条检测链路中断(Web端表现为 500);
    3. 额外给出 path_ext / tld 两个派生字段, 供各检查规则直接使用。
    """
    if not url:
        return {}

    raw = str(url).strip()
    if not raw:
        return {}

    # 先记录用户原始输入的协议: javascript:/data: 这类伪协议没有 "//",
    # 补上 http:// 之后 urlparse 会把它们当成主机名, 因此必须提前取出
    original_scheme = ""
    scheme_match = re.match(r"^([a-zA-Z][a-zA-Z0-9+.\-]*):", raw)
    if scheme_match:
        original_scheme = scheme_match.group(1).lower()

    # 任何 "scheme://" 形式都保留原样(伪协议交给专门规则判断)
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", raw):
        raw = "http://" + raw

    try:
        parsed = urlparse(raw)
    except Exception:
        return {}

    try:
        port = parsed.port
    except ValueError:
        port = None

    hostname = (parsed.hostname or "").lower()
    path = parsed.path or "/"
    tld = hostname.rsplit(".", 1)[-1] if "." in hostname else ""

    return {
        "scheme": original_scheme or (parsed.scheme or "").lower(),
        "netloc": parsed.netloc,
        "hostname": hostname,
        "port": port,
        "path": path,
        "params": parsed.params,
        "query": parsed.query,
        "fragment": parsed.fragment,
        "full_url": raw,
        "path_ext": get_path_extension(path),
        "tld": tld,
    }

def get_path_extension(path: str) -> str:
    """取路径最后一段的文件扩展名(小写, 不含点); 无扩展名返回空串"""
    if not path:
        return ""
    last_segment = path.rstrip("/").rsplit("/", 1)[-1]
    if "." not in last_segment:
        return ""
    ext = last_segment.rsplit(".", 1)[-1].lower()
    return ext if ext.isalnum() else ""

def is_shortened_url(url: str) -> bool:
    """检查是否为短链接"""
    features = extract_url_features(url)
    hostname = features.get("hostname", "").lower()
    # 去除 www. 前缀
    if hostname.startswith("www."):
        hostname = hostname[4:]
    return hostname in URL_SHORTENERS

def is_ip_address(hostname: str) -> bool:
    """检查主机名是否为IP地址"""
    if not hostname:
        return False
    ip_pattern = re.compile(
        r'^(\d{1,3}\.){3}\d{1,3}$'
    )
    if ip_pattern.match(hostname):
        # 验证每个段在0-255之间
        parts = hostname.split('.')
        return all(0 <= int(part) <= 255 for part in parts)
    return False

def get_domain_levels(hostname: str) -> list:
    """获取域名的层级"""
    if not hostname:
        return []
    parts = hostname.lower().split('.')
    # 过滤掉空字符串
    parts = [p for p in parts if p]
    return parts

def count_subdomains(hostname: str) -> int:
    """计算子域名数量（不包括www）"""
    parts = get_domain_levels(hostname)
    if len(parts) <= 2:
        return 0
    # 顶级域名如 .com.cn 等特殊情况简化处理
    count = len(parts) - 2
    if parts[0] == 'www':
        count -= 1
    return max(0, count)

def get_suspicious_keywords_matched(url: str) -> list:
    """查找URL中匹配的可疑关键词(不区分位置, 保留此接口兼容旧调用)"""
    url_lower = url.lower()
    matched = []
    for pattern in SUSPICIOUS_KEYWORDS:
        if re.search(pattern, url_lower):
            matched.append(pattern)
    return matched

# ==================== 信任域 / 仿冒域名 / 随机域名 工具 ====================

# 常见合法站点(命中其注册域或子域时用于压低误报)
TRUSTED_DOMAINS = {
    "google.com", "googleusercontent.com", "youtube.com", "gstatic.com",
    "facebook.com", "fbcdn.net", "twitter.com", "x.com", "instagram.com",
    "linkedin.com", "github.com", "githubusercontent.com", "gitlab.com",
    "stackoverflow.com", "stackexchange.com", "wikipedia.org",
    "microsoft.com", "live.com", "office.com", "office365.com", "bing.com",
    "apple.com", "icloud.com", "amazon.com", "baidu.com", "bdstatic.com",
    "taobao.com", "tmall.com", "alicdn.com", "qq.com", "weixin.qq.com",
    "alipay.com", "aliyun.com", "weibo.com", "zhihu.com", "bilibili.com",
    "douyin.com", "jd.com", "tencent.com", "163.com", "126.com",
    "cloudflare.com", "dropbox.com", "adobe.com", "netflix.com",
    "paypal.com", "mozilla.org", "python.org", "coursera.org",
    "npmjs.com", "pypi.org", "docker.com", "csdn.net", "gitee.com",
}

# 可信后缀(教育/政府等公共机构域, 其子域一律视为可信)
TRUSTED_SUFFIXES = {
    "edu.cn", "gov.cn", "ac.cn", "org.cn", "edu.hk", "gov.hk",
    "ac.uk", "gov.uk", "edu", "gov", "mil", "edu.tw", "gov.tw",
}

# 常见二级后缀(用于近似提取注册域名)
SECOND_LEVEL_SUFFIXES = {
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.jp", "ne.jp", "or.jp",
    "com.hk", "edu.hk", "com.tw", "com.au", "com.br", "co.kr",
}

def is_trusted_host(hostname: str) -> bool:
    """主机是否属于可信站点(常见合法站点及其子域, 或教育/政府域)"""
    host = (hostname or "").lower().strip(".")
    if not host:
        return False
    labels = host.split(".")
    for i in range(len(labels) - 1):
        if ".".join(labels[i:]) in TRUSTED_DOMAINS:
            return True
    return any(host == s or host.endswith("." + s) for s in TRUSTED_SUFFIXES)

def get_registered_domain(hostname: str) -> str:
    """近似提取注册域名(含常见二级后缀)

    mail.google.com → google.com;  a.b.com.cn → b.com.cn
    """
    host = (hostname or "").lower().strip(".")
    if not host:
        return ""
    labels = [x for x in host.split(".") if x]
    if len(labels) < 2:
        return host
    if len(labels) >= 3 and ".".join(labels[-2:]) in SECOND_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])

def get_domain_label(hostname: str) -> str:
    """取注册域名的主体部分(不含后缀): mail.google.com → google"""
    labels = [x for x in get_registered_domain(hostname).split(".") if x]
    return labels[0] if labels else ""

def normalize_homoglyphs(text: str) -> str:
    """把常见同形字/易混淆字符归一化: g00gle→google, 西里尔 аpple→apple"""
    return "".join(HOMOGLYPH_MAP.get(ch, ch) for ch in (text or "").lower())

def simplified_letters(text: str) -> str:
    """进一步合并易混淆的字母组合(rn→m, vv→w, cl→d)"""
    s = normalize_homoglyphs(text)
    for src, dst in (("rn", "m"), ("vv", "w"), ("cl", "d")):
        s = s.replace(src, dst)
    return s

def shannon_entropy(text: str) -> float:
    """计算字符串的香农熵(bit/字符), 熵越高说明字符分布越随机"""
    if not text:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())

def levenshtein_distance(a: str, b: str, max_distance: Optional[int] = None) -> int:
    """带早停的编辑距离(超过 max_distance 立即返回, 保证长域名下的性能)"""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    if max_distance is not None and abs(len(a) - len(b)) > max_distance:
        return max_distance + 1
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost))
        if max_distance is not None and min(current) > max_distance:
            return max_distance + 1
        previous = current
    return previous[-1]

def similarity_ratio(a: str, b: str) -> float:
    """基于编辑距离的相似度(0~1), 比字符集合相似度更能反映"长得像" """
    a, b = (a or "").lower(), (b or "").lower()
    if not a or not b:
        return 0.0
    return 1 - levenshtein_distance(a, b) / max(len(a), len(b))


def is_ip_like_hostname(hostname: str) -> bool:
    """识别各种写法的IP主机(钓鱼常用非点分十进制写法绕过检测)

    点分十进制 192.168.1.1 / 十进制整数 3232235777 /
    十六进制 0x7f.0.0.1 / 八进制 0177.0.0.1 / IPv6 ::1
    """
    host = (hostname or "").strip().lower()
    if not host:
        return False
    if is_ip_address(host):
        return True
    if re.fullmatch(r"\d{6,12}", host):
        return True
    if re.fullmatch(r"0x[0-9a-f]+(\.[0-9a-f]+){0,3}", host):
        return True
    if re.fullmatch(r"0[0-7]*(\.[0-7]+){1,3}", host):
        return True
    if ":" in host and re.fullmatch(r"[0-9a-f:]+", host):
        return True
    return False

def is_dga_like_label(label: str) -> bool:
    """域名主体是否具有"随机生成(DGA)/批量注册"特征

    典型特征: 长度长、数字占比高、元音少、连续辅音串长、字符熵高,
    例如 xjkqvzmtb3q9w.com、kq7f2m9xzt.xyz; 命中 2 项特征即判定为可疑。
    """
    label = (label or "").lower()
    if len(label) < 10:
        return False
    chars = [c for c in label if c.isalnum()]
    if not chars:
        return False
    digits = sum(c.isdigit() for c in chars)
    vowels = sum(c in "aeiou" for c in chars)
    longest_consonant_run = 0
    run = 0
    for c in chars:
        if c.isdigit() or c not in "aeiou":
            run += 1
            longest_consonant_run = max(longest_consonant_run, run)
        else:
            run = 0
    signs = 0
    if digits / len(chars) >= 0.30:
        signs += 1
    if vowels / len(chars) <= 0.22:
        signs += 1
    if longest_consonant_run >= 4:
        signs += 1
    if shannon_entropy(chars) >= 3.3:
        signs += 1
    if re.search(r"\d{4,}", label):
        signs += 1
    return signs >= 2

def is_free_hosting(hostname: str) -> bool:
    """是否托管在免费主机/动态DNS 域名下(短命钓鱼站高发区)"""
    return get_registered_domain(hostname) in FREE_HOSTING_DOMAINS

def has_dangerous_extension(path: str) -> str:
    """路径是否为高危可执行/脚本文件, 命中返回扩展名(否则空串)"""
    ext = get_path_extension(path)
    return ext if ext in DANGEROUS_EXTENSIONS else ""

def classify_extension(path: str) -> Tuple[str, str]:
    """给路径的文件扩展名分级, 返回 (扩展名, 级别)

    级别: "high"   高危可执行/脚本(下载运行风险极高)
          "medium" 宏文档/镜像/自解压包等(安装包投毒高发, 但正常下载站也用)
          ""       普通文件或无扩展名
    """
    ext = get_path_extension(path)
    if not ext:
        return "", ""
    if ext in DANGEROUS_EXTENSIONS:
        return ext, "high"
    if ext in MODERATE_RISK_EXTENSIONS:
        return ext, "medium"
    return ext, ""

def analyze_suspicious_keywords(url: str) -> Dict[str, List[str]]:
    """按出现位置统计可疑关键词: {"domain": [...], "path": [...], "query": [...]}

    位置很关键: 关键词出现在域名里(secure-login.tk)远比出现在查询参数里
    (google.com/search?q=login)可疑; 分开统计后对不同位置采用不同权重,
    可以显著降低对正常站点的误报。
    """
    features = extract_url_features(url)
    if not features:
        return {"domain": [], "path": [], "query": []}

    def scan(text: str) -> List[str]:
        text = (text or "").lower()
        return [p for p in SUSPICIOUS_KEYWORDS if re.search(p, text)]

    return {
        "domain": scan(features.get("hostname", "")),
        "path": scan(features.get("path", "")),
        "query": scan(features.get("query", "")),
    }

# ==================== 模式库(data/*.json)加载与匹配 ====================
_patterns_cache: Optional[Dict[str, List[str]]] = None
_suspicious_domains_cache: Optional[Dict[str, List[str]]] = None

def load_malicious_patterns() -> Dict[str, List[str]]:
    """加载 data/malicious_patterns.json 的恶意URL模式库(结果缓存)

    文件缺失/损坏时回退到内置模式, 保证规则在没有 data/ 目录时也能用。
    """
    global _patterns_cache
    if _patterns_cache is not None:
        return _patterns_cache
    patterns = {k: list(v) for k, v in _FALLBACK_PATTERNS.items()}
    try:
        with open(MALICIOUS_PATTERNS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        loaded = data.get("patterns") or {}
        if isinstance(loaded, dict):
            for category, items in loaded.items():
                if isinstance(items, list) and items:
                    patterns[str(category)] = [str(x) for x in items]
    except Exception:
        pass
    _patterns_cache = patterns
    return patterns

def load_suspicious_domains() -> Dict[str, List[str]]:
    """加载 data/suspicious_domains.json(已知可疑域名 + 域名模式), 结果缓存"""
    global _suspicious_domains_cache
    if _suspicious_domains_cache is not None:
        return _suspicious_domains_cache
    result: Dict[str, List[str]] = {
        "known_suspicious": sorted(_FALLBACK_SUSPICIOUS_DOMAINS),
        "suspicious_patterns": [
            "*-secure-*", "*-login-*", "*-verify-*", "*-account-*",
            "secure-*.*", "verify-*.*",
        ],
    }
    try:
        with open(SUSPICIOUS_DOMAINS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        known = data.get("known_suspicious")
        pats = data.get("suspicious_patterns")
        if isinstance(known, list) and known:
            result["known_suspicious"] = [str(x).lower().strip() for x in known]
        if isinstance(pats, list) and pats:
            result["suspicious_patterns"] = [str(x) for x in pats]
    except Exception:
        pass
    _suspicious_domains_cache = result
    return result

_tld_risk_cache: Optional[Dict[str, object]] = None

def load_tld_risk() -> Dict[str, object]:
    """加载 data/tld_risk.json（TLD → 恶意富集倍数 lift / 建议分值），结果缓存

    文件由 `ml_training/build_eval_sets.py` 生成；缺失时返回空表，自动回退到内置
    `SUSPICIOUS_TLDS` —— 删掉数据文件也不会影响检测流程。
    """
    global _tld_risk_cache
    if _tld_risk_cache is not None:
        return _tld_risk_cache
    result: Dict[str, object] = {"tlds": {}, "exempt": set()}
    try:
        with open(TLD_RISK_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        tlds = data.get("tlds") or {}
        if isinstance(tlds, dict):
            result["tlds"] = {str(k).lower(): v for k, v in tlds.items() if isinstance(v, dict)}
        exempt = data.get("exempt") or []
        if isinstance(exempt, list):
            result["exempt"] = {str(x).lower() for x in exempt}
    except Exception:
        pass
    _tld_risk_cache = result
    return result

def tld_risk_score(hostname: str) -> Tuple[int, float, str]:
    """TLD 风险分（数据驱动）→ (score, lift, tld)

    只按"恶意富集倍数 lift"分级（20 / 12 / 6 分）；合法国际化后缀(xn--)直接 0 分。
    分值远低于判定阈值(60)，只作为评分的一部分，不会单独定罪。
    """
    parts = get_domain_levels(hostname)
    if not parts:
        return 0, 0.0, ""
    tld = parts[-1].lower()
    info = load_tld_risk()
    if tld in info.get("exempt", set()):
        return 0, 0.0, tld
    entry = (info.get("tlds") or {}).get(tld)
    if not isinstance(entry, dict):
        return 0, 0.0, tld
    try:
        lift = float(entry.get("lift") or 0.0)
    except (TypeError, ValueError):
        lift = 0.0
    if lift >= 100:
        return 20, lift, tld
    if lift >= 20:
        return 12, lift, tld
    if lift >= 5:
        return 6, lift, tld
    return 0, lift, tld

_adult_keywords_cache: Optional[Dict[str, List[str]]] = None

def load_adult_keywords() -> Dict[str, List[str]]:
    """加载 data/adult_keywords.json(成人/赌博内容关键词库), 结果缓存

    文件缺失/损坏时回退到内置最小集合, 保证规则在没有 data/ 目录时也能用。
    """
    global _adult_keywords_cache
    if _adult_keywords_cache is not None:
        return _adult_keywords_cache
    result: Dict[str, List[str]] = {k: list(v) for k, v in _FALLBACK_ADULT_KEYWORDS.items()}
    try:
        with open(ADULT_KEYWORDS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        for key in ("domain_strong", "adult_brands", "gambling", "domain_weak", "path"):
            items = data.get(key)
            if isinstance(items, list) and items:
                result[key] = [str(x).lower().strip() for x in items if str(x).strip()]
    except Exception:
        pass
    _adult_keywords_cache = result
    return result

def match_adult_keywords(hostname: str, path: str = "", query: str = "") -> Dict[str, List[str]]:
    """把URL与成人/赌博关键词库比对, 返回命中的分类

    匹配策略(兼顾检出率与误伤):
      - domain_strong / adult_brands / gambling: 域名**子串**命中
        (porn / xxx / casino / xvideos 这类词本身足够特异);
      - domain_weak: 只做**完整域名标签**匹配(按 . - _ 切分后再比对),
        所以 sex.xxx、adult-video.com 会命中, 而 sexeducation.com、adultlearning.com 不会;
      - path: 仅"路径 + 查询参数"的子串命中(给中低分, 用于提示, 避免误伤正常站点的文章页)。
    """
    host = (hostname or "").lower().strip()
    labels = [x for x in re.split(r"[.\-_]+", host) if x]
    hits: Dict[str, List[str]] = {}
    rule = load_adult_keywords()
    for key in ("domain_strong", "adult_brands", "gambling"):
        matched = [w for w in rule.get(key, []) if w and w in host]
        if matched:
            hits[key] = matched
    weak = [w for w in rule.get("domain_weak", []) if w and w in labels]
    if weak:
        hits["domain_weak"] = weak
    target = "{} {}".format(path or "", query or "").lower()
    path_hits = [w for w in rule.get("path", []) if w and w in target]
    if path_hits:
        hits["path"] = path_hits
    return hits



def match_wildcard(value: str, pattern: str) -> bool:
    """通配符匹配: 模式中的 * 匹配任意字符, 两端按"包含"语义匹配

    因此 "login*verify" 能命中 ".../login-x-verify", "*.exe" 命中任何以 .exe 结尾的URL。
    """
    regex = ".*" + re.escape(pattern).replace(r"\*", ".*") + ".*"
    return re.search(regex, value or "", re.IGNORECASE) is not None

def match_pattern_library(hostname: str, path: str = "", query: str = "") -> Dict[str, List[str]]:
    """把URL与两个数据文件比对, 返回命中项(键名即分类)

    - known_domain: 命中 suspicious_domains.json 的已知可疑域名(含其子域)
    - phishing / malware / deception: 命中 malicious_patterns.json 的对应分类
    - suspicious_domain_pattern: 命中 suspicious_domains.json 的域名模式
    命中已知可疑域名时直接返回(强度最高), 不再叠加其它模式。
    """
    host = (hostname or "").lower()
    target = "{}{}".format(host, path or "")
    if query:
        target = "{}?{}".format(target, query)

    result: Dict[str, List[str]] = {}
    known = load_suspicious_domains().get("known_suspicious", [])
    labels = host.split(".")
    hits = []
    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        if candidate and candidate in known:
            hits.append(candidate)
    if hits:
        result["known_domain"] = sorted(set(hits))
        return result

    for category, patterns in load_malicious_patterns().items():
        matched = [p for p in patterns if match_wildcard(target, p)]
        if matched:
            result[category] = matched

    dom_patterns = [p for p in load_suspicious_domains().get("suspicious_patterns", [])
                    if match_wildcard(host, p)]
    if dom_patterns:
        result["suspicious_domain_pattern"] = dom_patterns
    return result

def is_suspicious_tld(hostname: str) -> bool:
    """检查是否为可疑顶级域名

    优先用 data/tld_risk.json 的数据驱动结果（lift>=5 即算可疑），
    没有该文件时回退到内置 SUSPICIOUS_TLDS —— 保证删数据文件也不影响运行。
    """
    score, _lift, tld = tld_risk_score(hostname)
    if score > 0:
        return True
    if not tld:
        parts = get_domain_levels(hostname)
        if not parts:
            return False
        tld = parts[-1].lower()
    return tld in SUSPICIOUS_TLDS

def compute_url_hash(url: str) -> str:
    """计算URL的哈希值，用于去重和索引"""
    return hashlib.sha256(url.encode('utf-8')).hexdigest()

def format_timestamp() -> str:
    """返回格式化的时间戳"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def check_domain_resolves(hostname: str, timeout: float = 3) -> bool:
    """检查域名是否能够解析

    使用局部超时(不修改全局 socket 默认值, 避免影响其它网络请求),
    域名不存在 / 解析超时 / 网络异常都返回 False。
    """
    if not hostname:
        return False
    old_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout)
        socket.gethostbyname(hostname)
        return True
    except (socket.gaierror, socket.timeout, OSError):
        return False
    finally:
        socket.setdefaulttimeout(old_timeout)

def is_valid_url(url: str) -> bool:
    """验证URL格式是否合法

    与原实现的区别:
    1. 兼容"省略协议"的写法(evil.com/a?b=1 按 http:// 处理), 裸域名也能进入检测,
       不会再被当成"无效URL"直接返回;
    2. 显式拒绝 javascript:/data:/file: 等非网络协议 —— 原实现会把它们补成
       http://javascript:... 从而绕过检查;
    3. 允许 RFC3986 中的保留字符(: @ , ; & = 等), 因此
       https://a.com/x?mail=a@b.com 这类URL不会被误判为非法;
    4. 主机名必须由字母/数字/连字符/下划线/点/冒号组成(兼容中文国际化域名与IPv6),
       整体不允许出现空格、尖括号、引号、反斜杠等非法字符。
    """
    if not url:
        return False
    raw = str(url).strip()
    if not raw or len(raw) > 2083:
        return False
    if re.search(r"[\s<>\"{}|\\^`]", raw):
        return False

    # 用户原始输入里的协议(伪协议没有 "//", 必须在这里拦截)
    scheme_match = re.match(r"^([a-zA-Z][a-zA-Z0-9+.\-]*):", raw)
    if scheme_match and scheme_match.group(1).lower() in DANGEROUS_SCHEMES:
        return False

    features = extract_url_features(raw)
    hostname = (features.get("hostname") or "").strip()
    if not hostname:
        return False
    return re.fullmatch(r"[\w\-.:]+", hostname, re.UNICODE) is not None

def extract_domain(url: str) -> str:
    """从URL中提取主域名"""
    features = extract_url_features(url)
    hostname = features.get("hostname", "")
    parts = get_domain_levels(hostname)
    if len(parts) >= 2:
        return f"{parts[-2]}.{parts[-1]}"
    return hostname