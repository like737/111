# -*- coding: utf-8 -*-
"""生成"演示用"的合成检测日志。

为什么需要它
------------
`docs/` 里的静态快照会渲染 `detection_log.json` 的内容（首页的"统计摘要"、
"最近检测"，报告页的表格）。真实日志属于个人浏览记录，绝不能进入公开仓库。

所以导出静态站时改用本模块生成的**合成样本**：URL 使用 RFC 2606 保留域名
（example.com / example.org / example.net 等，永远不会指向真实站点），
时间戳以"导出当天"为基准向前铺满 7 天，保证页面看起来是活的。

本模块不含任何读取真实日志的代码。
"""

import hashlib
import json
import os
from datetime import datetime, timedelta
from urllib.parse import urlsplit

# (相对天数, 时, 分, url, score, is_malicious, risk_level, blacklist_match, ml_prob)
_SAMPLES = [
    (6, 10, 12, "https://example.com/", 99, False, "安全", False, 0.0705),
    (6, 15, 40, "https://www.example.org/docs", 97, False, "安全", False, 0.0586),
    (5, 9, 3, "https://docs.demo.example.net/guide", 95, False, "安全", False, 0.1038),
    (4, 20, 18, "http://phish-demo.example.net/login?token=demo", 49, True, "危险", False, 0.7973),
    (4, 21, 2, "http://phish-demo.example.net/login?token=demo", 49, True, "危险", False, 0.7973),
    (3, 11, 27, "https://blog.demo.example.org/notes", 92, False, "安全", False, 0.2066),
    (2, 14, 55, "http://malware-demo.example.org/payload.exe", 18, True, "危险", True, 0.9409),
    (2, 16, 8, "https://shop.demo.example.com/", 99, False, "安全", False, 0.0705),
    (1, 9, 44, "https://example.com/", 99, False, "安全", False, 0.0705),
    (1, 13, 21, "http://192.0.2.10/login.php?url=demo", 61, True, "可疑", False, 0.4063),
    (0, 8, 30, "https://docs.demo.example.net/guide", 96, False, "安全", False, 0.1038),
    (0, 9, 5, "https://example.com/", 99, False, "安全", False, 0.0705),
]

_BENIGN_DETAILS = [
    "✅ 未命中已知恶意/钓鱼模式库",
    "✅ 未发现域名仿冒、欺骗性结构（同形字、punycode、品牌置于子域名）",
    "✅ 域名信誉正常（非高风险 TLD、非 IP 直连、非免费主机）",
    "✅ 未发现可疑关键词、高危文件下载或地址隐藏/内嵌跳转",
    "✅ URL 结构与字符组成正常（长度、字符集、编码均无异常）",
]

_SUSPICIOUS_DETAILS = [
    "⚠ 使用可疑顶级域名，常被恶意站点使用",
    "ℹ 未使用 HTTPS 加密连接",
    "⚠ 检测到可疑关键词（域名/路径/参数）",
    "ℹ 目标为 IP 直连，跳过 DNS 解析检查",
]

_MALICIOUS_DETAILS = [
    "⚠ 命中恶意/钓鱼模式库",
    "⚠ 命中高危可执行文件下载",
    "⚠ 域名无法解析，可能为已失效的钓鱼/恶意域名",
    "ℹ 未使用 HTTPS 加密连接",
]


def _details_for(score, blacklist_match):
    if blacklist_match:
        return ["⚠ 命中黑名单记录"] + _MALICIOUS_DETAILS
    if score >= 90:
        return list(_BENIGN_DETAILS)
    if score >= 60:
        return list(_SUSPICIOUS_DETAILS)
    return list(_MALICIOUS_DETAILS)


def build_entries(now=None):
    """构造合成日志条目（每次调用结果由 now 决定，便于 CI 复现）"""
    now = now or datetime.now()
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    entries = []
    for days_ago, hour, minute, url, score, malicious, risk, blacklisted, ml_prob in _SAMPLES:
        ts = (today - timedelta(days=days_ago)).replace(hour=hour, minute=minute, second=17, microsecond=940_000)
        parts = urlsplit(url)
        domain = parts.hostname or ""
        entries.append({
            "url": url,
            "url_hash": hashlib.sha256(url.encode("utf-8")).hexdigest(),
            "timestamp": ts.isoformat(),
            "is_malicious": malicious,
            "score": score,
            "risk_level": risk,
            "details": _details_for(score, blacklisted),
            "blacklist_match": blacklisted,
            "domain": domain,
            "ml_prob": ml_prob,
            "ml_verdict": 1 if ml_prob >= 0.9 else 0,
            "ml_high": ml_prob >= 0.9,
            "ml_mode": "enforce",
            "ml_domain_prob": ml_prob,
            "ml_path_prob": round(ml_prob / 8.0, 4),
            "ml_convict": [],
        })
    return entries


def write_demo_log(path, now=None):
    """把合成日志写到 path，返回写入的条目数"""
    entries = build_entries(now)
    folder = os.path.dirname(os.path.abspath(path))
    if folder:
        os.makedirs(folder, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(entries, f, ensure_ascii=False, indent=2)
    return len(entries)
