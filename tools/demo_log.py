# -*- coding: utf-8 -*-
"""生成"演示用"的合成检测日志。

为什么需要它
------------
`docs/` 里的静态快照会渲染检测日志（首页"统计摘要"/"最近检测"、报告页表格）。
真实 `detection_log.json` 属于个人浏览记录，绝不能进入公开仓库。

所以导出静态站时改用本模块生成的**合成样本**：URL 使用 RFC 2606 保留域名
（example.com / example.org / example.net，永远不会指向真实站点）。

为什么用固定锚点而不是 datetime.now()
-------------------------------------
如果用当前时间，本地（UTC+8）与 GitHub Actions（UTC）算出的"24 小时内"、
"最近 7 天"落点不同，每次 CI 运行都会产生无意义的 docs 差异。
这里用一个固定的 `DEMO_ANCHOR`，使导出结果**完全可复现**。

想刷新演示数据时，覆盖锚点即可：

    $env:EY_DEMO_NOW = "2027-01-01T20:00:00"
    python tools/export_docs.py

本模块不含任何读取真实日志的代码。
"""

import hashlib
import json
import os
from datetime import datetime, timedelta
from urllib.parse import urlsplit

# 演示时钟锚点：所有合成数据都围绕这个时刻铺开 7 天。
DEMO_ANCHOR = datetime(2026, 10, 27, 20, 0, 0)

# 相对锚点的偏移天数: (days_ago, hour, minute, url, score, is_malicious,
#                      risk_level, blacklist_match, ml_prob)
_SAMPLES = [
    (0, 8, 30, "https://example.com/", 99, False, "安全", False, 0.0705),
    (0, 9, 5, "https://docs.demo.example.net/guide", 96, False, "安全", False, 0.1038),
    (0, 17, 40, "https://shop.demo.example.com/", 99, False, "安全", False, 0.0705),
    (1, 11, 27, "https://blog.demo.example.org/notes", 92, False, "安全", False, 0.2066),
    (1, 13, 21, "http://192.0.2.10/login.php?url=demo", 61, True, "可疑", False, 0.4063),
    (2, 9, 44, "https://www.example.org/docs", 97, False, "安全", False, 0.0586),
    (3, 14, 55, "http://malware-demo.example.org/payload.exe", 18, True, "危险", True, 0.9409),
    (3, 20, 18, "http://phish-demo.example.net/login?token=demo", 49, True, "危险", False, 0.7973),
    (4, 10, 12, "https://example.com/", 99, False, "安全", False, 0.0705),
    (5, 15, 40, "https://docs.demo.example.net/guide", 95, False, "安全", False, 0.1038),
    (6, 9, 3, "https://www.example.org/docs", 97, False, "安全", False, 0.0586),
    (6, 21, 2, "http://phish-demo.example.net/login?token=demo", 49, True, "危险", False, 0.7973),
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


def demo_now():
    """返回演示时钟：默认固定锚点，可用 EY_DEMO_NOW 覆盖"""
    raw = (os.environ.get("EY_DEMO_NOW") or "").strip()
    if not raw:
        return DEMO_ANCHOR
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(raw, fmt)
        except ValueError:
            continue
    raise SystemExit("EY_DEMO_NOW 格式应为 YYYY-MM-DDTHH:MM:SS，收到: %r" % raw)


def build_entries(now=None):
    """构造合成日志条目（默认以 DEMO_ANCHOR 为基准，输出可复现）"""
    now = now or demo_now()
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    entries = []
    for days_ago, hour, minute, url, score, malicious, risk, blacklisted, ml_prob in _SAMPLES:
        ts = (today - timedelta(days=days_ago)).replace(
            hour=hour, minute=minute, second=17, microsecond=940_000
        )
        parts = urlsplit(url)
        entries.append({
            "url": url,
            "url_hash": hashlib.sha256(url.encode("utf-8")).hexdigest(),
            "timestamp": ts.isoformat(),
            "is_malicious": malicious,
            "score": score,
            "risk_level": risk,
            "details": _details_for(score, blacklisted),
            "blacklist_match": blacklisted,
            "domain": parts.hostname or "",
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
