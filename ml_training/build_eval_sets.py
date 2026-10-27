# coding:utf-8
"""评测集整理 + TLD 风险表生成（离线, 只读黑名单与现有数据集, 不覆盖原文件）

产出
  ml_training/data/domain_test_neg_clean.tsv  清洗后的负样本（剔除"真成人/赌博站"，punycode 单独标记）
  ml_training/data/eval_ip.tsv                IP 直连恶意样本（之前被当 invalid 整批丢弃）
  ml_training/data/eval_url.tsv               带路径的恶意 URL 样本（域名级评测覆盖不到的那批）
  ml_training/data/eval_manifest.json         本次整理的统计
  data/tld_risk.json                          TLD 恶意富集表（lift 分级 → 建议分值）

用法
  python ml_training/build_eval_sets.py
"""

import collections
import json
import os
import sys
import time
from urllib.parse import urlsplit

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
os.chdir(BASE)
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from utils import match_adult_keywords      # noqa: E402

DATA = os.path.join(BASE, "ml_training", "data")
BLACKLIST = os.path.join(BASE, "data", "blacklist.json")
TLD_RISK = os.path.join(BASE, "data", "tld_risk.json")

MIN_TLD_SAMPLES = 20          # TLD 黑名单样本下限（低于此不评估，避免噪声）
LIFT_LEVELS = ((100.0, 20), (20.0, 12), (5.0, 6))


def log(msg):
    print(msg, flush=True)


def host_of(value):
    text = (value or "").strip()
    if not text:
        return ""
    if "://" not in text:
        text = "http://" + text.lstrip("/")
    try:
        return (urlsplit(text).hostname or "").lower().strip(".")
    except Exception:
        return ""


def is_ip_host(host):
    parts = (host or "").split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def tld_of(host):
    host = (host or "").strip(".")
    return host.rsplit(".", 1)[-1].lower() if "." in host else ""


def load_tsv(name):
    rows = []
    path = os.path.join(DATA, name)
    if not os.path.exists(path):
        return rows
    with open(path, encoding="utf-8") as fp:
        for line in fp:
            parts = line.rstrip("\n").split("\t")
            if len(parts) >= 2 and parts[1]:
                rows.append((int(parts[0]), parts[1], parts[2] if len(parts) > 2 else ""))
    return rows


def is_adult_or_gambling(host):
    """强命中成人/赌博词 → 这条"正常域名"其实是成人/赌博站（评测集的标签噪声）"""
    try:
        hits = match_adult_keywords(host or "")
    except Exception:
        return False
    strong = (list(hits.get("domain_strong") or [])
              + list(hits.get("adult_brands") or [])
              + list(hits.get("gambling") or []))
    return bool(strong)


# ---------------- 1) 读黑名单, 拆成 域名/IP/URL 三类 ----------------
raw = json.load(open(BLACKLIST, encoding="utf-8"))
entries = raw.get("entries") or {}
log("黑名单: %d 条" % len(entries))

domain_rows, ip_rows, url_rows = [], [], []
cat_total = collections.Counter()
tld_pos = collections.Counter()
for value, category in entries.items():
    cat_total[category] += 1
    host = host_of(value)
    if is_ip_host(host):
        ip_rows.append((1, host, category or "恶意URL"))
        continue
    rest = (value or "").split("://", 1)[-1]
    if "/" in rest and rest.split("/", 1)[1].strip("/"):
        url_rows.append((1, value.strip(), category or "恶意URL"))
    if host:
        domain_rows.append((1, host, category or "恶意URL"))
        tld_pos[tld_of(host)] += 1

log("域名级 %d ｜ IP 直连 %d ｜ 带路径 URL %d" % (len(domain_rows), len(ip_rows), len(url_rows)))

# ---------------- 2) 清洗负样本（剔除真成人/赌博站, punycode 单独标记） ----------------
neg_raw = load_tsv("domain_test_neg.tsv")
neg_clean, dropped_adult, puny_rows = [], [], []
for label, host, cat in neg_raw:
    if is_adult_or_gambling(host):
        dropped_adult.append(host)
        continue
    if "xn--" in host.lower():
        puny_rows.append((label, host, "punycode"))
    else:
        neg_clean.append((label, host, "normal"))

with open(os.path.join(DATA, "domain_test_neg_clean.tsv"), "w", encoding="utf-8") as fp:
    for label, host, cat in neg_clean + puny_rows:
        fp.write("%d\t%s\t%s\n" % (label, host, cat))
log("负样本 %d → 清洗后 %d（剔除成人/赌博 %d；punycode 合法站 %d 单独标记）"
    % (len(neg_raw), len(neg_clean) + len(puny_rows), len(dropped_adult), len(puny_rows)))

for name, rows in (("eval_ip.tsv", ip_rows), ("eval_url.tsv", url_rows)):
    with open(os.path.join(DATA, name), "w", encoding="utf-8") as fp:
        for label, value, cat in rows:
            fp.write("%d\t%s\t%s\n" % (label, value, cat))
log("已写出 eval_ip.tsv（%d 条）与 eval_url.tsv（%d 条）" % (len(ip_rows), len(url_rows)))

# ---------------- 3) TLD 风险表（lift 分级） ----------------
tld_neg = collections.Counter(tld_of(h) for _l, h, _c in neg_raw)
total_pos = float(sum(tld_pos.values())) or 1.0
total_neg = float(sum(tld_neg.values())) or 1.0
tlds, exempt = {}, []
for tld, mal in tld_pos.items():
    if not tld:
        continue
    if tld.startswith("xn--"):
        exempt.append(tld)                      # 合法国际化后缀（如 .xn--p1ai = .рф）不计分
        continue
    if mal < MIN_TLD_SAMPLES:
        continue
    neg = tld_neg.get(tld, 0)
    lift = (mal / total_pos) / max(neg / total_neg, 1e-5)
    if lift < LIFT_LEVELS[-1][0]:
        continue
    score = next((pts for threshold, pts in LIFT_LEVELS if lift >= threshold), 0)
    tlds[tld] = {"lift": round(lift, 1), "score": score, "mal": mal, "neg": neg}

payload = {
    "description": "TLD 恶意富集表（lift = 黑名单内占比 ÷ 负样本内占比）；由 ml_training/build_eval_sets.py 生成",
    "version": "1.0",
    "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    "source": {"blacklist": len(entries), "blacklist_domains": len(domain_rows),
               "negatives": len(neg_raw)},
    "policy": {"min_samples": MIN_TLD_SAMPLES,
               "lift_levels": {str(int(t)): pts for t, pts in LIFT_LEVELS}},
    "exempt": sorted(set(exempt)),
    "tlds": dict(sorted(tlds.items(), key=lambda kv: -kv[1]["lift"])),
}
with open(TLD_RISK, "w", encoding="utf-8") as fp:
    json.dump(payload, fp, ensure_ascii=False, indent=2)
log("TLD 风险表: %d 个 TLD（另有 %d 个 IDN 后缀豁免）→ %s"
    % (len(tlds), len(payload["exempt"]), os.path.relpath(TLD_RISK, BASE)))

# ---------------- 4) 清单 ----------------
manifest = {
    "generated_at": payload["generated_at"],
    "blacklist_total": len(entries),
    "blacklist_by_category": dict(cat_total),
    "blacklist_domains": len(domain_rows),
    "blacklist_ip": len(ip_rows),
    "blacklist_url": len(url_rows),
    "negatives_raw": len(neg_raw),
    "negatives_clean": len(neg_clean) + len(puny_rows),
    "negatives_dropped_adult": len(dropped_adult),
    "negatives_punycode": len(puny_rows),
    "tld_risk_entries": len(tlds),
    "tld_risk_exempt": payload["exempt"],
}
with open(os.path.join(DATA, "eval_manifest.json"), "w", encoding="utf-8") as fp:
    json.dump(manifest, fp, ensure_ascii=False, indent=2)
log("清单已写出: ml_training/data/eval_manifest.json")
