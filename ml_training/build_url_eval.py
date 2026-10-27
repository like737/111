# coding:utf-8
"""第 7 步（7-A）：构建 URL 级评测集（供 path 模型评测与训练）

数据来源
  正样本  = external_url.tsv（URLhaus 恶意下载 + OpenPhish 钓鱼 URL, 真实恶意）
           + data/blacklist.json 里的"带路径条目"（URL 级恶意, 多为色情站）
  负样本  = Tranco 正常域名（domain_test_neg_clean.tsv, 已剔除成人/赌博站）
           × 常见路径模板（/、/login、/about、/search?q=、/download …）

红线
  * 按**注册域** 80/20 切分 train/eval（同一注册域绝不跨集）;
  * 负样本的注册域不得与任何正样本注册域重叠（防泄漏）;
  * IP 样本单独统计（path 模型看 URL 全串, IP 也是合法输入）。

产物（ml_training/data/）
  urltrain_pos.tsv / urltrain_neg.tsv    训练用
  urleval_pos.tsv  / urleval_neg.tsv     评测用（本轮只评测, 不训练）
  urleval_manifest.json                  统计

用法
  python ml_training/build_url_eval.py
"""

import json
import os
import random
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

from utils import get_registered_domain      # noqa: E402

DATA = os.path.join(BASE, "ml_training", "data")
BLACKLIST = os.path.join(BASE, "data", "blacklist.json")

# 正常站常见的路径（其中 /login、/download、/account 这类"敏感路径"也在内 —— 正好好好测误报）
PATH_TEMPLATES = [
    "/", "/index.html", "/about", "/contact", "/login", "/signup",
    "/search?q=how+to+use", "/products/12345", "/product/phone-x",
    "/news/2026/10/20", "/blog/how-to-cook", "/docs/getting-started",
    "/download/app", "/user/profile", "/account/settings",
    "/api/v1/items?page=2", "/static/js/app.js", "/images/logo.png",
    "/post/1234", "/category/tech",
]


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


def domain_key(host):
    """切分/防泄漏用的 key：IP 用自身, 域名用注册域"""
    if is_ip_host(host):
        return host
    return get_registered_domain(host) or host


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


def write_tsv(name, rows):
    with open(os.path.join(DATA, name), "w", encoding="utf-8") as fp:
        for label, value, category in rows:
            fp.write("%d\t%s\t%s\n" % (label, value, category))


def split_by_domain(rows, ratio, seed):
    """按注册域 80/20 切分（返回 train, eval, 域数统计）"""
    keys = sorted({domain_key(host_of(value)) for _l, value, _c in rows})
    rng = random.Random(seed)
    rng.shuffle(keys)
    cut = int(len(keys) * ratio)
    train_keys, eval_keys = set(keys[:cut]), set(keys[cut:])
    train = [r for r in rows if domain_key(host_of(r[1])) in train_keys]
    evals = [r for r in rows if domain_key(host_of(r[1])) in eval_keys]
    return train, evals, {"domains": len(keys), "train_domains": len(train_keys),
                          "eval_domains": len(eval_keys)}


def main():
    seed = 42

    # ---------- 1) 正样本 ----------
    positives = []
    for _label, value, category in load_tsv("external_url.tsv"):
        positives.append((1, value.strip(), category or "外部恶意"))
    ext_count = len(positives)

    raw = json.load(open(BLACKLIST, encoding="utf-8"))
    entries = raw.get("entries") or {}
    bl_count = 0
    seen = {value.lower() for _l, value, _c in positives}
    for value, category in entries.items():
        rest = (value or "").split("://", 1)[-1]
        if "/" not in rest or not rest.split("/", 1)[1].strip("/"):
            continue                                  # 只看带路径的 URL 级条目
        key = (value or "").strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        positives.append((1, value.strip(), category or "恶意URL"))
        bl_count += 1

    rng = random.Random(seed)
    rng.shuffle(positives)
    pos_train, pos_eval, pos_split = split_by_domain(positives, 0.8, seed)
    pos_regs = {domain_key(host_of(v)) for _l, v, _c in positives}

    # ---------- 2) 负样本（正常域名 × 路径模板；与正样本同注册域的一律排除） ----------
    neg_domains, dropped_leak = [], 0
    for _label, host, _cat in load_tsv("domain_test_neg_clean.tsv"):
        host = (host or "").strip()
        if not host:
            continue
        if domain_key(host) in pos_regs:
            dropped_leak += 1
            continue
        neg_domains.append(host)
    neg_domains = sorted(set(neg_domains))
    rng.shuffle(neg_domains)

    negatives = [(0, "https://%s%s" % (host, rng.choice(PATH_TEMPLATES)), "normal")
                 for host in neg_domains]
    neg_train, neg_eval, neg_split = split_by_domain(negatives, 0.8, seed)

    # ---------- 3) 写出 ----------
    write_tsv("urltrain_pos.tsv", pos_train)
    write_tsv("urltrain_neg.tsv", neg_train)
    write_tsv("urleval_pos.tsv", pos_eval)
    write_tsv("urleval_neg.tsv", neg_eval)

    def cat_counts(rows):
        counts = {}
        for _l, _v, cat in rows:
            counts[cat] = counts.get(cat, 0) + 1
        return counts

    ip_eval = sum(1 for _l, v, _c in pos_eval if is_ip_host(host_of(v)))
    manifest = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "seed": seed,
        "positives": {
            "external_url": ext_count,
            "blacklist_url_level": bl_count,
            "total": len(positives),
            "categories": cat_counts(positives),
        },
        "negatives": {"domains": len(neg_domains), "total": len(negatives),
                      "path_templates": len(PATH_TEMPLATES),
                      "dropped_leak": dropped_leak},
        "split": {"pos": pos_split, "neg": neg_split, "ratio_train": 0.8},
        "sets": {
            "train_pos": len(pos_train), "train_neg": len(neg_train),
            "eval_pos": len(pos_eval), "eval_neg": len(neg_eval),
            "eval_pos_ip": ip_eval,
        },
        "leak_guard": "负样本注册域与任何正样本注册域无交集",
    }
    with open(os.path.join(DATA, "urleval_manifest.json"), "w", encoding="utf-8") as fp:
        json.dump(manifest, fp, ensure_ascii=False, indent=2)

    log("正样本: 外部 %d + 黑名单带路径 %d = 去重后 %d 条" % (ext_count, bl_count, len(positives)))
    log("负样本: %d 个正常域名 × 路径模板 = %d 条（因与正样本同注册域排除 %d 个域名）"
        % (len(neg_domains), len(negatives), dropped_leak))
    log("按注册域 80/20 切分: 正 %s ｜ 负 %s" % (pos_split, neg_split))
    log("训练集: 正 %d / 负 %d" % (len(pos_train), len(neg_train)))
    log("评测集: 正 %d（含 IP 直连 %d）/ 负 %d" % (len(pos_eval), ip_eval, len(neg_eval)))
    log("正样本分类分布: %s" % json.dumps(cat_counts(positives), ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main())
