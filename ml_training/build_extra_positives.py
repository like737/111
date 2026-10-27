# coding:utf-8
"""第 6 步（A1）：抓取公开恶意样本源，补"钓鱼 / 恶意下载"两类正样本

解决当前正样本严重偏斜的问题（训练集里 96% 是色情域名 → 钓鱼/恶意下载几乎学不到）。

数据源（都无需 API key, 官方提供下载）
  URLhaus csv_recent        → 恶意下载（threat=malware_download 等）
  OpenPhish feed            → 钓鱼（最近 300 条, 质量高）
  PhishingArmy blocklist    → 钓鱼（约 15 万条, 量大）

红线
  * 与测试集正样本的**注册域**重叠的一律排除（防泄漏, 与 build_domain_dataset 同口径）;
  * 每类按配额采样（默认 2 万）, 避免钓鱼/恶意样本反过来淹没色情类;
  * 抓取失败只跳过该源并记录, 不影响其它源。

产物
  ml_training/data/external_pos.tsv      label<TAB>host<TAB>category
  ml_training/data/external_manifest.json

用法
  python ml_training/build_extra_positives.py
"""

import argparse
import csv
import io
import json
import os
import random
import sys
import time
import urllib.request
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
UA = {"User-Agent": "Mozilla/5.0 (compatible; eyilianjie-research/1.0)"}

SOURCES = [
    ("urlhaus", "https://urlhaus.abuse.ch/downloads/csv_recent/", "恶意下载", "urlhaus_csv"),
    ("urlhaus-domains", "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-domains.txt",
     "恶意下载", "plain_hosts"),
    ("openphish", "https://openphish.com/feed.txt", "钓鱼", "plain_urls"),
    ("phishingarmy", "https://phishing.army/download/phishing_army_blocklist_extended.txt",
     "钓鱼", "plain_hosts"),
]


def log(msg):
    print(msg, flush=True)


def fetch(url, timeout=40):
    request = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(request, timeout=timeout) as resp:
        return resp.read()


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


def is_private_ip(host):
    import ipaddress
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return bool(ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified)


def parse_urlhaus(raw):
    """URLhaus CSV: 跳过 # 注释, 取第 3 列 url（按表头定位更稳）"""
    text = raw.decode("utf-8", "replace")
    out = []
    reader = csv.reader(io.StringIO(text))
    url_index = 2
    for row in reader:
        if not row or (row[0] or "").startswith("#"):
            continue
        if (row[0] or "").strip().lower() == "id":
            for idx, name in enumerate(row):
                if name.strip().lower() == "url":
                    url_index = idx
            continue
        if len(row) > url_index:
            out.append(row[url_index])
    return out


def parse_plain(raw):
    return [line.strip() for line in raw.decode("utf-8", "replace").splitlines()
            if line.strip() and not line.startswith("#")]


def parse_hosts_file(raw):
    """兼容三种常见格式: 纯域名 / hosts(0.0.0.0 domain) / AdGuard(||domain^)"""
    out = []
    for line in raw.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("!"):
            continue
        if line.startswith("||"):
            line = line[2:].split("^")[0].split("/")[0]
        elif " " in line or "\t" in line:
            line = line.split()[-1]
        if line and "." in line:
            out.append(line)
    return out


def load_test_registered_domains():
    path = os.path.join(DATA, "domain_test_pos.tsv")
    regs = set()
    if not os.path.exists(path):
        return regs
    with open(path, encoding="utf-8") as fp:
        for line in fp:
            parts = line.rstrip("\n").split("\t")
            if len(parts) >= 2 and parts[1]:
                regs.add(get_registered_domain(parts[1]))
    return regs


def main():
    ap = argparse.ArgumentParser(description="抓取外部恶意样本（钓鱼 / 恶意下载）")
    ap.add_argument("--target-per-cat", type=int, default=20000, help="每类采样上限")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    test_regs = load_test_registered_domains()
    log("测试集正样本注册域: %d 个（同注册域的一律不进训练集, 防泄漏）" % len(test_regs))

    rng = random.Random(args.seed)
    buckets = {}          # category -> {host: None}
    url_level = {}        # category -> [url]  （第 7 步 URL 级训练用）
    stats = {"sources": {}, "skipped_leak": 0, "skipped_ip": 0, "errors": {}}

    for name, url, category, kind in SOURCES:
        try:
            raw = fetch(url)
        except Exception as exc:
            stats["errors"][name] = "%s: %s" % (type(exc).__name__, str(exc)[:80])
            log("[FAIL] %-14s %s" % (name, stats["errors"][name]))
            continue
        try:
            if kind == "urlhaus_csv":
                values = parse_urlhaus(raw)
            elif kind == "plain_hosts":
                values = parse_hosts_file(raw)
            else:
                values = parse_plain(raw)
        except Exception as exc:
            stats["errors"][name] = "parse: %s" % exc
            log("[FAIL] %-14s 解析失败: %s" % (name, exc))
            continue

        bucket = buckets.setdefault(category, {})
        urls = url_level.setdefault(category, [])
        added = 0
        for value in values:
            host = host_of(value)
            if not host:
                continue
            if is_ip_host(host):
                stats["skipped_ip"] += 1        # IP 样本归 ip_host 规则管, 不进域名模型
                continue
            if is_private_ip(host):
                continue
            if get_registered_domain(host) in test_regs:
                stats["skipped_leak"] += 1      # 与测试集同注册域 → 防泄漏
                continue
            if host not in bucket:
                bucket[host] = None
                added += 1
            if "://" in value and len(urls) < 60000:
                urls.append(value.strip())
        stats["sources"][name] = {"category": category, "parsed": len(values), "new_hosts": added}
        log("[OK]   %-14s -> %s: 解析 %d, 新增域名 %d（该类累计 %d）"
            % (name, category, len(values), added, len(bucket)))

    rows, manifest_cats = [], {}
    for category, bucket in buckets.items():
        hosts = sorted(bucket)
        picked = hosts if len(hosts) <= args.target_per_cat else rng.sample(hosts, args.target_per_cat)
        rows += [(1, host, category) for host in picked]
        manifest_cats[category] = {"available": len(hosts), "used": len(picked)}

    rng.shuffle(rows)
    with open(os.path.join(DATA, "external_pos.tsv"), "w", encoding="utf-8") as fp:
        for label, host, category in rows:
            fp.write("%d\t%s\t%s\n" % (label, host, category))

    url_rows = []
    for category, urls in url_level.items():
        for value in urls[:40000]:
            url_rows.append((1, value, category))
    with open(os.path.join(DATA, "external_url.tsv"), "w", encoding="utf-8") as fp:
        for label, value, category in url_rows:
            fp.write("%d\t%s\t%s\n" % (label, value, category))

    manifest = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "target_per_cat": args.target_per_cat,
        "seed": args.seed,
        "categories": manifest_cats,
        "total_rows": len(rows),
        "url_rows": len(url_rows),
        "skipped_leak": stats["skipped_leak"],
        "skipped_ip": stats["skipped_ip"],
        "sources": stats["sources"],
        "errors": stats["errors"],
    }
    with open(os.path.join(DATA, "external_manifest.json"), "w", encoding="utf-8") as fp:
        json.dump(manifest, fp, ensure_ascii=False, indent=2)

    log("")
    log("写出 ml_training/data/external_pos.tsv: %d 行" % len(rows))
    log("写出 ml_training/data/external_url.tsv: %d 行（第 7 步用）" % len(url_rows))
    log("分类统计: %s" % json.dumps(manifest_cats, ensure_ascii=False))
    log("防泄漏跳过 %d | IP 跳过 %d" % (stats["skipped_leak"], stats["skipped_ip"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
