# coding:utf-8
"""在 URL 级评测集上测「分析器（analyzer）」的效果（供规则改动前后对比）

用法
  python ml_training/eval_rules_on_urls.py                # 跑一次
  python ml_training/eval_rules_on_urls.py --tag before   # 打标签, 便于前后对比

产物：ml_training/metrics/rules-url-<tag>-<时间戳>.md / .json
"""

import argparse
import collections
import json
import os
import sys
import time

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
os.chdir(BASE)
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from analyzer import URLAnalyzer          # noqa: E402

DATA = os.path.join(BASE, "ml_training", "data")
METRICS = os.path.join(BASE, "ml_training", "metrics")
THRESHOLD = 60


def load_urls(name):
    rows = []
    path = os.path.join(DATA, name)
    if not os.path.exists(path):
        return rows
    with open(path, encoding="utf-8") as fp:
        for line in fp:
            parts = line.rstrip("\n").split("\t")
            if len(parts) >= 2 and parts[1]:
                rows.append((parts[1], parts[2] if len(parts) > 2 else ""))
    return rows


def host_of(value):
    from urllib.parse import urlsplit
    text = (value or "").strip()
    if "://" not in text:
        text = "http://" + text.lstrip("/")
    try:
        return (urlsplit(text).hostname or "").lower().strip(".")
    except Exception:
        return ""


def is_ip(host):
    parts = (host or "").split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def main():
    ap = argparse.ArgumentParser(description="URL 级评测集上的分析器体检")
    ap.add_argument("--tag", default="run", help="报告标签（如 before / after-combo）")
    args = ap.parse_args()

    pos = load_urls("urleval_pos.tsv")
    neg = load_urls("urleval_neg.tsv")
    if not pos or not neg:
        print("缺少 urleval_*.tsv，请先跑 build_url_eval.py")
        return 1

    cfg = json.load(open(os.path.join(BASE, "config.json"), encoding="utf-8"))["detection"]
    ana = URLAnalyzer(cfg)
    print("评测集: 正 %d ｜ 负 %d" % (len(pos), len(neg)))

    def run(rows):
        out = []
        t0 = time.time()
        for index, (url, cat) in enumerate(rows):
            try:
                result = ana.analyze(url, use_api=False)
            except Exception:
                result = {}
            out.append((url, cat, int(result.get("score") or 0),
                        list(result.get("matched_rules") or [])))
            if (index + 1) % 5000 == 0:
                print("    ... %d/%d (%.1fs)" % (index + 1, len(rows), time.time() - t0),
                      flush=True)
        return out

    pos_res = run(pos)
    neg_res = run(neg)
    return report(args, pos_res, neg_res)


def report(args, pos_res, neg_res):
    pos_hit = sum(1 for r in pos_res if r[2] >= THRESHOLD)
    neg_hit = sum(1 for r in neg_res if r[2] >= THRESHOLD)
    print("")
    print("== 召回 / 误报（阈值 %d）==" % THRESHOLD)
    print("  正样本召回 %.2f%%（%d/%d）"
          % (100.0 * pos_hit / len(pos_res), pos_hit, len(pos_res)))
    print("  负样本误报 %.3f%%（%d/%d）"
          % (100.0 * neg_hit / len(neg_res), neg_hit, len(neg_res)))

    by_cat = collections.defaultdict(lambda: [0, 0])
    for _u, cat, score, _r in pos_res:
        by_cat[cat][1] += 1
        if score >= THRESHOLD:
            by_cat[cat][0] += 1
    print("")
    print("== 分类别召回 ==")
    for cat, (hit, total) in sorted(by_cat.items(), key=lambda kv: -kv[1][1]):
        print("  %-12s %5d/%5d (%.1f%%)" % (cat, hit, total, 100.0 * hit / max(1, total)))

    ip_mask = [is_ip(host_of(row[0])) for row in pos_res]
    for label, want in (("IP 直连", True), ("非 IP（域名 URL）", False)):
        idx = [i for i, flag in enumerate(ip_mask) if flag is want]
        if not idx:
            continue
        hit = sum(1 for i in idx if pos_res[i][2] >= THRESHOLD)
        print("  %-12s %5d/%5d (%.1f%%)" % (label, hit, len(idx), 100.0 * hit / len(idx)))

    rule_pos, rule_neg = collections.Counter(), collections.Counter()
    for _u, _c, _s, rules in pos_res:
        for name in set(rules):
            rule_pos[name] += 1
    for _u, _c, _s, rules in neg_res:
        for name in set(rules):
            rule_neg[name] += 1
    rows = []
    for name in sorted(set(rule_pos) | set(rule_neg)):
        p = rule_pos.get(name, 0) / len(pos_res)
        n = rule_neg.get(name, 0) / len(neg_res)
        rows.append((name, rule_pos.get(name, 0), rule_neg.get(name, 0),
                     p, n, p / max(n, 1e-6)))
    rows.sort(key=lambda x: -x[3])
    print("")
    print("== 每条规则（URL 级评测集上）==")
    print("  %-22s %7s %7s %9s %9s %8s"
          % ("规则", "正命中", "负命中", "正命中率", "负命中率", "lift"))
    for name, ph, nh, p, n, lift in rows:
        print("  %-22s %7d %7d %8.2f%% %8.3f%% %8.1f"
              % (name, ph, nh, 100 * p, 100 * n, lift))

    os.makedirs(METRICS, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    base = "rules-url-%s-%s" % (args.tag, stamp)
    payload = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "tag": args.tag, "threshold": THRESHOLD,
        "eval_pos": len(pos_res), "eval_neg": len(neg_res),
        "recall": round(pos_hit / len(pos_res), 5),
        "fp": neg_hit,
        "by_cat": {k: {"hit": v[0], "total": v[1]} for k, v in by_cat.items()},
        "rules": {name: {"pos": ph, "neg": nh,
                         "pos_rate": round(p, 5), "neg_rate": round(n, 6),
                         "lift": round(lift, 2)}
                  for name, ph, nh, p, n, lift in rows},
    }
    with open(os.path.join(METRICS, base + ".json"), "w", encoding="utf-8") as fp:
        json.dump(payload, fp, ensure_ascii=False, indent=2)
    with open(os.path.join(METRICS, base + ".md"), "w", encoding="utf-8") as fp:
        fp.write("# 分析器 URL 级体检（tag=%s）\n\n" % args.tag)
        fp.write("正 %d ｜负 %d ｜阈值 %d\n\n"
                 % (len(pos_res), len(neg_res), THRESHOLD))
        fp.write("- 召回 **%.2f%%**（%d/%d）\n"
                 % (100.0 * pos_hit / len(pos_res), pos_hit, len(pos_res)))
        fp.write("- 误报 **%d/%d（%.3f%%）**\n\n"
                 % (neg_hit, len(neg_res), 100.0 * neg_hit / len(neg_res)))
        fp.write("| 分类 | 命中/总数 | 召回 |\n|---|---|---|\n")
        for cat, (hit, total) in sorted(by_cat.items(), key=lambda kv: -kv[1][1]):
            fp.write("| %s | %d/%d | %.1f%% |\n"
                     % (cat, hit, total, 100.0 * hit / max(1, total)))
        fp.write("\n| 规则 | 正命中 | 负命中 | 正命中率 | 负命中率 | lift |\n"
                 "|---|---|---|---|---|---|\n")
        for name, ph, nh, p, n, lift in rows:
            fp.write("| %s | %d | %d | %.2f%% | %.3f%% | %.1f |\n"
                     % (name, ph, nh, 100 * p, 100 * n, lift))
    print("")
    print("报告: %s" % os.path.relpath(os.path.join(METRICS, base + ".md"), BASE))
    return 0


if __name__ == "__main__":
    sys.exit(main())
