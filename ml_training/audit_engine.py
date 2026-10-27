# coding:utf-8
"""引擎体检（离线, 只读）: 用黑名单正样本 + 正常负样本跑 analyzer 的规则, 输出可对比的报告

回答三个问题:
  1) 每条规则到底有没有用（命中率 / 富集倍数 lift / 死规则 / 误报源）
  2) 判定阈值该不该动（阈值敏感性）
  3) 引擎在哪类样本上失效（覆盖缺口 + 误报明细）

用法
  python ml_training/audit_engine.py                            # 默认用清洗后的负样本
  python ml_training/audit_engine.py --extra                    # 额外跑 IP / URL 级样本（只测召回）
  python ml_training/audit_engine.py --neg domain_test_neg.tsv  # 用原始负样本做对比

产物: ml_training/metrics/audit-<时间戳>.md
"""

import argparse
import collections
import json
import os
import random
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


def load_tsv(name, limit=0, seed=42):
    path = os.path.join(DATA, name)
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path, encoding="utf-8") as fp:
        for line in fp:
            parts = line.rstrip("\n").split("\t")
            if len(parts) >= 2 and parts[1]:
                rows.append((int(parts[0]), parts[1], parts[2] if len(parts) > 2 else ""))
    if limit and len(rows) > limit:
        random.seed(seed)
        rows = random.sample(rows, limit)
    return rows


def tld_of(host):
    host = (host or "").strip(".")
    return host.rsplit(".", 1)[-1].lower() if "." in host else ""


def main():
    ap = argparse.ArgumentParser(description="analyzer 规则体检")
    ap.add_argument("--neg", default="domain_test_neg_clean.tsv",
                    help="负样本文件（默认清洗后的版本）")
    ap.add_argument("--limit-neg", type=int, default=0, help="负样本采样上限（0=全量）")
    ap.add_argument("--extra", action="store_true", help="额外评测 IP / URL 级样本（只测召回）")
    ap.add_argument("--out", default="", help="报告输出路径")
    args = ap.parse_args()

    cfg = json.load(open(os.path.join(BASE, "config.json"), encoding="utf-8"))["detection"]
    ana = URLAnalyzer(cfg)

    def run(rows, scheme="https://"):
        out = []
        t0 = time.time()
        for index, (_label, value, cat) in enumerate(rows):
            target = value if "://" in value else scheme + value
            try:
                result = ana.analyze(target, use_api=False)
            except Exception:
                result = {}
            out.append((value, cat, int(result.get("score") or 0),
                        list(result.get("matched_rules") or [])))
            if (index + 1) % 10000 == 0:
                print("    ... %d/%d (%.1fs)" % (index + 1, len(rows), time.time() - t0),
                      flush=True)
        return out

    pos = load_tsv("domain_test_pos.tsv")
    neg = load_tsv(args.neg, args.limit_neg)
    real = load_tsv("domain_realtraffic.tsv")
    print("正样本 %d ｜ 负样本 %d（%s）" % (len(pos), len(neg), args.neg))

    pos_res = run(pos)
    neg_res = run(neg)
    real_res = run(real)

    pos_n, neg_n = len(pos_res), len(neg_res)
    pos_hit = sum(1 for r in pos_res if r[2] >= THRESHOLD)
    neg_hit = sum(1 for r in neg_res if r[2] >= THRESHOLD)

    lines = []

    def w(text=""):
        lines.append(text)

    w("# 引擎体检报告（阈值 %d）" % THRESHOLD)
    w("")
    w("样本：正（黑名单域名）%d ｜ 负（%s）%d ｜ 真实流量 %d"
      % (pos_n, args.neg, neg_n, len(real_res)))
    w("")
    w("- 整体召回：%d/%d = **%.2f%%**" % (pos_hit, pos_n, 100.0 * pos_hit / max(1, pos_n)))
    w("- 整体误报：%d/%d = **%.3f%%**" % (neg_hit, neg_n, 100.0 * neg_hit / max(1, neg_n)))
    w("")

    w("## 1) 分类别召回")
    w("")
    w("| 分类 | 总数 | 命中 | 召回 |")
    w("|---|---|---|---|")
    by_cat = collections.defaultdict(lambda: [0, 0])
    for _v, cat, score, _r in pos_res:
        by_cat[cat][1] += 1
        if score >= THRESHOLD:
            by_cat[cat][0] += 1
    for cat, (hit, total) in sorted(by_cat.items(), key=lambda kv: -kv[1][1]):
        w("| %s | %d | %d | %.2f%% |"
          % (cat or "(未标)", total, hit, 100.0 * hit / max(1, total)))
    w("")

    w("## 2) 每条规则（lift = 正命中率 ÷ 负命中率）")
    w("")
    w("| 规则 | 正命中 | 负命中 | 正命中率 | 负命中率 | lift | 判定 |")
    w("|---|---|---|---|---|---|---|")
    rule_pos, rule_neg = collections.Counter(), collections.Counter()
    for _v, _c, _s, rules in pos_res:
        for name in set(rules):
            rule_pos[name] += 1
    for _v, _c, _s, rules in neg_res:
        for name in set(rules):
            rule_neg[name] += 1
    rule_rows = []
    for name in sorted(set(rule_pos) | set(rule_neg)):
        p = rule_pos.get(name, 0) / max(1, pos_n)
        n = rule_neg.get(name, 0) / max(1, neg_n)
        rule_rows.append((name, rule_pos.get(name, 0), rule_neg.get(name, 0),
                          p, n, p / max(n, 1e-6)))
    rule_rows.sort(key=lambda x: -x[3])
    for name, ph, nh, p, n, lift in rule_rows:
        verdict = ("**误报源**" if (lift < 2 and nh >= 10) else
                   "很专一" if lift >= 10 else "有效" if lift >= 3 else "偏弱")
        w("| %s | %d | %d | %.2f%% | %.3f%% | %.1f | %s |"
          % (name, ph, nh, 100 * p, 100 * n, lift, verdict))
    w("")

    w("## 3) 阈值敏感性")
    w("")
    w("| 阈值 | 正召回 | 负误报 | 真实流量误报 |")
    w("|---|---|---|---|")
    for thr in (40, 50, 55, 60, 65, 70, 80):
        ph = sum(1 for r in pos_res if r[2] >= thr)
        nh = sum(1 for r in neg_res if r[2] >= thr)
        rh = sum(1 for r in real_res if r[2] >= thr)
        w("| %d | %.2f%% (%d) | %.3f%% (%d) | %d |"
          % (thr, 100.0 * ph / max(1, pos_n), ph, 100.0 * nh / max(1, neg_n), nh, rh))
    w("")

    miss = [(v, c, s) for v, c, s, _r in pos_res if s < THRESHOLD]
    w("## 4) 覆盖缺口")
    w("")
    w("- 抓不到：%d/%d（%.2f%%）" % (len(miss), pos_n, 100.0 * len(miss) / max(1, pos_n)))
    tld_miss = collections.Counter(tld_of(v) for v, _c, _s in miss)
    w("- 漏掉的样本里最常见的 TLD：%s"
      % "、".join(".%s(%d)" % (t, n) for t, n in tld_miss.most_common(12)))
    w("")
    w("```")
    for v, c, s in miss[:10]:
        w("%-50s score=%-3d %s" % (v[:50], s, c))
    w("```")
    w("")

    bad = sorted([(v, s, r) for v, _c, s, r in neg_res if s >= THRESHOLD],
                 key=lambda x: -x[1])
    w("## 5) 误报明细（top 15）")
    w("")
    w("| 域名 | 分数 | 命中规则 |")
    w("|---|---|---|")
    for host, score, rules in bad[:15]:
        w("| %s | %d | %s |" % (host, score, ", ".join(rules)))
    w("")

    if real_res:
        w("## 6) 真实流量")
        w("")
        w("| 域名 | 分数 | 误报 | 命中规则 |")
        w("|---|---|---|---|")
        for host, _c, score, rules in real_res:
            w("| %s | %d | %s | %s |" % (host, score,
                                         "**是**" if score >= THRESHOLD else "否",
                                         ", ".join(rules)))
        w("")

    if args.extra:
        w("## 7) 额外评测集（只测召回, 没有对应负样本）")
        w("")
        # IP 直连分 http / https 两种: 真实恶意 IP 站点多为 http（ip_host 45 + no_https 15 = 60）
        ip_rows = load_tsv("eval_ip.tsv")
        if ip_rows:
            for scheme in ("http://", "https://"):
                res = run(ip_rows, scheme=scheme)
                hit = sum(1 for r in res if r[2] >= THRESHOLD)
                w("- **IP 直连恶意（%s）**：%d 条，命中 %d（**%.2f%%**）"
                  % (scheme.rstrip("/"), len(res), hit, 100.0 * hit / max(1, len(res))))
        else:
            w("- IP 直连恶意：文件不存在, 跳过（先跑 build_eval_sets.py）")

        url_rows = load_tsv("eval_url.tsv")
        if url_rows:
            res = run(url_rows, scheme="https://")
            hit = sum(1 for r in res if r[2] >= THRESHOLD)
            w("- **带路径恶意 URL**：%d 条，命中 %d（**%.2f%%**）"
              % (len(res), hit, 100.0 * hit / max(1, len(res))))
        else:
            w("- 带路径恶意 URL：文件不存在, 跳过")
        w("")

    os.makedirs(METRICS, exist_ok=True)
    out = args.out or os.path.join(METRICS, "audit-%s.md" % time.strftime("%Y%m%d-%H%M%S"))
    if not os.path.isabs(out):
        out = os.path.join(BASE, out)
    with open(out, "w", encoding="utf-8") as fp:
        fp.write("\n".join(lines))
    print("报告已写入: %s" % os.path.relpath(out, BASE))
    return 0


if __name__ == "__main__":
    sys.exit(main())


