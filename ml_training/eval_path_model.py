# coding:utf-8
"""第 7 步（7-B）：测现有 path 模型的真实基线（不改任何模型）

两个口径都报（因为 URL 级负样本是"构造"的, 误报率会偏低, 必须说清楚）:
  A. 现网口径：直接用模型自带阈值（path = 0.61, 生产就是它）
  B. 重选阈值：按"负样本误报率 ≤ fpr"重选阈值, 报召回@FPR 曲线

同时给**关键对照**：同一批 URL 正样本的 host 在现网域名模型（v2）上的召回,
以及"URL 级 ∪ 域名级"的融合召回 —— 用来判断第 7 步到底有没有补位价值。

产物
  ml_training/metrics/path-baseline-<时间戳>.md
  ml_training/metrics/path-baseline-<时间戳>.json

用法
  python ml_training/eval_path_model.py
"""

import json
import os
import sys
import time

import numpy as np
from sklearn.metrics import roc_auc_score

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
os.chdir(BASE)
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from ml_url_model import MLUrlModel, DomainURLModel      # noqa: E402

DATA = os.path.join(BASE, "ml_training", "data")
METRICS = os.path.join(BASE, "ml_training", "metrics")
PATH_MODEL = os.path.join(BASE, "data", "models", "path_model.pkl")
DOMAIN_MODEL = os.path.join(BASE, "data", "models", "domain_model.pkl")


def log(msg):
    print(msg, flush=True)


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


def threshold_for(normal_sorted, fpr):
    if normal_sorted.size == 0:
        return 1.0
    if fpr <= 0:
        return float(normal_sorted.max()) + 1e-9
    k = int(np.floor(fpr * normal_sorted.size))
    if k <= 0:
        return float(normal_sorted.max()) + 1e-9
    return float(normal_sorted[normal_sorted.size - k])


def recall_at(probs, threshold):
    probs = np.asarray(probs)
    return float((probs >= threshold).mean()) if probs.size else 0.0


def host_of(value):
    from urllib.parse import urlsplit
    text = (value or "").strip()
    if "://" not in text:
        text = "http://" + text.lstrip("/")
    try:
        return (urlsplit(text).hostname or "").lower().strip(".")
    except Exception:
        return ""


def _is_ip(host):
    parts = (host or "").split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def main():
    pos = load_urls("urleval_pos.tsv")
    neg = load_urls("urleval_neg.tsv")
    if not pos or not neg:
        log("缺少 urleval_pos.tsv / urleval_neg.tsv, 请先跑 build_url_eval.py")
        return 1
    log("评测集: 正 %d ｜ 负 %d" % (len(pos), len(neg)))

    pmodel = MLUrlModel(PATH_MODEL, threshold=None, confidence=0.9)
    if not pmodel.load(verbose=True):
        log("path 模型不可用: %s" % pmodel.error)
        return 1
    log("现网 path 模型: 阈值 %.4f" % float(pmodel.threshold))

    t0 = time.time()
    p_pos = np.array([pmodel.predict(v).get("prob") or 0.0 for v, _c in pos])
    p_neg = np.array([pmodel.predict(v).get("prob") or 0.0 for v, _c in neg])
    log("预测完成（%.1fs）" % (time.time() - t0))

    lines = []

    def w(text=""):
        lines.append(text)
        log(text)

    own_thr = float(pmodel.threshold)
    own_rec = recall_at(p_pos, own_thr)
    own_fp = int((p_neg >= own_thr).sum())

    w("")
    w("## 口径 A：现网阈值 %.4f（生产正在使用）" % own_thr)
    w("")
    w("- 正样本召回 **%.2f%%**（%d/%d）"
      % (100 * own_rec, int((p_pos >= own_thr).sum()), len(p_pos)))
    w("- 负样本误报 **%d/%d（%.3f%%）**"
      % (own_fp, len(p_neg), 100.0 * own_fp / max(1, len(p_neg))))
    w("")

    normal = np.sort(p_neg)
    w("## 口径 B：按负样本误报率重选阈值")
    w("")
    w("| FPR≤ | 阈值 | 召回 | 误报 |")
    w("|---|---|---|---|")
    curve = []
    for fpr in (0.0, 1e-4, 1e-3, 1e-2):
        thr = threshold_for(normal, fpr)
        rec = recall_at(p_pos, thr)
        fp = int((p_neg >= thr).sum())
        curve.append({"fpr": fpr, "threshold": thr, "recall": rec, "fp": fp})
        w("| %s | %.4f | %.2f%% | %d |" % (fpr, thr, 100 * rec, fp))
    w("")

    auc = roc_auc_score(np.r_[np.zeros(len(p_neg)), np.ones(len(p_pos))], np.r_[p_neg, p_pos])
    w("**AUC: %.4f**" % auc)
    w("")

    by_cat = {}
    for (value, cat), prob in zip(pos, p_pos):
        row = by_cat.setdefault(cat or "未标", [0, 0])
        row[1] += 1
        if prob >= own_thr:
            row[0] += 1
    ip_mask = np.asarray([_is_ip(host_of(v)) for v, _c in pos], dtype=bool)
    w("## 分类别召回（口径 A）")
    w("")
    w("| 类别 | 命中/总数 | 召回 |")
    w("|---|---|---|")
    for cat, (hit, total) in sorted(by_cat.items(), key=lambda kv: -kv[1][1]):
        w("| %s | %d/%d | %.1f%% |" % (cat, hit, total, 100.0 * hit / max(1, total)))
    if ip_mask.any():
        hit = int((p_pos[ip_mask] >= own_thr).sum())
        w("| IP 直连 | %d/%d | %.1f%% |"
          % (hit, int(ip_mask.sum()), 100.0 * hit / max(1, int(ip_mask.sum()))))
    if (~ip_mask).any():
        hit = int((p_pos[~ip_mask] >= own_thr).sum())
        w("| **非 IP（域名 URL）** | %d/%d | **%.1f%%** |"
          % (hit, int((~ip_mask).sum()), 100.0 * hit / max(1, int((~ip_mask).sum()))))
    w("")
    w("> 评测集里 IP 直连占 %.1f%%（黑名单里 IP URL 本就多）；看真实网页浏览场景请重点参考「非 IP」那一行。"
      % (100.0 * ip_mask.sum() / max(1, len(pos))))
    w("")

    dom_hit_rate = or_rec = None
    try:
        dmodel = DomainURLModel(DOMAIN_MODEL, threshold=None, confidence=0.9)
        if dmodel.load(verbose=False):
            d_probs = np.asarray(dmodel.proba_batch([host_of(v) for v, _c in pos]), dtype=float)
            d_apply = np.asarray([dmodel._calibrate(p) for p in d_probs], dtype=float)
            d_thr = float(dmodel.threshold)
            dom_mask = d_apply >= d_thr
            dom_hit_rate = float(dom_mask.mean())
            or_rec = float(np.logical_or(dom_mask, p_pos >= own_thr).mean())
            w("## 关键对照（同一批 %d 条恶意 URL）" % len(pos))
            w("")
            w("| 通道 | 阈值 | 召回 |")
            w("|---|---|---|")
            w("| 域名级（现网 v2） | %.4f | %.2f%% |" % (d_thr, 100 * dom_hit_rate))
            w("| URL 级（path） | %.4f | %.2f%% |" % (own_thr, 100 * own_rec))
            w("| **两者 OR 融合** | — | **%.2f%%**（相对域名级 %+.2f pt） |"
              % (100 * or_rec, 100 * (or_rec - dom_hit_rate)))
            w("")
    except Exception as exc:
        log("域名级对照失败(忽略): %s" % exc)

    w("> 说明：URL 级负样本是**构造**的（正常域名 × 常见路径模板），比真实分布「干净」，")
    w("> 所以口径 A 的误报率会**偏低**，请以口径 B 的曲线 + 人工抽检为准。")

    os.makedirs(METRICS, exist_ok=True)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    md_path = os.path.join(METRICS, "path-baseline-%s.md" % stamp)
    with open(md_path, "w", encoding="utf-8") as fp:
        fp.write("# path 模型基线评测（现网 path_model.pkl）\n\n")
        fp.write("评测集：正 %d（urleval_pos.tsv）｜负 %d（urleval_neg.tsv）\n\n"
                 % (len(pos), len(neg)))
        fp.write("\n".join(lines))
    json_path = os.path.join(METRICS, "path-baseline-%s.json" % stamp)
    with open(json_path, "w", encoding="utf-8") as fp:
        json.dump({
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "model": PATH_MODEL, "own_threshold": own_thr,
            "eval_pos": len(pos), "eval_neg": len(neg),
            "own_threshold_recall": round(own_rec, 5),
            "own_threshold_fp": own_fp,
            "auc": round(float(auc), 5),
            "curve": curve,
            "by_cat": {k: {"hit": v[0], "total": v[1]} for k, v in by_cat.items()},
            "domain_channel_hit_rate": round(dom_hit_rate, 5) if dom_hit_rate is not None else None,
            "or_recall_with_domain": round(or_rec, 5) if or_rec is not None else None,
            "caveat": "URL 级负样本为构造（正常域名×路径模板），误报率偏低",
        }, fp, ensure_ascii=False, indent=2)
    log("")
    log("报告: %s" % os.path.relpath(md_path, BASE))
    log("数据: %s" % os.path.relpath(json_path, BASE))
    return 0


if __name__ == "__main__":
    sys.exit(main())
