# coding:utf-8
"""第 6 步（A3+A4）：重训域名模型 v2

相对 v1 的改进
  1) 负样本清洗：剔除"真成人/赌博站"（Tranco 里混进来的标签噪声）;
  2) 正样本按类别配额：色情下采样到 per_cat, 并补入外部抓取的钓鱼/恶意下载样本;
  3) 概率校准（Platt scaling）: 让 prob 接近真实恶意率, 阈值才有"误拦/万次"的含义;
  4) 与 baseline（现网 domain_model.pkl）在同一测试集上对比, 达标才建议替换。

红线
  * 训练/测试按注册域切分（沿用现有 tsv, 外部样本已按注册域排除测试域）;
  * 不覆盖现网模型（输出 domain_model_v2.pkl）;
  * 只评估"域名级"样本, 不混入路径模型。

用法
  python ml_training/train_domain_model_v2.py                 # 训练 + 评测 + 存档
  python ml_training/train_domain_model_v2.py --per-cat 15000  # 调整每类正样本上限
"""

import argparse
import collections
import json
import os
import pickle
import random
import sys
import time

import numpy as np
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
os.chdir(BASE)
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

from ml_url_model import host_struct_features, DomainURLModel    # noqa: E402
from utils import match_adult_keywords                           # noqa: E402

DATA = os.path.join(BASE, "ml_training", "data")
METRICS = os.path.join(BASE, "ml_training", "metrics")
OUT_DEFAULT = os.path.join(BASE, "data", "models", "domain_model_v2.pkl")
BASELINE = os.path.join(BASE, "data", "models", "domain_model.pkl")


def log(msg):
    print(msg, flush=True)


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
    try:
        hits = match_adult_keywords(host or "")
    except Exception:
        return False
    strong = (list(hits.get("domain_strong") or []) + list(hits.get("adult_brands") or [])
              + list(hits.get("gambling") or []))
    return bool(strong)


def platt_apply(probs, a, b):
    """把原始概率经 sigmoid(a*logit+b) 校准（与 ml_url_model 的加载端实现一致）"""
    p = np.clip(np.asarray(probs, dtype=float), 1e-6, 1 - 1e-6)
    z = np.log(p / (1.0 - p))
    return 1.0 / (1.0 + np.exp(-(a * z + b)))


def featurize(vectorizer, hosts, mean=None, scale=None, fit=False):
    X = vectorizer.fit_transform(hosts) if fit else vectorizer.transform(hosts)
    F = np.asarray([host_struct_features(h) for h in hosts], dtype=float)
    if fit:
        mean = F.mean(axis=0)
        scale = F.std(axis=0)
        scale[scale == 0] = 1.0
    F = (F - mean) / scale
    return hstack([X, csr_matrix(F)]).tocsr(), mean, scale


def prepare_data(per_cat, seed):
    """训练集 = 现有正样本(按类配额) + 外部正样本(钓鱼/恶意下载) ; 负样本清洗后全量"""
    rng = random.Random(seed)
    train = load_tsv("domain_train.tsv")
    pos_by_cat = collections.defaultdict(list)
    neg, dropped_adult = [], 0
    for label, host, cat in train:
        if label == 1:
            pos_by_cat[cat or "未标"].append(host)
        else:
            if is_adult_or_gambling(host):
                dropped_adult += 1
                continue
            neg.append(host)

    pos, used_cats = [], {}
    for cat, hosts in sorted(pos_by_cat.items(), key=lambda kv: -len(kv[1])):
        picked = hosts if len(hosts) <= per_cat else rng.sample(hosts, per_cat)
        used_cats[cat] = {"available": len(hosts), "used": len(picked)}
        pos += [(host, cat) for host in picked]

    seen = {host for host, _ in pos}
    ext = load_tsv("external_pos.tsv")
    ext_added = 0
    for _label, host, cat in ext:
        if host in seen:
            continue
        seen.add(host)
        pos.append((host, cat))
        used_cats[cat] = used_cats.get(cat, {"available": 0, "used": 0})
        used_cats[cat]["used"] += 1
        ext_added += 1

    before = len(neg)
    neg = [host for host in neg if host not in seen]
    log("负样本清洗: 原 %d → 剔除成人/赌博 %d → 与正样本去重 -%d → 剩 %d"
        % (before + dropped_adult, dropped_adult, before - len(neg), len(neg)))
    log("正样本: 现有按类配额 + 外部 %d 条 → 合计 %d（分类: %s）"
        % (ext_added, len(pos), json.dumps(used_cats, ensure_ascii=False)))
    return pos, neg, dropped_adult, used_cats


def threshold_for(normal_sorted, fpr):
    """满足"正常集误报率 ≤ fpr"的最低阈值"""
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


def main():
    ap = argparse.ArgumentParser(description="训练域名模型 v2（含概率校准）")
    ap.add_argument("--per-cat", type=int, default=20000, help="现有正样本每类上限")
    ap.add_argument("--max-fpr", type=float, default=1e-4, help="选阈值时的正常集误报上限")
    ap.add_argument("--ngram-max", type=int, default=4)
    ap.add_argument("--C", type=float, default=4.0)
    ap.add_argument("--max-features", type=int, default=200000)
    ap.add_argument("--val-ratio", type=float, default=0.15, help="用于概率校准的验证集比例")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", default=OUT_DEFAULT)
    args = ap.parse_args()

    t0 = time.time()
    pos, neg, dropped_adult, used_cats = prepare_data(args.per_cat, args.seed)

    rng = random.Random(args.seed)
    rng.shuffle(pos)
    rng.shuffle(neg)
    n_val_pos = int(len(pos) * args.val_ratio)
    n_val_neg = int(len(neg) * args.val_ratio)
    val = [(h, 1) for h, _ in pos[:n_val_pos]] + [(h, 0) for h in neg[:n_val_neg]]
    train = [(h, 1) for h, _ in pos[n_val_pos:]] + [(h, 0) for h in neg[n_val_neg:]]
    rng.shuffle(train)
    rng.shuffle(val)
    log("训练 %d（正 %d / 负 %d）｜校准验证集 %d（正 %d / 负 %d）"
        % (len(train), len(pos) - n_val_pos, len(neg) - n_val_neg,
           len(val), n_val_pos, n_val_neg))

    hosts_tr = [h for h, _ in train]
    y_tr = np.array([y for _, y in train])
    hosts_val = [h for h, _ in val]
    y_val = np.array([y for _, y in val])

    vec = TfidfVectorizer(analyzer="char", ngram_range=(2, args.ngram_max),
                          lowercase=False, max_features=args.max_features, min_df=2)
    A_tr, mean, scale = featurize(vec, hosts_tr, fit=True)
    A_val, _, _ = featurize(vec, hosts_val, mean, scale)
    log("特征 %d 维（字符 n-gram + %d 维结构特征）｜耗时 %.1fs"
        % (A_tr.shape[1], len(mean), time.time() - t0))

    clf = LogisticRegression(C=args.C, max_iter=2000, solver="liblinear")
    clf.fit(A_tr, y_tr)
    p_val = clf.predict_proba(A_val)[:, 1]
    auc_val = roc_auc_score(y_val, p_val) if len(set(y_val.tolist())) > 1 else float("nan")
    log("训练完成: 验证集 AUC %.4f ｜耗时 %.1fs" % (auc_val, time.time() - t0))

    # ---- Platt 校准（一维 logistic 回归 → 两个参数 a, b；加载端只需 sigmoid） ----
    clipped = np.clip(p_val, 1e-6, 1 - 1e-6)
    z_val = np.log(clipped / (1.0 - clipped))
    cal = LogisticRegression(C=1e6, solver="lbfgs", max_iter=1000)
    cal.fit(z_val.reshape(-1, 1), y_val)
    a = float(cal.coef_[0][0])
    b = float(cal.intercept_[0])
    p_val_cal = platt_apply(p_val, a, b)
    log("Platt 校准: a=%.4f b=%.4f（验证集预测恶意率 %.4f / 真实 %.4f）"
        % (a, b, float(p_val_cal.mean()), float(y_val.mean())))

    test_pos = load_tsv("domain_test_pos.tsv")
    test_neg = load_tsv("domain_test_neg_clean.tsv")
    real = load_tsv("domain_realtraffic.tsv")

    A_pos, _, _ = featurize(vec, [h for _l, h, _c in test_pos], mean, scale)
    A_neg, _, _ = featurize(vec, [h for _l, h, _c in test_neg], mean, scale)
    p_pos = platt_apply(clf.predict_proba(A_pos)[:, 1], a, b)
    p_neg = platt_apply(clf.predict_proba(A_neg)[:, 1], a, b)
    if real:
        A_real, _, _ = featurize(vec, [h for _l, h, _c in real], mean, scale)
        p_real = platt_apply(clf.predict_proba(A_real)[:, 1], a, b)
    else:
        p_real = np.array([])

    normal = np.sort(np.concatenate([p_neg, p_real]) if p_real.size else p_neg)
    log("")
    log("阈值-误报-召回 曲线（正常集 = 测试负 %d + 真实流量 %d）:" % (len(p_neg), p_real.size))
    curve = []
    for fpr in (0.0, 1e-5, 1e-4, 1e-3, 1e-2):
        thr_i = threshold_for(normal, fpr)
        fp_neg = int((p_neg >= thr_i).sum())
        fp_real = int((p_real >= thr_i).sum()) if p_real.size else 0
        rec_i = recall_at(p_pos, thr_i)
        curve.append((fpr, thr_i, rec_i, fp_neg, fp_real))
        log("  FPR<=%-6s 阈值=%.4f -> 召回 %5.2f%% | 测试负误报 %d | 真实流量误报 %d"
            % (fpr, thr_i, 100.0 * rec_i, fp_neg, fp_real))

    usable = [c for c in curve if c[0] <= args.max_fpr + 1e-12]
    fpr_used, thr, rec, fp_neg, fp_real = usable[-1] if usable else curve[0]
    log("采用(max_fpr=%s): 阈值=%.4f | 召回 %.2f%% | 测试负误报 %d/%d | 真实流量误报 %d"
        % (args.max_fpr, thr, 100.0 * rec, fp_neg, len(p_neg), fp_real))
    if rec == 0.0:
        log("  ⚠ 该档下召回为 0 —— 正常集里仍有与恶意同形的样本, 需回看样本构造")

    by_cat = collections.defaultdict(lambda: [0, 0])
    for (_l, host, cat), prob in zip(test_pos, p_pos):
        by_cat[cat][1] += 1
        if prob >= thr:
            by_cat[cat][0] += 1
    log("")
    log("分类别召回: " + " | ".join(
        "%s %d/%d (%.1f%%)" % (k, v[0], v[1], 100.0 * v[0] / max(1, v[1]))
        for k, v in sorted(by_cat.items(), key=lambda kv: -kv[1][1])))

    auc = roc_auc_score(np.r_[np.zeros(len(p_neg)), np.ones(len(p_pos))],
                        np.r_[p_neg, p_pos])
    log("测试集 AUC: %.4f" % auc)

    base = None
    if os.path.exists(BASELINE):
        try:
            bmodel = DomainURLModel(BASELINE, threshold=None, confidence=0.9)
            bmodel.load(verbose=False)
            if bmodel.available:
                b_pos = np.asarray(bmodel.proba_batch([h for _l, h, _c in test_pos]), dtype=float)
                b_neg = np.asarray(bmodel.proba_batch([h for _l, h, _c in test_neg]), dtype=float)
                b_thr = threshold_for(np.sort(b_neg), args.max_fpr)
                b_auc = roc_auc_score(np.r_[np.zeros(len(b_neg)), np.ones(len(b_pos))],
                                      np.r_[b_neg, b_pos])
                base = {"auc": round(float(b_auc), 5), "threshold": b_thr,
                        "recall": round(recall_at(b_pos, b_thr), 5),
                        "fp_neg": int((b_neg >= b_thr).sum()),
                        "own_threshold": bmodel.threshold}
                log("baseline（现网 domain_model.pkl）: AUC %.4f | 同 FPR 口径阈值 %.4f | 召回 %.2f%% | 误报 %d"
                    % (b_auc, b_thr, 100.0 * base["recall"], base["fp_neg"]))
        except Exception as exc:
            log("baseline 评测失败(忽略): %s" % exc)

    engine_rec = or_rec = None
    try:
        from analyzer import URLAnalyzer
        cfg = json.load(open(os.path.join(BASE, "config.json"), encoding="utf-8"))["detection"]
        ana = URLAnalyzer(cfg)
        eng_hit = np.array([bool(ana.analyze("https://" + h, use_api=False).get("is_malicious"))
                            for _l, h, _c in test_pos])
        engine_rec = float(eng_hit.mean())
        or_rec = float(np.logical_or(eng_hit, p_pos >= thr).mean())
        log("引擎(启发式)召回 %.2f%% → 与本模型 OR 后 %.2f%%（净增 %+.2f pt）"
            % (100.0 * engine_rec, 100.0 * or_rec, 100.0 * (or_rec - engine_rec)))
    except Exception as exc:
        log("引擎对比失败(忽略): %s" % exc)

    out = args.out if os.path.isabs(args.out) else os.path.join(BASE, args.out)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    meta = {
        "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "train": len(train), "val": len(val), "pos": len(pos), "neg": len(neg),
        "pos_by_cat": used_cats, "neg_dropped_adult": dropped_adult,
        "auc_val": round(float(auc_val), 5), "auc_test": round(float(auc), 5),
        "threshold": thr, "max_fpr": args.max_fpr, "recall": round(float(rec), 5),
        "fp_test_neg": fp_neg, "fp_realtraffic": fp_real,
        "platt": {"a": a, "b": b},
        "by_cat": {k: {"hit": v[0], "total": v[1]} for k, v in by_cat.items()},
        "engine_recall": round(engine_rec, 5) if engine_rec is not None else None,
        "or_recall": round(or_rec, 5) if or_rec is not None else None,
        "baseline": base,
    }
    with open(out, "wb") as fp:
        pickle.dump({"kind": "domain-model", "ngram_range": (2, args.ngram_max),
                     "vectorizer": vec,
                     "struct": {"mean": mean.tolist(), "scale": scale.tolist()},
                     "classifier": clf, "threshold": thr, "confidence": 0.9,
                     "platt": {"a": a, "b": b},
                     "meta": meta}, fp)
    log("")
    log("模型已保存: %s（%.2f MB）"
        % (os.path.relpath(out, BASE), os.path.getsize(out) / 1048576))

    os.makedirs(METRICS, exist_ok=True)
    mp = os.path.join(METRICS, "domain-v2-%s.json" % time.strftime("%Y%m%d-%H%M%S"))
    with open(mp, "w", encoding="utf-8") as fp:
        json.dump(meta, fp, ensure_ascii=False, indent=2)
    log("指标已存档: %s" % os.path.relpath(mp, BASE))
    log("（现网模型未改动 —— 达标后再决定是否替换 data/models/domain_model.pkl）")
    return 0


if __name__ == "__main__":
    sys.exit(main())

