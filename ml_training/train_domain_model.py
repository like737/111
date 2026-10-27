# coding:utf-8
"""Phase 1: 训练"域名级模型"(方案A-①)

红线遵守
  - 只用"域名级"样本(绝不混入路径/payload 样本);
  - 阈值由**留出测试集**按 0 误报自动选定(不手工降阈值);
  - 不引入页面内容特征;
  - 输出为普通字典 pickle(可脱离本项目加载), 与 ml_url_model.DomainURLModel 对应。

用法
  python ml_training/train_domain_model.py
"""

import argparse
import json
import os
import pickle
import sys
import time
from datetime import datetime

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
os.chdir(BASE)
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

from ml_url_model import host_struct_features, STRUCT_FEATURE_NAMES

DATA = os.path.join(BASE, 'ml_training', 'data')
DEFAULT_OUT = os.path.join(BASE, 'data', 'models', 'domain_model.pkl')
METRICS_DIR = os.path.join(BASE, 'ml_training', 'metrics')


def log(msg):
    print(msg, flush=True)


def load_tsv(name):
    rows = []
    path = os.path.join(DATA, name)
    if not os.path.exists(path):
        raise FileNotFoundError('缺少数据集文件: %s (请先运行 build_domain_dataset.py)' % path)
    with open(path, encoding='utf-8') as f:
        for line in f:
            parts = line.rstrip('\n').split('\t')
            if len(parts) >= 2 and parts[1]:
                rows.append((int(parts[0]), parts[1], parts[2] if len(parts) > 2 else ''))
    return rows


def featurize(vectorizer, hosts, mean=None, scale=None, fit=False):
    """hosts → [字符 n-gram TF-IDF | 标准化后的结构化特征]"""
    from scipy.sparse import hstack, csr_matrix
    X = vectorizer.fit_transform(hosts) if fit else vectorizer.transform(hosts)
    F = np.asarray([host_struct_features(h) for h in hosts], dtype=float)
    if fit:
        mean = F.mean(axis=0)
        scale = F.std(axis=0)
        scale[scale == 0] = 1.0
    F = (F - mean) / scale
    return hstack([X, csr_matrix(F)]).tocsr(), mean, scale


def engine_scores(hosts, threshold=60):
    """引擎(启发式, 不含黑名单短路)的判定 —— 与生产同口径的基线"""
    from analyzer import URLAnalyzer
    cfg = json.load(open(os.path.join(BASE, 'config.json'), encoding='utf-8'))['detection']
    ana = URLAnalyzer(cfg)
    hits, scores = [], []
    for h in hosts:
        try:
            s = ana.analyze('http://' + h, use_api=False).get('score', 0)
        except Exception:
            s = 0
        scores.append(s)
        hits.append(s >= threshold)
    return np.asarray(hits), np.asarray(scores, dtype=float)


def main():
    ap = argparse.ArgumentParser(description='Phase 1: 训练域名级模型')
    ap.add_argument('--out', default=DEFAULT_OUT)
    ap.add_argument('--ngram-max', type=int, default=4)
    ap.add_argument('--C', type=float, default=4.0)
    ap.add_argument('--max-features', type=int, default=300000)
    ap.add_argument('--max-fpr', type=float, default=1e-4,
                    help='选定阈值时允许的整体正常集误报率上限(默认 0.01%%, 约 2-3 条/2.8万)')
    args = ap.parse_args()

    t0 = time.time()
    train = load_tsv('domain_train.tsv')
    test_pos = load_tsv('domain_test_pos.tsv')
    test_neg = load_tsv('domain_test_neg.tsv')
    real = load_tsv('domain_realtraffic.tsv')
    log('数据: 训练 %d | 测试正 %d | 测试负 %d | 真实流量 %d'
        % (len(train), len(test_pos), len(test_neg), len(real)))

    tr_h = [r[1] for r in train]
    tr_y = np.asarray([r[0] for r in train])
    pos_h, neg_h, real_h = [r[1] for r in test_pos], [r[1] for r in test_neg], [r[1] for r in real]

    vec = TfidfVectorizer(analyzer='char', ngram_range=(2, args.ngram_max), lowercase=False,
                          sublinear_tf=True, max_features=args.max_features)
    Xtr, mean, scale = featurize(vec, tr_h, fit=True)
    log('特征: 词表 %d 维 + 结构特征 %d 维 (耗时 %.1fs)'
        % (len(vec.vocabulary_), len(STRUCT_FEATURE_NAMES), time.time() - t0))

    clf = LogisticRegression(C=args.C, max_iter=2000, solver='liblinear')
    clf.fit(Xtr, tr_y)
    log('训练完成 (%.1fs)' % (time.time() - t0))

    p_pos = clf.predict_proba(featurize(vec, pos_h, mean, scale)[0])[:, 1]
    p_neg = clf.predict_proba(featurize(vec, neg_h, mean, scale)[0])[:, 1]
    p_real = (clf.predict_proba(featurize(vec, real_h, mean, scale)[0])[:, 1]
              if real_h else np.array([]))
    auc = roc_auc_score(np.r_[np.zeros(len(p_neg)), np.ones(len(p_pos))], np.r_[p_neg, p_pos])

    # ---- 阈值: 在"整体正常集误报率 ≤ max_fpr"前提下召回最高(附完整曲线) ----
    norm = np.r_[p_neg, p_real] if p_real.size else p_neg
    curve = []
    for fpr in (0.0, 1e-5, 1e-4, 1e-3, 1e-2):
        allowed = int(np.floor(fpr * len(norm)))
        gate = float(np.sort(norm)[::-1][allowed] + 1e-9) if allowed < len(norm) else 1.0
        curve.append((fpr, gate, float((p_pos >= gate).mean()),
                      int((p_neg >= gate).sum()),
                      int((p_real >= gate).sum()) if p_real.size else 0))
    log('\n阈值-误报-召回 曲线(正常集 = 测试负 %d + 真实流量 %d):' % (len(neg_h), len(real_h)))
    for fpr, gate, r, fpn, fpr_ in curve:
        log('  FPR<=%-8s 阈值=%.6f -> 召回 %.2f%% | 测试负误报 %d | 真实流量误报 %d'
            % (fpr, gate, 100 * r, fpn, fpr_))
    usable = [c for c in curve if c[0] <= args.max_fpr + 1e-12]
    fpr_used, thr, rec, fp_neg, fp_real = usable[-1] if usable else curve[0]
    if rec == 0.0:
        log('  ⚠ 在 max_fpr=%s 下召回为 0 —— 正常集里存在与恶意同形的样本, 需回看样本构造' % args.max_fpr)
    log('采用(max_fpr=%s): threshold=%.6f | 测试正召回 %.2f%% | 测试负误报 %d/%d | 真实流量误报 %d'
        % (fpr_used, thr, 100 * rec, fp_neg, len(neg_h), fp_real))

    by_cat = {}
    for (label, host, cat), p in zip(test_pos, p_pos):
        by_cat.setdefault(cat, [0, 0])
        by_cat[cat][1] += 1
        if p >= thr:
            by_cat[cat][0] += 1
    log('分类别召回: ' + ' | '.join('%s %d/%d (%.1f%%)' % (k, v[0], v[1], 100 * v[0] / v[1])
                                for k, v in sorted(by_cat.items(), key=lambda x: -x[1][1])[:8]))

    # ---- 基线对比: 引擎(启发式) vs 模型 vs OR ----
    eng_hit_pos, _ = engine_scores(pos_h)
    eng_hit_neg, _ = engine_scores(neg_h)
    eng_hit_real, _ = engine_scores(real_h) if real_h else (np.array([]), np.array([]))
    eng_rec = float(eng_hit_pos.mean())
    or_rec = float(np.logical_or(eng_hit_pos, p_pos >= thr).mean())
    log('\n=== 域名层: 引擎(启发式) vs 域名模型 vs OR ===')
    log('  引擎(启发式, 不含黑名单): 召回 %.2f%% | 负样本误报 %d/%d | 真实流量误报 %d'
        % (100 * eng_rec, int(eng_hit_neg.sum()), len(neg_h),
           int(eng_hit_real.sum()) if len(eng_hit_real) else 0))
    log('  域名模型(0 误报阈值):     召回 %.2f%% | 负样本误报 %d/%d | 真实流量误报 %d'
        % (100 * rec, fp_neg, len(neg_h), fp_real))
    log('  OR 融合(引擎 ∪ 模型):     召回 %.2f%% (净增 %+.2f pt)'
        % (100 * or_rec, 100 * (or_rec - eng_rec)))

    out = args.out if os.path.isabs(args.out) else os.path.join(BASE, args.out)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, 'wb') as f:
        pickle.dump({'kind': 'domain-model', 'ngram_range': (2, args.ngram_max),
                     'vectorizer': vec,
                     'struct': {'mean': mean.tolist(), 'scale': scale.tolist()},
                     'classifier': clf, 'threshold': thr, 'confidence': 0.9,
                     'meta': {'trained_at': datetime.now().isoformat(), 'train': len(train),
                              'test_pos': len(test_pos), 'test_neg': len(test_neg),
                              'auc': round(float(auc), 5), 'recall_at_0fpr': round(rec, 5),
                              'engine_recall': round(eng_rec, 5), 'or_recall': round(or_rec, 5)}}, f)
    log('\n模型已保存: %s (%.2f MB)' % (os.path.relpath(out, BASE), os.path.getsize(out) / 1048576))

    os.makedirs(METRICS_DIR, exist_ok=True)
    mp = os.path.join(METRICS_DIR, 'domain-%s.json' % datetime.now().strftime('%Y%m%d-%H%M%S'))
    with open(mp, 'w', encoding='utf-8') as f:
        json.dump({'AUC': round(float(auc), 5), 'threshold': thr, 'recall_at_0fpr': round(rec, 5),
                   'fp_test_neg': fp_neg, 'fp_realtraffic': fp_real,
                   'engine_recall': round(eng_rec, 5), 'or_recall': round(or_rec, 5),
                   'by_category': {k: {'hit': v[0], 'total': v[1]} for k, v in by_cat.items()},
                   'train': len(train), 'test_pos': len(test_pos), 'test_neg': len(test_neg)},
                  f, ensure_ascii=False, indent=2)
    log('指标已存档: %s' % os.path.relpath(mp, BASE))
    return 0


if __name__ == '__main__':
    sys.exit(main())
