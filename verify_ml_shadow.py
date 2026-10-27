# coding:utf-8
"""ML 检测通道回归验证(可反复运行, 不修改任何业务数据)

验证内容
  1) 关闭 ML(enable_ml_check=False) 与 影子模式(ml_mode=shadow) 的检测结果逐字段一致;
  2) AI(DeepSeek) 相关详情行完全不受影响, 且 ML 详情行不含 "DeepSeek" 字样(否则页面AI徽章会误判);
  3) 模型文件缺失/损坏时自动降级, 结果与"关闭 ML"完全一致;
  4) 黑名单短路优先级不受影响;
  5) enforce 模式行为边界: 分数 0-100 不变; 是否单独定罪由 ml_trigger_intercept 决定;
  6) 性能增量;
  7) (可选) 在 MaliciousURLs/data/eval 上给出 引擎/模型/OR 的召回与误报对比。

用法
    python verify_ml_shadow.py                # 默认: 模拟AI + 本地DNS (快, 不联网)
    python verify_ml_shadow.py --real-ai      # 额外做 1 次真实 DeepSeek 调用(需联网/额度)
    python verify_ml_shadow.py --eval-dir ..\\MaliciousURLs\\data\\eval   # 第7项对比

安全说明
    - 全程使用"模拟 AI 响应"与"本地 DNS", 不产生外部调用(除 --real-ai);
    - 检测日志被重定向到系统临时文件, 绝不写你的 detection_log.json;
    - 配置只改内存副本, 绝不写 config.json。
"""

import argparse
import copy
import os
import sys
import tempfile
import time

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)
os.chdir(BASE)
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')   # 避免 GBK 控制台打印 ✅/❌ 崩溃
except Exception:
    pass

import detector as D                      # noqa: E402
from config import Config                 # noqa: E402

ORIG_CHECK_API = D.Detector._check_with_api      # 保存原始 DeepSeek 调用(供 --real-ai)
NEUTRAL = 'http://example.com'
TMP = tempfile.gettempdir()

# ---------- 测试用 URL(覆盖各分支) ----------
TEST_URLS = [
    'https://www.baidu.com/s?wd=python',                     # 正常
    'https://github.com/torvalds/linux',                     # 正常
    'https://www.zhihu.com/question/123456789',              # 正常
    NEUTRAL + '/centreon/include/views/graphs/display.php?session_id=%27%20or%201=1',  # SQLi
    NEUTRAL + '/wp-content/plugins/../../../../etc/passwd',  # 路径穿越
    '/phpmyadmin/scripts/setup.php',                         # 扫描器
    'javascript:alert(1)',                                   # 伪协议
    'http://secure-login.faceb00k.tk/verify?acc=xxx',        # 域名层钓鱼
    'http://free-money.xyz/claim?prize=10000',               # 域名层诈骗
    'http://192.168.1.10/router/login.html',                 # 内网IP
]


def build_config(**overrides):
    """构造内存副本配置(不写 config.json)"""
    cfg = Config()
    for key, value in overrides.items():
        cfg._config['detection'][key] = value
    return cfg


def make_detector(cfg, tag):
    det = D.Detector(cfg)
    det.reporter.log_file = os.path.join(TMP, 'verify_ml_%s.json' % tag)   # 日志重定向
    return det


def snapshot(r):
    """取出用于一致性对比的字段(ML 详情行单列, 便于"去掉ML后是否一致")"""
    return {
        'score': r.score,
        'risk_level': r.risk_level,
        'is_malicious': r.is_malicious,
        'blacklist_match': r.blacklist_match,
        'domain': r.domain,
        'ai_lines': [d for d in r.details if ('DeepSeek' in str(d) or 'AI' in str(d))
                     and '[ML]' not in str(d)],
        'detail_count_wo_ml': len([d for d in r.details if '[ML]' not in str(d)]),
    }


def run_suite(det, urls):
    out, t0 = [], time.perf_counter()
    for u in urls:
        out.append(det.detect(u, use_api=True))
    return out, (time.perf_counter() - t0) / max(1, len(urls))


def main():
    ap = argparse.ArgumentParser(description='ML 检测通道回归验证')
    ap.add_argument('--real-ai', action='store_true', help='额外做 1 次真实 DeepSeek 调用')
    ap.add_argument('--eval-dir', default='', help='MaliciousURLs/data/eval 目录(第7项对比)')
    args = ap.parse_args()

    # ---- 本地化外部依赖: 不联网、结果确定 ----
    D.check_domain_resolves = lambda hostname, timeout=2.0: True
    # 模拟 AI 返回"未发现风险"(分数高=安全): 让最终判定由启发式引擎/ML 决定,
    # 这样才能观察到 enforce 模式下"ML 高置信"是否真的改变了结论。
    FAKE_AI = {'is_malicious': False, 'score': 90, 'risk_level': '安全',
               'reasons': ['模拟AI: 未发现明显风险'], 'source': 'DeepSeek AI'}
    D.Detector._check_with_api = lambda self, url: copy.deepcopy(FAKE_AI)

    print('=' * 80)
    print('ML 检测通道回归验证 (模拟AI + 本地DNS + 日志重定向; 不写任何业务数据)')
    print('=' * 80)

    det_off = make_detector(build_config(enable_ml_check=False), 'off')
    res_off, t_off = run_suite(det_off, TEST_URLS)
    print('\n[A] enable_ml_check=False  → 基线(等价于未接入 ML 时的行为)')

    det_sd = make_detector(build_config(enable_ml_check=True, ml_mode='shadow'), 'shadow')
    res_sd, t_sd = run_suite(det_sd, TEST_URLS)
    print('[B] enable_ml_check=True, ml_mode=shadow → 影子模式')

    # ---- 1) 逐字段一致性 ----
    diffs = []
    for u, a, b in zip(TEST_URLS, res_off, res_sd):
        sa, sb = snapshot(a), snapshot(b)
        for k in sa:
            if sa[k] != sb[k]:
                diffs.append((u, k, sa[k], sb[k]))
    print('\n1) 一致性检查(score / risk_level / is_malicious / 黑名单 / 域名 / AI行 / 非ML详情条数)')
    print('   差异条数: %d  %s' % (len(diffs), '✅ PASS' if not diffs else '❌ FAIL'))
    for d in diffs[:8]:
        print('     - %s: %s  基线=%s  影子=%s' % (d[0][:46], d[1], d[2], d[3]))

    # ---- 2) AI 行完整性 + ML 文案隔离 ----
    ai_ok = all(snapshot(a)['ai_lines'] == snapshot(b)['ai_lines']
                for a, b in zip(res_off, res_sd))
    ml_lines = [d for r in res_sd for d in r.details if '[ML]' in str(d)]
    ml_bad = [d for d in ml_lines if 'DeepSeek' in str(d)]
    print('\n2) AI 行完整性: %s | ML 详情行 %d 条, 其中含 "DeepSeek" 的: %d  %s'
          % ('✅ PASS' if ai_ok else '❌ FAIL', len(ml_lines), len(ml_bad),
             '✅ PASS' if not ml_bad else '❌ FAIL'))
    if ml_lines:
        print('   示例: %s' % ml_lines[0])

    # ---- 3) 模型缺失时的降级 ----
    broken_spec = {'domain': {'enabled': True, 'path': 'data/models/__no_domain__.pkl',
                              'confidence': 0.9, 'trigger_intercept': False},
                   'path': {'enabled': True, 'path': 'data/models/__no_path__.pkl',
                            'confidence': 0.9, 'trigger_intercept': True}}
    det_bad = make_detector(build_config(enable_ml_check=True, ml_mode='shadow',
                                         ml_models=broken_spec), 'broken')
    res_bad, _ = run_suite(det_bad, TEST_URLS)
    bad_same = all(snapshot(a) == snapshot(c) for a, c in zip(res_off, res_bad))
    # AI 行的正确断言: 与基线"逐条相同"(短路路径本来就没有 AI 行, 不能要求非空)
    ai_intact = all(snapshot(a)['ai_lines'] == snapshot(c)['ai_lines']
                    for a, c in zip(res_off, res_bad))
    n_ai = sum(1 for a in res_off if snapshot(a)['ai_lines'])
    print('\n3) 双模型都缺失时自动降级: 与基线逐字段一致 %s | AI 行与基线相同 %s '
          '(基线中 %d/%d 条调用过AI, 短路路径不调用属正常)'
          % ('✅ PASS' if bad_same else '❌ FAIL', '✅ PASS' if ai_intact else '❌ FAIL',
             n_ai, len(TEST_URLS)))

    # ---- 3b) 只缺域名模型(路径模型仍在) ----
    half_spec = {'domain': {'enabled': True, 'path': 'data/models/__no_domain__.pkl',
                            'confidence': 0.9, 'trigger_intercept': False},
                 'path': {'enabled': True, 'path': 'data/models/path_model.pkl',
                          'confidence': 0.9, 'trigger_intercept': True}}
    det_half = make_detector(build_config(enable_ml_check=True, ml_mode='enforce',
                                          ml_models=half_spec), 'halfbroken')
    res_half, _ = run_suite(det_half, TEST_URLS)
    half_ok = all(c.ml_prob is not None or c.blacklist_match or not c.url.startswith('http')
                  for c in res_half)
    print('3b) 仅缺域名模型时: 路径模型仍工作 %s'
          % ('✅ PASS' if any(getattr(c, 'ml_path_prob', None) is not None for c in res_half)
             else '❌ FAIL'))

    # ---- 4) 黑名单短路优先级 ----
    import json as _json
    with open(os.path.join(BASE, 'data', 'blacklist.json'), encoding='utf-8') as f:
        bl = _json.load(f)
    bl_entries = bl.get('entries', bl)
    bl_url = next(iter(bl_entries))
    r_off = det_off.detect(bl_url, use_api=True)
    r_sd = det_sd.detect(bl_url, use_api=True)
    ok4 = (r_off.score == r_sd.score and r_off.is_malicious == r_sd.is_malicious
           and r_sd.blacklist_match)
    print('\n4) 黑名单短路优先级: %s (样例 "%s" → 分数 %s/%s, 黑名单命中=%s)'
          % ('✅ PASS' if ok4 else '❌ FAIL', bl_url[:40], r_off.score, r_sd.score,
             r_sd.blacklist_match))

    # ---- 5) enforce 模式行为边界 ----
    det_en = make_detector(build_config(enable_ml_check=True, ml_mode='enforce',
                                        ml_trigger_intercept=False), 'enforce')
    res_en, _ = run_suite(det_en, TEST_URLS)
    det_en2 = make_detector(build_config(enable_ml_check=True, ml_mode='enforce',
                                         ml_trigger_intercept=True), 'enforce_i')
    res_en2, _ = run_suite(det_en2, TEST_URLS)
    score_same = all(a.score == b.score == c.score
                     for a, b, c in zip(res_off, res_en, res_en2))
    ai_same = all(snapshot(a)['ai_lines'] == snapshot(b)['ai_lines'] == snapshot(c)['ai_lines']
                  for a, b, c in zip(res_off, res_en, res_en2))
    flip_no = sum(1 for a, b in zip(res_off, res_en) if a.is_malicious != b.is_malicious)
    flip_yes = sum(1 for a, b in zip(res_off, res_en2) if a.is_malicious != b.is_malicious)
    lv_no = sum(1 for a, b in zip(res_off, res_en) if a.risk_level != b.risk_level)
    print('\n5) enforce 模式: 分数保持不变 %s | AI 行不变 %s'
          % ('✅ PASS' if score_same else '❌ FAIL', '✅ PASS' if ai_same else '❌ FAIL'))
    print('   ml_trigger_intercept=False → 判定(is_malicious)变化 %d 条, 等级变化 %d 条 '
          '(设计: 只提示不拦截)' % (flip_no, lv_no))
    print('   ml_trigger_intercept=True  → 判定(is_malicious)变化 %d 条 (设计: 高置信项被 ML 定罪)'
          % flip_yes)
    if flip_yes:
        print('   被 ML 单独定罪的样例:')
        for u, a, c in zip(TEST_URLS, res_off, res_en2):
            if a.is_malicious != c.is_malicious:
                ml_p = getattr(c, 'ml_prob', None)
                print('     - %-42s 引擎=%s → ML定罪=%s (ML概率 %s)'
                      % (u[:42], a.is_malicious, c.is_malicious, ml_p))

    # ---- 6) 性能 ----
    print('\n6) 性能: 单条 detect 基线 %.2f ms | 影子 %.2f ms | 增量 %+.2f ms'
          % (1000 * t_off, 1000 * t_sd, 1000 * (t_sd - t_off)))

    # ---- 7) 评测集对比(可选) ----
    if args.eval_dir and os.path.isdir(args.eval_dir):
        from ml_url_model import MLUrlModel
        from analyzer import URLAnalyzer
        ml = MLUrlModel('data/models/lgs_model.pickle', confidence=0.9)
        ml.load(verbose=False)
        det_cfg = dict(Config()._config['detection'])
        ana = URLAnalyzer(det_cfg)
        eng_thr = int(det_cfg.get('heuristic_threshold', 60) or 60)

        def rd(p, skip=True):
            if not os.path.exists(p):
                return []
            out = []
            with open(p, encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.rstrip('\r\n')
                    if line.strip() and not (skip and line.lstrip().startswith('#')):
                        out.append(line)
            return out

        sets = [('正常: 完整URL', rd(os.path.join(args.eval_dir, 'normal_urls.txt')), False, False),
                ('正常: 真实流量', rd(os.path.join(args.eval_dir, 'normal_urls_realtraffic.txt')), False, False),
                ('正常: 路径留出', rd(os.path.join(args.eval_dir, 'normal_paths_holdout.txt')), False, True),
                ('攻击: 路径留出', rd(os.path.join(args.eval_dir, 'attack_paths_holdout.txt')), True, True)]
        print('\n7) 评测集对比(引擎@%d vs 模型@%.2f vs OR 融合)' % (eng_thr, ml.threshold))
        print('   %-16s %6s %9s %9s %9s %9s' % ('集合', '条数', '引擎', '模型', '模型@0.9', 'OR'))
        agg_n, agg_a = [], []
        for name, docs, is_attack, prefix in sets:
            if not docs:
                continue
            d = [NEUTRAL + x for x in docs] if prefix else docs
            eng_hit = [ana.analyze(u, use_api=False).get('score', 0) >= eng_thr for u in d]
            probs = ml.predict_batch(d)
            m_hit = [p >= ml.threshold for p in probs]
            m_hi = [p >= 0.9 for p in probs]
            or_hit = [a or b for a, b in zip(eng_hit, m_hit)]
            print('   %-16s %6d %8.1f%% %8.1f%% %8.1f%% %8.1f%%'
                  % (name, len(d), 100 * sum(eng_hit) / len(d), 100 * sum(m_hit) / len(d),
                     100 * sum(m_hi) / len(d), 100 * sum(or_hit) / len(d)))
            (agg_a if is_attack else agg_n).extend(list(zip(eng_hit, m_hit, m_hi, or_hit)))
        if agg_n and agg_a:
            n_e = 100 * sum(x[0] for x in agg_n) / len(agg_n)
            n_o = 100 * sum(x[3] for x in agg_n) / len(agg_n)
            a_e = 100 * sum(x[0] for x in agg_a) / len(agg_a)
            a_o = 100 * sum(x[3] for x in agg_a) / len(agg_a)
            print('   汇总: 正常误报率 引擎 %.2f%% → OR %.2f%% (+%.2fpt) | 攻击召回率 引擎 %.2f%% → OR %.2f%% (+%.2fpt)'
                  % (n_e, n_o, n_o - n_e, a_e, a_o, a_o - a_e))
    else:
        print('\n7) 跳过评测集对比(未提供 --eval-dir)')

    # ---- 真实 AI 冒烟(可选) ----
    if args.real_ai:
        print('\n+ 真实 DeepSeek 冒烟测试(1 条)')
        D.Detector._check_with_api = ORIG_CHECK_API
        key = Config().get('api_keys', 'deepseek')
        print('   已配置密钥: %s' % ('是' if str(key or '').strip() else '否'))
        try:
            r = det_sd.detect('http://free-money.xyz/claim?prize=10000', use_api=True)
            print('   结果: score=%s risk=%s 恶意=%s' % (r.score, r.risk_level, r.is_malicious))
            print('   AI 行: %s' % [d for d in r.details if 'DeepSeek' in str(d)][:2])
        except Exception as e:
            print('   调用异常(不影响其它功能): %s' % e)

    print('\n' + '=' * 80)
    print('结论: 影子模式下第 1~4 项应全为 PASS —— 即"关闭开关 = 行为完全一致"且 AI 不受影响')
    print('=' * 80)


if __name__ == '__main__':
    main()
