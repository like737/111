# coding:utf-8
"""Phase 0: 构建"域名级"训练/评测数据集(正=恶意域名, 负=正常域名)

红线遵守
  - **按"注册域"切分**训练/测试: 同一注册域绝不跨集 → 杜绝数据泄漏;
  - 训练正样本不含测试域(测试集只用于选阈值与评估);
  - **标签噪声清洗**: 共享托管平台 / 可信域名 / 已知非恶意条目(如 free-counter 家族)
    从正样本剔除, 并作为"难负样本"加入负样本(教模型它们不是恶意);
  - 不使用任何"页面内容"特征(只用 hostname 字符串本身)。

输出(ml_training/data/)
  domain_train.tsv        label<TAB>host<TAB>category    (1=恶意, 0=正常)
  domain_test_pos.tsv / domain_test_neg.tsv / domain_realtraffic.tsv

用法
  python ml_training/build_domain_dataset.py --download      # 自动下载 Tranco(失败回退 Umbrella)
  python ml_training/build_domain_dataset.py --tranco <zip>  # 用本地 top-1M 压缩包
"""

import argparse
import csv
import io
import json
import os
import random
import sys
import urllib.request
import zipfile

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # eyilianjie/
sys.path.insert(0, BASE)
os.chdir(BASE)
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

from utils import (get_registered_domain, TRUSTED_DOMAINS, TRUSTED_SUFFIXES, extract_url_features,
                   match_adult_keywords)
from import_adult_blocklist import SHARED_PLATFORM, KNOWN_LEGIT

OUT_DIR = os.path.join(BASE, 'ml_training', 'data')
BLACKLIST = os.path.join(BASE, 'data', 'blacklist.json')
DETECTION_LOG = os.path.join(BASE, 'detection_log.json')
TRANCO_URL = 'https://tranco-list.eu/top-1m.csv.zip'
UMBRELLA_URL = 'https://s3-us-west-1.amazonaws.com/umbrella-static/top-1m.csv.zip'

# 黑名单里的"非恶意/误报"噪声(实测出现过): 从正样本剔除, 并进难负样本
NOISE_PATTERNS = ('free-counter', 'freecounters', 'counter.de', 'statcounter', 'histats',
                  'sitemeter', 'quantserve', 'scorecardresearch')
# 现实中最容易被误判的"敏感词子域"(难负样本用)
SENSITIVE_LABELS = ('login', 'secure', 'account', 'verify', 'update', 'signin', 'wallet',
                    'support', 'pay', 'mail', 'auth', 'portal', 'my', 'id')
# 合法站点的常见子域前缀(用于消除"有子域=恶意"这种构造性捷径)
SUB_PREFIXES = ('www', 'mail', 'api', 'cdn', 'app', 'm', 'blog', 'shop', 'support', 'docs',
                'static', 'img', 'video', 'news', 'en', 'cn', 'jp', 'cdn2')


def log(msg):
    print(msg, flush=True)


def host_of(entry):
    """把黑名单条目(可能是 URL 或裸域名)规范成 hostname"""
    try:
        f = extract_url_features(str(entry).strip())
        host = (f.get('hostname') or '').strip().lower().strip('.')
    except Exception:
        host = ''
    if not host or '.' not in host or host.replace('.', '').isdigit() or ' ' in host:
        return ''
    if host.startswith('www.'):
        host = host[4:]
    return host


def is_trusted(host):
    labels = host.split('.')
    if any('.'.join(labels[i:]) in TRUSTED_DOMAINS for i in range(len(labels) - 1)):
        return True
    return any(host == s or host.endswith('.' + s) for s in TRUSTED_SUFFIXES)


def is_shared_platform(host):
    return any(host == p or host.endswith('.' + p) for p in SHARED_PLATFORM)


def is_noise(host):
    return any(p in host for p in NOISE_PATTERNS)


def reg_of(host):
    """注册域(用于切分, 防止同一站点跨训练/测试)"""
    try:
        reg = get_registered_domain(host)
    except Exception:
        reg = None
    return (reg or '.'.join(host.split('.')[-2:])).lower()


def read_top_list(zip_path, limit=0):
    """从 top-1M 压缩包读域名(CSV: rank,domain); limit=0 表示读全量"""
    domains = []
    with zipfile.ZipFile(zip_path) as z:
        name = z.namelist()[0]
        with z.open(name) as fh:
            text = io.TextIOWrapper(fh, encoding='utf-8', errors='ignore')
            for row in csv.reader(text):
                if not row:
                    continue
                dom = row[-1].strip().lower()
                if dom and '.' in dom:
                    domains.append(dom)
                if limit and len(domains) >= limit:
                    break
    return domains


def write_tsv(path, rows):
    with open(path, 'w', encoding='utf-8', newline='') as f:
        for label, host, cat in rows:
            f.write('%d\t%s\t%s\n' % (label, host, cat))


def main():
    ap = argparse.ArgumentParser(description='Phase 0: 构建域名级数据集')
    ap.add_argument('--tranco', default='', help='本地 top-1M(csv.zip)路径')
    ap.add_argument('--download', action='store_true', help='先尝试下载 Tranco/Umbrella')
    ap.add_argument('--neg-limit', type=int, default=150000, help='负样本(裸注册域)上限')
    ap.add_argument('--long-neg', type=int, default=20000, help='额外加入的"最长域名"负样本数')
    ap.add_argument('--puny-neg', type=int, default=20000, help='额外加入的 punycode 负样本数')
    ap.add_argument('--pos-per-cat', type=int, default=60000, help='每类正样本上限(避免色情类主导)')
    ap.add_argument('--test-ratio', type=float, default=0.2, help='测试集比例(按注册域切分)')
    ap.add_argument('--seed', type=int, default=42)
    args = ap.parse_args()
    rng = random.Random(args.seed)
    os.makedirs(OUT_DIR, exist_ok=True)

    # ---------- 1) 正样本: eyilianjie 黑名单(清洗噪声) ----------
    with open(BLACKLIST, encoding='utf-8') as f:
        entries = json.load(f).get('entries', {})
    pos, dropped = {}, {'trusted': 0, 'shared': 0, 'noise': 0, 'invalid': 0}
    for key, cat in entries.items():
        host = host_of(key)
        if not host:
            dropped['invalid'] += 1
            continue
        if is_trusted(host):
            dropped['trusted'] += 1
            continue
        if is_shared_platform(host):
            dropped['shared'] += 1
            continue
        if is_noise(host):
            dropped['noise'] += 1
            continue
        pos.setdefault(host, cat)
    log('正样本(黑名单清洗后): %d 个唯一 host | 剔除统计: %s' % (len(pos), dropped))

    # 类别均衡: 色情类占 96%, 下采样到 pos_per_cat, 避免单一类别主导特征学习
    if args.pos_per_cat:
        by_cat = {}
        for h, c in pos.items():
            by_cat.setdefault(c, []).append(h)
        kept = {}
        for c, hosts in by_cat.items():
            for h in (rng.sample(hosts, args.pos_per_cat) if len(hosts) > args.pos_per_cat else hosts):
                kept[h] = c
        log('正样本类别均衡: %s -> %d'
            % ({k: len(v) for k, v in sorted(by_cat.items(), key=lambda x: -len(x[1]))}, len(kept)))
        pos = kept

    # ---------- 2) 负样本: top-1M 正常域名 ----------
    zip_path = args.tranco
    if not zip_path and args.download:
        for url in (TRANCO_URL, UMBRELLA_URL):
            try:
                req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
                data = urllib.request.urlopen(req, timeout=120).read()
                zip_path = os.path.join(OUT_DIR, os.path.basename(url))
                with open(zip_path, 'wb') as f:
                    f.write(data)
                log('已下载: %s (%.2f MB)' % (zip_path, len(data) / 1048576))
                break
            except Exception as e:
                log('下载失败 %s: %s' % (url, e))
    if not zip_path:
        import tempfile
        for cand in ('tranco.csv.zip', 'umbrella.csv.zip'):
            p = os.path.join(tempfile.gettempdir(), cand)
            if os.path.exists(p):
                zip_path = p
                break
    if not zip_path or not os.path.exists(zip_path):
        log('未找到 top-1M 清单; 请用 --tranco 指定, 或加 --download 自动下载')
        return 1
    neg = {}
    all_domains = [d for d in read_top_list(zip_path) if d]
    log('top-1M 全量: %d 条' % len(all_domains))

    dropped_adult = []

    def is_adult_or_gambling(value):
        """强命中成人/赌博词 → 它不是"正常域名"（Tranco 里确实收录了不少成人/赌博站,
        把它们当负样本会让"误报率"被高估, 也会教模型把成人词当正常特征)"""
        try:
            hits = match_adult_keywords(value or '')
        except Exception:
            return False
        strong = (list(hits.get('domain_strong') or []) + list(hits.get('adult_brands') or [])
                  + list(hits.get('gambling') or []))
        return bool(strong)

    def add_neg(host):
        host = host_of(host)
        if host and host not in pos:
            if is_adult_or_gambling(host):
                dropped_adult.append(host)
                return
            neg.setdefault(host, 'normal')

    # (a) 裸注册域: 在全量 1M 中随机抽样(不再只取前 N 名, 避免分布偏"热门短域名")
    for d in rng.sample(all_domains, min(args.neg_limit, len(all_domains))):
        add_neg(d)
    bare_cnt = len(neg)

    # (b) 合法子域: 消除"有子域=恶意"的构造性捷径
    for d in rng.sample(all_domains, min(30000, len(all_domains))):
        add_neg('%s.%s' % (rng.choice(SUB_PREFIXES), d))
    sub_cnt = len(neg) - bare_cnt

    # (c) 长域名: 覆盖"长=恶意"这一偏置(取全量里最长的 N 个)
    for d in sorted(all_domains, key=len, reverse=True)[:args.long_neg]:
        add_neg(d)
    long_cnt = len(neg) - bare_cnt - sub_cnt

    # (d) punycode(国际化)合法站: 修复"punycode=恶意"的误报(实测最严重的一类)
    puny = [d for d in all_domains if 'xn--' in d]
    for d in rng.sample(puny, min(args.puny_neg, len(puny))) if puny else []:
        add_neg(d)
    puny_cnt = len(neg) - bare_cnt - sub_cnt - long_cnt
    log('负样本构成: 裸域 %d | 合法子域 %d | 长域名 %d | punycode %d (去重后合计 %d)'
        % (bare_cnt, sub_cnt, long_cnt, puny_cnt, len(neg)))
    log('负样本(top-1M, 与正样本去重后): %d 个唯一 host' % len(neg))

    # ---------- 3) 难负样本(仅训练): 敏感词子域 + 共享平台子域 ----------
    hard = {}
    for h in rng.sample(sorted(neg), min(1200, len(neg))):
        hard['%s.%s' % (rng.choice(SENSITIVE_LABELS), h)] = 'hard_negative'
    for h in ('myapp.workers.dev', 'demo.github.io', 'site.netlify.app', 'blog.blogspot.com',
              'files.wordpress.com', 'static.weebly.com', 'preview.vercel.app'):
        hard[h] = 'hard_negative'
    log('难负样本(仅加入训练集): %d' % len(hard))

    # ---------- 4) 真实流量(仅评测) ----------
    real = {}
    try:
        for item in json.load(open(DETECTION_LOG, encoding='utf-8')):
            if item.get('is_malicious'):
                continue
            h = host_of(item.get('url') or item.get('domain') or '')
            if h:
                real.setdefault(h, 'realtraffic')
    except Exception as e:
        log('读取 detection_log 失败: %s' % e)
    log('真实流量(安全记录, 仅评测): %d 个唯一 host' % len(real))

    # ---------- 5) 按注册域切分(防泄漏) ----------
    def split(host_map, label):
        """按注册域切分; label: 1=恶意(正样本), 0=正常(负样本)

        注意: 这里必须显式传入 label —— 之前版本把它硬编码成 1,
        导致负样本标签错误(模型会学成"几乎所有域名都是恶意")。
        """
        regs = sorted({reg_of(h) for h in host_map})
        cut = int(len(regs) * (1 - args.test_ratio))
        train_regs = set(regs[:cut])
        a = [(label, h, c) for h, c in host_map.items() if reg_of(h) in train_regs]
        b = [(label, h, c) for h, c in host_map.items() if reg_of(h) not in train_regs]
        return a, b, train_regs, set(regs) - train_regs

    pos_tr, pos_te, pos_train_regs, pos_test_regs = split(pos, 1)
    neg_tr, neg_te, neg_train_regs, neg_test_regs = split(neg, 0)
    # 难负样本: 其注册域不得落在"测试正样本域"(否则等于教模型把恶意域当正常)
    hard_rows = [(0, h, c) for h, c in hard.items()
                 if reg_of(h) not in pos_test_regs and reg_of(h) not in neg_test_regs]
    neg_tr += hard_rows

    leak = (pos_train_regs & pos_test_regs) | (neg_train_regs & neg_test_regs)
    log('\n=== 数据集 ===')
    log('  训练: 正 %d | 负 %d (含难负 %d)' % (len(pos_tr), len(neg_tr), len(hard_rows)))
    log('  测试: 正 %d (注册域 %d) | 负 %d (注册域 %d)'
        % (len(pos_te), len(pos_test_regs), len(neg_te), len(neg_test_regs)))
    log('  真实流量: %d' % len(real))
    log('  泄漏检查(训练∩测试 注册域): %d %s' % (len(leak), '✅ 干净' if not leak else '❌ 有重叠!'))

    write_tsv(os.path.join(OUT_DIR, 'domain_train.tsv'), pos_tr + neg_tr)
    write_tsv(os.path.join(OUT_DIR, 'domain_test_pos.tsv'), pos_te)
    write_tsv(os.path.join(OUT_DIR, 'domain_test_neg.tsv'), neg_te)
    write_tsv(os.path.join(OUT_DIR, 'domain_realtraffic.tsv'), [(0, h, c) for h, c in real.items()])
    with open(os.path.join(OUT_DIR, 'domain_meta.json'), 'w', encoding='utf-8') as f:
        json.dump({'source': os.path.basename(zip_path), 'test_ratio': args.test_ratio,
                   'seed': args.seed, 'pos': len(pos), 'neg': len(neg), 'dropped': dropped,
                'neg_dropped_adult': len(dropped_adult),
                   'split_leak': len(leak)}, f, ensure_ascii=False, indent=2)
    log('\n已写入 %s/' % os.path.relpath(OUT_DIR, BASE))
    return 0


if __name__ == '__main__':
    sys.exit(main())
