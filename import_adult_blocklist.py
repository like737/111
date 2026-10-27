# coding:utf-8
"""方案A: 把公开的"成人站域名清单"清洗后导入 eyilianjie 黑名单

数据源(默认 StevenBlack porn-only hosts):
    https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts

特性
    - 清洗: 兼容 hosts 格式(0.0.0.0/127.0.0.1 前缀)、行内注释、重复项、上游脏数据
      (如 "0.0.0.0.creative.hpyrdr.com" 这类残留前缀会被还原, IP/本机名会被丢弃);
    - 安全过滤: 命中 TRUSTED_DOMAINS / edu·gov 等可信后缀的域名一律不导入,
      避免把合法站点整域封禁;
    - 幂等: 已在黑名单里的条目自动跳过;
    - 可回滚: 写入前自动备份 data/blacklist.json; 也可用 --remove 一键撤销;
    - 分类标记: 导入条目统一分类为「色情网站」, 便于事后批量识别与清理。

用法
    python import_adult_blocklist.py --dry-run              # 只统计, 不写文件(强烈建议先跑)
    python import_adult_blocklist.py                        # 真正导入(自动备份)
    python import_adult_blocklist.py --file porn-hosts.txt  # 用本地文件(离线)
    python import_adult_blocklist.py --limit 5000           # 只导入前 N 条(试水)
    python import_adult_blocklist.py --remove               # 回滚: 删除所有「色情网站」分类条目
"""

import argparse
import ipaddress
import json
import os
import re
import sys
import urllib.request
from datetime import datetime

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)
os.chdir(BASE)
try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

BLACKLIST_FILE = os.path.join(BASE, 'data', 'blacklist.json')
CATEGORY = '色情网站'
DEFAULT_SOURCE = ('https://raw.githubusercontent.com/StevenBlack/hosts/master/'
                  'alternates/porn/hosts')

# 明显不该封禁的本机/保留名
BAD_SUFFIX = ('.local', '.lan', '.home', '.internal', '.test', '.example',
              '.invalid', '.localhost', '.arpa')
BAD_EXACT = {'localhost', 'local', 'broadcast', 'ip6-localhost', 'ip6-loopback'}
# 共享托管/CDN 平台: 这类平台上"某个子域"是成人站, 但绝不能把整个平台封禁
SHARED_PLATFORM = (
    'amazonaws.com', 'cloudfront.net', 'azurewebsites.net', 'azureedge.net',
    'herokuapp.com', 'githubusercontent.com', 'github.io', 'gitlab.io',
    'blogspot.com', 'blogspotusercontent.com', 'wordpress.com', 'tumblr.com',
    'wixsite.com', 'weebly.com', 'glitch.me', 'repl.co', 'netlify.app',
    'vercel.app', 'pages.dev', 'workers.dev', 'firebaseapp.com',
    'akamaized.net', 'akamaihd.net', 'fastly.net', 'jsdelivr.net', 'unpkg.com',
    'googleapis.com', 'cloudflare.com', 'r2.dev', 'ngrok.io', 'ts.net',
    'github.com', 'gitlab.com', 'bitbucket.org', 'sourceforge.net',
)
# 明确属于"合法站点"的域名(即便出现在清单里也不导入; 含历史已知误报)
KNOWN_LEGIT = {
    # 社交/内容平台
    'reddit.com', 'twitter.com', 'x.com', 'discord.com', 'discord.gg', 'imgur.com',
    'imgur.io', 'twitch.tv', 'tiktok.com', 'telegram.org', 'patreon.com',
    'pinterest.com', 'facebook.com', 'instagram.com', 'youtube.com', 'google.com',
    'microsoft.com', 'apple.com', 'amazon.com', 'netflix.com', 'spotify.com',
    'wikipedia.org', 'wikimedia.org', 'stackoverflow.com', 'medium.com',
    'tumblr.com', 'flickr.com', 'vimeo.com', 'deviantart.com', 'artstation.com',
    'quora.com', 'linkedin.com', 'vk.com', 'dailymotion.com', 'soundcloud.com',
    'bandcamp.com', 'last.fm', 'giphy.com', 'tenor.com', 'photobucket.com',
    'postimg.cc', 'imgbb.com', 'mastodon.social', 'wordpress.org', 'archive.org',
    'creativecommons.org', 'example.com', 'example.org', 'example.net',
    # 常见商业/工具站
    'wix.com', 'shopify.com', 'canva.com', 'etsy.com', 'ebay.com', 'yelp.com',
    'tripadvisor.com', 'booking.com', 'dropbox.com', 'box.com', 'wetransfer.com',
    'notion.so', 'slack.com', 'zoom.us', 'whatsapp.com', 'signal.org',
    'mail.ru', 'yandex.ru', 'naver.com', 'line.me', 'kakao.com',
}
# 域名合法性: 至少两段, 每段由字母数字与连字符组成
DOMAIN_RE = re.compile(r'^(?=.{4,253}$)([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$')


def is_ip(token: str) -> bool:
    try:
        ipaddress.ip_address(token)
        return True
    except ValueError:
        return False


def normalize(token: str) -> str:
    """把一行内容规范成"纯域名"; 不合法返回空字符串"""
    token = token.strip().lower().strip('.')
    if not token or is_ip(token):
        return ''
    # 上游脏数据: 形如 "0.0.0.0.xxx.com" / "0.xxx.com" 的残留 IP 前缀 → 还原真实域名
    token = re.sub(r'^(?:\d{1,3}\.){3}\d{1,3}\.', '', token)
    if re.match(r'^0(?:\.0)*\.[a-z0-9]', token):          # 残留的前导 0. / 0.0. 标签
        candidate = re.sub(r'^(?:0\.)+', '', token)
        if DOMAIN_RE.match(candidate):
            token = candidate
    if token.startswith('www.'):
        token = token[4:]
    if not token or token in BAD_EXACT or token.endswith(BAD_SUFFIX):
        return ''
    if not DOMAIN_RE.match(token):
        return ''
    return token


def parse_hosts_text(text: str):
    """从 hosts 文件内容里提取域名(逐行: 取最后一个非注释字段)"""
    domains, dropped = set(), 0
    for raw in text.splitlines():
        line = raw.split('#', 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if not parts:
            continue
        dom = normalize(parts[-1])          # hosts 行: "0.0.0.0 domain" / "domain"
        if dom:
            domains.add(dom)
        else:
            dropped += 1
    return domains, dropped


def safety_filter(domains):
    """安全过滤: 可信域名单 / 共享托管平台 / 已知合法站 一律不导入

    注意: **不用"你日志里的安全域名"当白名单** —— `pornvideotop.com` 这类站
    正是因为旧版漏报才被记成"安全"的, 用它做白名单会把目标站一起放过。

    返回 (保留集合, 各原因被剔除集合的字典)
    """
    from utils import TRUSTED_DOMAINS, TRUSTED_SUFFIXES
    keep = set()
    reasons = {'trusted': set(), 'shared_platform': set(), 'known_legit': set()}
    for d in domains:
        labels = d.split('.')
        reg = '.'.join(labels[-2:])
        if any('.'.join(labels[i:]) in TRUSTED_DOMAINS for i in range(len(labels) - 1)) \
                or any(d == s or d.endswith('.' + s) for s in TRUSTED_SUFFIXES):
            reasons['trusted'].add(d)
            continue
        if any(d == p or d.endswith('.' + p) for p in SHARED_PLATFORM):
            reasons['shared_platform'].add(d)
            continue
        if reg in KNOWN_LEGIT or d in KNOWN_LEGIT:
            reasons['known_legit'].add(d)
            continue
        keep.add(d)
    return keep, reasons


# 校验: 这些域名(常用合法站 + 你日志里出现过的非成人站)绝不能被封禁
MUST_NOT_BLOCK = [
    'google.com', 'youtube.com', 'github.com', 'stackoverflow.com', 'wikipedia.org',
    'reddit.com', 'twitter.com', 'x.com', 'discord.com', 'twitch.tv', 'tiktok.com',
    'facebook.com', 'instagram.com', 'apple.com', 'microsoft.com', 'amazon.com',
    'netflix.com', 'spotify.com', 'medium.com', 'tumblr.com', 'pinterest.com',
    'quora.com', 'telegram.org', 'patreon.com', 'imgur.com', 'deviantart.com',
    'baidu.com', 'douyin.com', 'bilibili.com', 'zhihu.com', 'taobao.com', 'jd.com',
    'qq.com', 'weibo.com', 'metaso.cn', 'hltv.org', 'deepseek.com', 'examcrafts.com',
    'example.com', 'python.org', 'pypi.org', 'mozilla.org', 'apache.org', 'k8s.io',
]


def load_blacklist():
    with open(BLACKLIST_FILE, 'r', encoding='utf-8') as f:
        return json.load(f)


def save_blacklist(data):
    data['total'] = len(data.get('entries', {}))
    data['updated_at'] = datetime.now().isoformat()
    if os.path.exists(BLACKLIST_FILE):
        backup = os.path.join(
            BASE, 'data',
            'blacklist.backup-%s.json' % datetime.now().strftime('%Y%m%d-%H%M%S'))
        with open(BLACKLIST_FILE, 'r', encoding='utf-8') as src, \
                open(backup, 'w', encoding='utf-8') as dst:
            dst.write(src.read())
        print('[备份] 原黑名单已备份: %s (%.2f MB)'
              % (os.path.relpath(backup, BASE), os.path.getsize(backup) / 1024 / 1024))
    with open(BLACKLIST_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def main():
    ap = argparse.ArgumentParser(description='成人站清单 → 黑名单导入(方案A)')
    ap.add_argument('--source', default=DEFAULT_SOURCE, help='清单URL')
    ap.add_argument('--file', default='', help='本地清单文件(离线模式)')
    ap.add_argument('--limit', type=int, default=0, help='最多导入 N 条(0=不限)')
    ap.add_argument('--dry-run', action='store_true', help='只统计不写入')
    ap.add_argument('--remove', action='store_true',
                    help='回滚: 删除所有「%s」分类条目' % CATEGORY)
    args = ap.parse_args()

    data = load_blacklist()
    entries = data.get('entries', {})

    if args.remove:
        victims = [k for k, v in entries.items() if v == CATEGORY]
        print('准备删除「%s」分类条目: %d 条' % (CATEGORY, len(victims)))
        if args.dry_run:
            print('(dry-run, 未写入)')
            return
        for k in victims:
            entries.pop(k, None)
        save_blacklist(data)
        print('已删除; 黑名单现有 %d 条' % len(entries))
        return

    # ---------- 读取清单 ----------
    if args.file:
        with open(args.file, 'r', encoding='utf-8', errors='ignore') as f:
            text = f.read()
    else:
        print('下载清单: %s' % args.source)
        req = urllib.request.Request(args.source, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=90) as resp:
            text = resp.read().decode('utf-8', errors='ignore')

    domains, dropped = parse_hosts_text(text)
    print('解析出候选域名: %d 条 (丢弃脏数据/非法行 %d 行)' % (len(domains), dropped))
    domains, reasons = safety_filter(domains)
    print('安全过滤: 剔除 %d 条 → 可信域名单 %d | 共享托管平台 %d | 已知合法站 %d'
          % (sum(len(v) for v in reasons.values()), len(reasons['trusted']),
             len(reasons['shared_platform']), len(reasons['known_legit'])))
    for k, v in reasons.items():
        if v:
            print('   [%s] 示例: %s' % (k, sorted(v)[:3]))

    new_domains = sorted(d for d in domains if d not in entries)

    # 安全校验: 常用合法站绝不能被封禁
    violated = [d for d in MUST_NOT_BLOCK
                if d in new_domains or any(x.endswith('.' + d) for x in new_domains)]
    if violated:
        print('安全校验: ❌ 以下常用合法站会命中, 需加入排除名单: %s' % violated[:20])
    else:
        print('安全校验(常用合法站是否被误封): ✅ 通过')

    two_label = [d for d in new_domains if d.count('.') == 1]
    print('黑名单现有: %d 条 | 待新增: %d 条 | 已存在(重复): %d 条'
          % (len(entries), len(new_domains), len(domains) - len(new_domains)))
    print('   其中"整域级"条目(两级域名, 会封禁整个站点) %d 条, 示例: %s'
          % (len(two_label), two_label[:5]))
    if args.limit:
        new_domains = new_domains[:args.limit]
        print('按 --limit 截断为 %d 条' % len(new_domains))

    print('\n抽样(供人工确认, 20 条):')
    for d in new_domains[:20]:
        print('   ' + d)

    if args.dry_run:
        print('\n(dry-run, 未写入任何文件)')
        return

    # ---------- 写入 ----------
    for d in new_domains:
        entries[d] = CATEGORY
    save_blacklist(data)
    print('\n完成: 新增 %d 条, 黑名单共 %d 条 (分类「%s」)'
          % (len(new_domains), len(entries), CATEGORY))
    print('回滚命令: python import_adult_blocklist.py --remove')


if __name__ == '__main__':
    main()
