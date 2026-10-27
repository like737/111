# coding:utf-8
"""ML 检测通道 - MaliciousURLs 优化模型的只读适配层

定位
    与启发式引擎/DeepSeek 并行运行的"第三路信号", 专补"路径/参数 payload 类攻击"
    (实测: 引擎召回 1.39% -> 与模型融合后 91.84%, 正常样本误报增量 0)

设计要点(为什么不会影响既有检测)
    1. 只读: 不写盘、不联网, 只在内存里做向量化 + 预测;
    2. 异常隔离: 模型缺失/损坏/依赖缺失 → available=False, 调用方拿到 {"ok": False},
       完全退化为"没有接入", 绝不抛异常影响主检测链路;
    3. 懒加载 + 线程安全: 首次使用时加载一次(约 3~4 秒), 剪贴板线程与 Flask 多线程共享同一实例;
    4. 阈值来源于模型文件(训练时按 0 误报选定), 也可被 config 覆盖;
    5. 模型文件是普通参数字典({'vectorizer','classifier','threshold','ngram'}), 反序列化不依赖任何自定义类。

用法
    from ml_url_model import MLUrlModel
    ml = MLUrlModel('data/models/lgs_model.pickle', threshold=None, confidence=0.9)
    ml.load()                                  # 启动时调一次(失败只打印, 不抛)
    r = ml.predict(url)                        # {'ok','prob','verdict','high'}
"""

import os
import pickle
import threading
import urllib.parse

BASE = os.path.dirname(os.path.abspath(__file__))


class MLUrlModel(object):
    """MaliciousURLs 模型适配层(只读, 异常安全)"""

    def __init__(self, model_path, threshold=None, confidence=0.9):
        self.model_path = model_path if os.path.isabs(model_path) else os.path.join(BASE, model_path)
        self.threshold_override = threshold
        self.confidence = float(confidence)
        self.threshold = None            # 使用模型内保存值
        self.ngram = None
        self.available = False
        self.error = ""
        self._vectorizer = None
        self._classifier = None
        self._lock = threading.Lock()

    # ---------- 加载 ----------
    def load(self, verbose=True):
        with self._lock:
            if self.available:
                return True
            try:
                if not os.path.exists(self.model_path):
                    raise FileNotFoundError('模型文件不存在: %s' % self.model_path)
                with open(self.model_path, 'rb') as f:
                    data = pickle.load(f)
                if not isinstance(data, dict) or 'vectorizer' not in data or 'classifier' not in data:
                    raise ValueError('模型文件格式不正确(应为含 vectorizer/classifier 的字典)')
                self._vectorizer = data['vectorizer']
                self._classifier = data['classifier']
                self.ngram = data.get('ngram')
                self.threshold = (float(self.threshold_override)
                                  if self.threshold_override is not None
                                  else float(data.get('threshold', 0.5)))
                self.available = True
                self.error = ""
                if verbose:
                    print('[ML] 模型已加载: %s (阈值 %.4f, 词表 %d 维)'
                          % (os.path.basename(self.model_path), self.threshold,
                             len(getattr(self._vectorizer, 'vocabulary_', {}))))
            except Exception as e:                     # 任何异常都不向上抛
                self.available = False
                self.error = '%s: %s' % (type(e).__name__, e)
                if verbose:
                    print('[ML] 模型不可用(%s) —— 本次运行仅使用启发式引擎/AI, 功能不受影响' % self.error)
            return self.available

    # ---------- 推理 ----------
    def predict(self, url):
        """单条预测: {'ok','prob','verdict','high'}; 不可用时 ok=False, 其余为安全值"""
        if not self.available:
            return {'ok': False, 'prob': None, 'verdict': 0, 'high': False}
        try:
            X = self._vectorizer.transform([urllib.parse.unquote(str(url))])
            prob = float(self._classifier.predict_proba(X)[0, 1])
        except Exception as e:                         # 推理异常同样降级
            self.error = '%s: %s' % (type(e).__name__, e)
            return {'ok': False, 'prob': None, 'verdict': 0, 'high': False}
        return {'ok': True,
                'prob': round(prob, 4),
                'verdict': int(prob >= self.threshold),
                'high': bool(prob >= self.confidence)}

    def predict_batch(self, urls):
        """批量预测(评测/回归用), 返回概率列表; 不可用时返回空列表"""
        if not self.available or not urls:
            return []
        try:
            X = self._vectorizer.transform([urllib.parse.unquote(str(u)) for u in urls])
            return [float(p) for p in self._classifier.predict_proba(X)[:, 1]]
        except Exception as e:
            self.error = '%s: %s' % (type(e).__name__, e)
            return []

    # ---------- 供展示 ----------
    def detail_line(self, url, result=None):
        """生成写入 details 的一行文本(注意: 文案不含 'DeepSeek', 避免影响AI徽章判定)"""
        r = result if result is not None else self.predict(url)
        if not r['ok']:
            return '[ML] 模型不可用, 本项跳过'
        return '[ML] ML模型判定: 恶意概率 %.4f (阈值 %.2f) -> %s' % (
            r['prob'], self.threshold, '恶意' if r['verdict'] else '正常')


# ============================================================================
#  方案A-① 域名级模型(domain model) —— 与"路径模型"完全解耦, 独立数据/阈值/开关
#  说明: 结构化特征在这里实现, 训练脚本 import 本文件复用, 保证训练/推理特征一致
# ============================================================================

STRUCT_FEATURE_NAMES = [
    'len', 'n_labels', 'avg_label_len', 'max_label_len', 'digit_ratio', 'vowel_ratio',
    'dash_count', 'dot_count', 'subdomain_count', 'longest_consonant_run', 'entropy',
    'is_ip', 'is_punycode', 'tld_risky', 'is_free_hosting', 'has_brand_word',
    'has_adult_word', 'has_sensitive_word', 'has_hyphen_label', 'is_www_sub',
]

_VOWELS = set('aeiouAEIOU')
_CONSONANTS = set('bcdfghjklmnpqrstvwxzBCDFGHJKLMNPQRSTVWXZ')
_SENSITIVE_WORDS = ('login', 'secure', 'account', 'verify', 'update', 'signin', 'wallet',
                    'bank', 'pay', 'auth', 'confirm', 'bonus', 'prize', 'free', 'gift')
_cached_word_lists = {}


def _word_lists():
    """惰性加载项目内的品牌词/成人词表(复用现有数据, 避免重复维护)"""
    if _cached_word_lists:
        return _cached_word_lists
    brands, adults = set(), set()
    try:
        from analyzer import URLAnalyzer
        brands = {str(b).lower() for b in URLAnalyzer.BRAND_DOMAINS}
    except Exception:
        pass
    try:
        from utils import load_adult_keywords
        kw = load_adult_keywords()
        for key in ('domain_strong', 'adult_brands', 'gambling'):
            adults |= {str(x).lower() for x in kw.get(key, [])}
    except Exception:
        pass
    _cached_word_lists['brands'] = brands
    _cached_word_lists['adults'] = adults
    return _cached_word_lists


def host_struct_features(host):
    """hostname → 结构化特征向量(固定顺序, 与 STRUCT_FEATURE_NAMES 一一对应)

    只使用 hostname 字符串本身(不使用页面内容/网络请求), 纯计算、确定性。
    """
    import ipaddress
    import math

    host = (host or '').strip().lower().strip('.')
    labels = [x for x in host.split('.') if x]
    n = len(labels)
    tld = labels[-1] if labels else ''

    def entropy(s):
        if not s:
            return 0.0
        freq = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        total = float(len(s))
        return -sum((v / total) * math.log(v / total, 2) for v in freq.values())

    longest_run = cur = 0
    for c in host:
        if c in _CONSONANTS and c not in _VOWELS:
            cur += 1
            longest_run = max(longest_run, cur)
        else:
            cur = 0

    try:
        ipaddress.ip_address(host)
        is_ip = 1.0
    except ValueError:
        is_ip = 0.0
    try:
        from utils import is_suspicious_tld, is_free_hosting
        tld_risky = 1.0 if is_suspicious_tld(tld) else 0.0
        free_host = 1.0 if is_free_hosting(host) else 0.0
    except Exception:
        tld_risky = free_host = 0.0
    words = _word_lists()

    return [
        float(len(host)),
        float(n),
        (len(host) / n) if n else 0.0,
        float(max((len(x) for x in labels), default=0)),
        (sum(c.isdigit() for c in host) / len(host)) if host else 0.0,
        (sum(c in _VOWELS for c in host) / len(host)) if host else 0.0,
        float(host.count('-')),
        float(host.count('.')),
        float(max(0, n - 2)),
        float(longest_run),
        entropy(host),
        is_ip,
        1.0 if any(x.startswith('xn--') for x in labels) else 0.0,
        tld_risky,
        free_host,
        1.0 if any(b and b in host for b in words.get('brands', ())) else 0.0,
        1.0 if any(a and a in host for a in words.get('adults', ())) else 0.0,
        1.0 if any(w in host for w in _SENSITIVE_WORDS) else 0.0,
        1.0 if any('-' in x for x in labels) else 0.0,
        1.0 if n >= 2 and labels[0] == 'www' else 0.0,
    ]


def host_features_matrix(hosts):
    """hosts → (n, len(STRUCT_FEATURE_NAMES)) 的 numpy 数组"""
    import numpy as np
    return np.asarray([host_struct_features(h) for h in hosts], dtype=float)



class DomainURLModel(object):
    """域名级模型(方案A-①): hostname 的字符 n-gram + 结构化特征 + 逻辑回归

    模型文件是普通参数字典(不含自定义类), 换模型只覆盖文件:
      {'kind': 'domain-model', 'ngram_range': (2,4), 'vectorizer': TfidfVectorizer,
       'struct': {'mean': [...], 'scale': [...]}, 'classifier': LogisticRegression,
       'threshold': 0.x, 'meta': {...}}
    """

    def __init__(self, model_path, threshold=None, confidence=0.9):
        self.model_path = model_path if os.path.isabs(model_path) else os.path.join(BASE, model_path)
        self.threshold_override = threshold
        self.confidence = float(confidence)
        self.threshold = None
        self.available = False
        self.error = ""
        self.meta = {}
        self._vectorizer = None
        self._classifier = None
        self._mean = None
        self._scale = None
        self.platt = None          # (a, b)：v2 模型的概率校准参数；旧模型为 None
        self._lock = threading.Lock()

    @staticmethod
    def host_of(item):
        """输入归一化: 允许传完整URL / 带路径 / 裸域名, 统一取出 hostname"""
        s = str(item or '').strip().lower()
        if '://' in s:
            s = urllib.parse.urlsplit(s).hostname or ''
        elif '/' in s:
            s = s.split('/', 1)[0]
        if '@' in s:                      # user@host 形式
            s = s.split('@', 1)[1]
        s = s.strip().strip('.')
        return s[4:] if s.startswith('www.') else s

    def load(self, verbose=True):
        with self._lock:
            if self.available:
                return True
            try:
                if not os.path.exists(self.model_path):
                    raise FileNotFoundError('模型文件不存在: %s' % self.model_path)
                with open(self.model_path, 'rb') as f:
                    data = pickle.load(f)
                if not isinstance(data, dict) or data.get('kind') != 'domain-model':
                    raise ValueError('不是域名模型文件(期望 kind=domain-model)')
                self._vectorizer = data['vectorizer']
                self._classifier = data['classifier']
                struct = data.get('struct') or {}
                self._mean = struct.get('mean')
                self._scale = struct.get('scale')
                self.threshold = (float(self.threshold_override)
                                  if self.threshold_override is not None
                                  else float(data.get('threshold', 0.5)))
                self.meta = data.get('meta') or {}
                platt = data.get('platt')
                if isinstance(platt, dict) and 'a' in platt and 'b' in platt:
                    # Platt 校准参数（训练脚本 v2 写入）; 旧模型没有该字段 → 保持 None
                    self.platt = (float(platt['a']), float(platt['b']))
                self.available = True
                if verbose:
                    print('[ML] 域名模型已加载: %s (阈值 %.4f, 词表 %d 维%s)'
                          % (os.path.basename(self.model_path), self.threshold,
                             len(getattr(self._vectorizer, 'vocabulary_', {})),
                             ', 已校准' if self.platt else ''))
            except Exception as e:
                self.available = False
                self.error = '%s: %s' % (type(e).__name__, e)
                if verbose:
                    print('[ML] 域名模型不可用(%s) —— 已跳过该通道, 其它检测不受影响' % self.error)
            return self.available

    def _matrix(self, hosts):
        import numpy as np
        from scipy.sparse import hstack, csr_matrix
        X = self._vectorizer.transform(hosts)
        F = host_features_matrix(hosts)
        if self._mean is not None and self._scale is not None:
            F = (F - np.asarray(self._mean, dtype=float)) / np.asarray(self._scale, dtype=float)
        return hstack([X, csr_matrix(F)]).tocsr()

    def predict(self, item):
        if not self.available:
            return {'ok': False, 'prob': None, 'verdict': 0, 'high': False, 'host': None}
        try:
            host = self.host_of(item)
            if not host:
                return {'ok': False, 'prob': None, 'verdict': 0, 'high': False, 'host': None}
            prob = float(self._classifier.predict_proba(self._matrix([host]))[0, 1])
            prob = self._calibrate(prob)
        except Exception as e:
            self.error = '%s: %s' % (type(e).__name__, e)
            return {'ok': False, 'prob': None, 'verdict': 0, 'high': False, 'host': None}
        return {'ok': True, 'prob': round(prob, 4), 'verdict': int(prob >= self.threshold),
                'high': bool(prob >= self.confidence), 'host': host}

    def _calibrate(self, prob):
        """Platt 校准：sigmoid(a·logit(p)+b)

        v2 模型才有这两个参数；旧模型 self.platt is None → 原样返回（完全向后兼容）。
        """
        if not self.platt:
            return prob
        import math
        a, b = self.platt
        p = min(max(float(prob), 1e-6), 1 - 1e-6)
        z = math.log(p / (1.0 - p))
        return 1.0 / (1.0 + math.exp(-(a * z + b)))

    def proba_batch(self, hosts):
        """批量原始概率（评测/训练脚本用；不含校准）"""
        if not self.available or not hosts:
            return []
        import numpy as np
        hosts = [self.host_of(h) for h in hosts]
        keep = [h for h in hosts if h]
        if not keep:
            return []
        return list(self._classifier.predict_proba(self._matrix(keep))[:, 1])

    def predict_batch(self, items):
        if not self.available or not items:
            return []
        try:
            hosts = [self.host_of(x) for x in items]
            keep = [i for i, h in enumerate(hosts) if h]
            out = [0.0] * len(items)
            if keep:
                probs = self._classifier.predict_proba(self._matrix([hosts[i] for i in keep]))[:, 1]
                for idx, p in zip(keep, probs):
                    out[idx] = float(p)
            return out
        except Exception as e:
            self.error = '%s: %s' % (type(e).__name__, e)
            return []


# ============================================================================
#  方案A-② 多模型通道管理器: 域名模型 + 路径模型 并行(各自阈值/门限/拦截开关)
# ============================================================================

DEFAULT_MODEL_SPEC = {
    # 域名级: 补"未入库的新钓鱼/色情/赌博域名"(方案A主战场)
    'domain': {'enabled': True, 'path': 'data/models/domain_model.pkl',
               'confidence': 0.9, 'trigger_intercept': True},
    # 路径级: 沿用原模型(方案A-②), 覆盖 URL 里的攻击/探测痕迹
    'path': {'enabled': True, 'path': 'data/models/path_model.pkl',
             'confidence': 0.9, 'trigger_intercept': True},
}


class MLChannel(object):
    """多模型管理器

    配置(config.json → detection.ml_models):
      {"domain": {"enabled": true, "path": "data/models/domain_model.pkl",
                  "confidence": 0.9, "trigger_intercept": true},
       "path":   {"enabled": true, "path": "data/models/path_model.pkl",
                  "confidence": 0.9, "trigger_intercept": true}}
    向后兼容: 未配置 ml_models 时, 用旧的 ml_model_path / ml_confidence /
              ml_trigger_intercept 构造"单一路径模型"。
    """

    def __init__(self, config=None, spec=None, verbose=True):
        self.models = {}          # name -> 适配器实例
        self.spec = {}
        self.verbose = verbose
        det = {}
        if config is not None:
            det = (config.get('detection') or {}) if hasattr(config, 'get') else {}
            det = dict(det) if isinstance(det, dict) else {}
        conf_default = float(det.get('ml_confidence') or 0.9)
        trig_default = bool(det.get('ml_trigger_intercept'))
        cfg_models = det.get('ml_models')
        if isinstance(cfg_models, dict) and cfg_models:
            for name, item in cfg_models.items():
                item = dict(item or {})
                self.spec[name] = {
                    'enabled': bool(item.get('enabled', True)),
                    'path': item.get('path') or DEFAULT_MODEL_SPEC.get(name, {}).get('path', ''),
                    'confidence': float(item.get('confidence', conf_default)),
                    'trigger_intercept': bool(item.get('trigger_intercept', trig_default)),
                }
        elif spec:
            self.spec = {k: dict(v) for k, v in spec.items()}
        else:
            # 旧配置: 单一路径模型
            self.spec = {'path': {'enabled': True,
                                  'path': det.get('ml_model_path') or 'data/models/lgs_model.pickle',
                                  'confidence': conf_default,
                                  'trigger_intercept': trig_default}}

    def load(self, verbose=None):
        verbose = self.verbose if verbose is None else verbose
        for name, item in self.spec.items():
            if not item.get('enabled'):
                continue
            path = item.get('path') or ''
            if name == 'domain':
                model = DomainURLModel(path, confidence=item['confidence'])
            else:
                model = MLUrlModel(path, confidence=item['confidence'])
            model.load(verbose=verbose)
            if model.available:
                self.models[name] = model
            else:
                print('[ML] %s 模型不可用, 已跳过(其余通道与既有检测不受影响)' % name)
        return bool(self.models)

    @property
    def available(self):
        return bool(self.models)

    def predict(self, url):
        """返回 {"ok","models": {name: {...}}, "prob","verdict","high","convict","hint","thresholds"}"""
        out = {'ok': False, 'models': {}, 'prob': None, 'verdict': 0, 'high': False,
               'convict': [], 'hint': [], 'thresholds': {}}
        for name, model in self.models.items():
            r = model.predict(url)
            r['threshold'] = model.threshold
            r['confidence'] = model.confidence
            r['trigger_intercept'] = bool(self.spec.get(name, {}).get('trigger_intercept'))
            out['models'][name] = r
            out['thresholds'][name] = model.threshold
            if not r.get('ok'):
                continue
            out['ok'] = True
            p = float(r['prob'])
            out['prob'] = p if out['prob'] is None else max(out['prob'], p)
            out['verdict'] = max(out['verdict'], int(r['verdict']))
            if r['high']:
                out['high'] = True
                out['hint'].append(name)
                if r['trigger_intercept']:
                    out['convict'].append(name)
        return out

    def detail_lines(self, url, result=None):
        """生成每个模型的详情行(文案不含 "DeepSeek", 避免影响页面 AI 徽章)"""
        if result is None:
            result = self.predict(url)
        lines = []
        label = {'domain': '域名模型', 'path': '路径模型'}
        for name, r in (result.get('models') or {}).items():
            if not r.get('ok'):
                continue
            lines.append('[ML] %s: 概率 %.4f (阈值 %.4f) -> %s'
                         % (label.get(name, name), r['prob'], r['threshold'] or 0.0,
                            '恶意' if r['verdict'] else '正常'))
        return lines

    def describe(self):
        parts = []
        for name, model in self.models.items():
            item = self.spec.get(name, {})
            parts.append('%s(阈值%.4f,门限%.2f,拦截=%s)'
                         % (name, model.threshold or 0.0, model.confidence,
                            bool(item.get('trigger_intercept'))))
        return ' | '.join(parts)
