import os
import sys

# 控制台编码兜底: 启动横幅里有 emoji, 当输出被重定向到文件、或控制台是 GBK(默认 cp936)时,
# 直接 print 会抛 UnicodeEncodeError 导致服务起不来。这里统一改成 UTF-8 并容错。
try:
    if hasattr(sys.stdout, 'reconfigure'):
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

# 添加项目根目录到路径
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

# 是否为 Werkzeug reloader 拉起的子进程（真正提供服务的那个）
_RELOADER_CHILD = os.environ.get("WERKZEUG_RUN_MAIN") == "true"

# Web 端口（早鸟横幅与 run_web 共用, 避免两处写死不一致）
DEFAULT_PORT = 5000


def _print_banner_once(port=DEFAULT_PORT):
    """尽早打印启动横幅（不等黑名单/ML 模型加载，避免终端看起来"卡住"）

    为什么能提前: 这行只依赖 os/print，放在导入 config/detector 之前执行，
    终端大约 0.1~0.3 秒就能看到；黑名单(18 万条)和两个模型在它之后才加载。

    只打印一次: 用环境变量做标记。debug 模式下 reloader 子进程会继承父进程的环境变量，
    所以父进程打印过之后，子进程不会再打印第二行。
    """
    if os.environ.get("EY_WEB_BANNER_PRINTED") == "1":
        return
    os.environ["EY_WEB_BANNER_PRINTED"] = "1"
    print(f"🚀 Web服务器启动: http://127.0.0.1:{port}", flush=True)


# 以脚本方式启动时，先打横幅，再去加载耗时的黑名单/模型
if __name__ == "__main__" and not _RELOADER_CHILD:
    _print_banner_once()

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash  # noqa: E402
from html import escape as html_escape   # 拼接HTML时对URL/详情文本转义(防XSS与属性注入)  # noqa: E402
import json  # noqa: E402
import logging  # noqa: E402
import threading  # noqa: E402
import uuid  # noqa: E402
from datetime import datetime  # noqa: E402
from markupsafe import Markup  # noqa: E402


def _read_startup_verbose():
    """启动时要打印多详细?

    默认 False → 终端只有两行: 「🚀 Web服务器启动: …」+「✅ 就绪」（能访问后）。
    需要排查启动问题时，任选一种方式恢复完整日志:
      1) 环境变量: PowerShell 里 ``$env:EY_VERBOSE="1"`` 再启动;
      2) 配置: config.json → "logging": {"verbose_startup": true}
    """
    env = os.environ.get("EY_VERBOSE", "").strip().lower()
    if env in ("1", "true", "yes", "on"):
        return True
    if env in ("0", "false", "no", "off"):
        return False
    try:
        with open(os.path.join(BASE_DIR, "config.json"), "r", encoding="utf-8") as handle:
            logging_cfg = (json.load(handle) or {}).get("logging") or {}
        return bool(logging_cfg.get("verbose_startup", False))
    except Exception:
        return False


STARTUP_VERBOSE = _read_startup_verbose()


def _startup_log(*args, **kwargs):
    """只在"详细启动"模式下输出（错误信息不走这里，始终可见）"""
    if STARTUP_VERBOSE:
        print(*args, **kwargs)


def _install_startup_quiet(quiet=True):
    """安静启动: 屏蔽 Flask/werkzeug 的启动横幅，但保留请求日志与错误

    横幅内容（Serving Flask app / Debug mode / WARNING: development server /
    Running on / Press CTRL+C / Debugger PIN …）与业务无关，只是刷屏；
    这里按"记录文本"精确过滤，不动每条请求的访问日志。
    """
    if not quiet:
        return
    try:
        import flask.cli as flask_cli
        flask_cli.show_server_banner = lambda *args, **kwargs: None
    except Exception:
        pass

    class _StartupNoise(logging.Filter):
        # 横幅里可能带 ANSI 颜色码（如 Press CTRL+C 是黄色），所以按"包含"判断
        _SNIPPETS = (" * Restarting with", " * Debugger is active", " * Debugger PIN",
                     "Press CTRL+C to quit", "Press CTRL+C")

        def filter(self, record):
            try:
                message = record.getMessage()
            except Exception:
                return True
            if "WARNING: This is a development server" in message:
                return False
            if " * Running on" in message:
                return False
            return not any(snippet in message for snippet in self._SNIPPETS)

    try:
        logging.getLogger("werkzeug").addFilter(_StartupNoise())
    except Exception:
        pass


def _install_probe_log_filter():
    """屏蔽就绪探针(/healthz)自身的访问日志 —— 它只是内部心跳, 不该刷屏"""
    class _ProbeNoise(logging.Filter):
        def filter(self, record):
            try:
                return "/healthz" not in record.getMessage()
            except Exception:
                return True

    try:
        logging.getLogger("werkzeug").addFilter(_ProbeNoise())
    except Exception:
        pass


_install_startup_quiet(not STARTUP_VERBOSE)
_install_probe_log_filter()

from config import Config
from detector import Detector

app = Flask(__name__)
app.config['SECRET_KEY'] = 'malicious-url-detection-2024'

# 初始化核心模块（verbose=False → 不打印各模块的加载信息，终端只留启动提示）
config = Config(verbose=STARTUP_VERBOSE)

# debug 模式下 Werkzeug 会先起一个 "reloader 父进程"（只负责拉起子进程，不处理请求）。
# 父进程根本用不到黑名单/模型，这里延迟加载 —— 省掉父进程那 2~3 秒，子进程更快就绪。
# （以模块方式 import web_app 时照常立即加载，run_guarded.py / selftest 不受影响）
_DEFER_DETECTOR = (__name__ == "__main__" and not _RELOADER_CHILD)
detector = None if _DEFER_DETECTOR else Detector(config, verbose=STARTUP_VERBOSE)


def _ensure_detector():
    """真正开始服务前确保 detector 已加载（debug=False 的脚本模式也会走这里）"""
    global detector
    if detector is None:
        detector = Detector(config, verbose=STARTUP_VERBOSE)
    return detector


# 「✅ 就绪」探测用的随机令牌: 只有本进程的 /healthz 才会返回它。
# 作用: 端口被别的实例占用时，不会把"别人的 200"误判成"自己已就绪"。
_READY_TOKEN = uuid.uuid4().hex


def _notify_ready_when_serving(port, token, timeout=180.0):
    """等服务真正能响应 HTTP 后打印一行「✅ 就绪」

    为什么不能用"端口是否监听"判断: debug 模式下 Werkzeug 的 reloader 父进程
    会先把端口 bind 上（把 fd 传给子进程），此时连接能建立但请求会一直等 ——
    所以这里用真实 HTTP 请求 + 本进程令牌来确认"确实在服务"。
    """
    import http.client
    import time as _time

    deadline = _time.time() + float(timeout or 0)
    while _time.time() < deadline:
        conn = None
        try:
            conn = http.client.HTTPConnection("127.0.0.1", int(port), timeout=1.0)
            conn.request("GET", "/healthz")
            resp = conn.getresponse()
            body = resp.read(256)
            if resp.status == 200 and token.encode("ascii") in body:
                print("✅ 就绪", flush=True)
                return
        except Exception:
            pass
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
        _time.sleep(0.2)

# 二次元 SVG 图标：统一定义在 icon_svg.py，模板里用 {{ icon('search', 18, '检测') }}，
# 后端结果 HTML 继续调用 render_icon(...)，两处共用同一份 SVG，风格不会分叉。
from icon_svg import render_icon, render_mascot  # noqa: E402

app.jinja_env.globals['icon'] = render_icon
app.jinja_env.globals['mascot'] = render_mascot


@app.route('/healthz')
def healthz():
    """就绪探针: 极轻、无副作用（启动提示与监控用）"""
    return jsonify({'ok': True, 'token': _READY_TOKEN})


@app.context_processor
def _inject_icon_svgs():
    """把同一套 SVG 注入为 JSON，供 base.html 里 JS 动态提示使用。"""
    from icon_svg import icon_bodies
    svgs = {name: str(render_icon(name, 16)) for name in icon_bodies()}
    return {"icon_svgs_json": Markup(json.dumps(svgs, ensure_ascii=False))}

def get_risk_class(score):
    """根据评分(0-100)确定风险等级，越低越危险"""
    if score == 0:
        return 'dark', 'dark', '黑名单'
    elif score <= 69:
        return 'danger', 'danger', '危险'
    elif score <= 99:
        return 'success', 'success', '安全'
    else:  # score == 100
        return 'primary', 'primary', '白名单'

def get_risk_badge(result):
    """获取风险等级横条进度条HTML，支持对象或字典"""
    if isinstance(result, dict):
        score = result.get('score', 0)
    else:
        score = result.score
    
    if score == 0:
        color = 'dark'
        label = '黑名单'
    elif score <= 69:
        color = 'danger'
        label = '危险'
    elif score <= 99:
        color = 'success'
        label = '安全'
    else:
        color = 'primary'
        label = '白名单'
    
    return f'''
    <div class="d-flex flex-wrap align-items-center gap-2 w-100">
        <div class="progress flex-grow-1" style="height: 22px; min-width: 0; overflow: hidden;">
            <div class="progress-bar bg-{color}" 
                 role="progressbar" 
                 style="width: {'100%' if score >= 100 else score}%; min-width: fit-content;"
                 aria-valuenow="{score}" 
                 aria-valuemin="0" 
                 aria-valuemax="100">
            </div>
        </div>
        <small class="text-{color} fw-bold text-nowrap">{label} {score}</small>
    </div>'''

@app.template_filter('format_time')
def format_time(value, fmt='%Y-%m-%d %H:%M:%S'):
    """把检测时间格式化为可读形式

    detection_log.json 中保存的是 datetime.now().isoformat()，
    例如 "2026-09-15T08:29:53.981409"。模板里直接切片只能得到
    "09-15T08:2" 这种带 T 的片段，因此统一在这里转换；
    解析失败时原样返回前 19 位，保证页面不会因为脏数据报错。
    """
    if not value:
        return ''
    try:
        return datetime.strptime(str(value)[:19], '%Y-%m-%dT%H:%M:%S').strftime(fmt)
    except ValueError:
        return str(value)[:19]

@app.route('/')
def index():
    """首页 - URL检测"""
    # 首页"是否启用AI辅助检测"选项的默认状态:
    # 需要同时满足"已配置DeepSeek密钥" 且 "设置页未关闭AI辅助检测"
    ai_available = (bool(str(config.get('api_keys', 'deepseek') or '').strip())
                    and bool(config.get('detection', 'enable_api_check')))
    # 右栏（统计摘要 + 最近检测 + 7天趋势）与检测后的局部刷新共用同一份上下文
    return render_template('index.html', ai_available=ai_available, **_dashboard_context())


def _build_daily_trend(reporter, days=7):
    """汇总最近 N 天每日检测量, 供首页迷你柱状图使用(纯读取, 无副作用)。"""
    try:
        from datetime import timedelta
        today = datetime.now().date()
        buckets = {today - timedelta(days=days - 1 - i): {"total": 0, "malicious": 0}
                   for i in range(days)}
        for log in getattr(reporter, "_logs", None) or []:
            try:
                day = datetime.fromisoformat(str(log.get("timestamp", ""))).date()
            except (TypeError, ValueError):
                continue
            if day in buckets:
                buckets[day]["total"] += 1
                if log.get("is_malicious"):
                    buckets[day]["malicious"] += 1
        peak = max((b["total"] for b in buckets.values()), default=0)
        if peak == 0:
            return [], 0
        week_cn = "一二三四五六日"
        trend = [{
            "label": day.strftime("%m-%d"),
            "week": week_cn[day.weekday()],
            "total": bucket["total"],
            "malicious": bucket["malicious"],
            "pct": round(bucket["total"] / peak * 100, 1),
        } for day, bucket in buckets.items()]
        return trend, (0 if peak == 1 and not any(b["total"] for b in buckets.values()) else peak)
    except Exception:
        return [], 0


def _dashboard_context():
    """首页右栏（统计摘要 + 最近检测 + 7天趋势）的渲染上下文

    首屏与"检测完成后局部刷新"共用同一份数据与同一个模板，
    保证两处展示完全一致（不会有第二套渲染逻辑）。
    """
    reporter = detector.reporter
    stats = reporter.get_statistics()
    recent = reporter.get_recent_detections(5)
    trend, trend_peak = _build_daily_trend(reporter, days=7)
    try:
        safe_rate = max(0.0, round(100.0 - float(stats.get('malicious_rate') or 0), 2))
    except (TypeError, ValueError):
        safe_rate = 100.0
    return {
        "stats": stats,
        "recent": recent,
        "get_risk_class": get_risk_class,
        "get_risk_badge": get_risk_badge,
        "trend": trend,
        "trend_peak": trend_peak,
        "safe_rate": safe_rate,
    }

@app.route('/detect', methods=['POST'])
def detect():
    """执行URL检测"""
    url = request.form.get('url', '').strip()
    
    if not url:
        return jsonify({'error': 'URL不能为空'})
    
    # 首页的"是否启用AI辅助检测"选项: 未提交该字段时沿用原行为(启用),
    # detector 内部还会再校验设置页的全局开关 enable_api_check
    use_api_raw = request.form.get('use_api')
    use_api = True if use_api_raw is None else use_api_raw.strip().lower() in ('1', 'true', 'on', 'yes')
    
    result = detector.detect(url, use_api=use_api)
    # 检测刚完成 → 立刻把最新统计 + 最近记录 + 右栏 HTML 一起返回,
    # 前端无需整页刷新即可同步（与首屏复用同一个 _dashboard.html）。
    dash = _dashboard_context()
    return jsonify({
        'success': True,
        'result': result.to_dict(),
        'html': get_result_html(result),
        'stats': dash['stats'],
        'recent': dash['recent'],
        'dashboard_html': render_template('_dashboard.html', **dash),
    })

def get_result_html(result):
    """生成结果HTML

    链接拦截(本次新增): 结果里的URL渲染成"受守卫链接"——
    命中黑名单或判定为恶意时, 点击只弹出拦截提示、不会跳转;
    安全链接点击后在新标签页打开。
    另外所有插入HTML的URL/域名/详情文本都做了转义(原实现是直接拼接,
    URL中含有引号或标签时会破坏页面甚至造成XSS)。
    """
    score = result.score
    is_malicious = result.is_malicious

    # ---- 展示层修正: "ML 单独定罪"造成的 分数/结论 冲突 ----
    #   背景: ml_mode=enforce 且 ml_trigger_intercept=true 时, ML 高置信项会被直接置 is_malicious=True;
    #   但按约定 ML 不参与打分(ml_affect_score=false), 于是分数可能仍留在"安全"档(>=70),
    #   出现"评分 97 + 绿色进度条 + 结论却是恶意链接"的观感矛盾。
    #   处理(**只影响展示, 绝不改 result.score / 日志字段 / 判定结果**):
    #     1) 展示分数夹到"可疑"档 60-69(单调映射: 70→60, 99→69);
    #     2) 卡片改用警示配色, 并在 ML 区块标注"该判定来自 ML 通道（分数体系未参与打分）"。
    ml_only_conviction = bool(is_malicious
                              and not result.blacklist_match
                              and getattr(result, 'ml_mode', None) == 'enforce'
                              and getattr(result, 'ml_high', False)
                              and score >= 70)
    display_score = score
    if ml_only_conviction:
        display_score = max(60, min(69, 60 + int(round((min(99, score) - 70) / 29.0 * 9))))

    risk_class, bg_class, risk_text = get_risk_class(display_score)
    header_text_class = 'text-white'
    level_span_class = 'text-' + risk_class
    if ml_only_conviction:
        # 警示配色(黄) + "可疑"文案: 既区别于"危险(红)", 也区别于"安全(绿)"
        risk_class = bg_class = 'warning'
        risk_text = '可疑'
        header_text_class = 'text-dark'
        level_span_class = 'text-warning-emphasis'

    # 拦截判定: 命中黑名单 或 被判定为恶意链接
    blocked = bool(is_malicious or result.blacklist_match)
    block_reason = ("命中黑名单记录" if result.blacklist_match
                    else ("ML 通道高置信判定为恶意（分数体系未参与打分）" if ml_only_conviction
                          else "启发式/AI分析判定为恶意链接（评分 {}/100）".format(display_score)))
    url_attr = html_escape(result.url, quote=True)        # 放进 data-url 属性
    url_text = html_escape(result.url)                    # 页面显示文本
    reason_attr = html_escape(block_reason, quote=True)
    domain_text = html_escape(str(result.domain or "未知"))
    link_class = "text-danger text-decoration-line-through fw-bold" if blocked else "link-primary"
    guard_attrs = ('data-url="{url}" data-blocked="{blocked}" data-reason="{reason}" '
                   'onclick="return guardedOpen(this)"'.format(
                       url=url_attr, blocked="1" if blocked else "0", reason=reason_attr))
    blocked_badge = ('<span class="badge bg-danger ms-1">{} 已拦截</span>'.format(
                        render_icon('shield', 14, '拦截')) if blocked
                     else '<span class="badge bg-success ms-1">{} 可安全访问</span>'.format(
                        render_icon('check', 14, '安全')))
    # URL 下方一行提示: 只说明"点击会发生什么", 避免与卡片底部的结论重复
    # (block_reason 文本本身可能已带括号，这里不再套一层括号，避免出现 "））")
    blocked_hint = ('<div class="alert alert-danger mt-2 mb-0 py-2">'
                    '<small>{} 点击不会跳转 · 已自动拦截：{}</small></div>'.format(
                        render_icon('shield', 16, '拦截'), html_escape(block_reason)) if blocked else
                    '<div class="alert alert-success mt-2 mb-0 py-2">'
                    '<small>{} 点击可在新标签页打开该链接</small></div>'.format(
                        render_icon('check', 16, '安全')))
    # DeepSeek 是否参与本次分析(用于"AI分析"那一行的标记图标)
    deepseek_used = any('DeepSeek' in str(d) for d in result.details)
    ai_mark = str(render_icon('check', 14, '已启用')) if deepseek_used else ''
    
    # 进度条宽度计算
    # 直接按真实得分铺宽度（92 分就留 8% 灰色余量，不再">=70 直接满格"；
    # 满分 100 才铺满）。min-width 保障 0~5 分时文字仍能放下。
    bar_width = max(0, min(100, int(display_score)))
    bar_style = f"width: {bar_width}%; min-width: fit-content;"
    # ---- ML 检测通道展示(方案A: 域名模型 + 路径模型 分别展示) ----
    # 只追加一块信息, 不改变既有颜色/分级/拦截逻辑;
    # 模型未启用或不可用时 ml_block_html 为空, 页面与接入前完全一致。
    # (用字符串拼接而非 %/.format, 避免模板里的 % 或 {} 被误解析)
    ml_block_html = ''
    if getattr(result, 'ml_prob', None) is not None:
        _ml_bad = bool(getattr(result, 'ml_verdict', 0))
        _ml_badge = ('<span class="badge bg-danger">模型: 恶意</span>' if _ml_bad
                     else '<span class="badge bg-success">模型: 正常</span>')
        _ml_mode_txt = ('判定参与(enforce)' if getattr(result, 'ml_mode', '') == 'enforce'
                        else '仅记录(shadow)')
        _ml_high_txt = '是' if getattr(result, 'ml_high', False) else '否'
        # 各通道独立展示(域名模型 / 路径模型)
        _rows = ''
        for _name, _label in (('domain', '域名模型'), ('path', '路径模型')):
            _p = getattr(result, 'ml_' + _name + '_prob', None)
            if _p is None:
                continue
            _is_bad = float(_p) >= ((getattr(result, 'ml_thresholds', {}) or {}).get(_name) or 0.5)
            _rows += ('<li><strong>' + _label + ':</strong> ' + ('%.4f' % float(_p)) + '　'
                      + ('<span class="badge bg-danger">恶意</span>' if _is_bad
                         else '<span class="badge bg-success">正常</span>') + '</li>')
        _convict_txt = ('、'.join(getattr(result, 'ml_convict', []) or [])
                        or ('、'.join(getattr(result, 'ml_hint', []) or []) + '（仅提示）' if getattr(result, 'ml_hint', None) else '—'))
        ml_block_html = (
            '<div class="row mt-3"><div class="col-12">'
            '<h6>' + str(render_icon('shield', 16, 'ML')) + ' ML模型判定 (MaliciousURLs)</h6>'
            '<ul class="list-unstyled mb-0">'
            + _rows +
            '<li><strong>综合概率:</strong> ' + ('%.4f' % float(result.ml_prob)) + '　' + _ml_badge + '</li>'
            '<li><strong>高置信:</strong> ' + _ml_high_txt + '　<strong>模式:</strong> ' + _ml_mode_txt
            + '　<strong>参与拦截的通道:</strong> ' + _convict_txt + '</li>'
            '</ul></div></div>')
        # 说明标注: 让用户知道这条结论来自哪一路信号, 避免"分数/结论"观感矛盾
        if _ml_bad and getattr(result, 'ml_high', False):
            if ml_only_conviction:
                ml_block_html += ('<div class="alert alert-warning py-2 mt-2 mb-0">'
                                  '<small>⚠ <strong>该判定来自 ML 通道（分数体系未参与打分）</strong>：'
                                  '模型高置信判恶意，已参与拦截；上方风险评分已按"可疑"档展示。'
                                  '</small></div>')
            elif not blocked:
                ml_block_html += ('<div class="alert alert-warning py-2 mt-2 mb-0">'
                                  '<small>⚠ 模型高置信判定为恶意，但当前配置不参与拦截（仅提示）；'
                                  '建议人工复核后再访问。</small></div>')


    html = f'''
    <div class="card border-{risk_class} mb-4">
        <div class="card-header bg-{bg_class} {header_text_class} d-flex justify-content-between align-items-center gap-2">
            <h5 class="mb-0">
                {"🔴 检测结果 - 恶意链接" if is_malicious else "🟢 检测结果 - 安全链接"}
            </h5>
            <span class="ui-mascot-badge">{render_mascot(56, 'shield' if is_malicious else 'search')}</span>
        </div>
        <div class="card-body">
            <h6 class="card-title">{render_icon('link', 16, '链接')} 检测URL</h6>
            <p class="text-break">
                <a href="javascript:void(0)" class="{link_class}" {guard_attrs}>{url_text}</a>
                {blocked_badge}
            </p>
            {blocked_hint}
            
            <!-- 全宽度风险评分大横条 -->
            <div class="mb-4">
                <h6 class="mb-2">{render_icon('chart', 18, '评分')} 风险评分</h6>
                <div class="progress" style="height: 36px; border-radius: 18px; font-size: 16px; font-weight: bold; overflow: hidden;">
                    <div class="progress-bar bg-{risk_class} d-flex align-items-center justify-content-center" 
                         role="progressbar" 
                         style="{bar_style}" 
                         aria-valuenow="{display_score}" 
                         aria-valuemin="0" 
                         aria-valuemax="100">
                        {risk_text} · {display_score}/100
                    </div>
                </div>
            </div>
            
            <div class="row">
                <div class="col-md-6">
                    <h6>ℹ️ 基本信息</h6>
                    <ul class="list-unstyled">
                        <li><strong>域名:</strong> {domain_text}</li>
                        <li><strong>风险等级:</strong> <span class="{level_span_class} fw-bold">{result.risk_level}</span></li>
                        <li><strong>是否命中黑名单:</strong> {"是" if result.blacklist_match else "否"}</li>
                        <li><strong>时间:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</li>
                    </ul>
                </div>
                <div class="col-md-6">
                    <h6>{render_icon('robot', 16, 'AI')} AI分析</h6>
                    <ul class="list-unstyled">
                        <li><strong>DeepSeek增强:</strong> {"已启用 " + ai_mark if deepseek_used else "未启用"}</li>
                        <li><strong>检测方式:</strong> 启发式分析 + AI大模型</li>
                    </ul>
                </div>
            </div>
            {ml_block_html}

            
            {get_details_html(result.details)}
    '''
    
    if is_malicious:
        html += f'''
            <div class="alert alert-danger mt-3" role="alert">
                <strong>{render_icon('shield', 18, '警告')} 警告! 这很可能是一个恶意链接，点击将被自动拦截！</strong><br>
                <small>拦截原因：{html_escape(block_reason)}。它可能是钓鱼网站、诈骗网站或包含恶意软件。</small><br>
                <small>点击上方 URL 只会显示拦截提示、不会跳转；确需访问时需在提示中二次确认（不推荐）。</small>
            </div>
        '''

    else:
        html += f'''
            <div class="alert alert-success mt-3" role="alert">
                <strong>{render_icon('check', 18, '安全')} 安全!</strong> 该链接未检测出明显的恶意特征，但仍建议你保持警惕。
            </div>
        '''
    
    html += '''
        </div>
    </div>
    '''
    
    return html

def get_details_html(details):
    """生成详情HTML"""
    if not details:
        return '<p class="mt-3">未发现异常特征。</p>'
    
    html = '''
    <div class="mt-4">
        <h6>{icon} 检测详情</h6>
        <ul class="list-group mt-2">
    '''.format(icon=render_icon('search', 18, '详情'))
    
    # 按内容自动上色, 并把行首的 ✅ / ⚠ 换成二次元风格图标
    # (ℹ、⛔、🤖 暂无对应图标, 保留原符号):
    # 1) 先判断 ✅ —— 有些"通过"文案里也会出现"风险"二字
    #    (例如"✅ 顶级域名 .com 不在高风险域名名单中"), 不能据此判成警告;
    # 2) 图标是代码自己插入的 <img>, 因此只对剩余文本做 HTML 转义。
    for detail in details:
        raw = str(detail)
        if raw.startswith('✅'):
            cls = 'list-group-item-success'
            safe = str(render_icon('check', 14, '通过')) + ' ' + html_escape(raw[1:].lstrip())
        elif raw.startswith('⚠'):
            cls = 'list-group-item-warning'
            rest = raw[1:]
            if rest.startswith('\ufe0f'):     # 去掉 emoji 变体选择符
                rest = rest[1:]
            safe = str(render_icon('warning', 14, '提示')) + ' ' + html_escape(rest.lstrip())
        else:
            cls = ('list-group-item-warning' if ('⛔' in raw or '⚠' in raw or '风险' in raw)
                   else 'list-group-item-info')
            safe = html_escape(raw)
        html += '<li class="list-group-item {0}">{1}</li>'.format(cls, safe)
    
    html += '''
        </ul>
    </div>
    '''
    
    return html

@app.route('/report')
def report():
    """检测报告页面"""
    stats = detector.reporter.get_statistics()
    recent = detector.reporter.get_recent_detections(20)
    return render_template('report.html', stats=stats, recent=recent, 
                          get_risk_class=get_risk_class, get_risk_badge=get_risk_badge)

@app.route('/blacklist')
def blacklist():
    """黑名单管理页面

    列表规则: 用户手动添加的条目置顶显示(最新在最前), 其余维持原有顺序;
    模板用 user_added 给这些条目打上"📌 手动添加"标记。
    """
    blacklist = detector.get_blacklist(1000)
    return render_template('blacklist.html', blacklist=blacklist,
                           count=detector.get_blacklist_count(),
                           user_added=detector.get_user_added_urls())

@app.route('/blacklist/add', methods=['POST'])
def blacklist_add():
    """手动添加黑名单(新规则: 置顶 + 与黑名单原有条目比较后给出提示)"""
    url = request.form.get('url', '').strip()
    if not url:
        flash('请输入要添加的URL', 'warning')
        return redirect(url_for('blacklist'))

    result = detector.add_to_blacklist(url)

    if result.get("duplicate"):
        dup = result["duplicate"]
        flash('该链接已在黑名单中（匹配方式：{}，条目：{}），已将它置顶显示，未重复写入。'.format(
            dup["level"], dup["entry"][:120]), 'info')
    else:
        flash('✅ 已添加到黑名单并置顶：{}'.format(result["entry"][:120]), 'success')

    same_host = result.get("same_host_count") or 0
    if same_host:
        flash('⚠ 同一域名下已收录 {} 条记录，请确认是否为重复录入。'.format(same_host), 'warning')
    similar = result.get("similar") or []
    if similar:
        lines = "；".join('{}（{}）'.format(item["entry"][:90], item["reason"]) for item in similar[:3])
        flash('🔍 与已有条目相似（共 {} 条）：{}'.format(len(similar), lines), 'secondary')

    return redirect(url_for('blacklist'))

@app.route('/blacklist/import_feed', methods=['POST'])
def blacklist_import_feed():
    """从公开源导入黑名单"""
    results = detector.import_from_public_feeds()
    total = sum(v for v in results.values() if v > 0)
    return jsonify({'success': True, 'total': total, 'details': results})

@app.route('/blacklist/import_seed', methods=['POST'])
def blacklist_import_seed():
    """导入种子黑名单"""
    count = detector.import_seed_blacklist()
    return jsonify({'success': True, 'count': count})

@app.route('/blacklist/import_file', methods=['POST'])
def blacklist_import_file():
    """从上传的文件导入黑名单"""
    if 'file' not in request.files:
        return jsonify({'success': False, 'count': 0})
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'count': 0})
    
    content = file.read().decode('utf-8', errors='ignore')
    urls = [line.strip() for line in content.split('\n') if line.strip() and not line.startswith('#')]
    count = detector.import_blacklist_from_urls(urls)
    return jsonify({'success': True, 'count': count})

@app.route('/blacklist/remove', methods=['POST'])
def blacklist_remove():
    """从黑名单移除"""
    url = request.form.get('url', '').strip()
    if url:
        detector.remove_from_blacklist(url)
    return redirect(url_for('blacklist'))

# ========== 黑名单查询 / 一键移除(新增, 纯 AJAX 接口, 不影响既有页面与逻辑) ==========
@app.route('/blacklist/lookup')
def blacklist_lookup():
    """查询某个链接是否在黑名单中

    复用 detector.lookup_blacklist() 的多级匹配(精确/规范化/忽略协议/忽略查询参数/父路径/域名),
    并附带"同域名下的其它条目"; 只读, 不修改黑名单。
    """
    url = (request.args.get('url') or '').strip()
    if not url:
        return jsonify({'success': False, 'error': '请输入要查询的链接'})
    info = detector.lookup_blacklist(url)
    info['success'] = True
    return jsonify(info)

@app.route('/blacklist/remove_entry', methods=['POST'])
def blacklist_remove_entry():
    """按查询结果里的"条目原文"移除黑名单条目(AJAX)"""
    entry = (request.form.get('entry') or '').strip()
    res = detector.remove_blacklist_entry(entry)
    res['success'] = bool(res.get('removed'))
    if not res.get('success'):
        res['error'] = res.get('reason') or '移除失败'
    return jsonify(res)

@app.route('/settings')
def settings():
    """设置页面

    使用 config.public_config 渲染：DeepSeek 等敏感密钥在 Web 端只显示掩码，
    不显示明文，页面上也不出现任何"如何配置密钥"的提示文案（相关说明仅写在代码注释里）。

    DeepSeek 密钥仅支持在服务端配置（优先级从高到低）：
      1. 环境变量 DEEPSEEK_API_KEY —— 优先级最高，密钥不落盘（推荐）
      2. config.json 中的 api_keys.deepseek
      3. 命令行运行 python main.py，进入「系统设置 → 9」输入
    """
    return render_template('settings.html', config=config.public_config)

@app.route('/whitelist')
def whitelist():
    """白名单管理页面"""
    whitelist = detector.get_whitelist(500)
    return render_template('whitelist.html', whitelist=whitelist, count=detector.get_whitelist_count())

@app.route('/whitelist/add', methods=['POST'])
def whitelist_add():
    """添加到白名单"""
    url = request.form.get('url', '').strip()
    if url:
        detector.add_to_whitelist(url)
    return redirect(url_for('whitelist'))

@app.route('/whitelist/remove', methods=['POST'])
def whitelist_remove():
    """从白名单移除"""
    url = request.form.get('url', '').strip()
    if url:
        detector.remove_from_whitelist(url)
    return redirect(url_for('whitelist'))

@app.route('/settings/update', methods=['POST'])
def settings_update():
    """更新设置"""
    data = request.form.to_dict()
    
    # 更新检测设置
    config.set('enable_heuristic' in data, 'detection', 'enable_heuristic')
    config.set('enable_blacklist' in data, 'detection', 'enable_blacklist')
    config.set('enable_dns_check' in data, 'detection', 'enable_dns_check')
    config.set('enable_api_check' in data, 'detection', 'enable_api_check')
    
    try:
        threshold = int(data.get('heuristic_threshold', '60'))
        config.set(max(0, min(100, threshold)), 'detection', 'heuristic_threshold')
    except:
        pass
    
    try:
        interval = float(data.get('check_interval', '1.0'))
        config.set(max(0.5, interval), 'monitoring', 'check_interval')
    except:
        pass
    
    config.set('auto_intercept' in data, 'monitoring', 'auto_intercept')
    config.set('enable_clipboard_monitor' in data, 'monitoring', 'enable_clipboard_monitor')
    
    # API keys
    # 设置页已移除 Google Safe Browsing / VirusTotal 的输入框，密钥统一只在服务端维护
    # （config.json 或 main.py 的命令行设置），因此忽略表单中的这些字段，
    # 避免保存设置时把服务端已配置的密钥覆盖成空值。
    for key in ('google_safe_browsing', 'virustotal'):
        if key in data:
            print(f"[Web] 已忽略来自Web端的 {key} 密钥修改请求（请在服务端配置）")

    if 'deepseek' in data:
        print("[Web] 已忽略来自Web端的 DeepSeek 密钥修改请求（请在服务端配置）")

    return redirect(url_for('settings'))

@app.route('/export/csv')
def export_csv():
    """导出CSV"""
    detector.reporter.export_csv('detection_export.csv')
    return redirect(url_for('report'))

# =============================================================================
# 拦截控制台（guard 拦截层）—— 在页面上点「开始拦截」才真正开始拦
# -----------------------------------------------------------------------------
# 改动约束（保持最小侵入）:
#   * 这里只是「调用」guard: 判定逻辑、拦截数据、开关状态全在 guard\ 目录内;
#     eyilianjie 自己的检测 / 黑名单 / 白名单 / 日志逻辑一行未改;
#   * guard\ 不存在时, 整个控制台自动降级（页面给出提示, 其它功能完全不受影响）;
#   * 拦截层没启动时, 点「开始拦截」会在**本进程内按需启动**它（复用同一个
#     detector 实例, 所以「检测即真封」照样生效）, 不需要重启本服务;
#   * 读接口不限来源; 写接口只接受本机(127.0.0.1/::1) 且必须带自定义请求头 +
#     JSON 请求体（跨站表单无法伪造自定义头, 因此挡住本机 CSRF）。
# =============================================================================
GUARD_WRITE_HEADER = 'X-Guard-Request'

_guard_runtime = None
_guard_error = ''


def attach_guard(runtime):
    """由 run_guarded.py 调用: 把已经启动好的 guard 运行时交给 Web 使用"""
    global _guard_runtime, _guard_error
    _guard_runtime = runtime
    _guard_error = ''
    return runtime


def guarantee_guard():
    """拿到 guard 运行时; 没有就在本进程内启动一个（懒启动, 只启动一次）

    注意: 如果本机 8899 上已经有一份 guard 在跑（别处启动的）, 这里**不再启第二份**
    —— 否则两边会抢 8888/8899 端口, 结果是"控制台/代理都没绑上"的半残运行时
    （页面显示已开启, 实际什么都没拦）。此时返回 None, 由调用方把请求转发给那一份
    （见 _guard_forward / _guard_remote_base）。
    """
    global _guard_runtime, _guard_error
    if _guard_runtime is not None:
        return _guard_runtime
    try:
        from guard.settings import load as _load_guard_settings
        if _guard_api_alive(_load_guard_settings()):
            _guard_error = '本机已有 guard 在运行（%s），本进程不重复启动' % (
                _guard_remote_base() or '127.0.0.1:8899')
            return None
    except Exception:
        pass
    try:
        from guard.runtime import GuardRuntime
    except Exception as exc:
        _guard_error = '拦截层不可用（找不到 guard 模块）: {}'.format(exc)
        return None
    try:
        _ensure_detector()          # 保证 guard 复用到已加载的 detector
        runtime = GuardRuntime(detector=detector, verbose=STARTUP_VERBOSE)
        for name, (ok, msg) in runtime.start(enable_sysproxy=False).items():
            _startup_log('[guard] {:<9} {}'.format(name + ':', msg))
        runtime.patch_detector(detector)      # 检测即真封
        _guard_runtime = runtime
        _guard_error = ''
        return runtime
    except Exception as exc:
        _guard_error = '拦截层启动失败: {}'.format(exc)
        print('[guard] ' + _guard_error)
        return None


def _guard_write_allowed():
    """写接口守卫: 仅本机 + 自定义头 + JSON 体"""
    if (request.remote_addr or '') not in ('127.0.0.1', '::1'):
        return False, '只允许在本机(127.0.0.1)操作拦截开关'
    if request.headers.get(GUARD_WRITE_HEADER) != '1':
        return False, '缺少 {} 请求头（跨站请求会被拒绝）'.format(GUARD_WRITE_HEADER)
    if not request.is_json:
        return False, '请使用 JSON 提交'
    return True, ''


def _guard_remote_base():
    """独立 guard 控制台的地址（默认 127.0.0.1:8899）

    允许用 app.config['GUARD_REMOTE_BASE'] 覆盖（自测 / 调试用）。
    """
    override = app.config.get('GUARD_REMOTE_BASE')
    if override:
        return str(override).rstrip('/')
    try:
        from guard.settings import load as _load_guard_settings
        conf = _load_guard_settings()
    except Exception:
        return None
    host = str(conf.get("api.host", "127.0.0.1") or "127.0.0.1")
    try:
        port = int(conf.get("api.port", 8899) or 8899)
    except (TypeError, ValueError):
        port = 8899
    return "http://%s:%d" % (host, port)


def _guard_forward(path, payload=None, query=None, timeout=5.0):
    """把 guard 请求转发给本机独立运行的 guard 控制台（默认 127.0.0.1:8899）

    为什么需要: 如果 8899 上已经有一份 guard 在跑, web_app 启动时不会再启一份
    （否则两边抢 8888/8899）, 这时 Web 端的 /guard/* 就"没有运行时" —— 页面上
    点【开始拦截】/【加入拦截】会直接失败。转给那一份, 网页操作才真正生效。

    写请求会带上自定义头 X-Guard-Request（guard 的写接口要求它，防止本机跨站伪造）。
    返回 (ok, data, error_text)。
    """
    import json as _json
    import urllib.request
    from urllib.parse import urlencode

    base = _guard_remote_base()
    if not base:
        return False, None, "找不到 guard 接口地址（guard 模块/配置不可用）"
    url = base + path
    if query:
        url += ("&" if "?" in url else "?") + urlencode(query)
    try:
        if payload is None:
            req = urllib.request.Request(url, method="GET")
        else:
            body = _json.dumps(payload, ensure_ascii=False).encode("utf-8")
            req = urllib.request.Request(
                url, data=body, method="POST",
                headers={"Content-Type": "application/json",
                         GUARD_WRITE_HEADER: "1"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read().decode("utf-8", "replace")
        return True, (_json.loads(text) if text.strip() else {}), ""
    except Exception as exc:
        return False, None, str(exc)


def _guard_state_payload(logs_limit=20):
    """统一的状态结构（guard 未运行时也能给出合理值）"""
    try:
        from guard import control
    except Exception as exc:
        return {'available': False, 'running': False, 'enabled': False, 'modes': [],
                'logs': [], 'counters': {},
                'error': _guard_error or '拦截层不可用: {}'.format(exc)}
    state = control.ui_state(_guard_runtime, logs_limit)
    state['available'] = True
    state['error'] = _guard_error
    return state


@app.route('/guard')
def guard_console():
    """拦截控制台页面（模板 templates/guard.html）

    顺便把 guard 目录下两个"客户端"的路径传给页面（油猴脚本 / Edge 扩展），
    方便你直接在页面上看到该选哪个目录去安装。
    """
    paths = {}
    try:
        from guard import GUARD_DIR
        paths = {
            "script": os.path.join(GUARD_DIR, "userscript", "eyilianjie_guard.user.js"),
            "extension": os.path.join(GUARD_DIR, "extension"),
            "extension_preview": os.path.join(GUARD_DIR, "extension", "preview.png"),
        }
    except Exception:
        pass
    return render_template('guard.html', guard_paths=paths)


@app.route('/guard/state')
def guard_state():
    """当前拦截状态 + 各「拦截方式」的勾选情况 + 最近记录（JSON）

    本进程没有 guard 运行时（例如 8899 上已经有一份在跑）→ 转发给那一份,
    这样页面显示的是"真正在拦截的那个 guard"的状态, 而不是一份空配置。
    """
    try:
        limit = int(request.args.get('logs') or 20)
    except ValueError:
        limit = 20
    state = _guard_state_payload(limit)
    if _guard_runtime is None:
        ok, payload, err = _guard_forward('/guard/state', query={'logs': limit})
        if ok and isinstance(payload, dict):
            payload['forwarded'] = True
            payload['forwarded_to'] = _guard_remote_base()
            return jsonify(payload)
        state['forward_error'] = err or '拦截层未启动'
    return jsonify(state)


@app.route('/guard/rules_version')
def guard_rules_version():
    """名单版本号（极轻接口，供浏览器扩展每次导航前比对）

    扩展发现版本变了就丢掉自己的判定缓存 —— 于是"在页面上刚加入拦截"之后,
    浏览器下一次访问立刻生效（不必等 60 秒缓存过期, 也不用再去别处输一遍）。
    """
    runtime = _guard_runtime
    if runtime is not None:
        try:
            return jsonify({'ok': True, 'rules_version': runtime.store.rules_version()})
        except Exception as exc:
            return jsonify({'ok': False, 'reason': str(exc)})
    ok_fwd, payload, err = _guard_forward('/guard/rules_version')
    if ok_fwd and isinstance(payload, dict):
        return jsonify(payload)
    return jsonify({'ok': False, 'reason': '拦截层不可用: %s' % err})


@app.route('/guard/apply', methods=['POST'])
def guard_apply():
    """★ 核心接口: 应用「开始/停止拦截」以及勾选的拦截方式（立刻生效）"""
    ok, reason = _guard_write_allowed()
    if not ok:
        return jsonify({'ok': False, 'reason': reason}), 403
    data = request.get_json(silent=True) or {}
    want_on = str(data.get('enabled', '')).strip().lower() in ('1', 'true', 'on', 'yes')
    runtime = _guard_runtime
    if runtime is None and want_on:
        runtime = guarantee_guard()          # 懒启动: 第一次点「开始拦截」时启动
    if runtime is None:
        # 本机已有 guard 在跑（或本进程启动失败）→ 转发给那一份的 /guard/config
        ok_fwd, payload, err = _guard_forward('/guard/config', data)
        if ok_fwd and isinstance(payload, dict):
            payload['forwarded'] = True
            payload['forwarded_to'] = _guard_remote_base()
            return jsonify(payload)
        return jsonify({'ok': False,
                        'reason': '%s（转发到 %s 也失败: %s）' % (
                            _guard_error or '拦截层不可用',
                            _guard_remote_base() or '127.0.0.1:8899', err),
                        'state': _guard_state_payload()}), 503
    from guard import control
    ok, message, state = control.apply(runtime, data, enable_sysproxy=True)
    return jsonify({'ok': bool(ok), 'message': message,
                    'state': state or _guard_state_payload()})


@app.route('/guard/sysproxy', methods=['POST'])
def guard_sysproxy():
    """单独控制「系统代理指向 guard / 还原」（不动其它开关）"""
    ok, reason = _guard_write_allowed()
    if not ok:
        return jsonify({'ok': False, 'reason': reason}), 403
    data = request.get_json(silent=True) or {}
    enable = str(data.get('enable', '')).strip().lower() in ('1', 'true', 'on', 'yes')
    runtime = _guard_runtime
    if runtime is None and enable:
        runtime = guarantee_guard()
    if runtime is None:
        ok_fwd, payload, err = _guard_forward('/guard/sysproxy', data)
        if ok_fwd and isinstance(payload, dict):
            payload['forwarded'] = True
            return jsonify(payload)
        return jsonify({'ok': False,
                        'reason': '%s（转发到 %s 也失败: %s）' % (
                            _guard_error or '拦截层不可用',
                            _guard_remote_base() or '127.0.0.1:8899', err)}), 503
    ok, msg = (runtime.proxyctl.enable() if enable else runtime.proxyctl.disable())
    runtime.settings.set("block_via_proxy", bool(enable), save=True)   # 同步"意图"开关
    runtime.engine.invalidate()
    return jsonify({'ok': bool(ok), 'message': msg, 'state': _guard_state_payload()})


@app.route('/guard/entry', methods=['POST'])
def guard_entry():
    """动态拦截集 / 放行名单的增删（action=block|allow|remove|remove_allow|clear_dynamic）"""
    ok, reason = _guard_write_allowed()
    if not ok:
        return jsonify({'ok': False, 'reason': reason}), 403
    data = request.get_json(silent=True) or {}
    # 没有运行时不再直接报错: 先按需启动（不必先去点【开始拦截】）, 再转发给 8899 那一份
    runtime = _guard_runtime or guarantee_guard()
    if runtime is None:
        ok_fwd, payload, err = _guard_forward('/guard/entry', data)
        if ok_fwd and isinstance(payload, dict):
            payload['forwarded'] = True
            return jsonify(payload)
        return jsonify({'ok': False,
                        'reason': '拦截层不可用（%s），且无法连接本机 guard 控制台: %s'
                                  % (_guard_error or '本进程内启动失败', err)}), 503
    from guard import control
    ok, message = control.entry(runtime, (data.get('action') or '').strip(),
                                (data.get('url') or '').strip())
    return jsonify({'ok': bool(ok), 'message': message,
                    'state': _guard_state_payload() if ok else None})


@app.route('/guard/check')
def guard_check():
    """页面里的「手测一个 URL」: 纯本地判定（不联网, 不写 eyilianjie 的检测日志）"""
    url = (request.args.get('url') or '').strip()
    mode = (request.args.get('mode') or 'url').strip().lower()
    if not url:
        return jsonify({'ok': False, 'reason': '请输入 URL'})
    runtime = _guard_runtime
    if runtime is None and request.args.get('start'):
        runtime = guarantee_guard()
    if runtime is None:
        ok_fwd, payload, err = _guard_forward('/guard/check',
                                              query={'url': url, 'mode': mode})
        if ok_fwd and isinstance(payload, dict):
            payload['forwarded'] = True
            return jsonify(payload)
        return jsonify({'ok': False,
                        'reason': '拦截层不可用，且无法连接本机 guard 控制台: %s' % err})
    decision = runtime.engine.judge(url, mode=('host' if mode == 'host' else 'url'))
    return jsonify({'ok': True, 'decision': decision})


@app.route('/guard/logs')
def guard_logs():
    """最近的拦截 / 放行记录（JSON）"""
    try:
        limit = int(request.args.get('limit') or 50)
    except ValueError:
        limit = 50
    runtime = _guard_runtime
    if runtime is None:
        ok_fwd, payload, err = _guard_forward('/guard/logs', query={'limit': limit})
        if ok_fwd and isinstance(payload, dict):
            payload['forwarded'] = True
            return jsonify(payload)
        return jsonify({'ok': True, 'logs': _guard_state_payload(limit).get('logs') or []})
    return jsonify({'ok': True, 'logs': runtime.store.recent_logs(limit)})


def _guard_api_alive(conf, timeout=0.8):
    """本机是否已经有一个 guard 控制台在跑（避免重复启动抢 8888/8899）"""
    try:
        import urllib.request
        url = "http://%s:%s/guard/status" % (conf.get("api.host", "127.0.0.1"),
                                            conf.get("api.port", 8899))
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.getcode() == 200
    except Exception:
        return False


def _guard_auto_start(debug, web_port=None):
    """按 guard 配置里的 auto_start 自动把拦截层拉起来（返回 runtime 或 None）。

    目的: 让"照旧运行 python web_app.py"就等于带拦截运行 —— 不用再点 .bat。

    关键点:
      * Werkzeug 的 reloader: debug=True 时会 fork 出父/子两个进程, 只有真正跑服务的
        那个（环境变量 WERKZEUG_RUN_MAIN=true）才启动 guard, 否则会启动两份抢端口;
      * 不接管系统代理: 仍然要在网页「拦截」里点【开始拦截】才真正开始拦;
      * 失败绝不影响 Web: 任何异常都只打印一行提示;
      * 关闭方式: guard\\data\\config.json 里 auto_start=false。
    """
    if _guard_runtime is not None:          # run_guarded.py 已经挂好了, 直接复用
        return _guard_runtime
    if debug and os.environ.get("WERKZEUG_RUN_MAIN") != "true":
        return None                          # 这是 reloader 的父进程: 交给子进程去做
    try:
        from guard.settings import load as _load_guard_settings
        conf = _load_guard_settings()
    except Exception as exc:
        print("[guard] 没找到 guard 模块, 跳过自动拦截（Web 端照常运行）: %s" % exc)
        return None

    if not bool(conf.get("auto_start", True)):
        _startup_log("[guard] auto_start=false: 本次不自动启动拦截层"
                     "（想开启: 把 guard\\data\\config.json 里的 auto_start 改成 true）")
        return None

    # 让 auto_start 这个键出现在配置文件里（可见/可编辑）——只写 guard 自己的配置
    try:
        conf.set("auto_start", bool(conf.get("auto_start", True)))
    except Exception:
        pass

    if _guard_api_alive(conf):
        _startup_log("[guard] 本机已有 guard 在运行（%s:%s）, 本次不重复启动；"
                     "请在那一份的控制台里操作" % (conf.get("api.host", "127.0.0.1"),
                                                 conf.get("api.port", 8899)))
        return None

    runtime = guarantee_guard()
    if runtime is None:
        print("[guard] 拦截层自动启动失败（不影响 Web 端）: %s" % (_guard_error or "未知原因"))
        return None
    _startup_log("[guard] 已随 Web 端自动启动拦截层: 本地代理 %s:%s · 控制台 http://%s:%s/"
                 % (conf.get("proxy.host"), conf.get("proxy.port"),
                    conf.get("api.host", "127.0.0.1"), conf.get("api.port", 8899)))
    if web_port:
        _startup_log("[guard] 想开始拦截: 打开 http://127.0.0.1:%d/ → 顶部导航栏「拦截」→ 点【开始拦截】"
                     % web_port)
    _startup_log("[guard] 不想让它自动启动: 把 guard\\data\\config.json 里的 auto_start 改成 false")
    return runtime


def run_web(host='0.0.0.0', port=DEFAULT_PORT, debug=True):
    """启动Web服务器

    顺带按 guard 配置里的 auto_start 自动把拦截层拉起来（默认开启）——
    于是"照旧运行 python web_app.py"就等于带拦截运行，不用再点 .bat。
    关闭方式：把 guard\\data\\config.json 里的 auto_start 改成 false。
    """
    # debug 模式下 Werkzeug 会启两个进程（reloader 父进程 + 真正服务的子进程）：
    #   * 横幅在脚本最顶部就已打印（这里只做兜底，避免重复）；
    #   * detector 只在"真正服务"的进程里加载（父进程跳过, 省 2~3 秒）。
    reloader_parent = bool(debug) and os.environ.get('WERKZEUG_RUN_MAIN') != 'true'
    if not reloader_parent:
        _print_banner_once(port)
        _ensure_detector()
        if STARTUP_VERBOSE:
            print(f"📊 系统信息: 黑名单 {len(detector._blacklist)} 条, 检测历史 {len(detector.reporter._logs)} 条", flush=True)
    runtime = _guard_auto_start(debug, web_port=port)
    if not reloader_parent:
        # 等真正能响应 HTTP 后再打印「✅ 就绪」（后台线程, 不阻塞启动）
        threading.Thread(target=_notify_ready_when_serving, args=(port, _READY_TOKEN),
                         name='ready-notify', daemon=True).start()
    try:
        app.run(host=host, port=port, debug=debug)
    finally:
        if runtime is not None:
            try:
                runtime.stop()          # 正常退出（含 Ctrl+C）时把系统代理还原
            except Exception as exc:
                print("[guard] 退出清理出错（可执行 python -m guard sysproxy off 兜底）: %s" % exc)

if __name__ == '__main__':
    run_web()