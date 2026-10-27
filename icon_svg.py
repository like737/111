"""二次元风格 SVG 图标（单一来源）。

设计参考：深海军蓝夜空 + 青蓝能量刃 + 冰晶碎片 + 品红细线 + 狐耳萌点。
所有图标共用 24×24 视口、圆头圆角描边、左上主光 / 右下轮廓光的统一光向。

同一份定义同时供：
  - Jinja 模板：{{ icon('search', 18, '检测') }}
  - 后端结果 HTML：web_app.render_icon('shield', 16, '拦截')
这样页面图标与检测结果里的图标不会出现两套风格。

约束：
  - 不使用 <defs>/<filter>/渐变 id，避免同一页面多次内联时 id 冲突；
  - 发光用“叠层描边 + 低透明度”实现，不依赖滤镜；
  - 纯矢量、无位图、无外部依赖。
"""

from html import escape as _escape

from markupsafe import Markup

# 统一色板（与 base.html 的 --ui-* 设计令牌一致）
_NAVY = "#0B1020"
_CYAN = "#22D3EE"
_BLUE = "#38BDF8"
_ICE = "#7DD3FC"
_WHITE = "#E0F2FE"
_PINK = "#F472B6"
_GOLD = "#FBBF24"
_RED = "#F43F5E"
_WARN = "#F87171"
_GREEN = "#34D399"

# 每个图标只放“符号层”，外层 <svg> 由 render_icon 统一生成
_BODIES = {
    # 检测：能量放大镜 + 镜片里的红瞳（狐耳少女的萌点）+ 发带点缀
    "search": (
        f'<circle cx="10.5" cy="10.5" r="6.4" stroke="{_NAVY}" stroke-width="4.6" opacity=".18"/>'
        f'<circle cx="10.5" cy="10.5" r="6.4" stroke="{_CYAN}" stroke-width="2.2"/>'
        f'<path d="M5.9 7.7a5.1 5.1 0 0 1 3.6-2.3" stroke="{_WHITE}" stroke-width="1.2" opacity=".95"/>'
        f'<path d="M15.4 15.4 20.4 20.4" stroke="{_NAVY}" stroke-width="4.6" opacity=".18"/>'
        f'<path d="M15.4 15.4 20.4 20.4" stroke="{_BLUE}" stroke-width="2.4"/>'
        f'<path d="M16.3 15.5 19.3 18.5" stroke="{_WHITE}" stroke-width="1" opacity=".8"/>'
        f'<ellipse class="ui-eye" cx="10.5" cy="10.9" rx="1.8" ry="1.2" fill="{_RED}"/>'
        '<circle cx="10.9" cy="10.5" r=".42" fill="#FFFFFF"/>'
        f'<path d="M17.6 5.2l.5 1.4 1.4.5-1.4.5-.5 1.4-.5-1.4-1.4-.5 1.4-.5z" fill="{_WHITE}" opacity=".9"/>'
        f'<path d="M3.1 20.7l1.2-2.4 1.2 2.4-1.2-1z" fill="{_PINK}" opacity=".9"/>'
    ),
    # 报告：冰晶发簪柱状图 + 柱顶狐耳 + 星芒
    "chart": (
        f'<path d="M3.6 20.2h16.8" stroke="{_NAVY}" stroke-width="3.4" opacity=".16"/>'
        f'<path d="M3.6 20.2h16.8" stroke="{_BLUE}" stroke-width="1.6" opacity=".9"/>'
        f'<rect x="4.6" y="13.2" width="3.8" height="7" rx="1.3" fill="{_ICE}" opacity=".85" stroke="{_CYAN}" stroke-width="1"/>'
        f'<rect x="10.1" y="9.6" width="3.8" height="10.6" rx="1.3" fill="{_BLUE}" opacity=".9" stroke="{_CYAN}" stroke-width="1"/>'
        f'<rect x="15.6" y="5.6" width="3.8" height="14.6" rx="1.3" fill="#0EA5E9" opacity=".95" stroke="{_CYAN}" stroke-width="1"/>'
        f'<path d="M15.9 6.2v2.2M10.4 10.2v2.2M4.9 13.8v2.2" stroke="{_WHITE}" stroke-width="1" opacity=".85"/>'
        f'<path d="M15.2 5.4l1.1-1.9 1.1 1.9" fill="#132A4A" stroke="{_BLUE}" stroke-width=".9"/>'
        f'<path d="M18.6 3.2l.45 1.25 1.25.45-1.25.45-.45 1.25-.45-1.25-1.25-.45 1.25-.45z" fill="{_WHITE}" opacity=".9"/>'
        f'<path d="M19.9 9.4l.3.8.8.3-.8.3-.3.8-.3-.8-.8-.3.8-.3z" fill="{_PINK}" opacity=".85"/>'
    ),
    # 白名单 / 成功：光刃对勾 + 星芒
    "check": (
        f'<path d="M4.6 12.4l4.8 4.9 9.9-11" stroke="{_NAVY}" stroke-width="4.4" opacity=".16"/>'
        f'<path d="M4.6 12.4l4.8 4.9 9.9-11" stroke="{_GREEN}" stroke-width="2.6"/>'
        f'<path d="M5.4 12.4l3.9 4 8.9-9.8" stroke="{_WHITE}" stroke-width="1" opacity=".95"/>'
        f'<path d="M19.4 4.2l.5 1.35 1.35.5-1.35.5-.5 1.35-.5-1.35-1.35-.5 1.35-.5z" fill="{_WHITE}"/>'
        f'<circle cx="20" cy="8.2" r=".9" fill="{_ICE}" opacity=".8"/>'
    ),
    # 拦截：冰晶盾 + 盾后狐耳 + 中心对勾高光
    "shield": (
        f'<path d="M7 3.4l1.4-2.2 1.2 2" fill="#132A4A" stroke="{_BLUE}" stroke-width="1"/>'
        f'<path d="M17 3.4l-1.4-2.2-1.2 2" fill="#132A4A" stroke="{_BLUE}" stroke-width="1"/>'
        f'<path d="M12 2.6 20 5.6v5.9c0 5-3.5 8.3-8 10-4.5-1.7-8-5-8-10V5.6z" fill="{_NAVY}" opacity=".32"/>'
        f'<path d="M12 2.6 20 5.6v5.9c0 5-3.5 8.3-8 10-4.5-1.7-8-5-8-10V5.6z" stroke="{_CYAN}" stroke-width="2.2"/>'
        f'<path d="M12 2.6 20 5.6v5.9c0 5-3.5 8.3-8 10" stroke="{_BLUE}" stroke-width="1" opacity=".75"/>'
        f'<path d="M8.3 12.2l2.6 2.7 4.9-5.4" stroke="{_WHITE}" stroke-width="1.8"/>'
        f'<path d="M12 4.6l.4 1.1 1.1.4-1.1.4-.4 1.1-.4-1.1-1.1-.4 1.1-.4z" fill="{_WHITE}" opacity=".85"/>'
    ),
    # 品牌 / 锁：水晶锁体 + 狐耳 + 金色钥匙孔
    "lock": (
        f'<path d="M8.3 10.4V8.1a3.7 3.7 0 0 1 7.4 0v2.3" stroke="{_NAVY}" stroke-width="4.2" opacity=".16"/>'
        f'<path d="M8.3 10.4V8.1a3.7 3.7 0 0 1 7.4 0v2.3" stroke="{_BLUE}" stroke-width="2.2"/>'
        f'<rect x="5.4" y="10.2" width="13.2" height="9.8" rx="2.6" fill="{_NAVY}" opacity=".34"/>'
        f'<rect x="5.4" y="10.2" width="13.2" height="9.8" rx="2.6" stroke="{_CYAN}" stroke-width="2"/>'
        f'<circle cx="12" cy="14.2" r="1.5" fill="{_GOLD}"/>'
        f'<path d="M12 15.3v2.1" stroke="{_GOLD}" stroke-width="1.5"/>'
        f'<path d="M7.2 12.2h2.2" stroke="{_WHITE}" stroke-width="1" opacity=".8"/>'
        f'<path d="M7.6 6.1 6.5 3.9l2.3.7M16.4 6.1l1.1-2.2-2.3.7" fill="#132A4A" stroke="{_BLUE}" stroke-width="1"/>'
    ),
    # 历史 / 最近检测：数据终端面板 + 金色夹扣
    "clipboard": (
        f'<rect x="5.6" y="4.4" width="12.8" height="16" rx="2.4" fill="{_NAVY}" opacity=".3"/>'
        f'<rect x="5.6" y="4.4" width="12.8" height="16" rx="2.4" stroke="{_CYAN}" stroke-width="2"/>'
        f'<rect x="9.2" y="3" width="5.6" height="3.2" rx="1.1" fill="{_GOLD}" stroke="{_NAVY}" stroke-width=".8"/>'
        f'<path d="M8.6 9.4h6.8M8.6 12.4h6.8M8.6 15.4h4.6" stroke="{_ICE}" stroke-width="1.2" opacity=".9"/>'
        f'<path d="M17.2 17.2l1.6 1.6-1.6 1.6" stroke="{_PINK}" stroke-width="1" opacity=".8"/>'
    ),
    # 公开源：全息线框地球 + 星芒
    "globe": (
        f'<circle cx="12" cy="12" r="8.2" stroke="{_NAVY}" stroke-width="3.8" opacity=".16"/>'
        f'<circle cx="12" cy="12" r="8.2" stroke="{_CYAN}" stroke-width="2"/>'
        f'<ellipse cx="12" cy="12" rx="3.4" ry="8.2" stroke="{_BLUE}" stroke-width="1.1" opacity=".85"/>'
        f'<path d="M4.6 9.6h14.8M4.6 14.4h14.8" stroke="{_ICE}" stroke-width="1" opacity=".8"/>'
        f'<path d="M11.4 6.6a6.4 6.4 0 0 1 0 10.8" stroke="{_WHITE}" stroke-width="1" opacity=".55"/>'
        f'<path d="M19.2 3.8l.45 1.2 1.2.45-1.2.45-.45 1.2-.45-1.2-1.2-.45 1.2-.45z" fill="{_WHITE}"/>'
    ),
    # 警告：能量警戒三角 + 金色感叹号
    "warning": (
        f'<path d="M12 3.4 21 19.6H3z" fill="{_NAVY}" opacity=".3"/>'
        f'<path d="M12 3.4 21 19.6H3z" stroke="{_CYAN}" stroke-width="2.2"/>'
        f'<path d="M12 8.2v5.2" stroke="{_GOLD}" stroke-width="2.2"/>'
        f'<circle cx="12" cy="16.6" r="1.1" fill="{_GOLD}"/>'
        f'<path d="M6.4 17.2l1.6-2.9" stroke="{_PINK}" stroke-width=".9" opacity=".8"/>'
    ),
    # 链接：光链环 + 品红发带结
    "link": (
        f'<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" stroke="{_NAVY}" stroke-width="3.8" opacity=".16"/>'
        f'<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" stroke="{_CYAN}" stroke-width="2"/>'
        f'<path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" stroke="{_NAVY}" stroke-width="3.8" opacity=".16"/>'
        f'<path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" stroke="{_BLUE}" stroke-width="2"/>'
        f'<path d="M11.9 12.1l-2.2-1.4v2.9z" fill="{_PINK}" opacity=".9"/>'
        f'<path d="M12.1 11.9l2.2 1.4v-2.9z" fill="{_PINK}" opacity=".9"/>'
    ),
    # 黑名单：断裂冰环 + 品红光刃 + 压耳情绪
    "ban": (
        f'<circle cx="12" cy="12" r="8.4" stroke="{_NAVY}" stroke-width="3.8" opacity=".18"/>'
        f'<circle cx="12" cy="12" r="8.4" stroke="{_WARN}" stroke-width="2.2" stroke-dasharray="36 7 10 7"/>'
        f'<path d="M6.4 6.4 17.6 17.6" stroke="{_RED}" stroke-width="2.4"/>'
        f'<path d="M7.2 7.2l9.6 9.6" stroke="{_WHITE}" stroke-width=".9" opacity=".65"/>'
        f'<path d="M18.8 2.8l.45 1.2 1.2.45-1.2.45-.45 1.2-.45-1.2-1.2-.45 1.2-.45z" fill="{_PINK}" opacity=".9"/>'
    ),
    # 失败 / 关闭：红叉 + 星芒（与白名单对勾成对）
    "cross": (
        f'<path d="M6.2 6.2 17.8 17.8" stroke="{_NAVY}" stroke-width="4" opacity=".18"/>'
        f'<path d="M6.2 6.2 17.8 17.8" stroke="{_WARN}" stroke-width="2.4"/>'
        f'<path d="M17.8 6.2 6.2 17.8" stroke="{_NAVY}" stroke-width="4" opacity=".18"/>'
        f'<path d="M17.8 6.2 6.2 17.8" stroke="{_WARN}" stroke-width="2.4"/>'
        f'<path d="M17.8 3.4l.4 1.1 1.1.4-1.1.4-.4 1.1-.4-1.1-1.1-.4 1.1-.4z" fill="{_WHITE}" opacity=".85"/>'
    ),
    # 设置：金色扣具齿轮 + 品红刻度环
    "gear": (
        f'<circle cx="12" cy="12" r="3.1" fill="{_GOLD}" opacity=".95"/>'
        f'<circle cx="12" cy="12" r="3.1" stroke="{_NAVY}" stroke-width=".9"/>'
        f'<circle cx="12" cy="12" r="6.9" stroke="{_NAVY}" stroke-width="3.6" opacity=".16"/>'
        f'<circle cx="12" cy="12" r="6.9" stroke="{_CYAN}" stroke-width="2.2"/>'
        f'<path d="M12 5.1v-2.4M12 21.3v-2.4M5.1 12H2.7M21.3 12h-2.4M7.1 7.1 5.4 5.4M18.6 18.6l-1.7-1.7M16.9 7.1l1.7-1.7M5.4 18.6l1.7-1.7" stroke="{_BLUE}" stroke-width="2"/>'
        f'<circle cx="12" cy="12" r="9" stroke="{_PINK}" stroke-width=".8" opacity=".55"/>'
    ),
    # 监控设置：显示器 + 品红星芒
    "monitor": (
        f'<rect x="3.4" y="4.6" width="17.2" height="12" rx="2" fill="{_NAVY}" opacity=".3"/>'
        f'<rect x="3.4" y="4.6" width="17.2" height="12" rx="2" stroke="{_CYAN}" stroke-width="2"/>'
        f'<path d="M8 20.4h8M12 16.8v3.6" stroke="{_BLUE}" stroke-width="2"/>'
        f'<path d="M6.6 8.4h5.2" stroke="{_WHITE}" stroke-width="1" opacity=".8"/>'
        f'<path d="M18 9.4l.4 1.1 1.1.4-1.1.4-.4 1.1-.4-1.1-1.1-.4 1.1-.4z" fill="{_PINK}" opacity=".9"/>'
    ),
    # API 密钥：金色钥匙 + 冷白高光
    "key": (
        f'<circle cx="8.4" cy="8.4" r="4.4" stroke="{_NAVY}" stroke-width="3.6" opacity=".16"/>'
        f'<circle cx="8.4" cy="8.4" r="4.4" stroke="{_GOLD}" stroke-width="2.2"/>'
        f'<path d="M11.6 11.6 20 20" stroke="{_NAVY}" stroke-width="3.6" opacity=".16"/>'
        f'<path d="M11.6 11.6 20 20" stroke="{_GOLD}" stroke-width="2.2"/>'
        f'<path d="M16.2 16.2l2.2 2.2M18.4 18.4l-2-2" stroke="{_WHITE}" stroke-width="1.2"/>'
        f'<path d="M8.4 7.2v2.4" stroke="{_WHITE}" stroke-width="1" opacity=".8"/>'
    ),
    # DeepSeek AI：机器人头 + 红瞳 + 品红天线
    "robot": (
        f'<rect x="4.6" y="6.4" width="14.8" height="11.6" rx="3.4" fill="{_NAVY}" opacity=".3"/>'
        f'<rect x="4.6" y="6.4" width="14.8" height="11.6" rx="3.4" stroke="{_CYAN}" stroke-width="2"/>'
        f'<path d="M12 6.4V3.6" stroke="{_BLUE}" stroke-width="2"/>'
        f'<circle cx="12" cy="2.8" r="1.2" fill="{_PINK}"/>'
        f'<ellipse cx="9.3" cy="12" rx="1.7" ry="1.3" fill="{_RED}"/>'
        f'<ellipse cx="14.7" cy="12" rx="1.7" ry="1.3" fill="{_RED}"/>'
        f'<path d="M9.4 15.2h5.2" stroke="{_WHITE}" stroke-width="1.2"/>'
        f'<path d="M7 8.6h2M15 8.6h2" stroke="{_ICE}" stroke-width="1.2"/>'
    ),
}


def icon_bodies():
    """返回所有可用图标名（供 Jinja 全局注入 / 调试用）。"""
    return list(_BODIES.keys())


def render_icon(name, size=16, alt=""):
    """返回内联 SVG 图标（Markup 安全字符串）。

    未知名称返回空字符串，模板与结果 HTML 都不会因此报错。
    """
    body = _BODIES.get(str(name))
    if not body:
        return Markup("")
    try:
        px = int(size)
    except (TypeError, ValueError):
        px = 16
    if alt:
        aria = ' role="img" aria-label="{}"'.format(_escape(str(alt), quote=True))
    else:
        aria = ' aria-hidden="true"'
    return Markup(
        '<svg class="ui-ic icon-{0}" width="{0}" height="{0}" viewBox="0 0 24 24" '
        'fill="none" stroke-linecap="round" stroke-linejoin="round"{1}>{2}</svg>'.format(
            px, aria, body
        )
    )

# ============================================================================
# Q 版角色档：狐耳少女「小蓝」插画（96×96 视口，角色档 48–96px）
# 用于空状态与检测结果，属于图标系列之外的“角色层”，不参与图标网格。
# ============================================================================

_MASCOT_PROPS = {
    # 检测：举起能量放大镜
    "search": (
        '<g transform="translate(58,64)">'
        f'<circle cx="9" cy="9" r="9" fill="{_NAVY}" opacity=".3"/>'
        f'<circle cx="9" cy="9" r="9" stroke="{_CYAN}" stroke-width="2.6" fill="none"/>'
        f'<ellipse cx="9" cy="9.5" rx="2.6" ry="1.8" fill="{_RED}"/>'
        '<circle cx="10" cy="8.6" r=".7" fill="#FFFFFF"/>'
        f'<path d="M16 16 23 23" stroke="{_BLUE}" stroke-width="3" stroke-linecap="round"/>'
        '</g>'
    ),
    # 拦截：抱着冰盾
    "shield": (
        '<g transform="translate(60,58)">'
        f'<path d="M10 0 20 3.6v5.4c0 4.6-3.2 7.6-10 9.2-6.8-1.6-10-4.6-10-9.2V3.6z" fill="{_NAVY}" opacity=".3"/>'
        f'<path d="M10 0 20 3.6v5.4c0 4.6-3.2 7.6-10 9.2-6.8-1.6-10-4.6-10-9.2V3.6z" stroke="{_CYAN}" stroke-width="2" fill="none"/>'
        f'<path d="M5.8 8.8l2.6 2.8 4.8-5.4" stroke="{_WHITE}" stroke-width="1.8" fill="none"/>'
        '</g>'
    ),
    # 白名单：举起绿色对勾徽章
    "check": (
        '<g transform="translate(62,62)">'
        f'<circle cx="10" cy="10" r="10" fill="{_GREEN}" opacity=".18" stroke="{_GREEN}" stroke-width="2"/>'
        f'<path d="M5.4 10.4l3 3.2 6-7" stroke="{_WHITE}" stroke-width="2.2" fill="none"/>'
        '</g>'
    ),
    # 报告 / 历史：拿着数据终端
    "chart": (
        '<g transform="translate(58,62)">'
        f'<rect x="0" y="10" width="5" height="10" rx="1.5" fill="{_ICE}"/>'
        f'<rect x="7" y="5" width="5" height="15" rx="1.5" fill="{_BLUE}"/>'
        f'<rect x="14" y="0" width="5" height="20" rx="1.5" fill="#0EA5E9"/>'
        f'<path d="M-1 21h21" stroke="{_BLUE}" stroke-width="1.4"/>'
        '</g>'
    ),
    # 空状态：捧着一张空白记录
    "empty": (
        '<g transform="translate(60,62)">'
        f'<path d="M2 4h12l4 4v12H2z" fill="{_WHITE}" opacity=".92" stroke="{_ICE}" stroke-width="1.2"/>'
        f'<path d="M14 4v4h4" fill="none" stroke="{_ICE}" stroke-width="1.2"/>'
        f'<path d="M6 12h8M6 15h6" stroke="#94A3B8" stroke-width="1.2"/>'
        '</g>'
    ),
}

_MASCOT_BASE = (
    f'<circle cx="48" cy="50" r="40" fill="{_NAVY}" opacity=".05"/>'
    # 后发
    f'<path d="M20 44 C18 20 78 20 76 44 L78 72 C62 84 34 84 18 72 Z" fill="#132A4A"/>'
    # 狐耳
    f'<path d="M27 24 L21 5 L40 16 Z" fill="#132A4A" stroke="{_NAVY}" stroke-width="1.2"/>'
    f'<path d="M28.5 20 L25 11 L35 16 Z" fill="{_PINK}" opacity=".75"/>'
    f'<path d="M69 24 L75 5 L56 16 Z" fill="#132A4A" stroke="{_NAVY}" stroke-width="1.2"/>'
    f'<path d="M67.5 20 L71 11 L61 16 Z" fill="{_PINK}" opacity=".75"/>'
    # 脖子与外套
    f'<rect x="42" y="60" width="12" height="9" rx="4" fill="#FFE8DC" stroke="#E9BFAE" stroke-width="1"/>'
    f'<path d="M22 96 C23 78 33 68 48 68 C63 68 73 78 74 96 Z" fill="#0E7490"/>'
    f'<path d="M30 96 C31 82 38 74 48 74 C58 74 65 82 66 96 Z" fill="#0B3B47" opacity=".45"/>'
    f'<path d="M40 70 L48 80 L56 70 L52 67 L48 72 L44 67 Z" fill="{_WHITE}" stroke="#BAE6FD" stroke-width=".8"/>'
    f'<circle cx="48" cy="91" r="2.6" fill="{_GOLD}" stroke="#B45309" stroke-width=".7"/>'
    # 脸
    f'<ellipse cx="48" cy="43" rx="19" ry="20" fill="#FFE8DC" stroke="#1E293B" stroke-width="1.4"/>'
    # 侧发
    f'<path d="M29 34 C25 45 26 57 31 65" fill="none" stroke="#132A4A" stroke-width="4" stroke-linecap="round"/>'
    f'<path d="M67 34 C71 45 70 57 65 65" fill="none" stroke="#132A4A" stroke-width="4" stroke-linecap="round"/>'
    # 刘海与青色发丝高光
    f'<path d="M29 37 C29 24 39 17 48 17 C57 17 67 24 67 37 C63 30 58 29 55 35 C52 28 48 28 45 35 C42 29 36 30 33 37 Z" fill="#132A4A"/>'
    f'<path d="M34 30 C38 23 44 20 48 20 M52 22 C56 24 60 28 62 33" stroke="{_BLUE}" stroke-width="1.2" opacity=".75" fill="none"/>'
    # 眼睛
    f'<ellipse class="ui-mascot-eye" cx="40" cy="47" rx="3.9" ry="5" fill="{_RED}"/>'
    f'<ellipse class="ui-mascot-eye" cx="56" cy="47" rx="3.9" ry="5" fill="{_RED}"/>'
    f'<ellipse cx="40" cy="47.5" rx="1.5" ry="2.2" fill="#7F1D1D"/>'
    f'<ellipse cx="56" cy="47.5" rx="1.5" ry="2.2" fill="#7F1D1D"/>'
    '<circle cx="38.6" cy="45" r="1.5" fill="#FFFFFF"/>'
    '<circle cx="54.6" cy="45" r="1.5" fill="#FFFFFF"/>'
    '<circle cx="41.3" cy="49.4" r=".6" fill="#FFFFFF" opacity=".9"/>'
    '<circle cx="57.3" cy="49.4" r=".6" fill="#FFFFFF" opacity=".9"/>'
    # 睫毛与眉毛
    f'<path d="M35.4 43.2 C37 40.6 43 40.6 44.6 43.2" stroke="{_NAVY}" stroke-width="1.4" fill="none"/>'
    f'<path d="M51.4 43.2 C53 40.6 59 40.6 60.6 43.2" stroke="{_NAVY}" stroke-width="1.4" fill="none"/>'
    f'<path d="M35.6 38.2 C37.4 37 41 37 43 38.2" stroke="{_NAVY}" stroke-width="1" opacity=".7" fill="none"/>'
    f'<path d="M53 38.2 C55 37 58.6 37 60.4 38.2" stroke="{_NAVY}" stroke-width="1" opacity=".7" fill="none"/>'
    # 腮红与嘴
    f'<ellipse cx="34.5" cy="53.5" rx="3.2" ry="1.7" fill="#F9A8D4" opacity=".6"/>'
    f'<ellipse cx="61.5" cy="53.5" rx="3.2" ry="1.7" fill="#F9A8D4" opacity=".6"/>'
    '<path d="M45.6 56.4 C47.4 58.2 48.6 58.2 50.4 56.4" stroke="#B91C1C" stroke-width="1.3" fill="none"/>'
    '<!--PROP-->'
    # 星屑与冰晶
    f'<path d="M76 22l1 2.6 2.6 1-2.6 1-1 2.6-1-2.6-2.6-1 2.6-1z" fill="{_WHITE}" opacity=".9"/>'
    f'<path d="M18 28l.8 2 2 .8-2 .8-.8 2-.8-2-2-.8 2-.8z" fill="{_PINK}" opacity=".8"/>'
    f'<path d="M72 82l.8 2 2 .8-2 .8-.8 2-.8-2-2-.8 2-.8z" fill="{_WHITE}" opacity=".7"/>'
    f'<path d="M82 44l5-6 1 8z" fill="{_ICE}" opacity=".45"/>'
    f'<path d="M12 58l-4 5 6 1z" fill="{_ICE}" opacity=".35"/>'
)


def mascot_moods():
    """可用的角色姿态（供调试与文档）。"""
    return list(_MASCOT_PROPS.keys())


def render_mascot(size=96, mood="search"):
    """返回 Q 版小蓝的内联 SVG（Markup 安全字符串）。

    mood: search / shield / check / chart / empty
    """
    prop = _MASCOT_PROPS.get(str(mood), _MASCOT_PROPS["search"])
    body = _MASCOT_BASE.replace("<!--PROP-->", prop)
    try:
        px = int(size)
    except (TypeError, ValueError):
        px = 96
    return Markup(
        '<svg class="ui-mascot ui-mascot-{0}" width="{1}" height="{1}" viewBox="0 0 96 96" '
        'fill="none" stroke-linecap="round" stroke-linejoin="round" role="img" '
        'aria-label="小蓝插画">{2}</svg>'.format(mood, px, body)
    )
