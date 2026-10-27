# 界面优化说明（UI Optimization Log）

- 优化日期：2026-10-23
- 目标：在不改变原内容、不修改业务逻辑的前提下，提升网页的视觉层次、一致性与可访问性
- 备份目录：`D:\Vscode\eyilianjie_backup_20261023-215854`（第一轮，133 个文件 / 67.7 MB，排除可重建的 `.venv` 与 `__pycache__`）；`D:\Vscode\eyilianjie_backup_20261023-220733-ui2`（第二轮，仅 web_app.py + index.html + base.html）
- 改动范围：第一轮仅 `templates/` 下 6 个模板；第二轮在 `web_app.py` 的 `index()` 中增加只读的 7 天聚合函数 `_build_daily_trend()`，**不改检测/拦截逻辑**

## 一、改动文件

| 文件 | 改动 |
| --- | --- |
| `templates/base.html` | 新增一段独立的「UI 增强层」`<style id="ui-enhance">`（原样式块原样保留）；新增跳转链接、`<main>` 语义标签、导航折叠按钮 aria 属性；导航 emoji 图标换成内联 SVG |
| `templates/index.html` | 结果区增加 `role="status" aria-live="polite"`（检测结果对读屏可见） |
| `templates/report.html` | 6 个统计卡增加 `stat-tile` 类；统计行加 `g-3` 栅格间距 |
| `templates/settings.html` | 页头 emoji 换成内联 SVG 齿轮；分节标题由全局样式统一样式 |
| `templates/blacklist.html` | 页头 emoji 换成内联 SVG 禁用图标 |
| `templates/guard.html` | 4 个状态卡增加 `status-tile` 类（渐变底色 + 悬停阴影） |
| `templates/whitelist.html` | 未改（全局样式已覆盖表格/按钮/卡片） |

## 二、视觉与交互优化点

1. **设计令牌**：统一品牌色（`#1d4ed8 → #0ea5e9`）、圆角（14px / 10px）、阴影、聚焦环，避免各页面"各写各的"。
2. **导航栏**：品牌渐变 + 轻阴影；链接改胶囊式 hover/激活态；移动端折叠按钮补 aria 与聚焦环。
3. **卡片体系**：统一描边、圆角、轻阴影；卡头浅色渐变；`stats-card` / `stat-tile` 悬停上浮；拦截控制台状态卡使用独立 `status-tile`。
4. **按钮**：统一圆角与字重；主按钮渐变；hover 上浮 1px、active 复位。
5. **表单**：输入框/下拉统一圆角与边框，聚焦使用品牌色 focus ring；开关聚焦环统一。
6. **表格**：外层容器圆角描边；表头小号大写字母、加粗、不换行；行悬停淡蓝高亮；`code` 片段加 chip 样式。
7. **提示条**：统一圆角 + 左侧 4px 语义色条（success/danger/warning/info）。
8. **页脚**：更轻的玻璃条；`body` 增加 `padding-bottom: 5rem`，确保固定页脚不遮挡内容。
9. **可访问性**：键盘跳转链接（跳到主内容）、`<main id="main">` 语义化、导航 aria、`aria-live` 结果区、`focus-visible` 统一轮廓。
10. **响应式**：窄屏下背景改为 `scroll`（避免移动端 fixed 背景抖动）、表格与卡片内边距收紧、统计卡字号下调。
11. **动效克制**：支持 `prefers-reduced-motion: reduce`，系统开启减少动效时全部关闭。

## 三、验证

- 用 Flask test client 渲染全部 6 个页面：`/`、`/report`、`/whitelist`、`/blacklist`、`/settings`、`/guard` 均返回 **200**，无 Jinja 异常
- 用浏览器逐页截图检查：首页、报告页（统计卡间距）、黑名单页、设置页（分节标题/表单）、拦截控制台（状态卡）显示正常
- 未改动任何表单 action、JS 函数、路由与后端逻辑；所有原文本内容（标题、提示、按钮文案、页脚）保持不变

## 四、回滚方式

```powershell
# 方式一：只回滚模板
Copy-Item "D:\Vscode\eyilianjie_backup_20261023-215854\templates\*" "D:\Vscode\eyilianjie\templates\" -Force

# 方式二：回滚整个源码目录（备份已排除 .venv / __pycache__）
robocopy "D:\Vscode\eyilianjie_backup_20261023-215854" "D:\Vscode\eyilianjie" /MIR /XD ".venv" "__pycache__" ".idea"
```

> 小范围回退：base.html 里删除 `<style id="ui-enhance">...</style>` 整块即可恢复原始外观，其余改动都是渐进增强。

## 五、第二轮：首页信息密度（占比条 + 7 天趋势）

- 备份：`D:\Vscode\eyilianjie_backup_20261023-220733-ui2`
- 改动文件：`web_app.py`（新增只读聚合 `_build_daily_trend`）、`templates/index.html`（统计卡内新增两个区块）、`templates/base.html`（增强层新增 `.ratio-*` / `.spark-*` 样式）

### 新增内容

1. **恶意/安全占比条**：红绿双色圆角条 + 两端图例（数量），数据全部来自现有 `stats`（`malicious_rate`、`malicious_count`、`safe_count`），无新增查询。
2. **最近 7 天迷你柱状图**：按日统计检测量，含恶意的日子用红色柱、纯安全用蓝色柱；hover 显示「日期：N 次（恶意 M）」；右上角显示峰值。
3. **空状态**：总检测为 0 时占比条显示灰色占位 + "暂无数据"；最近 7 天无记录时显示 "暂无记录"（不画空柱）。
4. **可访问性**：两个图都带 `role="img"` 与 `aria-label`。

### 后端实现（只读）

`web_app.py` 的 `index()` 新增：

```python
trend, trend_peak = _build_daily_trend(detector.reporter, days=7)
```

- 函数只遍历 `reporter._logs` 的 `timestamp` / `is_malicious`，按最近 7 个自然日分桶；
- 不写文件、不改日志、不触发任何检测；
- 任何异常（时间格式损坏等）都会退化为空列表，页面仅显示"暂无记录"，不影响首页其余功能。

### 验证

- `/` 返回 200；真实数据下：总检测 110 / 恶意 10（9.09%）→ 占比条与图例正确，最近 7 天无记录 → 显示"暂无记录"
- 测试进程内注入 7 天模拟日志后渲染：柱状图 7 根柱、峰值 8 次/天、恶意日红色显示，hover 提示正确
- 其余 5 个页面（report/whitelist/blacklist/settings/guard）仍全部 200

### 回滚

```powershell
Copy-Item "D:\Vscode\eyilianjie_backup_20261023-220733-ui2\web_app.py" "D:\Vscode\eyilianjie\web_app.py" -Force
Copy-Item "D:\Vscode\eyilianjie_backup_20261023-220733-ui2\templates\*" "D:\Vscode\eyilianjie\templates\" -Force
```


## 六、第三轮：二次元 SVG 图标（检测 / 报告等）

- 备份：`D:\Vscode\eyilianjie_backup_20261023-222435-icons`（web_app.py + 7 个模板）
- 风格来源：用户提供的参考图（深海军蓝夜空、青蓝能量刃、冰晶碎片、品红细线、狐耳萌点、金色扣具）
- 实现方式：**纯 SVG 内联**，不引入任何位图/外部依赖；旧 PNG 全部保留作降级

### 新增/改动文件

| 文件 | 改动 |
| --- | --- |
| `icon_svg.py`（新增，10.5 KB） | 12 枚二次元 SVG 图标的单一来源：`search / chart / check / shield / lock / clipboard / globe / warning / link / ban / cross / gear`；`render_icon(name, size, alt)` 输出 Markup |
| `web_app.py` | 删除旧的 PNG `<img>` 生成函数；改为 `from icon_svg import render_icon`；注册 Jinja 全局 `icon`；新增 `_inject_icon_svgs` 上下文处理器，把同一套 SVG 以 JSON 注入 JS |
| `templates/*.html`（7 个） | 24 处 `<img ... icons/*.png>` 全部替换为 `{{ icon('name', size, 'alt') }}`；4 处内联线性 SVG（黑名单/设置）统一为同一套图标 |
| `templates/base.html` | JS 的 `ICONS` URL 表改为 `ICON_SVGS`（内联 SVG 字符串）；`iconImg()` 改为返回 SVG；新增 `.ui-ic` 样式：基线对齐、导航/按钮冷光、检测镜片 `ui-eye` 眨眼动画（尊重 `prefers-reduced-motion`） |

### 图标设计要点（对照参考图）

- **检测**：能量放大镜，镜片内一枚红瞳（狐耳少女的萌点），手柄带品红发带点缀；
- **报告**：冰晶发簪柱状图，最高柱顶一对狐耳，星芒落点；
- **白名单/成功**：青色光刃对勾 + 星屑；
- **黑名单**：断裂冰环 + 品红光刃 + 星芒（红色只出现在符号上）；
- **拦截**：冰盾 + 盾后狐耳 + 中心高光；
- **设置**：金色扣具齿轮 + 品红刻度环；
- **品牌/锁**：水晶锁体 + 狐耳 + 金色钥匙孔；
- 其余（历史/公开源/警告/链接/失败）沿用同一色板与光向。

统一规范：24×24 视口、圆头圆角描边、左上主光/右下青色轮廓光、无 `<defs>`/滤镜（避免同页多实例 id 冲突）、发光用叠层描边实现。

### 验证

- 6 个页面全部 **200**，页面内 SVG 图标数量：`/` 17、`/report` 13、`/whitelist` 9、`/blacklist` 11、`/settings` 10、`/guard` 11；页面内已无 PNG 图标 `<img>` 引用
- `POST /detect`（example.com）返回 **200**，结果 HTML 内 **13 个 SVG 图标、0 个 PNG 图标**，说明后端结果区与页面图标同源
- 浏览器截图核对：首页导航/卡头/按钮、黑名单页页头与警告条、设置页页头与分节图标，风格统一且可辨识
- 未改动任何业务逻辑、路由、表单与检测算法；`icon_svg.py` 未知图标名返回空字符串，不会导致模板报错

### 回滚

```powershell
Copy-Item "D:\Vscode\eyilianjie_backup_20261023-222435-icons\web_app.py" "D:\Vscode\eyilianjie\web_app.py" -Force
Copy-Item "D:\Vscode\eyilianjie_backup_20261023-222435-icons\templates\*" "D:\Vscode\eyilianjie\templates\" -Force
Remove-Item "D:\Vscode\eyilianjie\icon_svg.py" -Force
```

> 回滚后模板里的 `{{ icon(...) }}` 会失效（因为旧 web_app.py 没有注册该全局），所以两个文件必须一起回滚；旧 `static/icons/*.png` 未被删除，可随时切回。

## 七、第四轮：Q 版「小蓝」角色档插画 + 监控/密钥/AI 图标

- 备份：`D:\Vscode\eyilianjie_backup_20261023-223058-mascot`（web_app.py、icon_svg.py + base/settings/whitelist/blacklist/report/index 模板）
- 目标：把二次元浓度再推一档——小尺寸用符号档图标，空状态/检测结果用 **48–96px 的 Q 版角色档**；同时补齐「监控设置 / API 密钥 / DeepSeek AI」三处缺失图标

### 新增内容

| 项 | 说明 |
| --- | --- |
| `icon_svg.py` · 图标 | 新增 `monitor`（显示器）、`key`（金色钥匙）、`robot`（机器人头）3 枚，图标总数 **15** |
| `icon_svg.py` · 角色档 | 新增 `render_mascot(size, mood)`：96×96 视口 Q 版狐耳少女「小蓝」，支持 **5 种姿态**：`search`（放大镜）、`shield`（冰盾）、`check`（对勾徽章）、`chart`（数据终端）、`empty`（空白记录） |
| `web_app.py` | 注册 Jinja 全局 `mascot`；检测结果卡头右侧加入 **56px 角色插画**（恶意→盾牌姿态，安全→放大镜姿态）；"AI分析"标题改用 `robot` 图标 |
| `templates/settings.html` | 监控设置 → `monitor`；API密钥设置 → `key`；DeepSeek AI API → `robot`（原 🖥️/🔑/🤖 全部替换） |
| `templates/whitelist.html` | 空状态 → 96px 小蓝（check 姿态）+ 两行说明 |
| `templates/blacklist.html` | 空状态 → 96px 小蓝（shield 姿态） |
| `templates/report.html` | 无记录 → 96px 小蓝（chart 姿态）+ 引导文案 |
| `templates/index.html` | "AI辅助检测"标签的 🤖 换成 `robot` 图标 |
| `templates/base.html` | 新增 `.ui-mascot` 样式：居中、柔和投影、角色眼睛眨眼动画（尊重 `prefers-reduced-motion`） |

### 角色档设计要点

- 主形象：蓝黑长发、狐耳（内耳品红）、红瞳（高光星点）、青色外套 + 白衬衫、金色扣具、腮红，全部取自参考图；
- 姿态道具：放大镜/冰盾/对勾徽章/数据终端/空白记录，分别对应检测、拦截、白名单、报告、空状态；
- 装饰：星屑 3 枚、冰晶碎片 2 枚、无 `<defs>`/滤镜，纯叠色描边实现发光；
- 表情：大眼 + 高光 + 腮红 + 微笑嘴，属于 Q 版角色档，不与 24px 符号档混用。

### 验证

- 6 个页面全部 **200**；`POST /detect`（example.com）→ **200**，结果 HTML 内 14 个 SVG 图标 + 5 处角色插画标记
- 浏览器截图核对：
  - 白名单空状态：96px 小蓝 + "白名单目前为空" 正常居中显示
  - 设置页：检测设置（放大镜）/ 监控设置（显示器）/ API密钥设置（金钥匙）/ DeepSeek AI API（机器人）四组图标齐全
  - 角色档样张页：5 种姿态 96px + 56px/48px 缩放均清晰，无变形
- 页面内已无 🖥️/🔑/📭 残留；`index.html` 的 🤖 换成 robot 图标后同样 200
- 未改动任何业务逻辑、路由、表单与检测算法

### 回滚

```powershell
Copy-Item "D:\Vscode\eyilianjie_backup_20261023-223058-mascot\web_app.py" "D:\Vscode\eyilianjie\web_app.py" -Force
Copy-Item "D:\Vscode\eyilianjie_backup_20261023-223058-mascot\icon_svg.py" "D:\Vscode\eyilianjie\icon_svg.py" -Force
Copy-Item "D:\Vscode\eyilianjie_backup_20261023-223058-mascot\templates\*" "D:\Vscode\eyilianjie\templates\" -Force
```

> 若要单独关闭角色档：把 `templates/*.html` 中的 `{{ mascot(...) }}` 删掉即可；图标与角色档是分开的两层，互不影响。

## 八、第四轮修复：检测结果四处显示问题

### 问题与根因

| # | 现象 | 根因 | 修复 |
| --- | --- | --- | --- |
| 1 | 「检测结果 - 安全链接」卡头白字看不见 | UI 增强层的 `.card-header` 统一渐变覆盖了 Bootstrap `bg-success` 深色底，`text-white` 留在浅底上 | 渐变只作用于**没有 `bg-*` 工具类**的卡头：`.card > .card-header:not([class*="bg-"])` |
| 2 | 「点击可在新标签页打开该链接」提示条左缘错位 | 增强层给 `.alert` 加了 `border-left: 4px` 色条，与 12px 圆角在左缘错位 | 移除 `.alert` 左侧色条，仅保留统一圆角 |
| 3 | 92/100 进度条被填满 | 旧逻辑 `bar_width = 100 if display_score >= 70 else display_score`，"安全"档一律铺满 | 改为真实得分：`bar_width = max(0, min(100, display_score))` |
| 4 | ML 模型判定区块显示成源码（`&lt;/h6&gt;`…） | `Markup`（图标）与普通字符串混合拼接时，`Markup.__add__` 会把后续纯文本转义，导致 HTML 被当文本输出 | 拼接前对图标显式 `str(render_icon(...))`（ML 块、检测详情、AI 标记共 4 处） |

### 改动文件

- `web_app.py`：进度条宽度计算、4 处 `str(render_icon(...))`
- `templates/base.html`：卡头渐变选择器、`.alert` 样式

### 验证

- 6 个页面全部 **200**；`POST /detect`（example.com）→ 200
- 结果 HTML：ML 区块为真实 HTML（`raw ML: True`）、无 `&lt;/h6&gt;` 转义（`escaped: False`）
- 进度条宽度取真实分（99 分 → `width: 99%`，留 1% 灰色；92 分即留 8%）
- 浏览器整页截图核对：卡头绿底白字可读、提示条圆角正常、进度条不再无条件满格、ML 块以徽章列表正常渲染

### 回滚（本轮为纯修复，逐项反向即可）

1. `base.html`：把 `.card > .card-header:not([class*="bg-"])` 的渐变规则改回 `.card-header` 直接设置 `background`；
2. `base.html`：`.alert` 恢复 `border-width: 1px; border-left-width: 4px` 与各 `alert-*-color`；
3. `web_app.py`：`bar_width` 改回 `100 if display_score >= 70 else display_score`；
4. `web_app.py`：去掉 ML 块、检测详情、AI 标记这 4 处的 `str(...)` 包裹。

> 本轮修复后的完整快照：`D:\Vscode\eyilianjie_backup_<时间戳>-resultfix`（web_app.py + icon_svg.py + 全部模板）。

### 恶意链接结果复核（补充）

实测两条恶意样本：

| 样本 | 结果字段 | 核对点 |
| --- | --- | --- |
| `http://free-gift-card-now.xyz/login?token=abc` | `is_malicious=True, score=49, risk=危险` | 红卡头 `bg-danger text-white` 白字清晰；盾牌姿态小蓝 56px；拦截提示条圆角正常；进度条 **49%**（不再满格）；ML 区块正常渲染为徽章列表 |
| `http://z1.zedo.com/` | `is_malicious=True, score=0, risk=黑名单(色情网站)` | 卡头按黑名单档走 `bg-dark text-white`（深色而非红色，属既有分级逻辑）；盾牌小蓝与拦截提示同样正常 |

**附带修复**：拦截提示文案原本是「点击不会跳转（已自动拦截，原因：…（评分 49/100））」——`block_reason` 自带括号，外层又套了一层，渲染出 `））`。已改为「点击不会跳转 · 已自动拦截：…」，实测无双重括号。

- 验证：6 个页面 200；两条恶意样本均返回 200；`header red: True`、`shield mascot: True`、进度条宽度 = 真实得分
