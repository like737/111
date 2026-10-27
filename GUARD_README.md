# eyilianjie guard —— 真正能拦住链接的拦截层

> 解决的问题：以前 eyilianjie 说"已拦截"，其实只是**页面上的提示**（`interceptor.py:116` 里只是 print 一句，
> Web 端也只是把链接渲染成不可点）。换个页面/地址栏重新打开，照样能开。
> guard 把"检测结论"接到**流量层**上：命中的链接在任何浏览器、任何页面都真的打不开。

**eyilianjie 现有文件零改动**：guard 只**新增**文件，只**读**黑名单/白名单/检测日志/配置文件，
自己不往 eyilianjie 目录写任何东西（数据都在 `guard\data\`；运行时会关闭 .pyc 写入）。
自测脚本会用 SHA256 前后比对来证明这一点。

---

## 一、快速开始（三步）

```
1) 运行  python web_app.py          ← 用原来那套 eyilianjie 启动，只是多带一层拦截
2) 打开  http://127.0.0.1:5000/     ← eyilianjie 页面，顶部导航栏点「拦截」
                                      → 勾选要用的拦截方式 → 点【开始拦截】
                                      （点这一下才会真正开始拦, 并自动把系统代理指向 guard）
3) 装脚本（可选但强烈推荐，HTTPS 也能看到漂亮拦截页）:
   guard\userscript\eyilianjie_guard.user.js
   浏览器装 Tampermonkey → 新建脚本 → 粘贴该文件内容 → 保存
```

装完第 3 步后有三种拦截方式同时生效，互相补位：

| 方式 | 拦住什么 | 覆盖范围 | 需要设置 | 拦截页 |
|---|---|---|---|---|
| ① 本地代理（8888） | HTTP 按完整 URL；HTTPS 按域名（CONNECT 阶段，**不需要证书**） | 走系统代理的浏览器（Edge / Chrome / IE…） | 在 Web 端「拦截」页点【开始拦截】 | HTTP：自定义拦截页；HTTPS：浏览器自己的错误页 + 403 |
| ② 检测即真封 | eyilianjie 里**判过恶意**的链接 | 立即写入 guard 动态拦截集，配合 ① / ③ 生效 | 同一次点击就自动挂上 | — |
| ③ 油猴脚本 | 打开页面 / 点击链接 / 提交表单前预检 | 装了 Tampermonkey 的浏览器（含 Firefox） | 安装脚本 | **完整拦截页**（HTTPS 也有，且页面内容比代理版更丰富） |

---

## 一·二、Web 端拦截控制台（融进 eyilianjie 页面）

> 入口：eyilianjie 任何页面**顶部导航栏的「🛡 拦截」**（后面带一个实时状态徽章：
> `拦截中` / `部分生效` / `已停止` / `代理未生效` / `不可用`）。
> 也可以直接打开 `http://127.0.0.1:5000/guard`。

页面上的四块，**都是即时生效，不需要重启服务**：

| 区域 | 内容 |
|---|---|
| 状态总览 | 拦截总开关 · 系统代理（全浏览器生效） · 检测即真封 · 已拦截次数 · 检测日志联动 |
| 三个按钮 | **【开始拦截】**（勾选的方式一起生效 + 自动把系统代理指向 guard）· **【停止拦截】**（放行一切 + 还原系统代理）· **【系统代理：开/关】**（只动代理这一项） |
| 拦截方式 | 9 个可勾选项（2 个"通道" + 7 条"判定规则"），勾完点【应用勾选】；勾选会被记住（`block_via_proxy`） |
| 记录与管理 | 最近的拦截/放行记录 · 手动加入拦截/放行 · 清空动态拦截集 · 手测一个 URL（纯本地判定，不联网、不写检测日志） |

### 「拦截方式」对照表（页面勾选项 ↔ 配置键 ↔ 效果）

| 页面上的名字 | 配置键 | 效果 |
|---|---|---|
| 本地代理拦截 | `block_via_proxy` + 系统代理 | 把系统代理指向 `127.0.0.1:8888`，Edge/Chrome 等全浏览器生效；取消勾选则不动系统代理 |
| 检测即真封 | （运行时挂载 `detector.detect`） | eyilianjie 判为恶意 → 立刻写入拦截集，换个页面/地址栏重开也打不开 |
| 黑名单（18 万条） | `block.blacklist` | 命中 eyilianjie 黑名单（6 级匹配）即拦 |
| 成人 / 赌博关键词规则 | `block.adult` | 域名命中成人、赌博类关键词即拦 |
| 启发式规则（恶意模式库） | `block.heuristic` | 复用 eyilianjie 启发式（可疑 TLD、诱导词、恶意模式） |
| ML 通道（拦截档） | `block.ml_convict` | 路径模型 path_model 达阈值即拦 |
| ML 通道（提示档也拦） | `block.ml_hint` | 默认关；开启后域名模型也参与拦截（更严、误报更多） |
| 检测日志联动 | `block.dynamic_from_log` | 每 2 秒只读扫描 `detection_log.json`，**只增量导入新记录**（历史不重导，删掉的条目不会再被加回来） |
| HTTPS 隧道拦截 | `block.block_https_tunnel` | HTTPS CONNECT 阶段按域名拦（浏览器显示自己的错误页） |

### 为什么「点一下」就能立刻生效

guard 的判定引擎**每次判定都重新读配置**（`guard/engine.py:143/181/195/210/224/225`、
`guard/proxy.py:252`）。所以点【开始拦截】只做四件事：写配置 → 清一次判定缓存
（`engine.invalidate()`）→ 挂上"检测即真封" → 把系统代理指过来。任何后续请求都按新配置判定，
**不需要重启任何进程**。

### 页面用到的接口（都在 eyilianjie 自己的 Web 上，不再依赖 8899）

| 路由 | 方法 | 作用 |
|---|---|---|
| `/guard` | GET | 控制台页面（`templates/guard.html`，`extends base.html`，样式与原站一致） |
| `/guard/state` | GET | 状态 JSON（开关 / 各方式取值 / 计数器 / 最近记录） |
| `/guard/apply` | POST | **核心**：`{enabled, block_via_proxy, detect_block, block.*}` → 立即生效 |
| `/guard/sysproxy` | POST | 单独开关系统代理（并同步"意图"） |
| `/guard/entry` | POST | `action=block\|allow\|remove\|remove_allow\|clear_dynamic` + `url` |
| `/guard/check` | GET | 手测一个 URL（本地判定） |
| `/guard/logs` | GET | 最近拦截/放行记录 |

**安全**：读接口不限来源；**写接口只接受本机（127.0.0.1/::1）且必须带自定义请求头
`X-Guard-Request: 1` + JSON 请求体** —— 其它网站无法伪造自定义头，因此挡住了本机 CSRF
（自测 I3 专门验证这一点）。

### 独立控制台（8899）还要吗？

不再需要它是"主要入口"了；它保留下来给**油猴脚本 API** 和其它工具用，也多了
`POST /guard/config`（与 Web 端同一套开关逻辑）。不想让它监听可以把
`guard\data\config.json` 里 `api.port` 改成别的，或用 `python -m guard run --no-api`。

---

## 一·三、HTTPS 也有漂亮拦截页（Edge 扩展，不需要装证书）

走代理时 **HTTPS 命中只能显示浏览器自己的错误页**（`ERR_TUNNEL_CONNECTION_FAILED`）——
这是不给浏览器安装根证书的物理限制。想要 HTTPS 也显示我们自己的拦截页，用这个扩展：

```
guard\extension\                ← Edge 扩展「eyilianjie 拦截守卫」（MV3，纯前端，无需联网）
├── manifest.json              权限只有: webNavigation / tabs / storage（只允许访问 127.0.0.1）
├── background.js              导航前问 guard「这个 URL 会被拦吗」，命中就把标签页切到拦截页
├── blocked.html / blocked.js  拦截页（HTTPS 站点上也显示这一张）
├── popup.html / popup.js      扩展图标弹窗：状态 + 打开控制台 + 清缓存 + 运行自检
├── selftest.html / selftest.js 自检页（5 项检查，含拦截页渲染预览）
└── preview.png                拦截页的真实渲染截图（真 Edge 截的）
```

**安装（3 步，一次性）——也可以直接双击 `安装_Edge扩展.bat`：**

1. Edge 地址栏打开 `edge://extensions/`，打开左下角「**开发人员模式**」
2. 点「**加载解压缩的扩展**」，选择目录 `guard\extension`
3. 点扩展图标 →「**运行自检**」，看到 **5/5 通过** 就装好了

**工作原理（为什么不需要证书）：**

```
你点开链接 → Edge 即将导航
   └─ 扩展 webNavigation.onBeforeNavigate(主文档)
        └─ fetch http://127.0.0.1:8899/guard/check?url=...   ← 问 guard（guard 没运行则一律放行）
             ├─ 放行 → 什么都不做，正常访问
             └─ 命中 → chrome.tabs.update → chrome-extension://…/blocked.html?u=…&d=…
                        （拦截页是扩展页面, 不受目标站点的 CSP / 证书限制）
```

**拦截页上的四个按钮**：`返回上一页` · `复制链接` · `误报？加入放行名单`（写进 guard 放行名单，
立即生效）· `仍然访问`（10 秒倒计时后可用，只放行这一次、不写名单）。

**已知限制（选它就要接受）：**
- 只覆盖**装了扩展的 Edge**（其它浏览器/其它程序不生效）；
- 拦截发生在**导航刚发起时**（请求可能已发出、但会被立刻丢弃，不会显示内容）；
- 只拦**主文档导航**（"打开链接/地址栏访问"这个场景），不拦页面内的图片/脚本等子资源；
- guard 没运行 → 扩展一律放行（fail-open，不会让你上不了网），此时扩展图标徽章显示 `off`。

**回滚**：`edge://extensions/` → 找到「eyilianjie 拦截守卫」→ 移除即可（不影响 guard 与其它功能）。

---

## 一·四、不点 bat：让 `web_app.py` 自己带上拦截层（当前默认模式）

**现在的启动方式就是原来的那条命令**，不需要任何 .bat：

```bat
python web_app.py        （或 VS Code 里直接运行 web_app.py）
```

启动时会自动把拦截层一起拉起来，日志里会出现：

```
[guard] 已随 Web 端自动启动拦截层: 本地代理 127.0.0.1:8888 · 控制台 http://127.0.0.1:8899/
[guard] 想开始拦截: 打开 http://127.0.0.1:5000/ → 顶部导航栏「拦截」→ 点【开始拦截】
🚀 Web服务器启动: http://127.0.0.1:5000
```

**它做了什么 / 没做什么**

| 自动做了 | 仍然要你点一下 |
|---|---|
| 本地代理 8888 监听 | **接管系统代理**（不点就不动你的代理设置） |
| 控制台 8899 监听 | 勾选"拦截方式" |
| 检测日志联动（每 2s 只读扫描，增量导入） | 装 Edge 扩展 / 油猴脚本（想让 HTTPS 显示漂亮拦截页） |
| **检测即真封**（包装 `detector.detect`） | — |

**开关与细节**

- 开关：`guard\data\config.json` 里的 `"auto_start"`（默认 `true`）。改成 `false` = 完全回到
  "不带拦截"的原始行为（`python web_app.py` 就是纯 eyilianjie）。
- **Werkzeug reloader 处理**：`web_app.py` 默认 `debug=True`，会 fork 出父/子两个进程；
  只有真正跑服务的子进程（`WERKZEUG_RUN_MAIN=true`）才会启动 guard，**不会启动两份**抢端口。
- **重复启动保护**：如果本机已经有 guard 在跑（比如另一个窗口已经跑着 `web_app.py`），
  会自动跳过并提示"本机已有 guard 在运行"，避免抢 8888/8899。
- **启动输出**：`python web_app.py` 默认只有两行：
  `🚀 Web服务器启动: http://127.0.0.1:5000`（约 0.7 秒出现，不等黑名单/模型加载）
  和 `✅ 就绪`（服务真正能响应 HTTP 后出现，约 8 秒）。配置/黑名单/ML/guard 的加载信息、
  Flask 开发服务器横幅、就绪探针自身的访问日志都已静音；debug 模式下 reloader 父进程
  也不再重复加载黑名单/模型。需要排查启动问题时，用 `$env:EY_VERBOSE="1"` 再启动，
  或把 `config.json` 的 `logging.verbose_startup` 设为 `true`。
- **退出即还原**：Ctrl+C 或正常结束时（`run_web` 的 finally）会自动把系统代理还原成你原来的值；
  强杀窗口时用 `python -m guard sysproxy off` 兜底（控制台里也有「关闭系统代理（还原）」按钮）。
- `run_guarded.py` 那条路依然可用（它先把运行时挂好，再启动 Web，不会重复启动）。

---

## 二、这次新增了什么（清单）

```
eyilianjie\
├── run_guarded.py                 # 方案D 入口：import web_app → 内存挂载 → 启动拦截 + 把运行时交给 Web 端
├── 安装_Edge扩展.bat               # 打开扩展目录 + 引导你去 edge://extensions/ 加载
├── 卸载_guard.bat                  # 还原系统代理 + 还原被改文件 + 删除新增文件
├── GUARD_README.md                # 本文件
├── web_app.py                     # 【已改·按你的选择】文件末尾新增 guard 接入段 + /guard* 路由
├── templates\
│   ├── base.html                  # 【已改】导航栏多一个「🛡 拦截」入口 + 状态徽章脚本
│   └── guard.html                 # 【新增】拦截控制台页面（extends base.html，样式与原站一致）
└── guard\
    ├── __init__.py                # 关闭 .pyc 写入、路径常量
    ├── settings.py                # guard 自己的配置（guard/data/config.json）
    ├── store.py                   # 动态拦截集 / 放行名单 / 拦截记录 / 统计（原子写、纯本地）
    ├── engine.py                  # 判定引擎（只读复用 eyilianjie：黑名单/成人规则/ML/启发式）
    ├── control.py                 # 【新增】拦截开关与「拦截方式」的统一控制层（Web 端与 8899 共用）
    ├── logwatch.py                # 只读热同步 detection_log.json（增量导入，进度存 data\logwatch_state.json）
    ├── proxy.py                   # 本地 HTTP/HTTPS 代理（纯标准库，含上游链式转发）
    ├── api.py                     # 独立控制台 + 本地 API（127.0.0.1:8899，含 /guard/config）
    ├── blockpage.py               # 拦截页（HTTP 403 时返回的富页面）
    ├── proxyctl.py                # 系统代理开关（HKCU，免管理员，可还原）
    ├── runtime.py                 # 组装启停 + detector.detect 的运行时包装（方案D）
    ├── cli.py / __main__.py       # 命令行：run/status/check/block/allow/sysproxy/doctor/selftest
    ├── selftest.py                # 隔离自测（验收用，不碰系统设置；共 59 项）
    ├── doctor.py                  # 环境体检：端口被谁占了 / 为什么打不开（只读检查）
    ├── backup\                    # 【新增】接入 web 端之前的 web_app.py / base.html 原始备份
    │   ├── web_app.py.orig        #   （卸载_guard.bat 会自动用它们还原）
    │   └── base.html.orig
    ├── extension\                 # 【新增】Edge 扩展「eyilianjie 拦截守卫」（HTTPS 拦截页）
    │   ├── manifest.json / background.js
    │   ├── blocked.html / blocked.js      # 拦截页（HTTPS 站点也显示这张）
    │   ├── popup.html / popup.js          # 扩展弹窗（状态 / 打开控制台 / 清缓存 / 自检）
    │   ├── selftest.html / selftest.js    # 自检页（5 项，含拦截页渲染预览）
    │   ├── preview.png                    # 拦截页渲染截图
    │   └── icons\shield.png
    ├── userscript\eyilianjie_guard.user.js   # 方案F 油猴脚本（含丰富拦截页）
    └── data\                      # guard 的数据（运行时生成，与 eyilianjie 完全隔离）
        ├── dynamic_block.json     # 动态拦截集（手动加黑 / 检测日志联动）
        ├── allow.json             # 放行名单（放行优先于一切拦截）
        ├── access_log.json        # 拦截/放行记录
        ├── stats.json             # 累计计数
        └── logwatch_state.json    # 检测日志联动进度（last_ts：只导入比它更新的记录）
```

**改动情况说明**（按你的选择走的是"融入 web 端"的路线）：
- `web_app.py` 只**追加**了一段"拦截控制台"代码（原检测/黑名单/白名单/设置逻辑一行未动）；
  `templates/base.html` 只**追加**了一个导航项 + 一小段徽章脚本；
- 之前接入的其它 eyilianjie 文件（`detector.py`、`config.py`、`config.json`、`data\blacklist.json`、
  `detection_log.json` …）依然**一个都没改**，自测里用 SHA256 前后比对证明；
- 两个被追加过的文件，**原始版本备份在 `guard\backup\`**，双击 `卸载_guard.bat` 会自动还原。

---

## 三、判定顺序（本地、离线、毫秒级）

```
guard 放行名单 → eyilianjie 白名单 → 动态拦截集（检测记录联动 / 手动加黑）
→ eyilianjie 黑名单（18 万+ 条, 6 级匹配） → 成人/赌博规则（域名级强命中直接拦）
→ ML 通道（只信"参与拦截"的通道: 当前 = 路径模型; 域名模型仍按原设置"仅提示"）
→ 启发式规则（恶意/钓鱼模式库、可疑域名库、可疑 TLD、欺骗性域名、DGA…）
→ 放行
```

- 全部规则**都在本机**跑，不联网、不调用 AI、不产生任何外发请求；
- 判定异常时默认**放行**（`block.fail_open`），避免因为拦截层故障而上不了网；
- 结果缓存 60 秒（`cache.ttl`），同一页面里几十个请求不会重复判定。

---

## 四、配置（guard\data\config.json）

首次启动时自动把默认配置写到 `guard\data\config.json`（与 eyilianjie 的 config.json 完全无关）。常用项：

| 项 | 默认 | 说明 |
|---|---|---|
| `proxy.port` | 8888 | 本地代理端口（改完要同步改系统代理里的地址） |
| `proxy.upstream_proxy` | 空 | **重要**：如果你在用 v2ray/clash 之类的本地代理（例如 `127.0.0.1:10808`），填在这里，guard 未命中的请求会转发给它，不会顶掉你的科学上网。留空表示直连。 |
| `proxy.upstream_bypass` | 空 | 走上游代理的例外域名（逗号分隔） |
| `proxy.bypass_localhost` | true | 本机地址直连、不做判定（防止代理把自己绕进去） |
| `block.block_https_tunnel` | true | HTTPS 在 CONNECT 阶段按域名拦截 |
| `block.ml_hint` | false | 是否也拦"仅提示档"的 ML 通道（当前域名模型未达标，建议保持 false） |
| `block.fail_open` | true | 判定异常时放行（更安全的选择） |
| `log.log_all_requests` | false | 是否把放行请求也记进 guard 的 access_log |
| `cache.ttl` / `cache.max` | 60 / 5000 | 判定缓存 |
| `sysproxy.restore_on_exit` | true | 退出 guard 时自动还原系统代理 |

改完重启 guard 生效。也可以只在控制台里点按钮（加黑 / 放行 / 开关系统代理），不需要手改文件。

---

## 五、常见问题

**Q1：HTTPS 命中的时候，为什么看到的是浏览器的错误页，而不是你们的拦截页？**
A：走代理时，不装根证书的情况下能做的最多是"在 CONNECT 阶段把这个隧道掐掉"，浏览器收到 403 后
显示自己的 `ERR_TUNNEL_CONNECTION_FAILED`。**想让 HTTPS 也显示我们自己的拦截页，有两个现成办法**：
① **Edge 扩展**（推荐，不需要证书）——见上文「一·三」；
② **油猴脚本**（浏览器无关，含 Firefox）——见「一」的第 3 步。
两者都只负责"显示拦截页"，判定规则仍由本页控制。如果还想让 HTTPS 也能**按路径**判定、并且
**所有程序**都被强制拦住，那才需要上 MITM（给浏览器装一次性根证书）——这一步本方案刻意没做，
因为它的代价（改系统证书库 + 解密全部 HTTPS）远大于收益。


**Q2：开了系统代理，会不会影响我原来的代理软件？**
A：guard 开启前会先记录原始设置（`ProxyServer` / `ProxyOverride` / `AutoConfigURL`），关闭时逐项还原；
如果你原来就在用 10808 之类的本地代理，请把它填进 `proxy.upstream_proxy`，这样是"链式"关系而不是互相顶掉。

**Q3：代理/guard 崩了会不会上不了网？**
A：控制台点「关闭系统代理（还原）」，或执行 `python -m guard sysproxy off`；正常退出（Ctrl+C、关窗口）也会自动还原。

**Q4：Firefox 好像没走系统代理？**
A：Firefox 有自己的代理设置。两个办法：① 装油猴脚本（推荐，覆盖 Firefox）；
② 在 Firefox 里手动把代理设成 `127.0.0.1:8888`。

**Q4b：打开 `http://127.0.0.1:5000` 打不开 / 端口被占？**

先跑一条命令，它会直接告诉你"谁占着、怎么修"：

```bat
python -m guard doctor
```

`doctor` 会：① 列出 5000 / 8888 / 8899 上每个监听 socket 属于哪个进程；② 真发 HTTP 请求验证
`http://127.0.0.1:5000/` 到底能不能开；③ 检查系统代理是否指向 guard 但 guard 没运行（这会导致**所有**网页打不开）。

**本机实际遇到过的两种真凶（eyilianjie / guard 都没错）：**

1. **外设/游戏软件抢占了 `127.0.0.1:5000`** —— 实测是罗技 G HUB 的 `CS_GO_Arx_Applet.exe`
   （`%LOCALAPPDATA%\LGHUB\integrations\applet_csgo\`）。Windows 规则：同一端口上**具体地址 `127.0.0.1`
   优先于通配地址 `0.0.0.0`**，并且两者允许同时绑定。eyilianjie 的 Web 绑的是 `0.0.0.0:5000`
   （`web_app.run_web` 的默认值），于是它**收不到**发往 `127.0.0.1:5000` 的请求 —— 启动日志照样打印
   `🚀 Web服务器启动: http://127.0.0.1:5000`，但浏览器打不开（接管 127.0.0.1 的那个程序根本不说 HTTP）。
   - 立刻修：`Stop-Process -Id <doctor 报出来的 PID> -Force`
   - 永久修：在罗技 G HUB 里关掉"游戏集成 / CS:GO 集成"，或退出 G HUB
   - 绕开：`python run_guarded.py --port 5080`（或设环境变量 `EY_PORT=5080`），**不需要改 eyilianjie 任何文件**
   - 同类坑也可能出现在 Intel / NVIDIA / 雷蛇 / 微星等外设软件的本地服务上，`doctor` 一样能报出来

2. **同一个端口跑了两个实例**（例如同时跑了 `python web_app.py` 和 `python run_guarded.py`）。
   Windows 的 `SO_REUSEADDR` 允许两个进程都绑 `0.0.0.0:5000`，**请求落到哪个实例是随机的**，
   现象是"有时能开、有时白屏、数据对不上"。只留一个：保留带 8888/8899 的那个（guard 启动的那次）。
   另外 `web_app.py` 里 `run_web(debug=True)` 默认开 Werkzeug reloader，**一次启动会有两个 python 进程**，
   那是父子进程，不算重复实例。



**Q5：误拦了正常网站怎么办？**
A：三种途径任选：① 拦截页点「误报？加入放行名单」；② 控制台「加入放行」；
③ 命令行 `python -m guard allow <url或域名>`。放行写入 `guard\data\allow.json`，**立即生效**（会自动清掉同名的动态拦截条目）。

**Q6：会不会把 google/baidu 这种大站整站封掉？**
A：不会。eyilianjie 认定的**可信站点**（`utils.is_trusted_host`）在自动联动时只封"那一条 URL"，
不做域名级封禁；手动加黑才按整站处理。

**Q7：性能开销？**
A：本地判定（黑名单 18 万条 + 规则 + 模型）冷判定 p50 ≈ 1.1ms，缓存命中 ≈ 0.003ms（见下方自测数据）；
代理只在转发前多一次字典判断，正常浏览感受不到差别。

**Q8：页面显示「代理未生效 / 系统代理没生效」是什么意思？**
A：说明 guard 已经把系统代理写成"指向 127.0.0.1:8888"，但随后被**别的程序改回去了**（有些代理/安全
软件会守护这个设置）。这时 guard 会如实报告，而不会假报成功。两个办法：① 在那个软件里把系统代理指向
`127.0.0.1:8888`（或把它自己的地址填进 `guard\data\config.json` 的 `proxy.upstream_proxy` 做链式转发）；
② 跳过代理，直接用油猴脚本那条通道。

> 顺带一个真实修复记录：Windows 的 `InternetSetOption(SETTINGS_CHANGED/REFRESH)` 必须**先通知、再写
> 注册表**。早期版本是"先写、再通知"，结果 WinINet 用手里的旧缓存把注册表**刷回原值**，表现为
> "提示已开启，但 `ProxyEnable` 还是 0"。现在 `proxyctl.py` 已改成"先通知 → 再写 → 写后回读校验"。

**Q9：页面会不会被别人遥控（比如某个网页偷偷帮你开/关代理）？**
A：不会。所有写接口都要求 **只从本机发起 + 自定义请求头 `X-Guard-Request: 1` + JSON 请求体**，
浏览器不会允许其它站点伪造自定义头（会先触发跨域预检而失败）。自测 I3 就是验证这一点。



```powershell
python -m guard status                     # 看状态（优先问正在运行的 guard）
python -m guard check <url>                # 判定一个 URL（--host 模拟 HTTPS 只看域名）
python -m guard block <url>                # 手动加黑（立即生效）
python -m guard allow <url>                # 加白（立即生效）
python -m guard sysproxy on|off|status     # 系统代理开关
python -m guard selftest                   # 隔离自测（不碰系统设置、不改 eyilianjie 文件）
python -m guard userscript                 # 打印油猴脚本路径
```

`selftest` 最近一次结果：**27/27 通过**（含：黑名单/成人规则/可信站点/本机放行、检测日志只读联动、
动态集与放行名单、HTTP 403 拦截页、HTTPS CONNECT 403、隧道转发、外网透传、控制台接口、
判定延迟、端口释放、以及 **SHA256 证明 eyilianjie 现有文件零改动**）。

---

## 七、卸载（完全可回退）

双击 `卸载_guard.bat`：
1. 还原系统代理（逐项还原成 guard 开启前的原值）；
2. **把 `web_app.py` / `templates\base.html` 还原成接入 web 端之前的版本**（用 `guard\backup\*.orig`）；
3. 删除 `guard\`、`run_guarded.py`、`安装_Edge扩展.bat` 与本 README。

eyilianjie 的代码与数据不受影响，用原来的方式（`python web_app.py` / VS Code 里直接运行）启动即可。

> 注意：`guard\data\` 里保存着"检测即真封"累积下来的拦截条目与记录；如果你想保留，卸载前先备份该目录。
> 只想关掉控制台入口、不想卸载？把 `guard\data\config.json` 里 `"webui"` 相关开关关掉，或直接点【停止拦截】。

---

## 八、实现要点（为什么可以"零改动"）

1. **只读复用判定逻辑**：`Config.CONFIG_FILE`、`Detector.BLACKLIST_FILE/WHITELIST_FILE` 这类
   "相对工作目录"的路径常量，在 guard 进程内被改成绝对路径（`engine.py:_patch_paths`），
   于是从任意目录都能正确读到 eyilianjie 的数据 —— 但没有改动源文件一行；
   `utils.py` / `ml_url_model.py` 本来就用 `__file__` 定位数据，天然安全。
2. **绝不写 eyilianjie**：只调用 `match_blacklist / match_whitelist / analyzer.analyze / ml_channel.predict`
   这些不写日志的方法（刻意不调 `detector.detect()`）；只有在**独立进程自建 detector** 时
   才把 `reporter.log_detection` 置空（复用 web_app 的 detector 时绝不置空，否则 web 端
   「最近检测 / 统计摘要」会停更）；
   `detection_log.json` 只以只读方式打开。
3. **方案 D 的"检测即真封"**：`runtime.patch_detector()` 在内存里包装 `Detector.detect`，
   原返回值不变，只在你判定为恶意时把目标写进 guard 自己的动态拦截集（`guard\data\dynamic_block.json`）。
   原来的启动方式行为一字不变；只有用 `run_guarded.py` 启动时才带这个包装。
4. **不留下"新文件痕迹"**：`guard/__init__.py` 会设置 `sys.dont_write_bytecode = True`，
   连 `__pycache__` 都不新增（如需恢复：`set EY_GUARD_ALLOW_BYTECODE=1`）。

