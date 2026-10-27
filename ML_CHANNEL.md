# ML 检测通道接入说明（MaliciousURLs 优化模型）

> 本文档描述 eyilianjie 中新增的"第三路检测信号"。**它不会改变你的 AI（DeepSeek）辅助检测、
> 启发式引擎、黑名单/白名单短路与自动拦截策略**——已有回归验证脚本可反复证明这一点。

---

## 一、接入了什么

| 文件 | 说明 |
|---|---|
| `data/models/lgs_model.pickle` | 模型文件（来自 `D:\Vscode\MaliciousURLs\lgs.pickle`，普通参数字典：vectorizer/classifier/threshold） |
| `ml_url_model.py` | 只读适配层：懒加载、单例、异常隔离；提供 `predict()` / `predict_batch()` |
| `verify_ml_shadow.py` | 回归验证脚本（务必保留，换模型/升 sklearn 后必跑） |
| `detector.py` | `DetectionResult` 新增 4 字段；`Detector.__init__` 懒加载模型；`detect()` 在 **DeepSeek 融合之后**插入 ML 判定块 |
| `web_app.py` | 结果卡片新增「ML模型判定 (MaliciousURLs)」区块（不改动既有颜色/分级/拦截逻辑） |
| `config.py` / `config.json` | `detection` 段新增 7 个开关 |
| `requirements.txt` | 新增 `scikit-learn==1.9.1`（**版本必须与模型训练版本一致**） |

## 二、配置项（`config.json` → `detection`）

| 键 | 默认 | 作用 |
|---|---|---|
| `enable_ml_check` | `true` | 总开关。**置 false 后行为与未接入前完全一致** |
| `ml_mode` | `"shadow"` | `shadow`=只记录不裁决；`enforce`=参与判定（OR 通道） |
| `ml_model_path` | `"data/models/lgs_model.pickle"` | 模型路径（相对项目根目录） |
| `ml_threshold` | `null` | `null` = 使用模型文件内保存的阈值（当前 0.61） |
| `ml_confidence` | `0.9` | 高置信门限，enforce 只认高置信（实测该档误报 0%） |
| `ml_affect_score` | `false` | 固定 false：概率**绝不**加进 0-100 分体系 |
| `ml_trigger_intercept` | `false` | 是否允许 ML 单独定罪（进而触发自动拦截） |

## 三、三种运行状态

| 状态 | 配置 | 行为 |
|---|---|---|
| 关闭 | `enable_ml_check=false` | 与未接入完全一致（回归脚本第 1 项验证） |
| **影子（当前）** | `ml_mode="shadow"` | 检测照旧；ML 概率写入 `details`（`[ML] ...`）与日志字段 `ml_prob/ml_verdict/ml_high/ml_mode` |
| 增强 | `ml_mode="enforce"` | 仅"高置信"项参与：`ml_trigger_intercept=false` 时只把等级提示为「可疑」不拦截；`true` 时 ML 可单独定罪并触发拦截 |

## 四、日常操作

```powershell
cd d:\Vscode\eyilianjie
.\.venv\Scripts\python.exe verify_ml_shadow.py                                    # 回归验证(推荐每次改动后跑)
.\.venv\Scripts\python.exe verify_ml_shadow.py --eval-dir ..\MaliciousURLs\data\eval   # 附评测集召回/误报对比
.\.venv\Scripts\python.exe verify_ml_shadow.py --real-ai                          # 额外做1次真实AI冒烟
python web_app.py                                                                 # 正常启动(启动时会打印 ML 通道状态)
```

**切换到增强模式**：把 `config.json` 的 `ml_mode` 改成 `"enforce"`（建议先保持 `ml_trigger_intercept=false`），
重启服务即可；**回滚**：把 `enable_ml_check` 改回 `false` 或 `ml_mode` 改回 `"shadow"`。

## 五、回归验证结果（本机实测，可复现）

| 检查项 | 结果 |
|---|---|
| 1) 关闭 ML vs 影子模式，逐字段一致性（score/等级/判定/黑名单/域名/AI行/详情条数） | 差异 **0** → PASS |
| 2) AI 行完整性 / ML 文案不含 "DeepSeek" | PASS / PASS |
| 3) 模型缺失自动降级（结果与基线一致 + AI 行相同） | PASS |
| 4) 黑名单短路优先级不受影响 | PASS |
| 5) enforce：分数不变、AI 行不变；`trigger=false` 不改变判定、`trigger=true` 仅高置信项定罪 | PASS |
| 6) 性能增量 | 单条 +1.1 ms（模型推理 0.33 ms），启动加载约 1.3 s |
| 7) 评测集（引擎 × 模型 × OR） | 正常误报 **0.11% → 0.11%**（+0.00pt）；攻击召回 **1.63% → 97.35%**（+95.7pt） |

## 六、成人/赌博内容规则（方案 B，2026-09-20 新增）

**背景**：`pornvideotop.com` 这类站点原本重头戏都躲过了 —— 引擎只有 `no_https`（5 分，阈值 60），
ML 模型给 0.0046（正常）。原因：关键词表最高只有 24 分、模式库最高 35 分且不叠加，**永远过不了 60 分阈值**。

**新增内容**

| 文件 | 改动 |
|---|---|
| `data/adult_keywords.json` | **新增词表**：`domain_strong` / `adult_brands` / `gambling`（域名子串命中→**85 分**）、`domain_weak`（**整标签**匹配→35 分）、`path`（路径/参数→25 分） |
| `utils.py` | 新增 `ADULT_KEYWORDS_FILE`、`_FALLBACK_ADULT_KEYWORDS`、`load_adult_keywords()`、`match_adult_keywords()` |
| `analyzer.py` | 新增 `_check_adult_content()` 规则，并在 `analyze()` 中挂载（开关控制） |
| `config.py` / `config.json` | 新增 `detection.check_adult_content`（默认 `true`） |

**给分设计**：域名命中给 85 分（> 阈值 60）→ **单独定罪，不需要 AI 参与**；
路径命中只给 25 分（仅提示），避免误伤正常站点里的文章/讨论页。

**误伤防护**：① 可信站点（常见合法站 / edu / gov 域）直接跳过；② 短词（`sex`/`adult`/`jav`/`lottery`…）
只做"完整域名标签"匹配，所以 `sexeducation.gov.cn`、`adultlearning.example.com` 不会被误伤；
③ 词表是 JSON，可随时增删，不用改代码。

**实测（规则关闭 vs 开启）**

| 集合 | 条数 | 关闭命中率 | 开启命中率 | 变化 |
|---|---|---|---|---|
| 正常: 完整URL | 71 | 0.0% | 0.0% | +0 |
| 正常: 真实流量 | 11 | 9.1% | 18.2% | **+1（就是 `pornvideotop.com` 本身，目标修复项）** |
| 正常: 路径留出 | 2645 | 0.1% | 0.1% | +0 |
| 攻击: 路径留出 | 491 | 1.6% | 1.8% | +1（含 `xxx` 的 XSS 样本被抓到） |
| 成人/赌博站（10 个） | 10 | 0.0% | **100.0%** | +10 |
| 易误伤对照（gov/edu/javadoc 等 6 个） | 6 | 0.0% | 0.0% | +0 |

**AI 开启时的表现**（模拟 AI 判"安全/99 分"这一最不利情况）：

| 用例 | 分数 | 等级 | 判恶意 | 拦截 |
|---|---|---|---|---|
| `pornvideotop.com` + AI | 58 | 危险 | **True** | 是 |
| `pornvideotop.com` 不用 AI | 18 | 危险 | **True** | 是 |
| `pornhub.com` + AI | 58 | 危险 | **True** | 是 |
| 正常站（百度）+ AI | 99 | 安全 | False | 否 |

> 说明：AI 融合是"分数取平均"，**只能加强、不能推翻**引擎的恶意判定（`is_malicious=True` 后不会被 AI 改回），
> 所以成人/赌博类站点在"AI 开启"时同样会被拦截。

**维护方式**：要加新词只需编辑 `data/adult_keywords.json`（改完重启服务即可，无需改代码）。


## 七、已知注意点


1. **模型能力边界**：它只看"路径/参数形态"，对**域名层**钓鱼（如 `secure-login.faceb00k.tk`）无感 —— 那部分仍由启发式引擎/AI 负责。
2. **短参数路径需观察**：如 `/index.php?id=1` 这类短路径实测概率 0.99（被判恶意），影子期请重点抽查此类真实流量。
3. **依赖版本**：`scikit-learn` 必须与模型训练版本一致（当前 1.9.1）；升级前先跑 `verify_ml_shadow.py` 与第 7 项评测。
4. **启动开销**：模型加载约 1.3 s（一次），仅当 `enable_ml_check=true` 时发生；加载失败会自动降级且不影响任何既有功能。
5. **模型来源**：`MaliciousURLs` 项目训练产物；替换模型只需覆盖 `data/models/lgs_model.pickle`（无需改代码，阈值随模型走）。


---

## 八、方案 A：成人站黑名单批量导入（2026-09-20 新增）

**目的**：覆盖"域名里不含关键词"的成人站（方案 B 的关键词规则只能泛化到有特征词的站）。

**新脚本 `import_adult_blocklist.py`（纯标准库，无需额外依赖）**

```powershell
.\.venv\Scripts\python.exe import_adult_blocklist.py --dry-run     # 只统计（建议先跑）
.\.venv\Scripts\python.exe import_adult_blocklist.py              # 下载并导入（自动备份）
.\.venv\Scripts\python.exe import_adult_blocklist.py --limit 5000 # 试水：只导入 5000 条
.\.venv\Scripts\python.exe import_adult_blocklist.py --remove     # 回滚：删除所有「色情网站」条目
```

- 数据源：StevenBlack porn-only hosts（`https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts`）
- 清洗：兼容 `0.0.0.0`/`127.0.0.1` 前缀、行内注释、重复项，并修复上游脏数据（如 `0.0.0.0.xxx.com`、`0.xxx-cdn.com`）
- **安全过滤**（宁可少封不可错封）：
  1. `utils.TRUSTED_DOMAINS` / edu·gov 等可信后缀 → 剔除；
  2. 共享托管/CDN 平台（amazonaws.com、weebly.com、github.io…）→ 剔除；
  3. 常见合法站与历史已知误报（`quora.com`、`example.com`、`deviantart.com`…）→ 剔除；
  4. 内置"安全校验"：`MUST_NOT_BLOCK`（Google/百度/抖音/GitHub/你日志里的站点…）若被命中会直接报警。
- 分类标记：导入条目统一为「色情网站」，便于识别与一键回滚；写入前自动备份 `data/blacklist.backup-<时间戳>.json`。

**本次导入结果**

| 项目 | 数值 |
|---|---|
| 原始清单 | 156,507 条（4.16 MB） |
| 清洗后候选 | 121,171 条 |
| 安全过滤剔除 | 1,091 条（可信域 247 / 共享平台 780 / 已知合法站 64） |
| **新增入库** | **120,080 条**（其中"整域级"条目 72,863 条） |
| 黑名单总量 | **181,195 条**（色情网站 120,080 + 恶意URL 60,815 + 钓鱼网站 300），文件 8.97 MB |
| 备份 | `data/blacklist.backup-20260920-163448.json`（4.18 MB） |

**导入后验证**

| 用例 | 结果 |
|---|---|
| `007milf.com` / `privatesextapes.com`（新导入） | 分数 0 · 等级「黑名单(色情网站)」· 判恶意 ✓ |
| `www.007milf.com/video/1`、`https://cdn.007milf.com/x.mp4` | 域名级匹配命中（整域封禁覆盖所有子域与路径）✓ |
| `pornvideotop.com`、`xvideos.com` | 黑名单短路命中（优先于关键词规则）✓ |
| 百度 / 抖音 / GitHub / hltv.org | 99 分 · 安全 · 未命中 ✓ |
| Detector 初始化 | 约 **4.2 秒**（黑名单索引 ~3 s + ML 模型 1.2 s）——黑名单变大的一次性代价 |
| `/blacklist` 页面渲染 | `get_blacklist(1000)` 实测 **0.10 s**（全表排序），仍只展示置顶 + 最近 1000 条 |

**维护**：清单会持续更新，建议每月重跑一次（脚本幂等，已存在的条目自动跳过）。
若发现某个导入域名是误封，可在黑名单页删除，或用 `--remove` 一次性撤销全部「色情网站」条目。


---

## 九、黑名单热同步（2026-09-20 新增）—— 导入后无需重启

**背景**：用 `import_adult_blocklist.py` 导入后，终端里黑名单是 181,195 条，但网页仍显示 61,115 条。
原因不是文件错，而是**运行中的进程在启动时把黑名单读进了内存**（该进程 15:58 启动，导入发生在 16:34），之后一直用内存副本。

**修复（`detector.py`）**

| 内容 | 说明 |
|---|---|
| `BLACKLIST_SYNC_INTERVAL = 2.0` | 检查节流：最多每 2 秒做一次 `os.stat`，避免每条 URL 检测都产生磁盘调用 |
| `_blacklist_signature()` | 取 `data/blacklist.json` 的 (修改时间, 大小) 作为指纹 |
| `_sync_blacklist_if_changed()` | 指纹变化 → 重新加载 + 重建索引；**文件损坏/正在写入时保留原数据**，绝不影响检测 |
| 触发点 | `match_blacklist()`、`get_blacklist_count()`、`get_blacklist()`、`get_user_added_urls()` |
| `_save_blacklist()` | 保存后刷新指纹，避免把自己刚写的内容当成"外部改动" |

**效果**：用导入脚本或手工编辑 `data/blacklist.json` 后，**运行中的网站最多 2 秒内自动生效，无需重启**。

**顺带修复的真实崩溃点**：`web_app.py` 启动横幅 `print("🚀 ...")` 在"输出重定向到文件 / 控制台为 GBK(cp936)"时会抛
`UnicodeEncodeError` 导致服务起不来；已在文件顶部加 UTF-8 兜底（`sys.stdout/stderr.reconfigure`）。

**验证**

| 场景 | 结果 |
|---|---|
| 外部写入黑名单（未重启进程） | 自动热加载（2 → 5 条），新域名立即命中 ✓ |
| 文件被写坏（模拟写入进行中） | 保留原数据、不崩 ✓ |
| 页面 getter（计数/列表/置顶项） | 同步更新 ✓ |
| 线上实证（触碰文件 mtime 后访问 /blacklist） | 日志出现「检测到黑名单文件变化, 已自动热加载: 181195 条」✓ |
| 网页显示 | `/blacklist` 显示 **181195**（旧值 61115 消失），首页 200 ✓ |

**运维提示**：黑名单变大后启动索引约 3 秒（一次性）；热加载是整表重读（181k 条约 3 秒，发生在该次请求中，会让这一次请求稍慢）。


---

## 十、开启 ML 单独定罪/拦截（2026-09-20）

`config.json`：`ml_trigger_intercept: false → **true**`（`ml_mode=enforce`、`ml_confidence=0.9` 不变）。

**含义**：ML 高置信（p ≥ 0.9）项现在会 **真正置 `is_malicious=True`** → Web 显示「🔴 恶意链接 + 已拦截」徽章、链接不可点击，
剪贴板监控（`monitoring.auto_intercept=true`）也会实际拦截该链接。分数体系仍不变（`ml_affect_score=false`）。

**开启前的误伤量化（2,844 条正常 + 576 条攻击）**

| 门限 | 正常集误伤 | 攻击集命中 |
|---|---|---|
| p ≥ 0.9（当前） | **1/2844 = 0.04%** | **471/576 = 81.8%** |
| p ≥ 0.95 | 1/2844 = 0.04% | 402/576 = 69.8% |

> 那唯一的"误伤项"是裸路径 `/index.php?id=1`（模型给 0.9932）；但在真实链路里它**在 `is_valid_url` 阶段就被判为"无效URL"短路**，
> 与 ML 无关 —— 因此**实际新增误伤为 0**。完整 URL 形态上（71+11+91+26 条）模型在 p≥0.9 的误报率是 **0.00%**。

**开启后实测**

| 用例 | trigger=false | trigger=true |
|---|---|---|
| `/wp-content/plugins/../../../../etc/passwd` | 放行 | **拦截**（ML 概率 0.9999） |
| SQLi 参数 `session_id=' or 1=1` | 放行 | **拦截**（0.9098） |
| 百度 / 抖音 | 放行 | 放行（99 分·安全） |
| 页面 | — | 结论「恶意链接」+「已拦截」徽章 + 链接不可点击 ✓ |

**已知观感问题（不影响功能）**：ML 单独定罪时，**分数仍是引擎/AI 给的分数**（可能落在"安全"区间，如 97），
于是会出现"评分 97 + 绿色进度条 + 结论却是恶意链接"的混搭。若希望视觉一致，可选方案（需你确认）：
在 ML 单独定罪时把展示分数夹到"可疑"档（如 60–69），或让卡片改用警示配色 —— 二者都只影响展示，不改判定。

**回滚**：`config.json` 的 `ml_trigger_intercept` 改回 `false` 并重启（或依赖热同步重启一次即可）。


---

## 十一、展示层一致性改造（2026-09-20）—— "ML 单独定罪"不再出现分数/结论矛盾

**要做的事**：开启 `ml_trigger_intercept=true` 后，ML 单独定罪的项目**分数仍按引擎/AI 给出**（可能落在"安全"档，如 97），
于是页面出现「评分 97 + 绿色进度条 + 结论却是恶意链接」的混搭。本次把展示层改一致。


---

## 十三、黑名单查询 / 一键移除（Web 新增）

> 目的：不打开 JSON 文件、不影响既有页面与检测逻辑，直接在 Web 上「输入链接 → 查是否在黑名单 → 命中就移除」。
> 纯加法实现：复用已有的多级匹配与移除逻辑，未改动任何既有路由 / 判分 / 拦截行为。

### 1. 使用方式

浏览器打开黑名单页 `http://127.0.0.1:5000/blacklist`，在「➕ 手动添加」下方的查询框里粘贴链接，点 **🔍 查询黑名单**（或回车）：

| 查询结果 | 页面表现 |
|---|---|
| **命中** | 红条提示「⛔ 命中黑名单（相关记录 N 条，黑名单总计 M 条）」，下方表格列出：条目原文 / 分类 / **匹配方式** / ➖ 移除按钮 |
| **未命中** | 绿条「✅ 未命中黑名单（黑名单总计 M 条）」；若同域名下有其它条目，再附一张参考表 |
| **空输入** | 黄条「请输入要查询的链接」 |

- 匹配沿用 `Detector.match_blacklist()` 的 6 级匹配，所以输入**不需要和条目原文一模一样**：
  精确 → 规范化（大小写/端口/末尾斜杠/fragment）→ 忽略协议 → 忽略查询参数 → 父路径 → 域名（纯域名条目覆盖其全部子域）。
  例：条目为 `pornvideotop.com` 时，输入 `https://www.pornvideotop.com/video/1?x=2` 会以「域名匹配」命中。
- 表格里除命中项外，还会列出**同域名下的其它条目**（匹配方式显示为「同域名条目」），便于判断"到底封了几个"。
- ➖ 移除：点按钮 → 确认框显示**条目原文** → 确认后调用 `POST /blacklist/remove_entry`，成功后提示并自动刷新页面。移除的是**条目原文**（不是你的输入），所以不会因为输入带路径而删错东西；条目不存在时明确提示"可能已被移除"。
- 手动添加过的条目被移除时，对应"置顶记录"也一并清理（复用 `remove_from_blacklist()`）。

### 2. 接口（可直接用 curl / 脚本调用）

```powershell
# 查询(只读, 不修改黑名单)
curl "http://127.0.0.1:5000/blacklist/lookup?url=https://www.pornvideotop.com/video/1?x=2"
# -> {"success":true,"input":"...","matched":true,"host":"www.pornvideotop.com",
#     "total":181195,"hits":[{"entry":"pornvideotop.com","category":"色情网站","level":"域名匹配"}]}

# 按条目原文移除(必须传条目原文, 即查询结果里的 entry)
curl -X POST -d "entry=pornvideotop.com" http://127.0.0.1:5000/blacklist/remove_entry
# -> {"success":true,"removed":true,"entry":"pornvideotop.com","category":"色情网站","total":181194}
```

### 3. 实现位置

| 文件 | 改动 |
|---|---|
| `detector.py` | 新增 `lookup_blacklist(url)`（只读查询，返回 `matched/hits/host/total`）与 `remove_blacklist_entry(entry)`（返回 `removed/reason/total`）；两者都复用既有 `match_blacklist()` / `remove_from_blacklist()`，未改动原方法 |
| `web_app.py` | 新增 `GET /blacklist/lookup`、`POST /blacklist/remove_entry` 两个 AJAX 接口；未改动 `/blacklist/remove`（原表单式删除仍可用） |
| `templates/blacklist.html` | 新增查询框 + 结果区 + `lookupBlacklist()` / `removeEntry()` JS（输出全部经 HTML 转义，防 XSS）；原有添加/导入/列表/删除区块一字未动 |

### 4. 回滚

```powershell
# 只需删掉新增的三处即可(其余功能不受影响)
#   web_app.py 中 blacklist_lookup / blacklist_remove_entry 两个路由
#   templates/blacklist.html 中「黑名单查询(新增)」区块 + 两个 JS 函数
#   detector.py 中 lookup_blacklist / remove_blacklist_entry 两个方法
```

**改动（`web_app.py::get_result_html`，仅展示层）**

| 项 | 规则 |
|---|---|
| 触发条件 | `is_malicious` 且 非黑名单命中 且 `ml_mode=='enforce'` 且 `ml_high` 且 真实分数 ≥ 70（即"ML 单独定罪"） |
| 展示分数 | 线性夹到**可疑档 60–69**（70→60、99→69，保留相对高低） |
| 卡片配色 | `border-warning` / `bg-warning` + 标题文字 `text-dark`（警示黄） |
| 等级文字 | 进度条文案 = 「可疑 · {展示分数}/100」；基本信息里的等级用 `text-warning-emphasis` |
| 拦截原因 | 改为「ML 通道高置信判定为恶意（分数体系未参与打分）」 |
| ML 区块标注 | 「⚠ **该判定来自 ML 通道（分数体系未参与打分）**：模型高置信判恶意，已参与拦截；上方风险评分已按"可疑"档展示。」 |

**明确不变**：`result.score`、日志字段（`detection_log.json` 里仍是真实分数）、CSV 导出、判定结果、AI/引擎/黑名单逻辑。
—— 即"页面看得一致，数据不失真"。

**实测（4 类用例）**

| 用例 | 真实分数 | 展示分数 | 等级 | 卡片配色 | 已拦截 | 标注 |
|---|---|---|---|---|---|---|
| ML 单独定罪（payload 路径） | 97 | **68** | **可疑** | **warning** | 是 | 有 |
| 正常站（百度） | 99 | 99 | 安全 | success | 否 | 无 |
| 黑名单（成人站） | 0 | 0 | 黑名单 | dark | 是 | 无 |
| 引擎自己定罪（钓鱼域名） | 50 | 50 | 危险 | danger | 是 | 无 |

> 说明：`/index.php?id=1` 这类"裸路径"会在 `is_valid_url` 阶段判为无效 URL 短路，不走 ML 通道。

**回滚**：纯展示逻辑，无开关；如需恢复原样，删掉 `get_result_html` 里 `ml_only_conviction / display_score` 相关分支即可
（把 `display_score` 全部换回 `score`、`header_text_class` 换回 `text-white`、`level_span_class` 换回 `text-{risk_class}`）。


---

## 十二、方案A 落地：双模型通道（Phase 0 → Phase 2，2026-09-22）

### 架构

```
域名模型(domain)  ← 新增, data/models/domain_model.pkl
   输入 hostname → 字符 n-gram(2-4) TFIDF + 20 维结构化特征 → LR → 概率/阈值
路径模型(path)    ← 原模型, data/models/path_model.pkl(= lgs_model.pickle 的副本, 原文件保留)
   输入 完整URL → 字符 3-gram TFIDF → LR → 概率/阈值
两通道各自: 阈值 / 高置信门限 / 是否参与拦截(trigger_intercept), 以 OR 通道合并
```

| 文件 | 变化 |
|---|---|
| `ml_url_model.py` | 新增 `DomainURLModel`（域名模型适配）、`host_struct_features`（20 维结构特征）、`MLChannel`（多模型管理器）；原 `MLUrlModel` 保留 |
| `detector.py` | `Detector.__init__` 改用 `MLChannel`（双通道）；`detect()` 的 ML 块按通道追加详情与定罪；`DetectionResult` 新增 `ml_domain_prob / ml_path_prob / ml_convict / ml_hint / ml_thresholds` |
| `config.py` / `config.json` | 新增 `detection.ml_models`（domain / path 各自 enabled、path、confidence、trigger_intercept）；旧键保留作回退 |
| `web_app.py` | ML 区块改为**分通道展示**（域名模型/路径模型各一行 + 综合概率 + 参与拦截的通道） |
| `verify_ml_shadow.py` | 降级测试改为覆盖双模型（双缺 / 仅缺域名模型） |
| `ml_training/` | **新增**：`build_domain_dataset.py`（Phase 0）、`train_domain_model.py`（Phase 1）、`README.md`（含红线与实测） |
| `data/models/` | `domain_model.pkl`(11.7MB, 新)、`path_model.pkl`(2.31MB, 副本)、`archive/path-v1-20260922.pkl`(归档)；`lgs_model.pickle` **保留未删** |

### 线上配置（按实测指标设定）

| 通道 | 阈值 | 高置信门限 | 参与拦截 | 理由 |
|---|---|---|---|---|
| domain | 0.9959 | 0.90 | **false（仅提示）** | 严格误报档下召回 4.78%，低于引擎 27.41% → 尚不可定罪 |
| path | 0.6100 | 0.90 | **true** | 0 误报下召回 84.9%（实测），继续承担拦截 |

### 验证记录

| 项 | 结果 |
|---|---|
| 一致性（ML 关 vs 影子，含 AI 行/非ML详情条数） | 差异 **0** ✅ |
| AI 行完整 / ML 文案不含 "DeepSeek" | ✅ / ✅（16 条 ML 详情行） |
| 双模型都缺失 → 与基线逐字段一致、AI 行相同 | ✅ |
| 仅缺域名模型 → 路径模型仍工作 | ✅ |
| 黑名单短路优先级 / enforce 分数与 AI 行不变 | ✅ / ✅ |
| 性能 | 单条 detect 2.73 → 3.60 ms（**+0.87 ms**），启动加载 1.2–1.4 s |
| 页面渲染 | 攻击 payload：域名 0.1038 / 路径 0.9999 / 参与拦截 `['path']`；正常站：0.0204 / 0.021 / 无 |
| DeepSeek 连通性 | 实测可用（1.6 s，返回 is_malicious/score/reasons） |

### 红线遵守情况

**不与路径模型混训**（域名模型只用 hostname 样本）｜**按注册域 80/20 切分**（脚本打印泄漏检查=0）｜**阈值由整体误报上限决定**（`--max-fpr`，打印五档曲线）｜**模型不进 0-100 分**（`ml_affect_score=false`）｜**只用 hostname 字符串**（无页面内容/网络请求）｜**噪声清洗**（可信域 7,008 / 共享平台 909 / `free-counter` 类 116 从正样本剔除并转难负样本）

### 回滚

```powershell
# 只关域名通道(保留路径模型)
#   config.json → ml_models.domain.enabled = false  → 重启
# 回到"单模型时代"
#   config.json 删掉 ml_models 整段 → 自动用 ml_model_path(lgs_model.pickle) 单模型
# 彻底关闭
#   detection.enable_ml_check = false → 重启
# 换回旧模型文件
#   copy data\models\archive\path-v1-20260922.pkl data\models\path_model.pkl
```
