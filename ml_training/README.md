# ml_training —— 域名级模型的训练与评测（方案A / Phase 0→1）

> 本目录只做**训练与评测**，不影响线上检测；模型产物写入 `../data/models/`，
> 由 `../ml_url_model.py` 加载（普通字典 pickle，不含自定义类）。

## 1. 两个脚本（按顺序跑）

```powershell
cd d:\Vscode\eyilianjie
.\.venv\Scripts\python.exe ml_training\build_domain_dataset.py     # Phase 0: 建数据集(防泄漏)
.\.venv\Scripts\python.exe ml_training\train_domain_model.py       # Phase 1: 训练+评测+存档
```

- **Phase 0**（`build_domain_dataset.py`）
  - 正样本：`data/blacklist.json`（清洗：剔除可信域 7,008 / 共享托管平台 909 / 噪声 116，如 `free-counter` 家族）
  - 负样本：Tranco top-1M **全量随机抽样** + 合法子域（消除"有子域=恶意"的构造性捷径）+ 最长域名 + punycode 站
  - 难负样本（仅训练）：`login./secure./account.` 等敏感词子域 + 共享平台子域
  - **按注册域 80/20 切分**，脚本会打印"泄漏检查"（训练∩测试 注册域 = 0 才算通过）
  - 真实流量（`detection_log.json` 的安全记录）只用于评测
  - 产物：`data/domain_train.tsv / domain_test_pos.tsv / domain_test_neg.tsv / domain_realtraffic.tsv`（`label<TAB>host<TAB>category`）
- **Phase 1**（`train_domain_model.py`）
  - 特征：**hostname 的字符 n-gram(2-4) TF-IDF + 20 维结构化特征**（长度/标签数/数字比/元音比/连字符/熵/最长辅音串/是否IP/punycode/高危TLD/免费主机/品牌词/成人词/敏感词/是否 www…），结构特征按训练集均值方差标准化
  - 分类器：LogisticRegression（liblinear，C=4）
  - 阈值：**在"正常集（测试负 + 真实流量）整体误报率 ≤ `--max-fpr`（默认 1e-4）"前提下取召回最高**，并打印 0 / 1e-5 / 1e-4 / 1e-3 / 1e-2 五档曲线
  - 同时给出**引擎（启发式、不含黑名单）基线**与 **OR 融合**对比
  - 产物：`../data/models/domain_model.pkl` + `metrics/domain-<时间戳>.json`

## 2. 本机实测（2026-09-22）

数据：训练 212,791（正 52,636 / 负 160,155）｜测试 正 12,230 / 负 37,457｜真实流量 10

| 阈值档 (FPR≤) | 阈值 | 测试正召回 | 测试负误报 | 真实流量误报 |
|---|---|---|---|---|
| 0 | 0.997891 | 3.24% | 0 | 0 |
| **1e-4（当前采用）** | 0.995898 | **4.78%** | 3 | 0 |
| 1e-3 | 0.979874 | 14.41% | 36 | 1 |
| 1e-2 | 0.791891 | 47.79% | 372 | 2 |

分类别召回：色情 565/11,583 (4.9%)、恶意URL 19/627 (3.0%)、钓鱼 1/20 (5.0%)
对照基线：**引擎（启发式）召回 27.41%**（负样本误报 754）｜OR 融合 29.84%（+2.43pt）

**结论**：该模型**尚未达到"可定罪"水平**（在严格误报档下低于引擎），因此线上把它配成 **"仅提示"**（`trigger_intercept=false`）；
路径模型（原模型，实测 0 误报下召回 84.9%）继续承担定罪与拦截。

## 2.1 2026-10-02 评测集整理 + 规则校准（本轮）

### 新工具（都可离线跑）

| 脚本 | 作用 |
|---|---|
| `ml_training/build_eval_sets.py` | 整理评测集 + 生成 `data/tld_risk.json`（TLD 恶意富集表） |
| `ml_training/audit_engine.py` | 引擎体检：每条规则的命中率/富集倍数 lift、阈值敏感性、覆盖缺口、误报明细；加 `--extra` 额外测 IP / URL 级样本 |

### 新增产物

| 文件 | 说明 |
|---|---|
| `ml_training/data/domain_test_neg_clean.tsv` | 清洗后的负样本：剔除 **684 条"真成人/赌博站"**（Tranco 里混进来的标签噪声）；punycode 合法站 1,430 条单独标记为 `punycode` |
| `ml_training/data/eval_ip.tsv` | IP 直连恶意样本 **42,853** 条（以前被当 `invalid` 整批丢弃） |
| `ml_training/data/eval_url.tsv` | 带路径的恶意 URL **17,955** 条 |
| `ml_training/data/eval_manifest.json` | 本次整理统计（黑名单分类、负样本清洗量、TLD 表规模） |
| `data/tld_risk.json` | TLD 恶意富集表：46 个 TLD，按 lift 分 20/12/6 分；文件缺失时自动回退内置 `SUSPICIOUS_TLDS` |

### 指标变化（同一份正样本 12,230）

| 指标 | 改前（原始负样本） | 改后（清洗负样本 + 规则修正） |
|---|---|---|
| 整体召回 | 27.36% | 27.29%（基本不变） |
| 整体误报 | **1.865%** | **0.008%** |
| `deceptive_domain` lift | 0.2（最差，负命中 3.81%） | **1063（最专一，负命中 0）** |
| `special_chars` 负命中率 | 3.285% | 0.381% |
| `suspicious_tld` 正命中率 | 6.17% | **13.25%**（数据驱动补了 20 个高 lift TLD） |
| `dga` 正/负命中率 | 6.30% / 10.37% | 1.44% / 4.098% |

### 规则改动（4 处，均在 `analyzer.py`）

1. `suspicious_tld`：改为查 `data/tld_risk.json` 按 lift 分级给分（20 / 12 / 6）；没有该文件时回退内置表（12 分）
2. `deceptive_domain`：punycode 不再"一刀切"——**先解码、再做同形字归一化、与品牌相似才计分**（合法 IDN 如 `xn--fiqs8s`、`.xn--p1ai` 不再计分）
3. `dga`：收紧判据（纯字母的长词不算 DGA，须含数字或元音极少）+ 分值 12 → 8
4. `special_chars`：连字符规则加条件（须同时含敏感词才给 8 分，否则 4 个以上只给 3 分）；`xn--` 前缀不计入连字符

### 被暴露的两个覆盖缺口（下一步优先）

| 数据集 | 条数 | 引擎召回 |
|---|---|---|
| IP 直连恶意 | 42,853 | **4.26%**（`ip_host` 只给 20 分，远低于阈值 60 → 几乎全靠黑名单命中） |
| 带路径恶意 URL | 17,955 | **1.89%**（域名级规则看不到路径信息） |

### 复跑方式

```powershell
python ml_training\build_eval_sets.py          # 评测集 + TLD 表
python ml_training\audit_engine.py --extra     # 体检（含 IP/URL 维度）
```
报告写入 `ml_training/metrics/audit-<时间戳>.md`（本轮的两份存档：`audit-clean.md` / `audit-after.md`）。

## 2.2 2026-10-02 第二轮：成人分档（5a）+ IP 直连分级（5b）

### 5b：IP 直连分级（`analyzer._check_ip_address`）

| 场景 | 改前 | 改后 |
|---|---|---|
| 内网/保留地址（127/8、10/8、172.16/12、192.168/16、169.254/16、::1、fc00::/7…） | 20 分 | **0 分**（新增 `_is_private_or_reserved`，连十进制整数写法也识别） |
| 公网 IP（点分十进制） | 20 分 | **45 分** |
| 非标准写法（整数 / 十六进制 / 八进制 / IPv6 字面量） | 20 分 | **60 分**（单独定罪） |

- 顺带修掉 `_check_excessive_subdomains` 把 IP 当子域的既有 bug（`8.8.8.8` 曾被数成 2 级 +5 分）
- 实测：IP 直连恶意样本召回 **4.26% → 100.00%（http：45 + no_https 15 = 60）**；
  **https 仍 4.26%**（45 分不单独定罪，需配合端口/路径关键词）
- 域名级样本指标不变（27.29% / 0.008%）；`python -m guard selftest` 53/53

### 5a：成人/赌博分档（`analyzer._check_adult_content`，C2）

| 证据 | 改前 | 改后 |
|---|---|---|
| 知名成人品牌（pornhub / xvideos …） | 85 | **85** |
| 赌博词（casino / bet365 …） | 85 | **80** |
| 成人强词（porn / xxx / hentai …） | 85 | **75** |
| 弱词（sex / adult / jav，仅整标签匹配） | 35 | **45** |
| 路径 / 参数命中 | 25 | 25 |
| 组合 | — | 弱词 + 路径成人词 同现 → +10（**刻意不复用 TLD**：`suspicious_tld` 已为该信号计分，复用会重复加 10 分） |

- 实测：召回 27.29%、误报 0.008%（与改前一致 —— 属"结构改善、行为等价"）
- 收益：分数可分档解释（页面 details 会写「知名成人品牌 / 赌博关键词 / 成人强词 / 敏感标签」），
  后续做按类别阈值、组合规则才有依据
- 可选微调：把弱词 45 → 50，预演可多召回 18 条（27.29% → 27.43%），只改一个数字

## 2.3 2026-10-02 第三轮：域名模型 v2（第 6 步）

### 新工具

| 脚本 | 作用 |
|---|---|
| `ml_training/build_extra_positives.py` | 抓外部恶意样本（URLhaus / URLhaus-domains / OpenPhish / PhishingArmy），按类别配额 + 按注册域防泄漏 |
| `ml_training/train_domain_model_v2.py` | 重训域名模型：负样本清洗 + 类别配额 + Platt 校准 + 同口径对比 baseline |

### 外部样本（`ml_training/data/external_*.tsv`）

| 类别 | 可用 | 采样 | 来源 |
|---|---|---|---|
| 钓鱼 | 152,009 | 20,000 | OpenPhish(275) + PhishingArmy(151,734) |
| 恶意下载 | 1,857 | 1,857 | URLhaus csv(567) + URLhaus-domains(1,290) |
| URL 级样本 | — | 18,363 | 供第 7 步用（`external_url.tsv`） |

防泄漏跳过 4,181 条（与测试集同注册域）；IP 样本跳过 31,562 条（归 `ip_host` 规则）。

### v2 vs baseline（同一测试集、同 FPR 口径）

| 指标 | baseline（现网 v1） | **v2** |
|---|---|---|
| 测试集 AUC | 0.9161 | 0.9003 |
| **FPR≤1e-4 召回** | **4.66%** | **29.46%（6.3 倍）** |
| 测试负误报 | 3 | 2 |
| 分类别召回 | 色情 4.9% / 恶意URL 3.0% / 钓鱼 5.0% | 色情 **30.6%** / 恶意URL **9.7%** / 钓鱼 5.0% |
| 与引擎(启发式) OR | 29.84% | 29.47%（净增 +2.18pt） |

- 训练 171,274（正 38,034 / 负 133,240）；校准验证集 30,223；特征 159,974 维
- Platt 校准：a=1.0932、b=0.1248 → 验证集预测恶意率 0.2221 vs 真实 0.2220（校准准确）
- 产物：`data/models/domain_model_v2.pkl`（6.38 MB，**未替换现网模型**）、`ml_training/metrics/domain-v2-*.json`

### 结论（决定第 7 步方向）

1. **域名级通道已饱和**：v2 单独 29.46%、引擎 27.29%，两者 OR 后只有 29.47% —— 说明它们抓的是同一批线索（成人词、可疑 TLD、DGA…）；
2. **钓鱼在域名级几乎无效**：`paypal-verify.xyz`(0.27) / `secure-login.faceb00k.tk`(0.99，仍低于零误报阈值 0.9984)；
3. 因此第 7 步应转向 **URL / 路径级**，并用 `external_url.tsv`（18,363 条真实恶意 URL）建评测集。

### 复跑 / 已完成的替换（2026-10-20 执行完毕）

```powershell
# 1) 抓外部样本（需联网） + 2) 训练 / 校准 / 对比 baseline
python ml_training\build_extra_positives.py
python ml_training\train_domain_model_v2.py

# 3) 备份（v1）+ 替换（v2）—— 已于 2026-10-20 执行
Copy-Item data\models\domain_model.pkl    data\models\archive\domain-v1-20261020.pkl -Force
Copy-Item data\models\domain_model_v2.pkl data\models\domain_model.pkl -Force

# 回滚到 v1（一条命令即可）
Copy-Item data\models\archive\domain-v1-20261020.pkl data\models\domain_model.pkl -Force

# 想让该通道也参与拦截：config.json → ml_models.domain."trigger_intercept": true
```

**现网状态（已验证）**

| 项 | 值 |
|---|---|
| `data/models/domain_model.pkl` | **v2**：阈值 0.9984、词表 159,954 维、**已校准**（platt a=1.0932 / b=0.1248） |
| `trigger_intercept` | 仍为 **false**（只提示、不定罪）→ 判定行为与替换前**完全一致** |
| 备份 | `data/models/archive/domain-v1-20261020.pkl`（12.27 MB，原 v1） |
| 回归 | `python -m guard selftest` → **53/53**，ML 通道日志显示 `domain(阈值0.9984, 拦截=False)` |

## 2.4 2026-10-20 第四轮：URL 级评测集 + path 模型真实基线（第 7 步 7-A/7-B）

### 新工具

| 脚本 | 作用 |
|---|---|
| `ml_training/build_url_eval.py` | 建 URL 级评测集：正 = 外部 URL（URLhaus/OpenPhish）+ 黑名单带路径条目；负 = 正常域名 × 路径模板；按注册域 80/20 切分 + 防泄漏 |
| `ml_training/eval_path_model.py` | 测现网 path 模型的真实基线，并与域名级（v2）做同批对照 |

### 评测集（`ml_training/data/urleval_*.tsv`、`urltrain_*.tsv`）

| 项 | 数量 |
|---|---|
| 正样本（去重） | 79,057（外部 18,363 + 黑名单带路径 60,694） |
| 负样本 | 36,763（36,763 个正常域名 × 20 种路径模板） |
| 切分（按注册域 80/20） | 训练 正 67,151 / 负 29,418；**评测 正 11,906 / 负 7,345** |
| 防泄漏 | 负样本注册域与正样本无交集（仅排除 10 个域名） |
| 评测集 IP 占比 | 59.5%（黑名单里 IP URL 本就多） |

### 现网 path 模型真实基线（⚠️ 与旧文档的 84.9% 完全不同）

| 口径 | 召回 | 负样本误报 |
|---|---|---|
| **现网阈值 0.61（生产正在用）** | **2.58%**（307/11,906） | 1/7,345（0.014%） |
| 零误报（阈值 0.7013） | 2.03% | 0 |
| FPR≤1e-3 | 6.51% | 7 |
| FPR≤1e-2 | 14.77% | 73 |
| AUC | **0.7188** | — |

分类别（口径 A）：恶意下载 1.6%、钓鱼 **0%**、钓鱼网站 **0%**、IP 直连 3.0%、**非 IP（域名 URL）1.9%**。

### 与域名级同批对照（11,906 条恶意 URL）

| 通道 | 阈值 | 召回 |
|---|---|---|
| 域名级（现网 v2） | 0.9984 | 1.14% |
| URL 级（path） | 0.6100 | 2.58% |
| **两者 OR** | — | **3.72%（+2.58pt）** |

### 结论（决定第 7 步怎么走）

1. **旧文档的"零误报召回 84.9% / 攻击召回 97.35%"不适用于本项目数据** —— 那是
   `MaliciousURLs` 项目评测集的结果（样本带明显 payload 特征）。本项目真实恶意 URL
   （URLhaus 下载、OpenPhish 钓鱼、黑名单）**路径大多是正常结构**（`/login`、`/download/x.exe`）。
2. path 通道 AUC 0.72：**有信号但很弱**；现网阈值下只覆盖 2.58% → **几乎不贡献拦截，但也几乎不误报**（留着无害）。
3. **"URL 全文 n-gram"不是正确方向**：负样本里同样有 `/login`、`/download` → 模型把路径学成"正常"。
4. 真正有增量的是**「域名 × 路径」联合信号**（域名含品牌词 + 路径是 login/verify；域名正常 + 路径是随机串/编码载荷）。

### 第 7 步后续选项（7-C 之前先定方向）

| 选项 | 做法 | 预期 |
|---|---|---|
| **7-C1 联合特征模型** | 特征 = 域名模型概率 + 路径结构 + **品牌错配**（域名品牌词 vs 路径品牌词）+ 路径敏感词组合 | 零误报召回 2% → 10%+（待验证） |
| **7-C2 规则组合（不做模型）** | analyzer 加组合规则：品牌词域名 + 登录类路径；域名正常 + 可疑扩展名 + 诱导词 | 立刻可见、成本最低 |
| **7-C3 换信号源** | 证书 CN/SAN（代理侧可拿）、WHOIS 注册龄、外部威胁情报 API | 天花板最高，但要联网/改动大 |
| **7-C4 保持现状** | path 通道留着（无害），资源转到 7-C2/7-C3 | 零风险 |

## 2.5 2026-10-20 第五轮：7-C2「域名 × 路径」组合规则

### 改动（`analyzer._check_domain_path_combo`，新增规则 `combo`）

| 分支 | 触发条件 | 分值 |
|---|---|---|
| **A 品牌错配** | 域名含品牌词，但注册域标签 ≠ 该品牌，**且**路径/参数含 login / verify / account / password / unlock… | **40** |
| **B 恶意下载** | 路径是危险扩展名（`.exe/.msi/.scr/.ps1/.vbs/.hta/.jar/.apk/.dmg/.iso/.lnk`）**且**含 download / setup / free / crack / 下载 / 破解… | **30** |
| **C 随机串路径** | 路径段 ≥16 位且字母数字混合（≥8 字母 + ≥4 数字） | **20** |

- 可信站点跳过；最高 40 分（**不单独定罪**，与 TLD / 关键词 / IP 等信号叠加才越线）
- 在 `analyze()` 里注册为 `combo`（位置：模式库之后、成人规则之前）

### 效果（同一份 URL 评测集：正 11,906 / 负 7,345）

| 指标 | 改动前 | 改动后 |
|---|---|---|
| **combo 规则本身** | — | 正命中 598（5.02%）／负命中 2（0.027%）→ **lift 184.5（极专一）** |
| 整体召回 | 59.95%（7,138） | **60.24%（7,172，+34 条）** |
| 负样本误报 | 1（0.014%） | 3（0.041%） |
| 恶意下载类召回 | 2/2,389（0.1%） | **8/2,389（0.3%）** |
| 钓鱼类召回 | 0/31 | 0/31 |
| 非 IP（域名 URL）召回 | — | **1.8%（89/4,818）** |
| IP 直连召回 | — | 99.9%（7,083/7,088） |

### 结论

1. combo 规则**很干净**（lift 184.5、负命中 2 条），零成本补了 34 条 → **建议保留**。
2. 但**增量很小**（+0.29pt），说明"域名 × 路径"的**规则组合也已到顶** —— 这与 path 模型（1.9% 召回）**两次独立验证了同一结论**。
3. **非 IP 域名 URL 召回仅 1.8%**：这正是真实网页浏览的主场景，"纯字符串"方法几乎无能为力。
4. **第 7 步（7-C）到此为止**；再往上需要新的信号源（见 2.6 / 选项）。

回归：`python -m guard selftest` → **53/53**。
产物：`ml_training/metrics/rules-url-before-*.md`、`rules-url-after-combo-*.md`（含每条规则 lift 表）。

## 2.6 2026-10-20 第六轮：8-A「警告档」（三档判定）

### 为什么先做量化（量化结果改变了设计）

- 原设想按 **analyzer 分数 40~59** 做警告档 → 实测该区间**几乎没样本**（正 0.65% / 负 0.20%），
  因为分析器分数是"规则加和"，天然只有「0 或大分」两极。
- 改用**校准后的 ML 概率**（domain v2）分档 → 覆盖率高得多：

| 分档 | 恶意域名 12,230 | 正常域名 36,773 |
|---|---|---|
| 放行 <0.50 | 28.80% | 93.38% |
| 弱提示 0.50–0.90 | 22.30% | 6.04% |
| **警告 0.90–0.9984（新增档）** | **19.41%（2,374）** | **0.57%（210）** |
| 拦截 ≥0.9984 | 29.49% | 0.01% |

→ **19.4% 的恶意站**从"静默放行"变成"警告页（可继续）"，代价是 **0.57%** 的正常站看到警告。

### 实现

| 层 | 改动 |
|---|---|
| `guard/engine.py` | `_decision()` 增加 `warn` 字段；`_judge_uncached()` 收尾改三档：命中规则→**拦截**；否则 `ML 域概率 ≥ warn_prob` 或 `启发式分 ∈ [warn_score, 阈值)` → **warn**；其余放行。`_ml_judge()` 的 raw 里补上每模型概率 |
| `guard/settings.py` | 默认配置新增 `block.warn_prob: 0.90`、`block.warn_score: 40` |
| `guard/extension/background.js` | `(!blocked && !warn)` 才放行，否则切到扩展页 |
| `guard/extension/blocked.js` | `decision.warn` 时：标题→「⚠ 该链接存在风险」、副标题说明"可继续"、按钮→「仍然访问（不推荐）」**立即可点**（无 10 秒倒计时）、「这是误报？加入放行名单」 |
| 版本 | 扩展 → **1.0.4** |

### 已知限制（重要）

- **代理侧不出警告页**：warn 档在代理里仍按"放行"处理（HTTP 请求无法"用户点继续再转发"）。
  即 **警告页只对装了扩展的浏览器生效**；只用代理的同学行为不变（零影响、零风险）。
- 想"代理也出警告页"需要新接口 + 一次性令牌（可被滥用），本轮**刻意不做**。

### 验证

- `python -m guard selftest` → **54/54 通过**（新增 I20：放宽警告线 → warn=True；默认配置 → 正常站 warn=False）
- 扩展桩测（node）→ **5/5**：拦截→跳页(warn=false) ｜ 警告→跳页(warn=true) ｜ 放行→不跳
- 顺带修掉一个真实缺陷：`cfg.get(key, 默认) or 默认` 会把配置里的 **0** 当"未设置"（0 是 falsy）

### 调参

- `guard/data/config.json` → `block.warn_prob`（默认 0.90，越小警告越多）、`block.warn_score`（默认 40）
- 想**关闭警告档**：`warn_prob` 设 1.01、`warn_score` 设 9999（都不会命中）

## 3. 红线（改数据/训练时务必遵守）

1. 域名样本**绝不混入**路径/payload 模型（两类任务互相拖累，已验证）；
2. **不泄漏**：训练/测试按注册域切分；黑名单不得同时用于训练与测试（脚本已自动检查并打印）；
3. **不为单个 case 降阈值**：阈值由整体正常集误报上限决定（`--max-fpr`），并在指标里存档；
4. 模型**不参与 0-100 分**（`ml_affect_score=false` 保持不变）；
5. 不引入"页面内容"特征（只使用 hostname 字符串）；
6. **标签噪声清洗**：`NOISE_PATTERNS` / 共享平台 / 可信域 从正样本剔除，并作为难负样本。

## 4. 提升方向（Phase 3，按性价比排序）

| 方向 | 说明 |
|---|---|
| 扩充正样本类别 | 当前正样本 96% 是色情域名；接入 URLhaus / OpenPhish / PhishTank 扩大钓鱼与恶意下载样本 |
| 更匹配的负样本 | 增加"冷门但合法"的域名（长尾），当前负样本仍偏热门站；可用公开的更大域名清单 |
| 特征工程 | 注册龄/WHOIS（需联网，注意隐私）、TLD 信誉表、品牌相似度（编辑距离）等结构化特征 |
| 阈值与校准 | 用 isotonic/Platt 校准概率后再选阈值；或按类别分别设阈值（钓鱼/色情/赌博） |
| 换策略 | 若域名层长期难达标，可改为"清单+规则"为主，模型仅用于排序/提示 |

## 5. 重训与替换（不需要改代码）

```powershell
# 1) 重建数据集  2) 重训  3) 看评测是否达标  4) 重启 web_app 生效
.\.venv\Scripts\python.exe ml_training\build_domain_dataset.py
.\.venv\Scripts\python.exe ml_training\train_domain_model.py
# 5) 若达标, 在 config.json 里把 ml_models.domain.trigger_intercept 改为 true
# 6) 回滚: 把 data/models/domain_model.pkl 换回 archive/ 里的旧文件
```
