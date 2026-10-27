# 恶意链接跳转拦截与检测系统

基于 Flask + 启发式规则 + 机器学习的恶意 URL 检测与浏览器拦截系统（大三课程实践项目）。

**在线演示：<https://like737.github.io/111/>**

> 演示站是 `docs/` 里的静态快照，**只读**：页面展示、导航、样式完整，但表单提交与
> `/detect`、`/blacklist/*` 等接口没有后端，会返回 404。需要完整体验请本地运行。

---

## 功能特性

| 模块 | 说明 |
| --- | --- |
| 启发式检测 | 短链、可疑 TLD、IP 直连、同形字/欺骗性域名、DGA、高危文件下载、可疑关键词等 16 项规则 |
| 黑名单 / 白名单 | 本地 JSON 规则库，支持手动添加、批量导入、在线查证 |
| 机器学习通道 | 域名模型 + 路径模型并行（`data/models/`），`shadow` 只提示 / `enforce` 参与判定 |
| AI 辅助复核 | 可选接入 DeepSeek 大模型做二次研判，未配置密钥时自动跳过 |
| 浏览器拦截 | `guard/` 提供本地代理与拦截控制台，支持系统代理接管与告警提示 |
| 可视化报告 | 统计摘要、7 日趋势、最近检测、CSV 导出 |

## 快速开始

```powershell
git clone https://github.com/like737/111.git
cd 111

# 1. 准备虚拟环境
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# 2. 生成配置（仓库里不含 config.json）
Copy-Item config.example.json config.json

# 3. 填入密钥（二选一）
#    A. 写进 config.json 的 api_keys.deepseek
#    B. 不落盘，用环境变量（优先级高于配置文件）
$env:DEEPSEEK_API_KEY = "sk-你的密钥"

# 4. 启动
python web_app.py
```

打开 <http://127.0.0.1:5000> 即可。

> `Config.CONFIG_FILE` 是相对路径，**必须在项目根目录**启动 `web_app.py`。
> 没有配置文件时程序也能启动（使用内置默认值），但 `detection.ml_mode` 会退化为
> `shadow`（只记录、不参与拦截），与 `config.example.json` 的 `enforce` 不同。

## 配置与密钥

- `config.json` 内含真实的 `api_keys`，**已被 `.gitignore` 排除**，请勿提交。
- 密钥推荐用环境变量提供，避免落盘：

  | 环境变量 | 对应配置项 |
  | --- | --- |
  | `DEEPSEEK_API_KEY` | `api_keys.deepseek` |
  | `EY_VERBOSE=1` | `logging.verbose_startup` |

- `guard/data/config.json` 是拦截层自身的开关配置，不含密钥，**已入库**。
- 证书私钥（`*.key`）与本地检测日志（`detection_log.json`）同样被排除。

## 目录结构

```
.
├─ web_app.py            # Flask 入口与路由
├─ detector.py           # 检测主流程（规则 + 黑名单 + ML）
├─ analyzer.py           # 启发式规则与评分
├─ ml_url_model.py       # 域名 / 路径双模型推理
├─ reporter.py           # 检测历史与统计
├─ config.py             # 配置加载（支持环境变量覆盖密钥）
├─ config.example.json   # 配置模板（密钥留空）
├─ icon_svg.py           # 导航栏与页面图标（Jinja 全局函数）
├─ templates/            # Jinja2 模板（base.html 承载导航栏与全局样式）
├─ static/               # 图标、背景图、本地化 Bootstrap
│  └─ vendor/            # Bootstrap 5.3.0（本地内嵌，不依赖 CDN）
├─ data/                 # 规则库与预训练模型
├─ ml_training/          # 模型训练与评估脚本
├─ guard/                # 浏览器拦截层（代理 + 控制台）
├─ tools/
│  ├─ export_docs.py     # 导出静态站快照到 docs/
│  └─ demo_log.py        # 生成合成演示数据
├─ docs/                 # 静态演示站（自动生成，勿手改）
└─ .github/workflows/    # sync-docs：模板变更后自动重建 docs/
```

## 静态演示站

`docs/` 由 `tools/export_docs.py` 生成，**不要手工编辑**：

```powershell
python tools/export_docs.py
```

- 来源：`config.example.json` + **合成演示数据**（`tools/demo_log.py`）。
  真实 `config.json` 与 `detection_log.json` **不会被读取**，避免密钥泄露和个人浏览记录外泄。
- 渲染：走 Flask `test_client`，`{{ }}` / `{% %}` 会被真正求值，导航栏图标为真实 SVG。
- 路径：内部绝对路径统一改写为相对路径，以适配 `https://like737.github.io/111/` 的子路径。
- 自动同步：`.github/workflows/sync-docs.yml` 在 `templates/`、`static/`、`tools/` 等变更时
  自动重建并提交 `docs/`，无需手动操作。

## 常见问题

**线上导航栏变竖排 / 样式全丢？**

先看浏览器控制台 Network：若 `bootstrap.min.css` 加载失败，说明 CDN 不可达。
本项目已把 Bootstrap 本地化到 `static/vendor/`，正常情况下不应再出现。
若页面源码里出现 `{{ icon(...) }}` 字面量，说明打开的是未渲染的模板文件，
请访问 `docs/` 里的静态快照，或在本地运行服务。

## 免责声明

本项目仅用于课程实践与安全技术学习。请勿用于未授权的扫描、拦截或数据采集。
