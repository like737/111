# -*- coding: utf-8 -*-
"""把 Flask 模板导出成可部署到 GitHub Pages 的静态快照（docs/）。

用法
----
    python tools/export_docs.py

做了什么
--------
1. 以 `config.example.json` 为配置来源（**不会**读取本机含密钥的 config.json）；
2. 以 `tools/demo_log.py` 生成的合成日志作为检测数据（**不会**读取真实
   detection_log.json，避免把个人浏览记录发布到公开站点）；
3. 用 Flask 的 test_client 渲染各页面 —— 这样 Jinja 的 {{ }} / {% %} 会被
   真正求值，导航栏图标、url_for 生成的链接才是正确的 HTML；
4. 把内部绝对路径（`/static/...`、`/report` 等）改写为相对路径，
   因为 GitHub Pages 的站点位于子路径 `/111/` 下；
5. 复制 `static/` 到 `docs/static/`，并写入 `.nojekyll`
   （否则 Jekyll 会忽略下划线开头的文件，也会多余地处理静态资源）。

注意：静态站没有后端，表单提交与 /detect 等接口不可用，属于只读展示。
"""

import json
import os
import re
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# 让 `import demo_log`、`import config`、`import web_app` 都能找到模块
sys.path.insert(0, HERE)
sys.path.insert(0, ROOT)
os.chdir(ROOT)

CONFIG_SRC = os.path.join(ROOT, "config.example.json")
STATIC_SRC = os.path.join(ROOT, "static")
DOCS_DIR = os.path.join(ROOT, "docs")

PAGES = [
    ("/", "index.html"),
    ("/report", "report.html"),
    ("/blacklist", "blacklist.html"),
    ("/settings", "settings.html"),
    ("/whitelist", "whitelist.html"),
    ("/guard", "guard.html"),
]

# 顺序敏感：先处理 href 精确匹配，再处理 /static/ 前缀
REWRITES = [
    ('href="/"', 'href="index.html"'),
    ('href="/report"', 'href="report.html"'),
    ('href="/blacklist"', 'href="blacklist.html"'),
    ('href="/settings"', 'href="settings.html"'),
    ('href="/whitelist"', 'href="whitelist.html"'),
    ('href="/guard"', 'href="guard.html"'),
    ('"/static/', '"static/'),
    ("'/static/", "'static/"),
]


def _prepare_config(demo_log_path):
    """基于 config.example.json 生成临时配置，把日志指向合成样本"""
    if not os.path.exists(CONFIG_SRC):
        raise SystemExit("缺少 %s，无法导出" % CONFIG_SRC)
    with open(CONFIG_SRC, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    logging_cfg = cfg.setdefault("logging", {})
    logging_cfg["log_file"] = demo_log_path
    logging_cfg["verbose_startup"] = False
    tmp_cfg = os.path.join(tempfile.mkdtemp(prefix="eydocs-cfg-"), "config.json")
    with open(tmp_cfg, "w", encoding="utf-8", newline="\n") as f:
        json.dump(cfg, f, ensure_ascii=False, indent=2)
    return tmp_cfg


def main():
    import demo_log

    work = tempfile.mkdtemp(prefix="eydocs-")
    demo_path = os.path.join(work, "detection_log.demo.json")
    count = demo_log.write_demo_log(demo_path)

    # 必须在 import web_app 之前改 CONFIG_FILE：
    # web_app 在模块导入时就会构造 Config 与 Detector（以及内部的 Reporter）。
    from config import Config
    Config.CONFIG_FILE = _prepare_config(demo_path)

    import web_app

    client = web_app.app.test_client()
    os.makedirs(DOCS_DIR, exist_ok=True)

    # 清理上一轮遗留的页面，避免删掉路由后仍残留旧文件
    for name in os.listdir(DOCS_DIR):
        if name.endswith(".html"):
            os.remove(os.path.join(DOCS_DIR, name))

    print("合成演示日志: %d 条 (不含任何真实检测记录)" % count)
    print("%-16s %-6s %-9s %-6s %s" % ("file", "code", "bytes", "jinja", "cdn"))
    failed = []
    for route, filename in PAGES:
        resp = client.get(route)
        if resp.status_code != 200:
            failed.append((route, resp.status_code))
            print("%-16s %-6s 跳过" % (filename, resp.status_code))
            continue
        html = resp.get_data(as_text=True)
        for old, new in REWRITES:
            html = html.replace(old, new)
        jinja_left = len(re.findall(r"\{\{|\{%", html))
        cdn_left = html.count("cdn.jsdelivr.net")
        with open(os.path.join(DOCS_DIR, filename), "w", encoding="utf-8", newline="\n") as f:
            f.write(html)
        print("%-16s %-6d %-9d %-6d %d" % (filename, 200, len(html), jinja_left, cdn_left))

    if failed:
        raise SystemExit("以下页面渲染失败: %r" % (failed,))

    # 同步静态资源（先删后拷，避免 Copy-Item/copytree 的嵌套坑）
    dst_static = os.path.join(DOCS_DIR, "static")
    if os.path.isdir(dst_static):
        shutil.rmtree(dst_static)
    shutil.copytree(STATIC_SRC, dst_static)

    # 关闭 Jekyll：静态资源按原样发布
    open(os.path.join(DOCS_DIR, ".nojekyll"), "w", encoding="utf-8").close()

    print("\n完成: docs/ 已生成 %d 个页面，static/ 已同步" % len(PAGES))


if __name__ == "__main__":
    main()
