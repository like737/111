"""
eyilianjie guard —— 真正能"拦住"链接的本地拦截层（方案 C + D + F）

设计约束（务必保持）:
  * 只新增文件, **不修改 eyilianjie 任何现有文件的内容**;
  * 只读复用 eyilianjie 的判定代码（Detector / URLAnalyzer / ML 通道）,
    不向 eyilianjie 目录写任何数据（黑名单、日志一律不动）;
  * 进程内关闭 .pyc 写入, 避免在项目里留下新的 __pycache__ 文件
    （如需恢复默认行为: 设置环境变量 EY_GUARD_ALLOW_BYTECODE=1）。

拦截链路（三条, 互相补位）:
  1) 本地代理（默认 127.0.0.1:8888）: 浏览器走系统代理后, 每个请求先判定再放行/拦截;
  2) 运行时挂载（run_guarded.py）: 包装 eyilianjie 的 detector.detect,
     它一判恶意就把目标写进 guard 动态拦截集 → 别的页面再打开也打不开;
  3) 油猴脚本（guard/userscript/）: 页面内点击链接/打开页面时先问 guard, 命中即显示拦截页。
"""

import os
import sys

# 必须在导入其它模块（尤其 eyilianjie 的模块）之前设置, 否则解释器会写出 .pyc
if os.environ.get("EY_GUARD_ALLOW_BYTECODE", "").strip().lower() not in ("1", "true", "yes"):
    sys.dont_write_bytecode = True

VERSION = "1.0.0"
GUARD_DIR = os.path.dirname(os.path.abspath(__file__))          # ...\eyilianjie\guard
PROJECT_ROOT = os.path.dirname(GUARD_DIR)                       # ...\eyilianjie
DATA_DIR = os.path.join(GUARD_DIR, "data")                      # guard 自己的数据目录

__all__ = ["VERSION", "GUARD_DIR", "PROJECT_ROOT", "DATA_DIR"]
