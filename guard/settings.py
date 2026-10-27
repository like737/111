"""
guard 自己的配置文件（guard/data/config.json）

注意: 这是 **guard 自己的** 配置, 与 eyilianjie 的 config.json 完全独立。
guard 只读 eyilianjie 的 config.json（用于复用它的检测开关/阈值）, 绝不写它。
"""

import copy
import json
import os
import threading

from . import DATA_DIR

CONFIG_FILE = os.path.join(DATA_DIR, "config.json")

DEFAULT_CONFIG = {
    # 总开关: false 时 run_guarded.py 不启动任何拦截组件（只启动原样 eyilianjie）
    "enabled": True,

    # 随 Web 端自动启动拦截层（方案: 不点 .bat 也能带拦截）
    #   true  = 运行 python web_app.py / VS Code 里跑 web_app.py 时, 自动把
    #           guard 的 代理(8888)/控制台(8899)/检测日志联动/检测即真封 一起拉起来
    #           （**不会**自动接管系统代理, 仍要在网页「拦截」里点【开始拦截】）
    #   false = 完全回到"不带拦截"的原始行为
    "auto_start": True,

    # 「本地代理拦截」这个方式的勾选**意图**（Web 控制台用）:
    #   true  = 点「开始拦截」时把系统代理指向 guard（全浏览器生效）
    #   false = 不动系统代理（只靠页面内/油猴脚本那条通道）
    "block_via_proxy": True,

    # ---------- 本地代理 ----------
    "proxy": {
        "host": "127.0.0.1",
        "port": 8888,
        # 上游代理: 若你在用 v2ray/clash 之类的本地代理(例如 127.0.0.1:10808),
        # 填在这里 → guard 未命中的请求会转发给它, 不会顶掉你的科学上网。
        "upstream_proxy": "",
        # 上游直连例外（逗号分隔的域名后缀, 命中的不走上游代理）
        "upstream_bypass": "",
        "connect_timeout": 8,
        "bypass_localhost": True,       # localhost/127.0.0.1 直连不过代理判定
        "max_header_bytes": 65536,
    },

    # ---------- guard 控制台/API ----------
    "api": {"host": "127.0.0.1", "port": 8899},

    # ---------- 拦截判定 ----------
    "block": {
        "blacklist": True,              # 命中 eyilianjie 黑名单(18万条, 含6级匹配)
        "heuristic": True,              # 复用 eyilianjie 启发式(含成人站/恶意模式库)
        "adult": True,                  # 成人/赌博类关键词规则(命中直接拦)
        "ml_convict": True,             # ML 通道中"参与拦截"的模型(当前=路径模型)
        "ml_hint": False,               # ML 中"仅提示"的模型(当前=域名模型, 默认不拦)
        "dynamic_from_log": True,       # 只读同步 eyilianjie 检测日志里判恶意的目标
        "dynamic_host_level": True,     # 动态条目是否按整站(域名级)拦
        "dynamic_trusted_url_only": True,   # 可信站点(google/baidu等)只拦那一条URL, 不封整站
        "block_https_tunnel": True,     # HTTPS(CONNECT) 阶段按域名拦截
        "heuristic_on_tunnel": True,    # CONNECT 时只用域名做启发式(无路径)
        "warn_prob": 0.90,              # ★警告档: ML 域名概率 >= 该值(但未到拦截阈值) → 警告页(可继续)
        "warn_score": 40,               # ★警告档: 启发式评分落在 [该值, 阈值) → 警告页(可继续)
        "fail_open": True,              # 判定异常时放行(避免断网); false = 异常即拦
    },

    # ---------- 系统代理(Windows HKCU, 免管理员) ----------
    "sysproxy": {
        "server": "127.0.0.1:8888",
        "bypass": "localhost;127.0.0.1;*.local;<local>",
        "restore_on_exit": True,        # 退出时自动恢复成"开启前"的状态
    },

    # ---------- 判定缓存 ----------
    "cache": {"ttl": 60, "max": 5000},

    # ---------- 记录 ----------
    "log": {"max_entries": 2000, "log_all_requests": False},

    # ---------- 检测日志联动 ----------
    "logwatch": {"interval": 2.0, "max_entries": 20000},
}

_lock = threading.RLock()


class Settings:
    """带点号路径访问的配置对象: get('proxy.port') / set('proxy.port', 8888)"""

    def __init__(self, data=None):
        self._data = copy.deepcopy(DEFAULT_CONFIG)
        if data:
            self._deep_update(self._data, data)

    # ---------- 读写 ----------
    def get(self, path, default=None):
        node = self._data
        for key in str(path).split("."):
            if isinstance(node, dict) and key in node:
                node = node[key]
            else:
                return default
        return node

    def set(self, path, value, save=True):
        keys = str(path).split(".")
        node = self._data
        for key in keys[:-1]:
            if not isinstance(node.get(key), dict):
                node[key] = {}
            node = node[key]
        node[keys[-1]] = value
        if save:
            self.save()

    @property
    def data(self):
        return self._data

    def as_dict(self):
        return copy.deepcopy(self._data)

    # ---------- 持久化 ----------
    def load(self):
        if not os.path.exists(CONFIG_FILE):
            return self
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                self._deep_update(self._data, json.load(f) or {})
        except Exception as exc:                       # 配置损坏时用默认值继续跑
            print("[guard] 配置读取失败, 使用默认配置: %s" % exc)
        return self

    def save(self):
        with _lock:
            try:
                os.makedirs(DATA_DIR, exist_ok=True)
                tmp = CONFIG_FILE + ".tmp"
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(self._data, f, ensure_ascii=False, indent=2)
                os.replace(tmp, CONFIG_FILE)
            except Exception as exc:
                print("[guard] 配置保存失败: %s" % exc)

    @staticmethod
    def _deep_update(base, updates):
        for key, value in (updates or {}).items():
            if isinstance(base.get(key), dict) and isinstance(value, dict):
                Settings._deep_update(base[key], value)
            else:
                base[key] = value


def load():
    """读取 guard 配置（不存在则用默认值, 不写文件）"""
    return Settings().load()
