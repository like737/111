"""
配置管理模块 - 管理所有检测与拦截相关的配置项
"""

import copy
import json
import os

class Config:
    """配置管理类，支持加载/保存配置"""

    # ========== 敏感密钥保护 ==========
    # 以下密钥不会以明文形式下发到Web端（模板渲染/接口返回时统一替换为掩码）
    WEB_HIDDEN_KEYS = ("deepseek",)

    # 允许通过环境变量提供密钥（优先级高于配置文件，密钥无需写入 config.json）
    # 例: PowerShell 中 $env:DEEPSEEK_API_KEY="sk-xxx"; python web_app.py
    ENV_API_KEY_MAP = {
        "DEEPSEEK_API_KEY": ("api_keys", "deepseek"),
    }

    # 掩码文本：非空密钥在Web端统一显示为该内容，不泄露任何字符
    SECRET_MASK = "*" * 8

    DEFAULT_CONFIG = {
        # ========== 检测设置 ==========
        "detection": {
            "enable_heuristic": True,          # 启用启发式分析
            "enable_blacklist": True,          # 启用黑名单匹配
            "enable_dns_check": True,          # 启用DNS解析检查(域名无法解析视为可疑, +15)
            "enable_api_check": True,          # 启用外部API(AI)查询, 未配置密钥时自动跳过
            "heuristic_threshold": 60,         # 可疑分数阈值 (0-100)
            "max_url_length": 2000,            # URL最大长度检测
            "check_shortened_urls": True,      # 检测短链接服务
            "check_suspicious_tlds": True,     # 检测可疑顶级域名
            "check_typosquatting": True,       # 检测域名仿冒
            "check_ip_url": True,              # 检测IP直连URL
            "check_suspicious_keywords": True,  # 检测敏感关键词
            # ===== 以下为新增的启发式规则(默认开启, 置 false 可单独关闭) =====
            "check_deceptive_domain": True,    # 欺骗性域名结构(punycode/品牌置于子域名/免费主机)
            "check_dga": True,                 # 随机生成域名(DGA)检测
            "check_dangerous_extension": True,  # 高危可执行/脚本文件下载检测
            "check_malicious_patterns": True,   # 与 data/*.json 模式库比对
            "check_adult_content": True,       # 成人/赌博类内容检测(域名命中直接定罪, 不需要AI)

            # ===== ML 检测通道(方案A: 域名模型 + 路径模型 并行) =====
            "enable_ml_check": True,           # 总开关(关闭 = 与未接入前完全一致)
            "ml_mode": "shadow",               # shadow=只记录不裁决 | enforce=参与判定(OR通道)
            "ml_model_path": "data/models/lgs_model.pickle",   # 旧字段: 未配置 ml_models 时的单模型路径
            "ml_threshold": None,              # 概率阈值; None=使用模型文件内保存的阈值
            "ml_confidence": 0.9,              # 默认高置信门限(enforce 只认高置信)
            "ml_affect_score": False,          # 固定 False: 绝不把概率加进 0-100 分体系
            "ml_trigger_intercept": False,     # 旧字段: 未配置 ml_models 时是否允许 ML 单独定罪
            # 方案A 的多模型配置: 各通道独立阈值/门限/是否参与拦截
            #   域名模型: 补"未入库的新钓鱼/色情/赌博域名"; 当前指标未达标 → 先"仅提示"
            #   路径模型: 沿用原模型, 覆盖 URL 里的攻击/探测痕迹 → 参与拦截
            "ml_models": {
                "domain": {"enabled": True, "path": "data/models/domain_model.pkl",
                           "confidence": 0.9, "trigger_intercept": False},
                "path": {"enabled": True, "path": "data/models/path_model.pkl",
                         "confidence": 0.9, "trigger_intercept": True},
            },

        },
        # ========== API密钥(可选) ==========
        "api_keys": {
            "google_safe_browsing": "",        # Google Safe Browsing API
            "virustotal": "",                  # VirusTotal API
            "phish_tank": "",                  # PhishTank API
            "deepseek": "",                    # DeepSeek API
        },
        # ========== 监控设置 ==========
        "monitoring": {
            "enable_clipboard_monitor": True,  # 启用剪贴板监控
            "check_interval": 1.0,             # 检测间隔(秒)
            "auto_intercept": True,            # 自动拦截危险链接
        },
        # ========== 日志设置 ==========
        "logging": {
            "enable_logging": True,
            "log_file": "detection_log.json",
            "max_log_entries": 1000,           # 最大日志条目数
            # 启动时是否打印各模块的加载信息（配置/黑名单/ML/guard）
            #   false = 只保留一行「🚀 Web服务器启动: ...」（默认，终端更清爽）
            #   true  = 还原完整启动日志（与旧版一致）
            # 也可用环境变量临时开启: PowerShell 里 $env:EY_VERBOSE="1"
            "verbose_startup": False,
        },
    }

    CONFIG_FILE = "config.json"

    def __init__(self, verbose=True):
        # 深拷贝: 避免与类默认值 DEFAULT_CONFIG 的嵌套字典共享引用，
        # 防止多个 Config 实例之间互相污染（例如 A 实例改配置影响 B 实例）
        self._config = copy.deepcopy(self.DEFAULT_CONFIG)
        # verbose: 是否打印"已加载配置文件"这类启动信息（web_app 默认静默）
        self.verbose = bool(verbose)
        self.load()
        self._apply_env_overrides()

    def get(self, *keys):
        """获取嵌套配置值，例如 config.get('detection', 'heuristic_threshold')"""
        value = self._config
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return None
        return value

    def set(self, value, *keys):
        """设置嵌套配置值"""
        if len(keys) < 1:
            return
        section = self._config
        for key in keys[:-1]:
            if key not in section:
                section[key] = {}
            section = section[key]
        section[keys[-1]] = value
        self.save()

    def _apply_env_overrides(self):
        """
        从环境变量读取敏感密钥（仅内存生效，不写回 config.json）

        这样做的好处：密钥不需要落盘，也不需要在Web端填写/显示。
        """
        for env_name, path in self.ENV_API_KEY_MAP.items():
            value = (os.environ.get(env_name) or "").strip()
            if not value:
                continue
            section = self._config
            for key in path[:-1]:
                if not isinstance(section.get(key), dict):
                    section[key] = {}
                section = section[key]
            section[path[-1]] = value
            if getattr(self, "verbose", True):
                print(f"[配置] 已从环境变量 {env_name} 读取密钥（优先级高于配置文件）")

    @classmethod
    def mask_secret(cls, value) -> str:
        """把密钥打码：非空时统一返回固定掩码，不泄露任何字符"""
        return cls.SECRET_MASK if (value is not None and str(value).strip()) else ""

    def load(self):
        """从文件加载配置"""
        if os.path.exists(self.CONFIG_FILE):
            try:
                with open(self.CONFIG_FILE, 'r', encoding='utf-8') as f:
                    loaded = json.load(f)
                    self._deep_update(self._config, loaded)
                if getattr(self, "verbose", True):
                    print(f"[配置] 已加载配置文件: {self.CONFIG_FILE}")
            except Exception as e:
                print(f"[配置] 加载配置失败: {e}")

    def save(self):
        """保存配置到文件"""
        try:
            with open(self.CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(self._config, f, ensure_ascii=False, indent=4)
        except Exception as e:
            print(f"[配置] 保存配置失败: {e}")

    @staticmethod
    def _deep_update(base, updates):
        """递归更新嵌套字典"""
        for key, value in updates.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                Config._deep_update(base[key], value)
            else:
                base[key] = value

    @property
    def all_config(self):
        """完整配置（含明文密钥）

        ⚠️ 仅限服务端内部使用，禁止直接传给Web模板/接口，
        否则会把 DeepSeek 等密钥明文暴露到前端。
        """
        return self._config

    @property
    def public_config(self):
        """Web端安全配置副本（深拷贝）

        敏感密钥（WEB_HIDDEN_KEYS）会被替换为掩码，绝不返回明文，
        其余配置保持不变，可直接交给 render_template 使用。
        """
        data = copy.deepcopy(self._config)
        api_keys = data.get("api_keys")
        if isinstance(api_keys, dict):
            for key in self.WEB_HIDDEN_KEYS:
                if key in api_keys:
                    api_keys[key] = self.mask_secret(api_keys[key])
        return data