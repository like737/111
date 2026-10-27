"""
系统代理开关（Windows / HKCU, **不需要管理员权限**）

为什么用系统代理而不是改 hosts:
  * HKCU 注册表项 + InternetSetOption 刷新 → 无需管理员、即时生效、可一键还原;
  * 走系统代理的浏览器（Edge / Chrome / IE 等）请求都会经过 guard, 命中即真的打不开;
  * 会先记录"开启前"的原始设置（含你自己在用的 ProxyServer / AutoConfigURL / PAC）,
    关闭时逐项还原 —— 不会破坏你原有的代理软件配置。
"""

import ctypes
import json
import os
import sys
import time

from . import DATA_DIR

STATE_FILE = os.path.join(DATA_DIR, "sysproxy_state.json")
_REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

_INTERNET_OPTION_SETTINGS_CHANGED = 39
_INTERNET_OPTION_REFRESH = 37


class SysProxyCtl:
    def __init__(self, settings, verbose=True):
        self.settings = settings
        self.verbose = verbose
        self.server = str(settings.get("sysproxy.server", "127.0.0.1:8888"))
        self.bypass = str(settings.get("sysproxy.bypass", "localhost;127.0.0.1;*.local;<local>"))

    # ---------------- 平台判断 ----------------
    @staticmethod
    def is_windows():
        return sys.platform.startswith("win")

    # ---------------- 注册表读写 ----------------
    @staticmethod
    def _open_key(write=False):
        import winreg
        access = winreg.KEY_READ | (winreg.KEY_WRITE if write else 0)
        return winreg.OpenKey(winreg.HKEY_CURRENT_USER, _REG_PATH, 0, access)

    @staticmethod
    def _read_value(key, name, default=None):
        import winreg
        try:
            value, _kind = winreg.QueryValueEx(key, name)
            return value
        except OSError:
            return default

    def read_state(self):
        """读取当前系统代理设置（原始状态）"""
        if not self.is_windows():
            return {}
        try:
            with self._open_key(write=False) as key:
                return {
                    "ProxyEnable": int(self._read_value(key, "ProxyEnable", 0) or 0),
                    "ProxyServer": self._read_value(key, "ProxyServer", "") or "",
                    "ProxyOverride": self._read_value(key, "ProxyOverride", "") or "",
                    "AutoConfigURL": self._read_value(key, "AutoConfigURL", "") or "",
                }
        except Exception as exc:
            return {"error": str(exc)}

    def _write_value(self, key, name, value, kind=None):
        import winreg
        if value is None:
            try:
                winreg.DeleteValue(key, name)
            except OSError:
                pass
            return
        winreg.SetValueEx(key, name, 0, kind or winreg.REG_SZ, value)

    @staticmethod
    def _notify():
        """通知系统代理设置已变更。

        ⚠ 顺序很重要（2026-09 实测）: 在本机上, **写完注册表再调用本函数, WinINet 会用
        它自己的旧缓存把注册表刷回原值**（表现为"提示已开启, 但 ProxyEnable 还是 0"）。
        正确的做法是 **先 notify、再写注册表**; 写完不要再 notify。
        浏览器(Edge/Chrome) 与其它程序本身会监听注册表变化, 因此"写"这一步就够了。
        """
        try:
            wininet = ctypes.windll.WinINet
            wininet.InternetSetOptionW(0, _INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
            wininet.InternetSetOptionW(0, _INTERNET_OPTION_REFRESH, 0, 0)
        except Exception:
            pass

    # ---------------- 状态文件 ----------------
    def _save_state_file(self, data):
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
            with open(STATE_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as exc:
            print("[guard] 保存系统代理状态失败: %s" % exc)

    def _load_state_file(self):
        if not os.path.exists(STATE_FILE):
            return {}
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                return json.load(f) or {}
        except Exception:
            return {}

    # ---------------- 开关 ----------------
    def enable(self, server=None, bypass=None):
        """开启系统代理（会先记录原始状态, 便于还原）"""
        import winreg
        if not self.is_windows():
            return False, "系统代理开关目前只实现了 Windows"
        server = server or self.server
        bypass = bypass or self.bypass
        previous = self.read_state()
        if previous.get("error"):
            return False, "读取注册表失败: %s" % previous["error"]
        file_state = self._load_state_file()
        if not file_state.get("enabled_by_us"):
            self._save_state_file({"enabled_by_us": True, "previous": previous,
                                   "our_server": server,
                                   "enabled_at": time.strftime("%Y-%m-%d %H:%M:%S")})
        try:
            self._notify()                      # ⚠ 必须先通知、后写注册表（见 _notify 说明）
            with self._open_key(write=True) as key:
                self._write_value(key, "ProxyEnable", 1, winreg.REG_DWORD)
                self._write_value(key, "ProxyServer", server, winreg.REG_SZ)
                self._write_value(key, "ProxyOverride", bypass, winreg.REG_SZ)
                # PAC(AutoConfigURL)优先级高于手动代理: 开着 PAC 时我们的代理不会生效, 故临时摘掉
                if previous.get("AutoConfigURL"):
                    self._write_value(key, "AutoConfigURL", None)
        except PermissionError:
            return False, "写入注册表被拒绝（通常不需要管理员, 若失败请用管理员身份试一次）"
        except Exception as exc:
            return False, "设置系统代理失败: %s" % exc

        # 写后回读校验: 有些"代理守护"类软件会立刻把设置改回去, 这时要如实报告而不是假成功
        current = self.read_state()
        if int(current.get("ProxyEnable") or 0) != 1 or (current.get("ProxyServer") or "") != server:
            return False, ("系统代理写入后被改回（现在: ProxyEnable=%s, ProxyServer=%s）—— "
                           "可能有代理/安全软件在守护该设置; 可改用它自己把系统代理指向 %s, "
                           "或直接用油猴脚本那条通道。"
                           % (current.get("ProxyEnable"), current.get("ProxyServer") or "(空)", server))
        return True, "系统代理已开启 → %s（浏览器的请求现在都会先经过 guard）" % server

    def disable(self):
        """关闭系统代理, 并还原为开启前的状态"""
        import winreg
        if not self.is_windows():
            return False, "系统代理开关目前只实现了 Windows"
        file_state = self._load_state_file()
        previous = file_state.get("previous") or {}
        try:
            self._notify()                      # ⚠ 必须先通知、后写注册表（见 _notify 说明）
            with self._open_key(write=True) as key:
                if file_state.get("enabled_by_us"):
                    self._write_value(key, "ProxyEnable",
                                      int(previous.get("ProxyEnable", 0) or 0), winreg.REG_DWORD)
                    if previous.get("ProxyServer"):
                        self._write_value(key, "ProxyServer", previous["ProxyServer"], winreg.REG_SZ)
                    if previous.get("ProxyOverride"):
                        self._write_value(key, "ProxyOverride", previous["ProxyOverride"], winreg.REG_SZ)
                    if previous.get("AutoConfigURL"):
                        self._write_value(key, "AutoConfigURL", previous["AutoConfigURL"], winreg.REG_SZ)
                else:
                    self._write_value(key, "ProxyEnable", 0, winreg.REG_DWORD)
        except Exception as exc:
            return False, "还原系统代理失败: %s" % exc
        if file_state.get("enabled_by_us"):
            self._save_state_file({"enabled_by_us": False, "previous": previous,
                                   "restored_at": time.strftime("%Y-%m-%d %H:%M:%S")})
            if previous.get("ProxyServer"):
                return True, "系统代理已还原为原来的设置（%s）" % previous["ProxyServer"]
            return True, "系统代理已关闭（恢复到开启前的状态）"
        return True, "系统代理已关闭"

    def status(self):
        """返回 {supported, enabled, server, autoconfig, enabled_by_us, active, mismatch, previous, our_server}

        - enabled_by_us : guard 自己记录的"是我开的"（用于退出时还原）
        - active        : **注册表确认** guard 的代理确实生效中（ProxyEnable=1 且 ProxyServer 是我们）
        - mismatch      : 我们以为开着, 但注册表显示没生效（被别的程序改回去了）
        """
        current = self.read_state()
        file_state = self._load_state_file()
        enabled_now = bool(current.get("ProxyEnable"))
        server_now = current.get("ProxyServer") or ""
        active = bool(enabled_now and server_now == self.server)
        by_us = bool(file_state.get("enabled_by_us"))
        return {
            "supported": self.is_windows(),
            "enabled": enabled_now,
            "server": server_now,
            "autoconfig": current.get("AutoConfigURL") or "",
            "enabled_by_us": by_us,
            "active": active,
            "mismatch": bool(by_us and not active),
            "previous": file_state.get("previous") or {},
            "our_server": self.server,
        }
