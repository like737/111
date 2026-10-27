"""
链接拦截模块 - 监控剪贴板中的URL并自动检测
"""

import time
import threading
import re
from typing import Optional, Callable

from detector import Detector, DetectionResult
from utils import is_valid_url

class ClipboardInterceptor:
    """
    剪贴板监控拦截器
    
    后台线程监控剪贴板内容变化，自动检测复制的链接
    检测到恶意链接时发出警告并阻止自动访问
    """
    
    def __init__(self, detector: Detector, config=None):
        self.detector = detector
        from config import Config
        self.config = config or Config()
        self._monitoring = False
        self._thread: Optional[threading.Thread] = None
        self._last_content = ""
        self._check_interval = self.config.get("monitoring", "check_interval") or 1.0
        self._on_malicious_callbacks = []
        
        # 注册检测回调
        self.detector.on_detection(self._on_detection_result)
    
    def on_malicious_detected(self, callback: Callable[[DetectionResult], None]):
        """注册恶意链接检测回调"""
        self._on_malicious_callbacks.append(callback)
    
    def _on_detection_result(self, result: DetectionResult):
        """检测结果回调处理"""
        if result.is_malicious:
            print(f"\n🔴 [拦截器] 检测到恶意链接!")
            print(str(result))
            for callback in self._on_malicious_callbacks:
                try:
                    callback(result)
                except Exception as e:
                    print(f"[拦截器] 回调错误: {e}")
    
    def _get_clipboard_text(self) -> str:
        """获取剪贴板文本 (跨平台实现)"""
        try:
            import tkinter as tk
            root = tk.Tk()
            root.withdraw()  # 隐藏窗口
            try:
                text = root.clipboard_get()
                return text
            except tk.TclError:
                return ""
            finally:
                root.destroy()
        except Exception:
            # 备选方案: 尝试使用命令行
            try:
                import subprocess
                # Windows
                result = subprocess.run(["powershell", "-command", "Get-Clipboard"], 
                                       capture_output=True, text=True, timeout=2)
                if result.returncode == 0:
                    return result.stdout.strip()
            except Exception:
                pass
            return ""
    
    def _monitor_loop(self):
        """剪贴板监控主循环"""
        print(f"[拦截器] 剪贴板监控已启动 (间隔: {self._check_interval}秒)")
        print("[拦截器] 复制任何链接将自动检测...")
        
        while self._monitoring:
            try:
                content = self._get_clipboard_text()
                
                if content and content != self._last_content:
                    self._last_content = content
                    
                    # 检查是否为URL
                    if is_valid_url(content) or self._looks_like_url(content):
                        print(f"\n📋 [拦截器] 检测到新内容: {content[:80]}...")
                        result = self.detector.detect(content)
                        
                        # 如果自动拦截开启且检测为恶意
                        auto_intercept = self.config.get("monitoring", "auto_intercept")
                        if auto_intercept and result.is_malicious:
                            self._intercept_link(result)
                
                time.sleep(self._check_interval)
                
            except Exception as e:
                print(f"[拦截器] 监控异常: {e}")
                time.sleep(self._check_interval)
    
    def _looks_like_url(self, text: str) -> bool:
        """判断文本是否可能是URL"""
        if not text:
            return False
        # 检查是否包含常见URL特征
        url_patterns = [
            r'https?://',
            r'[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}',
            r'www\.[a-zA-Z0-9.-]+',
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP地址
        ]
        return any(re.search(pattern, text) for pattern in url_patterns)
    
    def _intercept_link(self, result: DetectionResult):
        """拦截恶意链接 - 阻止浏览器自动打开"""
        print("\n" + "!" * 60)
        print("⛔ 拦截警告! 检测到恶意链接，已阻止自动访问")
        print(f"🔗 URL: {result.url}")
        print(f"📊 风险评分: {result.score}/100")
        print(f"⚠️  风险等级: {result.risk_level}")
        print("!" * 60 + "\n")
    
    def start(self):
        """启动剪贴板监控（后台线程）"""
        if self._monitoring:
            print("[拦截器] 监控已在运行中")
            return
        
        self._monitoring = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        print("[拦截器] 剪贴板监控线程已启动")
    
    def stop(self):
        """停止剪贴板监控"""
        self._monitoring = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2)
        print("[拦截器] 剪贴板监控已停止")

class BrowserInterceptor:
    """
    浏览器链接拦截器 (预留扩展)
    
    未来可通过浏览器扩展或代理方式实现更深入的拦截
    """
    
    def __init__(self, detector: Detector, config=None):
        self.detector = detector
        self.config = config
    
    def start_proxy(self):
        """启动代理拦截模式 (待实现)"""
        print("[浏览器拦截器] 代理拦截模式 - 待实现")
        print("[浏览器拦截器] 可通过 mitmproxy 或自定义代理实现")
    
    def stop_proxy(self):
        """停止代理拦截"""
        print("[浏览器拦截器] 代理拦截已停止")