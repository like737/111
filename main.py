"""
恶意链接跳转拦截与检测系统 - 主程序入口
============================================

功能:
1. 单次URL检测 - 手动输入URL进行检测
2. 批量URL检测 - 从文件批量导入检测
3. 剪贴板监控 - 实时监控剪贴板中的链接
4. 黑名单管理 - 管理恶意URL黑名单
5. 检测报告 - 查看统计报告和检测历史

作者: 大三学生项目
版本: 1.0.0
"""

import sys
import os
import time
from typing import Dict, List

# 确保可以导入同级模块
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from config import Config
from detector import Detector, DetectionResult
from interceptor import ClipboardInterceptor
from reporter import Reporter

def print_banner():
    """打印程序启动横幅"""
    banner = """
╔══════════════════════════════════════════════════════╗
║     🔒 恶意链接跳转拦截与检测系统 v1.0.0            ║
║     大三网络安全课程实践项目                          ║
╚══════════════════════════════════════════════════════╝
"""
    print(banner)

def print_menu():
    """打印主菜单"""
    menu = """
══════════════════ 主菜单 ══════════════════
  [1] 🔍 单次URL检测
  [2] 📋 批量URL检测 (从文件)
  [3] 👁️  启动剪贴板监控
  [4] ⚫ 黑名单管理
  [5] 📊 查看检测报告
  [6] ⚙️  系统设置
  [0] ❌ 退出程序
════════════════════════════════════════════
"""
    print(menu)

def single_detection(detector: Detector):
    """单次URL检测"""
    print("\n--- 单次URL检测 ---")
    url = input("请输入要检测的URL: ").strip()
    
    if not url:
        print("❌ URL不能为空")
        return
    
    print(f"\n🔍 正在检测: {url}")
    print("正在分析...")
    time.sleep(0.5)  # 模拟分析过程
    
    result = detector.detect(url)
    print("\n" + str(result))
    
    # 如果是恶意链接，询问是否加入黑名单
    if result.is_malicious:
        choice = input("\n是否将该URL加入黑名单? (y/n): ").strip().lower()
        if choice == 'y':
            print_blacklist_compare(detector.add_to_blacklist(url))

def print_blacklist_compare(result: Dict) -> None:
    """打印"手动添加黑名单"的比较结果(与Web端提示保持一致)

    新规则说明:
    - 用户手动添加的条目会在黑名单列表里**置顶**显示(最新添加的在最前);
    - 添加前会先与黑名单原有条目比较(完全重复/高度相似/同域名),
      这里的输出就是这次比较的结果, 便于命令行用户判断是否重复录入。
    """
    if not result:
        return
    if result.get("duplicate"):
        dup = result["duplicate"]
        print(f"ℹ️  该链接已在黑名单中(匹配方式: {dup['level']}): {dup['entry'][:100]}")
        print("    已将它置顶显示，未重复写入")
    elif result.get("added"):
        print("✅ 已加入黑名单并置顶(最新添加的排在最前)")
    same_host = result.get("same_host_count") or 0
    if same_host:
        print(f"⚠️  同一域名下已收录 {same_host} 条记录，请确认是否为重复录入")
    for item in (result.get("similar") or [])[:3]:
        print(f"🔍 相似条目: {item['entry'][:100]} ({item['reason']})")

def batch_detection(detector: Detector):
    """批量检测从文件读取的URL"""
    print("\n--- 批量URL检测 ---")
    filepath = input("请输入URL列表文件路径 (每行一个URL): ").strip()
    
    if not os.path.exists(filepath):
        print(f"❌ 文件不存在: {filepath}")
        return
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]
        
        if not urls:
            print("❌ 文件中没有有效的URL")
            return
        
        print(f"\n📋 共读取到 {len(urls)} 个URL，开始检测...")
        
        results = []
        for i, url in enumerate(urls, 1):
            print(f"[{i}/{len(urls)}] 检测中: {url[:50]}...", end=" ")
            result = detector.detect(url)
            status = "⚠️ 恶意" if result.is_malicious else "✅ 安全"
            print(f"[{status}] 评分: {result.score}")
            results.append(result)
        
        # 统计汇总
        malicious = sum(1 for r in results if r.is_malicious)
        print(f"\n{'='*50}")
        print(f"📊 批量检测完成!")
        print(f"  总检测: {len(results)} 个")
        print(f"  恶意链接: {malicious} 个")
        print(f"  安全链接: {len(results) - malicious} 个")
        print(f"{'='*50}")
        
    except Exception as e:
        print(f"❌ 批量检测出错: {e}")

def clipboard_monitoring(detector: Detector):
    """启动剪贴板监控"""
    print("\n--- 剪贴板监控 ---")
    print("启动后将实时监控您的剪贴板内容")
    print("检测到复制链接时自动分析安全性")
    print("按 Ctrl+C 停止监控\n")
    
    interceptor = ClipboardInterceptor(detector)
    
    try:
        interceptor.start()
        print("🟢 监控已启动，请复制链接进行测试...")
        print("按 Ctrl+C 返回主菜单\n")
        
        # 保持主线程运行
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n\n正在停止监控...")
    finally:
        interceptor.stop()
        print("监控已停止")

def blacklist_management(detector: Detector):
    """黑名单管理"""
    while True:
        print("\n--- 黑名单管理 ---")
        print(f"  当前黑名单大小: {len(detector._blacklist)} 条")
        print("  [1] 📋 查看黑名单")
        print("  [2] ➕ 添加URL到黑名单")
        print("  [3] ➖ 从黑名单移除URL")
        print("  [4] 🗑️  清空黑名单")
        print("  [5] 🌐 从公开源自动更新黑名单")   # ← 新增
        print("  [6] 🌱 导入内置种子黑名单")        # ← 新增
        print("  [7] 📄 从文本文件导入黑名单")       # ← 新增
        print("  [0] ↩️  返回主菜单")
        
        choice = input("\n请选择: ").strip()
        
        if choice == '1':
            bl = detector._blacklist
            if not bl:
                print("📋 黑名单为空")
            else:
                print(f"\n📋 黑名单 ({len(bl)} 条):")
                for i, url in enumerate(sorted(bl), 1):
                    print(f"  {i}. {url}")
        
        elif choice == '2':
            url = input("请输入要添加的URL: ").strip()
            if url:
                print_blacklist_compare(detector.add_to_blacklist(url))
        
        elif choice == '3':
            url = input("请输入要移除的URL: ").strip()
            if url:
                detector.remove_from_blacklist(url)
        
        elif choice == '4':
            confirm = input("确定清空黑名单? (y/n): ").strip().lower()
            if confirm == 'y':
                detector._blacklist.clear()
                detector._save_blacklist()
                print("✅ 黑名单已清空")
        
        elif choice == '5':
            print("正在从公开源更新黑名单...")
            results = detector.import_from_public_feeds()
            for feed, count in results.items():
                if count > 0:
                    print(f"✅ {feed}: 新增 {count} 条")
                elif count == -1:
                    print(f"❌ {feed}: 更新失败")
        
        elif choice == '6':
            detector.import_seed_blacklist()
        
        elif choice == '7':
            filepath = input("请输入黑名单文件路径: ").strip()
            if filepath:
                detector.import_blacklist_from_file(filepath)
        
        elif choice == '0':
            break

def show_report(detector: Detector):
    """显示检测报告"""
    reporter = detector.reporter
    
    print("\n--- 检测报告 ---")
    print(reporter.generate_report())
    
    print("\n  [1] 导出CSV报告")
    print("  [0] 返回主菜单")
    
    choice = input("\n请选择: ").strip()
    if choice == '1':
        reporter.export_csv()
        print("✅ CSV报告已导出")

def show_settings(config: Config):
    """显示和修改系统设置"""
    while True:
        print("\n--- 系统设置 ---")
        print("当前配置:")
        print(f"  1. 启发式分析: {'✅ 开启' if config.get('detection', 'enable_heuristic') else '❌ 关闭'}")
        print(f"  2. 黑名单匹配: {'✅ 开启' if config.get('detection', 'enable_blacklist') else '❌ 关闭'}")
        print(f"  3. 检测阈值: {config.get('detection', 'heuristic_threshold')}")
        print(f"  4. 剪贴板监控: {'✅ 开启' if config.get('monitoring', 'enable_clipboard_monitor') else '❌ 关闭'}")
        print(f"  5. 自动拦截: {'✅ 开启' if config.get('monitoring', 'auto_intercept') else '❌ 关闭'}")
        print(f"  6. 监控间隔: {config.get('monitoring', 'check_interval')}秒")
        print(f"  7. Google Safe Browsing API: {'已配置' if config.get('api_keys', 'google_safe_browsing') else '未配置'}")
        print(f"  8. VirusTotal API: {'已配置' if config.get('api_keys', 'virustotal') else '未配置'}")
        print(f"  9. DeepSeek AI API: {'已配置（Web端不显示明文）✅' if config.get('api_keys', 'deepseek') else '未配置 ❌'}")
        print(f"  10. DNS解析检查: {'✅ 开启' if config.get('detection', 'enable_dns_check') else '❌ 关闭'}")
        print(f"  11. AI辅助检测(DeepSeek): {'✅ 开启' if config.get('detection', 'enable_api_check') else '❌ 关闭'}")
        print("  [0] 返回主菜单")
        
        choice = input("\n请选择要修改的项 (编号): ").strip()
        
        if choice == '1':
            val = not config.get('detection', 'enable_heuristic')
            config.set(val, 'detection', 'enable_heuristic')
            print(f"启发式分析已{'开启' if val else '关闭'}")
        
        elif choice == '2':
            val = not config.get('detection', 'enable_blacklist')
            config.set(val, 'detection', 'enable_blacklist')
            print(f"黑名单匹配已{'开启' if val else '关闭'}")
        
        elif choice == '3':
            try:
                val = int(input("请输入阈值 (0-100): "))
                config.set(max(0, min(100, val)), 'detection', 'heuristic_threshold')
                print(f"检测阈值已设置为: {val}")
            except ValueError:
                print("❌ 请输入有效数字")
        
        elif choice == '4':
            val = not config.get('monitoring', 'enable_clipboard_monitor')
            config.set(val, 'monitoring', 'enable_clipboard_monitor')
            print(f"剪贴板监控已{'开启' if val else '关闭'}")
        
        elif choice == '5':
            val = not config.get('monitoring', 'auto_intercept')
            config.set(val, 'monitoring', 'auto_intercept')
            print(f"自动拦截已{'开启' if val else '关闭'}")
        
        elif choice == '6':
            try:
                val = float(input("请输入监控间隔 (秒): "))
                config.set(max(0.5, val), 'monitoring', 'check_interval')
                print(f"监控间隔已设置为: {val}秒")
            except ValueError:
                print("❌ 请输入有效数字")
        
        elif choice == '7':
            val = input("请输入Google Safe Browsing API密钥: ").strip()
            config.set(val, 'api_keys', 'google_safe_browsing')
            print("API密钥已更新")
        
        elif choice == '8':
            val = input("请输入VirusTotal API密钥: ").strip()
            config.set(val, 'api_keys', 'virustotal')
            print("API密钥已更新")
        
        elif choice == '9':
            val = input("请输入DeepSeek API密钥: ").strip()
            config.set(val, 'api_keys', 'deepseek')
            print("✅ DeepSeek API密钥已更新，重启后生效")
            print("   (该密钥仅保存在服务端，Web端只显示掩码，不显示明文)")
            if os.environ.get("DEEPSEEK_API_KEY"):
                print("   ⚠️ 检测到环境变量 DEEPSEEK_API_KEY，其优先级更高，会覆盖此处填写的密钥")
        
        elif choice == '10':
            val = not config.get('detection', 'enable_dns_check')
            config.set(val, 'detection', 'enable_dns_check')
            print(f"DNS解析检查已{'开启' if val else '关闭'}")
        
        elif choice == '11':
            val = not config.get('detection', 'enable_api_check')
            config.set(val, 'detection', 'enable_api_check')
            print(f"AI辅助检测已{'开启' if val else '关闭'}")
        
        elif choice == '0':
            break

def main():
    """主程序入口"""
    print_banner()
    
    # 初始化核心组件
    config = Config()
    detector = Detector(config)
    
    print("✅ 系统初始化完成")
    print(f"📊 黑名单记录: {len(detector._blacklist)} 条")
    print(f"📋 检测历史: {len(detector.reporter._logs)} 条")
    
    while True:
        try:
            print_menu()
            choice = input("请选择操作: ").strip()
            
            if choice == '1':
                single_detection(detector)
            
            elif choice == '2':
                batch_detection(detector)
            
            elif choice == '3':
                clipboard_monitoring(detector)
            
            elif choice == '4':
                blacklist_management(detector)
            
            elif choice == '5':
                show_report(detector)
            
            elif choice == '6':
                show_settings(config)
            
            elif choice == '0':
                print("\n👋 感谢使用恶意链接检测系统！")
                print("安全上网，从我做起！")
                break
            
            else:
                print("❌ 无效选项，请重新选择")
            
            if choice != '0':
                input("\n按 Enter 键继续...")
            
        except KeyboardInterrupt:
            print("\n\n👋 程序已退出")
            break
        except Exception as e:
            print(f"\n❌ 程序异常: {e}")
            import traceback
            traceback.print_exc()

if __name__ == "__main__":
    main()