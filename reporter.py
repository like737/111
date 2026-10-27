"""
报告模块 - 检测结果记录、统计与报告生成

可靠性设计（多进程/多实例场景）:
  * 文件是唯一事实源: 每次读取前比对 (mtime, size)，变了就重新加载
    → 别的进程（另一个 web_app 实例 / 脚本）刚写入的记录，本进程页面也能看到;
  * 写文件用"临时文件 + os.replace"原子替换, 避免别的进程读到半截 JSON;
  * 写之前先合并磁盘上的最新记录, 尽量降低多进程互相覆盖造成的丢失;
  * 统计与列表对脏数据（缺字段/时间戳非法/分数非数字）做容错与异常隔离,
    单条坏记录不会让整个统计摘要 500。
"""

import json
import os
import threading
from datetime import datetime, timedelta
from typing import Dict, List


class Reporter:
    """检测报告管理器 - 负责记录和查询检测历史"""

    def __init__(self, config=None):
        from config import Config
        self.config = config or Config()
        self.log_file = self.config.get("logging", "log_file") or "detection_log.json"
        try:
            self.max_entries = int(self.config.get("logging", "max_log_entries") or 1000)
        except (TypeError, ValueError):
            self.max_entries = 1000
        self._lock = threading.RLock()
        self._stamp = self._current_stamp()
        self._logs = self._read_logs()
        if self._logs is None:            # 文件损坏: 先按空处理, 下次写入会重建
            self._logs = []

    # ================= 文件读写 =================
    def _current_stamp(self):
        """文件指纹（mtime_ns, size）; 文件不存在返回 None"""
        try:
            st = os.stat(self.log_file)
            return (st.st_mtime_ns, st.st_size)
        except OSError:
            return None

    def _read_logs(self):
        """从磁盘读取日志; 文件不存在→[]; 读取/解析失败→None（调用方保留现有内存）"""
        if not os.path.exists(self.log_file):
            return []
        try:
            with open(self.log_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            return None
        if isinstance(data, dict):
            data = data.get("logs") or data.get("entries") or []
        if not isinstance(data, list):
            return None
        return [item for item in data if isinstance(item, dict)]

    def _load_logs(self) -> List[Dict]:
        """兼容旧接口: 加载历史日志（失败时返回空列表）"""
        return self._read_logs() or []

    def _refresh_if_changed(self):
        """磁盘文件变了就重新加载（多进程/多实例下保持页面可见性）

        返回 True 表示确实重读过。解析失败（别的进程正在写）时保留现有内存。
        """
        stamp = self._current_stamp()
        if stamp == self._stamp:
            return False
        logs = self._read_logs()
        if logs is None:
            # 解析失败（可能是别的进程正在写）: 不更新指纹, 下次读取时重试
            return False
        with self._lock:
            self._logs = logs
            self._stamp = stamp
        return True

    def _save_logs(self):
        """保存日志到文件（原子写; 调用方需持有 _lock）"""
        try:
            if len(self._logs) > self.max_entries:
                self._logs = self._logs[-self.max_entries:]
            folder = os.path.dirname(os.path.abspath(self.log_file))
            if folder and not os.path.isdir(folder):
                os.makedirs(folder, exist_ok=True)
            tmp = "%s.%d.%d.tmp" % (self.log_file, os.getpid(), threading.get_ident())
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self._logs, f, ensure_ascii=False, indent=2)
            os.replace(tmp, self.log_file)
            self._stamp = self._current_stamp()
        except Exception as e:
            print(f"[报告] 保存日志失败: {e}")

    # ================= 写入 =================
    def log_detection(self, result):
        """记录一次检测结果"""
        try:
            log_entry = result.to_dict()
        except Exception as e:
            print(f"[报告] 检测结果无法序列化, 已跳过记录: {e}")
            return
        if not isinstance(log_entry, dict):
            return
        with self._lock:
            # 先并入其它进程刚写入的记录, 再追加 → 避免整文件覆盖时丢掉别人的记录
            self._refresh_if_changed()
            self._logs.append(log_entry)
            self._save_logs()
    
    # ================= 统计 =================
    @staticmethod
    def _safe_score(value):
        """分数容错: 非数字 / NaN / inf → 0"""
        try:
            score = float(value)
        except (TypeError, ValueError):
            return 0.0
        if score != score or score in (float("inf"), float("-inf")):
            return 0.0
        return score

    @staticmethod
    def _parse_ts(value):
        """时间戳容错: ISO(含 Z) / "YYYY-MM-DD HH:MM:SS" 均支持; 非法值 → None"""
        text = str(value or "").strip()
        if not text:
            return None
        try:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            dt = None
            for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
                try:
                    dt = datetime.strptime(text[:19], fmt)
                    break
                except ValueError:
                    continue
            if dt is None:
                return None
        if dt.tzinfo is not None:
            dt = dt.astimezone().replace(tzinfo=None)
        return dt

    @staticmethod
    def _empty_stats():
        return {
            "total_detections": 0,
            "malicious_count": 0,
            "safe_count": 0,
            "malicious_rate": 0,
            "recent_24h": 0,
            "avg_score": 0,
            "high_risk_count": 0,
        }

    def get_statistics(self) -> Dict:
        """获取统计信息

        对脏数据容错（缺字段、时间戳非法、分数非数字）；
        任何异常都降级为全 0，绝不让首页/报告页因为一条坏记录而 500。
        """
        try:
            with self._lock:
                self._refresh_if_changed()
                logs = list(self._logs)
            total = len(logs)
            if total == 0:
                return self._empty_stats()

            malicious = 0
            high_risk = 0
            score_sum = 0.0
            recent_24h = 0
            since = datetime.now() - timedelta(hours=24)
            for log in logs:
                if not isinstance(log, dict):
                    continue
                if log.get("is_malicious"):
                    malicious += 1
                score = self._safe_score(log.get("score"))
                score_sum += score
                if score >= 60:
                    high_risk += 1
                ts = self._parse_ts(log.get("timestamp"))
                if ts is not None and ts > since:
                    recent_24h += 1

            safe = total - malicious
            return {
                "total_detections": total,
                "malicious_count": malicious,
                "safe_count": safe,
                "malicious_rate": round(malicious / total * 100, 2),
                "recent_24h": recent_24h,
                "avg_score": round(score_sum / total, 1),
                "high_risk_count": high_risk,
            }
        except Exception as e:
            print(f"[报告] 统计计算异常(已降级为 0): {e}")
            return self._empty_stats()

    def get_recent_detections(self, count: int = 10) -> List[Dict]:
        """获取最近的检测记录（读取前先同步磁盘上的最新记录）"""
        try:
            count = int(count)
        except (TypeError, ValueError):
            count = 10
        if count <= 0:
            return []
        with self._lock:
            self._refresh_if_changed()
            return list(reversed(self._logs[-count:]))
    
    def generate_report(self) -> str:
        """生成可读的报告文本"""
        stats = self.get_statistics()
        recent = self.get_recent_detections(5)
        
        lines = [
            "=" * 60,
            "📊 恶意链接检测报告",
            "=" * 60,
            f"📅 报告时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"📈 总检测次数: {stats['total_detections']}",
            f"⚠️  恶意链接: {stats['malicious_count']} 次 ({stats['malicious_rate']}%)",
            f"✅ 安全链接: {stats['safe_count']} 次",
            f"📊 平均风险评分: {stats['avg_score']}/100",
            f"🔴 高风险链接: {stats['high_risk_count']} 次",
            f"🕐 24小时内检测: {stats['recent_24h']} 次",
            "-" * 60,
        ]
        
        if recent:
            lines.append("📋 最近检测记录:")
            for log in recent:
                status = "⚠️" if log.get("is_malicious") else "✅"
                timestamp = str(log.get("timestamp") or "未知")[:19]
                url = str(log.get("url") or "未知")[:50]
                score = self._safe_score(log.get("score"))
                lines.append(f"  {status} [{timestamp}] 评分:{score:g}  {url}")
        
        lines.append("=" * 60)
        return "\n".join(lines)
    
    def export_csv(self, filepath: str = "detection_report.csv"):
        """导出检测记录为CSV格式"""
        import csv
        try:
            with self._lock:
                self._refresh_if_changed()
                logs = list(self._logs)
            with open(filepath, 'w', newline='', encoding='utf-8-sig') as f:
                if not logs:
                    f.write("暂无检测记录")
                    return

                writer = csv.DictWriter(f, fieldnames=[
                    "timestamp", "url", "score", "risk_level",
                    "is_malicious", "details"
                ])
                writer.writeheader()
                for log in logs:
                    details = log.get("details") or []
                    if not isinstance(details, list):
                        details = [str(details)]
                    writer.writerow({
                        "timestamp": log.get("timestamp", ""),
                        "url": log.get("url", ""),
                        "score": log.get("score", 0),
                        "risk_level": log.get("risk_level", ""),
                        "is_malicious": log.get("is_malicious", False),
                        "details": "; ".join(str(x) for x in details),
                    })
            print(f"[报告] 已导出CSV报告: {filepath}")
        except Exception as e:
            print(f"[报告] 导出CSV失败: {e}")