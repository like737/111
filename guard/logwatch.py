"""
检测日志联动 —— 只读热同步 eyilianjie 的 detection_log.json

作用（这是"检测说已拦截, 别的页面却还能打开"的根治点）:
  eyilianjie 每做一次检测都会把结果写进它自己的 detection_log.json;
  本模块**只读**这个文件（mtime + size 指纹 + 定时间隔, 风格与 detector 的热同步一致）,
  把其中 is_malicious=true 的目标收进 guard 动态拦截集 →
  之后不论用哪个浏览器/哪个页面打开, 都会被真正拦住。

注意:
  * 绝不修改 eyilianjie 的 detection_log.json（只 open('r')）;
  * 旧版日志没有 domain 字段, 这里统一从 url 解析主机名;
  * 可信大站(github/google 等)只拦那一条 URL, 不封整站（避免误伤）。
"""

import json
import os
import threading
import time

from . import DATA_DIR, PROJECT_ROOT

LOG_FILE = os.path.join(PROJECT_ROOT, "detection_log.json")
# 「已经导入到哪个时间点」的进度文件（guard 自己的数据目录）
# 作用: 每次启动只导入"上次之后的新记录", 不再把历史整批重导一遍 ——
#       否则用户在页面上删掉的条目, 下次启动又会被历史日志加回来。
STATE_FILE = os.path.join(DATA_DIR, "logwatch_state.json")


class LogWatcher(threading.Thread):
    """后台线程: 轮询 eyilianjie 检测日志, 把"判过恶意"的目标并入动态拦截集"""

    def __init__(self, engine, store, interval=2.0, import_history=True,
                 history_limit=500, verbose=True, state_file=None):
        super(LogWatcher, self).__init__(name="guard-logwatch", daemon=True)
        self.engine = engine
        self.store = store
        self.interval = max(0.5, float(interval or 2.0))
        self.import_history = bool(import_history)
        self.history_limit = int(history_limit or 500)
        self.verbose = verbose
        self.state_file = state_file or STATE_FILE
        self.last_ts = ""
        self._stop_event = threading.Event()
        self._first_scan_done = False
        self.lock = threading.Lock()
        self.stats = {"scans": 0, "imported_urls": 0, "imported_hosts": 0,
                      "last_scan": "-", "last_error": "", "log_file": LOG_FILE,
                      "log_entries": 0, "last_ts": "", "skipped_old": 0,
                      "skipped_allowed": 0}
        self._load_state()

    # ---------------- 导入进度（水位） ----------------
    @staticmethod
    def _norm_ts(value):
        """日志时间戳 → 可比较的字符串（"YYYY-MM-DDTHH:MM:SS"）

        detection_log.json 里是 ISO 格式（可能带微秒），统一截到秒后
        直接按字符串比较即可（同一格式下字典序 = 时间序）。
        """
        text = str(value or "").strip().replace(" ", "T")
        return text[:19] if len(text) >= 19 else ""

    def _load_state(self):
        """读取"已导入到哪个时间点"；文件不存在/损坏 → 视为首次运行"""
        try:
            with open(self.state_file, "r", encoding="utf-8") as handle:
                data = json.load(handle) or {}
            self.last_ts = self._norm_ts(data.get("last_ts"))
        except Exception:
            self.last_ts = ""
        self.stats["last_ts"] = self.last_ts
        return self.last_ts

    def _save_state(self):
        """保存导入进度（失败只记日志, 绝不影响拦截本身）"""
        try:
            folder = os.path.dirname(self.state_file)
            if folder:
                os.makedirs(folder, exist_ok=True)
            tmp = self.state_file + ".tmp"
            with open(tmp, "w", encoding="utf-8") as handle:
                json.dump({"last_ts": self.last_ts,
                           "updated_at": time.strftime("%Y-%m-%d %H:%M:%S")},
                          handle, ensure_ascii=False, indent=2)
            os.replace(tmp, self.state_file)
            self.stats["last_ts"] = self.last_ts
        except Exception as exc:
            self.stats["last_error"] = "保存联动进度失败: %s" % exc

    # ---------------- 线程控制 ----------------
    def stop(self):
        self._stop_event.set()

    def run(self):
        if self.verbose:
            print("[guard] 检测日志联动已启动: %s（每 %.1fs 检查一次）"
                  % (LOG_FILE, self.interval))
        while not self._stop_event.is_set():
            try:
                self.scan()
            except Exception as exc:
                self.stats["last_error"] = str(exc)
            self._stop_event.wait(self.interval)

    # ---------------- 扫描 ----------------
    def scan(self, force=False):
        """扫描一次日志（指纹没变则直接返回）。返回本次新增的条目数。"""
        with self.lock:
            self.stats["scans"] += 1
            self.stats["last_scan"] = time.strftime("%Y-%m-%d %H:%M:%S")
            if not os.path.exists(LOG_FILE):
                return 0
            try:
                stat = os.stat(LOG_FILE)
                fingerprint = (int(stat.st_mtime), int(stat.st_size))
            except OSError:
                return 0
            if not force and self._first_scan_done and fingerprint == getattr(self, "_fp", None):
                return 0
            entries = self._read_entries()
            self._fp = fingerprint
            if not entries:
                self._first_scan_done = True
                return 0
            take = entries if (self.import_history and not self._first_scan_done) \
                else entries[-200:]
            if len(take) > self.history_limit and not self._first_scan_done:
                take = take[-self.history_limit:]
            self.stats["log_entries"] = len(entries)
            self._first_scan_done = True
            return self._import(take)

    def _read_entries(self):
        try:
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as exc:
            self.stats["last_error"] = "读取检测日志失败: %s" % exc
            return []
        if isinstance(data, dict):
            data = data.get("logs") or data.get("entries") or []
        return data if isinstance(data, list) else []

    def _is_allowed(self, url, host=""):
        """放行名单里的目标不再进动态拦截集（用户已明确表示可信）"""
        try:
            return bool(self.store.is_allowed(url, host or None, reload=False))
        except Exception:
            return False

    def _import(self, entries):
        """把日志里 is_malicious 的目标加入动态拦截集（批量, 只写一次盘）

        只处理"上次导入之后"的新记录（水位见 guard/data/logwatch_state.json）:
          * 用户在页面上删掉的条目不会再被历史日志加回来;
          * 启动时不必重复处理整份历史, 更快;
          * 放行名单里的目标直接跳过（放行优先于一切拦截）。
        """
        items, seen = [], set()
        max_ts = self.last_ts
        skipped_old = skipped_allowed = 0
        try:
            self.store.refresh_rules()      # 批量判定前只刷新一次, 之后用 reload=False
        except Exception:
            pass
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            ts = self._norm_ts(entry.get("timestamp"))
            if ts > max_ts:
                max_ts = ts
            if not entry.get("is_malicious"):
                continue
            if ts and self.last_ts and ts <= self.last_ts:
                skipped_old += 1
                continue
            url = (entry.get("url") or "").strip()
            if not url.lower().startswith(("http://", "https://")):
                continue
            key = url.lower()
            if key in seen:
                continue
            seen.add(key)
            host = (entry.get("domain") or "").strip()
            if self._is_allowed(url, host):
                skipped_allowed += 1
                continue
            trusted = bool(host and self.engine.is_trusted(host))
            category = "黑名单" if entry.get("blacklist_match") else "eyilianjie 判定"
            reason = "eyilianjie 已判定为恶意"
            if entry.get("blacklist_match"):
                reason += "（命中黑名单）"
            risk = entry.get("risk_level")
            score = entry.get("score")
            extra = []
            if risk:
                extra.append(str(risk))
            if score is not None:
                extra.append("评分 %s" % score)
            if extra:
                reason += " · " + " · ".join(extra)
            items.append({"url": url, "reason": reason, "category": category,
                          "source": "eyilianjie", "note": "来自检测日志",
                          "ts": (entry.get("timestamp") or "")[:19].replace("T", " "),
                          "host_level": not trusted, "trusted": trusted})
        self.stats["skipped_old"] += skipped_old
        self.stats["skipped_allowed"] += skipped_allowed
        # 先推进水位: 即便本轮没有新增, 也不该在下次启动重复处理这批历史
        if self.import_history and max_ts and max_ts != self.last_ts:
            self.last_ts = max_ts
            self._save_state()
        if not items:
            return 0
        result = self.store.add_dynamic_many(items)
        self.store.prune_dynamic()
        self.engine.invalidate()
        self.stats["imported_urls"] += len(result["urls"])
        self.stats["imported_hosts"] += len(result["hosts"])
        if self.verbose:
            print("[guard] 检测日志联动: 新增 %d 条 URL / %d 条域名拦截"
                  "（跳过历史 %d 条 · 放行名单 %d 条; 明细见 guard/data/dynamic_block.json）"
                  % (len(result["urls"]), len(result["hosts"]),
                     skipped_old, skipped_allowed))
        return len(result["urls"])
