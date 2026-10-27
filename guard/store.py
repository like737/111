"""
guard 自己的数据存储（全部落在 guard\\data, 与 eyilianjie 的数据完全隔离）

包含:
  * dynamic_block.json —— 动态拦截集（来源: eyilianjie 检测日志 / 手动加黑 / 拦截页误报回写）
  * allow.json         —— guard 放行名单（拦截页"误报放行"写入）
  * access_log.json    —— guard 的拦截/放行记录
  * stats.json         —— 累计计数（重启不清零）
所有写盘都是"临时文件 + os.replace"的原子写, 避免中断产生半个文件。
"""

import json
import os
import threading
import time

from . import DATA_DIR, urlutil


class Store:
    def __init__(self, data_dir=None, max_log=2000):
        self.dir = data_dir or DATA_DIR
        os.makedirs(self.dir, exist_ok=True)
        self.dynamic_file = os.path.join(self.dir, "dynamic_block.json")
        self.allow_file = os.path.join(self.dir, "allow.json")
        self.access_file = os.path.join(self.dir, "access_log.json")
        self.stats_file = os.path.join(self.dir, "stats.json")

        self._lock = threading.RLock()
        self.dynamic_hosts = {}          # host -> meta
        self.dynamic_urls = {}           # 规范化URL -> meta
        self.allow_hosts = set()
        self.allow_urls = set()
        self.counters = {"judged": 0, "blocked": 0, "allowed": 0,
                         "blocked_http": 0, "blocked_https": 0, "judge_errors": 0}
        self.started_at = time.time()
        self.max_log = int(max_log or 2000)
        self._logs = []
        self._load()
        self._rules_stamp_last = self._rules_stamp()   # 名单文件指纹（别的进程改过 → 重读）

    # ================= 读写文件 =================
    def _load(self):
        dyn = self._read_json(self.dynamic_file, {}) or {}
        self.dynamic_hosts = dict(dyn.get("hosts") or {})
        self.dynamic_urls = dict(dyn.get("urls") or {})
        allow = self._read_json(self.allow_file, {}) or {}
        self.allow_hosts = set(allow.get("hosts") or [])
        self.allow_urls = set(allow.get("urls") or allow.get("entries") or [])
        self._logs = list(self._read_json(self.access_file, []) or [])[:self.max_log]
        stats = self._read_json(self.stats_file, {}) or {}
        for key in self.counters:
            try:
                self.counters[key] = int(stats.get(key, 0))
            except (TypeError, ValueError):
                pass

    @staticmethod
    def _read_json(path, default):
        if not os.path.exists(path):
            return default
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as exc:
            print("[guard] 读取 %s 失败(忽略): %s" % (os.path.basename(path), exc))
            return default

    @staticmethod
    def _write_json(path, data):
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, path)

    def _save_dynamic(self):
        with self._lock:
            self._write_json(self.dynamic_file,
                             {"hosts": self.dynamic_hosts, "urls": self.dynamic_urls,
                              "updated_at": time.strftime("%Y-%m-%d %H:%M:%S")})
            self._rules_stamp_last = self._rules_stamp()

    def _save_allow(self):
        with self._lock:
            self._write_json(self.allow_file,
                             {"hosts": sorted(self.allow_hosts),
                              "urls": sorted(self.allow_urls),
                              "updated_at": time.strftime("%Y-%m-%d %H:%M:%S")})
            self._rules_stamp_last = self._rules_stamp()

    # ---------- 跨进程热同步 ----------
    @staticmethod
    def _file_stamp(path):
        """单个文件的指纹（mtime + 大小）"""
        try:
            stat = os.stat(path)
            return (stat.st_mtime_ns, stat.st_size)
        except OSError:
            return None

    def _rules_stamp(self):
        return (self._file_stamp(self.allow_file), self._file_stamp(self.dynamic_file))

    def refresh_rules(self):
        """手动刷新放行名单/动态拦截集（批量判定前调用一次, 之后可用 reload=False）"""
        return self._reload_rules_if_changed()

    def _reload_rules_if_changed(self):
        """名单文件被别的进程改过 → 重新读进来（返回是否真的重读了）。

        为什么需要: 放行名单 / 动态拦截集在内存里是"启动时的快照"。同时跑
        guard 控制台(8899) 和 Web 端(5000) 时是两个进程各一份 —— 在 A 里点
        "加入放行", B 不重读的话要等到重启才认（表现: 扩展里放行了, 浏览器还是拦）。
        文件很小; 先比指纹再决定要不要读, 每次判定只多两次 os.stat。
        """
        if self._rules_stamp() == self._rules_stamp_last:
            return False
        with self._lock:
            allow = self._read_json(self.allow_file, {}) or {}
            self.allow_hosts = set(allow.get("hosts") or [])
            self.allow_urls = set(allow.get("urls") or allow.get("entries") or [])
            dyn = self._read_json(self.dynamic_file, {}) or {}
            self.dynamic_hosts = dict(dyn.get("hosts") or {})
            self.dynamic_urls = dict(dyn.get("urls") or {})
            self._rules_stamp_last = self._rules_stamp()
        return True

    def _save_stats(self):
        with self._lock:
            data = dict(self.counters)
            data["started_at"] = time.strftime("%Y-%m-%d %H:%M:%S",
                                               time.localtime(self.started_at))
            self._write_json(self.stats_file, data)

    def flush(self):
        """把内存状态落盘（退出/手动时调用）"""
        try:
            self._save_dynamic()
            self._save_allow()
            self._save_stats()
        except Exception as exc:
            print("[guard] 落盘失败: %s" % exc)

    # ================= 匹配 =================
    @staticmethod
    def _match_host(host, table):
        """域名级匹配: 自身 + 各级父域（www.a.com -> www.a.com / a.com）"""
        for candidate in urlutil.parent_domains(host):
            if candidate in table:
                return candidate, table[candidate]
        return None, None

    @staticmethod
    def _url_candidates(url):
        """URL 级匹配候选: 精确 / 去参数 / 协议互换 / 父路径"""
        normed = urlutil.norm_url(url)
        candidates = [normed, urlutil.without_query(normed)]
        for item in list(candidates):
            if item.startswith("https://"):
                candidates.append("http://" + item[8:])
            elif item.startswith("http://"):
                candidates.append("https://" + item[7:])
        no_query = urlutil.without_query(normed)
        try:
            from urllib.parse import urlsplit, urlunsplit
            parts = urlsplit(no_query)
            for parent in urlutil.path_parents(no_query)[1:]:
                candidates.append(urlunsplit((parts.scheme, parts.netloc, parent, "", "")))
        except Exception:
            pass
        seen, out = set(), []
        for item in candidates:
            if item and item not in seen:
                seen.add(item)
                out.append(item)
        return out

    def match_dynamic(self, url, host=None):
        """命中动态拦截集则返回元信息, 否则 None"""
        self._reload_rules_if_changed()
        host = host or urlutil.host_of(url)
        with self._lock:
            key, meta = self._match_host(host, self.dynamic_hosts)
            if meta:
                return dict(meta, matched_level="域名", matched_key=key)
            for candidate in self._url_candidates(url):
                meta = self.dynamic_urls.get(candidate)
                if meta:
                    return dict(meta, matched_level="URL", matched_key=candidate)
        return None

    def match_allow(self, url, host=None, reload=True):
        """放行名单命中查询: 命中则返回命中的条目(域名或 URL), 否则 None。

        与 is_allowed 同一套规则（父域也算命中）。单独暴露出来是为了让"手动拦截"
        能提前告诉用户"这条会被放行压过去" —— 否则用户会看到"已加入拦截"却怎么都拦不住。

        reload=False: 批量场景（如检测日志联动逐条判断）跳过"文件指纹比对重读",
        由调用方保证先刷新一次即可, 避免几千次 os.stat。
        """
        if reload:
            self._reload_rules_if_changed()
        host = host or urlutil.host_of(url)
        allow_hosts = {item: True for item in self.allow_hosts}
        with self._lock:
            key = self._match_host(host, allow_hosts)[0]
            if key:
                return key
            for candidate in self._url_candidates(url):
                if candidate in self.allow_urls:
                    return candidate
        return None

    def is_allowed(self, url, host=None, reload=True):
        """guard 放行名单（含父域匹配; 放行优先于拦截）

        reload=False 供批量判定使用（见 match_allow 的说明）。
        """
        return self.match_allow(url, host, reload=reload) is not None

    def is_dynamic_empty(self):
        return not (self.dynamic_hosts or self.dynamic_urls)

    # ================= 写入 =================
    def add_dynamic(self, url, reason="", category="", source="", host_level=True,
                    trusted=False, note=""):
        """把一条目标加入动态拦截集（URL 必加; 域名级按参数与可信站点判断）

        trusted=True（eyilianjie 认定的可信大站）时只记录这条 URL,
        避免"AI 误判一条搜索链接 → 整个 google.com 被封"。
        """
        host = urlutil.host_of(url)
        meta = {"reason": reason, "category": category, "source": source,
                "ts": time.strftime("%Y-%m-%d %H:%M:%S"), "note": note}
        added = []
        with self._lock:
            normed = urlutil.norm_url(url)
            if normed:
                self.dynamic_urls[normed] = dict(meta, host=host, level="URL")
                added.append(normed)
            if host and host_level and not trusted and not urlutil.is_local_host(host):
                self.dynamic_hosts[host] = dict(meta, level="域名")
                added.append(host)
                reg = urlutil.registrable_domain(host)
                if reg and reg != host:
                    self.dynamic_hosts[reg] = dict(meta, level="注册域")
                    added.append(reg)
            if added:
                try:
                    self._save_dynamic()
                except Exception as exc:
                    print("[guard] 动态拦截集保存失败: %s" % exc)
        return {"added": added, "host": host}

    def add_dynamic_many(self, items, save=True):
        """批量加入动态拦截集（items: [{"url","reason","category","source","host_level","trusted"}...]）

        只在最后写一次盘, 用于"导入 eyilianjie 历史检测结果"这类批量场景。
        """
        added_total, hosts = [], []
        with self._lock:
            for item in items or []:
                url = (item or {}).get("url") or ""
                normed = urlutil.norm_url(url)
                if not normed:
                    continue
                host = urlutil.host_of(url)
                meta = {"reason": item.get("reason") or "", "category": item.get("category") or "",
                        "source": item.get("source") or "", "note": item.get("note") or "",
                        "ts": item.get("ts") or time.strftime("%Y-%m-%d %H:%M:%S")}
                self.dynamic_urls[normed] = dict(meta, host=host, level="URL")
                added_total.append(normed)
                if host and item.get("host_level", True) and not item.get("trusted"):
                    if not urlutil.is_local_host(host):
                        self.dynamic_hosts[host] = dict(meta, level="域名")
                        hosts.append(host)
                        reg = urlutil.registrable_domain(host)
                        if reg and reg != host:
                            self.dynamic_hosts[reg] = dict(meta, level="注册域")
                            hosts.append(reg)
            if added_total and save:
                try:
                    self._save_dynamic()
                except Exception as exc:
                    print("[guard] 动态拦截集保存失败: %s" % exc)
        return {"urls": added_total, "hosts": hosts}

    def add_allow(self, value, note=""):
        """加入放行名单; 同时移除动态拦截集里冲突的条目（放行立即生效）

        注意: 只登记"输入的主机名 + 该条 URL" —— 不会连带放行整个注册域,
        避免"给某个子域放行"意外放大成"整个站点都放行"。
        """
        value = (value or "").strip()
        if not value:
            return {"ok": False, "reason": "empty", "entry": ""}
        host = urlutil.host_of(value)
        with self._lock:
            if host and not urlutil.is_local_host(host):
                self.allow_hosts.add(host)
            normed = urlutil.norm_url(value)
            if normed:
                self.allow_urls.add(normed)
            removed = self._drop_dynamic_for(host, normed)
            self._save_allow()
            if removed:
                try:
                    self._save_dynamic()
                except Exception:
                    pass
        return {"ok": True, "entry": value, "host": host,
                "removed_dynamic": removed, "note": note}

    def allow_entries(self):
        """当前放行名单（域名 + URL），给页面展示 / CLI 用"""
        self._reload_rules_if_changed()
        with self._lock:
            return {"hosts": sorted(self.allow_hosts), "urls": sorted(self.allow_urls)}

    def dynamic_entries(self, limit=50):
        """当前动态拦截集（域名 + URL，按时间倒序），给页面展示用"""
        self._reload_rules_if_changed()
        with self._lock:
            rows = [(key, "域名", dict(meta or {})) for key, meta in self.dynamic_hosts.items()]
            rows += [(key, "URL", dict(meta or {})) for key, meta in self.dynamic_urls.items()]
        rows.sort(key=lambda item: item[2].get("ts") or "", reverse=True)
        return {
            "count": len(rows),
            "entries": [{"value": key, "level": level,
                         "source": meta.get("source") or "",
                         "category": meta.get("category") or "",
                         "reason": meta.get("reason") or "",
                         "ts": meta.get("ts") or ""}
                        for key, level, meta in rows[:int(limit)]],
        }

    def rules_version(self):
        """名单版本号（放行名单 + 动态拦截集的文件指纹）

        用途: 浏览器扩展在每次导航前比对它 —— 只要名单变了就丢掉自己的判定缓存,
        这样"刚在页面上加入拦截"下一次访问立刻生效, 不用等 60 秒缓存过期、
        也不需要在别的页面再输一遍。
        """
        return "|".join("%s:%s" % (stamp[0], stamp[1]) if stamp else "-"
                        for stamp in self._rules_stamp())

    def remove_allow(self, value):
        """从放行名单移除（匹配口径与 is_allowed 完全一致）

        为什么不能只做"字面相等": 名单里存的是 https://www.doubao.com/，而用户
        输入的是 www.doubao.com（会被 ensure_scheme 补成 http://）—— 字面比对
        删不掉 URL 级条目, 表现就是"明明移除了却还在放行"。
        这里按 is_allowed 的同一套候选（协议互换 / 去参数 / 父路径）匹配，并连带
        清掉该主机相关（父域/子域）的条目 —— 因为放行是"父域覆盖子域"的,
        只删其中一半等于没删。
        """
        value = (value or "").strip()
        if not value:
            return {"ok": False, "removed": []}
        host = urlutil.host_of(value)
        removed = []
        with self._lock:
            related = set()
            if host:
                related.update(urlutil.parent_domains(host))                 # 自己 + 各级父域
                related.update(k for k in self.allow_hosts if k.endswith("." + host))
            for key in list(self.allow_hosts):
                if key == value or key in related:
                    self.allow_hosts.discard(key)
                    removed.append(key)
            wanted = set(self._url_candidates(urlutil.norm_url(value) or value))
            wanted.add(value)
            for key in list(self.allow_urls):
                key_host = urlutil.host_of(key)
                if (key in wanted
                        or (key_host and (key_host in related
                                          or (host and key_host.endswith("." + host))))):
                    self.allow_urls.discard(key)
                    removed.append(key)
            if removed:
                self._save_allow()
        return {"ok": bool(removed), "removed": removed}

    def _drop_dynamic_for(self, host, normed):
        """移除与 host/URL 冲突的动态条目（放行、清理用）"""
        removed = []
        if host:
            reg = urlutil.registrable_domain(host)
            for key in list(self.dynamic_hosts):
                if key == host or key == reg or host.endswith("." + key):
                    self.dynamic_hosts.pop(key, None)
                    removed.append(key)
        if normed:
            for candidate in self._url_candidates(normed):
                if candidate in self.dynamic_urls:
                    self.dynamic_urls.pop(candidate, None)
                    removed.append(candidate)
        return removed

    def remove_dynamic(self, value):
        value = (value or "").strip()
        with self._lock:
            removed = self._drop_dynamic_for(urlutil.host_of(value), urlutil.norm_url(value))
            if removed:
                self._save_dynamic()
        return {"ok": bool(removed), "removed": removed}

    def clear_dynamic(self):
        with self._lock:
            count = len(self.dynamic_hosts) + len(self.dynamic_urls)
            self.dynamic_hosts.clear()
            self.dynamic_urls.clear()
            self._save_dynamic()
        return {"ok": True, "cleared": count}

    def prune_dynamic(self, max_entries=20000):
        """限制动态集规模（超出时按记录时间淘汰最旧的）"""
        with self._lock:
            total = len(self.dynamic_hosts) + len(self.dynamic_urls)
            if total <= max_entries:
                return 0
            items = sorted(list(self.dynamic_urls.items()) + list(self.dynamic_hosts.items()),
                           key=lambda kv: (kv[1] or {}).get("ts") or "")
            dropped = 0
            for key, _meta in items[:total - max_entries]:
                if self.dynamic_urls.pop(key, None) is not None:
                    dropped += 1
                elif self.dynamic_hosts.pop(key, None) is not None:
                    dropped += 1
            if dropped:
                self._save_dynamic()
            return dropped

    # ================= 记录与统计 =================
    def count(self, action, scheme=""):
        with self._lock:
            self.counters["judged"] = self.counters.get("judged", 0) + 1
            if action == "blocked":
                self.counters["blocked"] = self.counters.get("blocked", 0) + 1
                key = "blocked_https" if scheme == "https" else "blocked_http"
                self.counters[key] = self.counters.get(key, 0) + 1
            elif action == "allowed":
                self.counters["allowed"] = self.counters.get("allowed", 0) + 1
            elif action == "judge_error":
                self.counters["judge_errors"] = self.counters.get("judge_errors", 0) + 1
            if self.counters["blocked"] and self.counters["blocked"] % 10 == 0:
                try:
                    self._save_stats()
                except Exception:
                    pass

    def log_access(self, url, action, host="", reason="", category="", source="", extra=None):
        entry = {"time": time.strftime("%Y-%m-%d %H:%M:%S"),
                 "url": url, "host": host or urlutil.host_of(url), "action": action,
                 "reason": reason, "category": category, "source": source}
        if extra:
            entry.update(extra)
        with self._lock:
            self._logs.insert(0, entry)
            del self._logs[self.max_log:]
            try:
                self._write_json(self.access_file, self._logs)
            except Exception as exc:
                print("[guard] 访问记录写入失败: %s" % exc)
        return entry

    def recent_logs(self, limit=50):
        try:
            limit = max(1, min(int(limit), self.max_log))
        except (TypeError, ValueError):
            limit = 50
        with self._lock:
            return list(self._logs[:limit])

    def stats(self):
        with self._lock:
            return {
                "counters": dict(self.counters),
                "started_at": time.strftime("%Y-%m-%d %H:%M:%S",
                                            time.localtime(self.started_at)),
                "uptime_seconds": int(time.time() - self.started_at),
                "dynamic_hosts": len(self.dynamic_hosts),
                "dynamic_urls": len(self.dynamic_urls),
                "allow_hosts": len(self.allow_hosts),
                "allow_urls": len(self.allow_urls),
                "log_entries": len(self._logs),
            }
