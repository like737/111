// ==UserScript==
// @name         eyilianjie Guard 链接拦截
// @namespace    eyilianjie.guard
// @version      1.0.0
// @description  与本地 eyilianjie guard 联动：打开页面/点击链接前先在本地判定，命中即阻止并显示丰富的拦截页（不联网、不上传数据）
// @author       eyilianjie guard
// @match        *://*/*
// @run-at       document-start
// @grant        GM_xmlhttpRequest
// @grant        GM_registerMenuCommand
// @connect      127.0.0.1
// @connect      localhost
// @noframes
// ==/UserScript==

/*
   工作原理
   --------
   1) 页面开始加载时(document-start)立刻问本地 guard: "这个 URL 能不能开?";
      命中 → window.stop() 阻止页面继续加载, 然后铺一张拦截页(整页覆盖);
   2) 点击链接 / 提交表单时先判定, 命中则阻止跳转并显示拦截页;
   3) 判定完全走本机(默认 http://127.0.0.1:8899), 不联网、不上传任何数据;
   4) guard 没运行时, 会自动退回到 eyilianjie 自己的黑名单查询接口(端口 5000)。
   快捷键: ESC = 返回上一页; 只对 http/https 生效, 本机地址不做拦截。
*/

(function () {
  'use strict';

  // ================= 配置 =================
  var DEFAULTS = {
    api: 'http://127.0.0.1:8899',      // guard 控制台地址
    eyApi: 'http://127.0.0.1:5000',    // 兜底: eyilianjie 自带的 /blacklist/lookup
    enabled: true,                      // 总开关（菜单可切换）
    clickGuard: true,                   // 点击链接时拦截
    pageGuard: true,                    // 打开页面时拦截
    timeout: 2500,                      // 单次判定超时(ms)
    ttl: 60000,                         // 判定结果缓存(ms)
    proceedSeconds: 10                  // 拦截页上"仍然访问"的倒计时
  };
  var CFG = loadConfig();
  var CACHE = new Map();                // url -> {expire, data}
  var INFLIGHT = new Map();             // url -> Promise
  var SESSION_ALLOW = new Set();        // 本次会话放行（不写入 guard）
  var currentOverlay = null;

  function loadConfig() {
    var cfg = {};
    Object.keys(DEFAULTS).forEach(function (key) {
      var raw = localStorage.getItem('ey_guard_' + key);
      cfg[key] = (raw === null) ? DEFAULTS[key] : parseValue(raw, DEFAULTS[key]);
    });
    return cfg;
  }
  function parseValue(raw, fallback) {
    if (typeof fallback === 'boolean') return raw === 'true';
    if (typeof fallback === 'number') { var n = parseInt(raw, 10); return isNaN(n) ? fallback : n; }
    return raw;
  }
  function saveConfig() {
    Object.keys(CFG).forEach(function (key) {
      localStorage.setItem('ey_guard_' + key, String(CFG[key]));
    });
  }
  function apiBase() { return CFG.api.replace(/\/+$/, ''); }
  function eyApiBase() { return CFG.eyApi.replace(/\/+$/, ''); }

  // ================= 工具 =================
  function escapeHtml(text) {
    return String(text === null || text === undefined ? '' : text)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }
  function hostOf(url) {
    try { return new URL(url, location.href).hostname.toLowerCase(); } catch (e) { return ''; }
  }
  function isLocalHost(host) {
    return !host || host === 'localhost' || host === '127.0.0.1' || host === '::1'
      || host === '0.0.0.0' || host.endsWith('.local') || host.endsWith('.localhost');
  }
  function shouldSkip(url) {
    if (!url) return true;
    var lower = url.toLowerCase();
    if (!/^https?:\/\//.test(lower)) return true;             // 只处理 http/https
    var host = hostOf(url);
    if (isLocalHost(host)) return true;                        // 本机地址不拦
    if (host === hostOf(apiBase()) || host === hostOf(eyApiBase())) return true;
    if (lower.indexOf('/guard/') !== -1) return true;           // guard 控制台自身
    if (SESSION_ALLOW.has(lower)) return true;
    return false;
  }
  function gmGet(url, timeout) {
    return new Promise(function (resolve) {
      try {
        GM_xmlhttpRequest({
          method: 'GET',
          url: url,
          timeout: timeout || CFG.timeout,
          onload: function (resp) {
            resolve({ ok: resp.status >= 200 && resp.status < 300, text: resp.responseText });
          },
          onerror: function () { resolve({ ok: false, text: '' }); },
          ontimeout: function () { resolve({ ok: false, text: '' }); }
        });
      } catch (e) { resolve({ ok: false, text: '' }); }
    });
  }
  function gmPost(url, data) {
    return new Promise(function (resolve) {
      try {
        GM_xmlhttpRequest({
          method: 'POST',
          url: url,
          headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
          data: typeof data === 'string' ? data : '',
          timeout: CFG.timeout,
          onload: function (resp) {
            var parsed = null;
            try { parsed = JSON.parse(resp.responseText); } catch (e) { parsed = null; }
            resolve({ ok: resp.status >= 200 && resp.status < 300, data: parsed });
          },
          onerror: function () { resolve({ ok: false, data: null }); },
          ontimeout: function () { resolve({ ok: false, data: null }); }
        });
      } catch (e) { resolve({ ok: false, data: null }); }
    });
  }

  // ================= 判定（带缓存与请求去重） =================
  function checkUrl(url) {
    var hit = CACHE.get(url);
    if (hit && hit.expire > Date.now()) return Promise.resolve(hit.data);
    if (INFLIGHT.has(url)) return INFLIGHT.get(url);
    var task = checkRemote(url).then(function (data) {
      CACHE.set(url, { expire: Date.now() + CFG.ttl, data: data });
      INFLIGHT.delete(url);
      return data;
    })['catch'](function () {
      INFLIGHT.delete(url);
      return { blocked: false, source: 'error', reason: '判定接口不可用（已放行）',
               details: [], offline: true };
    });
    INFLIGHT.set(url, task);
    return task;
  }

  function checkRemote(url) {
    return gmGet(apiBase() + '/guard/check?url=' + encodeURIComponent(url)).then(function (resp) {
      if (resp.ok) {
        try {
          var payload = JSON.parse(resp.text);
          if (payload && payload.ok && payload.decision) {
            payload.decision.blocked = !!payload.blocked;
            payload.decision.apiBase = apiBase();
            return payload.decision;
          }
        } catch (e) { /* 落到兜底通道 */ }
      }
      return checkRemoteFallback(url);       // guard 没运行 → 用 eyilianjie 自己的黑名单接口
    });
  }

  function checkRemoteFallback(url) {
    return gmGet(eyApiBase() + '/blacklist/lookup?url=' + encodeURIComponent(url))
      .then(function (resp) {
        if (!resp.ok) {
          return { blocked: false, source: 'error', apiBase: apiBase(),
                   reason: 'guard 未运行（判定接口不可用, 已放行）', details: [], offline: true };
        }
        var hit = null;
        try { hit = JSON.parse(resp.text); } catch (e) { hit = null; }
        var first = (hit && hit.hits && hit.hits[0]) || {};
        if (hit && hit.matched) {
          return {
            blocked: true,
            source: 'blacklist',
            source_label: '命中 eyilianjie 黑名单（兜底通道）',
            category: first.category || '',
            entry: first.entry || '',
            level: first.level || '',
            reason: '命中 eyilianjie 黑名单记录',
            details: (hit.hits || []).slice(0, 8).map(function (item) {
              return item.entry + '  [' + (item.category || '') + ']';
            }),
            checked_at: new Date().toLocaleString(),
            apiBase: eyApiBase()
          };
        }
        return { blocked: false, source: 'none', apiBase: eyApiBase(),
                 reason: '未命中黑名单（兜底通道）', details: [] };
      });
  }

  // ================= 一些文案 =================
  var SOURCE_EXPLAIN = {
    blacklist: '该地址命中 eyilianjie 的恶意 URL 黑名单（18 万+ 条, 含恶意软件、钓鱼、诈骗、色情等分类）。',
    adult: '该域名命中成人/赌博类关键词库。eyilianjie 对「域名级强命中」采取直接拦截策略, 不需要 AI 参与判断。',
    heuristic: '该地址被 eyilianjie 的启发式规则集判定为恶意: 可能命中了恶意/钓鱼模式库、可疑域名库、可疑顶级域名、欺骗性域名结构或 DGA 随机域名等规则。',
    ml: '该地址被 eyilianjie 的机器学习模型判定为恶意（模型只看 URL 的字符与结构特征, 不联网、不看页面内容）。',
    'ml-hint': '该地址被机器学习模型高置信判为恶意, 该模型默认只做提示; guard 已按配置把它纳入拦截。',
    dynamic_log: '该地址出现在 eyilianjie 的检测记录里, 且当时的结论是「恶意」。guard 会持续只读同步这些结论 —— 检测判过的东西, 现在真的打不开了。',
    dynamic_manual: '该地址被手动加入了 guard 的拦截名单（控制台或命令行）。',
    allowlist: '该地址在 guard 放行名单中, 理论上不该被拦（若出现本页请刷新重试）。',
    whitelist: '该地址在 eyilianjie 白名单中, 理论上不该被拦（若出现本页请刷新重试）。',
    error: '判定时出现异常。guard 默认「判定异常即放行」, 以免影响正常上网。',
    local: '本机地址不会被拦截。',
    none: '未命中任何规则。'
  };

  // ================= 拦截页（整页覆盖, 内容尽量丰富） =================
  var STYLE_ID = 'eyg-guard-style';
  function ensureStyle() {
    if (document.getElementById(STYLE_ID)) return;
    var css = [
      '.eyg-mask{position:fixed;inset:0;z-index:2147483647;overflow:auto;',
      'background:radial-gradient(1200px 620px at 50% -10%,#3b1d1d 0%,#1b1b22 45%,#0e0e13 100%);',
      'color:#f4f5f8;font-family:"Segoe UI","Microsoft YaHei",system-ui,-apple-system,sans-serif;',
      'display:flex;align-items:flex-start;justify-content:center;padding:34px 16px;',
      'animation:eyg-in .18s ease-out}',
      '@keyframes eyg-in{from{opacity:0}to{opacity:1}}',
      '.eyg-card{width:100%;max-width:860px;background:rgba(28,28,36,.92);',
      'border:1px solid rgba(255,255,255,.10);border-radius:20px;box-shadow:0 26px 74px rgba(0,0,0,.62);',
      'overflow:hidden}',
      '.eyg-head{display:flex;gap:18px;align-items:center;padding:24px 28px;',
      'background:linear-gradient(135deg,rgba(220,53,69,.24),rgba(255,193,7,.10));',
      'border-bottom:1px solid rgba(255,255,255,.07)}',
      '.eyg-head svg{width:64px;height:64px;flex:0 0 64px;filter:drop-shadow(0 8px 18px rgba(220,53,69,.45))}',
      '.eyg-head h1{font-size:24px;letter-spacing:.4px;margin:0}',
      '.eyg-head p{color:#c9cad6;font-size:13px;margin-top:6px;line-height:1.6}',
      '.eyg-body{padding:22px 28px 6px}',
      '.eyg-url{background:rgba(0,0,0,.38);border:1px dashed rgba(255,255,255,.18);border-radius:12px;',
      'padding:12px 14px;font-family:Consolas,Menlo,monospace;font-size:13px;word-break:break-all;color:#ffd9dd}',
      '.eyg-chips{display:flex;flex-wrap:wrap;gap:8px;margin:16px 0 4px}',
      '.eyg-chip{background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.10);',
      'border-radius:999px;padding:6px 12px;font-size:12.4px;color:#e9e9f0}',
      '.eyg-chip b{color:#fff}',
      '.eyg-chip.red{border-color:rgba(220,53,69,.5);background:rgba(220,53,69,.16)}',
      '.eyg-chip.yellow{border-color:rgba(255,193,7,.45);background:rgba(255,193,7,.12)}',
      '.eyg-sec{margin-top:18px;padding-top:16px;border-top:1px solid rgba(255,255,255,.07)}',
      '.eyg-sec h2{font-size:13.5px;color:#a8a9b8;font-weight:600;letter-spacing:1px;margin:0 0 10px}',
      '.eyg-sec p{font-size:13.4px;line-height:1.75;color:#d7d7df;margin:0}',
      '.eyg-list{list-style:none;margin:0;padding:0;font-size:12.7px;color:#cfd0da}',
      '.eyg-list li{padding:7px 10px;margin:6px 0;background:rgba(255,255,255,.045);border-radius:8px;',
      'border-left:3px solid rgba(220,53,69,.6);word-break:break-all;font-family:Consolas,Menlo,monospace}',
      '.eyg-state{margin-top:14px;padding:11px 13px;border-radius:11px;font-size:12.8px;display:none}',
      '.eyg-state.on{display:block}',
      '.eyg-state.ok{background:rgba(25,135,84,.18);border:1px solid rgba(25,135,84,.45)}',
      '.eyg-state.err{background:rgba(220,53,69,.18);border:1px solid rgba(220,53,69,.45)}',
      '.eyg-actions{display:flex;flex-wrap:wrap;gap:10px;padding:20px 28px 6px}',
      '.eyg-actions button,.eyg-actions a{font:inherit;font-size:13.4px;padding:11px 17px;border-radius:11px;',
      'cursor:pointer;border:1px solid rgba(255,255,255,.15);background:rgba(255,255,255,.07);',
      'color:#f2f3f8;text-decoration:none;display:inline-block}',
      '.eyg-actions button:hover,.eyg-actions a:hover{background:rgba(255,255,255,.15)}',
      '.eyg-actions .eyg-primary{background:linear-gradient(135deg,#dc3545,#a5283a);border-color:transparent;font-weight:600}',
      '.eyg-actions .eyg-ok{background:linear-gradient(135deg,#198754,#14664a);border-color:transparent}',
      '.eyg-actions button[disabled]{opacity:.45;cursor:not-allowed}',
      '.eyg-foot{padding:14px 28px 22px;color:#8e8f9d;font-size:11.9px;line-height:1.7}',
      '.eyg-foot a{color:#9ecbff;text-decoration:none}',
      '.eyg-badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11.5px;',
      'background:rgba(255,255,255,.10);margin-left:6px}',
      '@media(max-width:600px){.eyg-head{flex-direction:column;align-items:flex-start}',
      '.eyg-body,.eyg-actions,.eyg-foot,.eyg-head{padding-left:18px;padding-right:18px}}'
    ].join('');
    var style = document.createElement('style');
    style.id = STYLE_ID;
    style.textContent = css;
    (document.head || document.documentElement).appendChild(style);
  }

  var SHIELD_SVG = '<svg viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">'
    + '<path d="M32 4l22 8v18c0 14-9.4 24.6-22 30C19.4 54.6 10 44 10 30V12l22-8z"'
    + ' fill="rgba(220,53,69,.22)" stroke="#dc3545" stroke-width="2.5"/>'
    + '<path d="M22 32.5l7.2 7.2L43 25" stroke="#ff8a95" stroke-width="4"'
    + ' stroke-linecap="round" stroke-linejoin="round"/></svg>';

  function chip(label, value, tone) {
    if (value === undefined || value === null || value === '') return '';
    return '<span class="eyg-chip' + (tone ? ' ' + tone : '') + '">' + escapeHtml(label)
      + ' <b>' + escapeHtml(value) + '</b></span>';
  }

  function modeLabel(mode) {
    if (mode === 'page') return '打开页面时预检（已阻止继续加载）';
    if (mode === 'form') return '提交表单时预检';
    return '点击链接时预检';
  }

  function hideOverlay() {
    if (currentOverlay && currentOverlay.parentNode) {
      currentOverlay.parentNode.removeChild(currentOverlay);
    }
    currentOverlay = null;
  }

  function showOverlay(decision, target, mode) {
    ensureStyle();
    hideOverlay();
    var d = decision || {};
    var source = d.source || 'none';
    var chips = [
      chip('拦截来源', d.source_label || source, 'red'),
      chip('分类', d.category),
      chip('命中条目', d.entry ? String(d.entry).slice(0, 120) : ''),
      chip('匹配方式', d.level),
      chip('危险加分', (d.score === 0 || d.score) ? d.score : '', 'yellow'),
      chip('判定阈值', d.threshold),
      chip('模型概率', (d.ml && d.ml.prob !== undefined && d.ml.prob !== null)
        ? Number(d.ml.prob).toFixed(4) : ''),
      chip('判定时间', d.checked_at || new Date().toLocaleString()),
      chip('拦截方式', modeLabel(mode))
    ].join('');
    var evidence = (d.details && d.details.length)
      ? d.details.slice(0, 12).map(function (line) {
          return '<li>' + escapeHtml(line) + '</li>';
        }).join('')
      : '<li>（该来源没有附加的规则明细）</li>';
    var apiUrl = (d.apiBase || apiBase()).replace(/\/+$/, '');

    var mask = document.createElement('div');
    mask.className = 'eyg-mask';
    mask.innerHTML = [
      '<div class="eyg-card">',
      '<div class="eyg-head">', SHIELD_SVG,
      '<div><h1>⛔ 该链接已被拦截</h1>',
      '<p>由本机 <b>eyilianjie guard</b> 在浏览器里拦下：页面没有继续加载，',
      '请求也没有发往目标站点（window.stop 已执行）。</p></div></div>',
      '<div class="eyg-body">',
      '<div class="eyg-url">', escapeHtml(target), '</div>',
      '<div class="eyg-chips">', chips, '</div>',
      '<div class="eyg-sec"><h2>为什么被拦</h2><p>',
      escapeHtml(SOURCE_EXPLAIN[source] || SOURCE_EXPLAIN.none), '</p></div>',
      '<div class="eyg-sec"><h2>判定依据（来自 eyilianjie 的规则）</h2>',
      '<ul class="eyg-list">', evidence, '</ul></div>',
      '<div class="eyg-state"></div>',
      '</div>',
      '<div class="eyg-actions">',
      '<button class="eyg-primary eyg-back" type="button">← 返回上一页</button>',
      '<button class="eyg-stay" type="button">关闭提示（不再跳转）</button>',
      '<button class="eyg-ok eyg-allow" type="button">误报？加入放行名单</button>',
      '<button class="eyg-proceed" type="button" disabled>仍然访问（<span class="eyg-secs">',
      String(CFG.proceedSeconds), '</span>s）</button>',
      '<button class="eyg-copy" type="button">复制链接</button>',
      '<a class="eyg-console" target="_blank" rel="noopener" href="', escapeHtml(apiUrl), '/">',
      '打开 guard 控制台</a>',
      '</div>',
      '<div class="eyg-foot">',
      '拦截链路: 黑名单 → 成人规则 → 机器学习模型 → 启发式规则 → eyilianjie 检测记录联动。',
      '<br>误拦请点「加入放行名单」（写入本机 guard, 立即生效）; ESC = 返回上一页。',
      '<br>判定服务: ', escapeHtml(apiUrl), d.offline ? '（不可用, 已按放行处理）' : '',
      ' · 脚本版本 1.0.0 · 数据不出本机',
      '</div></div>'
    ].join('');
    (document.documentElement || document.body).appendChild(mask);
    currentOverlay = mask;

    var state = mask.querySelector('.eyg-state');
    function setState(text, ok) {
      state.className = 'eyg-state on' + (ok ? ' ok' : ' err');
      state.textContent = text;
    }
    mask.querySelector('.eyg-back').addEventListener('click', function () { goBack(); });
    mask.querySelector('.eyg-stay').addEventListener('click', function () { hideOverlay(); });
    mask.querySelector('.eyg-copy').addEventListener('click', function () {
      copyText(target, setState);
    });
    mask.querySelector('.eyg-allow').addEventListener('click', function () {
      setState('正在加入放行名单…', true);
      gmPost(apiBase() + '/guard/allow', 'url=' + encodeURIComponent(target)).then(function (res) {
        if (res.ok && res.data && (res.data.ok || (res.data.removed_dynamic || []).length)) {
          SESSION_ALLOW.add(String(target).toLowerCase());
          CACHE["delete"](target);
          setState('已加入 guard 放行名单：' + target + '（点「仍然访问」即可打开）', true);
        } else {
          setState('加入放行名单失败：'
            + ((res.data && (res.data.reason || res.data.error)) || '无法连接 guard 控制台'), false);
        }
      });
    });

    var proceed = mask.querySelector('.eyg-proceed');
    var secs = CFG.proceedSeconds;
    if (d.offline) {                       // guard 不可用时不必等倒计时
      proceed.disabled = false;
      proceed.textContent = '仍然访问（风险自负）';
    } else {
      var timer = setInterval(function () {
        secs -= 1;
        var el = mask.querySelector('.eyg-secs');
        if (el) el.textContent = String(secs > 0 ? secs : 0);
        if (secs <= 0) {
          clearInterval(timer);
          proceed.disabled = false;
          proceed.textContent = '仍然访问（风险自负）';
        }
      }, 1000);
    }
    proceed.addEventListener('click', function () {
      SESSION_ALLOW.add(String(target).toLowerCase());
      CACHE["delete"](target);
      window.location.href = target;
    });
    return mask;
  }

  function copyText(text, setState) {
    function fallback() {
      try {
        var area = document.createElement('textarea');
        area.value = text;
        area.style.position = 'fixed';
        area.style.opacity = '0';
        document.documentElement.appendChild(area);
        area.select();
        document.execCommand('copy');
        area.remove();
        setState('链接已复制到剪贴板', true);
      } catch (e) { setState('复制失败, 请手动选中上方地址复制', false); }
    }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () {
        setState('链接已复制到剪贴板', true);
      })['catch'](fallback);
    } else {
      fallback();
    }
  }

  // ================= 拦截入口 =================
  function goBack() {
    if (history.length > 1) history.back();
    else window.location.href = 'about:blank';
  }

  function navigateTo(url, newTab) {
    if (newTab) window.open(url, '_blank', 'noopener');
    else window.location.assign(url);
  }

  function closestAnchor(node) {
    var element = node;
    while (element && element.nodeType === 1) {
      if (element.tagName === 'A' && element.hasAttribute('href')) return element;
      element = element.parentNode;
    }
    return null;
  }

  function onClickCapture(event) {
    if (!CFG.enabled || !CFG.clickGuard) return;
    if (event.defaultPrevented) return;
    if (event.type === 'click' && event.button !== 0) return;
    var anchor = closestAnchor(event.target);
    if (!anchor) return;
    var href = anchor.getAttribute('href');
    if (!href || href.charAt(0) === '#') return;
    if (anchor.hasAttribute('download')) return;
    var url = anchor.href;
    if (shouldSkip(url)) return;
    var newTab = (anchor.target && anchor.target !== '_self') || event.ctrlKey
      || event.metaKey || event.shiftKey || event.button === 1;
    event.preventDefault();
    event.stopImmediatePropagation();
    checkUrl(url).then(function (d) {
      if (d && d.blocked) {
        try { window.stop(); } catch (e) { /* 忽略 */ }
        showOverlay(d, url, 'click');
      } else {
        navigateTo(url, newTab);
      }
    });
  }

  function onSubmitCapture(event) {
    if (!CFG.enabled || !CFG.clickGuard) return;
    var form = event.target;
    if (!form || form.tagName !== 'FORM') return;
    var url = '';
    try {
      url = new URL(form.getAttribute('action') || location.href, location.href).href;
    } catch (e) { return; }
    if (shouldSkip(url)) return;
    event.preventDefault();
    event.stopImmediatePropagation();
    checkUrl(url).then(function (d) {
      if (d && d.blocked) showOverlay(d, url, 'form');
      else if (typeof form.submit === 'function') form.submit();
    });
  }

  function pageGuard() {
    if (!CFG.enabled || !CFG.pageGuard) return;
    var url = location.href;
    if (shouldSkip(url)) return;
    checkUrl(url).then(function (d) {
      if (d && d.blocked) {
        try { window.stop(); } catch (e) { /* 忽略 */ }
        showOverlay(d, url, 'page');
      }
    });
  }

  function spaGuard() {
    var last = location.href;
    function recheck() {
      var now = location.href;
      if (now === last) return;
      last = now;
      if (!CFG.enabled || !CFG.pageGuard) return;
      if (shouldSkip(now)) return;
      checkUrl(now).then(function (d) {
        if (d && d.blocked) {
          try { window.stop(); } catch (e) { /* 忽略 */ }
          showOverlay(d, now, 'page');
        }
      });
    }
    ['pushState', 'replaceState'].forEach(function (name) {
      var original = history[name];
      if (typeof original !== 'function') return;
      history[name] = function () {
        var result = original.apply(this, arguments);
        setTimeout(recheck, 0);
        return result;
      };
    });
    window.addEventListener('popstate', recheck);
    window.addEventListener('hashchange', recheck);
  }

  function initMenus() {
    if (typeof GM_registerMenuCommand !== 'function') return;
    GM_registerMenuCommand(CFG.enabled ? '⏸ 暂停本浏览器拦截' : '▶ 启用本浏览器拦截', function () {
      CFG.enabled = !CFG.enabled;
      saveConfig();
      alert('eyilianjie guard：' + (CFG.enabled ? '已启用拦截' : '已暂停拦截（仅本浏览器）'));
    });
    GM_registerMenuCommand('🖥 打开 guard 控制台', function () {
      window.open(apiBase() + '/', '_blank', 'noopener');
    });
    GM_registerMenuCommand('🧪 查看拦截页样张', function () {
      showOverlay({
        source: 'blacklist',
        source_label: '命中 eyilianjie 黑名单',
        reason: '样张演示, 并非真实拦截',
        category: '示例分类',
        entry: 'example-malware.com',
        level: '域名匹配',
        details: ['黑名单条目: example-malware.com', '匹配方式: 域名匹配', '（这是一张演示样张）'],
        checked_at: new Date().toLocaleString(),
        apiBase: apiBase()
      }, location.href, 'click');
    });
    GM_registerMenuCommand('🧹 清空本地判定缓存', function () {
      CACHE.clear();
      alert('已清空本地判定缓存（' + CFG.ttl / 1000 + ' 秒后自动过期）');
    });
  }

  function boot() {
    try {
      ensureStyle();
      initMenus();
      pageGuard();
      document.addEventListener('click', onClickCapture, true);
      document.addEventListener('auxclick', onClickCapture, true);
      document.addEventListener('submit', onSubmitCapture, true);
      window.addEventListener('keydown', function (event) {
        if (event.key === 'Escape' && currentOverlay) goBack();
      }, true);
      spaGuard();
    } catch (e) { /* 任何异常都不影响页面本身 */ }
  }

  boot();
})();




