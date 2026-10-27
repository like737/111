"""
拦截页（丰富版）—— 代理命中 / guard 控制台 / 油猴脚本 落地页共用同一套视觉

设计要点:
  * 完全离线: 不引用任何 CDN/字体/图片, 只用内联 CSS + 内联 SVG, 断网也能正常显示;
  * 信息丰富: 目标地址、命中来源、分类、命中的规则条目、匹配级别、危险评分、
    判定时间、命中依据逐条列出、按来源给出的"为什么被拦"说明;
  * 操作齐全: 返回上一页 / 误报放行（写 guard 放行名单）/ 仍然访问（倒计时后可用）/
    复制链接 / 打开 guard 控制台;
  * 所有动态内容都做 HTML 转义（URL 里带引号或标签也不会破坏页面）。

用法:
    from .blockpage import render_block_page
    html = render_block_page(decision, api_base="http://127.0.0.1:8899", kind="http")
"""

from html import escape

# 来源 → 拦截原因说明（让用户看得懂"为什么被拦"）
SOURCE_EXPLAIN = {
    "blacklist": "该地址命中 eyilianjie 的恶意 URL 黑名单（目前 18 万+ 条, 含恶意软件、钓鱼、"
                 "诈骗、色情等分类）。这类网址被收录通常意味着已经有人举报或检测确认过。",
    "adult": "该域名命中成人/赌博类关键词库。eyilianjie 对「域名级强命中」采用直接拦截策略, "
             "不需要 AI 参与判断（词库文件: data/adult_keywords.json, 可自行增删)。",
    "heuristic": "该地址被 eyilianjie 的启发式规则集判定为恶意: 可能命中恶意/钓鱼模式库、"
                 "可疑域名库、可疑顶级域名、欺骗性域名结构、DGA 随机域名等规则。",
    "ml": "该地址被 eyilianjie 的机器学习模型判定为恶意（模型只看 URL 的字符与结构特征, "
          "不联网、不看页面内容）。这一类网站在黑名单里往往还没收录。",
    "ml-hint": "该地址被机器学习模型高置信判为恶意, 该模型默认只做提示; guard 已按配置把它纳入拦截。",
    "dynamic_log": "该地址出现在 eyilianjie 的检测记录里, 且当时的检测结论是「恶意」。"
                   "guard 会持续只读同步这些结论 —— 也就是说: 检测判过的东西, 现在真的打不开了。",
    "dynamic_manual": "该地址被手动加入了 guard 的拦截名单（控制台「手动拦截」或导入）。",
    "allowlist": "该地址在 guard 的放行名单中, 不应被拦截（若你看到本页, 可能是缓存所致, 刷新即可）。",
    "whitelist": "该地址在 eyilianjie 白名单中, 不应被拦截（若你看到本页, 可能是缓存所致, 刷新即可）。",
    "error": "本次判定出现异常。guard 默认采取「判定异常即放行」的策略, 以免影响正常上网; "
             "详情请查看 guard 控制台的错误计数。",
    "local": "本机地址不会被拦截。",
    "none": "未命中任何规则。",
    "disabled": "guard 拦截当前未启用。",
}

_CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:"Segoe UI","Microsoft YaHei",system-ui,-apple-system,sans-serif;
background:radial-gradient(1200px 600px at 50% -10%,#3b1d1d 0%,#1b1b22 45%,#0f0f14 100%);
color:#f5f5f7;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:28px 16px}
.wrap{width:100%;max-width:820px}
.card{background:rgba(28,28,36,.86);border:1px solid rgba(255,255,255,.09);
border-radius:20px;box-shadow:0 24px 70px rgba(0,0,0,.55);overflow:hidden}
.head{display:flex;gap:18px;align-items:center;padding:26px 30px;
background:linear-gradient(135deg,rgba(220,53,69,.22),rgba(255,193,7,.10));border-bottom:1px solid rgba(255,255,255,.07)}
.shield{width:66px;height:66px;flex:0 0 66px;filter:drop-shadow(0 6px 16px rgba(220,53,69,.45))}
.head h1{font-size:26px;letter-spacing:.5px}
.head p{color:#c7c7d1;font-size:13.5px;margin-top:6px;line-height:1.5}
.body{padding:24px 30px 8px}
.url{background:rgba(0,0,0,.35);border:1px dashed rgba(255,255,255,.16);border-radius:12px;
padding:12px 14px;font-family:Consolas,Menlo,monospace;font-size:13px;word-break:break-all;color:#ffd9dd}
.chips{display:flex;flex-wrap:wrap;gap:8px;margin:16px 0 4px}
.chip{background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.10);border-radius:999px;
padding:6px 12px;font-size:12.5px;color:#e8e8ee}
.chip b{color:#fff;font-weight:600}
.chip.red{border-color:rgba(220,53,69,.5);background:rgba(220,53,69,.16)}
.chip.yellow{border-color:rgba(255,193,7,.45);background:rgba(255,193,7,.12)}
.sec{margin-top:18px;padding-top:16px;border-top:1px solid rgba(255,255,255,.07)}
.sec h2{font-size:14px;color:#a9a9b6;font-weight:600;letter-spacing:1px;margin-bottom:10px}
.sec p{font-size:13.5px;line-height:1.75;color:#d6d6de}
ul.ev{list-style:none;font-size:12.8px;color:#cfcfd8}
ul.ev li{padding:7px 10px;margin:6px 0;background:rgba(255,255,255,.045);border-radius:8px;
border-left:3px solid rgba(220,53,69,.6);word-break:break-all;font-family:Consolas,Menlo,monospace}
.actions{display:flex;flex-wrap:wrap;gap:10px;padding:22px 30px 8px}
button,.btn{font:inherit;font-size:13.5px;padding:11px 18px;border-radius:11px;cursor:pointer;
border:1px solid rgba(255,255,255,.14);background:rgba(255,255,255,.07);color:#f2f2f7;
transition:transform .06s ease,background .15s ease}
button:hover,.btn:hover{background:rgba(255,255,255,.14)}
button:active{transform:translateY(1px)}
.btn.primary{background:linear-gradient(135deg,#dc3545,#b02a37);border-color:transparent;font-weight:600}
.btn.ghost{background:transparent}
.btn[disabled]{opacity:.45;cursor:not-allowed}
.foot{padding:16px 30px 24px;color:#8d8d99;font-size:12px;line-height:1.7}
.foot a{color:#9ecbff;text-decoration:none}
.msg{margin:14px 30px 0;padding:12px 14px;border-radius:11px;font-size:13px;display:none}
.msg.ok{display:block;background:rgba(25,135,84,.18);border:1px solid rgba(25,135,84,.45)}
.msg.err{display:block;background:rgba(220,53,69,.16);border:1px solid rgba(220,53,69,.45)}
@media(max-width:560px){.head{flex-direction:column;align-items:flex-start}.body,.actions,.foot{padding-left:20px;padding-right:20px}}
"""

_SHIELD = """<svg class="shield" viewBox="0 0 64 64" fill="none" xmlns="http://www.w3.org/2000/svg">
<path d="M32 4l22 8v18c0 14-9.4 24.6-22 30C19.4 54.6 10 44 10 30V12l22-8z"
 fill="rgba(220,53,69,.22)" stroke="#dc3545" stroke-width="2.5"/>
<path d="M22 32.5l7.2 7.2L43 25" stroke="#ff8a95" stroke-width="4"
 stroke-linecap="round" stroke-linejoin="round"/></svg>"""

_KIND_LABELS = {
    "http": "本地代理 · HTTP 请求",
    "https": "本地代理 · HTTPS 隧道（按域名判定）",
    "userscript": "浏览器脚本（点击/打开前预检）",
    "console": "guard 控制台",
}


def _chip(label, value, tone=""):
    cls = "chip" + (" " + tone if tone else "")
    return '<span class="%s">%s <b>%s</b></span>' % (cls, escape(str(label)), escape(str(value)))


def render_block_page(decision, api_base="http://127.0.0.1:8899", kind="http", note=""):
    """渲染拦截页 HTML（decision 为 engine.judge() 的返回值或等价的 dict）"""
    d = decision or {}
    target = str(d.get("url") or "")
    source = str(d.get("source") or "none")
    explain = SOURCE_EXPLAIN.get(source, SOURCE_EXPLAIN["none"])
    chips = [_chip("拦截来源", d.get("source_label") or source, "red")]
    if d.get("category"):
        chips.append(_chip("分类", d["category"]))
    if d.get("entry"):
        chips.append(_chip("命中条目", str(d["entry"])[:160]))
    if d.get("level"):
        chips.append(_chip("匹配方式", d["level"]))
    if d.get("score") is not None:
        chips.append(_chip("危险加分", d["score"], "yellow"))
    if d.get("threshold") is not None:
        chips.append(_chip("判定阈值", d["threshold"]))
    prob = (d.get("ml") or {}).get("prob")
    if prob is not None:
        try:
            chips.append(_chip("模型概率", "%.4f" % float(prob)))
        except (TypeError, ValueError):
            pass
    chips.append(_chip("判定时间", d.get("checked_at") or ""))
    chips.append(_chip("拦截方式", _KIND_LABELS.get(kind, kind)))

    evidence = "".join("<li>%s</li>" % escape(str(item))
                       for item in (d.get("details") or [])[:12]) \
        or "<li>（该来源没有附加的规则明细）</li>"

    html = [
        "<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">",
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">",
        "<meta name=\"robots\" content=\"noindex\">",
        "<title>已拦截 · eyilianjie guard</title><style>", _CSS,
        "</style></head><body><div class=\"wrap\"><div class=\"card\">",
        "<div class=\"head\">", _SHIELD,
        "<div><h1>⛔ 该链接已被拦截</h1>",
        "<p>你访问的地址被 <b>eyilianjie guard</b> 本地拦截层拦下了, 请求没有发往目标站点。</p>",
        "</div></div><div class=\"body\">",
        "<div class=\"url\">", escape(target or "(未提供目标地址)"), "</div>",
        "<div class=\"chips\">", "".join(chips), "</div>",
        "<div class=\"sec\"><h2>为什么被拦</h2><p>", escape(explain), "</p></div>",
        "<div class=\"sec\"><h2>判定依据（来自 eyilianjie 的规则）</h2><ul class=\"ev\">",
        evidence, "</ul></div></div>",
        "<div id=\"msg\" class=\"msg\"></div>",
        "<div class=\"actions\">",
        "<button class=\"btn primary\" id=\"backBtn\" type=\"button\">← 返回上一页</button>",
        "<button class=\"btn\" id=\"allowBtn\" type=\"button\">误报？加入放行名单</button>",
        "<button class=\"btn\" id=\"proceedBtn\" type=\"button\" disabled>仍然访问（<span id=\"secs\">10</span>s）</button>",
        "<button class=\"btn ghost\" id=\"copyBtn\" type=\"button\">复制链接</button>",
        "<a class=\"btn ghost\" href=\"__API__/\" target=\"_blank\" rel=\"noopener\">打开 guard 控制台</a>",
        "</div>",
        "<div class=\"foot\">",
        "拦截由本机 <b>eyilianjie guard</b> 在流量层完成"
        "（黑名单 + 启发式规则 + 成人规则 + 机器学习模型 + 检测记录联动）。",
        "<br>误拦请点「加入放行名单」, 该地址会立即恢复访问; 需要调整规则可在 guard 控制台或 eyilianjie 里操作。",
        "<br>", escape(note) if note else "",
        "生成时间: ", escape(str(d.get("checked_at") or "")),
        " · guard 地址: ", escape(api_base.rstrip("/")),
        "</div></div></div>",
        "<script>", _script(api_base, target), "</script></body></html>",
    ]
    return "".join(html).replace("__API__", api_base.rstrip("/"))


def _script(api_base, target):
    """拦截页交互脚本（返回上一页 / 放行 / 倒计时后仍要访问 / 复制链接）"""
    import json as _json
    return """
(function(){
  var API = %s; var TARGET = %s;
  /* 这张拦截页可能挂在 guard 控制台(8899) 也可能挂在 Web 端(5000) 的代理上, 而两边的
     写接口不一样: 8899 用 /guard/allow（表单）, 5000 用 /guard/entry（JSON + 自定义头）。
     所以按 (地址 × 端点) 逐个试 —— 否则"点放行却没反应"（以前只有 8899 那一条路）。 */
  var BASES = [API, 'http://127.0.0.1:5000'];
  var WRITES = [
    {path: '/guard/allow',
     headers: {'Content-Type': 'application/x-www-form-urlencoded'},
     body: function(u){ return 'url=' + encodeURIComponent(u); }},
    {path: '/guard/entry',
     headers: {'Content-Type': 'application/json', 'X-Guard-Request': '1'},
     body: function(u){ return JSON.stringify({action: 'allow', url: u}); }}
  ];
  var CANDIDATES = [];
  for (var bi = 0; bi < BASES.length; bi++){
    for (var ei = 0; ei < WRITES.length; ei++){ CANDIDATES.push({base: BASES[bi], ep: WRITES[ei]}); }
  }
  var msg = document.getElementById('msg');
  function show(text, ok){ msg.className = 'msg ' + (ok ? 'ok' : 'err'); msg.textContent = text; }
  function postForm(body){
    var tried = [];
    var attempt = function(i){
      if (i >= CANDIDATES.length) { return Promise.reject(new Error(tried.join(' / ') || '没有可用地址')); }
      var item = CANDIDATES[i];
      return fetch(item.base + item.ep.path, {method:'POST',
          headers: item.ep.headers, body: item.ep.body(body)})
        .then(function(r){ return r.json().then(function(j){ return {status: r.status, json: j}; }); })
        .then(function(out){
          if (out.json && out.json.ok) { return out.json; }
          tried.push(item.base + item.ep.path + ' → HTTP ' + out.status + ' ' +
                     ((out.json && (out.json.reason || out.json.error)) || ''));
          return attempt(i + 1);
        }, function(err){
          tried.push(item.base + item.ep.path + ' → ' + (err && err.message ? err.message : err));
          return attempt(i + 1);
        });
    };
    return attempt(0);
  }
  document.getElementById('backBtn').onclick = function(){
    if (history.length > 1) history.back(); else window.location.href = 'about:blank';
  };
  document.getElementById('copyBtn').onclick = function(){
    try { navigator.clipboard.writeText(TARGET); show('链接已复制到剪贴板', true); }
    catch (e) { show('复制失败, 请手动选中上方地址复制', false); }
  };
  document.getElementById('allowBtn').onclick = function(){
    postForm(TARGET).then(function(data){
      show('已加入放行名单: ' + TARGET + '（刷新页面即可访问; 只放行该地址与其主机名）', true);
    }).catch(function(e){ show('加入放行名单失败: ' + e.message, false); });
  };
  var secs = 10, btn = document.getElementById('proceedBtn');
  var timer = setInterval(function(){
    secs--; document.getElementById('secs').textContent = secs;
    if (secs <= 0) { clearInterval(timer); btn.disabled = false;
      btn.textContent = '仍然访问（风险自负）'; }
  }, 1000);
  btn.onclick = function(){
    btn.disabled = true; btn.textContent = '正在放行…';
    postForm(TARGET).catch(function(){}).then(function(){
      window.location.href = TARGET;
    });
  };
})();
""" % (_json.dumps(api_base.rstrip("/")), _json.dumps(target))
