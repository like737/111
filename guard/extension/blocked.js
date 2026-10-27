/* 拦截页逻辑：从地址栏参数还原目标 URL 与判定结论，并处理四个按钮。 */
const params = new URLSearchParams(location.search);
const target = params.get("u") || "";
let decision = {};
try {
    decision = JSON.parse(fromBase64(params.get("d") || ""));
} catch (err) {
    decision = { reason: "（未能解析判定详情）" };
}

function fromBase64(b64) {
    const binary = atob(b64);
    const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
    return new TextDecoder().decode(bytes);
}

function esc(value) {
    return String(value === undefined || value === null ? "" : value)
        .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function toast(message) {
    const box = document.getElementById("toast");
    box.textContent = message;
    box.classList.add("show");
    setTimeout(() => box.classList.remove("show"), 2200);
}

function chip(label, value, tone) {
    if (!value) { return ""; }
    return '<span class="chip ' + (tone || "") + '">' + esc(label) + ' <b>' + esc(value) + "</b></span>";
}

/* ---------------- 渲染 ---------------- */
document.getElementById("target").textContent = target || "（空）";

const chips = [
    chip("来源", decision.source, "blue"),
    chip("分类", decision.category, "red"),
    chip("匹配", decision.level, "amber"),
    (decision.score === undefined || decision.score === null) ? "" : chip("评分", decision.score, "amber"),
    chip("命中条目", decision.entry, "")
].filter(Boolean).join("");
document.getElementById("chips").innerHTML = chips || '<span class="chip">无附加信息</span>';

document.getElementById("reason").textContent = decision.reason || "命中拦截规则";

const details = Array.isArray(decision.details) ? decision.details : [];
document.getElementById("details").innerHTML = details.length
    ? details.map((line) => "<li>" + esc(line) + "</li>").join("")
    : "";

const sourceText = {
    dynamic_log: "它在 eyilianjie 的检测记录里被判定为恶意（guard 已同步该结论）。",
    dynamic_manual: "它在 guard 的拦截名单里（手动加入或拦截页回写过）。",
    blacklist: "它命中了本地黑名单（约 18 万条，含精确/后缀/关键词多级匹配）。",
    blacklist_suffix: "它命中了本地黑名单的后缀/域名级条目。",
    adult: "它的域名命中了成人 / 赌博类关键词规则。",
    heuristic: "它触发了恶意 URL 启发式规则（可疑特征较多）。",
    ml: "本地机器学习模型给出的高置信恶意判定。",
    whitelist: "它命中白名单（本不该被拦，可能是配置问题）。",
    none: "它没有命中任何拦截规则（可能已被放行）。"
}[decision.source] || "";

document.getElementById("how").innerHTML =
    (sourceText ? esc(sourceText) + "<br>" : "") +
    "拦截逻辑：扩展在导航前向本机 guard 询问 “这个 URL 会不会被拦”，命中就先切到本页，" +
    "因此 HTTPS 站点也能显示这张页面（不需要给浏览器安装证书）。";

document.getElementById("footLeft").textContent =
    "eyilianjie 拦截守卫 v" + chrome.runtime.getManifest().version;
document.getElementById("footRight").textContent = "拦截时间 " + new Date().toLocaleString();

/* ---- 警告档（8-A）：不是拦截，只是「可疑提示」，用户可以直接继续 ---- */
if (decision.warn) {
    document.title = "该链接存在风险 · eyilianjie 拦截守卫";
    const h1 = document.querySelector("h1");
    const sub = document.querySelector(".sub");
    if (h1) { h1.textContent = "⚠ 该链接存在风险"; }
    if (sub) {
        sub.textContent = "由 eyilianjie 拦截守卫提前提示：尚未达到拦截线，但检测到可疑信号（可继续访问）";
    }
    const btnAllow = document.getElementById("btnAllow");
    if (btnAllow) { btnAllow.textContent = "这是误报？加入放行名单"; }
}

/* ---------------- 按钮 ---------------- */
document.getElementById("btnBack").addEventListener("click", () => {
    if (history.length > 1) { history.back(); } else { location.replace("about:blank"); }
});

document.getElementById("btnCopy").addEventListener("click", async () => {
    try {
        await navigator.clipboard.writeText(target);
        toast("已复制链接");
    } catch (err) {
        toast("复制失败：" + err.message);
    }
});

/* ---------------- 写接口：加入放行名单 ----------------
   后端有两个, 提供的写接口不一样, 所以按顺序试 —— 谁先接受就用谁:
     * eyilianjie Web 端(5000): POST /guard/entry（JSON + 必须带 X-Guard-Request）
     * guard 控制台(8899):      POST /guard/entry（同上, 新版 guard 才有）
     * 老版 guard 控制台:        POST /guard/allow（form 表单, 兜底）
   自定义头 X-Guard-Request 与 web_app.py / templates/guard.html 保持一致:
   服务端用它拒绝"本机跨站伪造"的写请求, 没有它一律 403 ——
   之前这里漏了它, 所以一点「误报？加入放行名单」就报"加入放行失败"。 */
const GUARD_HDR = "X-Guard-Request";

const WRITE_ENDPOINTS = [
    {
        path: "/guard/entry",
        headers: { "Content-Type": "application/json", [GUARD_HDR]: "1" },
        body: (data) => JSON.stringify(data || {})
    },
    {
        path: "/guard/allow",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: (data) => "url=" + encodeURIComponent((data && data.url) || "")
    }
];

function askGuard(base, data) {
    return new Promise((resolve) => {
        const tried = [];
        const attempt = (i) => {
            if (i >= WRITE_ENDPOINTS.length) {
                resolve({ ok: false, reason: "所有写接口都失败 → " + tried.join(" / ") });
                return;
            }
            const ep = WRITE_ENDPOINTS[i];
            fetch(base + ep.path, { method: "POST", headers: ep.headers, body: ep.body(data) })
                .then((resp) => resp.json().then(
                    (json) => ({ resp: resp, json: json }),
                    () => { throw new Error("HTTP " + resp.status + "（响应不是 JSON）"); }
                ))
                .then((out) => {
                    if (out.json && out.json.ok) { resolve(out.json); return; }
                    tried.push(ep.path + " → HTTP " + out.resp.status + " " +
                               ((out.json && (out.json.reason || out.json.error)) || ""));
                    attempt(i + 1);
                })
                .catch((err) => {
                    tried.push(ep.path + " → " + err.message);
                    attempt(i + 1);
                });
        };
        attempt(0);
    });
}

/* 先问后台要 guard 接口地址（它会探测 8899 / 5000 并缓存结果），再写入 */
function guardWrite(data) {
    return new Promise((resolve) => {
        chrome.runtime.sendMessage({ type: "api_base" }, (info) => {
            if (!info || !info.ok || !info.base) {
                const tried = (info && info.tried) || [];
                resolve({ ok: false, reason: "拦截层未运行，无法写入放行名单" +
                          (tried.length ? "（试过 " + tried.join(" / ") + "）" : "") });
                return;
            }
            askGuard(info.base, data).then(resolve);
        });
    });
}

document.getElementById("btnAllow").addEventListener("click", async () => {
    const btn = document.getElementById("btnAllow");
    btn.disabled = true;
    const result = await guardWrite({ action: "allow", url: target });
    if (result && result.ok) {
        /* 放行名单只登记"这条 URL + 它的主机名", 不会连带放行整个注册域 —— 说清楚免得误会 */
        toast("已加入放行名单（只放行该地址与其主机名），正在打开…");
        chrome.runtime.sendMessage({ type: "forget_url", url: target });   // 丢掉这条的判定缓存
        chrome.runtime.sendMessage({ type: "allow_once", url: target }, () => {
            setTimeout(() => { location.href = target; }, 300);
        });
    } else {
        btn.disabled = false;
        toast("加入放行失败：" + ((result && (result.reason || result.error)) || "未知错误"));
    }
});

/* 「仍然访问」: 拦截页 10 秒倒计时；警告页(warn) 立即可点（只是提示，不强制等待） */
const force = document.getElementById("btnForce");
if (decision.warn) {
    force.disabled = false;
    force.textContent = "仍然访问（不推荐）";
} else {
    let left = 10;
    const timer = setInterval(() => {
        left -= 1;
        if (left > 0) {
            force.textContent = "仍然访问（" + left + "）";
            return;
        }
        clearInterval(timer);
        force.disabled = false;
        force.textContent = "仍然访问（仅本次）";
    }, 1000);
}

force.addEventListener("click", () => {
    chrome.runtime.sendMessage({ type: "allow_once", url: target }, () => {
        location.href = target;
    });
});
