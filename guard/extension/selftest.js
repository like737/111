/* 扩展自检：逐项验证“能否找到 guard、判定接口是否通、拦截页能否渲染” */
const list = document.getElementById("results");
const items = [];

function ask(message) {
    return new Promise((resolve) => chrome.runtime.sendMessage(message, (resp) => resolve(resp)));
}

function add(name, ok, detail, skipped) {
    items.push({ ok: ok });
    const li = document.createElement("li");
    const flag = skipped ? '<span class="skip">[跳过]</span>' : (ok ? '<span class="ok">[通过]</span>' : '<span class="bad">[失败]</span>');
    li.innerHTML = flag + " " + name + (detail ? '<div class="muted">' + String(detail).replace(/</g, "&lt;") + "</div>" : "");
    list.appendChild(li);
    return ok;
}

async function main() {
    list.innerHTML = "";

    /* 1) 扩展环境 */
    const manifest = chrome.runtime.getManifest();
    add("扩展已加载（manifest v3, v" + manifest.version + "）", true,
        "ID: " + chrome.runtime.id + " · 权限: " + manifest.permissions.join(", "));

    /* 2) 能否找到 guard */
    const info = await ask({ type: "status" });
    const apiOk = add("找到本地 guard 接口", !!(info && info.ok),
        info && info.ok ? ("地址: " + info.base)
                        : ("都不可达: " + ((info && info.tried) || []).join(" / ") +
                           " —— 请先启动拦截层: python web_app.py（或 python -m guard run）"));
    if (!apiOk) {
        finish();
        return;
    }

    /* 3) guard 状态 */
    let state = null;
    try {
        state = await (await fetch(info.base + "/guard/state?logs=1", { cache: "no-store" })).json();
    } catch (err) {
        state = null;
    }
    add("读取 guard 状态", !!state,
        state ? ("总开关=" + (state.enabled ? "开" : "关") + " · 系统代理=" +
                 ((state.sysproxy && state.sysproxy.active) ? "走 guard" : "未启用") +
                 " · 已拦 " + ((state.counters || {}).blocked || 0) + " 次")
              : "读取失败");

    /* 4) 判定接口：恶意样例应命中 */
    const bad = "http://pornvideotop.com/";
    let badDecision = null;
    try {
        badDecision = (await (await fetch(info.base + "/guard/check?url=" + encodeURIComponent(bad) +
            "&mode=url", { cache: "no-store" })).json()).decision;
    } catch (err) { badDecision = null; }
    add("判定接口（恶意样例 " + bad + "）", !!(badDecision && badDecision.blocked),
        badDecision ? ("blocked=" + badDecision.blocked + " · source=" + badDecision.source +
                       " · " + (badDecision.reason || "")) : "请求失败");

    /* 5) 判定接口：正常站点应放行 */
    const good = "https://example.com/";
    let goodDecision = null;
    try {
        goodDecision = (await (await fetch(info.base + "/guard/check?url=" + encodeURIComponent(good) +
            "&mode=url", { cache: "no-store" })).json()).decision;
    } catch (err) { goodDecision = null; }
    add("判定接口（正常站点 " + good + "）", !!(goodDecision && !goodDecision.blocked),
        goodDecision ? ("blocked=" + goodDecision.blocked + " · source=" + goodDecision.source) : "请求失败");

    /* 6) 拦截页渲染 */
    const frame = document.getElementById("preview");
    const rendered = await new Promise((resolve) => {
        const check = () => {
            try {
                const text = frame.contentDocument && frame.contentDocument.body
                    ? frame.contentDocument.body.innerText : "";
                if (text.indexOf("该链接已被拦截") >= 0) { resolve(true); return true; }
            } catch (err) { /* 还没加载好 */ }
            return false;
        };
        if (check()) { return; }
        let tries = 0;
        const timer = setInterval(() => {
            tries += 1;
            if (check()) { clearInterval(timer); return; }
            if (tries > 40) { clearInterval(timer); resolve(false); }
        }, 120);
    });
    add("拦截页 blocked.html 渲染", rendered,
        rendered ? "页面已显示“该链接已被拦截”与判定详情" : "未能在预览里读到页面内容");

    finish();
}

function finish() {
    const passed = items.filter((x) => x.ok).length;
    const li = document.createElement("li");
    li.innerHTML = "<b>结论: " + passed + "/" + items.length + " 项通过</b>" +
        (passed === items.length ? ' <span class="ok">✅ 扩展工作正常</span>'
                                 : ' <span class="warn">请按上面提示处理</span>');
    list.appendChild(li);
}

main();
