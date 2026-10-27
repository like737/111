/* 弹窗：显示 guard 状态 + 三个快捷操作 */
const $ = (id) => document.getElementById(id);

document.getElementById("version").textContent =
    "版本 v" + chrome.runtime.getManifest().version + "（拦截页：HTTPS 同样生效）";

function renderStatus(info) {
    const apiState = $("apiState");
    const banner = $("downBanner");
    if (!info || !info.ok) {
        apiState.textContent = "未运行";
        apiState.className = "bad";
        $("enabled").textContent = "-";
        $("blocked").textContent = "-";
        banner.classList.remove("d-none");
        const gd = (info && info.guardDown) || {};
        $("diag").textContent = "guard 未运行 → 当前一律放行（不拦任何请求）" +
            (gd.count ? "；已因此放行 " + gd.count + " 个请求" : "") +
            "。启动：python web_app.py 或 python -m guard run";
        return;
    }
    banner.classList.add("d-none");
    apiState.textContent = info.base + (info.kind === "web" ? "（Web 端）"
                                     : info.kind === "console" ? "（控制台）" : "");
    apiState.className = "ok";
}

function ask(message) {
    return new Promise((resolve) => chrome.runtime.sendMessage(message, (resp) => resolve(resp)));
}

/* 读状态: 新版/Web 端有 /guard/state; 老版 guard 控制台只有 /guard/status → 回退 */
async function readState(base) {
    for (const path of ["/guard/state?logs=1", "/guard/status"]) {
        try {
            const resp = await fetch(base + path, { cache: "no-store" });
            const data = await resp.json();
            if (data && data.available !== false) { return data; }
        } catch (err) {
            /* 试下一个 */
        }
    }
    return null;
}

async function refresh() {
    const info = await ask({ type: "status" });
    renderStatus(info);
    if (!info || !info.ok) {
        const tried = ((info && info.tried) || []).join(" / ");
        $("diag").textContent += tried ? "（探测记录: " + tried + "）" : "";
        return;
    }
    const state = await readState(info.base);
    if (!state) {
        $("apiState").textContent = "读取失败";
        $("apiState").className = "warn";
        $("diag").textContent = "接口地址可达但读不到状态（" + info.base + "）";
        return;
    }
    $("enabled").textContent = state.enabled ? "已开启" : "已停止";
    $("enabled").className = state.enabled ? "ok" : "warn";
    const counters = state.counters || {};
    $("blocked").textContent = (counters.blocked || 0) + " 次";
    $("diag").textContent = "";
}

$("btnConsole").addEventListener("click", async () => {
    const info = await ask({ type: "status" });
    const url = (info && info.ok ? info.base : "http://127.0.0.1:8899") + "/";
    chrome.tabs.create({ url: url });
    window.close();
});

$("btnClear").addEventListener("click", async () => {
    const resp = await ask({ type: "clear_cache" });
    $("btnClear").textContent = resp && resp.ok ? "已清空 ✓" : "清空失败";
    setTimeout(() => { $("btnClear").textContent = "清空判定缓存"; }, 1500);
});

$("btnSelftest").addEventListener("click", () => {
    chrome.tabs.create({ url: chrome.runtime.getURL("selftest.html") });
    window.close();
});

refresh();
