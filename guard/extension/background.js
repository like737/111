/* =============================================================================
   eyilianjie 拦截守卫 —— 后台逻辑（MV3 service worker）

   只做一件事：主文档开始导航时，先问本地 guard「这个 URL 会被拦吗」；
   命中就把这个标签页切到扩展自带的拦截页（blocked.html）。

   为什么这样 HTTPS 也能显示漂亮拦截页：
     * 拦截页是 chrome-extension:// 页面，不是在目标站点里注入 —— 不受站点
       的 CSP / 证书 / 混合内容限制，也不需要给浏览器装根证书；
     * 缺点（必须知道）：只覆盖装了本扩展的浏览器（当前=Edge），
       而且"拦断"发生在导航刚发起时（请求可能已经发出但会被立刻丢弃）。

   与 guard 的关系：只调用它的两个只读/写接口（默认 127.0.0.1:8899，
   不在时退回 127.0.0.1:5000 上的 Web 端接口）；guard 没运行 → 一律放行
   （fail-open，绝不因为拦截层挂了而上不了网）。
   ============================================================================= */

/* 候选后端（按顺序探测）:
   * guard 控制台: 8899（自带 Web 控制台; 新版提供 /guard/state 与 /guard/entry）
   * eyilianjie Web 端: 5000（只跑 web_app.py 时用这个） */
const CANDIDATE_APIS = [
    { base: "http://127.0.0.1:8899", kind: "console" },
    { base: "http://127.0.0.1:5000", kind: "web" }
];
const API_TTL_MS = 30 * 1000;        // 探测结果缓存
const DECISION_TTL_MS = 60 * 1000;   // 「会被拦截」结论的缓存（稳定, 可以久一点）
const ALLOW_TTL_MS = 5 * 1000;       // 「会被放行」结论只缓存 5 秒（名单随时可能被改）
const ALLOW_ONCE_TTL_MS = 90 * 1000; // 用户点「仍然访问」的有效期

let apiBase = null;
let apiKind = "";                    // console | web（给弹窗/拦截页显示"现在用的是哪个后端"）
let apiCheckedAt = 0;
let lastTried = [];
let rulesVersion = null;             // guard 侧的"名单版本号"（变了就丢本地判定缓存）
let rulesVersionHits = 0;            // 因名单变化而清缓存的次数（诊断用）
const decisionCache = new Map();
const allowOnce = new Map();

/* guard 没在运行时的"显式提示"状态 —— 扩展仍然 fail-open（绝不因此阻断上网）,
   但不再"静默"：徽章变 OFF、图标悬停给出启动命令、弹窗里红字提示"当前一律放行"。 */
const guardDown = { count: 0, since: 0, sample: "" };

function log() {
    try { console.log.apply(console, ["[guard-ext]"].concat([].slice.call(arguments))); } catch (e) {}
}

function setBadge(text, color) {
    try {
        chrome.action.setBadgeText({ text: text || "" });
        if (color) { chrome.action.setBadgeBackgroundColor({ color: color }); }
    } catch (e) {}
}

const GUARD_DOWN_TITLE =
    "eyilianjie 拦截守卫：guard 未运行（当前一律放行）\n" +
    "启动：python web_app.py   或   python -m guard run";

function setTitle(text) {
    try { chrome.action.setTitle({ title: text }); } catch (e) {}
}

/* 探测/判定发现 guard 不在运行: 记一笔 + 把"未运行"显示出来（不静默放行） */
function noteGuardDown(url) {
    guardDown.count += 1;
    if (!guardDown.since) { guardDown.since = Date.now(); }
    if (!guardDown.sample) { guardDown.sample = url || ""; }
    setBadge("OFF", "#dc3545");
    setTitle(GUARD_DOWN_TITLE);
    log("guard 未运行, 本次放行:", url);
}

/* guard 又能连上了: 清掉"未运行"提示 */
function guardUp() {
    const was = guardDown.count;
    guardDown.count = 0;
    guardDown.since = 0;
    guardDown.sample = "";
    setTitle("eyilianjie 拦截守卫");
    if (was) { log("guard 已恢复（此前有 " + was + " 个请求因它没运行而放行）"); }
}

function guardDownInfo() {
    return { count: guardDown.count, since: guardDown.since, sample: guardDown.sample };
}

async function fetchJson(url, timeoutMs) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs || 2500);
    try {
        const resp = await fetch(url, { cache: "no-store", signal: controller.signal });
        if (!resp.ok) { throw new Error("HTTP " + resp.status); }
        return await resp.json();
    } finally {
        clearTimeout(timer);
    }
}

/* 探测一个后端是否可用。
   按"能力"探测而不是按端口: Web 端(5000) 一定有 /guard/state; guard 控制台(8899)
   新版也有, 老版只有 /guard/status —— 所以留一条回退, 兼容没升级的 guard。
   （以前只认 /guard/state → 老版 8899 探测不到 → 扩展等于"没装", 静默不拦。） */
async function probe(base) {
    for (const path of ["/guard/state?logs=1", "/guard/status"]) {
        try {
            const data = await fetchJson(base + path, 1500);
            if (data && data.available !== false) { return data; }
            lastTried.push(base + path + " (available=false)");
        } catch (err) {
            lastTried.push(base + path + " (" + err.message + ")");
        }
    }
    return null;
}

/* 探测 guard 控制台在哪个端口（8899 = run_guarded 自带; 5000 = Web 端） */
async function detectApi(force) {
    const now = Date.now();
    if (!force && apiBase && now - apiCheckedAt < API_TTL_MS) { return apiBase; }
    lastTried = [];
    for (const item of CANDIDATE_APIS) {
        const state = await probe(item.base);
        if (!state) { continue; }
        apiBase = item.base;
        apiKind = item.kind;
        apiCheckedAt = now;
        setBadge(state.enabled ? "ON" : "OFF", state.enabled ? "#198754" : "#6c757d");
        guardUp();
        log("guard API =", item.base, "(" + item.kind + ") enabled =", state.enabled);
        return apiBase;
    }
    apiBase = null;
    apiKind = "";
    apiCheckedAt = now;
    setBadge("OFF", "#dc3545");
    setTitle(GUARD_DOWN_TITLE);
    log("找不到 guard 接口:", lastTried.join(" / "));
    return null;
}

/* 「会被放行」的结论只信 5 秒、「会被拦截」的信 60 秒 ——
   因为放行名单 / 拦截名单随时可能在页面上被改动。 */
function ttlFor(decision) {
    return (decision && decision.blocked) ? DECISION_TTL_MS : ALLOW_TTL_MS;
}

/* 比对 guard 侧的"名单版本号"：一变就丢掉本地判定缓存。
   于是"在页面上刚点完【加入拦截】"→ 浏览器下一次访问立刻被拦,
   不用等 60 秒缓存过期, 也不需要去别的页面再输一遍。
   请求极轻（只回两个文件的指纹），所以每次都发也不心疼。 */
async function syncRulesVersion(base) {
    try {
        const data = await fetchJson(base + "/guard/rules_version", 1500);
        const version = (data && data.rules_version) || "";
        if (!version) { return; }
        if (rulesVersion !== null && version !== rulesVersion) {
            decisionCache.clear();
            rulesVersionHits += 1;
            log("名单已变更 → 已清空判定缓存:", version);
        }
        rulesVersion = version;
    } catch (err) {
        /* 拿不到就算了: 不影响上网, 仍由上面 5 秒 / 60 秒的 TTL 兜底 */
    }
}

async function checkUrl(url) {
    const base = await detectApi(false);
    if (!base) {
        noteGuardDown(url);
        return { blocked: false, source: "guard_down",
                 reason: "guard 未运行（127.0.0.1:8899 / 5000 都不可达）—— 本次已放行。" +
                         "启动方式: python web_app.py 或 python -m guard run" };
    }
    guardUp();
    await syncRulesVersion(base);                 // ← 先同步名单版本（变了就清缓存）
    const hit = decisionCache.get(url);
    if (hit && Date.now() - hit.at < ttlFor(hit.decision)) { return hit.decision; }
    try {
        const data = await fetchJson(base + "/guard/check?url=" + encodeURIComponent(url) + "&mode=url", 3000);
        const decision = (data && data.decision) || { blocked: false, reason: (data && data.reason) || "" };
        decisionCache.set(url, { at: Date.now(), decision: decision });
        return decision;
    } catch (err) {
        log("check 失败:", err.message);
        return { blocked: false, source: "error", reason: "检查失败（已放行）: " + err.message };
    }
}

function toBase64(text) {
    const bytes = new TextEncoder().encode(text);
    let binary = "";
    bytes.forEach((b) => { binary += String.fromCharCode(b); });
    return btoa(binary);
}

function blockPageUrl(target, decision) {
    return chrome.runtime.getURL("blocked.html") +
        "?u=" + encodeURIComponent(target) +
        "&d=" + encodeURIComponent(toBase64(JSON.stringify(decision || {})));
}

/* ---------------- 主文档导航前检查 ---------------- */
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    if (!details || details.frameId !== 0) { return; }          // 只看主文档
    const url = details.url || "";
    if (!/^https?:/i.test(url)) { return; }                     // 只管 http/https
    if (url.indexOf(chrome.runtime.getURL("")) === 0) { return; } // 我们自己("拦截页/弹窗/自检")
    const until = allowOnce.get(url);
    if (until && until > Date.now()) { return; }                // 用户这次选择"仍然访问"
    checkUrl(url).then((decision) => {
        if (!decision || (!decision.blocked && !decision.warn)) { return; }
        log(decision.blocked ? "拦截:" : "警告:", url, "|", decision.source);
        chrome.tabs.update(details.tabId, { url: blockPageUrl(url, decision) }, () => {
            void chrome.runtime.lastError;
        });
    }).catch((err) => log("处理失败:", err.message));
});

/* ---------------- 与拦截页/弹窗通信 ---------------- */
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (!msg || typeof msg !== "object") { return; }
    if (msg.type === "api_base") {
        detectApi(true).then((base) => sendResponse({ ok: !!base, base: base,
                                                     kind: apiKind, tried: lastTried,
                                                     guardDown: guardDownInfo() }));
        return true;
    }
    if (msg.type === "allow_once" && msg.url) {
        allowOnce.set(msg.url, Date.now() + ALLOW_ONCE_TTL_MS);
        sendResponse({ ok: true });
        return true;
    }
    if (msg.type === "forget_url" && msg.url) {
        /* 只丢"这一条 URL"的判定缓存。
           注意不能用 clear_cache: 它会把 allow_once 一起清掉, 用户点完放行反而又被拦。 */
        const dropped = decisionCache.delete(msg.url);
        sendResponse({ ok: true, dropped: dropped });
        return true;
    }
    if (msg.type === "clear_cache") {
        decisionCache.clear();
        allowOnce.clear();
        sendResponse({ ok: true, message: "缓存已清空" });
        return true;
    }
    if (msg.type === "status") {
        detectApi(true).then((base) => sendResponse({
            ok: !!base, base: base, kind: apiKind, tried: lastTried,
            guardDown: guardDownInfo(),
            rules_version: rulesVersion, rules_reloads: rulesVersionHits,
            version: chrome.runtime.getManifest().version,
            cached: decisionCache.size
        }));
        return true;
    }
    return undefined;
});

chrome.runtime.onInstalled.addListener(() => { detectApi(true); });
void detectApi(true);
