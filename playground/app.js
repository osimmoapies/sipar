// Sipar playground: the page. The interpreter lives in worker.js; this file is the editor and the report.
// Everything a visitor or a shared link brings in goes to the page as text (.value / textContent), never as HTML.
const $ = (id) => document.getElementById(id);

const KEYWORDS = new Set(("agent ai allow and as assert break budget catch continue else enum false fn for if in let " +
    "match mock none not or return test tools true try type uses var while").split(" "));
const RUN_TIMEOUT_MS = 15000;
const MAX_EDIT = 200000;        // one edited file, the same limit as glue.py
const MAX_LINK = 16000;         // characters of edits a shared link may carry
const MAX_HIGHLIGHT = 60000;    // longer files are shown without colours
const OWN_LINK = /https:\/\/github\.com\/osimmoapies\/sipar(?:\/[\w\-./]*[\w/])?/g;

const state = {
    scenarios: [], byId: new Map(), sid: null, file: null,
    edits: {},                  // scenario id -> {file name: text}, only the files that differ
    worker: null, ready: false, queued: false, reveal: false, runId: 0, timer: 0, hashTimer: 0,
    overlay: false, build: null, versions: null, dead: false,
};

function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
}

function setStatus(text, busy = false) {
    const s = $("status");
    s.textContent = text;
    s.classList.toggle("busy", busy);
}

// ---- highlighting: [class, text] pairs whose texts joined give the source back, character for character

function sipar(src) {
    const out = [];
    const n = src.length;
    let i = 0, plain = i;
    const flush = (to) => { if (to > plain) out.push(["", src.slice(plain, to)]); };
    const take = (cls, to) => { flush(i); out.push([cls, src.slice(i, to)]); i = plain = to; };
    const word = /[A-Za-z_]\w*/y, num = /\d[\d_]*(?:\.\d[\d_]*)?/y, deco = /@[A-Za-z_]\w*/y;
    while (i < n) {
        const c = src[i];
        if (c === "/" && src[i + 1] === "/") {
            const j = src.indexOf("\n", i);
            take("com", j < 0 ? n : j);
        } else if (c === '"') {
            const triple = src.startsWith('"""', i);
            flush(i);
            i = plain = string(src, i, triple, out);
        } else if (c === "@" && (deco.lastIndex = i, deco.test(src))) {
            take("dec", deco.lastIndex);
        } else if (c >= "0" && c <= "9") {
            num.lastIndex = i;
            num.test(src);
            take("num", num.lastIndex);
        } else if ((word.lastIndex = i, word.test(src))) {
            const w = src.slice(i, word.lastIndex);
            if (KEYWORDS.has(w)) take("kw", word.lastIndex);
            else if (w[0] >= "A" && w[0] <= "Z") take("ty", word.lastIndex);
            else i = word.lastIndex;
        } else {
            i += 1;
        }
    }
    flush(n);
    return out;
}

function string(src, start, triple, out) {
    // one string literal from `start`; {…} inside it is an interpolation. Returns the index after it.
    const n = src.length, quote = triple ? '"""' : '"';
    let i = start + quote.length, from = start;
    const emit = (cls, to) => { if (to > from) out.push([cls, src.slice(from, to)]); from = to; };
    while (i < n) {
        const c = src[i];
        if (c === "\\") {
            i += 2;
        } else if (src.startsWith(quote, i)) {
            i += quote.length;
            emit("str", i);
            return i;
        } else if (c === "\n" && !triple) {
            break;                                          // not closed on its line
        } else if (c === "{") {
            emit("str", i);
            let depth = 0;
            while (i < n && !(src[i] === "\n" && !triple)) {
                if (src[i] === "{") depth += 1;
                else if (src[i] === "}" && --depth === 0) { i += 1; break; }
                i += 1;
            }
            emit("ip", i);
        } else {
            i += 1;
        }
    }
    i = Math.min(i, n);
    emit("str", i);
    return i;
}

function json(src) {
    const out = [];
    const re = /"(?:[^"\\\n]|\\.)*"?|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|\b(?:true|false|null)\b/g;
    let last = 0, m;
    while ((m = re.exec(src)) !== null) {
        if (m[0] === "") { re.lastIndex += 1; continue; }
        if (m.index > last) out.push(["", src.slice(last, m.index)]);
        let cls = "num";
        if (m[0][0] === '"') cls = /^\s*:/.test(src.slice(re.lastIndex, re.lastIndex + 40)) ? "key" : "str";
        else if (/[a-z]/.test(m[0][0])) cls = "kw";
        out.push([cls, m[0]]);
        last = re.lastIndex;
    }
    if (last < src.length) out.push(["", src.slice(last)]);
    return out;
}

function highlighter(name) {
    if (name.endsWith(".sipar")) return sipar;
    if (name.endsWith(".json")) return json;
    return null;
}

function paint() {
    const text = $("code").value;
    const fn = state.overlay && text.length <= MAX_HIGHLIGHT ? highlighter(state.file || "") : null;
    $("editor").classList.toggle("plain", !fn);
    if (!fn) { $("hlcode").replaceChildren(); return; }
    const frag = document.createDocumentFragment();
    for (const [cls, part] of fn(text)) frag.append(cls ? el("span", "t-" + cls, part) : part);
    frag.append("\n");                                      // a pre drops one final line break, a textarea shows it
    $("hlcode").replaceChildren(frag);
    follow();
}

function follow() {
    const ta = $("code");
    $("hlcode").style.transform = `translate(${-ta.scrollLeft}px, ${-ta.scrollTop}px)`;
}

function overlayWorks() {
    // The colours are a layer under a see-through textarea. That is only right when both lay the same text out
    // the same way, to the pixel. Measure it here, in this browser; if it is off, show the plain textarea.
    const ta = $("code"), code = $("hlcode");
    const sample = Array.from({ length: 40 }, (_, k) => "x".repeat(k % 2 ? 400 : 7) + "\tй{}").join("\n");
    ta.value = sample;
    code.replaceChildren(sample + "\n");
    const cs = getComputedStyle(ta);
    const box = code.getBoundingClientRect();
    const high = box.height + parseFloat(cs.paddingTop) + parseFloat(cs.paddingBottom);
    // browsers differ on one point only: whether the padding after the longest line counts as scrollable width
    const over = ta.scrollWidth - box.width - parseFloat(cs.paddingLeft);
    const ok = box.height > 0 && Math.abs(ta.scrollHeight - high) <= 1.5 &&
        (Math.abs(over) <= 1.5 || Math.abs(over - parseFloat(cs.paddingRight)) <= 1.5);
    ta.value = "";
    code.replaceChildren();
    return ok;
}

// ---- state

const scenario = () => state.byId.get(state.sid);
const fileOf = (sc, name) => sc.files.find((f) => f.name === name);
const editsOf = (sid) => state.edits[sid] || {};

function textOf(sid, name) {
    const e = editsOf(sid);
    return Object.hasOwn(e, name) ? e[name] : fileOf(state.byId.get(sid), name).text;
}

function firstFile(sc) {
    const open = sc.files.filter((f) => !f.locked);
    return (open.find((f) => f.role === "attacker") || open[0] || sc.files[0]).name;
}

function encode(obj) {
    let s = "";
    for (const b of new TextEncoder().encode(JSON.stringify(obj))) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function decode(str) {
    const bin = atob(str.replace(/-/g, "+").replace(/_/g, "/"));
    const bytes = Uint8Array.from(bin, (ch) => ch.charCodeAt(0));
    return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
}

function hashFor(withEdits = true) {
    const sc = scenario();
    const p = new URLSearchParams();
    p.set("s", state.sid);
    if (state.file !== firstFile(sc)) p.set("f", state.file);
    const e = editsOf(state.sid);
    if (withEdits && Object.keys(e).length) p.set("e", encode(e));
    return p.toString();
}

function putHash() {
    const sc = scenario();
    const plain = state.sid === state.scenarios[0].id && state.file === firstFile(sc) &&
        !Object.keys(editsOf(state.sid)).length;
    let h = plain ? "" : hashFor();
    if (h.length > MAX_LINK) h = hashFor(false);        // too long for an address: keep the place, not the text
    try {
        history.replaceState(null, "", location.pathname + location.search + (h ? "#" + h : ""));
    } catch { /* a browser that refuses: the page works without the address */ }
}

function writeHash(typing = false) {
    // while typing the address waits for a pause; a click on a tab changes it at once
    clearTimeout(state.hashTimer);
    if (typing) state.hashTimer = setTimeout(putHash, 250);
    else putHash();
}

function readHash() {
    // A link is somebody else's input. Take a known scenario, a file it has, and text for its open files only.
    const p = new URLSearchParams(location.hash.slice(1));
    const out = { sid: null, file: null, edits: null };
    const sid = p.get("s");
    if (!sid || !state.byId.has(sid)) return out;
    out.sid = sid;
    const sc = state.byId.get(sid);
    const f = p.get("f");
    if (f && fileOf(sc, f)) out.file = f;
    const e = p.get("e");
    if (e && e.length <= MAX_LINK) {
        try {
            const obj = decode(e);
            if (obj && typeof obj === "object" && !Array.isArray(obj)) {
                out.edits = {};
                for (const file of sc.files) {
                    const v = Object.hasOwn(obj, file.name) ? obj[file.name] : null;
                    if (typeof v === "string" && !file.locked && v.length <= MAX_EDIT && v !== file.text) {
                        out.edits[file.name] = v;
                    }
                }
            }
        } catch { /* a damaged link opens the scenario as it is */ }
    }
    return out;
}

// ---- drawing

function drawTabs(box, items, current, pick) {
    const had = box.contains(document.activeElement);
    box.replaceChildren();
    for (const it of items) {
        const b = el("button");
        b.type = "button";
        b.setAttribute("role", "tab");
        b.setAttribute("aria-selected", it.id === current ? "true" : "false");
        b.tabIndex = it.id === current ? 0 : -1;
        b.dataset.id = it.id;
        b.append(...it.label);
        b.addEventListener("click", () => pick(it.id));
        box.append(b);
    }
    if (had) box.querySelector('[aria-selected="true"]')?.focus();
}

function arrows(box, pick) {
    box.addEventListener("keydown", (e) => {
        const tabs = [...box.querySelectorAll('[role="tab"]')];
        const at = tabs.indexOf(document.activeElement);
        if (at < 0) return;
        let to = -1;
        if (e.key === "ArrowRight" || e.key === "ArrowDown") to = (at + 1) % tabs.length;
        else if (e.key === "ArrowLeft" || e.key === "ArrowUp") to = (at - 1 + tabs.length) % tabs.length;
        else if (e.key === "Home") to = 0;
        else if (e.key === "End") to = tabs.length - 1;
        if (to < 0) return;
        e.preventDefault();
        tabs[to].focus();
        pick(tabs[to].dataset.id);
    });
}

function drawScenarios() {
    drawTabs($("scenarios"), state.scenarios.map((s) => ({ id: s.id, label: [s.tab || s.title] })), state.sid,
        (id) => { if (id !== state.sid) open(id); });
}

function drawFiles() {
    const sc = scenario();
    const e = editsOf(state.sid);
    drawTabs($("filetabs"), sc.files.map((f) => {
        const edited = Object.hasOwn(e, f.name);
        const tag = el("span", edited ? "tag edited" : "tag", f.locked ? "fixed" : edited ? "edited" : "edit");
        return { id: f.name, label: [f.name, tag] };
    }), state.file, (name) => { if (name !== state.file) showFile(name); });
    $("reset").disabled = !Object.keys(e).length;
}

function describe(sc, f) {
    if (f.role === "attacker") {
        return sc.kind === "challenge" ? "The hijacked model: you write what it says, step by step."
            : "The model's replies. There is no real model here: edit them.";
    }
    if (f.role === "program") {
        return f.locked ? "The program. It is fixed: the attack has to work against this code."
            : "The program. Edit it.";
    }
    return f.locked ? "Data the program reads. It is fixed." : "Data the program reads. Edit it.";
}

function showFile(name) {
    const sc = scenario();
    const f = fileOf(sc, name);
    const ta = $("code");
    state.file = name;
    ta.value = textOf(state.sid, name);
    ta.readOnly = Boolean(f.locked);
    ta.setAttribute("aria-label", `${name}${f.locked ? " (read only)" : ""}`);
    ta.scrollTop = 0;
    ta.scrollLeft = 0;
    $("filemeta").textContent = describe(sc, f);
    drawFiles();
    paint();
    writeHash();
}

function showScenario() {
    const sc = scenario();
    document.title = `${sc.title} · Sipar playground`;
    $("kind").textContent = sc.kind === "challenge" ? "Challenge" : "Lesson";
    $("title").textContent = sc.title;
    $("goal").replaceChildren(...rich(sc.goal || ""));
    $("notes").replaceChildren(...(sc.notes || []).map((t) => {
        const li = el("li");
        li.append(...rich(t));
        return li;
    }));
    drawScenarios();
}

function open(sid, file = null, andRun = true) {
    state.sid = sid;
    showScenario();
    showFile(file && fileOf(scenario(), file) ? file : firstFile(scenario()));
    blank("Running");
    if (andRun) run();
}

function linked(text) {
    // plain text, except links to this project's own pages
    const out = [];
    let last = 0;
    for (const m of text.matchAll(OWN_LINK)) {
        if (m.index > last) out.push(text.slice(last, m.index));
        const a = el("a", "", m[0]);
        a.href = m[0];
        a.rel = "noopener";
        out.push(a);
        last = m.index + m[0].length;
    }
    if (last < text.length) out.push(text.slice(last));
    return out;
}

function rich(text) {
    // plain text, except `code` and links to this project's own pages
    const parts = text.split("`");
    if (parts.length % 2 === 0) return linked(text);        // an odd backtick: leave the text as it is
    return parts.flatMap((part, i) => (i % 2 ? [el("code", "", part)] : linked(part)));
}

function showVerdict(v) {
    const box = $("verdict");
    box.hidden = !(v && v.title);
    box.className = "verdict" + (v && ["held", "broken", "limit"].includes(v.state) ? " " + v.state : "");
    $("verdict-title").textContent = v ? v.title : "";
    $("verdict-text").replaceChildren(...rich(v ? v.text || "" : ""));
}

function eventCard(ev) {
    const card = el("div", "event");
    let what, body;
    if (ev.kind === "shell") {
        what = "Command: recorded, not started";
        body = JSON.stringify(ev.cmd);
    } else if (ev.kind === "http") {
        what = "HTTP request: recorded, a canned answer came back";
        const head = Object.entries(ev.headers || {}).map(([k, v]) => `${k}: ${v}`);
        body = [`${ev.method} ${ev.url}`, ...head].join("\n") + (ev.body ? "\n\n" + ev.body : "");
    } else {
        what = `File written: ${ev.path} (${ev.bytes} ${ev.bytes === 1 ? "byte" : "bytes"})`;
        body = ev.text;
    }
    card.append(el("p", "what", what), el("pre", "", body));
    return card;
}

function blank(why) {
    $("result").classList.add("stale");
    setStatus(why, why === "Running");
}

function reveal() {
    // on a narrow screen the result sits under the editor: after a run the visitor asked for, bring it into view
    if (!state.reveal) return;
    state.reveal = false;
    if ($("result").getBoundingClientRect().top < innerHeight * 0.6) return;
    const calm = matchMedia("(prefers-reduced-motion: reduce)").matches;
    $("result").scrollIntoView({ block: "start", behavior: calm ? "auto" : "smooth" });
}

function show(r) {
    $("result").classList.remove("stale");
    showVerdict(r.verdict);
    $("out").textContent = r.stdout || "(no output)";
    $("err").textContent = r.stderr || "";
    $("err").hidden = !r.stderr;
    $("runmeta").textContent = `exit ${r.rc} · ${r.ms} ms`;
    const events = r.events || [];
    $("events").replaceChildren(...(events.length ? events.map(eventCard)
        : [el("p", "none", "Nothing: no command, no request, no file.")]));
    $("journal").textContent = r.journal || "(empty)";
    setStatus(r.verdict && r.verdict.state === "none" && r.verdict.title ? r.verdict.title : "Done");
    reveal();
}

function showStopped(title, text) {
    $("result").classList.remove("stale");
    showVerdict({ state: "none", title, text });
    $("out").textContent = "(no output)";
    $("err").hidden = true;
    $("runmeta").textContent = "";
    $("events").replaceChildren(el("p", "none", "Nothing was recorded."));
    $("journal").textContent = "(empty)";
    setStatus(title);
    reveal();
}

function drawBuild() {
    const b = state.build || {}, v = state.versions || {};
    const parts = [];
    if (v.sipar || b.sipar) parts.push(`Sipar ${v.sipar || b.sipar}`);
    if (b.commit) parts.push(`commit ${b.commit.slice(0, 7)}`);
    if (b.pyodide) parts.push(`Pyodide ${b.pyodide}`);
    if (v.python) parts.push(`Python ${v.python}`);
    $("build").textContent = parts.join(" · ");
}

// ---- the interpreter

function fatal(text) {
    state.dead = true;
    state.ready = false;
    clearTimeout(state.timer);
    $("run").disabled = true;
    showStopped("The interpreter did not start", text + " Reload the page to try again.");
}

function startWorker() {
    state.ready = false;
    let w;
    try {
        w = new Worker("worker.js", { type: "module" });
    } catch {
        fatal("This browser cannot start it: module workers and WebAssembly are needed.");
        return;
    }
    state.worker = w;
    w.onmessage = (e) => { if (state.worker === w) onWorker(e.data || {}); };
    w.onerror = (e) => {
        if (state.worker !== w) return;
        e.preventDefault?.();
        fatal(e.message ? `Loading failed: ${e.message}.` : "Loading failed.");
    };
}

function onWorker(m) {
    if (m.type === "status") {
        if (!state.ready) setStatus(m.text, true);
    } else if (m.type === "ready") {
        state.ready = true;
        state.versions = { sipar: m.sipar, python: m.python };
        drawBuild();
        if (state.queued) { state.queued = false; run(state.reveal); } else setStatus("Ready");
    } else if (m.type === "fatal") {
        fatal(`Loading failed: ${m.text}.`);
    } else if (m.id === state.runId && (m.type === "result" || m.type === "error")) {
        clearTimeout(state.timer);
        if (m.type === "result") show(m.result);
        else showStopped("The playground failed", `${m.text}. This is a bug in the page, not in your program.`);
    }
}

function run(asked = false) {
    if (state.dead || !state.sid) return;
    state.reveal = asked === true;
    if (!state.ready) { state.queued = true; return; }
    const id = ++state.runId;
    blank("Running");
    clearTimeout(state.timer);
    state.timer = setTimeout(() => {
        if (id !== state.runId) return;
        state.runId += 1;                                   // whatever that run still says is ignored
        state.worker.terminate();
        showStopped("Stopped", `The program ran for more than ${RUN_TIMEOUT_MS / 1000} seconds (an endless loop?). ` +
            "The interpreter is starting again.");
        startWorker();
    }, RUN_TIMEOUT_MS);
    state.worker.postMessage({ type: "run", id, scenario: scenario(), edits: editsOf(state.sid) });
}

// ---- the visitor

function onInput() {
    const sc = scenario(), f = fileOf(sc, state.file), ta = $("code");
    if (f.locked) return;
    const was = Object.hasOwn(editsOf(state.sid), f.name);
    const text = ta.value.length > MAX_EDIT ? ta.value.slice(0, MAX_EDIT) : ta.value;
    if (text === f.text) {
        if (state.edits[state.sid]) delete state.edits[state.sid][f.name];
    } else {
        (state.edits[state.sid] ||= {})[f.name] = text;
    }
    if (was !== (text !== f.text)) drawFiles();
    paint();
    blank("Edited. Press Run.");
    writeHash(true);
}

function reset() {
    delete state.edits[state.sid];
    showFile(state.file);
    run(true);
}

async function share() {
    let h = hashFor();
    const tooLong = h.length > MAX_LINK;
    if (tooLong) h = hashFor(false);
    const url = location.origin + location.pathname + "#" + h;
    let ok = false;
    try {
        await navigator.clipboard.writeText(url);
        ok = true;
    } catch {
        const t = el("textarea");
        t.value = url;
        t.setAttribute("readonly", "");
        t.className = "offscreen";
        document.body.append(t);
        t.select();
        try { ok = document.execCommand("copy"); } catch { ok = false; }
        t.remove();
    }
    setStatus(!ok ? "Could not copy: take the link from the address bar."
        : tooLong ? "Link copied, without your edits: they are too long for a link."
            : "Link copied. It opens this scenario with your edits.");
}

function insert(text) {
    const ta = $("code");
    if (!document.execCommand("insertText", false, text)) {
        ta.setRangeText(text, ta.selectionStart, ta.selectionEnd, "end");
        ta.dispatchEvent(new Event("input", { bubbles: true }));
    }
}

function wire() {
    const ta = $("code");
    let tabLeaves = false;                                  // Esc, then Tab: leave the editor with the keyboard
    ta.addEventListener("input", onInput);
    ta.addEventListener("scroll", follow, { passive: true });
    ta.addEventListener("blur", () => { tabLeaves = false; });
    ta.addEventListener("keydown", (e) => {
        if (e.key === "Escape") { tabLeaves = true; return; }
        if (e.key === "Tab" && !e.shiftKey && !e.ctrlKey && !e.metaKey && !e.altKey && !ta.readOnly && !tabLeaves) {
            e.preventDefault();
            insert("    ");
        }
        if (e.key !== "Tab" && e.key !== "Shift") tabLeaves = false;
    });
    document.addEventListener("keydown", (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === "Enter") { e.preventDefault(); run(true); }
    });
    $("run").addEventListener("click", () => run(true));
    $("reset").addEventListener("click", reset);
    $("share").addEventListener("click", share);
    arrows($("scenarios"), (id) => { if (id !== state.sid) open(id); });
    arrows($("filetabs"), (name) => { if (name !== state.file) showFile(name); });
    window.addEventListener("hashchange", () => fromHash(true));
    if (/Mac|iPhone|iPad/.test(navigator.platform || navigator.userAgent || "")) $("runkey").textContent = "⌘ Enter";
}

function fromHash(changed = false) {
    const h = readHash();
    const sid = h.sid || (changed ? state.sid : state.scenarios[0].id);
    if (h.edits) state.edits[sid] = h.edits;
    open(sid, h.file);
}

async function load(name) {
    const r = await fetch(name);
    if (!r.ok) throw new Error(`${name}: HTTP ${r.status}`);
    return r.json();
}

async function main() {
    wire();
    startWorker();                                          // Python downloads while the page gets its data
    try {
        const [scenarios, build] = await Promise.all([load("scenarios.json"), load("build.json").catch(() => null)]);
        state.scenarios = scenarios;
        state.byId = new Map(scenarios.map((s) => [s.id, s]));
        state.build = build;
    } catch (err) {
        $("title").textContent = "The playground did not load";
        $("goal").textContent = `${(err && err.message) || err}. Reload the page to try again.`;
        setStatus("Not loaded");
        $("run").disabled = true;
        return;
    }
    state.overlay = overlayWorks();
    drawBuild();
    fromHash();
}

main();
