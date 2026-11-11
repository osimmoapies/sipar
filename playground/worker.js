// The playground's worker: CPython (Pyodide) with the unchanged Sipar package inside.
// The page sends {type: "run", id, scenario, edits}; the answer is what glue.py returns.
import { loadPyodide } from "./pyodide/pyodide.mjs";

let runJson = null;

function say(text) {
    self.postMessage({ type: "status", text });
}

async function get(url, as) {
    const r = await fetch(url);
    if (!r.ok) throw new Error(`${url}: HTTP ${r.status}`);
    return as === "json" ? r.json() : r.text();
}

async function boot() {
    say("Loading Python");
    const pyodide = await loadPyodide({ indexURL: new URL("./pyodide/", self.location.href).href });
    say("Loading the Sipar interpreter");
    const [bundle, glue] = await Promise.all([get("sipar_bundle.json", "json"), get("glue.py", "text")]);
    const root = "/lib/sipar_pkg/";
    for (const [path, source] of Object.entries(bundle)) {
        const full = root + path;
        pyodide.FS.mkdirTree(full.slice(0, full.lastIndexOf("/")));
        pyodide.FS.writeFile(full, source);
    }
    pyodide.FS.writeFile(root + "glue.py", glue);
    pyodide.runPython(`import sys\nsys.path.insert(0, ${JSON.stringify(root)})\nimport glue, sipar`);
    runJson = pyodide.runPython("glue.run_json");
    self.postMessage({
        type: "ready",
        sipar: pyodide.runPython("sipar.__version__"),
        python: pyodide.runPython("sys.version.split()[0]"),
    });
}

const ready = boot();
ready.catch((err) => self.postMessage({ type: "fatal", text: String((err && err.message) || err) }));

self.onmessage = async (e) => {
    const m = e.data;
    if (!m || m.type !== "run") return;
    try {
        await ready;
        const out = runJson(JSON.stringify({ scenario: m.scenario, edits: m.edits }));
        self.postMessage({ type: "result", id: m.id, result: JSON.parse(out) });
    } catch (err) {
        self.postMessage({ type: "error", id: m.id, text: String((err && err.message) || err) });
    }
};
