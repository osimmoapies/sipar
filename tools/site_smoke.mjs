// Checks a built playground site before it is published: loads the site's own Python runtime (Pyodide)
// under Node, puts the bundled Sipar package inside the way playground/worker.js does, and runs every
// scenario as shipped. A challenge must come out "held"; a lesson must run to the end.
//
//     node tools/site_smoke.mjs _site
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const site = resolve(process.argv[2] || "_site");
const text = (name) => readFileSync(resolve(site, name), "utf8");

const { loadPyodide } = await import(pathToFileURL(resolve(site, "pyodide", "pyodide.mjs")).href);
const pyodide = await loadPyodide({ indexURL: resolve(site, "pyodide") + "/" });

const root = "/lib/sipar_pkg/";
for (const [path, source] of Object.entries(JSON.parse(text("sipar_bundle.json")))) {
    const full = root + path;
    pyodide.FS.mkdirTree(full.slice(0, full.lastIndexOf("/")));
    pyodide.FS.writeFile(full, source);
}
pyodide.FS.writeFile(root + "glue.py", text("glue.py"));
pyodide.runPython(`import sys\nsys.path.insert(0, ${JSON.stringify(root)})\nimport glue, sipar`);
const runJson = pyodide.runPython("glue.run_json");

const build = JSON.parse(text("build.json"));
const sipar = pyodide.runPython("sipar.__version__");
console.log(`Sipar ${sipar} on Python ${pyodide.runPython("sys.version.split()[0]")} (Pyodide ${pyodide.version})`);

let bad = sipar === build.sipar && pyodide.version === build.pyodide ? 0 : 1;
if (bad) console.log(`FAIL  build.json says Sipar ${build.sipar}, Pyodide ${build.pyodide}`);

const scenarios = JSON.parse(text("scenarios.json"));
if (!scenarios.length) bad += 1;
for (const scenario of scenarios) {
    const r = JSON.parse(runJson(JSON.stringify({ scenario, edits: {} })));
    const ok = scenario.kind === "challenge" ? r.verdict.state === "held" : r.rc === 0 && r.verdict.state === "none";
    if (!ok) bad += 1;
    console.log(`${ok ? "ok  " : "FAIL"}  ${scenario.id}: ${scenario.kind}, exit ${r.rc}, verdict ${r.verdict.state}`);
    if (!ok) console.log(JSON.stringify(r, null, 2));
}
if (bad) {
    console.log(`${bad} of the checks failed: the site must not be published`);
    process.exit(1);
}
console.log(`all ${scenarios.length} scenarios behave as shipped`);
