// Load docs/index.html in a real browser and measure it. No dependencies: the check
// drives headless Chrome over the DevTools protocol using node's built-in WebSocket.
//
// Why not just assert the file exists and the unit tests pass. Because a page's entire
// script can fail to parse while every unit test passes, and the page then renders as
// static HTML with no numbers in it. So the probe below runs INSIDE the page, is written
// here rather than in the page (a page that grades itself proves nothing about the page),
// and asserts on values only a running script could have produced.
//
//   node scripts/browser_check.mjs <html-path> <width> <height>
//
// Exit 0 and print JSON on success. Exit nonzero with a reason otherwise.

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir, homedir } from "node:os";
import path from "node:path";
import process from "node:process";

const [, , htmlPath, widthArg, heightArg] = process.argv;
if (!htmlPath) {
  console.error("usage: browser_check.mjs <html-path> [width] [height]");
  process.exit(2);
}
const width = Number(widthArg || 390);
const height = Number(heightArg || 844);

const CANDIDATES = [
  process.env.SESSION_SEARCH_CHROME,
  path.join(homedir(), ".cache/ms-playwright/chromium_headless_shell-1208/"
    + "chrome-headless-shell-linux64/chrome-headless-shell"),
  "/usr/bin/google-chrome",
  "/usr/bin/chromium",
  "/usr/bin/chromium-browser",
  "/snap/bin/chromium",
].filter(Boolean);

function findChrome() {
  for (const c of CANDIDATES) if (existsSync(c)) return c;
  const globbed = [];
  try {
    const base = path.join(homedir(), ".cache/ms-playwright");
    const { readdirSync } = require("node:fs");
    for (const d of readdirSync(base)) {
      if (!d.startsWith("chromium")) continue;
      for (const sub of ["chrome-headless-shell-linux64/chrome-headless-shell",
        "chrome-linux/chrome"]) {
        const p = path.join(base, d, sub);
        if (existsSync(p)) globbed.push(p);
      }
    }
  } catch { /* no playwright cache; the explicit candidates already failed */ }
  return globbed[0] || null;
}

const chrome = findChrome();
if (!chrome) {
  console.error(
    "no headless Chrome found, so the page was never loaded and this check cannot pass.\n"
    + "  Install one:   npx playwright install chromium\n"
    + "  Or point at one: SESSION_SEARCH_CHROME=/path/to/chrome\n"
    + "  Without it the suite still covers parsing, ranking, redaction and the leak\n"
    + "  audit, but nothing has executed the page's script.");
  process.exit(3);
}

const profile = await mkdtemp(path.join(tmpdir(), "session-search-chrome-"));
const proc = spawn(chrome, [
  "--headless", "--disable-gpu", "--no-sandbox", "--no-first-run",
  "--disable-dev-shm-usage", "--remote-debugging-port=0",
  `--user-data-dir=${profile}`, "about:blank",
], { stdio: ["ignore", "pipe", "pipe"] });

let stderr = "";
const wsUrl = await new Promise((resolve, reject) => {
  const timer = setTimeout(() => reject(new Error("browser did not report a debug port")),
    30000);
  proc.stderr.on("data", (chunk) => {
    stderr += chunk.toString();
    const m = stderr.match(/ws:\/\/[^\s]+/);
    if (m) { clearTimeout(timer); resolve(m[0]); }
  });
  proc.on("exit", (code) => {
    clearTimeout(timer);
    reject(new Error(`browser exited with ${code}: ${stderr.slice(0, 400)}`));
  });
});

// The endpoint printed on stderr is the browser-level one, which has no Runtime domain.
// The page target has to be looked up over the HTTP side of the protocol.
const port = new URL(wsUrl).port;
let pageWs = null;
for (let attempt = 0; attempt < 30 && !pageWs; attempt++) {
  try {
    const list = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
    const page = list.find((t) => t.type === "page" && t.webSocketDebuggerUrl);
    if (page) pageWs = page.webSocketDebuggerUrl;
  } catch { /* the browser is still coming up */ }
  if (!pageWs) await new Promise((r) => setTimeout(r, 100));
}
if (!pageWs) {
  proc.kill("SIGKILL");
  console.error("the browser started but exposed no page target to drive");
  process.exit(1);
}

const ws = new WebSocket(pageWs);
await new Promise((resolve, reject) => {
  ws.addEventListener("open", resolve, { once: true });
  ws.addEventListener("error", () => reject(new Error("cdp socket failed")), { once: true });
});

let nextId = 1;
const pending = new Map();
const consoleErrors = [];
ws.addEventListener("message", (ev) => {
  const msg = JSON.parse(ev.data);
  if (msg.id && pending.has(msg.id)) {
    const { resolve, reject } = pending.get(msg.id);
    pending.delete(msg.id);
    if (msg.error) reject(new Error(JSON.stringify(msg.error)));
    else resolve(msg.result);
    return;
  }
  if (msg.method === "Runtime.exceptionThrown") {
    consoleErrors.push("exception: "
      + (msg.params?.exceptionDetails?.exception?.description
        || msg.params?.exceptionDetails?.text || "unknown"));
  }
  if (msg.method === "Runtime.consoleAPICalled"
    && ["error", "warning", "assert"].includes(msg.params?.type)) {
    consoleErrors.push(msg.params.type + ": "
      + (msg.params.args || []).map((a) => a.value ?? a.description ?? "?").join(" "));
  }
  if (msg.method === "Log.entryAdded" && msg.params?.entry?.level === "error") {
    consoleErrors.push("log: " + msg.params.entry.text);
  }
});

function send(method, params = {}) {
  const id = nextId++;
  return new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
    ws.send(JSON.stringify({ id, method, params }));
  });
}

async function fail(reason) {
  try { ws.close(); } catch { /* already gone */ }
  proc.kill("SIGKILL");
  await rm(profile, { recursive: true, force: true });
  console.error(reason);
  process.exit(1);
}

await send("Runtime.enable");
await send("Log.enable");
await send("Page.enable");
await send("Emulation.setDeviceMetricsOverride",
  { width, height, deviceScaleFactor: 1, mobile: width < 500 });

const fileUrl = "file://" + path.resolve(htmlPath);
await send("Page.navigate", { url: fileUrl });
await new Promise((r) => setTimeout(r, 900));

// The probe. Everything it asserts is either page identity or a value that only the
// page's own script could have written.
const probeSource = `(() => {
  const out = {};
  out.title = document.title;
  out.selftest = (document.getElementById("selftest") || {}).textContent || "";
  out.hits = document.querySelectorAll("#results .hit").length;
  out.kindOptions = document.querySelectorAll("#kind option").length;
  out.scores = Array.from(document.querySelectorAll("#results .score"))
    .map((el) => Number(el.textContent));
  out.marks = document.querySelectorAll("#results mark").length;

  // Dark mode, both mechanisms. The stylesheet must contain a
  // prefers-color-scheme rule AND a :root[data-theme] rule, and setting the
  // attribute must actually change the rendered background.
  let css = "";
  for (const sheet of document.styleSheets) {
    try { for (const rule of sheet.cssRules) css += rule.cssText; } catch (e) { }
  }
  out.hasMediaDark = /prefers-color-scheme:\\s*dark/.test(css);
  out.hasAttrDark = /\\[data-theme=.?dark.?\\]/.test(css);
  const root = document.documentElement;
  const before = root.getAttribute("data-theme");
  const bg = (v) => {
    if (v === null) root.removeAttribute("data-theme");
    else root.setAttribute("data-theme", v);
    return getComputedStyle(document.body).backgroundColor;
  };
  out.bgLight = bg("light");
  out.bgDark = bg("dark");
  bg(before);

  // Overflow. Walk every element and compare its right edge against the viewport,
  // skipping anything inside a container that is allowed to scroll sideways, because
  // content scrolling inside its own box is correct and only content escaping the page
  // is not.
  const limit = document.documentElement.clientWidth;
  const scrollable = (el) => {
    for (let p = el.parentElement; p; p = p.parentElement) {
      const ox = getComputedStyle(p).overflowX;
      if (ox === "auto" || ox === "scroll") return true;
    }
    return false;
  };
  const offenders = [];
  for (const el of document.querySelectorAll("*")) {
    const r = el.getBoundingClientRect();
    if (r.width === 0 && r.height === 0) continue;
    if (r.right > limit + 0.5 && !scrollable(el)) {
      offenders.push(el.tagName.toLowerCase()
        + (el.id ? "#" + el.id : "")
        + (el.className && typeof el.className === "string"
          ? "." + el.className.trim().split(/\\s+/).join(".") : "")
        + " right=" + r.right.toFixed(1));
    }
  }
  out.viewport = limit;
  out.scrollWidth = document.documentElement.scrollWidth;
  out.bodyOverflowX = getComputedStyle(document.body).overflowX;
  out.offenders = offenders.slice(0, 6);

  // The demo must actually respond to input, not merely render once.
  const q = document.getElementById("query");
  const setValue = (v) => {
    q.value = v;
    q.dispatchEvent(new Event("input", { bubbles: true }));
    return document.querySelectorAll("#results .hit").length;
  };
  out.hitsForQuaternionInClaude = setValue("quaternion pelican");
  out.hitsForCrlf = setValue("crlf importer");
  return out;
})()`;

let probe;
try {
  const res = await send("Runtime.evaluate",
    { expression: probeSource, returnByValue: true, awaitPromise: false });
  if (res.exceptionDetails) {
    await fail("probe threw inside the page: "
      + JSON.stringify(res.exceptionDetails).slice(0, 500));
  }
  probe = res.result.value;
} catch (err) {
  await fail("could not evaluate in the page: " + err.message);
}

const problems = [];
// Page identity first. The browser is a shared resource on this machine and another
// agent can navigate it out from under a check, so every measurement is worthless
// unless this is the page it claims to be.
if (!/session-search/.test(probe.title || "")) {
  problems.push(`wrong page loaded: title is ${JSON.stringify(probe.title)}`);
}
if (!/^SELFTEST:OK/.test(probe.selftest)) {
  problems.push("the page's script never wrote its result, so it did not run: "
    + JSON.stringify(probe.selftest).slice(0, 120));
}
if (!probe.hits) problems.push("the demo rendered no results");
if (!probe.marks) problems.push("no query terms were highlighted, so rendering is partial");
if (probe.kindOptions < 5) {
  problems.push(`the kind filter has ${probe.kindOptions} options; the script builds it`);
}
if (!(probe.scores.length && probe.scores.every((n) => Number.isFinite(n)))) {
  problems.push("scores are not numbers: " + JSON.stringify(probe.scores));
}
if (probe.scores.some((n, i) => i && n > probe.scores[i - 1])) {
  problems.push("results are not in descending score order: " + JSON.stringify(probe.scores));
}
if (!probe.hasMediaDark) problems.push("no prefers-color-scheme dark rule");
if (!probe.hasAttrDark) problems.push("no :root[data-theme] dark rule");
if (probe.bgLight === probe.bgDark) {
  problems.push(`data-theme does not change the background: ${probe.bgLight}`);
}
if (probe.bodyOverflowX === "hidden") {
  problems.push("body has overflow-x: hidden, which hides the bug and makes the "
    + "measurement vacuous");
}
if (probe.offenders.length) {
  problems.push(`${probe.offenders.length} element(s) overflow the viewport: `
    + probe.offenders.join("; "));
}
if (probe.scrollWidth > probe.viewport + 0.5) {
  problems.push(`document scrollWidth ${probe.scrollWidth} exceeds viewport ${probe.viewport}`);
}
if (probe.hitsForQuaternionInClaude !== 0) {
  problems.push("a query with no possible match still returned results, so the demo is "
    + "not filtering");
}
if (probe.hitsForCrlf < 1) problems.push("typing a known query returned nothing");
if (consoleErrors.length) {
  problems.push(`${consoleErrors.length} console error(s): ` + consoleErrors.slice(0, 3).join(" | "));
}

try { ws.close(); } catch { /* already gone */ }
proc.kill("SIGKILL");
await rm(profile, { recursive: true, force: true });

if (problems.length) {
  console.error(`browser check FAILED at ${width}x${height}`);
  for (const p of problems) console.error("  - " + p);
  process.exit(1);
}
console.log(JSON.stringify({
  viewport: `${width}x${height}`,
  browser: path.basename(chrome),
  selftest: probe.selftest,
  hits: probe.hits,
  scores: probe.scores,
  scrollWidth: probe.scrollWidth,
  offenders: probe.offenders.length,
  consoleErrors: consoleErrors.length,
}));
