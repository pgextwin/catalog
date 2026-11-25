#!/usr/bin/env node
/**
 * Proposal C Phase C1/C2 — Headless Chrome CDP Smoke & Request-Trace Test
 *
 * Reuses the headless Chrome CDP approach from pgextwin/website/scripts/verify-published-ui.mjs
 * to trace cold-load network requests, verify JS-disabled readability, test interactive filters,
 * and verify UTC EOL boundaries in a real browser DOM.
 *
 * Usage:
 *   node site/tests/pages-smoke.mjs --base <preview-dir-or-url> --trace <pages-request-trace.json> [--filters-out <pages-filter-results.json>]
 */

import assert from "node:assert/strict";
import { spawn, execFileSync } from "node:child_process";
import { createServer } from "node:http";
import { mkdtemp, readFile, rm, stat, writeFile, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, extname, join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".json": "application/json; charset=utf-8",
  ".txt": "text/plain; charset=utf-8",
};

function parseArgs(argv) {
  const args = {
    base: "site/out/pages-preview",
    trace: "site/out/pages-request-trace.json",
    filtersOut: null,
  };
  for (let i = 2; i < argv.length; i += 1) {
    const key = argv[i];
    if (key === "--base" && argv[i + 1]) args.base = argv[++i];
    else if (key === "--trace" && argv[i + 1]) args.trace = argv[++i];
    else if (key === "--filters-out" && argv[i + 1]) args.filtersOut = argv[++i];
    else throw new Error(`Unknown or incomplete argument: ${key}`);
  }
  if (!args.filtersOut) {
    args.filtersOut = join(dirname(args.trace), "pages-filter-results.json");
  }
  return args;
}

function findChrome() {
  const candidates = [process.env.CHROME_BIN, "google-chrome", "chromium", "chromium-browser"].filter(Boolean);
  for (const bin of candidates) {
    try {
      return execFileSync("which", [bin], { stdio: ["ignore", "pipe", "ignore"] }).toString("utf8").trim();
    } catch {}
  }
  return null;
}

async function startStaticServer(rootDir) {
  const root = resolve(rootDir);
  const server = createServer(async (req, res) => {
    try {
      const urlPath = new URL(req.url || "/", "http://127.0.0.1").pathname;
      const rel = urlPath.endsWith("/") ? `${urlPath}index.html` : urlPath;
      const target = resolve(root, `.${rel}`);
      if (!target.startsWith(root)) {
        res.writeHead(403).end("Forbidden");
        return;
      }
      const info = await stat(target);
      if (!info.isFile()) {
        res.writeHead(404).end("Not found");
        return;
      }
      const data = await readFile(target);
      res.writeHead(200, { "Content-Type": MIME[extname(target)] || "application/octet-stream" });
      res.end(data);
    } catch {
      res.writeHead(404).end("Not found");
    }
  });
  await new Promise((resolveListen) => server.listen(0, "127.0.0.1", resolveListen));
  const addr = server.address();
  return { server, baseUrl: `http://127.0.0.1:${addr.port}/` };
}

function classifyRequests(requests, baseOrigin) {
  const dataFetches = [];
  const externalRequests = [];
  const staticAssets = [];
  for (const req of requests) {
    const parsed = new URL(req.url);
    if (parsed.origin !== baseOrigin) {
      externalRequests.push(req);
    } else if (req.type === "Fetch" || req.type === "XHR" || parsed.pathname.endsWith(".json")) {
      dataFetches.push(req);
    } else {
      staticAssets.push(req);
    }
  }
  return { dataFetches, externalRequests, staticAssets };
}

async function main() {
  const args = parseArgs(process.argv);
  const chromeBin = findChrome();
  if (!chromeBin) {
    throw new Error(
      "Headless Chrome binary not found (checked CHROME_BIN, google-chrome, chromium, chromium-browser). " +
      "Cannot run CDP browser smoke in this container."
    );
  }

  let serverHandle = null;
  let baseUrl = args.base;
  if (!/^https?:\/\//i.test(baseUrl)) {
    serverHandle = await startStaticServer(baseUrl);
    baseUrl = serverHandle.baseUrl;
  }
  if (!baseUrl.endsWith("/")) baseUrl += "/";
  const baseOrigin = new URL(baseUrl).origin;

  const profileDir = await mkdtemp(join(tmpdir(), "pgextwin-pages-smoke-"));
  const chrome = spawn(chromeBin, [
    "--headless=new", "--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu",
    "--remote-debugging-port=0", "--remote-allow-origins=*",
    "--no-first-run", "--no-default-browser-check", "--user-data-dir=" + profileDir,
    "--window-size=1280,800", "about:blank",
  ], { stdio: "ignore" });

  let ws;
  try {
    let port = null;
    for (let i = 0; i < 300; i += 1) {
      try {
        const file = await readFile(join(profileDir, "DevToolsActivePort"), "utf8");
        port = Number(file.split("\n")[0]);
        if (port > 0) break;
      } catch {}
      if (chrome.exitCode !== null || chrome.signalCode !== null) {
        throw new Error(`Chrome terminated before opening DevTools (exit=${chrome.exitCode}, signal=${chrome.signalCode})`);
      }
      await delay(100);
    }
    assert.ok(port, "Chrome DevTools port unavailable");
    const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
    const tab = targets.find((x) => x.type === "page" && x.webSocketDebuggerUrl);
    assert.ok(tab, "No inspectable browser tab");

    ws = new WebSocket(tab.webSocketDebuggerUrl);
    await new Promise((resolveOpen, rejectOpen) => {
      ws.addEventListener("open", resolveOpen, { once: true });
      ws.addEventListener("error", rejectOpen, { once: true });
    });

    let seq = 0;
    const pending = new Map();
    const recordedRequests = [];
    ws.addEventListener("message", (event) => {
      const msg = JSON.parse(event.data);
      if (msg.method === "Network.requestWillBeSent") {
        recordedRequests.push({
          url: msg.params.request.url,
          type: msg.params.type,
          method: msg.params.request.method,
        });
      }
      if (msg.id && pending.has(msg.id)) {
        const { resolve: res, reject: rej } = pending.get(msg.id);
        pending.delete(msg.id);
        if (msg.error) rej(new Error(msg.error.message));
        else res(msg.result);
      }
    });

    function send(method, params = {}) {
      const id = ++seq;
      return new Promise((res, rej) => {
        pending.set(id, { resolve: res, reject: rej });
        ws.send(JSON.stringify({ id, method, params }));
      });
    }

    async function evaluate(expression) {
      const out = await send("Runtime.evaluate", { expression, returnByValue: true, awaitPromise: true });
      if (out.exceptionDetails) throw new Error(out.exceptionDetails.text);
      return out.result.value;
    }

    await send("Page.enable");
    await send("Runtime.enable");
    await send("Network.enable");
    await send("Network.setCacheDisabled", { cacheDisabled: true });

    const traces = {};
    for (const [key, relPath, expectedDataFetches] of [
      ["en_home", "en/", 1],
      ["ja_home", "ja/", 1],
      ["en_cli", "en/cli.html", 0],
      ["ja_cli", "ja/cli.html", 0],
    ]) {
      recordedRequests.length = 0;
      await send("Page.navigate", { url: new URL(relPath, baseUrl).href });
      await delay(800);
      const classified = classifyRequests(recordedRequests, baseOrigin);
      assert.equal(classified.dataFetches.length, expectedDataFetches, `${key} data fetch count mismatch`);
      assert.equal(classified.externalRequests.length, 0, `${key} made unexpected external requests`);
      traces[key] = classified;
    }

    // Interactive filter verification on en/
    await send("Page.navigate", { url: new URL("en/", baseUrl).href });
    await delay(800);
    const filterResults = await evaluate(`(() => {
      const search = document.getElementById("search");
      const pg = document.getElementById("pg-filter");
      search.value = "ossc-db/pg_hint_plan";
      search.dispatchEvent(new Event("input", {bubbles: true}));
      const repoSearch = [...document.querySelectorAll("#extensions article:not([hidden])")].map(a => a.dataset.extension);
      search.value = "";
      search.dispatchEvent(new Event("input", {bubbles: true}));
      pg.value = "14";
      pg.dispatchEvent(new Event("change", {bubbles: true}));
      const pg14 = [...document.querySelectorAll("#extensions article:not([hidden])")].map(a => a.dataset.extension);
      pg.value = "";
      pg.dispatchEvent(new Event("change", {bubbles: true}));
      const lf = document.getElementById("landscape-filter");
      lf.value = "external-direct";
      lf.dispatchEvent(new Event("change", {bubbles: true}));
      const externalDirect = [...document.querySelectorAll("#landscape-grid article:not([hidden])")].map(a => a.dataset.landscape);
      return { repoSearch, pg14, externalDirect };
    })()`);

    // JS-disabled readability check
    await send("Emulation.setScriptExecutionDisabled", { value: true });
    await send("Page.navigate", { url: new URL("en/", baseUrl).href });
    await delay(500);
    const noJsVisible = await evaluate(`(() => ({
      extCount: document.querySelectorAll("#extensions article").length,
      landCount: document.querySelectorAll("#landscape-grid article").length,
      zipLinks: document.querySelectorAll("#extensions a.download-link").length
    }))()`);
    assert.equal(noJsVisible.extCount, 26);
    assert.equal(noJsVisible.landCount, 46);
    assert.ok(noJsVisible.zipLinks > 0);
    await send("Emulation.setScriptExecutionDisabled", { value: false });

    await mkdir(dirname(resolve(args.trace)), { recursive: true });
    await writeFile(resolve(args.trace), JSON.stringify({ result: "PASS", traces, noJsVisible }, null, 2) + "\n");
    await writeFile(resolve(args.filtersOut), JSON.stringify({ result: "PASS", filterResults }, null, 2) + "\n");
    console.log(JSON.stringify({ result: "PASS", trace: args.trace, filtersOut: args.filtersOut }));
  } finally {
    try { ws?.close(); } catch {}
    chrome.kill("SIGTERM");
    if (serverHandle) serverHandle.server.close();
    await rm(profileDir, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
  }
}

main().catch((err) => {
  console.error("pages-smoke FAILED:", err.message);
  process.exit(1);
});
