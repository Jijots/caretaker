import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { spawn } from "node:child_process";
import { promises as fs } from "node:fs";
import type { AddressInfo } from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { BrowserUnavailableError, launchBrowser } from "./browser.js";
import { tmpDir } from "./testkit.js";

const cli = path.join(path.dirname(fileURLToPath(import.meta.url)), "cli.ts");
const strip = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, "");

/** Async on purpose: spawnSync would block this process, and with it the web server the CLI is loading. */
function guard(args: string[], env: Record<string, string>): Promise<{ code: number | null; out: string }> {
  const clean = { ...process.env };
  for (const k of Object.keys(clean)) if (k.startsWith("GUARD_")) delete clean[k];
  return new Promise((resolve) => {
    const p = spawn(process.execPath, ["--import", "tsx", cli, ...args], { env: { ...clean, ...env } });
    let out = "";
    p.stdout.on("data", (d) => (out += d));
    p.stderr.on("data", (d) => (out += d));
    p.on("close", (code) => resolve({ code, out: strip(out) }));
  });
}

const HOME = `<!doctype html><html lang="en"><head><title>Acme Dental</title></head><body>
<h1>Acme Dental Clinic</h1><p>Open Monday to Friday, 9am to 5pm</p><p>Book an appointment today</p>
<p>We offer cleaning, whitening and braces</p><p>Call us on 0917 000 0000</p><p>Visit us at 12 Rizal Avenue, Manila</p>
</body></html>`;

test("pages end to end through the CLI: snapshot, quiet check, defaced check, run, journal", async (t) => {
  try {
    await (await launchBrowser()).close();
  } catch (e) {
    if (e instanceof BrowserUnavailableError) return t.skip(e.message);
    throw e;
  }
  const { dir, cleanup } = await tmpDir();
  let html = HOME;
  const server = http.createServer((_req, res) => res.writeHead(200, { "content-type": "text/html" }).end(html));
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  try {
    const sites = path.join(dir, "sites");
    const data = path.join(dir, "data");
    await fs.mkdir(sites);
    await fs.writeFile(path.join(sites, "acme-p.site.json"), JSON.stringify({
      id: "acme-p", name: "P", baseUrl: origin, platform: "wix", transport: { type: "none" }, pages: ["/"],
    }));
    const env = { GUARD_SITES_DIR: sites, GUARD_DATA_DIR: data };

    const before = await guard(["run", "--once"], env);
    assert.match(before.out, /acme-p: page watcher not started: no page baseline yet/);
    assert.match(before.out, /No site is being watched yet/);

    const snap = await guard(["baseline", "snapshot", "acme-p"], env);
    assert.equal(snap.code, 0, snap.out);
    assert.match(snap.out, /page baseline acme-p \/: \d+ stable text blocks, 0 volatile ignored/);
    assert.match(snap.out, /already defaced or backdoored, that is now "normal"/);
    assert.doesNotMatch(snap.out, /file baseline/, "a site with no readable files gets no file baseline, and no complaint");
    assert.match((await guard(["baseline", "show", "acme-p"], env)).out, /acme-p \/: \d+ text blocks/);

    const clean = await guard(["page", "check", "acme-p"], env);
    assert.equal(clean.code, 0, clean.out);
    assert.match(clean.out, /nothing differs from the baseline/);

    html = HOME.replace("</body>", "<h2>Hacked by Test Crew</h2><iframe src='https://evil.example/f' style='display:none'></iframe></body>");
    const dirty = await guard(["page", "check", "acme-p"], env);
    assert.equal(dirty.code, 2, dirty.out);
    assert.match(dirty.out, /critical\s+page\.defacement_signal/);
    assert.match(dirty.out, /high\s+page\.iframe_injected/);

    const run = await guard(["run", "--once"], env);
    assert.equal(run.code, 0, run.out);
    assert.match(run.out, /Page watcher on: acme-p/);
    assert.match(run.out, /\[acme-p\] confirmed_defacement critical/);
    assert.equal((await guard(["journal", "verify"], env)).code, 0);
    const kinds = (await fs.readFile(path.join(data, "events.jsonl"), "utf8")).trim().split("\n").map((l) => JSON.parse(l).kind);
    assert.ok(kinds.includes("event") && kinds.includes("incident") && kinds.includes("decision"), kinds.join());

    // A baseline that fails its digest check stops that site being watched.
    const pagesDir = path.join(data, "baselines", "acme-p", "pages");
    const jf = path.join(pagesDir, (await fs.readdir(pagesDir)).find((f) => f.endsWith(".json"))!);
    const m = JSON.parse(await fs.readFile(jf, "utf8"));
    m.body.texts = ["all is well"];
    await fs.writeFile(jf, JSON.stringify(m));
    const tampered = await guard(["run", "--once"], env);
    assert.match(tampered.out, /page watcher not started: .*fails its digest check/);
    assert.match(tampered.out, /No site is being watched yet/);
    assert.equal((await guard(["page", "check", "acme-p"], env)).code, 1);
    assert.match(await fs.readFile(path.join(data, "events.jsonl"), "utf8"), /"worker":"page"/);
  } finally {
    server.close();
    await cleanup();
  }
});
