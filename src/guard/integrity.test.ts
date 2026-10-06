import test from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import path from "node:path";
import { BaselineError, BaselineStore } from "./baseline.js";
import { IntegrityWatcher, looksExecutableName } from "./integrity.js";
import { LocalFsTransport } from "./transport-local.js";
import { effectiveIntegrityRules, SiteConfig } from "./config.js";
import { site as mkSite, tmpDir } from "./testkit.js";

async function put(root: string, files: Record<string, string>) {
  for (const [p, c] of Object.entries(files)) {
    await fs.mkdir(path.dirname(path.join(root, p)), { recursive: true });
    await fs.writeFile(path.join(root, p), c);
  }
}

async function setup(files: Record<string, string>, over: Record<string, unknown> = {}) {
  const { dir, cleanup } = await tmpDir();
  const root = path.join(dir, "public_html");
  const data = path.join(dir, "data");
  await fs.mkdir(root);
  await put(root, files);
  const site = mkSite({ transport: { type: "local-fs", root }, ...over });
  const transport = await LocalFsTransport.open(root);
  const store = new BaselineStore(data);
  await store.snapshot(site, transport);
  const baseline = (await store.load(site.id))!;
  const watcher = new IntegrityWatcher({ site, transport, baseline });
  return { dir, root, data, site, transport, store, baseline, watcher, cleanup };
}
const types = (r: { events: { type: string }[] }) => r.events.map((e) => e.type).sort();

test("an untouched site produces no events", async () => {
  const s = await setup({ "index.php": "<?php echo 1;", "css/a.css": "a{}" });
  try {
    const r = await s.watcher.runOnce();
    assert.deepEqual(r.events, []);
    assert.equal(r.filesChecked, 2);
  } finally {
    await s.cleanup();
  }
});

test("a changed file is reported with both hashes, and an entry point is rated higher", async () => {
  const s = await setup({ "index.php": "good", "about.php": "good" });
  try {
    await put(s.root, { "index.php": "HACKED", "about.php": "also changed" });
    const r = await s.watcher.runOnce();
    assert.deepEqual(types(r), ["integrity.file_changed", "integrity.file_changed"]);
    const idx = r.events.find((e) => e.evidence.path === "index.php")!;
    const about = r.events.find((e) => e.evidence.path === "about.php")!;
    assert.equal(idx.severity, "critical");
    assert.equal(about.severity, "high");
    assert.ok(idx.confidence > about.confidence);
    assert.notEqual(idx.evidence.baselineSha256, idx.evidence.currentSha256);
    assert.equal(idx.evidence.restorable, true);
    assert.deepEqual(idx.indicators.paths, ["index.php"]);
  } finally {
    await s.cleanup();
  }
});

test("an added file and a removed file are reported, and a removed entry point is critical", async () => {
  const s = await setup({ "index.php": "x", "keep.txt": "k", "gone.txt": "g" });
  try {
    await fs.rm(path.join(s.root, "index.php"));
    await fs.rm(path.join(s.root, "gone.txt"));
    await put(s.root, { "new.php": "n" });
    const r = await s.watcher.runOnce();
    assert.deepEqual(types(r), ["integrity.file_added", "integrity.file_removed", "integrity.file_removed"]);
    assert.equal(r.events.find((e) => e.evidence.path === "index.php")!.severity, "critical");
    assert.equal(r.events.find((e) => e.evidence.path === "gone.txt")!.severity, "medium");
  } finally {
    await s.cleanup();
  }
});

test("a difference is reported once, again if the file changes again, and forgotten once fixed", async () => {
  const s = await setup({ "a.php": "good" });
  try {
    await put(s.root, { "a.php": "bad1" });
    assert.equal((await s.watcher.runOnce()).events.length, 1);
    const again = await s.watcher.runOnce();
    assert.equal(again.events.length, 0, "same difference, not re-emitted");
    assert.equal(again.suppressed, 1);

    await put(s.root, { "a.php": "bad2 and longer" });
    assert.equal((await s.watcher.runOnce()).events.length, 1, "a further change is news");

    await put(s.root, { "a.php": "good" });
    assert.equal((await s.watcher.runOnce()).events.length, 0, "restored");
    await put(s.root, { "a.php": "bad1" });
    assert.equal((await s.watcher.runOnce()).events.length, 1, "and it is reported afresh if it comes back");
  } finally {
    await s.cleanup();
  }
});

test("a rewrite that restores size and mtime is still caught on a cheap pass, because ctime moves", async () => {
  const s = await setup({ "a.php": "AAAA" });
  try {
    await s.watcher.runOnce(); // pass 0 is a full rehash and primes the cache
    const p = path.join(s.root, "a.php");
    const before = await fs.stat(p);
    await fs.writeFile(p, "BBBB"); // same length
    await fs.utimes(p, before.atime, before.mtime); // mtime put back
    const r = await s.watcher.runOnce();
    assert.equal(r.fullRehash, false, "this is a cheap pass");
    assert.equal(r.events.length, 1, "ctime cannot be set back by an ordinary user");
  } finally {
    await s.cleanup();
  }
});

test("the full rehash runs on pass 0 and then every Nth pass", async () => {
  const s = await setup({ "a.txt": "1" }, { integrity: { fullRehashEvery: 3 } });
  try {
    const flags: boolean[] = [];
    for (let i = 0; i < 7; i++) flags.push((await s.watcher.runOnce()).fullRehash);
    assert.deepEqual(flags, [true, false, false, true, false, false, true]);
  } finally {
    await s.cleanup();
  }
});

test("platform defaults: WordPress cache is ignored, and uploads are not baselined but are checked", async () => {
  const s = await setup(
    { "index.php": "x", "wp-content/cache/page.html": "c", "wp-content/uploads/2026/photo.jpg": "jpegbytes" },
    { platform: "wordpress" },
  );
  try {
    assert.ok(!("wp-content/cache/page.html" in s.baseline.files), "cache excluded from the baseline");
    assert.ok(!("wp-content/uploads/2026/photo.jpg" in s.baseline.files), "uploads are not baselined");
    await put(s.root, { "wp-content/cache/page2.html": "noise", "wp-content/uploads/2026/photo2.jpg": "more" });
    assert.deepEqual((await s.watcher.runOnce()).events, [], "ordinary upload and cache churn is silent");
  } finally {
    await s.cleanup();
  }
});

test("a webshell in uploads is critical, however it is named", async () => {
  const s = await setup({ "index.php": "x", "wp-content/uploads/a.jpg": "ok" }, { platform: "wordpress" });
  try {
    await put(s.root, {
      "wp-content/uploads/shell.php": "<?php system($_GET[1]);",
      "wp-content/uploads/pic.php.jpg": "x",
      "wp-content/uploads/.htaccess": "AddType application/x-httpd-php .jpg",
      "wp-content/uploads/innocent.png": "GIF89a<?php eval($_POST[1]); ?>",
    });
    const r = await s.watcher.runOnce();
    const paths = r.events.map((e) => e.evidence.path).sort();
    assert.deepEqual(paths, [
      "wp-content/uploads/.htaccess",
      "wp-content/uploads/innocent.png",
      "wp-content/uploads/pic.php.jpg",
      "wp-content/uploads/shell.php",
    ]);
    for (const e of r.events) {
      assert.equal(e.type, "integrity.executable_in_uploads");
      assert.equal(e.severity, "critical");
      assert.equal(e.worker, "integrity");
    }
  } finally {
    await s.cleanup();
  }
});

test("an executable already in uploads on the first pass is reported, not assumed fine", async () => {
  const { dir, cleanup } = await tmpDir();
  try {
    const root = path.join(dir, "site");
    await fs.mkdir(root);
    await put(root, { "index.php": "x", "uploads/old-shell.php": "<?php" });
    const site = mkSite({ transport: { type: "local-fs", root }, integrity: { uploadDirs: ["uploads/**"] } });
    const t = await LocalFsTransport.open(root);
    const store = new BaselineStore(path.join(dir, "data"));
    await store.snapshot(site, t);
    const w = new IntegrityWatcher({ site, transport: t, baseline: (await store.load(site.id))! });
    assert.equal((await w.runOnce()).events.length, 1);
  } finally {
    await cleanup();
  }
});

test("a flood is itemised up to a cap and then summarised, never silently dropped", async () => {
  const s = await setup({ "index.php": "x" });
  try {
    for (let i = 0; i < 40; i++) await put(s.root, { [`spam/f${i}.html`]: String(i) });
    const r = await s.watcher.runOnce();
    assert.equal(r.events.length, 26, "25 itemised plus one summary");
    assert.match(r.events.at(-1)!.summary, /15 more integrity.file_added not itemised \(40 in this pass\)/);
  } finally {
    await s.cleanup();
  }
});

test("a directory that cannot be read does not make its files look removed", async () => {
  const s = await setup({ "index.php": "x", "private/a.txt": "a" });
  try {
    const real = s.transport.list.bind(s.transport);
    s.transport.list = async (d, o) => {
      const r = (await real(d, o)).filter((f) => !f.path.startsWith("private/"));
      o?.onUnreadable?.("private", "EACCES");
      return r;
    };
    const stat = s.transport.stat.bind(s.transport);
    s.transport.stat = async (p) =>
      p.startsWith("private/") ? Promise.reject(Object.assign(new Error("denied"), { code: "EACCES" })) : stat(p);
    const r = await s.watcher.runOnce();
    assert.deepEqual(r.events, []);
    assert.deepEqual(r.unreadable, ["private"]);
  } finally {
    await s.cleanup();
  }
});

test("looksExecutableName", () => {
  for (const n of ["a.php", "A.PHP", "x/y/shell.phtml", "pic.php.jpg", ".htaccess", "z/.user.ini", "run.sh", "web.config"]) {
    assert.equal(looksExecutableName(n), true, n);
  }
  for (const n of ["photo.jpg", "doc.pdf", "php.txt", "archive.tar.gz", "notes"]) assert.equal(looksExecutableName(n), false, n);
});

test("events are valid and carry the standards tags from the type table", async () => {
  const s = await setup({ "index.php": "x" });
  try {
    await put(s.root, { "index.php": "y" });
    const [e] = (await s.watcher.runOnce()).events;
    assert.equal(e.worker, "integrity");
    assert.deepEqual(e.tags.attack, ["T1491.002"]);
    assert.deepEqual(e.tags.owasp, ["A08"]);
  } finally {
    await s.cleanup();
  }
});

/* ------------------------------------------------------------- baseline */

test("a baseline records hashes and keeps restorable bytes off the host, verifying them on read", async () => {
  const s = await setup({ "index.php": "original", "big.bin": "x".repeat(2000) }, { integrity: { maxStoreBytes: 1024 } });
  try {
    assert.equal(s.baseline.files["index.php"].stored, true);
    assert.equal(s.baseline.files["big.bin"].stored, false, "over the cap: hash only, so detectable but not restorable");
    const sha = s.baseline.files["index.php"].sha256;
    assert.equal((await s.store.readObject(s.site.id, sha)).toString(), "original");
    await fs.writeFile(s.store.objectPath(s.site.id, sha), "tampered");
    await assert.rejects(() => s.store.readObject(s.site.id, sha), /corrupt/);
  } finally {
    await s.cleanup();
  }
});

test("an edited manifest fails its digest check, and a keyed manifest needs the key", async () => {
  const s = await setup({ "index.php": "x" });
  try {
    const file = path.join(s.store.dir(s.site.id), "manifest.json");
    const m = JSON.parse(await fs.readFile(file, "utf8"));
    m.body.files["index.php"].sha256 = "a".repeat(64);
    await fs.writeFile(file, JSON.stringify(m));
    await assert.rejects(
      () => s.store.load(s.site.id),
      (e: Error) => e instanceof BaselineError && /digest check/.test(e.message),
    );

    const keyed = new BaselineStore(s.data, Buffer.from("k".repeat(40)));
    await keyed.snapshot(s.site, s.transport);
    assert.ok(await keyed.load(s.site.id));
    await assert.rejects(() => new BaselineStore(s.data).load(s.site.id), /keyed but GUARD_JOURNAL_KEY is not set/);
    await assert.rejects(() => new BaselineStore(s.data, Buffer.from("z".repeat(40))).load(s.site.id), /digest check/);
  } finally {
    await s.cleanup();
  }
});

test("no baseline is null, not an error", async () => {
  const { dir, cleanup } = await tmpDir();
  try {
    assert.equal(await new BaselineStore(dir).load("acme-clinic"), null);
  } finally {
    await cleanup();
  }
});

/* --------------------------------------------------------------- config */

test("integrity config: defaults, rules that would blind the watcher, and merged platform rules", () => {
  const base = { id: "acme-x", name: "X", baseUrl: "https://x.example", platform: "wordpress", transport: { type: "none" } };
  assert.equal(SiteConfig.parse(base).integrity.intervalSeconds, 300);
  for (const g of ["**", "**/*", "/"]) assert.equal(SiteConfig.safeParse({ ...base, integrity: { exclude: [g] } }).success, false, g);
  for (const g of ["../x", "/etc", "a/../b"]) assert.equal(SiteConfig.safeParse({ ...base, integrity: { exclude: [g] } }).success, false, g);
  assert.equal(SiteConfig.safeParse({ ...base, integrity: { intervalSeconds: 5 } }).success, false);
  assert.equal(SiteConfig.safeParse({ ...base, integrity: { surprise: 1 } }).success, false);

  const r = effectiveIntegrityRules(SiteConfig.parse({ ...base, integrity: { exclude: ["tmp/**"], uploadDirs: ["media/**"] } }));
  assert.ok(r.exclude.includes(".git/**") && r.exclude.includes("wp-content/cache/**") && r.exclude.includes("tmp/**"));
  assert.deepEqual(r.uploadDirs, ["wp-content/uploads/**", "media/**"]);
  const off = effectiveIntegrityRules(SiteConfig.parse({ ...base, integrity: { platformDefaults: false } }));
  assert.ok(!off.exclude.includes("wp-content/cache/**") && off.exclude.includes(".git/**"), "VCS dirs are excluded regardless");
});
