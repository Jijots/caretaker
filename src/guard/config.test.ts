import test from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  ConfigError, PageRegion, SiteConfig, assertDataDirOffHost, formatIssues, loadSiteFile, loadSites, resolveGuardPaths,
} from "./config.js";
import { site, tmpDir } from "./testkit.js";

const minimal = () => ({
  id: "acme-clinic", name: "Acme", baseUrl: "https://acme.example", platform: "wordpress",
  transport: { type: "local-fs", root: path.resolve("/srv/acme") },
});
const bad = (over: Record<string, unknown>) => SiteConfig.safeParse({ ...minimal(), ...over });
const messages = (r: ReturnType<typeof bad>) => (r.success ? "" : JSON.stringify(r.error.issues));

test("a minimal config gets safe defaults, including the nested responder ones", () => {
  const s = SiteConfig.parse(minimal());
  assert.equal(s.timezone, "Asia/Manila");
  assert.deepEqual(s.pages, ["/"]);
  assert.deepEqual(s.deployWindows, []);
  assert.equal(s.responder.enabled, false, "off unless the site opts in");
  assert.equal(s.responder.mode, "dry-run");
  assert.equal(s.responder.autoBlockIps, false);
  assert.equal(s.responder.autoRestoreMinConfidence, 0.9);
  assert.equal(s.responder.maxRestoresPerWindow, 2);
  assert.deepEqual(s.owner, {});
});

test("unknown keys are rejected at every level", () => {
  assert.equal(bad({ extra: 1 }).success, false);
  assert.equal(bad({ responder: { enabled: true, yolo: true } }).success, false);
  assert.equal(bad({ transport: { type: "none", host: "x" } }).success, false);
});

test("secrets by reference: a pasted token is rejected, and the error never echoes it", () => {
  // Deliberately NOT token-shaped: a realistic-looking fake would trip secret scanners on a public repo.
  const token = "FAKE-fixture:not-a-real-token";
  const r = bad({ owner: { telegramChatIdEnv: token } });
  assert.equal(r.success, false);
  const text = messages(r);
  assert.match(text, /must be the NAME of an environment variable/);
  assert.ok(!text.includes(token), "the rejected value must not appear in the error");
  assert.equal(bad({ owner: { telegramChatIdEnv: "my_chat_id" } }).success, false, "lowercase is not an env var name");
  assert.equal(bad({ owner: { telegramChatIdEnv: "GUARD_TELEGRAM_CHAT_ACME" } }).success, true);
});

test("a git remote may not embed a password or token", () => {
  const g = (remote: string) => bad({ transport: { type: "git", remote } });
  assert.equal(g("https://user:faketoken123@github.com/acme/shop.git").success, false);
  assert.ok(!messages(g("https://user:faketoken123@github.com/acme/shop.git")).includes("faketoken123"));
  assert.equal(g("https://github.com/acme/shop.git").success, true);
  assert.equal(g("git@github.com:acme/shop.git").success, true);
  assert.equal(g("ssh://git@github.com/acme/shop.git").success, true, "a bare ssh user is not a secret");
  assert.equal(g("https://oauth2:abc@gitlab.com/a/b.git").success, false);
});

test("local-fs needs an absolute root; platforms, urls and zones are checked", () => {
  assert.equal(bad({ transport: { type: "local-fs", root: "relative/path" } }).success, false);
  assert.equal(bad({ platform: "drupal" }).success, false);
  assert.equal(bad({ baseUrl: "ftp://acme.example" }).success, false);
  assert.equal(bad({ baseUrl: "not a url" }).success, false);
  assert.equal(bad({ timezone: "Mars/Olympus" }).success, false);
  assert.equal(bad({ timezone: "America/New_York" }).success, true);
  assert.equal(bad({ id: "Has Spaces" }).success, false);
});

test("a whitelist that would blind the page watcher is refused", () => {
  const r = (selector: string) => PageRegion.safeParse({ page: "/", selector, reason: "because" });
  for (const s of ["body", "html", "*", ":root", "  BODY  ", "HTML"]) assert.equal(r(s).success, false, `selector '${s}'`);
  assert.equal(r(".cart-count").success, true);
  assert.equal(r("#visitor-counter").success, true);
  assert.equal(PageRegion.safeParse({ page: "/", selector: ".x", reason: "" }).success, false, "every exception must say why");
  assert.equal(PageRegion.safeParse({ page: "products", selector: ".x", reason: "why" }).success, false, "page must be a path");
});

test("a page region must point at a watched page, or at '*'", () => {
  assert.equal(bad({ pages: ["/", "/shop"], pageRegions: [{ page: "/shop", selector: ".stock", reason: "changes per sale" }] }).success, true);
  assert.equal(bad({ pages: ["/"], pageRegions: [{ page: "/shop", selector: ".stock", reason: "changes per sale" }] }).success, false);
  assert.equal(bad({ pages: ["/"], pageRegions: [{ page: "*", selector: ".stock", reason: "everywhere" }] }).success, true);
});

test("the IP allowlist accepts addresses and CIDR ranges and nothing else", () => {
  const a = (ipAllowlist: string[]) => bad({ responder: { ipAllowlist } }).success;
  assert.equal(a(["203.0.113.7", "10.0.0.0/8", "2001:db8::/32", "::1"]), true);
  for (const x of ["999.1.1.1", "10.0.0.0/33", "::1/129", "example.com", "10.0.0.0/8/9", "10.0.0.0/"]) assert.equal(a([x]), false, x);
});

test("responder limits are bounded", () => {
  const r = (responder: Record<string, unknown>) => bad({ responder }).success;
  assert.equal(r({ autoRestoreMinConfidence: 0.4 }), false, "a threshold below 0.5 would restore on coin flips");
  assert.equal(r({ autoRestoreMinConfidence: 1.1 }), false);
  assert.equal(r({ ipBlockTtlMinutes: 0 }), false, "a block must expire");
  assert.equal(r({ ipBlockTtlMinutes: 100_000 }), false);
  assert.equal(r({ maxRestoresPerWindow: 0 }), false);
  assert.equal(r({ mode: "yolo" }), false);
});

test("the shipped example configs all validate", async () => {
  const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), "examples");
  const files = (await fs.readdir(dir)).filter((f) => f.endsWith(".site.json"));
  assert.ok(files.length >= 3);
  const seen = new Set<string>();
  for (const f of files) {
    const s = await loadSiteFile(path.join(dir, f));
    assert.ok(!seen.has(s.id), `duplicate id ${s.id}`);
    seen.add(s.id);
    assert.equal(s.responder.enabled, false, `${f}: examples must ship with the responder off`);
  }
  assert.deepEqual([...seen].sort(), ["acme-clinic", "acme-shop", "acme-studio", "acme-wix"]);
});

test("loadSites: duplicates, bad files and unrelated files", async () => {
  const { dir, cleanup } = await tmpDir();
  try {
    const put = (n: string, o: unknown) => fs.writeFile(path.join(dir, n), typeof o === "string" ? o : JSON.stringify(o));
    assert.equal((await loadSites(path.join(dir, "missing"))).size, 0, "a missing directory is an empty fleet");

    await put("a.site.json", { ...minimal(), id: "site-a" });
    await put("b.site.json", { ...minimal(), id: "site-b" });
    await put("notes.txt", "ignored");
    await put("c.json", "also ignored");
    assert.deepEqual([...(await loadSites(dir)).keys()], ["site-a", "site-b"]);

    await put("dup.site.json", { ...minimal(), id: "site-a" });
    await assert.rejects(() => loadSites(dir), (e: ConfigError) => e.problems.some((p) => /duplicate site id 'site-a'/.test(p)));
    await fs.rm(path.join(dir, "dup.site.json"));

    await put("broken.site.json", { ...minimal(), id: "site-c", responder: { mode: "yolo" } });
    await assert.rejects(() => loadSites(dir), (e: ConfigError) => e.problems.some((p) => /broken\.site\.json: responder\.mode/.test(p)));
    await put("broken.site.json", "{ not json");
    await assert.rejects(() => loadSites(dir), (e: ConfigError) => e.problems.some((p) => /broken\.site\.json: not valid JSON/.test(p)));
  } finally {
    await cleanup();
  }
});

test("formatIssues names the file and the field path", () => {
  const r = SiteConfig.safeParse({ ...minimal(), responder: { mode: "yolo" } });
  assert.equal(r.success, false);
  if (!r.success) assert.match(formatIssues(r.error, "x.site.json")[0], /^x\.site\.json: responder\.mode: /);
});

test("GUARD_JOURNAL_KEY must be long enough to mean something", () => {
  assert.throws(() => resolveGuardPaths({ GUARD_JOURNAL_KEY: "short" }), (e: ConfigError) => /shorter than 32/.test(e.problems[0]));
  const p = resolveGuardPaths({ GUARD_JOURNAL_KEY: "k".repeat(32), GUARD_DATA_DIR: "data", GUARD_SITES_DIR: "sites" });
  assert.equal(p.journalKey?.length, 32);
  assert.equal(p.dataDir, path.resolve("data"));
  const d = resolveGuardPaths({});
  assert.equal(d.journalKey, undefined);
  assert.equal(d.dataDir, path.resolve(".guard-data"));
  assert.equal(d.sitesDir, path.resolve("guard-sites"));
});

test("guardrail 1: the data directory may not sit inside a monitored web root", async () => {
  const { dir, cleanup } = await tmpDir();
  try {
    const root = path.join(dir, "public_html");
    await fs.mkdir(path.join(root, "wp-content", "guard-data"), { recursive: true });
    const s = site({ transport: { type: "local-fs", root } });

    assert.throws(() => assertDataDirOffHost(path.join(root, "wp-content", "guard-data"), [s]), (e: ConfigError) => /acme-clinic.*inside the monitored web root/.test(e.problems[0]));
    assert.throws(() => assertDataDirOffHost(root, [s]), ConfigError, "equal to the root counts as inside");
    assert.throws(() => assertDataDirOffHost(path.join(root, "not", "created", "yet"), [s]), ConfigError, "a path that does not exist yet is still judged");

    assert.doesNotThrow(() => assertDataDirOffHost(path.join(dir, "guard-data"), [s]), "a sibling directory is fine");
    assert.doesNotThrow(() => assertDataDirOffHost(path.join(dir, "public_html_backup"), [s]), "a name that merely starts the same is not inside");
    assert.doesNotThrow(() => assertDataDirOffHost(path.join(root, "x"), [site({ transport: { type: "none" } }), site({ id: "gitsite", transport: { type: "git", remote: "git@github.com:a/b.git" } })]), "only local-fs roots are monitored paths");
  } finally {
    await cleanup();
  }
});
