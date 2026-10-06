import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { promises as fs } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Journal } from "./journal.js";
import { tmpDir } from "./testkit.js";

const here = path.dirname(fileURLToPath(import.meta.url));
const cli = path.join(here, "cli.ts");
const example = (n: string) => path.join(here, "examples", n);

function guard(args: string[], env: Record<string, string> = {}) {
  const clean = { ...process.env };
  for (const k of Object.keys(clean)) if (k.startsWith("GUARD_")) delete clean[k];
  const r = spawnSync(process.execPath, ["--import", "tsx", cli, ...args], { env: { ...clean, ...env }, encoding: "utf8", timeout: 60_000 });
  return { code: r.status, out: (r.stdout ?? "") + (r.stderr ?? ""), stdout: r.stdout ?? "", stderr: r.stderr ?? "" };
}
const strip = (s: string) => s.replace(/\x1b\[[0-9;]*m/g, "");

test("help lists every command and states that Phase 1 changes nothing", () => {
  const r = guard(["help"]);
  assert.equal(r.code, 0);
  const o = strip(r.out);
  for (const w of ["validate", "journal verify", "journal head", "run", "GUARD_DATA_DIR", "GUARD_JOURNAL_KEY", "never changes a site"]) assert.match(o, new RegExp(w));
});

test("validate accepts each shipped example and reports what it found", () => {
  for (const f of ["acme-clinic.site.json", "acme-shop.site.json", "acme-wix.site.json"]) {
    const r = guard(["validate", example(f)]);
    assert.equal(r.code, 0, `${f}: ${r.out}`);
    assert.match(strip(r.out), /^ok acme-/);
  }
  assert.match(strip(guard(["validate", example("acme-clinic.site.json")]).out), /deploy windows: 1, whitelisted page regions: 2/);
});

test("validate rejects a bad config with the file and the field path, and exits non-zero", async () => {
  const { dir, cleanup } = await tmpDir();
  try {
    const f = path.join(dir, "x.site.json");
    await fs.writeFile(f, JSON.stringify({ id: "x1", name: "X", baseUrl: "https://x.example", platform: "wordpress", transport: { type: "none" }, owner: { telegramChatIdEnv: "FAKE-fixture:not-a-secret" } }));
    const r = guard(["validate", f]);
    assert.equal(r.code, 1);
    assert.match(strip(r.out), /owner\.telegramChatIdEnv: must be the NAME of an environment variable/);
    assert.ok(!r.out.includes("FAKE-fixture:not-a-secret"), "the pasted secret is not echoed");
    assert.equal(guard(["validate", path.join(dir, "missing.site.json")]).code, 1);
  } finally {
    await cleanup();
  }
});

test("validate --all enforces guardrail 1: a data directory inside a monitored root refuses to start", async () => {
  const { dir, cleanup } = await tmpDir();
  try {
    const sites = path.join(dir, "sites");
    const root = path.join(dir, "public_html");
    await fs.mkdir(sites);
    await fs.mkdir(root);
    await fs.writeFile(path.join(sites, "a.site.json"), JSON.stringify({ id: "acme-a", name: "A", baseUrl: "https://a.example", platform: "wordpress", transport: { type: "local-fs", root } }));

    const inside = guard(["validate", "--all"], { GUARD_SITES_DIR: sites, GUARD_DATA_DIR: path.join(root, ".guard") });
    assert.equal(inside.code, 1);
    assert.match(strip(inside.out), /acme-a.*inside the monitored web root/);

    const outside = guard(["validate", "--all"], { GUARD_SITES_DIR: sites, GUARD_DATA_DIR: path.join(dir, "data") });
    assert.equal(outside.code, 0, outside.out);
    assert.match(strip(outside.out), /1 site\(s\).*outside every monitored root/);

    const run = guard(["run", "--once"], { GUARD_SITES_DIR: sites, GUARD_DATA_DIR: path.join(root, ".guard") });
    assert.equal(run.code, 1, "run refuses too, not just validate");
  } finally {
    await cleanup();
  }
});

test("run --once starts, opens the journal, says there are no workers yet, and releases the lock", async () => {
  const { dir, cleanup } = await tmpDir();
  try {
    const env = { GUARD_SITES_DIR: path.join(dir, "sites"), GUARD_DATA_DIR: path.join(dir, "data") };
    const r = guard(["run", "--once"], env);
    assert.equal(r.code, 0, r.out);
    assert.match(strip(r.out), /ready 0 site\(s\)/);
    assert.match(strip(r.out), /No workers are registered in Phase 1/);
    await assert.rejects(() => fs.stat(path.join(dir, "data", "events.jsonl.lock")), /ENOENT/, "lock released on shutdown");
    assert.equal(guard(["run", "--once"], env).code, 0, "and it can start again");
  } finally {
    await cleanup();
  }
});

test("journal verify / head: ok, tampered, truncated-with-anchor, keyed", async () => {
  const { dir, cleanup } = await tmpDir();
  try {
    const data = path.join(dir, "data");
    const file = path.join(data, "events.jsonl");
    const env = { GUARD_DATA_DIR: data };
    const j = await Journal.open(file);
    for (let n = 1; n <= 4; n++) await j.append("event", { n });
    const head = j.head();
    await j.close();

    const ok = guard(["journal", "verify"], env);
    assert.equal(ok.code, 0, ok.out);
    assert.match(strip(ok.out), new RegExp(`ok 4 entries, head ${head.hash}.*unkeyed`));
    assert.equal(strip(guard(["journal", "head"], env).stdout).trim(), `4 ${head.hash}`);

    const lines = (await fs.readFile(file, "utf8")).slice(0, -1).split("\n");
    await fs.writeFile(file, lines.slice(0, 2).join("\n") + "\n");
    assert.equal(guard(["journal", "verify"], env).code, 0, "a shorter chain still verifies on its own");
    const anchored = guard(["journal", "verify", "--expected-head", head.hash], env);
    assert.equal(anchored.code, 1);
    assert.match(strip(anchored.out), /head_mismatch/);

    await fs.writeFile(file, lines.map((l, i) => (i === 1 ? l.replace('"n":2', '"n":9') : l)).join("\n") + "\n");
    const bad = guard(["journal", "verify"], env);
    assert.equal(bad.code, 1);
    assert.match(strip(bad.out), /bad_hash at line 2/);
    assert.equal(guard(["journal", "head"], env).code, 1, "refuses to print a head for a journal that does not verify");
  } finally {
    await cleanup();
  }
});

test("a keyed journal verifies only when the CLI is given the key", async () => {
  const { dir, cleanup } = await tmpDir();
  try {
    const data = path.join(dir, "data");
    const key = "s".repeat(40);
    const j = await Journal.open(path.join(data, "events.jsonl"), { key: Buffer.from(key) });
    await j.append("event", { n: 1 });
    await j.close();
    const withKey = guard(["journal", "verify"], { GUARD_DATA_DIR: data, GUARD_JOURNAL_KEY: key });
    assert.equal(withKey.code, 0, withKey.out);
    assert.match(strip(withKey.out), /HMAC keyed/);
    assert.equal(guard(["journal", "verify"], { GUARD_DATA_DIR: data }).code, 1);
  } finally {
    await cleanup();
  }
});

test("a weak journal key and an unknown command are both refused", () => {
  const weak = guard(["journal", "verify"], { GUARD_JOURNAL_KEY: "short" });
  assert.equal(weak.code, 1);
  assert.match(strip(weak.out), /shorter than 32/);
  const unknown = guard(["frobnicate"]);
  assert.equal(unknown.code, 1);
  assert.match(strip(unknown.out), /unknown command 'frobnicate'/);
});
