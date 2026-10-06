import test from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { LocalFsTransport } from "./transport-local.js";
import { TransportError } from "./transport.js";
import { tmpDir } from "./testkit.js";

async function tree(dir: string, files: Record<string, string>) {
  for (const [p, c] of Object.entries(files)) {
    await fs.mkdir(path.dirname(path.join(dir, p)), { recursive: true });
    await fs.writeFile(path.join(dir, p), c);
  }
}
// Symlinks need privileges on some Windows setups. Those tests skip rather than fail.
async function link(target: string, at: string, type: "file" | "dir" = "file"): Promise<boolean> {
  try {
    await fs.symlink(target, at, type === "dir" ? "junction" : "file");
    return true;
  } catch {
    return false;
  }
}

test("lists recursively, in a stable order, with forward-slash relative paths", async () => {
  const { dir, cleanup } = await tmpDir();
  try {
    await tree(dir, { "b.txt": "b", "a.txt": "a", "sub/c.txt": "c", "sub/deep/d.txt": "d" });
    const t = await LocalFsTransport.open(dir);
    const flat = await t.list("", { recursive: false });
    assert.deepEqual(flat.map((f) => f.path), ["a.txt", "b.txt"]);
    const all = await t.list("", { recursive: true });
    assert.deepEqual(all.map((f) => f.path).sort(), ["a.txt", "b.txt", "sub/c.txt", "sub/deep/d.txt"]);
    assert.deepEqual((await t.list("", { recursive: true })).map((f) => f.path), all.map((f) => f.path), "same order twice");
  } finally {
    await cleanup();
  }
});

test("skipDir prunes a directory without descending into it", async () => {
  const { dir, cleanup } = await tmpDir();
  try {
    await tree(dir, { "keep/a": "1", "cache/b": "2" });
    const t = await LocalFsTransport.open(dir);
    const r = await t.list("", { recursive: true, skipDir: (p) => p === "cache" });
    assert.deepEqual(r.map((f) => f.path), ["keep/a"]);
  } finally {
    await cleanup();
  }
});

test("paths may not leave the root, however they are spelled", async () => {
  const { dir, cleanup } = await tmpDir();
  try {
    const t = await LocalFsTransport.open(dir);
    for (const p of ["../x", "a/../../x", "/etc/passwd", "C:/Windows/win.ini", "a\\..\\..\\x", "a\0b"]) {
      await assert.rejects(() => t.read(p), TransportError, JSON.stringify(p));
      await assert.rejects(() => t.stat(p), TransportError, JSON.stringify(p));
    }
  } finally {
    await cleanup();
  }
});

test("a missing file stats as null, and a missing root is refused", async () => {
  const { dir, cleanup } = await tmpDir();
  try {
    const t = await LocalFsTransport.open(dir);
    assert.equal(await t.stat("nope.txt"), null);
    await assert.rejects(() => LocalFsTransport.open(path.join(dir, "missing")), /not reachable/);
  } finally {
    await cleanup();
  }
});

test("hash matches sha256 of the content and read honours maxBytes", async () => {
  const { dir, cleanup } = await tmpDir();
  try {
    await tree(dir, { "a.txt": "hello world" });
    const t = await LocalFsTransport.open(dir);
    const h = await t.hash("a.txt");
    assert.equal(h.sha256, createHash("sha256").update("hello world").digest("hex"));
    assert.equal(h.size, 11);
    assert.equal((await t.read("a.txt", { maxBytes: 5 })).toString(), "hello");
    assert.equal((await t.read("a.txt")).toString(), "hello world");
  } finally {
    await cleanup();
  }
});

test("a symlink is reported but never followed: not read, and not hashed through", async () => {
  const { dir, cleanup } = await tmpDir();
  try {
    const outside = path.join(dir, "outside.txt");
    const root = path.join(dir, "site");
    await fs.mkdir(root);
    await fs.writeFile(outside, "secret");
    if (!(await link(outside, path.join(root, "link.txt")))) return; // cannot create symlinks here
    const t = await LocalFsTransport.open(root);
    const listed = await t.list("", {});
    assert.equal(listed.find((f) => f.path === "link.txt")?.isSymlink, true);
    await assert.rejects(() => t.read("link.txt"), /symlink/);
    const h = await t.hash("link.txt");
    assert.notEqual(h.sha256, createHash("sha256").update("secret").digest("hex"), "hashes the link, not the target");
  } finally {
    await cleanup();
  }
});

test("a symlinked directory is not descended into, so it cannot lead outside the root", async () => {
  const { dir, cleanup } = await tmpDir();
  try {
    const root = path.join(dir, "site");
    const outside = path.join(dir, "outside");
    await tree(outside, { "secret.txt": "x" });
    await fs.mkdir(root);
    if (!(await link(outside, path.join(root, "escape"), "dir"))) return;
    const t = await LocalFsTransport.open(root);
    const all = await t.list("", { recursive: true });
    assert.ok(!all.some((f) => f.path.includes("secret.txt")), "nothing from outside the root is listed");
    await assert.rejects(() => t.read("escape/secret.txt"), TransportError);
    await assert.rejects(() => t.hash("escape/secret.txt"), TransportError);
  } finally {
    await cleanup();
  }
});

test("too many files fails loudly instead of returning a partial list", async () => {
  const { dir, cleanup } = await tmpDir();
  try {
    await tree(dir, { a: "1", b: "2", c: "3" });
    const t = await LocalFsTransport.open(dir);
    await assert.rejects(() => t.list("", { recursive: true, maxEntries: 2 }), /more than 2 files/);
  } finally {
    await cleanup();
  }
});
