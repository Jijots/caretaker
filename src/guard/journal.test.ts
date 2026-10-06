import test from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { GENESIS, Journal, JournalError, readJournal, verifyJournal } from "./journal.js";
import { canonicalize } from "./canonical.js";
import { tmpDir } from "./testkit.js";

async function withJournal<T>(fn: (file: string, dir: string) => Promise<T>): Promise<T> {
  const { dir, cleanup } = await tmpDir();
  try {
    return await fn(path.join(dir, "events.jsonl"), dir);
  } finally {
    await cleanup();
  }
}

async function seed(file: string, n: number, key?: Buffer) {
  const j = await Journal.open(file, { key });
  for (let i = 1; i <= n; i++) await j.append("event", { n: i });
  const head = j.head();
  await j.close();
  return head;
}

const lines = async (f: string) => (await fs.readFile(f, "utf8")).slice(0, -1).split("\n");
const write = (f: string, ls: string[]) => fs.writeFile(f, ls.join("\n") + "\n");

test("a missing file is a valid empty journal", () =>
  withJournal(async (file) => {
    assert.deepEqual(await verifyJournal(file), { ok: true, entries: 0, head: GENESIS });
  }));

test("appends chain together, verify, and survive a reopen", () =>
  withJournal(async (file) => {
    const head = await seed(file, 5);
    const v = await verifyJournal(file);
    assert.deepEqual(v, { ok: true, entries: 5, head: head.hash });
    const j = await Journal.open(file);
    assert.equal(j.head().seq, 5);
    const e = await j.append("event", { n: 6 });
    assert.equal(e.seq, 6);
    assert.equal(e.prev, head.hash);
    await j.close();
    assert.equal((await readJournal(file)).length, 6);
  }));

test("editing a payload is detected at the edited line", () =>
  withJournal(async (file) => {
    await seed(file, 4);
    const ls = await lines(file);
    const e = JSON.parse(ls[1]);
    e.payload.n = 999;
    ls[1] = JSON.stringify(e);
    await write(file, ls);
    const v = await verifyJournal(file);
    assert.equal(v.ok, false);
    if (!v.ok) assert.deepEqual([v.problem, v.line], ["bad_hash", 2]);
  }));

test("deleting a middle entry is detected", () =>
  withJournal(async (file) => {
    await seed(file, 5);
    const ls = await lines(file);
    ls.splice(2, 1);
    await write(file, ls);
    const v = await verifyJournal(file);
    assert.equal(v.ok, false);
    if (!v.ok) assert.deepEqual([v.problem, v.line], ["bad_seq", 3]);
  }));

test("swapping two entries is detected", () =>
  withJournal(async (file) => {
    await seed(file, 4);
    const ls = await lines(file);
    [ls[1], ls[2]] = [ls[2], ls[1]];
    await write(file, ls);
    assert.equal((await verifyJournal(file)).ok, false);
  }));

test("an entry that rewrites its own history cannot hide: fixing one hash breaks the next link", () =>
  withJournal(async (file) => {
    await seed(file, 3);
    const ls = await lines(file);
    const e = JSON.parse(ls[0]);
    e.payload.n = 111;
    e.hash = createHash("sha256").update(`${e.seq}\n${e.ts}\n${e.kind}\n${e.prev}\n${canonicalize(e.payload)}`).digest("hex");
    ls[0] = JSON.stringify(e);
    await write(file, ls);
    const v = await verifyJournal(file);
    assert.equal(v.ok, false);
    if (!v.ok) assert.deepEqual([v.problem, v.line], ["broken_link", 2]);
  }));

test("deleting entries from the END is only caught when the head was anchored elsewhere", () =>
  withJournal(async (file) => {
    const head = await seed(file, 5);
    const ls = await lines(file);
    await write(file, ls.slice(0, 3));
    assert.equal((await verifyJournal(file)).ok, true, "a shorter chain is still a valid chain, which is the honest limit");
    const v = await verifyJournal(file, { expectedHead: head.hash });
    assert.equal(v.ok, false);
    if (!v.ok) assert.equal(v.problem, "head_mismatch");
    assert.equal((await verifyJournal(await (async () => { await write(file, ls); return file; })(), { expectedHead: head.hash })).ok, true);
  }));

test("a torn final line is reported, and open() refuses without touching the file", () =>
  withJournal(async (file) => {
    await seed(file, 3);
    await fs.appendFile(file, '{"seq":4,"ts":"2026-');
    const before = await fs.readFile(file, "utf8");
    const v = await verifyJournal(file);
    assert.equal(v.ok, false);
    if (!v.ok) assert.equal(v.problem, "torn_tail");
    await assert.rejects(() => Journal.open(file), /refusing to open.*torn_tail.*left untouched/);
    assert.equal(await fs.readFile(file, "utf8"), before, "the damaged file is preserved as evidence");
  }));

test("a corrupt journal refuses to open and does not leave a stale lock behind", () =>
  withJournal(async (file) => {
    await seed(file, 3);
    const ls = await lines(file);
    ls[1] = ls[1].replace('"n":2', '"n":22');
    await write(file, ls);
    await assert.rejects(() => Journal.open(file), /refusing to open.*bad_hash/);
    await assert.rejects(() => Journal.open(file), /refusing to open.*bad_hash/, "second attempt fails on corruption, not on a leftover lock");
    await assert.rejects(() => fs.stat(`${file}.lock`), /ENOENT/);
  }));

test("two writers cannot share one journal", () =>
  withJournal(async (file) => {
    const a = await Journal.open(file);
    await assert.rejects(() => Journal.open(file), (e: Error) => e instanceof JournalError && /already open in another process/.test(e.message));
    await a.close();
    const b = await Journal.open(file);
    await b.close();
  }));

test("a stale lock left by a dead process is taken over", () =>
  withJournal(async (file) => {
    const child = spawn(process.execPath, ["-e", "0"]);
    const dead = await new Promise<number>((res) => child.on("exit", () => res(child.pid!)));
    await fs.writeFile(`${file}.lock`, String(dead));
    const j = await Journal.open(file);
    await j.append("event", { ok: true });
    await j.close();
  }));

test("100 concurrent appends produce one clean, ordered chain", () =>
  withJournal(async (file) => {
    const j = await Journal.open(file);
    const entries = await Promise.all(Array.from({ length: 100 }, (_, i) => j.append("event", { i })));
    await j.close();
    assert.deepEqual(entries.map((e) => e.seq), Array.from({ length: 100 }, (_, i) => i + 1));
    assert.equal((await verifyJournal(file)).ok, true);
  }));

test("an oversized entry is rejected and the journal stays usable", () =>
  withJournal(async (file) => {
    const j = await Journal.open(file);
    await assert.rejects(() => j.append("event", { blob: "x".repeat(300_000) }), /exceeds the .* limit/);
    const e = await j.append("event", { fine: true });
    assert.equal(e.seq, 1, "the rejected entry consumed no sequence number");
    await j.close();
    assert.equal((await verifyJournal(file)).ok, true);
  }));

const KEY = Buffer.from("k".repeat(40));

test("a keyed chain verifies only with the right key", () =>
  withJournal(async (file) => {
    await seed(file, 3, KEY);
    assert.equal((await verifyJournal(file, { key: KEY })).ok, true);
    assert.equal((await verifyJournal(file)).ok, false, "unkeyed verification fails");
    assert.equal((await verifyJournal(file, { key: Buffer.from("z".repeat(40)) })).ok, false, "wrong key fails");
  }));

test("an attacker who can write the file but lacks the key cannot forge a keyed chain", () =>
  withJournal(async (file) => {
    await seed(file, 3, KEY);
    // Rewrite the whole file as a perfectly consistent PLAIN sha-256 chain with the evidence changed.
    let prev = GENESIS;
    const forged: string[] = [];
    for (let seq = 1; seq <= 3; seq++) {
      const body = { seq, ts: new Date().toISOString(), kind: "event", prev, payload: { n: seq, forged: true } };
      const hash = createHash("sha256").update(`${seq}\n${body.ts}\n${body.kind}\n${prev}\n${canonicalize(body.payload)}`).digest("hex");
      forged.push(JSON.stringify({ ...body, hash }));
      prev = hash;
    }
    await write(file, forged);
    assert.equal((await verifyJournal(file)).ok, true, "the same forgery fully fools an UNKEYED verifier");
    const v = await verifyJournal(file, { key: KEY });
    assert.equal(v.ok, false, "but not a keyed one");
    if (!v.ok) assert.equal(v.problem, "bad_hash");
  }));

test("readJournal refuses to return entries from a journal that does not verify", () =>
  withJournal(async (file) => {
    await seed(file, 2);
    const ls = await lines(file);
    ls[0] = ls[0].replace('"n":1', '"n":7');
    await write(file, ls);
    await assert.rejects(() => readJournal(file), /does not verify/);
  }));
