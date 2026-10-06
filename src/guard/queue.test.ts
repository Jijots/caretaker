import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { Journal, readJournal } from "./journal.js";
import { InProcessQueue } from "./queue.js";
import { ev, tmpDir } from "./testkit.js";
import type { SecurityEvent } from "./events.js";

async function rig<T>(fn: (q: InProcessQueue, j: Journal, file: string, errors: string[]) => Promise<T>): Promise<T> {
  const { dir, cleanup } = await tmpDir();
  const file = path.join(dir, "events.jsonl");
  const j = await Journal.open(file);
  const errors: string[] = [];
  const q = new InProcessQueue(j, (m) => errors.push(m));
  try {
    return await fn(q, j, file, errors);
  } finally {
    await q.close();
    await j.close();
    await cleanup();
  }
}

const kinds = async (file: string) => (await readJournal(file)).map((e) => e.kind);

test("a valid event is journaled BEFORE any subscriber sees it", () =>
  rig(async (q, _j, file) => {
    let sawInJournal = false;
    q.subscribe(async (e) => {
      sawInJournal = (await readJournal(file)).some((x) => x.kind === "event" && (x.payload as SecurityEvent).id === e.id);
    });
    const r = await q.publish(ev());
    assert.equal(r.ok, true);
    await q.drain();
    assert.equal(sawInJournal, true);
  }));

test("an invalid event never reaches a subscriber and is journaled as rejected", () =>
  rig(async (q, _j, file) => {
    const seen: string[] = [];
    q.subscribe((e) => void seen.push(e.id));
    const bad = { ...ev(), severity: "catastrophic" };
    const r = await q.publish(bad);
    await q.drain();
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.error, /severity/);
    assert.deepEqual(seen, []);
    const entries = await readJournal(file);
    assert.equal(entries.length, 1);
    assert.equal(entries[0].kind, "event_rejected");
    assert.match(JSON.stringify(entries[0].payload), /severity/);
  }));

test("garbage and non-objects are rejected cleanly, with a bounded snippet in the journal", () =>
  rig(async (q, _j, file) => {
    for (const junk of [null, undefined, 42, "hello", [], { a: 1 }, { ...ev(), summary: "x".repeat(50_000) }]) {
      assert.equal((await q.publish(junk)).ok, false);
    }
    const entries = await readJournal(file);
    assert.equal(entries.length, 7);
    assert.ok(entries.every((e) => e.kind === "event_rejected"));
    assert.ok(entries.every((e) => String((e.payload as any).raw).length <= 2000), "attacker-sized input cannot bloat the journal");
  }));

test("a worker cannot emit another worker's event type", () =>
  rig(async (q) => {
    const r = await q.publish({ ...ev(), worker: "traffic" });
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.error, /may not emit/);
  }));

test("duplicate event ids are rejected", () =>
  rig(async (q, _j, file) => {
    const e = ev();
    assert.equal((await q.publish(e)).ok, true);
    const again = await q.publish(e);
    assert.equal(again.ok, false);
    if (!again.ok) assert.match(again.error, /duplicate/);
    assert.deepEqual(await kinds(file), ["event", "event_rejected"]);
  }));

test("delivery preserves publish order, even for concurrent publishers", () =>
  rig(async (q, _j, file) => {
    const delivered: string[] = [];
    q.subscribe(async (e) => {
      await new Promise((r) => setTimeout(r, Math.random() * 3));
      delivered.push(e.id);
    });
    await Promise.all(Array.from({ length: 25 }, () => q.publish(ev())));
    await q.drain();
    const journaled = (await readJournal(file)).filter((e) => e.kind === "event").map((e) => (e.payload as SecurityEvent).id);
    assert.equal(delivered.length, 25);
    assert.deepEqual(delivered, journaled, "delivered in exactly the order the journal recorded");
  }));

test("a failing subscriber is recorded and does not stop the others", () =>
  rig(async (q, _j, file, errors) => {
    const got: string[] = [];
    q.subscribe(() => { throw new Error("boom"); });
    q.subscribe((e) => void got.push(e.id));
    await q.publish(ev());
    await q.publish(ev());
    await q.drain();
    assert.equal(got.length, 2);
    assert.equal(errors.length, 2);
    assert.match(errors[0], /boom/);
    assert.equal((await kinds(file)).filter((k) => k === "handler_error").length, 2);
  }));

test("unsubscribe stops delivery", () =>
  rig(async (q) => {
    let n = 0;
    const off = q.subscribe(() => void n++);
    await q.publish(ev());
    await q.drain();
    off();
    await q.publish(ev());
    await q.drain();
    assert.equal(n, 1);
  }));

test("drain waits for a slow asynchronous subscriber", () =>
  rig(async (q) => {
    let done = false;
    q.subscribe(async () => {
      await new Promise((r) => setTimeout(r, 40));
      done = true;
    });
    await q.publish(ev());
    assert.equal(done, false, "publish returns once the event is durable, not once it is processed");
    await q.drain();
    assert.equal(done, true);
  }));

test("a closed queue accepts nothing", () =>
  rig(async (q) => {
    await q.close();
    const r = await q.publish(ev());
    assert.equal(r.ok, false);
  }));
