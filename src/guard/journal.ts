/**
 * Append-only, hash-chained JSONL journal. Events, incidents, decisions and
 * (later) actions and approvals all land here, and it is the audit trail.
 *
 * Each line carries the hash of the line before it, so editing or deleting any
 * entry breaks every hash after it and verify() says exactly where.
 *
 * What the chain does NOT do on its own, stated plainly because it is the part
 * people assume:
 *
 *  - A plain SHA-256 chain can be rewritten end to end by anyone who can write
 *    the file: recompute every hash and it verifies. Pass an HMAC key (kept
 *    off the monitored host) and a forger without the key cannot continue it.
 *  - Deleting the LAST entries leaves a perfectly valid shorter chain. Catch
 *    that by anchoring head() somewhere else (a message to the owner, a second
 *    machine) and passing it back as expectedHead.
 *  - If the host holding the journal is fully compromised, neither helps. The
 *    real answer is to run the agent somewhere other than the site it watches.
 *
 * Single writer. Two processes appending to one chain would silently fork it,
 * so open() takes a lock file and refuses if a live process holds it. Separate
 * processes (the orchestrator, a future responder) each own their own journal.
 *
 * Fail closed. A journal that does not verify refuses to open, and a failed
 * write stops all further writes, rather than carrying on with a damaged trail.
 */

import { promises as fs } from "node:fs";
import type { FileHandle } from "node:fs/promises";
import path from "node:path";
import { createHash, createHmac } from "node:crypto";
import { canonicalize } from "./canonical.js";

export const GENESIS = "0".repeat(64);
const MAX_PAYLOAD_BYTES = 256 * 1024;

export interface JournalEntry {
  seq: number;
  ts: string;
  kind: string;
  prev: string;
  hash: string;
  payload: unknown;
}

export type VerifyProblem = "bad_json" | "bad_shape" | "bad_seq" | "broken_link" | "bad_hash" | "torn_tail" | "head_mismatch";

export type VerifyResult =
  | { ok: true; entries: number; head: string }
  | { ok: false; entries: number; problem: VerifyProblem; line: number; detail: string };

export interface JournalOptions {
  /** HMAC key. If set, the chain is keyed and cannot be forged without it. */
  key?: Buffer;
}

export class JournalError extends Error {}

function entryHash(key: Buffer | undefined, e: Omit<JournalEntry, "hash">): string {
  const data = `${e.seq}\n${e.ts}\n${e.kind}\n${e.prev}\n${canonicalize(e.payload)}`;
  return key
    ? createHmac("sha256", key).update(data).digest("hex")
    : createHash("sha256").update(data).digest("hex");
}

export async function verifyJournal(
  file: string,
  opts: JournalOptions & { expectedHead?: string } = {},
): Promise<VerifyResult> {
  let text: string;
  try {
    text = await fs.readFile(file, "utf8");
  } catch (e: any) {
    if (e?.code === "ENOENT") return { ok: true, entries: 0, head: GENESIS };
    throw e;
  }

  if (text.length > 0 && !text.endsWith("\n")) {
    const lines = text.split("\n").length;
    return { ok: false, entries: Math.max(0, lines - 2), problem: "torn_tail", line: lines, detail: "the file ends mid-line, which means a write was interrupted" };
  }

  const lines = text.length ? text.slice(0, -1).split("\n") : [];
  let prev = GENESIS;
  for (let i = 0; i < lines.length; i++) {
    const lineNo = i + 1;
    let e: any;
    try {
      e = JSON.parse(lines[i]);
    } catch {
      return { ok: false, entries: i, problem: "bad_json", line: lineNo, detail: "line is not valid JSON" };
    }
    if (
      !e || typeof e.seq !== "number" || typeof e.ts !== "string" || typeof e.kind !== "string" ||
      typeof e.prev !== "string" || typeof e.hash !== "string" || !("payload" in e)
    ) {
      return { ok: false, entries: i, problem: "bad_shape", line: lineNo, detail: "entry is missing required fields" };
    }
    if (e.seq !== lineNo) {
      return { ok: false, entries: i, problem: "bad_seq", line: lineNo, detail: `expected seq ${lineNo}, found ${e.seq}; an entry was removed or reordered` };
    }
    if (e.prev !== prev) {
      return { ok: false, entries: i, problem: "broken_link", line: lineNo, detail: "prev does not match the previous entry's hash" };
    }
    const expected = entryHash(opts.key, e);
    if (e.hash !== expected) {
      return { ok: false, entries: i, problem: "bad_hash", line: lineNo, detail: "hash does not match the entry contents (edited, or wrong key)" };
    }
    prev = e.hash;
  }

  if (opts.expectedHead && opts.expectedHead !== prev) {
    return { ok: false, entries: lines.length, problem: "head_mismatch", line: lines.length, detail: `head is ${prev}, expected ${opts.expectedHead}; entries were removed from the end or the chain diverged` };
  }
  return { ok: true, entries: lines.length, head: prev };
}

/** Read every entry of a journal that verifies. Throws if it does not. */
export async function readJournal(file: string, opts: JournalOptions = {}): Promise<JournalEntry[]> {
  const v = await verifyJournal(file, opts);
  if (!v.ok) throw new JournalError(`journal ${file} does not verify: ${v.problem} at line ${v.line}: ${v.detail}`);
  let text = "";
  try {
    text = await fs.readFile(file, "utf8");
  } catch (e: any) {
    if (e?.code !== "ENOENT") throw e;
  }
  return text ? text.slice(0, -1).split("\n").map((l) => JSON.parse(l) as JournalEntry) : [];
}

function pidAlive(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (e: any) {
    return e?.code === "EPERM"; // exists, just not ours
  }
}

async function acquireLock(lockPath: string): Promise<void> {
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const fh = await fs.open(lockPath, "wx");
      await fh.writeFile(String(process.pid));
      await fh.close();
      return;
    } catch (e: any) {
      if (e?.code !== "EEXIST") throw e;
      const holder = Number((await fs.readFile(lockPath, "utf8").catch(() => "")).trim());
      if (Number.isInteger(holder) && holder > 0 && pidAlive(holder)) {
        throw new JournalError(`journal is already open in another process (pid ${holder}). Two writers would fork the chain.`);
      }
      await fs.rm(lockPath, { force: true }); // stale lock from a crashed process
    }
  }
  throw new JournalError(`could not take the journal lock at ${lockPath}`);
}

export class Journal {
  private queue: Promise<unknown> = Promise.resolve();
  private broken: string | null = null;

  private constructor(
    readonly file: string,
    private readonly key: Buffer | undefined,
    private fh: FileHandle,
    private readonly lockPath: string,
    private seq: number,
    private headHash: string,
  ) {}

  static async open(file: string, opts: JournalOptions = {}): Promise<Journal> {
    await fs.mkdir(path.dirname(file), { recursive: true });
    const lockPath = `${file}.lock`;
    await acquireLock(lockPath);
    try {
      const v = await verifyJournal(file, opts);
      if (!v.ok) {
        throw new JournalError(
          `refusing to open ${file}: ${v.problem} at line ${v.line}: ${v.detail}. ` +
            `The file has been left untouched so it can be inspected as evidence.`,
        );
      }
      const fh = await fs.open(file, "a");
      return new Journal(file, opts.key, fh, lockPath, v.entries, v.head);
    } catch (e) {
      await fs.rm(lockPath, { force: true });
      throw e;
    }
  }

  /** Current position, for anchoring somewhere the monitored host cannot reach. */
  head(): { seq: number; hash: string } {
    return { seq: this.seq, hash: this.headHash };
  }

  append(kind: string, payload: unknown): Promise<JournalEntry> {
    const run = async (): Promise<JournalEntry> => {
      if (this.broken) throw new JournalError(`journal is closed to writes: ${this.broken}`);
      const body = { seq: this.seq + 1, ts: new Date().toISOString(), kind, prev: this.headHash, payload };
      const entry: JournalEntry = { ...body, hash: entryHash(this.key, body) };
      const line = JSON.stringify(entry) + "\n";
      if (Buffer.byteLength(line) > MAX_PAYLOAD_BYTES) {
        throw new JournalError(`entry of ${Buffer.byteLength(line)} bytes exceeds the ${MAX_PAYLOAD_BYTES} byte limit`);
      }
      try {
        await this.fh.write(line);
        await this.fh.datasync();
      } catch (e: any) {
        this.broken = `write failed (${e?.message ?? e}); the file may end mid-line and needs inspection`;
        throw new JournalError(this.broken);
      }
      this.seq = entry.seq;
      this.headHash = entry.hash;
      return entry;
    };
    const p = this.queue.then(run);
    this.queue = p.catch(() => undefined);
    return p;
  }

  async close(): Promise<void> {
    await this.queue.catch(() => undefined);
    await this.fh.close().catch(() => undefined);
    await fs.rm(this.lockPath, { force: true });
  }
}
