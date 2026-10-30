/**
 * The Integrity watcher. Compares a site's files with its baseline and checks
 * upload directories for anything that could execute. Deterministic, no LLM,
 * and handed only the read-only SiteTransport.
 *
 * Cost control: a pass trusts a file's (size, mtime, ctime) to skip rehashing,
 * except on every Nth pass (integrity.fullRehashEvery) when everything is
 * rehashed. mtime alone is not enough, since an attacker can set it back, but
 * ctime cannot be set by an ordinary user, and the periodic full pass is the
 * backstop for the rest.
 *
 * Noise control: a difference is reported once, when it first appears or when
 * the file changes again, not on every pass. Otherwise one defaced file would
 * produce an event every five minutes for as long as it stayed that way. A
 * difference that goes away (the file was restored) is forgotten, so it is
 * reported again if it returns.
 */

import path from "node:path";
import { effectiveIntegrityRules, type SiteConfig } from "./config.js";
import { createEvent, type SecurityEvent } from "./events.js";
import { matchesAny } from "./glob.js";
import type { BaselineBody } from "./baseline.js";
import type { FileEntry, SiteTransport } from "./transport.js";

/** Extensions that a web server may execute. Matched on every dot-separated segment, to catch shell.php.jpg. */
export const EXECUTABLE_EXTENSIONS = new Set([
  "php", "php3", "php4", "php5", "php7", "php8", "phtml", "phar", "pht", "phps", "inc",
  "asp", "aspx", "ashx", "asmx", "cer", "jsp", "jspx", "jsw", "cgi", "pl", "py", "pyw", "pyc", "sh", "bash",
]);

/** Files that change what the server does with other files, wherever they appear in an upload directory. */
const SERVER_CONFIG_NAMES = new Set([".htaccess", ".user.ini", "web.config", ".htpasswd"]);

/** Entry points: replacing one is how most defacements happen, so a change here is rated higher. */
// Django's equivalents: the file that wires URLs to code, the settings, and the two server entry points.
const ENTRY_POINT = /^(index\.(php|html?|js)|\.htaccess|\.user\.ini|wp-config\.php|wp-settings\.php|default\.(php|html?)|home\.(php|html?)|manage\.py|settings\.py|urls\.py|wsgi\.py|asgi\.py)$/i;

const MAX_EVENTS_PER_TYPE = 25;
const SNIFF_BYTES = 4096;
const SNIFF_MARKERS = [/<\?php/i, /<\?=/, /<script[\s>]/i, /\beval\s*\(/i, /\bbase64_decode\s*\(/i];

export function looksExecutableName(name: string): boolean {
  const base = path.posix.basename(name);
  if (SERVER_CONFIG_NAMES.has(base.toLowerCase())) return true;
  return base
    .toLowerCase()
    .split(".")
    .slice(1)
    .some((seg) => EXECUTABLE_EXTENSIONS.has(seg));
}

interface Fingerprint {
  size: number;
  mtimeMs: number;
  ctimeMs: number;
  sha256: string;
}

export interface PassResult {
  events: SecurityEvent[];
  filesChecked: number;
  rehashed: number;
  /** Differences that exist but were already reported, so were not re-emitted. */
  suppressed: number;
  unreadable: string[];
  fullRehash: boolean;
}

export interface IntegrityOptions {
  site: SiteConfig;
  transport: SiteTransport;
  baseline: BaselineBody;
  now?: () => Date;
}

const sameStat = (a: Fingerprint, f: FileEntry): boolean => a.size === f.size && a.mtimeMs === f.mtimeMs && a.ctimeMs === f.ctimeMs;

export class IntegrityWatcher {
  private readonly rules;
  private seen = new Map<string, Fingerprint>(); // fingerprint cache for every file we hashed
  private reported = new Map<string, string>(); // path -> "<kind>:<sha or ->" already emitted
  private passes = 0;

  constructor(private readonly o: IntegrityOptions) {
    this.rules = effectiveIntegrityRules(o.site);
  }

  async runOnce(): Promise<PassResult> {
    const { site, transport, baseline } = this.o;
    const rules = this.rules;
    const full = this.passes % site.integrity.fullRehashEvery === 0;
    this.passes++;

    const unreadable: string[] = [];
    const listed = await transport.list("", {
      recursive: true,
      maxEntries: site.integrity.maxFiles,
      skipDir: (rel) => matchesAny(rel, rules.exclude),
      onUnreadable: (rel) => unreadable.push(rel),
    });

    const stamp = (this.o.now?.() ?? new Date()).toISOString();
    const events: { kind: string; ev: () => SecurityEvent; key: string; state: string }[] = [];
    const present = new Set<string>();
    let rehashed = 0;
    let checked = 0;

    for (const f of listed) {
      if (matchesAny(f.path, rules.exclude)) continue;
      const inUploads = matchesAny(f.path, rules.uploadDirs);
      if (!inUploads && !matchesAny(f.path, rules.include)) continue;
      present.add(f.path);
      checked++;

      const cached = this.seen.get(f.path);
      let sha: string;
      if (cached && !full && sameStat(cached, f)) {
        sha = cached.sha256;
      } else {
        try {
          sha = (await transport.hash(f.path)).sha256;
        } catch (e: any) {
          if (e?.code === "ENOENT") continue;
          unreadable.push(f.path);
          continue;
        }
        rehashed++;
        this.seen.set(f.path, { size: f.size, mtimeMs: f.mtimeMs, ctimeMs: f.ctimeMs, sha256: sha });
      }

      if (inUploads) {
        const changedSinceLast = !cached || cached.sha256 !== sha;
        await this.checkUpload(f, sha, changedSinceLast, stamp, events);
        continue;
      }

      const base = baseline.files[f.path];
      if (!base) {
        events.push({
          kind: "added", key: f.path, state: `added:${sha}`,
          ev: () => createEvent({
            siteId: site.id, type: "integrity.file_added", severity: "medium", confidence: 0.6, timestamp: stamp,
            summary: `new file ${f.path}`,
            evidence: { path: f.path, sha256: sha, size: f.size },
            indicators: { paths: [f.path], fileHashes: [sha] },
          }),
        });
      } else if (base.sha256 !== sha) {
        const entry = ENTRY_POINT.test(path.posix.basename(f.path));
        events.push({
          kind: "changed", key: f.path, state: `changed:${sha}`,
          ev: () => createEvent({
            siteId: site.id, type: "integrity.file_changed", severity: entry ? "critical" : "high", confidence: entry ? 0.85 : 0.75, timestamp: stamp,
            summary: `${f.path} differs from the baseline${entry ? " (entry point)" : ""}`,
            evidence: { path: f.path, baselineSha256: base.sha256, currentSha256: sha, baselineSize: base.size, currentSize: f.size, restorable: base.stored },
            indicators: { paths: [f.path], fileHashes: [sha] },
          }),
        });
      }
    }

    // Removed: in the baseline, absent now. Only judged where the listing was complete.
    const blind = (p: string) => unreadable.some((u) => p === u || p.startsWith(`${u}/`));
    for (const [p, base] of Object.entries(baseline.files)) {
      if (present.has(p) || blind(p) || matchesAny(p, rules.exclude)) continue;
      if (await transport.stat(p).then((s) => s !== null, () => true)) continue; // still there, or cannot tell
      const entry = ENTRY_POINT.test(path.posix.basename(p));
      events.push({
        kind: "removed", key: p, state: "removed:-",
        ev: () => createEvent({
          siteId: site.id, type: "integrity.file_removed", severity: entry ? "critical" : "medium", confidence: entry ? 0.8 : 0.5, timestamp: stamp,
          summary: `${p} is missing${entry ? " (entry point)" : ""}`,
          evidence: { path: p, baselineSha256: base.sha256, restorable: base.stored },
          indicators: { paths: [p], fileHashes: [base.sha256] },
        }),
      });
    }

    // Forget differences that are gone, so they are reported afresh if they come back.
    const live = new Set(events.map((e) => `${e.kind}|${e.key}`));
    for (const k of [...this.reported.keys()]) if (!live.has(k)) this.reported.delete(k);
    for (const p of [...this.seen.keys()]) if (!present.has(p)) this.seen.delete(p);

    const out: SecurityEvent[] = [];
    const perType = new Map<string, number>();
    let suppressed = 0;
    for (const e of events) {
      const rk = `${e.kind}|${e.key}`;
      if (this.reported.get(rk) === e.state) {
        suppressed++;
        continue;
      }
      this.reported.set(rk, e.state);
      const ev = e.ev();
      const n = (perType.get(ev.type) ?? 0) + 1;
      perType.set(ev.type, n);
      if (n <= MAX_EVENTS_PER_TYPE) out.push(ev);
    }
    // A flood is itself a signal, and silently dropping the tail would hide it.
    for (const [type, n] of perType) {
      if (n > MAX_EVENTS_PER_TYPE) {
        out.push(createEvent({
          siteId: site.id, type: type as SecurityEvent["type"], severity: "high", confidence: 0.8, timestamp: stamp,
          summary: `${n - MAX_EVENTS_PER_TYPE} more ${type} not itemised (${n} in this pass)`,
          evidence: { total: n, itemised: MAX_EVENTS_PER_TYPE },
        }));
      }
    }

    return { events: out, filesChecked: checked, rehashed, suppressed, unreadable: [...new Set(unreadable)].slice(0, 50), fullRehash: full };
  }

  private async checkUpload(
    f: FileEntry, sha: string, changed: boolean, stamp: string,
    events: { kind: string; ev: () => SecurityEvent; key: string; state: string }[],
  ): Promise<void> {
    const { site, transport } = this.o;
    let reason = looksExecutableName(f.path) ? "executable or server-config file name" : "";
    if (!reason && changed && f.size > 0 && !f.isSymlink) {
      try {
        const head = (await transport.read(f.path, { maxBytes: SNIFF_BYTES })).toString("latin1");
        if (SNIFF_MARKERS.some((m) => m.test(head))) reason = "script content inside a file that is not named like one";
      } catch {
        /* unreadable here is reported by the listing, not by the sniff */
      }
    }
    if (!reason) return;
    events.push({
      kind: "upload-exec", key: f.path, state: `upload-exec:${sha}`,
      ev: () => createEvent({
        siteId: site.id, type: "integrity.executable_in_uploads", severity: "critical", confidence: 0.9, timestamp: stamp,
        summary: `${f.path} in an upload directory: ${reason}`,
        evidence: { path: f.path, sha256: sha, size: f.size, reason },
        indicators: { paths: [f.path], fileHashes: [sha] },
      }),
    });
  }
}
