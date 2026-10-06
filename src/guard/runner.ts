/**
 * Starts the detection workers and feeds their events to the queue. Phase 2
 * has one worker, Integrity. It runs on its own timer per site and never
 * crashes the process: a failing pass is logged and tried again next interval.
 *
 * Fail closed on the baseline. A baseline that does not verify means the
 * definition of "normal" cannot be trusted, so that site is NOT watched, the
 * reason is written to the journal, and the operator is told. Watching against
 * a tampered baseline would report nonsense or, worse, report nothing.
 */

import { BaselineError, type BaselineStore } from "./baseline.js";
import type { SiteConfig } from "./config.js";
import { IntegrityWatcher, type PassResult } from "./integrity.js";
import type { Journal } from "./journal.js";
import type { EventQueue } from "./queue.js";
import { LocalFsTransport } from "./transport-local.js";

export interface RunnerOptions {
  sites: Map<string, SiteConfig>;
  queue: EventQueue;
  journal: Journal;
  store: BaselineStore;
  log: (message: string) => void;
  warn: (message: string) => void;
}

export interface StartedWorkers {
  /** Sites actually being watched, and why the others are not. */
  watching: string[];
  skipped: { siteId: string; reason: string }[];
  /** One immediate pass for every watched site, then resolves. */
  passOnce(): Promise<void>;
  start(): void;
  stop(): void;
}

export async function prepareIntegrityWorkers(o: RunnerOptions): Promise<StartedWorkers> {
  const watchers: { site: SiteConfig; watcher: IntegrityWatcher }[] = [];
  const skipped: { siteId: string; reason: string }[] = [];

  for (const site of o.sites.values()) {
    const skip = async (reason: string, journalIt = false) => {
      skipped.push({ siteId: site.id, reason });
      o.warn(`${site.id}: integrity watcher not started: ${reason}`);
      if (journalIt) await o.journal.append("worker_unavailable", { siteId: site.id, worker: "integrity", reason });
    };
    if (site.transport.type !== "local-fs") {
      await skip(`transport '${site.transport.type}' cannot be read, so there are no files to compare`);
      continue;
    }
    let baseline;
    try {
      baseline = await o.store.load(site.id);
    } catch (e) {
      if (e instanceof BaselineError) {
        await skip(`${e.message}`, true);
        continue;
      }
      throw e;
    }
    if (!baseline) {
      await skip(`no baseline yet. Run: npm run caretaker -- baseline snapshot ${site.id}`);
      continue;
    }
    let transport;
    try {
      transport = await LocalFsTransport.open(site.transport.root);
    } catch (e: any) {
      await skip(e?.message ?? String(e), true);
      continue;
    }
    watchers.push({ site, watcher: new IntegrityWatcher({ site, transport, baseline }) });
  }

  const timers = new Map<string, NodeJS.Timeout>();
  let stopped = false;
  const running = new Set<string>();

  const pass = async (site: SiteConfig, watcher: IntegrityWatcher): Promise<void> => {
    if (running.has(site.id)) return; // a slow pass is never overlapped by the next one
    running.add(site.id);
    try {
      const r: PassResult = await watcher.runOnce();
      for (const e of r.events) {
        const res = await o.queue.publish(e);
        if (!res.ok) o.warn(`${site.id}: integrity event rejected: ${res.error}`);
      }
      if (r.unreadable.length) o.warn(`${site.id}: ${r.unreadable.length} path(s) could not be read, e.g. ${r.unreadable[0]}`);
      o.log(`${site.id}: integrity pass${r.fullRehash ? " (full)" : ""}: ${r.filesChecked} files, ${r.rehashed} hashed, ${r.events.length} event(s)`);
    } catch (e: any) {
      o.warn(`${site.id}: integrity pass failed: ${e?.message ?? e}`);
      await o.journal.append("worker_error", { siteId: site.id, worker: "integrity", error: String(e?.message ?? e).slice(0, 500) }).catch(() => undefined);
    } finally {
      running.delete(site.id);
    }
  };

  return {
    watching: watchers.map((w) => w.site.id),
    skipped,
    async passOnce() {
      for (const w of watchers) await pass(w.site, w.watcher);
      await o.queue.drain();
    },
    start() {
      for (const w of watchers) {
        const tick = () => {
          if (stopped) return;
          void pass(w.site, w.watcher).finally(() => {
            if (!stopped) timers.set(w.site.id, setTimeout(tick, w.site.integrity.intervalSeconds * 1000));
          });
        };
        tick();
      }
    },
    stop() {
      stopped = true;
      for (const t of timers.values()) clearTimeout(t);
      timers.clear();
    },
  };
}
