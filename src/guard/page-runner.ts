/**
 * Starts the Page watcher for every site that has page baselines, on each
 * site's own interval. Same rules as the Integrity runner (runner.ts): it never
 * crashes the process, it never watches against a baseline that fails
 * verification, and it says why a site is not being watched.
 *
 * One browser is shared by every site and launched only if something needs it,
 * so a machine without Chromium still runs the Integrity watcher. If Chromium
 * cannot start, the Page watcher is off for every site and the journal says so.
 */

import { BaselineError } from "./baseline.js";
import { BrowserUnavailableError, launchBrowser } from "./browser.js";
import type { SiteConfig } from "./config.js";
import type { Journal } from "./journal.js";
import { PageBaselineStore } from "./page-baseline.js";
import type { PageFetcher } from "./page-digest.js";
import { PageWatcher, type LoadedPageBaseline } from "./page-watcher.js";
import type { EventQueue } from "./queue.js";
import type { StartedWorkers } from "./runner.js";

export interface PageRunnerOptions {
  sites: Map<string, SiteConfig>;
  queue: EventQueue;
  journal: Journal;
  store: PageBaselineStore;
  log: (message: string) => void;
  warn: (message: string) => void;
  /** Replaceable for tests. */
  launch?: () => Promise<PageFetcher>;
}

export async function preparePageWorkers(o: PageRunnerOptions): Promise<StartedWorkers> {
  const skipped: { siteId: string; reason: string }[] = [];
  const candidates: { site: SiteConfig; baselines: Map<string, LoadedPageBaseline> }[] = [];

  for (const site of o.sites.values()) {
    const skip = async (reason: string, journalIt = false) => {
      skipped.push({ siteId: site.id, reason });
      o.warn(`${site.id}: page watcher not started: ${reason}`);
      if (journalIt) await o.journal.append("worker_unavailable", { siteId: site.id, worker: "page", reason });
    };
    const baselines = new Map<string, LoadedPageBaseline>();
    let broken = false;
    for (const p of site.pages) {
      try {
        const b = await o.store.load(site.id, p);
        if (b) baselines.set(p, b);
      } catch (e) {
        if (e instanceof BaselineError) {
          await skip(e.message, true);
          broken = true;
          break;
        }
        throw e;
      }
    }
    if (broken) continue;
    if (!baselines.size) {
      await skip(`no page baseline yet. Run: npm run caretaker -- baseline snapshot ${site.id}`);
      continue;
    }
    const missing = site.pages.filter((p) => !baselines.has(p));
    if (missing.length) o.warn(`${site.id}: ${missing.length} page(s) have no baseline and are not watched: ${missing.slice(0, 3).join(", ")}`);
    candidates.push({ site, baselines });
  }

  let fetcher: PageFetcher | null = null;
  let watchers: { site: SiteConfig; watcher: PageWatcher }[] = [];
  if (candidates.length) {
    try {
      fetcher = await (o.launch ?? launchBrowser)();
      const f = fetcher;
      watchers = candidates.map((c) => ({ site: c.site, watcher: new PageWatcher({ site: c.site, fetcher: f, baselines: c.baselines }) }));
    } catch (e: any) {
      const reason = e instanceof BrowserUnavailableError ? e.message : `the browser failed to start: ${String(e?.message ?? e).slice(0, 200)}`;
      for (const c of candidates) {
        skipped.push({ siteId: c.site.id, reason });
        await o.journal.append("worker_unavailable", { siteId: c.site.id, worker: "page", reason });
      }
      o.warn(`page watcher not started for ${candidates.length} site(s): ${reason}`);
    }
  }

  const timers = new Map<string, NodeJS.Timeout>();
  const running = new Set<string>();
  let stopped = false;

  const pass = async (site: SiteConfig, watcher: PageWatcher): Promise<void> => {
    if (running.has(site.id)) return;
    running.add(site.id);
    try {
      const r = await watcher.runOnce();
      for (const e of r.events) {
        const res = await o.queue.publish(e);
        if (!res.ok) o.warn(`${site.id}: page event rejected: ${res.error}`);
      }
      for (const f of r.failed) o.warn(`${site.id}: could not load ${f.path}: ${f.error}`);
      o.log(`${site.id}: page pass: ${r.pagesChecked} page(s), ${r.events.length} event(s)`);
    } catch (e: any) {
      o.warn(`${site.id}: page pass failed: ${e?.message ?? e}`);
      await o.journal.append("worker_error", { siteId: site.id, worker: "page", error: String(e?.message ?? e).slice(0, 500) }).catch(() => undefined);
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
            if (!stopped) timers.set(w.site.id, setTimeout(tick, w.site.page.intervalSeconds * 1000));
          });
        };
        tick();
      }
    },
    async stop() {
      stopped = true;
      for (const t of timers.values()) clearTimeout(t);
      timers.clear();
      await fetcher?.close();
    },
  };
}
