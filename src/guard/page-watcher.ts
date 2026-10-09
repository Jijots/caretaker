/**
 * The Page watcher. Loads each watched page in a real browser, compares what
 * visitors would see with the page's baseline, and emits events. Deterministic,
 * no LLM, and it only ever loads URLs under the site's own baseUrl.
 *
 * What counts as evidence, and how strongly:
 *   defacement phrase new since the baseline   strong 0.97, weak 0.6
 *   hidden iframe that was not there           0.85 (a visible new frame 0.6)
 *   script from an origin the baseline never saw   0.75
 *   redirect to another origin, meta refresh   0.7
 *   text switched to another writing system    0.7
 *   share of text blocks changed               0.4 to 0.9, by how much changed
 *   share of pixels changed                    0.45 to 0.75, weakest of all
 * Pixels are weakest because ordinary content (a photo carousel, a new product)
 * moves them. Nothing here is a verdict: the orchestrator weighs these together
 * and a deploy window can explain only the ones that are deploy-explainable.
 *
 * Like the Integrity watcher, a difference is reported once, again if it
 * changes, and forgotten once the page matches again.
 */

import { effectivePageRegions, type SiteConfig } from "./config.js";
import { createEvent, type SecurityEvent } from "./events.js";
import { diffPng } from "./pixel.js";
import {
  SIGNALS, customSignals, digestPage, findSignals, sha256, textChange,
  type PageDigest, type PageFetcher, type SignalDef,
} from "./page-digest.js";
import type { PageBaselineBody } from "./page-baseline.js";

export interface LoadedPageBaseline {
  body: PageBaselineBody;
  png: Buffer | null;
}

export interface PageWatcherOptions {
  site: SiteConfig;
  fetcher: PageFetcher;
  baselines: Map<string, LoadedPageBaseline>;
  now?: () => Date;
}

export interface PageResult {
  events: SecurityEvent[];
  pagesChecked: number;
  suppressed: number;
  failed: { path: string; error: string }[];
}

interface Candidate {
  key: string;
  state: string;
  ev: () => SecurityEvent;
}

const clamp = (n: number, lo: number, hi: number) => Math.min(hi, Math.max(lo, n));
const round3 = (n: number) => Math.round(n * 1000) / 1000;
const clip = (s: string, n = 200) => s.slice(0, n);

export class PageWatcher {
  private readonly siteOrigin: string;
  private readonly defs: SignalDef[];
  private readonly extra: SignalDef[];
  private reported = new Map<string, string>();

  constructor(private readonly o: PageWatcherOptions) {
    this.siteOrigin = new URL(o.site.baseUrl).origin;
    this.extra = customSignals(o.site.page.extraSignals);
    this.defs = [...SIGNALS, ...this.extra];
  }

  async runOnce(): Promise<PageResult> {
    const { site, fetcher, baselines } = this.o;
    const stamp = (this.o.now?.() ?? new Date()).toISOString();
    const candidates: Candidate[] = [];
    const failed: { path: string; error: string }[] = [];
    const checkedPaths = new Set<string>();
    let checked = 0;

    for (const [pagePath, base] of baselines) {
      const hide = effectivePageRegions(site, pagePath);
      let digest: PageDigest;
      let png: Buffer | null = null;
      try {
        const raw = await fetcher.fetch(new URL(pagePath, site.baseUrl).toString(), { hideSelectors: hide, screenshot: base.png !== null });
        digest = digestPage(raw, this.siteOrigin, this.extra);
        png = raw.png;
      } catch (e: any) {
        failed.push({ path: pagePath, error: String(e?.message ?? e).slice(0, 300) });
        continue; // a page that would not load is not evidence about its content, and its history is kept
      }
      checked++;
      checkedPaths.add(pagePath);
      candidates.push(...this.compare(pagePath, base, digest, png, stamp));
    }

    // Forget differences that are gone, on pages we actually reached.
    const live = new Set(candidates.map((c) => c.key));
    for (const k of [...this.reported.keys()]) {
      const p = k.slice(k.indexOf("|") + 1); // the kind has no "|", the path might
      if (checkedPaths.has(p) && !live.has(k)) this.reported.delete(k);
    }

    const events: SecurityEvent[] = [];
    let suppressed = 0;
    for (const c of candidates) {
      if (this.reported.get(c.key) === c.state) {
        suppressed++;
        continue;
      }
      this.reported.set(c.key, c.state);
      events.push(c.ev());
    }
    return { events, pagesChecked: checked, suppressed, failed };
  }

  private compare(pagePath: string, base: LoadedPageBaseline, cur: PageDigest, png: Buffer | null, stamp: string): Candidate[] {
    const { site } = this.o;
    const b = base.body;
    const allowed = new Set(site.page.allowedOrigins);
    const out: Candidate[] = [];
    const indicators = { paths: [pagePath] };
    const mk = (kind: string, state: string, make: () => SecurityEvent): Candidate => ({ key: `${kind}|${pagePath}`, state, ev: make });

    // 1. Where the page ends up.
    const movedAway = cur.finalOrigin !== b.finalOrigin;
    const metaAway = cur.metaRefreshOrigin !== null && cur.metaRefreshOrigin !== this.siteOrigin && !allowed.has(cur.metaRefreshOrigin);
    if (movedAway || metaAway) {
      const to = movedAway ? cur.finalOrigin || "(unparseable)" : (cur.metaRefreshOrigin as string);
      out.push(mk("redirect", `redirect:${movedAway ? "navigation" : "meta"}:${to}`, () => createEvent({
        siteId: site.id, type: "page.defacement_signal", severity: "high", confidence: 0.7, timestamp: stamp, indicators,
        summary: `${pagePath} sends visitors to ${clip(to, 100)}`,
        evidence: { path: pagePath, signal: movedAway ? "redirect to another origin" : "meta refresh to another origin", expectedOrigin: b.finalOrigin, actualOrigin: to },
      })));
    }

    // 2. Defacement phrases that were not there before.
    const hits = findSignals([cur.title, ...cur.texts].join("\n"), this.defs).filter((s) => !b.signals.includes(s.id));
    if (hits.length) {
      const strong = hits.some((h) => h.strength === "strong");
      out.push(mk("signal", `signal:${hits.map((h) => h.id).sort().join(",")}`, () => createEvent({
        siteId: site.id, type: "page.defacement_signal", severity: strong ? "critical" : "medium", confidence: strong ? 0.97 : 0.6, timestamp: stamp, indicators,
        summary: `${pagePath} contains ${strong ? "a defacement phrase" : "a phrase sometimes left by defacers"}: ${hits.map((h) => h.id).join(", ")}`,
        evidence: { path: pagePath, signals: hits.map((h) => h.id), snippet: hits[0].snippet, strength: strong ? "strong" : "weak" },
      })));
    }

    // 3. The page switched writing system.
    if (b.dominantScript !== "unknown" && cur.dominantScript !== "unknown" && b.dominantScript !== cur.dominantScript) {
      out.push(mk("script", `script:${cur.dominantScript}`, () => createEvent({
        siteId: site.id, type: "page.defacement_signal", severity: "high", confidence: 0.7, timestamp: stamp, indicators,
        summary: `${pagePath} text changed from ${b.dominantScript} to ${cur.dominantScript} script`,
        evidence: { path: pagePath, signal: "writing system changed", was: b.dominantScript, now: cur.dominantScript },
      })));
    }

    // 4. Scripts from origins nobody had seen.
    const knownScripts = new Set([...b.scriptOrigins, ...allowed]);
    const newScripts = cur.scriptOrigins.filter((o) => !knownScripts.has(o));
    if (newScripts.length) {
      out.push(mk("script-origin", `scripts:${newScripts.join(",")}`, () => createEvent({
        siteId: site.id, type: "page.external_script_added", severity: "high", confidence: 0.75, timestamp: stamp, indicators,
        summary: `${pagePath} loads code from ${newScripts.length} new origin(s): ${clip(newScripts.slice(0, 3).join(", "), 150)}`,
        evidence: { path: pagePath, origins: newScripts.slice(0, 10).map((o) => clip(o, 300)), count: newScripts.length },
      })));
    }

    // 5. Frames that were not there.
    const knownFrameKeys = new Set(b.iframes.map((f) => f.key));
    const trustedFrameOrigins = new Set([this.siteOrigin, ...b.iframes.map((f) => f.origin), ...allowed]);
    const newFrames = cur.iframes.filter((f) => !knownFrameKeys.has(f.key) && (f.hidden || !trustedFrameOrigins.has(f.origin)));
    if (newFrames.length) {
      const hidden = newFrames.some((f) => f.hidden);
      out.push(mk("iframe", `iframes:${newFrames.map((f) => f.key + (f.hidden ? "!" : "")).sort().join(",")}`, () => createEvent({
        siteId: site.id, type: "page.iframe_injected", severity: hidden ? "high" : "medium", confidence: hidden ? 0.85 : 0.6, timestamp: stamp, indicators,
        summary: `${pagePath} has ${newFrames.length} new ${hidden ? "hidden " : ""}frame(s): ${clip(newFrames.slice(0, 2).map((f) => f.key).join(", "), 150)}`,
        evidence: { path: pagePath, frames: newFrames.slice(0, 10).map((f) => clip(f.key, 300)), hidden },
      })));
    }

    // 6. How much of the text changed.
    const tc = textChange(b.texts, cur.texts, new Set(b.volatile));
    if (tc.ratio >= site.page.domChangeThreshold) {
      const skeletonChanged = cur.skeletonHash !== b.skeletonHash;
      out.push(mk("dom", `dom:${sha256([...tc.added].sort().join("\n") + "\u0000" + [...tc.removed].sort().join("\n"))}`, () => createEvent({
        siteId: site.id, type: "page.dom_changed", severity: tc.ratio >= 0.5 ? "high" : "medium", confidence: clamp(0.4 + tc.ratio * 0.5, 0.4, 0.9), timestamp: stamp, indicators,
        summary: `${round3(tc.ratio * 100)}% of the text on ${pagePath} changed (${tc.added.length} added, ${tc.removed.length} removed)`,
        evidence: {
          path: pagePath, changeRatio: round3(tc.ratio), added: tc.added.length, removed: tc.removed.length,
          addedSample: tc.added.slice(0, 5).map((t) => clip(t)), removedSample: tc.removed.slice(0, 5).map((t) => clip(t)),
          skeletonChanged, status: cur.status, baselineStatus: b.status, titleChanged: cur.title !== b.title,
        },
      })));
    }

    // 7. How much of the picture changed.
    if (base.png && png) {
      try {
        const d = diffPng(base.png, png);
        const threshold = Math.max(site.page.visualDiffThreshold, b.visualNoise * 3);
        if (d.ratio >= threshold) {
          out.push(mk("visual", `visual:${Math.floor(d.ratio * 20)}:${d.sizeMismatch}`, () => createEvent({
            siteId: site.id, type: "page.visual_diff", severity: d.ratio >= 0.3 ? "high" : "medium", confidence: clamp(0.45 + d.ratio, 0.45, 0.75), timestamp: stamp, indicators,
            summary: `${pagePath} looks ${round3(d.ratio * 100)}% different from its baseline`,
            evidence: { path: pagePath, changedRatio: round3(d.ratio), threshold: round3(threshold), sizeMismatch: d.sizeMismatch, baselineHeight: d.a.height, currentHeight: d.b.height },
          })));
        }
      } catch {
        /* an undecodable screenshot is a capture problem, not evidence */
      }
    }
    return out;
  }
}
