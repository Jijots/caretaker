/**
 * Page baselines: what each watched page looked like when it was known good.
 * Kept in GUARD_DATA_DIR beside the file baselines, off the monitored host, and
 * protected the same way (a digest over the body, an HMAC when keyed, written
 * atomically, refused when it does not verify). The screenshot is a separate
 * file whose hash sits inside the signed body, so swapping the image is caught.
 *
 * A snapshot is taken twice a few seconds apart. Whatever differs between the
 * two loads (a clock, a rotating banner, a CSRF token) is recorded as volatile
 * and left out of later text comparisons, and the pixel difference between the
 * two screenshots becomes a noise floor the visual threshold must clear. That
 * removes the usual false alarms without anyone hand-whitelisting by guesswork,
 * and the volatile list is printed so a person can see exactly what was ignored.
 */

import { promises as fs } from "node:fs";
import path from "node:path";
import { z } from "zod";
import { atomicWrite, BaselineError, digestJson } from "./baseline.js";
import { diffPng } from "./pixel.js";
import { digestPage, findSignals, SIGNALS, sha256, type PageDigest, type PageFetcher, type SignalDef } from "./page-digest.js";
import { effectivePageRegions, type SiteConfig } from "./config.js";

export const PAGE_BASELINE_VERSION = 1 as const;

const Sha = z.string().regex(/^[a-f0-9]{64}$/);

const Body = z
  .object({
    v: z.literal(PAGE_BASELINE_VERSION),
    siteId: z.string(),
    path: z.string().max(500),
    createdAt: z.string().datetime(),
    status: z.number().int(),
    finalOrigin: z.string().max(300),
    finalPath: z.string().max(500),
    title: z.string().max(300),
    lang: z.string().max(20),
    texts: z.array(z.string().max(300)).max(5000),
    volatile: z.array(z.string().max(300)).max(5000),
    skeletonHash: Sha,
    scriptOrigins: z.array(z.string().max(300)).max(200),
    iframes: z.array(z.object({ key: z.string().max(500), origin: z.string().max(300), hidden: z.boolean() }).strict()).max(100),
    dominantScript: z.string().max(20),
    signals: z.array(z.string().max(40)).max(50),
    pngSha256: Sha.nullable(),
    /** Share of pixels that differed between the two snapshot screenshots. */
    visualNoise: z.number().min(0).max(1),
    warnings: z.array(z.string().max(300)).max(20),
  })
  .strict();
export type PageBaselineBody = z.infer<typeof Body>;
const Manifest = z.object({ body: Body, digest: Sha, keyed: z.boolean() }).strict();

const slug = (p: string): string => sha256(p).slice(0, 16);

export class PageBaselineStore {
  constructor(
    private readonly dataDir: string,
    private readonly key?: Buffer,
  ) {}

  private dir(siteId: string): string {
    return path.join(this.dataDir, "baselines", siteId, "pages");
  }
  private jsonPath(siteId: string, p: string): string {
    return path.join(this.dir(siteId), `${slug(p)}.json`);
  }
  private pngPath(siteId: string, p: string): string {
    return path.join(this.dir(siteId), `${slug(p)}.png`);
  }

  async load(siteId: string, pagePath: string): Promise<{ body: PageBaselineBody; png: Buffer | null } | null> {
    let text: string;
    try {
      text = await fs.readFile(this.jsonPath(siteId, pagePath), "utf8");
    } catch (e: any) {
      if (e?.code === "ENOENT") return null;
      throw e;
    }
    let parsed;
    try {
      parsed = Manifest.safeParse(JSON.parse(text));
    } catch {
      throw new BaselineError(`page baseline for '${siteId}' ${pagePath} is not valid JSON`);
    }
    if (!parsed.success) throw new BaselineError(`page baseline for '${siteId}' ${pagePath} has an unexpected shape`);
    const m = parsed.data;
    if (m.body.siteId !== siteId || m.body.path !== pagePath) throw new BaselineError(`page baseline file for '${siteId}' ${pagePath} belongs to another page`);
    if (m.keyed && !this.key) throw new BaselineError(`page baseline for '${siteId}' ${pagePath} is keyed but GUARD_JOURNAL_KEY is not set`);
    if (!m.keyed && this.key) throw new BaselineError(`page baseline for '${siteId}' ${pagePath} is unkeyed but GUARD_JOURNAL_KEY is set. Take a new snapshot to key it.`);
    if (digestJson(m.body, m.keyed ? this.key : undefined) !== m.digest) {
      throw new BaselineError(`page baseline for '${siteId}' ${pagePath} fails its digest check. It was edited, or the key is wrong.`);
    }
    let png: Buffer | null = null;
    if (m.body.pngSha256) {
      try {
        png = await fs.readFile(this.pngPath(siteId, pagePath));
      } catch {
        throw new BaselineError(`screenshot for '${siteId}' ${pagePath} is missing`);
      }
      if (sha256(png) !== m.body.pngSha256) throw new BaselineError(`screenshot for '${siteId}' ${pagePath} does not match its recorded hash`);
    }
    return { body: m.body, png };
  }

  async save(body: PageBaselineBody, png: Buffer | null): Promise<void> {
    Body.parse(body);
    if (png) await atomicWrite(this.pngPath(body.siteId, body.path), png);
    await atomicWrite(this.jsonPath(body.siteId, body.path), JSON.stringify({ body, digest: digestJson(body, this.key), keyed: !!this.key }, null, 1) + "\n");
  }
}

export interface PageSnapshotOptions {
  /** Pause between the two loads. Long enough for a clock or rotator to tick. */
  gapMs?: number;
  extra?: SignalDef[];
  now?: () => Date;
  screenshot?: boolean;
}

export interface PageSnapshotResult {
  path: string;
  body: PageBaselineBody;
  volatileCount: number;
}

export async function snapshotPages(site: SiteConfig, fetcher: PageFetcher, store: PageBaselineStore, opts: PageSnapshotOptions = {}): Promise<PageSnapshotResult[]> {
  const siteOrigin = new URL(site.baseUrl).origin;
  const shoot = opts.screenshot ?? true;
  const gap = opts.gapMs ?? 3000;
  const results: PageSnapshotResult[] = [];

  for (const p of site.pages) {
    const url = new URL(p, site.baseUrl).toString();
    const hide = effectivePageRegions(site, p);
    const first = await fetcher.fetch(url, { hideSelectors: hide, screenshot: shoot });
    if (gap > 0) await new Promise((r) => setTimeout(r, gap));
    const second = await fetcher.fetch(url, { hideSelectors: hide, screenshot: shoot });

    const a = digestPage(first, siteOrigin, opts.extra);
    const b = digestPage(second, siteOrigin, opts.extra);
    const A = new Set(a.texts);
    const B = new Set(b.texts);
    const volatile = [...new Set([...a.texts.filter((t) => !B.has(t)), ...b.texts.filter((t) => !A.has(t))])];
    const stable = b.texts.filter((t) => A.has(t));

    const warnings: string[] = [...second.warnings];
    if (b.status < 200 || b.status >= 300) warnings.push(`the page answered HTTP ${b.status} when the baseline was taken`);
    if (b.finalOrigin && b.finalOrigin !== siteOrigin) warnings.push(`the page ended on ${b.finalOrigin}, not ${siteOrigin}`);
    const already = findSignals([b.title, ...b.texts].join("\n"), [...SIGNALS, ...(opts.extra ?? [])]);
    for (const s of already) warnings.push(`defacement phrase '${s.id}' is ALREADY on the page ("${s.snippet.slice(0, 60)}"). If the site is defaced, do not baseline it.`);
    if (!stable.length) warnings.push("no stable text was found, so text changes cannot be detected on this page");

    let noise = 0;
    if (shoot && first.png && second.png) {
      try {
        noise = diffPng(first.png, second.png).ratio;
      } catch (e: any) {
        warnings.push(`could not compare the two screenshots: ${String(e?.message ?? e).slice(0, 120)}`);
      }
    }
    if (noise > 0.02) warnings.push(`the page differed by ${(noise * 100).toFixed(1)}% of pixels between two loads seconds apart. Whitelist the moving part with pageRegions.`);

    const body: PageBaselineBody = {
      v: PAGE_BASELINE_VERSION,
      siteId: site.id,
      path: p,
      createdAt: (opts.now?.() ?? new Date()).toISOString(),
      status: b.status,
      finalOrigin: b.finalOrigin,
      finalPath: b.finalPath,
      title: b.title,
      lang: b.lang,
      texts: stable.slice(0, 5000),
      volatile: volatile.slice(0, 5000),
      skeletonHash: b.skeletonHash,
      scriptOrigins: [...new Set([...a.scriptOrigins, ...b.scriptOrigins])].sort().slice(0, 200),
      iframes: [...new Map([...a.iframes, ...b.iframes].map((f) => [f.key, f])).values()].slice(0, 100),
      dominantScript: b.dominantScript,
      signals: b.signals,
      pngSha256: shoot && second.png ? sha256(second.png) : null,
      visualNoise: noise,
      warnings: warnings.map((w) => w.slice(0, 300)).slice(0, 20),
    };
    await store.save(body, shoot ? second.png : null);
    results.push({ path: p, body, volatileCount: volatile.length });
  }
  return results;
}

export type { PageDigest };
