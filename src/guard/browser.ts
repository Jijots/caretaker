/**
 * The real PageFetcher: headless Chromium through Playwright, loaded lazily so
 * nothing else in the module needs it installed.
 *
 * The browser opens pages that may be hostile, so it is boxed in:
 *  - a fresh context for every load, nothing kept between pages
 *  - no downloads, no permissions, service workers blocked, dialogs dismissed,
 *    popups closed
 *  - requests to internal addresses are aborted (net-guard.ts), so a defaced
 *    page cannot use Caretaker's machine to probe its network
 *  - a hard time limit on the whole load
 * It still executes the page's JavaScript, which is the point, so run it on a
 * machine that is not trusted with anything the page should not reach.
 */

import { requestAllowed } from "./net-guard.js";
import type { PageFetcher, RawPage } from "./page-digest.js";

export class BrowserUnavailableError extends Error {}

export const VIEWPORT = { width: 1280, height: 800 } as const;
const MAX_SHOT_HEIGHT = 3000;
const NAV_TIMEOUT_MS = 30_000;
const TOTAL_TIMEOUT_MS = 60_000;

/**
 * Runs inside the page. A string on purpose: the TypeScript transform can add
 * helper references (such as __name) to functions, and those do not exist in
 * the page. Selectors in cfg.hide are skipped from the comparison AND made
 * invisible (layout kept) so the screenshot ignores them too.
 */
export const EXTRACT_SCRIPT = `(cfg) => {
  const MAX_TEXTS = 6000, MAX_SKEL = 20000, MAX_URLS = 200;
  const warnings = [];
  const good = [];
  for (const s of cfg.hide) {
    try { document.querySelector(s); good.push(s); } catch (e) { warnings.push('invalid selector ignored: ' + String(s).slice(0, 80)); }
  }
  const selector = good.join(',');
  const skip = new Set(['SCRIPT', 'STYLE', 'NOSCRIPT', 'TEMPLATE']);
  const texts = [];
  const skeleton = [];
  const root = document.body || document.documentElement;
  const stack = root ? [root] : [];
  while (stack.length) {
    const el = stack.pop();
    if (skip.has(el.tagName)) continue;
    let inRegion = false;
    if (selector) { try { inRegion = el.matches(selector); } catch (e) { inRegion = false; } }
    if (inRegion) continue;
    if (skeleton.length < MAX_SKEL) skeleton.push(el.tagName);
    const kids = el.childNodes;
    for (let i = kids.length - 1; i >= 0; i--) {
      const k = kids[i];
      if (k.nodeType === 1) stack.push(k);
      else if (k.nodeType === 3 && texts.length < MAX_TEXTS) {
        const t = (k.nodeValue || '').replace(/\\s+/g, ' ').trim();
        if (t) texts.push(t.slice(0, 300));
      }
    }
  }
  const scriptSrcs = [];
  const inlineScriptUrls = [];
  for (const s of document.querySelectorAll('script')) {
    if (s.src) { scriptSrcs.push(s.src); continue; }
    const m = (s.textContent || '').slice(0, 20000).match(/https?:\\/\\/[^\\s'"\`<>\\\\)]+/g);
    if (m) for (const u of m) if (inlineScriptUrls.length < MAX_URLS) inlineScriptUrls.push(u);
  }
  const iframes = [];
  for (const f of document.querySelectorAll('iframe,frame')) {
    if (iframes.length >= 100) break;
    const cs = getComputedStyle(f);
    const r = f.getBoundingClientRect();
    const hidden = cs.display === 'none' || cs.visibility === 'hidden' || parseFloat(cs.opacity) === 0 ||
      r.width <= 2 || r.height <= 2 || r.right + window.scrollX <= 0 || r.bottom + window.scrollY <= 0;
    iframes.push({ src: f.src || (f.hasAttribute('srcdoc') ? 'about:srcdoc' : ''), hidden });
  }
  const mr = document.querySelector('meta[http-equiv="refresh" i]');
  if (cfg.hideNow && selector) {
    try { for (const e of document.querySelectorAll(selector)) e.style.setProperty('visibility', 'hidden', 'important'); } catch (e) {}
  }
  return {
    title: (document.title || '').slice(0, 300),
    lang: (document.documentElement.lang || '').slice(0, 20),
    texts, skeleton, scriptSrcs, inlineScriptUrls, iframes,
    metaRefresh: mr ? String(mr.getAttribute('content') || '').slice(0, 500) : null,
    scrollHeight: Math.max(document.documentElement.scrollHeight, (document.body || {}).scrollHeight || 0),
    warnings,
  };
}`;

function withTimeout<T>(p: Promise<T>, ms: number, what: string): Promise<T> {
  let t: NodeJS.Timeout;
  return Promise.race([
    p,
    new Promise<never>((_, rej) => {
      t = setTimeout(() => rej(new Error(`${what} timed out after ${ms / 1000}s`)), ms);
    }),
  ]).finally(() => clearTimeout(t!));
}

export async function launchBrowser(): Promise<PageFetcher> {
  let chromium: any;
  try {
    ({ chromium } = await import("playwright"));
  } catch {
    throw new BrowserUnavailableError("the 'playwright' package is not installed. Run: npm install");
  }
  let browser: any;
  try {
    browser = await chromium.launch({ headless: true });
  } catch (e: any) {
    throw new BrowserUnavailableError(`Chromium could not start (${String(e?.message ?? e).split("\n")[0]}). Run: npx playwright install chromium`);
  }

  return {
    async fetch(url, opts): Promise<RawPage> {
      const siteHost = new URL(url).host;
      const context = await browser.newContext({
        viewport: VIEWPORT,
        acceptDownloads: false,
        serviceWorkers: "block",
        permissions: [],
        locale: "en-US",
        javaScriptEnabled: true,
        ignoreHTTPSErrors: false,
      });
      try {
        return await withTimeout(
          (async (): Promise<RawPage> => {
            await context.route("**/*", (route: any) => (requestAllowed(route.request().url(), siteHost) ? route.continue() : route.abort("blockedbyclient")));
            let main: any = null;
            context.on("page", (p: any) => {
              // The first page event is ours, fired while newPage() is still running. Any later page is a popup.
              if (main && p !== main) void p.close().catch(() => undefined);
            });
            const page = await context.newPage();
            main = page;
            page.on("dialog", (d: any) => void d.dismiss().catch(() => undefined));

            const resp = await page.goto(url, { waitUntil: "load", timeout: NAV_TIMEOUT_MS });
            await page.waitForLoadState("networkidle", { timeout: 5000 }).catch(() => undefined);
            await page.waitForTimeout(300);

            // Called explicitly: given a string plus an argument, Playwright returns the function itself instead of running it.
            const cfg = JSON.stringify({ hide: opts.hideSelectors, hideNow: opts.screenshot });
            const data = await page.evaluate(`(${EXTRACT_SCRIPT})(${cfg})`);
            if (!data || typeof data !== "object") throw new Error("the page could not be read");
            let png: Buffer | null = null;
            if (opts.screenshot) {
              const height = Math.max(VIEWPORT.height, Math.min(MAX_SHOT_HEIGHT, data.scrollHeight));
              png = await page.screenshot({
                fullPage: true,
                clip: { x: 0, y: 0, width: VIEWPORT.width, height },
                animations: "disabled",
                caret: "hide",
                timeout: 15_000,
              });
            }
            return {
              url,
              finalUrl: page.url(),
              status: resp?.status() ?? 0,
              title: data.title,
              lang: data.lang,
              texts: data.texts,
              skeleton: data.skeleton,
              scriptSrcs: data.scriptSrcs,
              inlineScriptUrls: data.inlineScriptUrls,
              iframes: data.iframes,
              metaRefresh: data.metaRefresh,
              png,
              warnings: data.warnings,
            };
          })(),
          TOTAL_TIMEOUT_MS,
          `loading ${url}`,
        );
      } finally {
        await context.close().catch(() => undefined);
      }
    },
    async close() {
      await browser.close().catch(() => undefined);
    },
  };
}
