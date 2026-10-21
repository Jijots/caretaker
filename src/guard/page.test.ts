import test from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import path from "node:path";
import { SiteConfig } from "./config.js";
import { BaselineError } from "./baseline.js";
import { classify } from "./orchestrator.js";
import { isInternalHost, requestAllowed } from "./net-guard.js";
import { diffPng, solidPng } from "./pixel.js";
import { PageBaselineStore, snapshotPages } from "./page-baseline.js";
import {
  SIGNALS, boundTexts, digestPage, dominantScript, findSignals, textChange,
  type PageFetcher, type RawPage,
} from "./page-digest.js";
import { PageWatcher, type LoadedPageBaseline } from "./page-watcher.js";
import { site as mkSite, tmpDir } from "./testkit.js";

/* ----------------------------------------------------------------- helpers */

const ORIGIN = "https://acme.example";
const HOME = [
  "Acme Dental Clinic", "Open Monday to Friday, 9am to 5pm", "Book an appointment today",
  "We offer cleaning, whitening and braces", "Call us on 0917 000 0000", "Visit us at 12 Rizal Avenue, Manila",
  "Meet our dentists", "Patient reviews", "Frequently asked questions", "Contact us",
];

function raw(over: Partial<RawPage> = {}): RawPage {
  return {
    url: `${ORIGIN}/`, finalUrl: `${ORIGIN}/`, status: 200, title: "Acme Dental", lang: "en",
    texts: HOME, skeleton: ["BODY", "DIV", "P", "P"], scriptSrcs: [`${ORIGIN}/app.js`], inlineScriptUrls: [],
    iframes: [], metaRefresh: null, png: null, warnings: [], ...over,
  };
}

/** Serves whatever `current` is, or throws it if it is an Error. */
class Fake implements PageFetcher {
  current: RawPage | Error = raw();
  calls: { url: string; hide: string[]; shot: boolean }[] = [];
  async fetch(url: string, o: { hideSelectors: string[]; screenshot: boolean }): Promise<RawPage> {
    this.calls.push({ url, hide: o.hideSelectors, shot: o.screenshot });
    if (this.current instanceof Error) throw this.current;
    return { ...this.current, url, png: o.screenshot ? this.current.png : null };
  }
  async close() {}
}

async function rig(over: Record<string, unknown> = {}, first: Partial<RawPage> = {}) {
  const { dir, cleanup } = await tmpDir();
  const site = mkSite({ platform: "static", transport: { type: "none" }, baseUrl: ORIGIN, ...over });
  const fetcher = new Fake();
  fetcher.current = raw(first);
  const store = new PageBaselineStore(path.join(dir, "data"));
  await snapshotPages(site, fetcher, store, { gapMs: 0, screenshot: first.png !== undefined });
  const baselines = new Map<string, LoadedPageBaseline>();
  for (const p of site.pages) baselines.set(p, (await store.load(site.id, p))!);
  const watcher = new PageWatcher({ site, fetcher, baselines });
  return { dir, site, fetcher, store, watcher, cleanup };
}
const types = (r: { events: { type: string }[] }) => r.events.map((e) => e.type).sort();

/* --------------------------------------------------------------- net-guard */

test("the browser may reach the site and the public internet, and nothing internal", () => {
  const host = "acme.example";
  assert.equal(requestAllowed("https://acme.example/a.js", host), true);
  assert.equal(requestAllowed("https://cdn.jsdelivr.net/x.js", host), true);
  assert.equal(requestAllowed("data:text/plain,hi", host), true);
  for (const u of [
    "http://localhost/", "http://127.0.0.1:8080/", "http://10.0.0.5/", "http://192.168.1.1/", "http://172.20.0.1/",
    "http://169.254.169.254/latest/meta-data/", "http://[::1]/", "http://[fd00::1]/", "http://[::ffff:127.0.0.1]/",
    "http://0.0.0.0/", "http://printer.local/", "http://db.internal/", "http://2130706433/", "http://0x7f.1/",
    "file:///etc/passwd", "ftp://example.com/", "javascript:alert(1)", "not a url",
  ]) assert.equal(requestAllowed(u, host), false, u);
  assert.equal(isInternalHost("8.8.8.8"), false);
  assert.equal(isInternalHost("172.32.0.1"), false, "just outside 172.16/12");
  assert.equal(isInternalHost("100.64.0.1"), true, "carrier-grade NAT");
});

test("a site that is itself local may reach its own host and port only", () => {
  assert.equal(requestAllowed("http://127.0.0.1:4000/a", "127.0.0.1:4000"), true);
  assert.equal(requestAllowed("http://127.0.0.1:4001/a", "127.0.0.1:4000"), false, "another port is another service");
});

/* ------------------------------------------------------------------- pixel */

test("pixel diff: identical is zero, a patch is its share, a longer page counts the extra area", () => {
  const base = solidPng(100, 100, [255, 255, 255]);
  assert.equal(diffPng(base, solidPng(100, 100, [255, 255, 255])).ratio, 0);
  const patched = diffPng(base, solidPng(100, 100, [255, 255, 255], { x: 0, y: 0, w: 50, h: 20, rgb: [0, 0, 0] }));
  assert.equal(patched.ratio, 0.1);
  assert.equal(diffPng(base, solidPng(100, 100, [250, 250, 250])).ratio, 0, "within tolerance is anti-aliasing noise");
  const longer = diffPng(base, solidPng(100, 200, [255, 255, 255]));
  assert.equal(longer.sizeMismatch, true);
  assert.equal(longer.ratio, 0.5);
});

/* ------------------------------------------------------------------ digest */

test("defacement phrases: strong ones match, ordinary copy does not, weak ones are marked weak", () => {
  const ids = (s: string) => findSignals(s, SIGNALS).map((x) => x.id);
  assert.deepEqual(ids("Hacked by Some Group"), ["hacked-by"]);
  assert.deepEqual(ids("h4cked by x"), ["hacked-by"]);
  assert.deepEqual(ids("This website has been hacked"), ["site-hacked"]);
  assert.deepEqual(ids("Greetz to my friends"), ["greetz"]);
  assert.deepEqual(ids("Family owned by the Reyes brothers since 1990"), ["owned-by"]);
  assert.equal(findSignals("Family owned by the Reyes", SIGNALS)[0].strength, "weak");
  assert.deepEqual(ids("We protect your site. Book a cleaning."), []);
  assert.deepEqual(ids("Greetings to all our new patients"), [], "ordinary clinic copy");
  assert.deepEqual(ids("Is your site is compromised? We clean malware"), [], "ordinary security-vendor copy");
  assert.deepEqual(ids("The shipment was hacked together overnight"), [], "'hacked together' is not 'hacked by'");
  const [hit] = findSignals("x".repeat(200) + " Hacked by Evil \u0007\u0000 " + "y".repeat(200), SIGNALS);
  assert.ok(hit.snippet.length <= 120 && !/[\u0000-\u001f]/.test(hit.snippet), "snippets are bounded and carry no control characters");
});

test("dominant writing system needs enough text to say", () => {
  assert.equal(dominantScript(["Hello there"]).script, "unknown");
  assert.equal(dominantScript(["Open Monday to Friday, book an appointment today with our dentists in Manila"]).script, "latin");
  assert.equal(dominantScript(["Добро пожаловать на наш сайт. Мы работаем с понедельника по пятницу каждую неделю"]).script, "cyrillic");
  assert.equal(dominantScript(["مرحبا بكم في موقعنا نحن نعمل من الاثنين إلى الجمعة في كل أسبوع من السنة"]).script, "arabic");
});

test("texts are collapsed, deduplicated and bounded", () => {
  assert.deepEqual(boundTexts(["  a   b ", "a b", "", "   ", "c"]), ["a b", "c"]);
  assert.equal(boundTexts(["x".repeat(1000)])[0].length, 300);
  assert.equal(boundTexts(Array.from({ length: 9000 }, (_, i) => `t${i}`)).length, 5000);
});

test("textChange: symmetric share, volatile text ignored", () => {
  assert.equal(textChange(["a", "b"], ["a", "b"], new Set()).ratio, 0);
  assert.equal(textChange(["a", "b"], ["x", "y"], new Set()).ratio, 1);
  assert.equal(textChange(["a", "b", "clock 1"], ["a", "b", "clock 2"], new Set(["clock 1", "clock 2"])).ratio, 0);
  assert.equal(textChange([], [], new Set()).ratio, 0);
});

test("digestPage: external origins, inline script urls, frame keys and meta refresh", () => {
  const d = digestPage(
    raw({
      scriptSrcs: [`${ORIGIN}/a.js`, "https://cdn.example.com/lib.js?v=1", "/rel.js"],
      inlineScriptUrls: ["https://tracker.example.net/t.gif", "javascript:void(0)"],
      iframes: [{ src: "https://www.youtube.com/embed/abc?autoplay=1", hidden: false }, { src: "https://www.youtube.com/embed/abc?autoplay=0", hidden: true }, { src: "", hidden: true }],
      metaRefresh: "0; url=https://evil.example/landing",
    }),
    ORIGIN,
  );
  assert.deepEqual(d.scriptOrigins, ["https://cdn.example.com", "https://tracker.example.net"]);
  assert.equal(d.iframes.length, 2, "the same frame twice is one key");
  assert.equal(d.iframes.find((f) => f.key === "https://www.youtube.com/embed/abc")?.hidden, true, "hidden if any copy is");
  assert.equal(d.metaRefreshOrigin, "https://evil.example");
});

/* ------------------------------------------------------------------ config */

test("pages must be plain paths on the site, and origins must be origins", () => {
  const base = { id: "acme-x", name: "X", baseUrl: ORIGIN, platform: "static", transport: { type: "none" } };
  for (const p of ["//evil.example/x", "/\\evil.example", "/a b", "/a\u0007b", "x", "/ok\n"]) {
    assert.equal(SiteConfig.safeParse({ ...base, pages: [p] }).success, false, JSON.stringify(p));
  }
  assert.equal(SiteConfig.safeParse({ ...base, pages: ["/", "/services/dental-implants?x=1"] }).success, true);
  assert.equal(SiteConfig.safeParse({ ...base, page: { allowedOrigins: ["https://cdn.example.com"] } }).success, true);
  for (const o of ["cdn.example.com", "https://cdn.example.com/path", "ftp://x.example", "https://"]) {
    assert.equal(SiteConfig.safeParse({ ...base, page: { allowedOrigins: [o] } }).success, false, o);
  }
  assert.equal(SiteConfig.safeParse({ ...base, page: { domChangeThreshold: 0.01 } }).success, false);
  assert.equal(SiteConfig.safeParse({ ...base, page: { surprise: 1 } }).success, false);
  assert.equal(SiteConfig.parse(base).page.intervalSeconds, 600);
});

/* ----------------------------------------------------------------- watcher */

test("an unchanged page produces no events", async () => {
  const r = await rig();
  try {
    const out = await r.watcher.runOnce();
    assert.deepEqual(out.events, []);
    assert.equal(out.pagesChecked, 1);
  } finally { await r.cleanup(); }
});

test("a new defacement phrase is a strong, critical signal that the orchestrator confirms by itself", async () => {
  const r = await rig();
  try {
    r.fetcher.current = raw({ texts: ["Hacked by Bad Actor", "Greetz to all"], title: "owned" });
    const out = await r.watcher.runOnce();
    const sig = out.events.find((e) => e.type === "page.defacement_signal")!;
    assert.equal(sig.severity, "critical");
    assert.equal(sig.confidence, 0.97);
    assert.deepEqual(sig.evidence.signals, ["hacked-by", "greetz"]);
    assert.equal(sig.worker, "page");
    assert.deepEqual(sig.indicators.paths, ["/"]);
    const c = classify(r.site, out.events, 0.99, "unknown");
    assert.equal(c.classification, "confirmed_defacement", "a loud signal does not wait for a deploy to be ruled out");
  } finally { await r.cleanup(); }
});

test("a phrase already on the page at baseline time is not news, and a weak phrase is only a hint", async () => {
  const quoted = await rig({}, { texts: [...HOME, "Our article: how sites get hacked by bots"] });
  try {
    assert.match(JSON.stringify((await quoted.store.load(quoted.site.id, "/"))!.body.warnings), /ALREADY on the page/);
    assert.deepEqual((await quoted.watcher.runOnce()).events, []);
  } finally { await quoted.cleanup(); }

  const weak = await rig();
  try {
    weak.fetcher.current = raw({ texts: [...HOME, "Family owned by the Reyes brothers"] });
    const [e] = (await weak.watcher.runOnce()).events.filter((x) => x.type === "page.defacement_signal");
    assert.equal(e.confidence, 0.6);
    assert.equal(e.severity, "medium");
  } finally { await weak.cleanup(); }
});

test("site-specific phrases from config count as strong", async () => {
  const r = await rig({ page: { extraSignals: ["Team Sapphire"] } });
  try {
    r.fetcher.current = raw({ texts: [...HOME, "team SAPPHIRE was glad to visit"] });
    const e = (await r.watcher.runOnce()).events.find((x) => x.type === "page.defacement_signal")!;
    assert.ok(e.confidence >= 0.95);
  } finally { await r.cleanup(); }
});

test("scripts from a new origin are reported, including ones hidden in inline scripts; allowed origins are not", async () => {
  const r = await rig({ page: { allowedOrigins: ["https://analytics.example.org"] } }, { scriptSrcs: [`${ORIGIN}/a.js`, "https://cdn.example.com/lib.js"] });
  try {
    r.fetcher.current = raw({
      scriptSrcs: [`${ORIGIN}/a.js`, "https://cdn.example.com/lib.js", "https://analytics.example.org/t.js", "https://evil.example/x.js"],
      inlineScriptUrls: ["https://other.example.net/b.js"],
    });
    const [e, ...rest] = (await r.watcher.runOnce()).events;
    assert.equal(rest.length, 0);
    assert.equal(e.type, "page.external_script_added");
    assert.deepEqual(e.evidence.origins, ["https://evil.example", "https://other.example.net"]);
    assert.equal(e.confidence, 0.75);
  } finally { await r.cleanup(); }
});

test("frames: a hidden new one is serious, a known origin and a plain same-origin one are not", async () => {
  const r = await rig({}, { iframes: [{ src: "https://www.google.com/maps/embed?pb=1", hidden: false }] });
  try {
    r.fetcher.current = raw({ iframes: [
      { src: "https://www.google.com/maps/embed?pb=1", hidden: false },
      { src: "https://www.google.com/maps/embed?pb=2", hidden: false },
      { src: `${ORIGIN}/widget`, hidden: false },
    ] });
    assert.deepEqual((await r.watcher.runOnce()).events, [], "same origin as a known frame, or the site's own");

    r.fetcher.current = raw({ iframes: [{ src: "https://evil.example/x", hidden: true }] });
    const [e] = (await r.watcher.runOnce()).events;
    assert.equal(e.type, "page.iframe_injected");
    assert.equal(e.confidence, 0.85);
    assert.equal(e.evidence.hidden, true);

    r.fetcher.current = raw({ iframes: [{ src: "https://video.example/embed", hidden: false }] });
    const [v] = (await r.watcher.runOnce()).events;
    assert.equal(v.confidence, 0.6, "a visible third-party frame is a question, not an alarm");

    r.fetcher.current = raw({ iframes: [{ src: `${ORIGIN}/hidden-thing`, hidden: true }] });
    assert.equal((await r.watcher.runOnce()).events.length, 1, "hidden counts even on the site's own origin");
  } finally { await r.cleanup(); }
});

test("a redirect to another origin, a meta refresh, and a language switch are signals", async () => {
  const r = await rig();
  try {
    r.fetcher.current = raw({ finalUrl: "https://evil.example/landing", texts: HOME });
    const e = (await r.watcher.runOnce()).events.find((x) => x.type === "page.defacement_signal")!;
    assert.equal(e.evidence.signal, "redirect to another origin");
    assert.equal(e.evidence.actualOrigin, "https://evil.example");

    r.fetcher.current = raw({ metaRefresh: "0;url=https://evil.example/" });
    assert.equal((await r.watcher.runOnce()).events.find((x) => x.type === "page.defacement_signal")!.evidence.signal, "meta refresh to another origin");

    r.fetcher.current = raw({ metaRefresh: null, texts: ["Добро пожаловать на наш сайт. Мы работаем с понедельника по пятницу каждую неделю круглый год"] });
    const switched = (await r.watcher.runOnce()).events.find((x) => x.evidence.signal === "writing system changed");
    assert.equal(switched?.evidence.now, "cyrillic");
  } finally { await r.cleanup(); }
});

test("text change: below the threshold is quiet, above it scales with how much changed, volatile text is ignored", async () => {
  const r = await rig({ page: { domChangeThreshold: 0.2 } });
  try {
    r.fetcher.current = raw({ texts: [...HOME.slice(0, 9), "Contact us today"] });
    assert.deepEqual((await r.watcher.runOnce()).events, [], "1 of 10 blocks changed is under 20%");

    r.fetcher.current = raw({ texts: [...HOME.slice(0, 7), "New A", "New B", "New C"] });
    const [mid] = (await r.watcher.runOnce()).events;
    assert.equal(mid.type, "page.dom_changed");
    assert.equal(mid.severity, "medium");

    r.fetcher.current = raw({ texts: ["Totally different", "Nothing the same"] });
    const [big] = (await r.watcher.runOnce()).events;
    assert.equal(big.severity, "high");
    assert.ok(big.confidence > mid.confidence && big.confidence <= 0.9);
    assert.equal(big.evidence.removed, 10);
    assert.ok((big.evidence.addedSample as string[]).length <= 5);
  } finally { await r.cleanup(); }

  const clock = await rig({}, { texts: [...HOME, "12:00:01"] });
  try {
    const b = await clock.store.load(clock.site.id, "/");
    assert.ok(!b!.body.texts.includes("12:00:01") || b!.body.volatile.length === 0);
  } finally { await clock.cleanup(); }
});

test("snapshot loads the page twice and records what moved between loads as volatile", async () => {
  const { dir, cleanup } = await tmpDir();
  try {
    const site = mkSite({ platform: "static", transport: { type: "none" }, baseUrl: ORIGIN });
    let n = 0;
    const f: PageFetcher = {
      async fetch(url) {
        n++;
        return raw({ url, texts: [...HOME, `Server time 12:00:0${n}`, `Visitor number ${100 + n}`] });
      },
      async close() {},
    };
    const store = new PageBaselineStore(path.join(dir, "data"));
    const [res] = await snapshotPages(site, f, store, { gapMs: 0, screenshot: false });
    assert.equal(n, 2);
    assert.equal(res.volatileCount, 4);
    assert.deepEqual(res.body.texts, HOME);
    const watcher = new PageWatcher({ site, fetcher: { async fetch(url) { n++; return raw({ url, texts: [...HOME, `Server time 12:09:59`, `Visitor number 999`] }); }, async close() {} }, baselines: new Map([["/", (await store.load(site.id, "/"))!]]) });
    assert.deepEqual((await watcher.runOnce()).events, [], "a ticking clock is not a defacement");
  } finally { await cleanup(); }
});

test("visual diff: a big change speaks, the noise floor raises the bar, and it is the weakest evidence", async () => {
  const white = solidPng(1280, 800, [255, 255, 255]);
  const r = await rig({}, { png: white });
  try {
    r.fetcher.current = raw({ png: solidPng(1280, 800, [255, 255, 255], { x: 0, y: 0, w: 1280, h: 200, rgb: [0, 0, 0] }) });
    const [e] = (await r.watcher.runOnce()).events;
    assert.equal(e.type, "page.visual_diff");
    assert.equal(e.evidence.changedRatio, 0.25);
    assert.ok(e.confidence <= 0.75 && e.confidence < 0.8);

    r.fetcher.current = raw({ png: solidPng(1280, 800, [255, 255, 255], { x: 0, y: 0, w: 100, h: 100, rgb: [0, 0, 0] }) });
    assert.deepEqual((await r.watcher.runOnce()).events, [], "under 5% of pixels");

    r.fetcher.current = raw({ png: solidPng(1280, 1600, [255, 255, 255]) });
    assert.equal((await r.watcher.runOnce()).events[0].evidence.sizeMismatch, true);
  } finally { await r.cleanup(); }
});

test("a difference is reported once, again if it changes, forgotten when fixed; a failed load changes nothing", async () => {
  const r = await rig();
  try {
    r.fetcher.current = raw({ texts: ["Hacked by X"] });
    assert.ok((await r.watcher.runOnce()).events.length >= 1);
    const again = await r.watcher.runOnce();
    assert.equal(again.events.length, 0);
    assert.ok(again.suppressed >= 1);

    r.fetcher.current = new Error("net::ERR_CONNECTION_RESET");
    const failed = await r.watcher.runOnce();
    assert.deepEqual(failed.events, []);
    assert.equal(failed.failed[0].path, "/");
    assert.match(failed.failed[0].error, /ERR_CONNECTION_RESET/);

    r.fetcher.current = raw({ texts: ["Hacked by X"] });
    assert.equal((await r.watcher.runOnce()).events.length, 0, "a failed load did not make the old finding look new");

    r.fetcher.current = raw();
    assert.equal((await r.watcher.runOnce()).events.length, 0, "fixed");
    r.fetcher.current = raw({ texts: ["Hacked by X"] });
    assert.ok((await r.watcher.runOnce()).events.length >= 1, "and reported afresh if it returns");
  } finally { await r.cleanup(); }
});

test("regions are passed to the browser for this page and for every page", async () => {
  const r = await rig({
    pages: ["/", "/shop"],
    pageRegions: [{ page: "/shop", selector: ".stock", reason: "per sale" }, { page: "*", selector: "#counter", reason: "footer" }],
  });
  try {
    const shop = r.fetcher.calls.find((c) => c.url.endsWith("/shop"))!;
    const home = r.fetcher.calls.find((c) => c.url === `${ORIGIN}/`)!;
    assert.deepEqual(shop.hide.sort(), ["#counter", ".stock"]);
    assert.deepEqual(home.hide, ["#counter"]);
  } finally { await r.cleanup(); }
});

test("only URLs under the site's own baseUrl are ever fetched", async () => {
  const r = await rig({ pages: ["/", "/a/b?c=1"] });
  try {
    await r.watcher.runOnce();
    for (const c of r.fetcher.calls) assert.equal(new URL(c.url).origin, ORIGIN, c.url);
  } finally { await r.cleanup(); }
});

/* ---------------------------------------------------------------- baseline */

test("a tampered page baseline, a swapped screenshot, and a missing key are all refused", async () => {
  const r = await rig({}, { png: solidPng(200, 100, [255, 255, 255]) });
  try {
    const dir = path.join(r.dir, "data", "baselines", r.site.id, "pages");
    const [json, png] = [(await fs.readdir(dir)).find((f) => f.endsWith(".json"))!, (await fs.readdir(dir)).find((f) => f.endsWith(".png"))!];

    await fs.writeFile(path.join(dir, png), solidPng(200, 100, [0, 0, 0]));
    await assert.rejects(() => r.store.load(r.site.id, "/"), (e: Error) => e instanceof BaselineError && /does not match its recorded hash/.test(e.message));
    await fs.writeFile(path.join(dir, png), solidPng(200, 100, [255, 255, 255]));
    assert.ok(await r.store.load(r.site.id, "/"));

    const m = JSON.parse(await fs.readFile(path.join(dir, json), "utf8"));
    m.body.texts = ["everything is fine"];
    await fs.writeFile(path.join(dir, json), JSON.stringify(m));
    await assert.rejects(() => r.store.load(r.site.id, "/"), /fails its digest check/);

    const keyed = new PageBaselineStore(path.join(r.dir, "data"), Buffer.from("k".repeat(40)));
    await snapshotPages(r.site, r.fetcher, keyed, { gapMs: 0, screenshot: false });
    assert.ok(await keyed.load(r.site.id, "/"));
    await assert.rejects(() => new PageBaselineStore(path.join(r.dir, "data")).load(r.site.id, "/"), /keyed but GUARD_JOURNAL_KEY is not set/);
  } finally { await r.cleanup(); }
});

test("no page baseline is null, and snapshot warns about a page that is already wrong", async () => {
  const r = await rig({}, { status: 503, finalUrl: "https://elsewhere.example/" });
  try {
    assert.equal(await r.store.load(r.site.id, "/nope"), null);
    const w = (await r.store.load(r.site.id, "/"))!.body.warnings.join("\n");
    assert.match(w, /HTTP 503/);
    assert.match(w, /ended on https:\/\/elsewhere\.example/);
  } finally { await r.cleanup(); }
});

/* ---------------------------------------------------- resolving request guard */

import { createRequestGuard } from "./net-guard.js";

test("a public-looking name that resolves to an internal address is refused", async () => {
  const answers: Record<string, string[] | Error> = {
    "evil.example": ["127.0.0.1"],
    "mixed.example": ["93.184.216.34", "10.0.0.5"],
    "v6.example": ["fd00::1"],
    "ok.example": ["93.184.216.34", "2606:2800:220:1::1"],
    "gone.example": new Error("ENOTFOUND"),
  };
  const asked: string[] = [];
  const guard = createRequestGuard({
    resolve: async (h) => {
      asked.push(h);
      const a = answers[h];
      if (a instanceof Error) throw a;
      return a ?? [];
    },
  });
  const site = "acme.example";
  assert.equal(await guard("https://ok.example/a.js", site), true);
  assert.equal(await guard("https://evil.example/a.js", site), false, "points at loopback");
  assert.equal(await guard("https://mixed.example/a.js", site), false, "one internal answer is enough");
  assert.equal(await guard("https://v6.example/a.js", site), false);
  assert.equal(await guard("https://gone.example/a.js", site), false, "a name that will not resolve is refused");
  assert.equal(await guard("https://unlisted.example/a.js", site), false, "no answers at all is refused");
  assert.equal(await guard("https://acme.example/own.js", site), true, "the site itself is never looked up");
  assert.equal(await guard("data:text/plain,hi", site), true);
  assert.equal(await guard("http://127.0.0.1/", site), false, "literals are still judged without a lookup");
  assert.ok(!asked.includes("acme.example") && !asked.includes("127.0.0.1"));
});

test("lookups are cached briefly, then asked again", async () => {
  let now = 1000;
  let n = 0;
  const guard = createRequestGuard({ resolve: async () => (n++, ["93.184.216.34"]), ttlMs: 500, now: () => now });
  for (let i = 0; i < 5; i++) await guard("https://cdn.example/x.js", "acme.example");
  assert.equal(n, 1);
  now += 501;
  await guard("https://cdn.example/x.js", "acme.example");
  assert.equal(n, 2);
});
