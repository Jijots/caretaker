/**
 * What the Page watcher keeps about a page, and the pure functions that turn a
 * rendered page into it. No browser here: the fetcher (browser.ts) hands over a
 * RawPage and everything below is deterministic and testable without one.
 *
 * Everything in a RawPage is attacker-controlled when the site is defaced, so
 * it is bounded on the way in and treated as inert data on the way out.
 */

import { createHash } from "node:crypto";

export interface RawPage {
  url: string;
  finalUrl: string;
  status: number;
  title: string;
  lang: string;
  /** Visible and hidden text nodes outside whitelisted regions, whitespace collapsed. */
  texts: string[];
  /** Tag names, in order, outside whitelisted regions. */
  skeleton: string[];
  scriptSrcs: string[];
  /** http(s) URLs written inside inline scripts. */
  inlineScriptUrls: string[];
  iframes: { src: string; hidden: boolean }[];
  metaRefresh: string | null;
  png: Buffer | null;
  warnings: string[];
}

export interface PageFetcher {
  fetch(url: string, opts: { hideSelectors: string[]; screenshot: boolean }): Promise<RawPage>;
  close(): Promise<void>;
}

export interface IframeRef {
  key: string;
  origin: string;
  hidden: boolean;
}

export interface PageDigest {
  status: number;
  finalOrigin: string;
  finalPath: string;
  title: string;
  lang: string;
  texts: string[];
  skeletonHash: string;
  /** Origins other than the site's own that scripts (or inline scripts) load from. */
  scriptOrigins: string[];
  iframes: IframeRef[];
  dominantScript: string;
  /** Ids of defacement phrases present in the page. */
  signals: string[];
  metaRefreshOrigin: string | null;
}

const MAX_TEXTS = 5000;
const MAX_TEXT_LEN = 300;
const MAX_TOTAL_CHARS = 300_000;

export const sha256 = (s: string | Buffer): string => createHash("sha256").update(s).digest("hex");

function originOf(url: string, base?: string): string | null {
  try {
    const u = new URL(url, base);
    return /^https?:$/.test(u.protocol) ? u.origin : null;
  } catch {
    return null;
  }
}

/* ----------------------------------------------------------- defacement text */

export interface SignalDef {
  id: string;
  re: RegExp;
  strength: "strong" | "weak";
}

/**
 * Phrases defacers actually leave behind. Strong ones are specific enough that a
 * match is nearly always hostile. Weak ones appear in innocent copy ("family
 * owned by...") and only count as a hint. A phrase already present when the
 * baseline was taken is ignored, so a security blog that quotes "hacked by" in
 * an article does not raise an alert every pass.
 */
export const SIGNALS: SignalDef[] = [
  { id: "hacked-by", re: /\b(hack(ed|3d)|h4ck(ed|3d)?)\s+by\b/i, strength: "strong" },
  { id: "defaced-by", re: /\bdefac(ed|3d)\s+by\b/i, strength: "strong" },
  // Deliberately narrow. "Your site is compromised" is ordinary copy for a malware-cleanup business, and
  // "Greetings to our patients" is ordinary copy for a clinic, so neither is a strong signal.
  { id: "site-hacked", re: /\b(this|your|the)\s+(web)?site\s+(has\s+been|was|got)\s+(hacked|defaced|pwned)\b/i, strength: "strong" },
  { id: "pwned-by", re: /\bpwn(ed|3d)\s+by\b/i, strength: "strong" },
  { id: "greetz", re: /\bgreetz\s+(to|fly)\b/i, strength: "strong" },
  { id: "owned-by", re: /\bowned\s+by\b/i, strength: "weak" },
  { id: "pwned", re: /\bpwn(ed|3d)\b/i, strength: "weak" },
  { id: "was-here", re: /\bwas\s+here\b/i, strength: "weak" },
  { id: "cyber-army", re: /\bcyber\s+(army|team|crew|warriors?)\b/i, strength: "weak" },
];

export function customSignals(phrases: string[]): SignalDef[] {
  return phrases.map((p, i) => ({
    id: `custom-${i}`,
    re: new RegExp(p.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i"),
    strength: "strong" as const,
  }));
}

export function findSignals(haystack: string, defs: SignalDef[]): { id: string; strength: "strong" | "weak"; snippet: string }[] {
  const out: { id: string; strength: "strong" | "weak"; snippet: string }[] = [];
  for (const d of defs) {
    const m = d.re.exec(haystack);
    if (!m) continue;
    const from = Math.max(0, m.index - 40);
    // eslint-disable-next-line no-control-regex
    const snippet = haystack.slice(from, m.index + m[0].length + 40).replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, 120);
    out.push({ id: d.id, strength: d.strength, snippet });
  }
  return out;
}

/* ------------------------------------------------------------------ script */

const SCRIPT_RANGES: [string, RegExp][] = [
  ["latin", /\p{Script=Latin}/gu],
  ["cyrillic", /\p{Script=Cyrillic}/gu],
  ["arabic", /\p{Script=Arabic}/gu],
  ["han", /\p{Script=Han}/gu],
  ["kana", /[\p{Script=Hiragana}\p{Script=Katakana}]/gu],
  ["hangul", /\p{Script=Hangul}/gu],
  ["devanagari", /\p{Script=Devanagari}/gu],
  ["thai", /\p{Script=Thai}/gu],
  ["hebrew", /\p{Script=Hebrew}/gu],
  ["greek", /\p{Script=Greek}/gu],
];

/** The writing system most of the letters are in, or "unknown" when there is too little text to say. */
export function dominantScript(texts: string[]): { script: string; share: number } {
  const joined = texts.join(" ");
  const counts = SCRIPT_RANGES.map(([name, re]) => [name, (joined.match(re) ?? []).length] as const);
  const total = counts.reduce((n, [, c]) => n + c, 0);
  if (total < 40) return { script: "unknown", share: 0 };
  const [name, c] = counts.reduce((a, b) => (b[1] > a[1] ? b : a));
  return { script: name, share: c / total };
}

/* ------------------------------------------------------------------ digest */

export function boundTexts(texts: string[]): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  let chars = 0;
  for (const raw of texts) {
    const t = raw.replace(/\s+/g, " ").trim().slice(0, MAX_TEXT_LEN);
    if (!t || seen.has(t)) continue;
    seen.add(t);
    chars += t.length;
    if (out.length >= MAX_TEXTS || chars > MAX_TOTAL_CHARS) break;
    out.push(t);
  }
  return out;
}

export function digestPage(raw: RawPage, siteOrigin: string, extra: SignalDef[] = []): PageDigest {
  const texts = boundTexts(raw.texts);
  const scriptOrigins = new Set<string>();
  for (const s of [...raw.scriptSrcs, ...raw.inlineScriptUrls]) {
    const o = originOf(s, raw.finalUrl);
    if (o && o !== siteOrigin) scriptOrigins.add(o);
  }
  const iframes: IframeRef[] = [];
  const seenFrames = new Set<string>();
  for (const f of raw.iframes.slice(0, 100)) {
    const o = originOf(f.src, raw.finalUrl);
    const key = f.src.startsWith("about:") || !f.src ? f.src || "about:blank" : (() => {
      try {
        const u = new URL(f.src, raw.finalUrl);
        return u.origin + u.pathname;
      } catch {
        return f.src.slice(0, 200);
      }
    })();
    if (seenFrames.has(key)) {
      const prev = iframes.find((x) => x.key === key)!;
      prev.hidden = prev.hidden || f.hidden;
      continue;
    }
    seenFrames.add(key);
    iframes.push({ key, origin: o ?? (f.src || "about:blank").slice(0, 100), hidden: f.hidden });
  }
  let finalOrigin = "";
  let finalPath = "";
  try {
    const u = new URL(raw.finalUrl);
    finalOrigin = u.origin;
    finalPath = u.pathname;
  } catch {
    /* leave empty: it will not match the baseline, which is the right outcome */
  }
  const haystack = [raw.title, ...texts].join("\n");
  return {
    status: raw.status,
    finalOrigin,
    finalPath,
    title: raw.title.replace(/\s+/g, " ").trim().slice(0, 300),
    lang: raw.lang.slice(0, 20),
    texts,
    skeletonHash: sha256(raw.skeleton.slice(0, 20_000).join(",")),
    scriptOrigins: [...scriptOrigins].sort(),
    iframes,
    dominantScript: dominantScript(texts).script,
    signals: findSignals(haystack, [...SIGNALS, ...extra]).map((s) => s.id),
    metaRefreshOrigin: raw.metaRefresh ? originOf((/url\s*=\s*['"]?([^'";\s]+)/i.exec(raw.metaRefresh) ?? [])[1] ?? "", raw.finalUrl) : null,
  };
}

/** Fraction of text blocks that differ, added plus removed over both sides. 0 identical, 1 nothing in common. */
export function textChange(baseline: string[], current: string[], volatile: ReadonlySet<string>): { ratio: number; added: string[]; removed: string[] } {
  const b = new Set(baseline.filter((t) => !volatile.has(t)));
  const c = new Set(current.filter((t) => !volatile.has(t)));
  const added = [...c].filter((t) => !b.has(t));
  const removed = [...b].filter((t) => !c.has(t));
  const denom = b.size + c.size;
  return { ratio: denom ? (added.length + removed.length) / denom : 0, added, removed };
}
