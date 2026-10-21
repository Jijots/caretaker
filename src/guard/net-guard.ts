/**
 * Which requests the page watcher's browser may make.
 *
 * The browser loads a page that may be attacker-controlled (that is the whole
 * point: a defaced site). Such a page can ask it to fetch http://127.0.0.1:..,
 * the cloud metadata address, or anything on the LAN of the machine running
 * Caretaker. So a request is allowed only if it goes to the monitored site's
 * own host:port, or to a host that is not an internal address.
 *
 * requestAllowed() judges the address written in the URL. createRequestGuard()
 * also resolves names, so a public-looking hostname that points at a private
 * address is refused. Limit, stated plainly: DNS rebinding (an answer that
 * changes between our lookup and the browser's own) is narrowed, not closed.
 * Run Caretaker on a network where the browser cannot reach anything sensitive.
 */

import { promises as dns } from "node:dns";
import { isIP } from "node:net";

const ALLOWED_SCHEMES = new Set(["http:", "https:", "data:", "blob:", "about:"]);

function v4Private(a: number, b: number): boolean {
  return (
    a === 0 || a === 10 || a === 127 ||
    (a === 100 && b >= 64 && b <= 127) || // carrier-grade NAT
    (a === 169 && b === 254) || // link-local, including cloud metadata
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    a >= 224 // multicast and reserved
  );
}

export function isInternalHost(hostname: string): boolean {
  let h = hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  if (h === "localhost" || h.endsWith(".localhost") || h.endsWith(".local") || h.endsWith(".internal") || h.endsWith(".lan")) return true;
  // Decimal, hex and octal IPv4 spellings are normalised by the URL parser before they get here.
  const fam = isIP(h);
  if (fam === 4) {
    const [a, b] = h.split(".").map(Number);
    return v4Private(a, b);
  }
  if (fam === 6) {
    if (h === "::" || h === "::1") return true;
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(h);
    if (mapped) {
      const [a, b] = mapped[1].split(".").map(Number);
      return v4Private(a, b);
    }
    const mappedHex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(h);
    if (mappedHex) {
      const hi = parseInt(mappedHex[1], 16);
      return v4Private(hi >> 8, hi & 255);
    }
    return /^f[cd]/.test(h) || /^fe[89ab]/.test(h); // unique-local fc00::/7, link-local fe80::/10
  }
  return false;
}

/** True if the browser may make this request on behalf of a site whose own host:port is siteHost. */
export function requestAllowed(requestUrl: string, siteHost: string): boolean {
  let u: URL;
  try {
    u = new URL(requestUrl);
  } catch {
    return false;
  }
  if (!ALLOWED_SCHEMES.has(u.protocol)) return false;
  if (u.protocol === "data:" || u.protocol === "blob:" || u.protocol === "about:") return true;
  if (u.host.toLowerCase() === siteHost.toLowerCase()) return true;
  return !isInternalHost(u.hostname);
}

/* ------------------------------------------------------- resolved names */

export type Resolver = (hostname: string) => Promise<string[]>;

const defaultResolver: Resolver = async (hostname) => (await dns.lookup(hostname, { all: true, verbatim: true })).map((a) => a.address);

/**
 * requestAllowed() plus a lookup of the name. "evil.example" with an A record of
 * 127.0.0.1 looks public to a string check and is not. Every address the name
 * resolves to must be public, and a name that will not resolve is refused.
 *
 * This narrows DNS rebinding and does not close it: the browser resolves the
 * name again itself, and an attacker who answers differently the second time
 * (a very short TTL) can still get through. Results are cached briefly so a page
 * with fifty images from one host costs one lookup.
 */
export function createRequestGuard(opts: { resolve?: Resolver; ttlMs?: number; now?: () => number } = {}) {
  const resolve = opts.resolve ?? defaultResolver;
  const ttl = opts.ttlMs ?? 30_000;
  const now = opts.now ?? Date.now;
  const cache = new Map<string, { ok: boolean; until: number }>();

  return async function allowed(requestUrl: string, siteHost: string): Promise<boolean> {
    if (!requestAllowed(requestUrl, siteHost)) return false;
    const u = new URL(requestUrl);
    if (u.protocol !== "http:" && u.protocol !== "https:") return true;
    if (u.host.toLowerCase() === siteHost.toLowerCase()) return true;
    const host = u.hostname.toLowerCase().replace(/^\[|\]$/g, "");
    if (isIP(host)) return true; // a literal was already judged above
    const hit = cache.get(host);
    if (hit && hit.until > now()) return hit.ok;
    let ok: boolean;
    try {
      const addrs = await resolve(host);
      ok = addrs.length > 0 && addrs.every((a) => !isInternalHost(a));
    } catch {
      ok = false;
    }
    if (cache.size > 2000) cache.clear();
    cache.set(host, { ok, until: now() + ttl });
    return ok;
  };
}
