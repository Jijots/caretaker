/**
 * Which requests the page watcher's browser may make.
 *
 * The browser loads a page that may be attacker-controlled (that is the whole
 * point: a defaced site). Such a page can ask it to fetch http://127.0.0.1:..,
 * the cloud metadata address, or anything on the LAN of the machine running
 * Caretaker. So a request is allowed only if it goes to the monitored site's
 * own host:port, or to a host that is not an internal address.
 *
 * Limit, stated plainly: this judges the name or address in the URL. A public
 * hostname that RESOLVES to a private address (DNS rebinding) is not caught.
 * Run Caretaker on a network where the browser cannot reach anything sensitive.
 */

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
