/**
 * IP address parsing and range matching for both families, with no dependency.
 *
 * Addresses are compared as numbers, never as strings: "::1" and
 * "0:0:0:0:0:0:0:1" are the same address, and "::ffff:203.0.113.7" is the same
 * as "203.0.113.7" (an IPv4 client seen through a dual-stack socket). String
 * comparison gets both wrong, and an allowlist that misses its own entry would
 * block the owner.
 */

import { isIP } from "node:net";

export interface ParsedIp {
  family: 4 | 6;
  value: bigint;
}

export function parseIp(input: string): ParsedIp | null {
  const t = input.trim().toLowerCase().replace(/^\[|\]$/g, "").split("%")[0];
  const fam = isIP(t);
  if (fam === 4) {
    return { family: 4, value: t.split(".").reduce((n, p) => n * 256n + BigInt(p), 0n) };
  }
  if (fam !== 6) return null;

  let h = t;
  const tail4 = /^(.*:)(\d+\.\d+\.\d+\.\d+)$/.exec(h);
  if (tail4) {
    const [a, b, c, d] = tail4[2].split(".").map(Number);
    h = `${tail4[1]}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  let groups: string[];
  if (h.includes("::")) {
    const [head, tail] = h.split("::");
    const hp = head ? head.split(":") : [];
    const tp = tail ? tail.split(":") : [];
    groups = [...hp, ...Array<string>(8 - hp.length - tp.length).fill("0"), ...tp];
  } else {
    groups = h.split(":");
  }
  if (groups.length !== 8) return null;
  const value = groups.reduce((n, g) => (n << 16n) | BigInt(parseInt(g, 16)), 0n);
  if (value >> 32n === 0xffffn) return { family: 4, value: value & 0xffffffffn }; // IPv4-mapped
  return { family: 6, value };
}

/** True if `ip` is the address `entry`, or inside the range `entry` ("addr/bits"). Anything unparseable matches nothing. */
export function ipMatches(ip: string, entry: string): boolean {
  const [base, bits, ...rest] = entry.split("/");
  if (rest.length) return false;
  const a = parseIp(ip);
  const b = parseIp(base);
  if (!a || !b || a.family !== b.family) return false;
  if (bits === undefined) return a.value === b.value;
  if (!/^\d{1,3}$/.test(bits)) return false;
  const width = a.family === 4 ? 32 : 128;
  const len = Number(bits);
  if (len > width) return false;
  const shift = BigInt(width - len);
  return a.value >> shift === b.value >> shift;
}
