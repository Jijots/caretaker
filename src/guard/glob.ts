/**
 * A deliberately small glob matcher for watch rules, so the module does not
 * take a dependency for twenty lines of logic.
 *
 * Patterns are relative to the site root, use forward slashes, and are
 * anchored: "*.log" matches only at the root, "**\/*.log" matches anywhere.
 *   **   any number of path segments, including none
 *   *    anything within one segment
 *   ?    one character within one segment
 * A trailing slash means "everything under this directory".
 */

const cache = new Map<string, RegExp>();

function escape(c: string): string {
  return /[\\^$.|+(){}[\]]/.test(c) ? `\\${c}` : c;
}

export function globToRegExp(pattern: string, opts: { caseInsensitive?: boolean } = {}): RegExp {
  const key = `${opts.caseInsensitive ? "i" : "s"}:${pattern}`;
  const hit = cache.get(key);
  if (hit) return hit;

  let p = pattern.replace(/\\/g, "/").replace(/^\.\//, "");
  if (p.endsWith("/")) p += "**";

  let out = "";
  for (let i = 0; i < p.length; i++) {
    const c = p[i];
    if (c === "*" && p[i + 1] === "*") {
      const atStart = i === 0 || p[i - 1] === "/";
      const atEnd = i + 2 === p.length;
      const slashAfter = p[i + 2] === "/";
      if (atStart && slashAfter) {
        out += "(?:.*/)?"; // "**/" : zero or more whole segments
        i += 2;
      } else if (atStart && atEnd && i > 0) {
        out = out.slice(0, -1) + "(?:/.*)?"; // "dir/**" : the directory itself or anything under it
        i += 1;
      } else {
        out += ".*";
        i += 1;
      }
    } else if (c === "*") {
      out += "[^/]*";
    } else if (c === "?") {
      out += "[^/]";
    } else {
      out += escape(c);
    }
  }
  const re = new RegExp(`^${out}$`, opts.caseInsensitive ? "i" : "");
  cache.set(key, re);
  return re;
}

export function matchesAny(relPath: string, patterns: readonly string[], opts: { caseInsensitive?: boolean } = {}): boolean {
  return patterns.some((g) => globToRegExp(g, opts).test(relPath));
}

/** A pattern that would match every file, which as an exclude would blind the watcher. */
export function isTotalGlob(pattern: string): boolean {
  const p = pattern.trim().replace(/\\/g, "/");
  return p === "**" || p === "**/*" || p === "/" || p === "" || p === "**/" || p === "**/**";
}
