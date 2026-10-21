/**
 * Keeps secret VALUES out of what the scanner hands to a model.
 *
 * Why this exists: the API providers (groq, openai, and local) send every tool
 * result to a model endpoint on the next turn. A secrets audit is exactly the run
 * most likely to be pointed at a project with a real .env, so without this the
 * audit would copy the secrets it is looking for to a third party. A self-audit
 * run through Paperclip found that.
 *
 * What the model still gets: that a secret exists, where (file and line), what
 * kind it looks like, and how long it is. That is enough to report "a hardcoded
 * key is on line 12" without the key. What it no longer gets is the key.
 *
 * Two layers:
 *  1. Env files (.env, .env.local, .env.production, ...): every value is
 *     replaced, whatever it looks like, because a value there is a secret by
 *     convention. Variable NAMES stay. Template files (.env.example and similar)
 *     are left alone, they hold names and empty values by design.
 *  2. Anywhere else: values shaped like known credentials are replaced.
 *
 * Limits, stated plainly: layer 2 recognises shapes it knows. A password in
 * plain words, or a vendor key with no distinctive prefix, is not caught
 * outside an env file. This lowers the exposure, it does not remove it. The
 * default claude provider reads files itself and is not affected by this module.
 */

const TEMPLATE_SUFFIX = /\.(example|sample|template|dist|defaults?)$/i;

/** A real env file, not a template. */
export function isEnvFile(relPath: string): boolean {
  const name = relPath.replace(/\\/g, "/").split("/").pop() ?? "";
  return /^\.env(\..+)?$/i.test(name) && !TEMPLATE_SUFFIX.test(name);
}

const SHAPES: [string, RegExp][] = [
  ["private-key", /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g],
  // No leading \b on purpose: a key glued to a word ("bot123456:AA...", "Bearersk-...") would slip through.
  // The cost is an occasional over-match, which only hides a harmless string. Hence the longer minimum on sk-.
  ["openai-style-key", /sk-[A-Za-z0-9_-]{32,}/g],
  ["groq-key", /gsk_[A-Za-z0-9]{20,}/g],
  ["github-token", /gh[pousr]_[A-Za-z0-9]{30,}/g],
  ["aws-access-key", /AKIA[0-9A-Z]{16}/g],
  ["google-api-key", /AIza[0-9A-Za-z_-]{30,}/g],
  ["slack-token", /xox[baprs]-[A-Za-z0-9-]{10,}/g],
  ["telegram-bot-token", /\d{8,10}:AA[A-Za-z0-9_-]{30,}/g],
  ["jwt", /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g],
];

const marker = (label: string, matched: string): string => `[REDACTED ${label}, ${matched.length} chars]`;

/** Replace credential-shaped values. Newlines inside a match are kept, so line numbers do not move. */
export function redactSecretShapes(text: string): string {
  let out = text;
  for (const [label, re] of SHAPES) {
    out = out.replace(re, (m) => marker(label, m) + "\n".repeat((m.match(/\n/g) ?? []).length));
  }
  return out;
}

const ENV_ASSIGNMENT = /^(\s*(?:export\s+)?[A-Za-z_][A-Za-z0-9_.-]*\s*[=:]\s*)(.*)$/;

function redactEnvLine(line: string): string {
  const trimmed = line.trim();
  if (trimmed === "") return line;
  if (trimmed.startsWith("#")) {
    // A comment can still hold an old key. Mask anything long and token-like.
    return line.replace(/[A-Za-z0-9_\-+/=]{24,}/g, (m) => marker("token-like", m));
  }
  const m = ENV_ASSIGNMENT.exec(line);
  if (!m) return marker("env-line", line);
  const value = m[2].trim();
  if (value === "" || value === '""' || value === "''") return line; // an empty value is not a secret
  return `${m[1]}${marker("env value", value)}`;
}

/** The whole file as the model may see it. Line count is unchanged. */
export function redactForModel(relPath: string, text: string): string {
  const base = isEnvFile(relPath) ? text.split("\n").map(redactEnvLine).join("\n") : text;
  return redactSecretShapes(base);
}
