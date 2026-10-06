/**
 * Per-site configuration. One JSON file per site, strictly validated.
 *
 * Two rules that are enforced here rather than left to documentation:
 *
 *  - Secrets never appear in config. Fields ending in Env hold the NAME of an
 *    environment variable (TELEGRAM_CHAT_ID_ACME), and the schema rejects
 *    anything that does not look like one, so pasting a real token fails
 *    validation. The error message deliberately does not echo the value back.
 *
 *  - The journal and baselines must not live inside a monitored web root. An
 *    attacker who can write the site can otherwise rewrite the evidence and
 *    the baseline that defines "normal". assertDataDirOffHost() refuses to
 *    start in that situation.
 */

import { z } from "zod";
import { isIP } from "node:net";
import { promises as fs, realpathSync } from "node:fs";
import path from "node:path";
import { SiteId } from "./events.js";
import { isTotalGlob } from "./glob.js";

export const DAYS = ["sun", "mon", "tue", "wed", "thu", "fri", "sat"] as const; // index matches Date#getDay
const Day = z.enum(DAYS);

const EnvName = z
  .string()
  .regex(/^[A-Z][A-Z0-9_]{1,63}$/, "must be the NAME of an environment variable (UPPER_SNAKE_CASE), never the secret itself");

const Hhmm = z.string().regex(/^([01]\d|2[0-3]):[0-5]\d$/, "HH:MM in 24 hour time");

export const DeployWindow = z
  .object({
    days: z.array(Day).min(1).max(7),
    start: Hhmm,
    end: Hhmm,
    note: z.string().max(200).optional(),
  })
  .strict()
  .refine((w) => w.start !== w.end, "start and end must differ. A window that ends before it starts runs overnight.");
export type DeployWindow = z.infer<typeof DeployWindow>;

/** Selectors that would blind the page watcher completely. A whitelist is a blind spot, so these are refused. */
const TOTAL_BLIND_SELECTORS = new Set(["*", "html", "body", ":root"]);

export const PageRegion = z
  .object({
    page: z.string().max(500).refine((p) => p === "*" || p.startsWith("/"), "a path starting with / or *"),
    selector: z
      .string()
      .min(1)
      .max(200)
      .refine((s) => !TOTAL_BLIND_SELECTORS.has(s.trim().toLowerCase()), "that selector covers the whole page and would disable the Page watcher"),
    reason: z.string().min(3).max(200),
  })
  .strict();
export type PageRegion = z.infer<typeof PageRegion>;

const LocalFs = z
  .object({
    type: z.literal("local-fs"),
    root: z.string().min(1).refine((p) => path.isAbsolute(p), "must be an absolute path"),
  })
  .strict();

const Git = z
  .object({
    type: z.literal("git"),
    remote: z
      .string()
      .min(1)
      .max(500)
      .refine((r) => !/:\/\/[^/@]*:[^/@]*@/.test(r), "the remote URL must not embed a password or token. Use an SSH key or a credential helper."),
    branch: z.string().min(1).max(200).default("main"),
    deployHookEnv: EnvName.optional(),
  })
  .strict();

const NoAccess = z.object({ type: z.literal("none") }).strict();

export const TransportConfig = z.discriminatedUnion("type", [LocalFs, Git, NoAccess]);
export type TransportConfig = z.infer<typeof TransportConfig>;

function isIpOrCidr(s: string): boolean {
  const [addr, prefix, ...rest] = s.split("/");
  if (rest.length) return false;
  const fam = isIP(addr);
  if (!fam) return false;
  if (prefix === undefined) return true;
  if (!/^\d{1,3}$/.test(prefix)) return false;
  return Number(prefix) <= (fam === 4 ? 32 : 128);
}

export const Responder = z
  .object({
    /** The responder is OFF unless a site opts in, and it only runs from its own separate command. */
    enabled: z.boolean().default(false),
    /** dry-run records what it would do and changes nothing. */
    mode: z.enum(["dry-run", "live"]).default("dry-run"),
    autoRestoreMinConfidence: z.number().min(0.5).max(1).default(0.9),
    /** Off by default: one public address can be thousands of people behind carrier-grade NAT. */
    autoBlockIps: z.boolean().default(false),
    ipBlockTtlMinutes: z.number().int().min(1).max(1440).default(60),
    ipAllowlist: z.array(z.string().refine(isIpOrCidr, "not an IP address or CIDR range")).max(200).default([]),
    /** Loop breaker: restoring is not fixing. After this many in the window, stop and ask a human. */
    maxRestoresPerWindow: z.number().int().min(1).max(10).default(2),
    restoreWindowMinutes: z.number().int().min(5).max(1440).default(60),
  })
  .strict();
export type Responder = z.infer<typeof Responder>;

const RelGlob = z
  .string()
  .min(1)
  .max(300)
  .refine((g) => !g.replace(/\\/g, "/").split("/").includes(".."), "may not contain ..")
  .refine((g) => !/^([a-zA-Z]:|[/\\])/.test(g), "relative to the site root, without a leading slash");

/**
 * What the Integrity watcher looks at. Patterns are globs relative to the site
 * root (see glob.ts). Platform defaults are added unless turned off, so a
 * WordPress site gets its cache excluded and its uploads treated as uploads
 * without anyone having to know those paths.
 */
export const IntegrityRules = z
  .object({
    platformDefaults: z.boolean().default(true),
    include: z.array(RelGlob).min(1).max(100).default(["**"]),
    exclude: z
      .array(RelGlob.refine((g) => !isTotalGlob(g), "that pattern excludes every file and would disable the Integrity watcher"))
      .max(200)
      .default([]),
    /**
     * Where visitors' files land. Content here changes all the time and is not
     * baselined, but every pass checks it for anything that could execute.
     */
    uploadDirs: z.array(RelGlob).max(50).default([]),
    intervalSeconds: z.number().int().min(30).max(86_400).default(300),
    /** Every Nth pass rehashes every file instead of trusting size, mtime and ctime. */
    fullRehashEvery: z.number().int().min(1).max(1000).default(12),
    maxFiles: z.number().int().min(100).max(1_000_000).default(100_000),
    /** Larger files are baselined by hash only, so they can be detected but not restored. */
    maxStoreBytes: z.number().int().min(1024).max(200 * 1024 * 1024).default(10 * 1024 * 1024),
  })
  .strict();
export type IntegrityRules = z.infer<typeof IntegrityRules>;

export const SITE_PLATFORMS = ["wordpress", "nextjs", "laravel", "codeigniter", "wix", "static", "other"] as const;

export const SiteConfig = z
  .object({
    id: SiteId,
    name: z.string().min(1).max(120),
    baseUrl: z
      .string()
      .url()
      // zod runs refinements even after .url() has failed, so this must not throw on a malformed string.
      .refine((u) => {
        try {
          return /^https?:$/.test(new URL(u).protocol);
        } catch {
          return false;
        }
      }, "http or https only"),
    platform: z.enum(SITE_PLATFORMS),
    timezone: z
      .string()
      .default("Asia/Manila")
      .refine((tz) => {
        try {
          new Intl.DateTimeFormat("en-US", { timeZone: tz });
          return true;
        } catch {
          return false;
        }
      }, "not a valid IANA time zone"),
    transport: TransportConfig,
    pages: z.array(z.string().startsWith("/").max(500)).min(1).max(50).default(["/"]),
    deployWindows: z.array(DeployWindow).max(20).default([]),
    pageRegions: z.array(PageRegion).max(100).default([]),
    owner: z.object({ telegramChatIdEnv: EnvName.optional() }).strict().default({}),
    responder: Responder.default({}),
    integrity: IntegrityRules.default({}),
  })
  .strict()
  .superRefine((s, ctx) => {
    s.pageRegions.forEach((r, i) => {
      if (r.page !== "*" && !s.pages.includes(r.page)) {
        ctx.addIssue({ code: "custom", path: ["pageRegions", i, "page"], message: `'${r.page}' is not one of this site's watched pages` });
      }
    });
  });
export type SiteConfig = z.infer<typeof SiteConfig>;

/* ----------------------------------------------------------- loading */

export function formatIssues(err: z.ZodError, label: string): string[] {
  return err.issues.map((i) => `${label}: ${i.path.join(".") || "(root)"}: ${i.message}`);
}

export class ConfigError extends Error {
  constructor(readonly problems: string[]) {
    super(problems.join("\n"));
  }
}

export async function loadSiteFile(file: string): Promise<SiteConfig> {
  let raw: unknown;
  try {
    raw = JSON.parse(await fs.readFile(file, "utf8"));
  } catch (e: any) {
    throw new ConfigError([`${file}: ${e?.code === "ENOENT" ? "file not found" : "not valid JSON"}`]);
  }
  const parsed = SiteConfig.safeParse(raw);
  if (!parsed.success) throw new ConfigError(formatIssues(parsed.error, file));
  return parsed.data;
}

/** Every *.site.json in a directory. A missing directory is an empty fleet, not an error. */
export async function loadSites(dir: string): Promise<Map<string, SiteConfig>> {
  let names: string[] = [];
  try {
    names = (await fs.readdir(dir)).filter((n) => n.endsWith(".site.json")).sort();
  } catch (e: any) {
    if (e?.code !== "ENOENT") throw e;
  }
  const sites = new Map<string, SiteConfig>();
  const problems: string[] = [];
  for (const n of names) {
    try {
      const s = await loadSiteFile(path.join(dir, n));
      if (sites.has(s.id)) problems.push(`${n}: duplicate site id '${s.id}'`);
      else sites.set(s.id, s);
    } catch (e) {
      if (e instanceof ConfigError) problems.push(...e.problems);
      else throw e;
    }
  }
  if (problems.length) throw new ConfigError(problems);
  return sites;
}

/* -------------------------------------------------- guard-wide settings */

export interface GuardPaths {
  dataDir: string;
  sitesDir: string;
  /** HMAC key for the journal chain. From the environment, never from a file in the repo. */
  journalKey?: Buffer;
}

export function resolveGuardPaths(env: NodeJS.ProcessEnv = process.env): GuardPaths {
  const key = env.GUARD_JOURNAL_KEY;
  if (key !== undefined && key.length < 32) {
    throw new ConfigError(["GUARD_JOURNAL_KEY is set but shorter than 32 characters. A weak key makes the HMAC chain pointless."]);
  }
  return {
    dataDir: path.resolve(env.GUARD_DATA_DIR ?? ".guard-data"),
    sitesDir: path.resolve(env.GUARD_SITES_DIR ?? "guard-sites"),
    journalKey: key ? Buffer.from(key, "utf8") : undefined,
  };
}

function canon(p: string): string {
  const abs = path.resolve(p);
  try {
    return realpathSync.native(abs);
  } catch {
    return abs; // does not exist yet; fall back to the resolved path
  }
}

export function isInside(child: string, parent: string): boolean {
  const rel = path.relative(canon(parent), canon(child));
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

/**
 * Guardrail: baselines and the audit journal must not sit inside a web root
 * the agent watches. Necessary, not sufficient. If the agent runs ON the
 * monitored host, anything it can write an attacker with the same access can
 * too, and only running it elsewhere fully solves that.
 */
export function assertDataDirOffHost(dataDir: string, sites: Iterable<SiteConfig>): void {
  const problems: string[] = [];
  for (const s of sites) {
    if (s.transport.type === "local-fs" && isInside(dataDir, s.transport.root)) {
      problems.push(
        `site '${s.id}': the data directory (${dataDir}) is inside the monitored web root (${s.transport.root}). ` +
          `An attacker who can write the site could rewrite the baseline and the audit trail. Move GUARD_DATA_DIR outside it.`,
      );
    }
  }
  if (problems.length) throw new ConfigError(problems);
}

/* ------------------------------------------------- integrity defaults */

export interface EffectiveIntegrityRules {
  include: string[];
  exclude: string[];
  uploadDirs: string[];
}

/** Always excluded: version control internals change on every pull and are not served. */
const ALWAYS_EXCLUDE = [".git/**", ".svn/**", ".hg/**"];

/** Generated or volatile paths per platform, and where uploads land. Sources: each platform's documented directory layout. */
export const PLATFORM_INTEGRITY: Record<SiteConfig["platform"], { exclude: string[]; uploadDirs: string[] }> = {
  wordpress: {
    exclude: ["wp-content/cache/**", "wp-content/upgrade/**", "wp-content/debug.log", "wp-content/wflogs/**"],
    uploadDirs: ["wp-content/uploads/**"],
  },
  laravel: {
    exclude: ["storage/framework/**", "storage/logs/**", "bootstrap/cache/**"],
    uploadDirs: ["storage/app/public/**", "public/storage/**", "public/uploads/**"],
  },
  codeigniter: {
    exclude: ["writable/cache/**", "writable/logs/**", "writable/session/**", "writable/debugbar/**", "application/cache/**", "application/logs/**"],
    uploadDirs: ["writable/uploads/**", "public/uploads/**", "uploads/**"],
  },
  nextjs: { exclude: [".next/cache/**", "node_modules/.cache/**"], uploadDirs: ["public/uploads/**"] },
  static: { exclude: [], uploadDirs: [] },
  wix: { exclude: [], uploadDirs: [] },
  other: { exclude: [], uploadDirs: [] },
};

export function effectiveIntegrityRules(site: SiteConfig): EffectiveIntegrityRules {
  const r = site.integrity;
  const d = r.platformDefaults ? PLATFORM_INTEGRITY[site.platform] : { exclude: [], uploadDirs: [] };
  const uniq = (xs: string[]) => [...new Set(xs)];
  return {
    include: uniq(r.include),
    exclude: uniq([...ALWAYS_EXCLUDE, ...d.exclude, ...r.exclude]),
    uploadDirs: uniq([...d.uploadDirs, ...r.uploadDirs]),
  };
}
