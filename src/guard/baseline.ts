/**
 * Baselines: what "known good" means for a site, kept OFF the monitored host
 * (GUARD_DATA_DIR, which config.ts refuses to place inside a web root).
 *
 * Layout under <dataDir>/baselines/<siteId>/:
 *   manifest.json     path -> { sha256, size }, plus how and when it was taken
 *   objects/<sha256>  the bytes of every file small enough to store, so a later
 *                     restore has something to restore FROM
 *
 * Two things are stated plainly because they are easy to assume the other way:
 *
 *  - A snapshot trusts the site as it is at that moment. If the site is already
 *    defaced or backdoored, the snapshot enshrines that as normal. The CLI says
 *    so when it takes one, and the manifest records the source as "snapshot".
 *    Checking against a vendor's published checksums or a git commit is a
 *    stronger source and a later addition, not something this file provides.
 *
 *  - The manifest carries a digest (HMAC when GUARD_JOURNAL_KEY is set). It
 *    detects casual edits and, keyed, forgery by someone without the key. It is
 *    not a defence against an attacker who controls the host holding it.
 *
 * Every write is write-to-temp then rename, so a crash never leaves a half
 * manifest, and a manifest is never replaced by anything that failed to verify.
 */

import { promises as fs } from "node:fs";
import path from "node:path";
import { createHash, createHmac, randomBytes } from "node:crypto";
import { z } from "zod";
import { canonicalize } from "./canonical.js";
import { matchesAny } from "./glob.js";
import { effectiveIntegrityRules, type SiteConfig } from "./config.js";
import type { SiteTransport } from "./transport.js";

export const BASELINE_VERSION = 1 as const;

const Sha = z.string().regex(/^[a-f0-9]{64}$/);

const BaselineFile = z
  .object({
    sha256: Sha,
    size: z.number().int().min(0),
    /** True when the bytes are in objects/, so the file can be restored. */
    stored: z.boolean(),
  })
  .strict();
export type BaselineFile = z.infer<typeof BaselineFile>;

const Body = z
  .object({
    v: z.literal(BASELINE_VERSION),
    siteId: z.string(),
    createdAt: z.string().datetime(),
    /** Where "known good" came from. Only "snapshot" exists so far. */
    source: z.enum(["snapshot"]),
    note: z.string().max(500).optional(),
    files: z.record(z.string().max(1000), BaselineFile),
  })
  .strict();

export const BaselineManifest = z.object({ body: Body, digest: Sha, keyed: z.boolean() }).strict();
export type BaselineManifest = z.infer<typeof BaselineManifest>;
export type BaselineBody = z.infer<typeof Body>;

export class BaselineError extends Error {}

/** SHA-256 of the canonical JSON, or HMAC-SHA-256 when a key is given. Shared by every baseline kind. */
export function digestJson(value: unknown, key?: Buffer): string {
  const data = canonicalize(value);
  return key ? createHmac("sha256", key).update(data).digest("hex") : createHash("sha256").update(data).digest("hex");
}

const digestOf = (body: BaselineBody, key?: Buffer): string => digestJson(body, key);

export async function atomicWrite(file: string, data: string | Buffer): Promise<void> {
  await fs.mkdir(path.dirname(file), { recursive: true });
  const tmp = `${file}.${randomBytes(6).toString("hex")}.tmp`;
  try {
    await fs.writeFile(tmp, data, { flag: "wx" });
    await fs.rename(tmp, file);
  } catch (e) {
    await fs.rm(tmp, { force: true });
    throw e;
  }
}

export class BaselineStore {
  constructor(
    private readonly dataDir: string,
    private readonly key?: Buffer,
  ) {}

  dir(siteId: string): string {
    return path.join(this.dataDir, "baselines", siteId);
  }
  private manifestPath(siteId: string): string {
    return path.join(this.dir(siteId), "manifest.json");
  }
  objectPath(siteId: string, sha256: string): string {
    if (!Sha.safeParse(sha256).success) throw new BaselineError("not a sha256");
    return path.join(this.dir(siteId), "objects", sha256);
  }

  /** The manifest, or null if none exists. Throws BaselineError if one exists and does not verify. */
  async load(siteId: string): Promise<BaselineBody | null> {
    let text: string;
    try {
      text = await fs.readFile(this.manifestPath(siteId), "utf8");
    } catch (e: any) {
      if (e?.code === "ENOENT") return null;
      throw e;
    }
    let parsed;
    try {
      parsed = BaselineManifest.safeParse(JSON.parse(text));
    } catch {
      throw new BaselineError(`baseline for '${siteId}' is not valid JSON`);
    }
    if (!parsed.success) throw new BaselineError(`baseline for '${siteId}' has an unexpected shape`);
    const m = parsed.data;
    if (m.body.siteId !== siteId) throw new BaselineError(`baseline file for '${siteId}' belongs to '${m.body.siteId}'`);
    if (m.keyed && !this.key) throw new BaselineError(`baseline for '${siteId}' is keyed but GUARD_JOURNAL_KEY is not set`);
    if (!m.keyed && this.key) {
      throw new BaselineError(`baseline for '${siteId}' is unkeyed but GUARD_JOURNAL_KEY is set. A keyless baseline can be forged, so take a new snapshot to key it.`);
    }
    if (digestOf(m.body, m.keyed ? this.key : undefined) !== m.digest) {
      throw new BaselineError(`baseline for '${siteId}' fails its digest check. It was edited, or the key is wrong.`);
    }
    return m.body;
  }

  /** Read a stored file's bytes, verifying them against their hash. */
  async readObject(siteId: string, sha256: string): Promise<Buffer> {
    const buf = await fs.readFile(this.objectPath(siteId, sha256));
    if (createHash("sha256").update(buf).digest("hex") !== sha256) {
      throw new BaselineError(`stored copy ${sha256.slice(0, 12)} for '${siteId}' is corrupt`);
    }
    return buf;
  }

  /**
   * Walk the site and record it. Replaces any existing baseline only if this
   * one is complete; a failure partway leaves the previous baseline untouched.
   */
  async snapshot(
    site: SiteConfig,
    transport: SiteTransport,
    opts: { note?: string; now?: () => Date } = {},
  ): Promise<{ body: BaselineBody; stored: number; hashOnly: number; skippedUnreadable: string[] }> {
    const rules = effectiveIntegrityRules(site);
    const files: Record<string, BaselineFile> = {};
    const unreadable: string[] = [];
    let stored = 0;
    let hashOnly = 0;

    const listed = await transport.list("", {
      recursive: true,
      maxEntries: site.integrity.maxFiles,
      skipDir: (rel) => matchesAny(rel, rules.exclude),
      onUnreadable: (rel) => unreadable.push(rel),
    });

    for (const f of listed) {
      if (!matchesAny(f.path, rules.include) || matchesAny(f.path, rules.exclude) || matchesAny(f.path, rules.uploadDirs)) continue;
      try {
        const h = await transport.hash(f.path);
        const keep = !f.isSymlink && h.size <= site.integrity.maxStoreBytes;
        if (keep) {
          const bytes = await transport.read(f.path, { maxBytes: site.integrity.maxStoreBytes });
          const actual = createHash("sha256").update(bytes).digest("hex");
          // The file changed between hashing and reading. Do not enshrine a half-state.
          if (actual !== h.sha256) throw new BaselineError(`'${f.path}' changed while the snapshot was being taken`);
          const objPath = this.objectPath(site.id, h.sha256);
          const exists = await fs.stat(objPath).then(() => true, () => false);
          if (!exists) await atomicWrite(objPath, bytes);
          stored++;
        } else {
          hashOnly++;
        }
        files[f.path] = { sha256: h.sha256, size: h.size, stored: keep };
      } catch (e: any) {
        if (e instanceof BaselineError) throw e;
        if (e?.code === "ENOENT") continue; // removed during the walk
        unreadable.push(f.path);
      }
    }

    const body: BaselineBody = {
      v: BASELINE_VERSION,
      siteId: site.id,
      createdAt: (opts.now?.() ?? new Date()).toISOString(),
      source: "snapshot",
      ...(opts.note ? { note: opts.note.slice(0, 500) } : {}),
      files,
    };
    Body.parse(body);
    const manifest: BaselineManifest = { body, digest: digestOf(body, this.key), keyed: !!this.key };
    await atomicWrite(this.manifestPath(site.id), JSON.stringify(manifest, null, 1) + "\n");
    return { body, stored, hashOnly, skippedUnreadable: unreadable };
  }
}
