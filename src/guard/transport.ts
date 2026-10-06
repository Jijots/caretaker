/**
 * How the agent reaches a site. Phase 1 defined the contract and what each
 * transport is able to do. The local filesystem implementation is in
 * transport-local.ts (Phase 2); the git restore adapter arrives in Phase 5.
 *
 * SiteTransport is READ-ONLY by construction. Watchers are only ever handed
 * this type, so they cannot change a site even by mistake. Anything that
 * writes (restore, quarantine, maintenance page) will be a separate, wider
 * interface that only the responder receives.
 */

import type { TransportConfig } from "./config.js";

export interface FileEntry {
  /** Path relative to the site root, forward slashes. */
  path: string;
  size: number;
  mtimeMs: number;
  /**
   * Inode change time. Unlike mtime, an ordinary user cannot set it back, so a
   * file rewritten with its old size and mtime restored still shows a new ctime.
   */
  ctimeMs: number;
  /** Symlinks are reported, never followed out of the root. */
  isSymlink: boolean;
}

export interface ListOptions {
  recursive?: boolean;
  /** Fail loudly past this many entries rather than return a silently partial list. */
  maxEntries?: number;
  /** Return true to skip a directory entirely (it is not descended into or listed). */
  skipDir?: (relPath: string) => boolean;
  /** Called for a directory that could not be read, instead of aborting the whole listing. */
  onUnreadable?: (relPath: string, code: string) => void;
}

export interface SiteTransport {
  readonly kind: TransportConfig["type"];
  list(dir: string, opts?: ListOptions): Promise<FileEntry[]>;
  /** At most maxBytes (default 10 MB). A longer file yields its first maxBytes bytes. Never follows a symlink. */
  read(path: string, opts?: { maxBytes?: number }): Promise<Buffer>;
  stat(path: string): Promise<FileEntry | null>;
  /** SHA-256 of the content, streamed so large files are not held in memory. For a symlink, of its target string. */
  hash(path: string): Promise<{ sha256: string; size: number }>;
}

export class TransportError extends Error {}

/** What the agent can actually do to a site of this kind. The policy only proposes what is possible. */
export interface Capabilities {
  read: boolean;
  restore: boolean;
  quarantine: boolean;
  maintenancePage: boolean;
  /** Needs a firewall or WAF adapter. None exists yet, so this is false everywhere. */
  blockIp: boolean;
}

export function capabilitiesFor(t: TransportConfig): Capabilities {
  switch (t.type) {
    case "local-fs":
      return { read: true, restore: true, quarantine: true, maintenancePage: true, blockIp: false };
    case "git":
      // Restore means redeploying a known-good commit. There is no live filesystem to read or edit.
      return { read: false, restore: true, quarantine: false, maintenancePage: false, blockIp: false };
    case "none":
      // Platforms such as Wix: only the Page watcher can observe, and nothing can be changed.
      return { read: false, restore: false, quarantine: false, maintenancePage: false, blockIp: false };
  }
}
