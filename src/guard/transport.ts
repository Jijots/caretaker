/**
 * How the agent reaches a site. Phase 1 defines the contract and what each
 * transport is able to do; the local filesystem implementation arrives with the
 * Integrity watcher in Phase 2, and the git restore adapter in Phase 5.
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
  /** Symlinks are reported, never followed out of the root. */
  isSymlink: boolean;
}

export interface SiteTransport {
  readonly kind: TransportConfig["type"];
  list(dir: string, opts?: { recursive?: boolean; maxEntries?: number }): Promise<FileEntry[]>;
  read(path: string, opts?: { maxBytes?: number }): Promise<Buffer>;
  stat(path: string): Promise<FileEntry | null>;
}

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
