/**
 * Read-only access to a site on a filesystem this process can reach: the same
 * machine, or a mount of the host (sshfs, an rsync mirror). This class has no
 * method that writes, and watchers are only ever handed the SiteTransport type.
 *
 * Containment is the point of most of this file. Paths are relative to the
 * site root and may not climb out of it; symlinks are reported, never
 * followed, and a symlinked directory is not descended into, so a link to
 * /etc planted in the web root cannot make the agent read or hash outside it.
 */

import { constants, promises as fs } from "node:fs";
import type { Dirent, Stats } from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { TransportError, type FileEntry, type ListOptions, type SiteTransport } from "./transport.js";

const DEFAULT_MAX_READ = 10 * 1024 * 1024;
const DEFAULT_MAX_ENTRIES = 200_000;
// Not defined on Windows. There, the lstat check before opening is the only guard.
const NOFOLLOW = (constants as Record<string, number>).O_NOFOLLOW ?? 0;

function inside(child: string, parent: string): boolean {
  const rel = path.relative(parent, child);
  return rel === "" || (!rel.startsWith("..") && !path.isAbsolute(rel));
}

function entry(rel: string, st: Stats): FileEntry {
  return { path: rel, size: st.size, mtimeMs: st.mtimeMs, ctimeMs: st.ctimeMs, isSymlink: st.isSymbolicLink() };
}

export class LocalFsTransport implements SiteTransport {
  readonly kind = "local-fs" as const;

  private constructor(readonly root: string) {}

  static async open(root: string): Promise<LocalFsTransport> {
    let real: string;
    try {
      real = await fs.realpath(root);
    } catch (e: any) {
      throw new TransportError(`site root ${root} is not reachable (${e?.code ?? e})`);
    }
    if (!(await fs.stat(real)).isDirectory()) throw new TransportError(`site root ${root} is not a directory`);
    return new LocalFsTransport(real);
  }

  /** Relative path in, absolute path out, or a TransportError if it could leave the root. */
  private resolve(rel: string): string {
    if (typeof rel !== "string" || rel.includes("\0")) throw new TransportError("invalid path");
    const norm = rel.replace(/\\/g, "/");
    if (norm.startsWith("/") || /^[a-zA-Z]:/.test(norm)) throw new TransportError(`'${rel}' is absolute; paths are relative to the site root`);
    const parts = norm.split("/").filter((p) => p !== "" && p !== ".");
    if (parts.includes("..")) throw new TransportError(`'${rel}' climbs out of the site root`);
    return path.join(this.root, ...parts);
  }

  private toRel(abs: string): string {
    return path.relative(this.root, abs).split(path.sep).join("/");
  }

  /** A symlinked ancestor directory could still lead outside; the real parent must be inside the root. */
  private async assertContained(abs: string): Promise<void> {
    let parent: string;
    try {
      parent = await fs.realpath(path.dirname(abs));
    } catch (e: any) {
      throw Object.assign(new TransportError(`cannot resolve the directory of '${this.toRel(abs)}'`), { code: e?.code });
    }
    if (!inside(parent, this.root)) throw new TransportError(`'${this.toRel(abs)}' leads outside the site root through a symlink`);
  }

  async stat(rel: string): Promise<FileEntry | null> {
    const abs = this.resolve(rel);
    try {
      await this.assertContained(abs);
      return entry(this.toRel(abs), await fs.lstat(abs));
    } catch (e: any) {
      if (e?.code === "ENOENT") return null;
      throw e;
    }
  }

  async list(dir: string, opts: ListOptions = {}): Promise<FileEntry[]> {
    const max = opts.maxEntries ?? DEFAULT_MAX_ENTRIES;
    const start = this.resolve(dir);
    // A directory is judged by itself, not by its parent: for the root, the parent is outside it.
    const realStart = await fs.realpath(start);
    if (!inside(realStart, this.root)) throw new TransportError(`'${dir}' leads outside the site root through a symlink`);
    const out: FileEntry[] = [];
    const stack = [start];

    while (stack.length) {
      const abs = stack.pop()!;
      let dirents: Dirent[];
      try {
        dirents = await fs.readdir(abs, { withFileTypes: true });
      } catch (e: any) {
        if (abs === start) throw e;
        opts.onUnreadable?.(this.toRel(abs), e?.code ?? "EUNKNOWN");
        continue;
      }
      // Sorted so two listings of the same tree come back in the same order.
      dirents.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
      const subdirs: string[] = [];
      for (const d of dirents) {
        const child = path.join(abs, d.name);
        const rel = this.toRel(child);
        if (d.isDirectory()) {
          if (opts.recursive && !opts.skipDir?.(rel)) subdirs.push(child);
          continue;
        }
        if (!d.isFile() && !d.isSymbolicLink()) continue; // sockets, fifos, devices
        let st: Stats;
        try {
          st = await fs.lstat(child);
        } catch (e: any) {
          if (e?.code === "ENOENT") continue; // removed while we listed
          opts.onUnreadable?.(rel, e?.code ?? "EUNKNOWN");
          continue;
        }
        out.push(entry(rel, st));
        if (out.length > max) {
          throw new TransportError(`more than ${max} files under '${dir || "."}'. Raise integrity.maxFiles or exclude generated directories.`);
        }
      }
      // Reverse so the stack pops them in sorted order.
      stack.push(...subdirs.reverse());
    }
    return out;
  }

  private async openNoFollow(abs: string) {
    await this.assertContained(abs);
    const st = await fs.lstat(abs);
    if (st.isSymbolicLink()) throw new TransportError(`'${this.toRel(abs)}' is a symlink and is not followed`);
    if (!st.isFile()) throw new TransportError(`'${this.toRel(abs)}' is not a regular file`);
    return fs.open(abs, constants.O_RDONLY | NOFOLLOW);
  }

  async read(rel: string, opts: { maxBytes?: number } = {}): Promise<Buffer> {
    const max = opts.maxBytes ?? DEFAULT_MAX_READ;
    const fh = await this.openNoFollow(this.resolve(rel));
    try {
      const buf = Buffer.alloc(max);
      let n = 0;
      while (n < max) {
        const { bytesRead } = await fh.read(buf, n, max - n, n);
        if (!bytesRead) break;
        n += bytesRead;
      }
      return buf.subarray(0, n);
    } finally {
      await fh.close();
    }
  }

  async hash(rel: string): Promise<{ sha256: string; size: number }> {
    const abs = this.resolve(rel);
    await this.assertContained(abs);
    const st = await fs.lstat(abs);
    if (st.isSymbolicLink()) {
      // Hash where it points, not what it points at, so retargeting a link is a change.
      const target = await fs.readlink(abs);
      return { sha256: createHash("sha256").update(`symlink\0${target}`).digest("hex"), size: 0 };
    }
    const fh = await this.openNoFollow(abs);
    try {
      const h = createHash("sha256");
      let size = 0;
      for await (const chunk of fh.createReadStream({ autoClose: false })) {
        h.update(chunk as Buffer);
        size += (chunk as Buffer).length;
      }
      return { sha256: h.digest("hex"), size };
    } finally {
      await fh.close();
    }
  }
}
