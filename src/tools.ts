/**
 * Read-only tools.
 *
 * There is deliberately no write, edit, move or execute tool. The agent cannot
 * change the codebase it is auditing, by construction rather than by instruction.
 * Every path is resolved and checked to be inside the scan root before use.
 */

import { promises as fs } from "node:fs";
import path from "node:path";

const SKIP_DIRS = new Set([
  "node_modules", ".git", "vendor", "dist", "build", ".next", ".nuxt",
  "coverage", ".turbo", "storage", "__pycache__", ".venv", "venv", "out",
]);

const BINARY_EXT = new Set([
  ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".pdf", ".zip",
  ".woff", ".woff2", ".ttf", ".otf", ".mp4", ".mp3", ".psd", ".lock",
]);

// This tool's own generated output. Found the hard way: a stray report.md
// left sitting in the scan root got read as source, and a check found the
// word "BookingController.php" inside markdown describing a PAST finding,
// then reported it as a real one in a file that does not exist in this
// project. Same patterns as .gitignore, because that is exactly what these
// are, artifacts, not code, and scanning your own prior output is how you
// end up auditing yourself.
const SKIP_FILE_PATTERNS = [/^report.*\.md$/i, /\.md\.out$/i, /^\.pentest-challenges\.json$/i];

const MAX_FILE_BYTES = 40_000;
const MAX_GREP_HITS = 18;

export class Sandbox {
  constructor(public readonly root: string) {
    this.root = path.resolve(root);
  }

  /** Resolve a caller-supplied path and refuse anything outside the scan root. */
  resolve(rel: string): string {
    const abs = path.resolve(this.root, rel);
    const within = abs === this.root || abs.startsWith(this.root + path.sep);
    if (!within) throw new Error(`Refused: "${rel}" is outside the scan root.`);
    return abs;
  }

  rel(abs: string): string {
    return path.relative(this.root, abs).split(path.sep).join("/");
  }
}

export async function walk(sb: Sandbox, dir = sb.root, acc: string[] = []): Promise<string[]> {
  let entries;
  try {
    entries = await fs.readdir(dir, { withFileTypes: true });
  } catch {
    return acc;
  }
  for (const e of entries) {
    if (e.name.startsWith(".") && e.name !== ".env" && e.name !== ".gitignore" && e.name !== ".env.example") {
      if (e.isDirectory()) continue;
    }
    const abs = path.join(dir, e.name);
    if (e.isDirectory()) {
      if (SKIP_DIRS.has(e.name)) continue;
      await walk(sb, abs, acc);
    } else {
      if (BINARY_EXT.has(path.extname(e.name).toLowerCase())) continue;
      if (SKIP_FILE_PATTERNS.some((p) => p.test(e.name))) continue;
      acc.push(abs);
    }
  }
  return acc;
}

/* ------------------------------------------------------------------ tools */

export async function listFiles(sb: Sandbox, args: { pattern?: string; limit?: number }) {
  const files = await walk(sb);
  const rels = files.map((f) => sb.rel(f));
  const pattern = args.pattern?.toLowerCase();
  const filtered = pattern ? rels.filter((r) => r.toLowerCase().includes(pattern)) : rels;
  const limit = Math.min(args.limit ?? 120, 250);
  return {
    total: filtered.length,
    shown: Math.min(filtered.length, limit),
    files: filtered.slice(0, limit),
  };
}

export async function readFile(sb: Sandbox, args: { path: string; start?: number; end?: number }) {
  const abs = sb.resolve(args.path);
  const stat = await fs.stat(abs);
  if (stat.size > MAX_FILE_BYTES) {
    const buf = await fs.readFile(abs, "utf8");
    const lines = buf.split("\n");
    return {
      path: args.path,
      truncated: true,
      note: `File is ${stat.size} bytes. Showing first 120 lines. Use start and end to read a specific range.`,
      content: numbered(lines.slice(0, 120), 1),
      totalLines: lines.length,
    };
  }
  const lines = (await fs.readFile(abs, "utf8")).split("\n");
  const start = Math.max(1, args.start ?? 1);
  const end = Math.min(lines.length, args.end ?? Math.min(lines.length, start + 119));
  return {
    path: args.path,
    totalLines: lines.length,
    content: numbered(lines.slice(start - 1, end), start),
  };
}

export async function grep(sb: Sandbox, args: { pattern: string; glob?: string; ignoreCase?: boolean }) {
  let re: RegExp;
  try {
    re = new RegExp(args.pattern, args.ignoreCase === false ? "" : "i");
  } catch (e) {
    return { error: `Invalid regex: ${(e as Error).message}` };
  }
  const files = await walk(sb);
  const glob = args.glob?.toLowerCase();
  const hits: { file: string; line: number; text: string }[] = [];

  for (const abs of files) {
    const rel = sb.rel(abs);
    if (glob && !rel.toLowerCase().includes(glob)) continue;
    let content: string;
    try {
      content = await fs.readFile(abs, "utf8");
    } catch {
      continue;
    }
    const lines = content.split("\n");
    for (let i = 0; i < lines.length; i++) {
      if (re.test(lines[i])) {
        hits.push({ file: rel, line: i + 1, text: lines[i].trim().slice(0, 160) });
        if (hits.length >= MAX_GREP_HITS) {
          return { truncated: true, count: hits.length, hits };
        }
      }
    }
  }
  return { truncated: false, count: hits.length, hits };
}

function numbered(lines: string[], from: number): string {
  return lines.map((l, i) => `${String(from + i).padStart(5)}| ${l}`).join("\n");
}

/* ------------------------------------------------------- tool definitions */

export const TOOL_DEFS = [
  {
    type: "function" as const,
    function: {
      name: "list_files",
      description:
        "List files in the codebase. Optionally filter by a substring of the path. Dependencies, build output and VCS internals are already excluded.",
      parameters: {
        type: "object",
        properties: {
          pattern: { type: "string", description: "Case-insensitive substring of the path, e.g. 'routes' or '.env'." },
          limit: { type: "number", description: "Max files to return. Default 300." },
        },
      },
    },
  },
  {
    type: "function" as const,
    function: {
      name: "grep",
      description:
        "Search file contents with a JavaScript regular expression. Returns file, line number and the matching line. This is the fastest way to locate a pattern.",
      parameters: {
        type: "object",
        properties: {
          pattern: { type: "string", description: "JavaScript regex source, e.g. 'localStorage\\\\.(get|set)Item'." },
          glob: { type: "string", description: "Optional case-insensitive path substring to narrow the search." },
          ignoreCase: { type: "boolean", description: "Default true." },
        },
        required: ["pattern"],
      },
    },
  },
  {
    type: "function" as const,
    function: {
      name: "read_file",
      description: "Read a file with line numbers. Use start and end to read a range rather than a whole large file.",
      parameters: {
        type: "object",
        properties: {
          path: { type: "string", description: "Path relative to the scan root." },
          start: { type: "number" },
          end: { type: "number" },
        },
        required: ["path"],
      },
    },
  },
];

export async function runTool(sb: Sandbox, name: string, args: any) {
  switch (name) {
    case "list_files":
      return await listFiles(sb, args ?? {});
    case "read_file":
      return await readFile(sb, args);
    case "grep":
      return await grep(sb, args);
    default:
      return { error: `Unknown tool: ${name}` };
  }
}
