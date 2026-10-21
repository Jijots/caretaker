/**
 * Creates the read-only scanner team in a running Paperclip instance and then
 * checks, from what the server stored, that every agent is actually locked down.
 *
 *   npx tsx paperclip/src/create-team.ts --company <id> --target <dir> [--lead-root <dir>]
 *                                        [--model sonnet] [--probe <file>] [--dry-run]
 *
 * Safe to run twice: an agent that already exists is not recreated, but it IS
 * still verified, so this doubles as an audit of an existing team.
 */

import { pathToFileURL } from "node:url";
import { NO_POWERS, QUIET_RUNTIME, buildAdapterConfig, lockdownProblems, type StoredAgent } from "./lockdown.js";
import { buildAuditPrompt } from "./prompts.js";

export interface TeamMember {
  name: string;
  title: string;
  capabilities: string;
  /** Checklist ids this agent runs. The lead runs none, it merges. */
  checks: string[];
}

export const LEAD: TeamMember = {
  name: "Scanner Lead",
  title: "Read-only security audit lead",
  capabilities: "Merges the specialists' reports into one. Reads only, and cites a file and line for every claim.",
  checks: [],
};

/** The seven checks the scanner marks critical7, split by category. */
export const SPECIALISTS: TeamMember[] = [
  {
    name: "Secrets and Config Specialist",
    title: "Checks SEC-01 and SEC-03",
    capabilities: "Read-only reviewer of how secrets and keys are handled. Cites file and line for every finding, and says so when it cannot tell.",
    checks: ["SEC-01", "SEC-03"],
  },
  {
    name: "Auth Access and Database Specialist",
    title: "Checks DB-01 and AUTH-02",
    capabilities: "Read-only reviewer of database access rules and ownership checks. Cites file and line for every finding, and says so when it cannot tell.",
    checks: ["DB-01", "AUTH-02"],
  },
  {
    name: "Abuse and Input Specialist",
    title: "Checks RATE-01, RATE-02 and IO-01",
    capabilities: "Read-only reviewer of rate limiting, billing caps and query safety. Cites file and line for every finding, and says so when it cannot tell.",
    checks: ["RATE-01", "RATE-02", "IO-01"],
  },
];

export interface Api {
  get(path: string): Promise<any>;
  post(path: string, body: unknown): Promise<any>;
  patch(path: string, body: unknown): Promise<any>;
}

export function httpApi(baseUrl: string): Api {
  const root = `${baseUrl.replace(/\/+$/, "")}/api`;
  const call = async (method: string, path: string, body?: unknown) => {
    const res = await fetch(root + path, {
      method,
      headers: { "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    if (!res.ok) throw new Error(`${method} ${path} -> ${res.status} ${text.slice(0, 300)}`);
    return text ? JSON.parse(text) : null;
  };
  return { get: (p) => call("GET", p), post: (p, b) => call("POST", p, b), patch: (p, b) => call("PATCH", p, b) };
}

export interface CreateOptions {
  companyId: string;
  /** The only folder the specialists may read. Use a clean clone: a working copy may hold a real .env. */
  targetRoot: string;
  /** The only folder the lead may read. Defaults to targetRoot. */
  leadRoot?: string;
  model?: string;
  /** A file outside the scan folder each specialist tries to read, to prove the boundary. */
  boundaryProbePath?: string;
  dryRun?: boolean;
}

export interface TeamResult {
  created: string[];
  existing: string[];
  wouldCreate: string[];
  /** Agent name -> what is wrong with it. Empty when every agent is locked down. */
  problems: Record<string, string[]>;
}

export class LockdownError extends Error {
  constructor(readonly result: TeamResult) {
    super(
      "not locked down: " +
        Object.entries(result.problems)
          .map(([n, p]) => `${n}: ${p.join("; ")}`)
          .join(" | "),
    );
  }
}

export async function createTeam(api: Api, o: CreateOptions): Promise<TeamResult> {
  const result: TeamResult = { created: [], existing: [], wouldCreate: [], problems: {} };
  const base = `/companies/${o.companyId}`;
  const agents: any[] = (await api.get(`${base}/agents`)) ?? [];
  const byName = new Map<string, any>(agents.map((a) => [a.name, a]));
  const leadRoot = o.leadRoot ?? o.targetRoot;

  const ensure = async (m: TeamMember, scanRoot: string, reportsTo: string | null): Promise<any> => {
    const found = byName.get(m.name);
    if (found) {
      result.existing.push(m.name);
      return found;
    }
    if (o.dryRun) {
      result.wouldCreate.push(m.name);
      return { id: `(would create ${m.name})`, name: m.name };
    }
    const adapterConfig: Record<string, unknown> = buildAdapterConfig({ scanRoot, model: o.model, maxTurns: m.checks.length ? 25 : 8 });
    if (m.checks.length) adapterConfig.promptTemplate = buildAuditPrompt({ checks: m.checks, boundaryProbePath: o.boundaryProbePath });
    const made = await api.post(`${base}/agents`, {
      name: m.name,
      role: "security",
      title: m.title,
      capabilities: m.capabilities,
      reportsTo,
      adapterType: "claude_local",
      adapterConfig,
      runtimeConfig: QUIET_RUNTIME,
      budgetMonthlyCents: 500,
    });
    // Paperclip creates agents able to create agents and skills. Turn that off before anything else.
    await api.patch(`/agents/${made.id}/permissions`, NO_POWERS);
    result.created.push(m.name);
    return made;
  };

  const lead = await ensure(LEAD, leadRoot, null);
  const members: [TeamMember, any, string][] = [[LEAD, lead, leadRoot]];
  for (const s of SPECIALISTS) members.push([s, await ensure(s, o.targetRoot, o.dryRun ? null : lead.id), o.targetRoot]);

  if (!o.dryRun) {
    for (const [m, agent, root] of members) {
      const stored: StoredAgent = await api.get(`/agents/${agent.id}`);
      const problems = lockdownProblems(stored, root);
      if (problems.length) result.problems[m.name] = problems;
    }
    if (Object.keys(result.problems).length) throw new LockdownError(result);
  }
  return result;
}

/* ------------------------------------------------------------------- CLI */

function arg(args: string[], name: string): string | undefined {
  const i = args.indexOf(`--${name}`);
  return i !== -1 && args[i + 1] && !args[i + 1].startsWith("--") ? args[i + 1] : undefined;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const companyId = arg(args, "company");
  const targetRoot = arg(args, "target");
  if (!companyId || !targetRoot) {
    console.error("usage: create-team.ts --company <id> --target <dir> [--lead-root <dir>] [--model sonnet] [--probe <file>] [--dry-run] [--base http://127.0.0.1:3100]");
    process.exitCode = 2;
    return;
  }
  const api = httpApi(arg(args, "base") ?? "http://127.0.0.1:3100");
  try {
    const r = await createTeam(api, {
      companyId,
      targetRoot,
      leadRoot: arg(args, "lead-root"),
      model: arg(args, "model"),
      boundaryProbePath: arg(args, "probe"),
      dryRun: args.includes("--dry-run"),
    });
    if (r.wouldCreate.length) console.log(`dry run, would create: ${r.wouldCreate.join(", ")}`);
    if (r.created.length) console.log(`created: ${r.created.join(", ")}`);
    if (r.existing.length) console.log(`already present: ${r.existing.join(", ")}`);
    if (!args.includes("--dry-run")) console.log("verified from the server's own record: every agent is read-only, scoped, quiet and powerless.");
  } catch (e) {
    console.error(String((e as Error).message));
    // Not process.exit(): on Windows it can trip a libuv assertion while HTTP handles are still closing.
    process.exitCode = 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) void main();
