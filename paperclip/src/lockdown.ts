/**
 * The lock-down for a read-only Paperclip agent, written as pure functions so
 * it can be tested and so a regression in it is loud.
 *
 * Every setting here exists because of something observed in a real run, see
 * ../README.md. The short version: Paperclip's defaults give an agent write and
 * shell access, and the obvious way of restricting it (an allowlist of tools)
 * still let the agent read any file the user's account could.
 */

/** Windows or POSIX path to Claude Code's permission-rule form: D:\a\b -> //d/a/b, /home/x -> //home/x. */
export function toRulePath(p: string): string {
  const s = p.replace(/\\/g, "/").replace(/\/+$/, "");
  const drive = /^([A-Za-z]):(\/.*)?$/.exec(s);
  if (drive) return `//${drive[1].toLowerCase()}${drive[2] ?? ""}`;
  return s.startsWith("/") ? `/${s}` : s;
}

/** A Read rule that allows one folder and its contents. Grep and Glob are confined by the same rule. */
export function scopedReadRule(dir: string): string {
  return `Read(${toRulePath(dir)}/**)`;
}

export interface LockdownOptions {
  /** The only folder the agent may read. */
  scanRoot: string;
  model?: string;
  maxTurns?: number;
  timeoutSec?: number;
}

/**
 * Claude Code flags, passed through Paperclip's `extraArgs`.
 *  --tools          the agent has exactly these built-in tools, nothing else exists for it
 *  --allowedTools   pre-approves Read only inside scanRoot. NOT a bare "Read": that allowed any path.
 *  --setting-sources project   do not load the user's own hooks, plugins or settings
 */
export function buildExtraArgs(scanRoot: string): string[] {
  return ["--tools", "Read,Grep,Glob", "--allowedTools", scopedReadRule(scanRoot), "--setting-sources", "project"];
}

export function buildAdapterConfig(o: LockdownOptions): Record<string, unknown> {
  return {
    cwd: o.scanRoot,
    // Paperclip defaults to an ACP engine that ignores extraArgs and auto-approves every tool request.
    engine: "cli",
    // Defaults to true in Paperclip. Left on, the CLI runs with all permission prompts bypassed.
    dangerouslySkipPermissions: false,
    // Second layer, for the day someone flips the engine back.
    permissionMode: "approve-reads",
    nonInteractivePermissions: "deny",
    extraArgs: buildExtraArgs(o.scanRoot),
    maxTurnsPerRun: o.maxTurns ?? 25,
    timeoutSec: o.timeoutSec ?? 900,
    graceSec: 15,
    ...(o.model ? { model: o.model } : {}),
  };
}

/** No timer, no surprise runs. An agent only works when told to. */
export const QUIET_RUNTIME = {
  heartbeat: {
    enabled: false,
    intervalSec: 3600,
    wakeOnDemand: true,
    skipTimerWhenNoActionableWork: true,
    cooldownSec: 10,
    maxConcurrentRuns: 1,
  },
};

/** Paperclip hands a new agent the right to create agents and skills. A reviewer needs neither. */
export const NO_POWERS = { canCreateAgents: false, canCreateSkills: false, canAssignTasks: false };

export interface StoredAgent {
  adapterConfig?: Record<string, any>;
  runtimeConfig?: Record<string, any>;
  permissions?: Record<string, any>;
}

/**
 * Check what the SERVER stored, not what we sent. Returns the problems found, empty if the agent is locked down.
 * Worth having because a config can be accepted and then ignored (the ACP engine ignores extraArgs entirely).
 */
export function lockdownProblems(agent: StoredAgent, scanRoot: string): string[] {
  const c = agent.adapterConfig ?? {};
  const problems: string[] = [];
  if (c.dangerouslySkipPermissions !== false) problems.push("dangerouslySkipPermissions is not false");
  if (c.engine !== "cli") problems.push(`engine is '${c.engine}', not 'cli' (other engines ignore extraArgs)`);
  const args: string[] = Array.isArray(c.extraArgs) ? c.extraArgs : [];
  const at = args.indexOf("--tools");
  if (at === -1 || args[at + 1] !== "Read,Grep,Glob") problems.push("--tools Read,Grep,Glob is missing");
  const allowed = args.indexOf("--allowedTools");
  const rule = allowed === -1 ? undefined : args[allowed + 1];
  if (rule !== scopedReadRule(scanRoot)) problems.push(`--allowedTools is '${rule}', not '${scopedReadRule(scanRoot)}'`);
  if (args.some((a) => a === "Read" || a === "Grep" || a === "Glob")) problems.push("a bare tool name in extraArgs would allow it on any path");
  if (args.some((a) => a.includes("dangerously") || a === "bypassPermissions")) problems.push("a permission-bypass flag is present");
  if (agent.runtimeConfig?.heartbeat?.enabled !== false) problems.push("the heartbeat is enabled");
  for (const [k, v] of Object.entries(agent.permissions ?? {})) {
    if (k.startsWith("can") && v !== false) problems.push(`permission ${k} is ${String(v)}`);
  }
  return problems;
}
