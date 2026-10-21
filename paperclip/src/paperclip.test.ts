import test from "node:test";
import assert from "node:assert/strict";
import { NO_POWERS, QUIET_RUNTIME, buildAdapterConfig, buildExtraArgs, lockdownProblems, scopedReadRule, toRulePath } from "./lockdown.js";
import { buildAuditPrompt } from "./prompts.js";
import { LEAD, LockdownError, SPECIALISTS, createTeam, type Api } from "./create-team.js";

const TARGET = "D:\\labs\\targets\\caretaker";
const LEAD_ROOT = "D:\\labs\\workspace";

/* ---------------------------------------------------------------- lockdown */

test("paths become Claude Code permission-rule paths", () => {
  assert.equal(toRulePath("D:\\paperclip-lab\\targets\\caretaker"), "//d/paperclip-lab/targets/caretaker");
  assert.equal(toRulePath("c:/Users/x/"), "//c/Users/x");
  assert.equal(toRulePath("D:\\"), "//d");
  assert.equal(toRulePath("/home/dev/project"), "//home/dev/project");
  assert.equal(scopedReadRule(TARGET), "Read(//d/labs/targets/caretaker/**)");
});

test("the lock-down config closes each hole that was found, and allows no bare tool name", () => {
  const c = buildAdapterConfig({ scanRoot: TARGET });
  assert.equal(c.dangerouslySkipPermissions, false, "Paperclip defaults this to true");
  assert.equal(c.engine, "cli", "the default ACP engine ignores extraArgs");
  assert.equal(c.permissionMode, "approve-reads", "ACP's default is approve-all");
  assert.equal(c.nonInteractivePermissions, "deny");
  const args = c.extraArgs as string[];
  assert.deepEqual(args.slice(0, 2), ["--tools", "Read,Grep,Glob"]);
  assert.ok(args.includes("Read(//d/labs/targets/caretaker/**)"));
  for (const bare of ["Read", "Grep", "Glob"]) assert.ok(!args.includes(bare), `a bare '${bare}' would allow any path`);
  assert.ok(!args.some((a) => /dangerous|bypass/i.test(a)));
  assert.ok(args.includes("--setting-sources") && args.includes("project"), "the user's own hooks and plugins stay out");
});

test("a model is only set when asked for", () => {
  assert.equal("model" in buildAdapterConfig({ scanRoot: TARGET }), false);
  assert.equal(buildAdapterConfig({ scanRoot: TARGET, model: "sonnet" }).model, "sonnet");
});

test("a correctly built agent passes verification", () => {
  const agent = { adapterConfig: buildAdapterConfig({ scanRoot: TARGET }), runtimeConfig: QUIET_RUNTIME, permissions: NO_POWERS };
  assert.deepEqual(lockdownProblems(agent, TARGET), []);
});

test("every way of weakening the agent is reported", () => {
  const good = () => ({ adapterConfig: buildAdapterConfig({ scanRoot: TARGET }) as Record<string, any>, runtimeConfig: structuredClone(QUIET_RUNTIME) as Record<string, any>, permissions: { ...NO_POWERS } as Record<string, any> });
  const cases: [string, (a: ReturnType<typeof good>) => void, RegExp][] = [
    ["skip permissions on", (a) => { a.adapterConfig.dangerouslySkipPermissions = true; }, /dangerouslySkipPermissions/],
    ["the default engine", (a) => { a.adapterConfig.engine = "acp"; }, /engine is 'acp'/],
    ["no engine at all", (a) => { delete a.adapterConfig.engine; }, /engine is 'undefined'/],
    ["tools dropped", (a) => { a.adapterConfig.extraArgs = []; }, /--tools Read,Grep,Glob is missing/],
    ["a wider tool list", (a) => { a.adapterConfig.extraArgs = buildExtraArgs(TARGET).map((x) => (x === "Read,Grep,Glob" ? "Read,Grep,Glob,Bash" : x)); }, /--tools/],
    ["a blanket Read allow", (a) => { a.adapterConfig.extraArgs = ["--tools", "Read,Grep,Glob", "--allowedTools", "Read", "Grep", "Glob"]; }, /--allowedTools is 'Read'/],
    ["the wrong folder", (a) => { a.adapterConfig.extraArgs = buildExtraArgs("D:\\elsewhere"); }, /--allowedTools is 'Read\(\/\/d\/elsewhere/],
    ["a bypass flag", (a) => { a.adapterConfig.extraArgs = [...buildExtraArgs(TARGET), "--dangerously-skip-permissions"]; }, /bypass/],
    ["the heartbeat on", (a) => { a.runtimeConfig.heartbeat.enabled = true; }, /heartbeat is enabled/],
    ["creation powers on", (a) => { a.permissions.canCreateAgents = true; }, /permission canCreateAgents is true/],
    ["assignment powers on", (a) => { a.permissions.canAssignTasks = true; }, /canAssignTasks/],
  ];
  for (const [name, mutate, expected] of cases) {
    const a = good();
    mutate(a);
    const found = lockdownProblems(a, TARGET).join(" | ");
    assert.match(found, expected, name);
  }
});

/* ----------------------------------------------------------------- prompts */

test("the audit prompt names the checks, demands citations, and only probes when asked", () => {
  const p = buildAuditPrompt({ checks: ["SEC-01", "SEC-03"] });
  assert.match(p, /checks SEC-01, SEC-03/);
  assert.match(p, /Every finding must cite a file and a line you actually read/);
  assert.match(p, /COULD NOT VERIFY/);
  assert.match(p, /NOT VISIBLE FROM CODE/);
  assert.doesNotMatch(p, /PROBE/);
  assert.match(buildAuditPrompt({ checks: ["SEC-01"], boundaryProbePath: "D:\\x\\canary.txt" }), /PROBE: followed by either BLOCKED/);
  assert.throws(() => buildAuditPrompt({ checks: [] }), /at least one/);
  assert.throws(() => buildAuditPrompt({ checks: ["SEC-01; rm -rf"] }), /not a checklist id/, "an id is never spliced into a prompt unchecked");
});

/* ------------------------------------------------------------ create-team */

/** An in-memory Paperclip. New agents start with creation powers ON, like the real one. */
function fakePaperclip(tamper?: (stored: any) => void) {
  const agents: any[] = [];
  let n = 0;
  const calls: string[] = [];
  const api: Api = {
    async get(path) {
      calls.push(`GET ${path}`);
      if (path.endsWith("/agents")) return agents.map((a) => ({ id: a.id, name: a.name }));
      return agents.find((a) => path === `/agents/${a.id}`);
    },
    async post(path, body: any) {
      calls.push(`POST ${path} ${body.name}`);
      const stored = { id: `agent-${++n}`, ...structuredClone(body), permissions: { canCreateAgents: true, canCreateSkills: true } };
      tamper?.(stored);
      agents.push(stored);
      return stored;
    },
    async patch(path, body: any) {
      calls.push(`PATCH ${path}`);
      const a = agents.find((x) => path === `/agents/${x.id}/permissions`);
      Object.assign(a.permissions, body);
      return a;
    },
  };
  return { api, agents, calls };
}

test("createTeam builds four agents, turns their powers off, and verifies each from the stored record", async () => {
  const { api, agents, calls } = fakePaperclip();
  const r = await createTeam(api, { companyId: "co", targetRoot: TARGET, leadRoot: LEAD_ROOT, model: "sonnet", boundaryProbePath: "D:\\labs\\canary.txt" });
  assert.deepEqual(r.created, [LEAD.name, ...SPECIALISTS.map((s) => s.name)]);
  assert.deepEqual(r.problems, {});
  const lead = agents.find((a) => a.name === LEAD.name);
  assert.equal(lead.reportsTo, null);
  assert.equal(lead.adapterConfig.cwd, LEAD_ROOT);
  assert.ok(lead.adapterConfig.extraArgs.includes("Read(//d/labs/workspace/**)"), "the lead reads only its own folder");
  assert.equal(lead.adapterConfig.promptTemplate, undefined, "the lead runs no checks");
  for (const s of SPECIALISTS) {
    const a = agents.find((x) => x.name === s.name);
    assert.equal(a.reportsTo, lead.id);
    assert.equal(a.adapterConfig.model, "sonnet");
    assert.ok(a.adapterConfig.extraArgs.includes("Read(//d/labs/targets/caretaker/**)"));
    assert.match(a.adapterConfig.promptTemplate, new RegExp(s.checks[0]));
    assert.match(a.adapterConfig.promptTemplate, /PROBE/);
    assert.deepEqual(a.permissions, { canCreateAgents: false, canCreateSkills: false, canAssignTasks: false });
    assert.equal(a.runtimeConfig.heartbeat.enabled, false);
    assert.equal(a.budgetMonthlyCents, 500);
  }
  assert.equal(calls.filter((c) => c.startsWith("PATCH")).length, 4, "permissions are changed for every new agent");
});

test("running it twice creates nothing new, but still checks what exists", async () => {
  const { api, agents } = fakePaperclip();
  await createTeam(api, { companyId: "co", targetRoot: TARGET });
  const again = await createTeam(api, { companyId: "co", targetRoot: TARGET });
  assert.equal(again.created.length, 0);
  assert.equal(again.existing.length, 4);
  assert.equal(agents.length, 4);

  agents[2].adapterConfig.dangerouslySkipPermissions = true; // someone flips a switch in the UI
  await assert.rejects(() => createTeam(api, { companyId: "co", targetRoot: TARGET }), (e: Error) => e instanceof LockdownError && /dangerouslySkipPermissions/.test(e.message));
});

test("a server that quietly stores something weaker is caught, because it checks the stored record", async () => {
  const { api } = fakePaperclip((stored) => {
    stored.adapterConfig.engine = "acp"; // accepted, then ignored: this is what the default engine does to extraArgs
  });
  await assert.rejects(
    () => createTeam(api, { companyId: "co", targetRoot: TARGET }),
    (e: Error) => e instanceof LockdownError && /engine is 'acp'/.test(e.message) && Object.keys((e as LockdownError).result.problems).length === 4,
  );
});

test("a dry run reads, plans, and changes nothing", async () => {
  const { api, agents, calls } = fakePaperclip();
  const r = await createTeam(api, { companyId: "co", targetRoot: TARGET, dryRun: true });
  assert.equal(r.wouldCreate.length, 4);
  assert.equal(r.created.length, 0);
  assert.equal(agents.length, 0);
  assert.ok(calls.every((c) => c.startsWith("GET")), calls.join(", "));
});
