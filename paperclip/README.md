# The Paperclip version: a read-only scanner team

The same job as [`security-pass`](../README.md#security-pass-the-pre-launch-scanner), rebuilt on
[Paperclip](https://github.com/paperclipai/paperclip), an open-source platform for running teams
of AI agents with an org chart, budgets and approvals. Written to see what a platform gives you
over a hand-built agent loop, and what it takes away.

Status, honestly: a locked-down four-agent team exists, one specialist has run one real check
twice (on two models), and that run found a real flaw in this repository, which is now fixed.
The lead agent that merges the specialists' reports is **not** built. See [What does not work yet](#what-does-not-work-yet).

Everything below was done against Paperclip `2026.1012.0` on Windows, in October 2026. Paperclip
is young and moves fast, so treat the findings as true of that version.

## Two versions of one tool

| | Hand-built (`src/`) | On Paperclip (`paperclip/`) |
|---|---|---|
| The agent loop | Written here: tool calls, retries, context pruning | Paperclip's |
| Read-only guarantee | In code: the tool set has no write or shell tool at all | Configured, then **verified from the server's stored record** |
| Scheduling, budgets, a dashboard | None | Built in |
| Control | Total | Whatever the platform exposes |
| What it cost to get safe | Designed in from the start | Four defaults had to be found and overridden (below) |

## What was built

A team of four, all created and checked by one script, [`src/create-team.ts`](src/create-team.ts):

| Agent | Runs | Reads only |
|---|---|---|
| Scanner Lead | merges reports (not built yet) | its own workspace |
| Secrets and Config Specialist | SEC-01, SEC-03 | the scan folder |
| Auth Access and Database Specialist | DB-01, AUTH-02 | the scan folder |
| Abuse and Input Specialist | RATE-01, RATE-02, IO-01 | the scan folder |

Those seven are the checks the scanner already marks as most important (`critical7` in
`src/checklist.ts`).

Each agent is locked down by [`src/lockdown.ts`](src/lockdown.ts), as pure functions with tests:

- **Exactly three tools**: `--tools Read,Grep,Glob`. There is no `Bash`, `Edit`, `Write`, web or sub-agent tool to misuse, because none exists in the session.
- **Reads confined to one folder**: `--allowedTools "Read(//d/path/to/scan/**)"`. One scoped rule confines `Read`, `Grep` and `Glob`.
- **Permission prompts are not bypassed**, and the engine is forced to the CLI (see finding 2).
- **No timer, no surprise runs**: the heartbeat is off. An agent works only when told to.
- **No powers over the platform**: cannot create agents or skills, cannot assign tasks.
- **Capped**: 25 turns and 15 minutes per run, a $5 monthly budget.
- **Your own hooks and plugins stay out**: `--setting-sources project`.

After creating anything, the script reads each agent back from Paperclip and checks the stored
configuration against that list. It exits non-zero if anything is weaker than intended, and it is
safe to run again as an audit of an existing team.

```bash
npx tsx paperclip/src/create-team.ts --company <id> --target <clean clone of the repo to scan> \
    [--lead-root <dir>] [--model sonnet] [--probe <file outside the scan folder>] [--dry-run]
```

Point `--target` at a **clean clone**, not a working copy. A working copy may hold a real `.env`.

## What I found in Paperclip's defaults

Read from the shipped JavaScript in `node_modules`, so the paths are inside that tree. Each was
also observed running, except where noted.

1. **Permission prompts are bypassed by default.** `@paperclipai/adapter-claude-local/dist/server/execute.js` reads `asBoolean(config.dangerouslySkipPermissions, true)`, and the new-agent form defaults it to true. Left alone, Claude Code runs with `--dangerously-skip-permissions`.
2. **The default engine ignores the usual restrictions and approves everything.** With no `engine` set, `acp.js` picks the ACP engine, and `@paperclipai/adapter-utils/dist/acpx-engine/constants.js` sets its permission mode to `approve-all`. The `extraArgs` that carry `--allowedTools` are Claude CLI flags added in the CLI engine's argument builder; I found no equivalent in the ACP path. So a tool allowlist set the obvious way would have been accepted and not applied. The fix is `engine: "cli"`, which the adapter's own error text suggests.
3. **The "Claude subscription" button copies your login.** `@paperclipai/server/dist/services/local-ai-credentials.js` reads the OAuth access token from `~/.claude/.credentials.json` and calls Anthropic's quota endpoint with it, and the agent-create schema describes binding that token to a stored value. I did not complete it. The adapter can instead simply run the local `claude` command with your own login, which does not move a credential into another app.
4. **New agents can create agents and skills.** Observed: a freshly created agent came back with `canCreateAgents` and `canCreateSkills` true.
5. **A task an agent cannot close starts a repair loop that spends usage.** A read-only agent cannot post its result back (no shell, no `curl`), so Paperclip re-ran it twice to "repair" the task. Observed. Running the agent from a prompt template with no task attached avoids it, which is how the scripts here work.
6. **Paperclip's own tools are still present.** The agent reported `create_project`, `create_task` and similar MCP tools alongside the three built-in ones. Reported by the agent itself, not checked independently.

## A bug of mine the safety test caught

My first lock-down was `--tools Read,Grep,Glob` plus a bare `--allowedTools Read`. It blocked
writing and running commands, and I said it was proven. Then a boundary test asked the agent to
read a file outside its folder, and it did. **The bare `Read` allowed any path**, including
anything in the user's home directory.

The fix is the scoped rule above. I tested the rule syntax directly with the Claude CLI on a cheap
model (inside allowed, outside refused, for `Read`, `Grep` and `Glob`), then reran the probe
through Paperclip itself: refused, on both models. The probe now rides along in every real run
(`--probe`).

The lesson is the same as for any security control: test the thing it should refuse, not only the
thing it should allow, and check what the server stored, not what you sent. That second point is
why `create-team.ts` reads agents back.

## Results

One check, SEC-01, on a clean clone of this repository at commit `8c34fa9`. Full reports:
[Opus](results/sec-01-opus.md), [Sonnet](results/sec-01-sonnet.md).

| | Opus | Sonnet |
|---|---|---|
| Cost (usage-equivalent, billed to a subscription) | about $0.63 | about $0.31 |
| Wall time | 129 s | 36 s |
| Tool calls | 20 | 5 |
| Boundary probe | blocked | blocked |
| The real finding | **reported as a finding** | noticed, left under "could not verify" |
| Citations | all correct in the lines I checked | one wrong: it cited `src/.gitignore:2`, which does not exist |

**The finding.** `src/tools.ts:67` deliberately let `.env` through the scanner's file filter, and
`src/agent.ts` sends tool results to the model provider on the next turn. So scanning a project
with a real `.env` using `--provider groq` or `openai` would have sent its secret values to a
third party. I verified the cited lines before believing it. The fix is
[`src/redact.ts`](../src/redact.ts) (commit `d13bcbe`): every value in a real env file and anything
shaped like a known credential is replaced with a label and a length before the model sees it.

The security agent had a security flaw, and a second agent found it. That is the useful result.
The cost comparison is the cautionary one: the cheaper model covered the same ground and missed
the point, so on a security audit I would not pick the model on price.

## What does not work yet

- **The lead does not merge anything.** The specialists cannot post comments or update tasks, so their answers live in Paperclip's run logs (`<data-dir>/instances/default/data/run-logs/`). Merging them needs either an API call from outside the agents or a reviewed hand-off. I have not built it.
- **One check has run for real.** Six of the seven are untested here. No quality claim covers them.
- **This is a few runs, not a benchmark.** Two runs on one check cannot rank models. Treat the table as an anecdote with receipts.
- **It is not cheap.** A single check cost tens of cents of usage on a subscription that has limits. Seven checks on a strong model is several dollars-equivalent.
- **Windows only, one Paperclip version.** Both of those matter for the path syntax and for findings 1 to 6.
- **Paperclip's MCP tools remain** (finding 6). They write only into Paperclip, but that is more than three tools.

## Running it yourself

1. Install Paperclip, keep its data in a folder you choose, and bind it to loopback only:
   `npx paperclipai onboard --yes --bind loopback --data-dir <folder> --no-install-service`
2. **Do not use the wizard's "Claude subscription" button** (finding 3). If your `claude` login on disk has expired, sign in yourself with `claude auth login`.
3. Create a clean clone of what you want scanned, then run `create-team.ts` as above.
4. Run an agent: `POST /api/agents/<id>/heartbeat/invoke`. The answer is in the run log.
5. `npm test` runs the lock-down tests (they use a fake Paperclip, no usage spent).

Only scan code you own or may test. Every run uses your Claude usage.

## Files

| | |
|---|---|
| [`src/lockdown.ts`](src/lockdown.ts) | The lock-down, as pure functions, plus the check that reads it back |
| [`src/prompts.ts`](src/prompts.ts) | The audit prompt, and why it is a prompt template and not a task |
| [`src/create-team.ts`](src/create-team.ts) | Creates and verifies the team through Paperclip's API |
| [`src/paperclip.test.ts`](src/paperclip.test.ts) | 10 tests, including a fake Paperclip that quietly stores something weaker |
| [`results/`](results/) | The two SEC-01 reports |
