# security-pass

A read-only, tool-calling agent that runs a pre-launch security review over a codebase and reports findings for a human to confirm.

Built because I was doing this pass by hand before every launch, from memory, and memory is not a checklist. The two things it caught on past projects, a mass-assignable `role` column and a Content Security Policy still allowing `unsafe-inline`, are both in here as checks now.

## The design position

**It reports, it does not fix.** Read-only is enforced at the process boundary, not in a prompt: the Claude Code provider is launched with `--allowedTools Read Grep Glob`, so no write, edit or shell tool exists in the run at all. An agent that edits code unsupervised is a much worse trade than one that points at a line and explains itself.

**That claim covers the scanner, and only the scanner.** The optional [guard module](src/guard/README.md) (defacement detection and response) is different on purpose: its responder can restore files, quarantine them and block addresses, so it is isolated rather than blended in. It is a separate command that `guard run` never starts, it is off per site until the site's config enables it, it is dry-run until that config says `live`, and the scanner never imports any of it. Delete `src/guard/` and the scanner is unchanged.

**Every finding cites a file and a line it actually read.** Findings without a location are dropped by the harness before they reach you, not merely discouraged in the prompt.

**It is allowed to say it does not know.** Output has three buckets, not two:

| Bucket | Meaning |
|---|---|
| Findings | It read the line and something is wrong |
| Could not verify | It looked and could not decide, and says why |
| Not visible from code | Billing caps, 2FA, backups. A repository cannot answer these |

The third bucket matters. A tool that reports "clean" on backups because it never looked is worse than useless, it is misleading. An auditor that never says "I could not tell" is not careful, it is guessing.

**Searching before reading.** The agent greps to locate candidates, then reads around each hit to confirm the context before it judges. Judging from a grep line alone is how false positives get made, and a tool that cries wolf gets ignored inside a week.

## Setup

```bash
npm install
```

That is all, if you have Claude Code installed and signed in. The default provider shells out to `claude -p` once per check, which means the scan runs on an existing subscription rather than metered API credits, and that is what makes running all 34 checks practical.

To use a chat API instead, put `GROQ_API_KEY` or `OPENAI_API_KEY` in `.env` and pass `--provider groq` or `--provider openai`. Those paths run a hand-written tool-calling loop in `agent.ts` against sandboxed read-only tools in `tools.ts`.

To run entirely offline, with nothing sent to any API, point it at a local model instead:

```bash
npm run scan -- . --provider local --model qwen2.5:14b
```

Defaults to `http://localhost:11434/v1`, which is Ollama's OpenAI-compatible endpoint; override with `--base-url` or `LOCAL_BASE_URL` for LM Studio or anything else that speaks the same API. This needs a model that actually supports tool calling, most small local models don't reliably; `qwen2.5` and `llama3.1` do. No API key required, and no code content leaves the machine.

## Use

```bash
npm run scan -- C:/xampp/htdocs/FEU-COMPASS
npm run scan -- ../mariposa --all --out report.md
npm run scan -- . --only AUTH-03,IO-01 --verbose
```

By default it runs the seven checks that matter most. `--all` runs all 34.

| Option | |
|---|---|
| `--all` | every check |
| `--only <ids>` | specific checks or a category |
| `--provider <name>` | `claude` (default), `groq`, `openai`, or `local` |
| `--model <name>` | default `sonnet` |
| `--base-url <url>` | `local` provider only, default `http://localhost:11434/v1` |
| `--timeout <s>` | per check, claude provider. Default 240 |
| `--max-tools <n>` | tool calls per check, api providers. Default 12 |
| `--out <file.md>` | write a markdown report |
| `--verbose` | print each tool call as it happens |

Exit code is `2` if any critical finding was emitted, so it can gate a pipeline.

## The checks

34 checks across secrets, database, auth and access control, rate limiting, input and output, payments, AI features, deployment and ops, and mobile. They live in [`src/checklist.ts`](src/checklist.ts), which is the part worth reading. Each one carries what to look for, why it matters, and whether it is decidable from source at all.

The seven marked `critical7` are the ones to run first: secrets on the server, the public database key on the client, row-level security, ownership checks rather than just authentication, rate limiting, billing caps, and parameterized queries.

## Active scanning, a live target rather than a directory

Static analysis gets authorization for free: you can only point it at files you can already read, and the filesystem enforces that. A URL has no equivalent gate, anyone can type anyone's domain, so this mode requires proof of control before it will touch anything, the same way Let's Encrypt proves domain control before issuing a certificate. There is no flag to skip this.

```bash
npm run scan -- https://target.example --pentest-init
# publish the printed token at https://target.example/.well-known/security-scan-verify.txt

npm run scan -- https://target.example --pentest
# re-fetches the token from the live target; only runs Nuclei if it matches
```

It wraps [Nuclei](https://github.com/projectdiscovery/nuclei) rather than generating attack payloads itself, community-maintained template coverage beats anything worth hand-rolling for a first version, in the same spirit that the static side wraps Claude Code instead of reimplementing a static analyzer. Requires `nuclei` on `PATH`; the command tells you how to install it if it's missing. DoS-tagged templates are excluded by default, `--nuclei-args` can override that, deliberately, so opting back in takes a conscious choice rather than a default.

**Only point this at something you own or have explicit written permission to test.** Verification proves you control the domain. It does not prove you were authorized to test it, that part stays on you.

## Architecture

```
src/
  checklist.ts     the 34 checks. domain knowledge, no code
  claude-runner.ts default provider. one `claude -p` per check, read-only tools
  tools.ts         list_files, grep, read_file. sandboxed, for the api providers
  agent.ts         hand-written tool-calling loop, for the api providers
  report.ts        console and markdown output, static scan
  verify.ts         ownership verification for the active scan, no bypass
  pentest.ts        Nuclei wrapper + its own console/markdown output
  index.ts         CLI, routes a URL target to pentest mode, a directory to the static scan
  guard/           optional defacement detection and response module, self-contained.
                   Its own CLI (npm run guard) and tests (npm test). See guard/README.md
```

Two providers exist on purpose. The Claude Code path is what you run. The API path in `agent.ts` is the loop written by hand, with its own sandbox, retry-on-429 and context pruning, and it is the one worth reading if you want to see how the loop actually works.

One agent run per check, rather than one run for everything. A stubborn check cannot eat the whole budget, a failure is isolated to that check, and each run only holds the context for one question.

## Known limits

- It reads a repository. It cannot see your live database, your hosting config, or your provider dashboards.
- Row-level security is checked against migrations and policy files. The live database is the real source of truth.
- Git history is not searched. Run `git log --all --full-history -- .env` yourself.
- It has no dependency vulnerability database. Run `npm audit` and `composer audit`.
- Findings are evidence for a human, not a verdict. Confirm before changing anything.
- The active scan's coverage is exactly Nuclei's template set. No findings does not mean no vulnerabilities, it means nothing matched the templates that ran.
- Ownership verification proves domain control, not testing authorization. Those are different things; the tool only checks the first one.

## Next

- Audit log of every tool call per run, so a finding can be traced back to what was read
- A regression mode that fails only on findings new since the last run
- Framework packs, so a Laravel scan and a Next.js scan ask different questions
- An optional sqlmap pass behind the same verification gate, for injection specifically
