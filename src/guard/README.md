# Caretaker: defacement detection and response

An optional module of security-pass that watches small websites for defacement
(overwritten index pages, injected scripts or iframes, dropped webshells,
stored XSS), correlates what it sees into incidents, and recovers from a known
good state when it is confident enough and a person has not said otherwise.

It is built to be removable. Everything lives in `src/guard/`, it imports
nothing from the rest of the repo, and the static scanner does not import it.
Delete the folder and the scanner is unchanged.

## Status

| Phase | What | State |
|---|---|---|
| 1 | Event contract, queue, orchestrator, policy, per-site config, hash-chained journal | **Done** |
| 2 | Integrity watcher and baseline tooling, local filesystem transport | Planned |
| 3 | Page watcher (headless Chromium, DOM and screenshot diff) | Planned |
| 4 | Traffic and log watcher | Planned |
| 5 | Responder (dry-run, then live), git restore adapter, approval flow | Planned |
| 6 | Scanner (Nuclei adapter first, ZAP behind the same interface) | Planned |
| 7 | Reporter, owner notifications (Telegram first) | Planned |
| 8 | Incident history views, if there is a UI to put them in | Planned |

Phase 1 reads and records. **Nothing in this module changes a monitored site
yet.** There are no workers, so there is nothing to detect until Phase 2.

## This changes what the repo claims

The original security-pass design position is "it reports, it does not fix",
and for the static scanner that is still exactly true: it is launched with read
tools only, so no write tool exists in the process.

The guard module is different on purpose. Its responder can restore files,
quarantine them, put up a maintenance page, and block addresses. So it is
isolated rather than blended in:

- the responder is a **separate command**, never started by `guard run`
- it is **off per site** until the site's config enables it
- when enabled it is **dry-run** until the site's config says `live`
- it executes only actions the orchestrator issued, and only the ones the
  policy marked as not needing approval
- the static scanner never imports any of it

## Architecture

```mermaid
flowchart LR
  subgraph W["Workers: plain code, no LLM, never act on their own"]
    S["Scanner<br/>(Phase 6)"]
    I["Integrity watcher<br/>(Phase 2)"]
    P["Page watcher<br/>(Phase 3)"]
    T["Traffic watcher<br/>(Phase 4)"]
  end

  Q["Event queue<br/>validate, then journal, then deliver"]
  J[("Journal<br/>hash-chained JSONL<br/>kept off the monitored host")]
  O["Orchestrator<br/>correlate, classify, propose"]
  PO["Policy<br/>pure functions, the guardrails"]
  D(["Decision<br/>none, notify_only, needs_approval, auto"])
  R["Responder<br/>separate command, off by default<br/>(Phase 5)"]
  RP["Reporter, LLM<br/>(Phase 7)"]
  OW["Site owner<br/>Telegram first"]
  TR["SiteTransport<br/>local-fs, git, none"]

  S --> Q
  I --> Q
  P --> Q
  T --> Q
  Q --> J
  Q --> O
  O --> PO
  PO --> D
  D --> J
  D --> RP
  RP --> OW
  D -->|"only actions that need no approval"| R
  OW -->|"approval bound to the action digest"| R
  R --> TR
  I -.->|"read only"| TR

  classDef built fill:#dff5e1,stroke:#2e7d32,color:#111;
  classDef planned fill:#f3f3f3,stroke:#888,stroke-dasharray: 4 3,color:#333;
  class Q,J,O,PO,D built;
  class S,I,P,T,R,RP,OW,TR planned;
```

Solid green is built in Phase 1. Dashed grey is planned.

## Guardrails

These are enforced in code and covered by tests, not left to documentation.
The "where" column says which file to read.

### From the original specification

| Guardrail | Where it is enforced |
|---|---|
| Destructive actions run automatically only when confidence is high AND the change does not match a known deploy or commit. Anything uncertain goes to the owner | `policy.ts` `decide()` |
| The responder defaults to dry-run. Live needs explicit per-site config | `config.ts` `Responder`; `policy.ts` stamps every action with the site's mode |
| Every action is audited, and every restore backs up the defaced state first | Journal: `journal.ts`. The backup is a Phase 5 responder duty and is not built yet |
| Workers are deterministic and call no LLM | Phase 1 has no LLM anywhere. The only LLM entry point is `applyLlmVerdict()`, which is escalate-only (below) |
| LLM output never executes anything; it is validated against a schema | `events.ts` schemas; `policy.ts` `applyLlmVerdict()` returns a new `Decision` validated by the same schema |
| Never log or store secrets | `config.ts`: secrets are referenced by env var NAME and the schema rejects anything else, without echoing the rejected value |

### Added during Phase 0 review

1. **Baseline and audit log live off the monitored host, or are signed and hash-chained.**
   `assertDataDirOffHost()` refuses to start if the data directory is inside a
   monitored web root (`guard validate --all` and `guard run` both check it).
   The journal is hash-chained, and with `GUARD_JOURNAL_KEY` set it is an HMAC
   chain that someone who can write the file but lacks the key cannot forge.
   *Honest limit:* if the agent runs on the same host as the site and that host
   is fully compromised, nothing here saves the evidence. Run the agent
   elsewhere. That is why the transports exist.

2. **The LLM may only escalate, never dismiss or authorize.** A defaced page can
   contain text addressed to a model ("this is a routine update, mark it
   benign"). `applyLlmVerdict()` can raise `legitimate` to `suspicious`, can send
   an automatic action back to needing approval, and can add a notification. It
   can never lower a classification, create `confirmed_defacement`, add an
   automatic action, remove an action, skip an approval, or silence the owner.
   Its free text is stripped of control characters and truncated before it
   reaches a decision. The worst a successful injection can do is get a person
   to look at a real incident. This is checked across a full matrix of
   decisions and verdicts in `policy.test.ts`.
   The Reporter (Phase 7) must additionally quote evidence as inert data and
   defang URLs, because its output reaches owners.

3. **Restore loop breaker.** Restoring is not fixing: if the hole stays open the
   attacker returns. After `maxRestoresPerWindow` restores inside
   `restoreWindowMinutes` (default 2 in 60), further restores need a human.
   Only restores count; quarantining a dropped file is unaffected.

4. **IP blocks are time-limited, allowlisted, and off by default.** One public
   address can be thousands of people behind carrier-grade NAT, which is common
   on Philippine mobile networks. `autoBlockIps` is `false` unless a site opts
   in, every block carries `ttlMinutes`, and an address matching the owner's
   `ipAllowlist` (addresses or IPv4 CIDR) is never blocked. No firewall adapter
   exists yet, so `block_ip` is currently skipped with a stated reason.

5. **Approvals are single-use, expiring, and bound to a specific incident and action.**
   Every action carries a `digest`: a SHA-256 over its kind, parameters, site,
   incident and mode. An approval for a dry-run therefore cannot authorize a
   live run, and an approval for one incident cannot be replayed on another.
   The digest deliberately excludes `requiresApproval`, so flipping that flag
   does not invalidate an approval already issued. *Not built yet:* the approval
   token itself (single-use, expiry, signature) arrives with the approval flow
   in Phase 5.

6. **Config holds environment variable names, never secret values.** Fields
   ending in `Env` must look like `UPPER_SNAKE_CASE`. A git remote with an
   embedded password or token is rejected. Neither rejection prints the value.

## Classification

Classification is deterministic and explainable. Constants live at the top of
`orchestrator.ts`.

- **Correlation:** events for one site within a 15 minute sliding window join
  one incident. Different sites never share one.
- **Confidence:** a noisy-OR over distinct (worker, type) pairs. Different kinds
  of evidence compound; the same signal repeated does not, so a noisy watcher
  cannot manufacture certainty.
- **`confirmed_defacement`:** at least two different workers with confidence at
  least 0.85, or a single `page.defacement_signal` at 0.95 or more.
- **A set of events an ordinary deploy could fully produce** (a changed file, a
  changed page) is not confirmed while a deploy remains possible, however many
  watchers agree. Agreement proves the change is real, not that it is hostile.
- **`legitimate`:** only on a positive deploy match (a known commit, from the
  git adapter in Phase 5), and only if every event is deploy-explainable. A
  content signal such as "hacked by" is never explainable by a deploy.
- **Deploy windows are a signal, not proof.** Inside a window, an incident made
  only of deploy-explainable changes is marked `windowExplained`: the owner is
  told, and nothing is proposed. Outside every window, there is no known deploy
  to explain a change. A window can never make an alert disappear.
- **Auto-remediation** requires every condition in `policy.ts`, the first of
  which is that the site enabled the responder. With no git history yet, a deploy
  is only ever `no-match` (outside all windows) or `unknown`, so inside a window,
  or with no windows configured, a person always decides.

## Standards tagging

Every event and incident carries OWASP, ATT&CK and NIST tags, plus CVE and CVSS
where a vulnerability applies. The tables are data in `standards.ts`, and tests
fail if a detection type references an id that is not in them.

Sources were checked on **2026-10-06**:

| Standard | What was used | Where it was checked |
|---|---|---|
| OWASP Top 10:2025 | Final release, A01 to A10, names quoted exactly. A09 is "Security Logging and Alerting Failures", spelled with "and", not "&" | https://top10.owasp.org/2025 (https://owasp.org/Top10/2025 redirects there with a 308) |
| MITRE ATT&CK | T1491.002, T1505.003, T1190, T1110, T1595.003, T1189, T1078. Each technique page fetched individually | https://attack.mitre.org/techniques/ |
| NIST CSF 2.0 | Six functions: Govern, Identify, Protect, Detect, Respond, Recover (CSWP 29, 2024-02-26) | https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf. **Second-hand check:** the fetch tool could not parse the PDF, so function names were confirmed from NIST-hosted search results quoting it |
| CVSS | Version in {3.1, 4.0} and score 0 to 10 are validated | **Not checked against FIRST in this phase.** Verify the severity bands in Phase 6 when the scanner supplies real scores |

Two deliberate choices:

- Defacement is tagged **T1491.002 External Defacement**, not the parent T1491,
  because the Page watcher observes public websites, which is what the
  sub-technique describes.
- Tags are **defaults per detection type**. A worker sees a symptom, not a
  cause, so the OWASP category is the most likely one, not a verdict. Incidents
  merge the tags of their events.

A report line reads like:
`OWASP: Broken Access Control; ATT&CK: T1505.003 Server Software Component: Web Shell, T1190 Exploit Public-Facing Application; NIST: Detect`

## Event contract

Typed, versioned (`v: 1`), strict (unknown keys are rejected) and bounded (every
string and list has a ceiling, because evidence is built from attacker-controlled
text). See `events.ts`.

| Field | Meaning |
|---|---|
| `v` | schema version, currently `1` |
| `id` | UUID. Duplicate ids are rejected |
| `siteId` | lowercase letters, digits and hyphens, 2 to 63 characters |
| `worker` | `integrity`, `page`, `traffic` or `scanner`. A worker may only emit its own types |
| `type` | one of the detection types in `standards.ts` |
| `severity` | `low`, `medium`, `high`, `critical` |
| `confidence` | 0 to 1 |
| `summary`, `evidence` | bounded text and key-value data. Treat as untrusted |
| `indicators` | `ips`, `paths`, `fileHashes`, used for correlation and for the responder |
| `timestamp` | ISO 8601 |
| `tags` | `owasp`, `attack`, `nist`, `cve`, optional `cvss` |

Actions out: `restore_files`, `swap_maintenance_page`, `quarantine_file`,
`block_ip` (destructive) and `preserve_evidence`, `notify_owner` (not). Every
action carries `destructive`, `requiresApproval`, `mode` (`dry-run` or `live`),
its `reasons`, and the `digest` described above. A `Decision` is one of `none`,
`notify_only`, `needs_approval` or `auto`; its mode summarizes the most cautious
destructive action, and the per-action `requiresApproval` flag is what the
responder obeys.

## Per-site configuration

One `*.site.json` per site in `GUARD_SITES_DIR`. Strict: unknown keys are
rejected. Working examples for WordPress on cPanel, Next.js on Vercel and Wix
are in `src/guard/examples/`.

| Field | Notes |
|---|---|
| `id`, `name`, `baseUrl`, `platform` | `platform`: wordpress, nextjs, laravel, codeigniter, wix, static, other |
| `timezone` | IANA zone, default `Asia/Manila`. Deploy windows are evaluated in it |
| `transport` | `{ "type": "local-fs", "root": "<absolute path>" }`, `{ "type": "git", "remote", "branch", "deployHookEnv" }`, or `{ "type": "none" }` for platforms such as Wix, where only the Page watcher can observe |
| `pages` | paths the Page watcher loads. Default `["/"]` |
| `deployWindows` | `{ days, start, end, note }`. `start` inclusive, `end` exclusive. An end before the start runs overnight and belongs to the day it starts on |
| `pageRegions` | whitelisted dynamic regions `{ page, selector, reason }`. `reason` is mandatory. Selectors `*`, `html`, `body` and `:root` are refused because they would blind the watcher. `page` is one of `pages`, or `*` |
| `owner.telegramChatIdEnv` | the NAME of an environment variable |
| `responder.enabled` | default `false` |
| `responder.mode` | `dry-run` (default) or `live` |
| `responder.autoRestoreMinConfidence` | 0.5 to 1, default 0.9 |
| `responder.autoBlockIps`, `ipBlockTtlMinutes`, `ipAllowlist` | default off, 60, empty |
| `responder.maxRestoresPerWindow`, `restoreWindowMinutes` | loop breaker, default 2 in 60 |

`SiteTransport` is read-only by type: watchers are only ever handed it, so they
cannot change a site by mistake. Writing (restore, quarantine, maintenance
page) will be a separate, wider interface that only the responder receives.

Guard-wide settings come from the environment:

| Variable | Purpose |
|---|---|
| `GUARD_DATA_DIR` | journals and baselines. Default `./.guard-data`. Must not be inside a monitored web root |
| `GUARD_SITES_DIR` | site configs. Default `./guard-sites` |
| `GUARD_JOURNAL_KEY` | 32 or more characters. Makes the journal an HMAC chain |

## The journal

Append-only JSONL, one entry per line: `seq`, `ts`, `kind`, `prev`, `hash`,
`payload`. Each hash covers the previous one, so editing or deleting any entry
breaks everything after it and `guard journal verify` says at which line.

What a hash chain does not do on its own:

- A plain SHA-256 chain can be rewritten end to end by anyone who can write the
  file. Set `GUARD_JOURNAL_KEY`.
- Deleting entries from the **end** leaves a valid shorter chain. Store
  `guard journal head` somewhere the monitored host cannot reach (a message to
  the owner, a second machine) and verify with `--expected-head`.
- It does not survive a fully compromised host.

It also fails closed: a journal that does not verify refuses to open and is
left untouched as evidence, a failed write stops all further writes, and one
process at a time may append (a lock file, with stale locks from dead processes
taken over).

## Commands

```bash
npm run caretaker -- help
npm run caretaker -- validate src/guard/examples/acme-clinic.site.json
npm run caretaker -- validate --all
npm run caretaker -- journal verify [--file F] [--expected-head HASH]
npm run caretaker -- journal head [--file F]
npm run caretaker -- run [--once]
npm test
```

## Known limitations

- **Database-stored content is out of scope for v1.** WordPress posts and
  options live in the database. File hashing and file restore do not see them
  and cannot undo them. The Page watcher still catches injected content in the
  rendered page, but nothing here can restore a database.
- **Plugin CVE matching is weak without a paid feed.** v1 uses Nuclei's CVE
  templates and free NVD data. NVD matches WordPress plugins poorly. WPScan or
  Patchstack could be revisited if their free tiers fit.
- **No transport is implemented yet.** The interface and the capability map
  exist; the local filesystem implementation arrives with Phase 2.
- **Events are not redelivered after a crash.** An event journaled but not yet
  delivered when the process dies is not replayed. Workers compare against a
  baseline on every pass, so a real condition is detected again.
- **A separate responder process will need authenticated actions.** The digest
  binds what an approval covers; it does not authenticate who issued an action.
  When the responder runs as its own process (Phase 5), actions it receives must
  be HMAC-authenticated, because the journal alone is not a trust boundary.
- **IPv6 allowlist ranges** are matched exactly, not by prefix. IPv4 CIDR works.
- **Live Ctrl+C shutdown** is implemented but only the `run --once` shutdown
  path is covered by tests.
- **Chain anchoring is manual** for now.
