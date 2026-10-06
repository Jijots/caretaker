#!/usr/bin/env node
import "dotenv/config";
import OpenAI from "openai";
import path from "node:path";
import { promises as fs } from "node:fs";
import { CHECKS, CRITICAL_7, type Check } from "./checklist.js";
import { Sandbox } from "./tools.js";
import { runCheck, type CheckResult } from "./agent.js";
import { runCheckViaClaude } from "./claude-runner.js";
import { renderConsole, renderMarkdown } from "./report.js";
import { initChallenge, getStoredChallenge, checkChallenge } from "./verify.js";
import { runNuclei, renderPentestConsole, renderPentestMarkdown } from "./pentest.js";

const C = { bold: "\x1b[1m", grey: "\x1b[90m", reset: "\x1b[0m", red: "\x1b[31m", green: "\x1b[32m", cyan: "\x1b[36m" };

function arg(name: string, fallback?: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  if (i !== -1 && process.argv[i + 1] && !process.argv[i + 1].startsWith("--")) return process.argv[i + 1];
  return fallback;
}
const flag = (name: string) => process.argv.includes(`--${name}`);

async function main() {
  if (flag("help")) return help();

  const rawTarget = process.argv[2] && !process.argv[2].startsWith("--") ? process.argv[2] : ".";

  // A URL target means the active pentest path, not the static file scan.
  // Routed here, before any directory resolution, because a URL is never a
  // valid filesystem path and treating it as one is how you accidentally
  // pass a live target through code written for local files.
  if (/^https?:\/\//i.test(rawTarget)) {
    return runPentestMode(rawTarget);
  }

  const root = path.resolve(rawTarget);

  try {
    const st = await fs.stat(root);
    if (!st.isDirectory()) throw new Error("not a directory");
  } catch {
    console.error(`${C.red}Not a directory:${C.reset} ${root}`);
    process.exit(1);
  }

  // Provider. Claude Code is preferred: it runs on an existing subscription,
  // and --allowedTools enforces read-only at the process boundary rather than
  // in a prompt. Groq and OpenAI remain available for a keyed API run, and
  // "local" points at any OpenAI-compatible endpoint (Ollama, LM Studio, ...)
  // for a run that needs no subscription and no data leaving the machine.
  const forced = arg("provider");
  const groqKey = process.env.GROQ_API_KEY;
  const openaiKey = process.env.OPENAI_API_KEY;

  let provider: "claude" | "groq" | "openai" | "local";
  if (forced === "claude" || forced === "groq" || forced === "openai" || forced === "local") provider = forced;
  else provider = "claude";

  let key: string | undefined;
  let baseURL: string | undefined;
  let defaultModel = "sonnet";

  if (provider === "groq") {
    key = groqKey; baseURL = "https://api.groq.com/openai/v1"; defaultModel = "openai/gpt-oss-120b";
  } else if (provider === "openai") {
    key = openaiKey; defaultModel = "gpt-4o";
  } else if (provider === "local") {
    // Ollama, LM Studio and most local runners speak the OpenAI chat
    // completions API and ignore the key entirely, but the SDK still
    // requires a non-empty string, so a placeholder stands in for one.
    key = process.env.LOCAL_API_KEY || "local";
    baseURL = process.env.LOCAL_BASE_URL || arg("base-url") || "http://localhost:11434/v1";
    defaultModel = process.env.MODEL || "llama3.1";
  }
  if ((provider === "groq" || provider === "openai") && !key) {
    console.error(`${C.red}${provider.toUpperCase()}_API_KEY is not set.${C.reset} Or drop --provider to use Claude Code.`);
    process.exit(1);
  }

  const model = arg("model", process.env.MODEL || defaultModel) as string;
  const maxToolCalls = Number(arg("max-tools", "12"));
  const only = arg("only");

  let checks: Check[] = flag("all") ? CHECKS : CRITICAL_7;
  if (only) {
    const ids = only.split(",").map((s) => s.trim().toUpperCase());
    checks = CHECKS.filter((c) => ids.includes(c.id) || ids.includes(c.category.toUpperCase()));
  }
  if (!checks.length) {
    console.error(`${C.red}No checks matched.${C.reset}`);
    process.exit(1);
  }

  const sb = new Sandbox(root);
  const client = provider === "claude" ? null : new OpenAI({ apiKey: key!, baseURL });

  console.log("");
  console.log(`${C.bold}Security pass${C.reset} ${C.grey}${root}${C.reset}`);
  console.log(`${C.grey}${checks.length} checks · ${provider}/${model} · read-only, nothing will be modified${C.reset}`);
  console.log("");

  const results: CheckResult[] = [];
  for (let i = 0; i < checks.length; i++) {
    const check = checks[i];
    process.stdout.write(`${C.grey}[${i + 1}/${checks.length}]${C.reset} ${check.id} ${check.title}\n`);

    if (check.verifiable === "manual") {
      results.push({
        check, status: "unverified", findings: [],
        couldNotVerify: ["Not decidable from a repository."],
        notes: check.detect, toolCalls: 0,
      });
      console.log(`${C.grey}    skipped, not visible from code${C.reset}`);
      continue;
    }

    const step = (m: string) => { if (flag("verbose")) console.log(`${C.grey}${m}${C.reset}`); };
    const r = provider === "claude"
      ? await runCheckViaClaude(model, root, check, Number(arg("timeout", "240")) * 1000, step)
      : await runCheck(client!, model, sb, check, maxToolCalls, step);
    results.push(r);

    const mark =
      r.status === "findings" ? `${C.red}${r.findings.length} finding(s)${C.reset}`
      : r.status === "clean" ? `${C.green}clean${C.reset}`
      : r.status === "error" ? `${C.red}error: ${r.error}${C.reset}`
      : `${C.grey}${r.status}${C.reset}`;
    console.log(`${C.grey}    ${r.toolCalls} tool calls ·${C.reset} ${mark}`);
  }

  console.log(renderConsole(results, root));

  const out = arg("out");
  if (out) {
    await fs.writeFile(out, renderMarkdown(results, root), "utf8");
    console.log(`${C.grey}Report written to ${out}${C.reset}\n`);
  }

  const criticals = results.flatMap((r) => r.findings).filter((f) => f.severity === "critical");
  process.exit(criticals.length ? 2 : 0);
}

/**
 * The active pentest path. Two phases, run as separate invocations:
 *
 *   --pentest-init   issue a challenge and print where to publish it
 *   --pentest        check the published challenge, and only on success
 *                     run Nuclei against the target
 *
 * Splitting these matters. A single command that scans immediately after
 * asking the user to "confirm" ownership verifies nothing, it just adds a
 * prompt. Two invocations, with the second one independently re-fetching the
 * token from the live target, means the check is actually load-bearing.
 */
async function runPentestMode(target: string) {
  let origin: string;
  try {
    origin = new URL(target).origin;
  } catch {
    console.error(`${C.red}Not a valid URL:${C.reset} ${target}`);
    process.exit(1);
  }

  if (flag("pentest-init")) {
    const challenge = await initChallenge(target);
    console.log(`
${C.bold}Ownership verification required${C.reset} ${C.grey}before any active scan can run${C.reset}

Publish a file at this exact URL, publicly reachable, containing only the token below:

  ${C.cyan}${challenge.verifyUrl}${C.reset}

Token (the file's entire contents, no extra whitespace):

  ${C.bold}${challenge.token}${C.reset}

Once it is live, run:

  ${C.grey}npm run scan -- ${target} --pentest${C.reset}
`);
    return;
  }

  if (!flag("pentest")) {
    console.error(`${C.red}A URL target needs --pentest-init first, then --pentest.${C.reset} See --help.`);
    process.exit(1);
  }

  const challenge = await getStoredChallenge(target);
  if (!challenge) {
    console.error(`${C.red}No verification challenge found for ${origin}.${C.reset} Run with --pentest-init first.`);
    process.exit(1);
  }

  console.log(`${C.grey}Checking ${challenge.verifyUrl} ...${C.reset}`);
  const verified = await checkChallenge(challenge);
  if (!verified.ok) {
    console.error(`
${C.red}Ownership verification failed.${C.reset}
${verified.reason}

Nothing was scanned. Publish the token correctly and try again.
`);
    process.exit(1);
  }

  console.log(`${C.green}Verified.${C.reset} ${C.grey}Running Nuclei against ${target}. This sends real requests to the live target.${C.reset}`);

  const nucleiArgsRaw = arg("nuclei-args");
  const extraArgs = nucleiArgsRaw ? nucleiArgsRaw.split(" ").filter(Boolean) : [];
  const result = await runNuclei(target, extraArgs);

  console.log(renderPentestConsole(target, result));

  const out = arg("out");
  if (out) {
    await fs.writeFile(out, renderPentestMarkdown(target, result), "utf8");
    console.log(`${C.grey}Report written to ${out}${C.reset}\n`);
  }

  if (!result.ran) process.exit(1);
  const critical = result.findings.some((f) => f.severity === "critical");
  process.exit(critical ? 2 : 0);
}

function help() {
  console.log(`
${C.bold}security-pass${C.reset}  read-only code audit, plus an authorized-only active scan mode

STATIC SCAN, reads a local directory, never modifies anything

  npm run scan -- <path> [options]

Options
  --all                 run every check (default: the 7 that matter most)
  --only <ids>          run specific checks, e.g. --only AUTH-03,IO-01
  --provider <name>     claude (default, uses your Claude subscription), groq, openai, or local
  --model <name>        default sonnet on claude, gpt-4o on openai, llama3.1 on local
  --base-url <url>      local provider only, default http://localhost:11434/v1 (Ollama)
  --timeout <seconds>   per check, claude provider only. Default 240
  --max-tools <n>       tool calls allowed per check, default 12
  --out <file.md>       write a markdown report
  --verbose             print every tool call as it happens
  --help

Examples
  npm run scan -- C:/xampp/htdocs/FEU-COMPASS
  npm run scan -- ../mariposa --all --out report.md
  npm run scan -- . --only AUTH-03 --verbose
  npm run scan -- . --provider local --model qwen2.5:14b

Exit code is 2 if any critical finding was emitted, otherwise 0.

ACTIVE SCAN, sends real requests to a live URL. Only runs after you prove you
control the target. There is no flag to skip this.

  npm run scan -- https://target.example --pentest-init
      Issues a token and tells you where to publish it.

  npm run scan -- https://target.example --pentest
      Re-checks the published token, and only on success runs Nuclei
      (https://github.com/projectdiscovery/nuclei) against the target.
      Requires nuclei on PATH; the command tells you how to install it
      if it is missing.

  --nuclei-args "..."   extra arguments passed straight through to nuclei
  --out <file.md>        write a markdown report

DoS-tagged templates are excluded by default (--nuclei-args can override this,
but that is on you). Only ever point this at something you own or have
explicit written permission to test. The verification step proves control of
the domain, it does not prove you were the one authorized to test it, that
part is still your responsibility.
`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
