/**
 * Claude Code provider.
 *
 * Instead of running my own tool-calling loop against a chat API, this shells
 * out to `claude -p` once per check. Claude Code already has Read, Grep and
 * Glob, and --allowedTools restricts the run to exactly those, so the read-only
 * guarantee is enforced by the process boundary rather than by my prompt.
 *
 * It also means the scan runs on an existing Claude subscription rather than
 * metered API credits, which is what makes running all 34 checks practical.
 */

import { spawn } from "node:child_process";
import type { Check } from "./checklist.js";
import type { CheckResult, Finding } from "./agent.js";

const READ_ONLY_TOOLS = ["Read", "Grep", "Glob"];

const RULES = `You are running one item of a pre-launch security review over a codebase you may only read.

Rules, in order of importance:

1. You never edit anything. You have Read, Grep and Glob only. You report, a human decides.
2. Every finding must cite a real file path and line number you actually read, plus the line itself as evidence. A finding without a location is a guess, and you must not emit it.
3. "I could not verify this" is a correct answer and you are expected to use it. Put those in couldNotVerify. Never turn an unverified thing into a finding, and never report clean when you simply could not see the answer.
4. Mark confidence honestly. "confirmed" means you read the line and it is unambiguous. "likely" means the pattern is there but context could change it. "possible" means it is worth a human look and no more.
5. Only this check. No style, formatting or general code quality.
6. If the check does not apply to this codebase, return status not_applicable rather than inventing findings.

Search first, read second. Grep to locate candidates, then Read around each hit to confirm context before judging. Do not judge from a grep line alone.`;

const SHAPE = `Reply with JSON and nothing else. No prose, no code fences.

{
  "status": "clean" | "findings" | "unverified" | "not_applicable",
  "findings": [
    { "file": "relative/path.php", "line": 42, "evidence": "the exact line", "explanation": "what is wrong and what an attacker could do", "confidence": "confirmed" | "likely" | "possible" }
  ],
  "couldNotVerify": ["what you could not determine, and why"],
  "notes": "one or two sentences on what you looked at"
}`;

export function buildPrompt(check: Check): string {
  return [
    RULES,
    "",
    `CHECK ${check.id}: ${check.title}`,
    `Category: ${check.category}`,
    `Severity if found: ${check.severity}`,
    `Why it matters: ${check.why}`,
    "",
    "What to look for:",
    check.detect,
    "",
    check.verifiable === "partial"
      ? "This check is only partly decidable from source. State clearly in couldNotVerify what the repository cannot tell you."
      : "",
    SHAPE,
  ]
    .filter(Boolean)
    .join("\n");
}

/**
 * The prompt goes in on stdin rather than as an argument. On Windows `claude` is
 * a .cmd shim so spawn needs a shell, and a shell concatenates arguments without
 * escaping, which mangles anything multi-line. stdin sidesteps the quoting
 * problem entirely.
 */
function run(
  args: string[],
  prompt: string,
  cwd: string,
  timeoutMs: number,
): Promise<{ code: number; out: string; err: string }> {
  return new Promise((resolve) => {
    const child = spawn("claude", args, {
      cwd,
      shell: process.platform === "win32",
      stdio: ["pipe", "pipe", "pipe"],
    });
    let out = "", err = "";
    const timer = setTimeout(() => {
      child.kill();
      resolve({ code: -1, out, err: err + " [timed out]" });
    }, timeoutMs);
    child.stdout.on("data", (d) => (out += d.toString()));
    child.stderr.on("data", (d) => (err += d.toString()));
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code: code ?? -1, out, err });
    });
    child.on("error", (e) => {
      clearTimeout(timer);
      resolve({ code: -1, out, err: String(e) });
    });
    child.stdin.write(prompt);
    child.stdin.end();
  });
}

export async function runCheckViaClaude(
  model: string,
  root: string,
  check: Check,
  timeoutMs: number,
  onStep?: (m: string) => void,
): Promise<CheckResult> {
  const args = [
    "-p",
    "--output-format", "json",
    "--allowedTools", ...READ_ONLY_TOOLS,
    "--model", model,
  ];

  onStep?.(`    claude -p --model ${model} --allowedTools ${READ_ONLY_TOOLS.join(",")}`);
  const { code, out, err } = await run(args, buildPrompt(check), root, timeoutMs);

  if (code !== 0 && !out.trim()) {
    return {
      check, status: "error", findings: [], couldNotVerify: [], notes: "",
      toolCalls: 0, error: (err || `claude exited ${code}`).trim().slice(0, 300),
    };
  }

  // Envelope from --output-format json, with the model's text in .result
  let envelope: any;
  try {
    envelope = JSON.parse(out.slice(out.indexOf("{")));
  } catch {
    return {
      check, status: "error", findings: [], couldNotVerify: [], notes: "",
      toolCalls: 0, error: "Could not parse the claude envelope.",
    };
  }

  if (envelope.is_error) {
    return {
      check, status: "error", findings: [], couldNotVerify: [], notes: "",
      toolCalls: envelope.num_turns ?? 0, error: String(envelope.result ?? "unknown").slice(0, 300),
    };
  }

  const parsed = extractJson(String(envelope.result ?? ""));
  if (!parsed) {
    return {
      check, status: "unverified", findings: [],
      couldNotVerify: ["The run finished but did not return parseable JSON."],
      notes: String(envelope.result ?? "").slice(0, 400),
      toolCalls: envelope.num_turns ?? 0,
    };
  }

  const findings: Finding[] = (parsed.findings ?? [])
    .filter((f: any) => f && f.file && f.line) // rule 2, enforced not trusted
    .map((f: any) => ({
      checkId: check.id,
      title: check.title,
      severity: check.severity,
      file: String(f.file).replace(/\\/g, "/"),
      line: Number(f.line),
      evidence: String(f.evidence ?? "").slice(0, 300),
      explanation: String(f.explanation ?? ""),
      confidence: ["confirmed", "likely", "possible"].includes(f.confidence) ? f.confidence : "possible",
    }));

  let status = parsed.status as CheckResult["status"];
  if (findings.length && status !== "not_applicable") status = "findings";
  if (!findings.length && status === "findings") status = "unverified";

  return {
    check,
    status: status ?? "unverified",
    findings,
    couldNotVerify: (parsed.couldNotVerify ?? []).map(String),
    notes: String(parsed.notes ?? ""),
    toolCalls: envelope.num_turns ?? 0,
  };
}

function extractJson(text: string): any | null {
  const cleaned = text.trim().replace(/^```(?:json)?/i, "").replace(/```$/, "").trim();
  try {
    return JSON.parse(cleaned);
  } catch { /* fall through */ }
  const first = cleaned.indexOf("{");
  const last = cleaned.lastIndexOf("}");
  if (first !== -1 && last > first) {
    try {
      return JSON.parse(cleaned.slice(first, last + 1));
    } catch { /* give up */ }
  }
  return null;
}
