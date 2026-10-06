/**
 * The loop.
 *
 * One bounded agent run per check, so a single stubborn check cannot eat the
 * whole budget, and so a failure is isolated to that check rather than the scan.
 *
 * The agent gathers evidence with read-only tools and then returns structured
 * findings. It is told, repeatedly, that "I could not verify this" is an
 * acceptable and expected answer. An auditor that never says that is not
 * careful, it is guessing.
 */

import OpenAI from "openai";
import type { Check } from "./checklist.js";
import { Sandbox, TOOL_DEFS, runTool } from "./tools.js";

export interface Finding {
  checkId: string;
  title: string;
  severity: Check["severity"];
  file: string | null;
  line: number | null;
  evidence: string;
  explanation: string;
  confidence: "confirmed" | "likely" | "possible";
}

export interface CheckResult {
  check: Check;
  status: "clean" | "findings" | "unverified" | "not_applicable" | "error";
  findings: Finding[];
  couldNotVerify: string[];
  notes: string;
  toolCalls: number;
  error?: string;
}

const SYSTEM = `You are running one item of a pre-launch security review over a codebase you can only read.

Rules, in order of importance:

1. You never edit anything. You have no write tool. You report, a human decides.
2. Every finding must cite a real file path and line number you actually read, plus the line as evidence. A finding without a location is not a finding, it is a guess, and you must not emit it.
3. Saying "I could not verify this" is a correct answer and you are expected to use it. Put those in couldNotVerify. Do not turn an unverified thing into a finding, and do not report a check as clean when you simply could not see the answer.
4. Mark confidence honestly. "confirmed" means you read the line and it is unambiguous. "likely" means the pattern is there but context could change it. "possible" means it is worth a human look and no more.
5. Do not report style, formatting or general code quality. Only this specific check.
6. If the check does not apply to this codebase, say so with status not_applicable rather than inventing findings.

Work by searching first and reading second. grep to locate candidates, then read_file around each hit to confirm the context before you judge it. Do not judge from a grep line alone.

When you have finished gathering evidence, reply with JSON only, matching this shape:

{
  "status": "clean" | "findings" | "unverified" | "not_applicable",
  "findings": [
    {
      "file": "relative/path.ts",
      "line": 42,
      "evidence": "the exact line you read",
      "explanation": "what is wrong and what an attacker could do",
      "confidence": "confirmed" | "likely" | "possible"
    }
  ],
  "couldNotVerify": ["what you could not determine, and why"],
  "notes": "one or two sentences, what you looked at"
}`;

export async function runCheck(
  client: OpenAI,
  model: string,
  sb: Sandbox,
  check: Check,
  maxToolCalls: number,
  onStep?: (msg: string) => void,
): Promise<CheckResult> {
  const messages: any[] = [
    { role: "system", content: SYSTEM },
    {
      role: "user",
      content:
        `CHECK ${check.id}: ${check.title}\n` +
        `Category: ${check.category}\n` +
        `Severity if found: ${check.severity}\n` +
        `Why it matters: ${check.why}\n\n` +
        `What to look for:\n${check.detect}\n\n` +
        (check.verifiable === "partial"
          ? `Note: this check is only partly decidable from source. Say clearly in couldNotVerify what the repository cannot tell you.\n`
          : "") +
        `Begin.`,
    },
  ];

  let toolCalls = 0;

  for (let turn = 0; turn < maxToolCalls + 4; turn++) {
    let res;
    try {
      res = await withRetry(
        () =>
          client.chat.completions.create({
            model,
            messages: prune(messages),
            // Out of budget: drop the tools entirely rather than asking for
            // tool_choice "none". Some models call a tool anyway when the
            // definitions are still present, and the request is then rejected.
            ...(toolCalls >= maxToolCalls ? {} : { tools: TOOL_DEFS, tool_choice: "auto" as const }),
            temperature: 0,
          }),
        onStep,
      );
    } catch (e) {
      return {
        check, status: "error", findings: [], couldNotVerify: [], notes: "",
        toolCalls, error: (e as Error).message,
      };
    }

    const msg = res.choices[0].message;
    messages.push(msg);

    if (msg.tool_calls?.length) {
      for (const tc of msg.tool_calls) {
        toolCalls++;
        let args: any = {};
        try {
          args = JSON.parse(tc.function.arguments || "{}");
        } catch { /* leave empty, tool will complain */ }
        onStep?.(`    ${tc.function.name}(${short(args)})`);
        let out: any;
        try {
          out = await runTool(sb, tc.function.name, args);
        } catch (e) {
          out = { error: (e as Error).message };
        }
        messages.push({
          role: "tool",
          tool_call_id: tc.id,
          content: JSON.stringify(out).slice(0, 5_000),
        });
      }
      continue;
    }

    // No tool calls left, so this should be the verdict.
    const parsed = parseJson(msg.content ?? "");
    if (!parsed) {
      messages.push({
        role: "user",
        content: "Reply with the JSON object only. No prose, no code fences.",
      });
      continue;
    }

    const findings: Finding[] = (parsed.findings ?? [])
      .filter((f: any) => f && f.file && f.line) // rule 2, enforced not trusted
      .map((f: any) => ({
        checkId: check.id,
        title: check.title,
        severity: check.severity,
        file: String(f.file),
        line: Number(f.line),
        evidence: String(f.evidence ?? "").slice(0, 300),
        explanation: String(f.explanation ?? ""),
        confidence: (["confirmed", "likely", "possible"].includes(f.confidence) ? f.confidence : "possible"),
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
      toolCalls,
    };
  }

  return {
    check, status: "unverified", findings: [],
    couldNotVerify: ["Ran out of turns before reaching a verdict."],
    notes: "", toolCalls,
  };
}

function parseJson(text: string): any | null {
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

function short(args: any): string {
  const s = Object.entries(args)
    .map(([k, v]) => `${k}: ${JSON.stringify(v)}`)
    .join(", ");
  return s.length > 90 ? s.slice(0, 90) + "..." : s;
}

/**
 * Free tiers meter tokens per minute, so a 429 is a pacing problem rather than a
 * failure. Wait for the window the provider names and try again.
 */
async function withRetry<T>(fn: () => Promise<T>, onStep?: (m: string) => void, attempts = 4): Promise<T> {
  let lastErr: any;
  for (let i = 0; i < attempts; i++) {
    try {
      return await fn();
    } catch (e: any) {
      lastErr = e;
      const status = e?.status ?? e?.response?.status;
      if (status !== 429 && status !== 503) throw e;
      const msg = String(e?.message ?? "");
      const m = msg.match(/try again in ([\d.]+)s/i);
      const waitMs = m ? Math.ceil(parseFloat(m[1]) * 1000) + 750 : Math.min(60_000, 8_000 * (i + 1));
      onStep?.(`    rate limited, waiting ${Math.round(waitMs / 1000)}s`);
      await new Promise((r) => setTimeout(r, waitMs));
    }
  }
  throw lastErr;
}

/**
 * Keep the instructions and the question, keep recent work, drop the middle.
 * Tool results from six steps ago rarely change the verdict and they are the
 * bulk of the tokens.
 */
function prune(messages: any[], keepTail = 8): any[] {
  if (messages.length <= keepTail + 2) return messages;
  const head = messages.slice(0, 2);
  let tail = messages.slice(-keepTail);
  // A tool result must follow its assistant tool_call, so drop orphans at the seam.
  while (tail.length && tail[0].role === "tool") tail = tail.slice(1);
  return [...head, ...tail];
}
