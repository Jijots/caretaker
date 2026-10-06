import type { CheckResult } from "./agent.js";

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3 } as const;

const C = {
  reset: "\x1b[0m", bold: "\x1b[1m", dim: "\x1b[2m",
  red: "\x1b[31m", yellow: "\x1b[33m", green: "\x1b[32m",
  cyan: "\x1b[36m", grey: "\x1b[90m",
};

export function renderConsole(results: CheckResult[], root: string): string {
  const out: string[] = [];
  const findings = results.flatMap((r) => r.findings)
    .sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);

  out.push("");
  out.push(`${C.bold}Security pass${C.reset} ${C.grey}${root}${C.reset}`);
  out.push("");

  if (findings.length) {
    out.push(`${C.bold}FINDINGS (${findings.length})${C.reset}`);
    out.push("");
    for (const f of findings) {
      const col = f.severity === "critical" ? C.red : f.severity === "high" ? C.yellow : C.cyan;
      out.push(`${col}${C.bold}${f.severity.toUpperCase()}${C.reset}  ${f.title}  ${C.grey}[${f.checkId}]${C.reset}`);
      out.push(`  ${C.cyan}${f.file}:${f.line}${C.reset}  ${C.grey}(${f.confidence})${C.reset}`);
      out.push(`  ${C.grey}${f.evidence}${C.reset}`);
      out.push(`  ${f.explanation}`);
      out.push("");
    }
  } else {
    out.push(`${C.green}No findings emitted.${C.reset} That is not the same as secure. Read the unverified list below.`);
    out.push("");
  }

  const unverified = results.filter((r) => r.couldNotVerify.length);
  if (unverified.length) {
    out.push(`${C.bold}COULD NOT VERIFY${C.reset}  ${C.grey}the agent looked and could not decide${C.reset}`);
    out.push("");
    for (const r of unverified) {
      out.push(`  ${C.bold}${r.check.id}${C.reset} ${r.check.title}`);
      for (const u of r.couldNotVerify) out.push(`    ${C.grey}- ${u}${C.reset}`);
    }
    out.push("");
  }

  const manual = results.filter((r) => r.check.verifiable === "manual");
  if (manual.length) {
    out.push(`${C.bold}NOT VISIBLE FROM CODE${C.reset}  ${C.grey}you have to check these yourself${C.reset}`);
    out.push("");
    for (const r of manual) {
      out.push(`  ${C.bold}${r.check.id}${C.reset} ${r.check.title}`);
      if (r.notes) out.push(`    ${C.grey}${r.notes}${C.reset}`);
    }
    out.push("");
  }

  const clean = results.filter((r) => r.status === "clean").length;
  const na = results.filter((r) => r.status === "not_applicable").length;
  const errored = results.filter((r) => r.status === "error");
  out.push(`${C.grey}${results.length} checks. ${clean} clean, ${findings.length} findings, ${unverified.length} partly unverified, ${na} not applicable.${C.reset}`);
  if (errored.length) {
    out.push(`${C.red}${errored.length} check(s) errored:${C.reset} ${errored.map((e) => e.check.id).join(", ")}`);
  }
  out.push("");
  return out.join("\n");
}

export function renderMarkdown(results: CheckResult[], root: string): string {
  const findings = results.flatMap((r) => r.findings)
    .sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);
  const md: string[] = [];

  md.push(`# Security pass`);
  md.push("");
  md.push(`**Target:** \`${root}\`  `);
  md.push(`**Run:** ${new Date().toISOString()}  `);
  md.push(`**Checks:** ${results.length}  `);
  md.push("");
  md.push(`> This is a read-only audit. Nothing was modified. Every finding needs a human to confirm it before anything is changed.`);
  md.push("");

  md.push(`## Findings (${findings.length})`);
  md.push("");
  if (!findings.length) {
    md.push(`None emitted. That is not the same as secure. See what could not be verified.`);
    md.push("");
  }
  for (const f of findings) {
    md.push(`### ${f.severity.toUpperCase()} · ${f.title}`);
    md.push("");
    md.push(`- **Where:** \`${f.file}:${f.line}\``);
    md.push(`- **Check:** ${f.checkId}`);
    md.push(`- **Confidence:** ${f.confidence}`);
    md.push("");
    md.push("```");
    md.push(f.evidence);
    md.push("```");
    md.push("");
    md.push(f.explanation);
    md.push("");
  }

  md.push(`## Could not verify`);
  md.push("");
  const unv = results.filter((r) => r.couldNotVerify.length);
  if (!unv.length) md.push("_Nothing flagged._");
  for (const r of unv) {
    md.push(`**${r.check.id} ${r.check.title}**`);
    md.push("");
    for (const u of r.couldNotVerify) md.push(`- ${u}`);
    md.push("");
  }

  md.push(`## Not visible from code`);
  md.push("");
  md.push("These cannot be decided by reading a repository. Check them yourself.");
  md.push("");
  for (const r of results.filter((r) => r.check.verifiable === "manual")) {
    md.push(`- **${r.check.id}** ${r.check.title}${r.notes ? ` — ${r.notes}` : ""}`);
  }
  md.push("");

  md.push(`## Checks that came back clean`);
  md.push("");
  for (const r of results.filter((r) => r.status === "clean")) {
    md.push(`- ${r.check.id} ${r.check.title}`);
  }
  md.push("");
  return md.join("\n");
}
