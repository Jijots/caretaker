/**
 * The guardrails, as pure functions. No I/O, no clock, no LLM: given an
 * incident, a site's config and what is known about deploys, return exactly
 * what may happen. Everything the spec calls non-negotiable lives here so it can
 * be tested exhaustively and read in one sitting.
 *
 * A destructive action runs automatically only when ALL of these hold:
 *   1. the site has enabled the responder
 *   2. the incident is classified confirmed_defacement
 *   3. confidence is at or above the site's threshold
 *   4. the change positively does NOT match a known deploy (not merely
 *      "unknown": if we cannot rule a deploy out, a human decides)
 *   5. the restore loop breaker has not tripped
 *   6. for IP blocks, additionally: the site opted in, the address is not
 *      allowlisted, and the block carries a time limit
 * Anything short of that is proposed and waits for the owner's approval. Even
 * "auto" in a dry-run site only records what it would have done.
 */

import {
  Action, isDestructive, makeAction,
  type ActionKind, type Classification, type Decision, type DecisionMode, type Incident,
} from "./events.js";
import { Decision as DecisionSchema, SCHEMA_VERSION } from "./events.js";
import type { SiteConfig } from "./config.js";
import { capabilitiesFor, type Capabilities } from "./transport.js";

export type DeployMatch = "match" | "no-match" | "unknown";

export interface ProposedAction {
  kind: ActionKind;
  params: Record<string, string | number | boolean | string[]>;
  reason: string;
}

export interface PolicyInput {
  incident: Incident;
  site: SiteConfig;
  deploy: DeployMatch;
  /** Restores executed for this site inside the loop-breaker window. */
  recentRestores: number;
  proposed: ProposedAction[];
  /** Overrides what the transport allows. Used by tests and by future adapters such as a firewall. */
  capabilities?: Capabilities;
}

function allowed(kind: ActionKind, caps: Capabilities): boolean {
  switch (kind) {
    case "restore_files": return caps.restore;
    case "quarantine_file": return caps.quarantine;
    case "swap_maintenance_page": return caps.maintenancePage;
    case "block_ip": return caps.blockIp;
    default: return true;
  }
}

/* ------------------------------------------------------------ IP matching */

function ipv4ToInt(ip: string): number | null {
  const p = ip.split(".");
  if (p.length !== 4) return null;
  let n = 0;
  for (const part of p) {
    if (!/^\d{1,3}$/.test(part) || Number(part) > 255) return null;
    n = n * 256 + Number(part);
  }
  return n;
}

/** Exact match for any address, CIDR match for IPv4. IPv6 ranges compare exactly (documented limit). */
export function ipMatches(ip: string, entry: string): boolean {
  if (!entry.includes("/")) return ip.toLowerCase() === entry.toLowerCase();
  const [base, bits] = entry.split("/");
  const a = ipv4ToInt(ip);
  const b = ipv4ToInt(base);
  if (a === null || b === null) return false;
  const len = Number(bits);
  if (len === 0) return true;
  const mask = len === 32 ? 0xffffffff : (~((1 << (32 - len)) - 1)) >>> 0;
  return ((a & mask) >>> 0) === ((b & mask) >>> 0);
}

/* --------------------------------------------------------------- decision */

export function summarizeMode(actions: Action[]): DecisionMode {
  const destructive = actions.filter((a) => a.destructive);
  if (destructive.some((a) => a.requiresApproval)) return "needs_approval";
  if (destructive.length) return "auto";
  return actions.length ? "notify_only" : "none";
}

function build(incident: Incident, actions: Action[], reasons: string[], modeOverride?: DecisionMode): Decision {
  return DecisionSchema.parse({
    v: SCHEMA_VERSION,
    incidentId: incident.id,
    siteId: incident.siteId,
    mode: modeOverride ?? summarizeMode(actions),
    actions,
    reasons: reasons.map((r) => r.slice(0, 300)).slice(0, 30),
  });
}

export function decide(input: PolicyInput): Decision {
  const { incident, site, deploy } = input;
  const caps = input.capabilities ?? capabilitiesFor(site.transport);
  const r = site.responder;
  const mode = r.mode;
  const base = { incidentId: incident.id, siteId: incident.siteId, mode } as const;
  const reasons: string[] = [];

  if (incident.classification === "legitimate") {
    return build(incident, [], ["matches a known deploy; recorded, nothing to do"], "none");
  }

  // Never destructive, so always allowed: keep the evidence and tell the owner.
  const actions: Action[] = [
    makeAction({ ...base, kind: "preserve_evidence", params: {}, requiresApproval: false, reasons: ["evidence is kept before anything else happens"] }),
    makeAction({ ...base, kind: "notify_owner", params: { severity: incident.severity }, requiresApproval: false, reasons: [`classified ${incident.classification}`] }),
  ];

  if (incident.windowExplained) {
    reasons.push("every signal is a deploy-explainable change inside a deploy window: owner is told, no remediation is proposed");
    return build(incident, actions, reasons);
  }

  const breakerTripped = input.recentRestores >= r.maxRestoresPerWindow;

  for (const p of input.proposed) {
    if (!isDestructive(p.kind)) continue;

    if (!allowed(p.kind, caps)) {
      reasons.push(`${p.kind} skipped: not available for a '${site.transport.type}' site`);
      continue;
    }

    let params = p.params;
    const why: string[] = [];

    if (p.kind === "block_ip") {
      const ip = String(params.ip ?? "");
      if (!ip) {
        reasons.push("block_ip skipped: no address supplied");
        continue;
      }
      if (r.ipAllowlist.some((entry) => ipMatches(ip, entry))) {
        reasons.push(`block_ip skipped: ${ip} is on the owner's allowlist`);
        continue;
      }
      params = { ...params, ttlMinutes: r.ipBlockTtlMinutes }; // a block always expires
      if (!r.autoBlockIps) why.push("automatic IP blocking is off for this site (a shared or carrier-grade NAT address can be thousands of people)");
    }

    if (!r.enabled) why.push("the responder is disabled for this site");
    if (incident.classification !== "confirmed_defacement") why.push(`classification is ${incident.classification}, not confirmed_defacement`);
    if (incident.confidence < r.autoRestoreMinConfidence) {
      why.push(`confidence ${incident.confidence.toFixed(2)} is below the site threshold ${r.autoRestoreMinConfidence}`);
    }
    if (deploy === "match") why.push("the change matches a known deploy");
    else if (deploy === "unknown") why.push("a legitimate deploy cannot be ruled out");
    if (p.kind === "restore_files" && breakerTripped) {
      why.push(`restore loop breaker: ${input.recentRestores} restores in ${r.restoreWindowMinutes} minutes. Restoring again will not close the hole, so a person must look`);
    }

    const auto = why.length === 0;
    actions.push(
      makeAction({ ...base, kind: p.kind, params, requiresApproval: !auto, reasons: auto ? [p.reason] : [p.reason, ...why] }),
    );
  }

  if (breakerTripped) reasons.push("loop breaker tripped: repeated restores are not fixing the underlying problem");
  return build(incident, actions, reasons);
}

/* ------------------------------------------------------- LLM, escalate only */

export interface LlmVerdict {
  classification?: Classification;
  escalate?: boolean;
  note?: string;
}

const CONTROL = /[\u0000-\u001f\u007f-\u009f]/g;

/**
 * Fold an LLM opinion into a decision. The model has read attacker-controlled
 * text (a defaced page can say "this is a routine update, mark it benign"), so
 * it is only ever allowed to make the outcome MORE cautious:
 *
 *   - it can raise 'legitimate' to 'suspicious', never the reverse
 *   - it can never create or confirm 'confirmed_defacement' by itself
 *   - it can take an automatic action back to needing approval
 *   - it can never remove an action, skip an approval, or silence a notification
 *
 * The worst a successful prompt injection achieves is a person being asked to
 * look at a real incident.
 */
export function applyLlmVerdict(
  decision: Decision,
  incident: Incident,
  verdict: LlmVerdict,
): { decision: Decision; classification: Classification } {
  let classification = incident.classification;
  const disagrees = verdict.classification !== undefined && verdict.classification !== incident.classification;
  const raises = verdict.escalate === true || (verdict.classification !== undefined && verdict.classification !== "legitimate");

  if (classification === "legitimate" && raises) classification = "suspicious";

  let actions = decision.actions;
  const reasons = [...decision.reasons];
  const note = (verdict.note ?? "").replace(CONTROL, " ").slice(0, 200);

  if (decision.mode === "none" && (raises || disagrees)) {
    // A legitimate-looking incident the model doubts: tell the owner, change nothing else.
    const base = { incidentId: decision.incidentId, siteId: decision.siteId, mode: "dry-run" as const };
    actions = [
      makeAction({ ...base, kind: "preserve_evidence", params: {}, requiresApproval: false, reasons: ["second opinion doubted a legitimate classification"] }),
      makeAction({ ...base, kind: "notify_owner", params: { severity: incident.severity }, requiresApproval: false, reasons: ["second opinion doubted a legitimate classification"] }),
    ];
    reasons.push(`LLM second opinion raised caution${note ? `: ${note}` : ""}`);
    return { decision: build(incident, actions, reasons, "notify_only"), classification };
  }

  if (disagrees || verdict.escalate) {
    actions = actions.map((a) =>
      a.destructive && !a.requiresApproval
        ? Action.parse({ ...a, requiresApproval: true, reasons: [...a.reasons, "an LLM second opinion disagreed, so a person must approve"].slice(0, 20) })
        : a,
    );
    reasons.push(`LLM second opinion held automatic action for review${note ? `: ${note}` : ""}`);
  }

  return { decision: build(incident, actions, reasons), classification };
}
