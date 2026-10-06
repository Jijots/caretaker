/**
 * The event contract: events in, actions out. Shared by every worker, the
 * orchestrator and the responder. Versioned (SCHEMA_VERSION), strict (unknown
 * keys are rejected), and bounded (every string and list has a ceiling).
 *
 * Bounds matter here. Evidence is built from things an attacker controls:
 * page text, User-Agent strings, file names. Unbounded, a hostile site could
 * make the journal enormous or smuggle a novel into a report. Anything that
 * renders evidence must still treat it as inert data, never as instructions.
 */

import { z } from "zod";
import { randomUUID } from "node:crypto";
import { isIP } from "node:net";
import { canonicalize, sha256Hex } from "./canonical.js";
import {
  ATTACK_IDS, DETECTION_TYPES, DETECTION_TYPE_IDS, NIST_CSF_FUNCTIONS, OWASP_IDS,
  tagsFor, type DetectionType, type TagOverrides,
} from "./standards.js";

export const SCHEMA_VERSION = 1 as const;

/* ------------------------------------------------------------- primitives */

export const SiteId = z.string().regex(/^[a-z0-9][a-z0-9-]{1,62}$/, "lowercase letters, digits and hyphens, 2 to 63 characters");

export const Severity = z.enum(["low", "medium", "high", "critical"]);
export type Severity = z.infer<typeof Severity>;
export const SEVERITY_RANK: Record<Severity, number> = { low: 0, medium: 1, high: 2, critical: 3 };
export const maxSeverity = (xs: Severity[]): Severity =>
  xs.reduce((a, b) => (SEVERITY_RANK[b] > SEVERITY_RANK[a] ? b : a));

export const Confidence = z.number().min(0).max(1);

const Isoz = z.string().datetime();

const BoundedText = z.string().max(2000);
const EvidenceValue = z.union([BoundedText, z.number().finite(), z.boolean(), z.array(BoundedText).max(50)]);
export const Evidence = z
  .record(z.string().max(64), EvidenceValue)
  .refine((r) => Object.keys(r).length <= 50, "evidence has at most 50 keys");

export const Indicators = z
  .object({
    ips: z.array(z.string().refine((s) => isIP(s) !== 0, "not an IP address")).max(50).default([]),
    paths: z.array(z.string().max(500)).max(50).default([]),
    fileHashes: z.array(z.string().regex(/^[a-f0-9]{64}$/)).max(50).default([]),
  })
  .strict();
export type Indicators = z.infer<typeof Indicators>;

export const TagsSchema = z
  .object({
    owasp: z.array(z.enum(OWASP_IDS)).min(1),
    attack: z.array(z.enum(ATTACK_IDS)).min(1),
    nist: z.array(z.enum(NIST_CSF_FUNCTIONS)).min(1),
    cve: z.array(z.string().regex(/^CVE-\d{4}-\d{4,}$/, "not a CVE id")).max(50).default([]),
    cvss: z
      .object({ version: z.enum(["3.1", "4.0"]), score: z.number().min(0).max(10), vector: z.string().max(200).optional() })
      .strict()
      .optional(),
  })
  .strict();

/* ------------------------------------------------------------------ events */

export const DetectionWorker = z.enum(["integrity", "page", "traffic", "scanner"]);
export type DetectionWorker = z.infer<typeof DetectionWorker>;

export const SecurityEvent = z
  .object({
    v: z.literal(SCHEMA_VERSION),
    id: z.string().uuid(),
    siteId: SiteId,
    worker: DetectionWorker,
    type: z.enum(DETECTION_TYPE_IDS),
    severity: Severity,
    confidence: Confidence,
    summary: z.string().min(1).max(300),
    evidence: Evidence,
    indicators: Indicators.default({}),
    timestamp: Isoz,
    tags: TagsSchema,
  })
  .strict()
  .superRefine((e, ctx) => {
    if (DETECTION_TYPES[e.type].worker !== e.worker) {
      ctx.addIssue({ code: "custom", path: ["worker"], message: `worker '${e.worker}' may not emit '${e.type}'` });
    }
  });
export type SecurityEvent = z.infer<typeof SecurityEvent>;

export interface NewEventInput {
  siteId: string;
  type: DetectionType;
  severity: Severity;
  confidence: number;
  summary: string;
  evidence?: Record<string, string | number | boolean | string[]>;
  indicators?: Partial<Indicators>;
  tags?: TagOverrides;
  timestamp?: string;
}

/** The way workers build events. Worker and tags come from the type table, so a worker cannot mislabel itself. */
export function createEvent(input: NewEventInput): SecurityEvent {
  return SecurityEvent.parse({
    v: SCHEMA_VERSION,
    id: randomUUID(),
    siteId: input.siteId,
    worker: DETECTION_TYPES[input.type].worker,
    type: input.type,
    severity: input.severity,
    confidence: input.confidence,
    summary: input.summary,
    evidence: input.evidence ?? {},
    indicators: input.indicators ?? {},
    timestamp: input.timestamp ?? new Date().toISOString(),
    tags: tagsFor(input.type, input.tags),
  });
}

/* --------------------------------------------------------------- incidents */

export const Classification = z.enum(["legitimate", "suspicious", "confirmed_defacement"]);
export type Classification = z.infer<typeof Classification>;

export const Incident = z
  .object({
    v: z.literal(SCHEMA_VERSION),
    id: z.string().uuid(),
    siteId: SiteId,
    openedAt: Isoz,
    updatedAt: Isoz,
    eventIds: z.array(z.string().uuid()).min(1).max(1000),
    workers: z.array(DetectionWorker).min(1),
    severity: Severity,
    confidence: Confidence,
    classification: Classification,
    /** Every event is deploy-explainable AND inside a deploy window. Informational: never suppresses an alert. */
    windowExplained: z.boolean(),
    summary: z.string().max(500),
    indicators: Indicators,
    tags: TagsSchema,
  })
  .strict();
export type Incident = z.infer<typeof Incident>;

/* ----------------------------------------------------------------- actions */

export const ACTION_KINDS = [
  "restore_files", "swap_maintenance_page", "quarantine_file", "block_ip", "preserve_evidence", "notify_owner",
] as const;
export const ActionKind = z.enum(ACTION_KINDS);
export type ActionKind = z.infer<typeof ActionKind>;

/** Single source of truth for "changes something on the site or its perimeter". */
const DESTRUCTIVE: Record<ActionKind, boolean> = {
  restore_files: true,
  swap_maintenance_page: true,
  quarantine_file: true,
  block_ip: true,
  preserve_evidence: false,
  notify_owner: false,
};
export const isDestructive = (k: ActionKind): boolean => DESTRUCTIVE[k];

export const ActionMode = z.enum(["dry-run", "live"]);
export type ActionMode = z.infer<typeof ActionMode>;

const ActionParams = z.record(z.string().max(64), EvidenceValue).refine((r) => Object.keys(r).length <= 50);

interface DigestInput {
  incidentId: string;
  siteId: string;
  kind: ActionKind;
  params: Record<string, unknown>;
  mode: ActionMode;
}

/**
 * What an approval is bound to. Covers WHAT will run, WHERE, and in WHICH mode,
 * and nothing else. An approval for a dry-run therefore cannot authorise a live
 * run, and an approval for one incident cannot be replayed against another.
 */
export function actionDigest(a: DigestInput): string {
  return sha256Hex(
    canonicalize({ v: SCHEMA_VERSION, incidentId: a.incidentId, siteId: a.siteId, kind: a.kind, params: a.params, mode: a.mode }),
  );
}

export const Action = z
  .object({
    v: z.literal(SCHEMA_VERSION),
    id: z.string().uuid(),
    incidentId: z.string().uuid(),
    siteId: SiteId,
    kind: ActionKind,
    params: ActionParams,
    destructive: z.boolean(),
    requiresApproval: z.boolean(),
    mode: ActionMode,
    reasons: z.array(z.string().max(300)).max(20),
    digest: z.string().regex(/^[a-f0-9]{64}$/),
  })
  .strict()
  .superRefine((a, ctx) => {
    if (a.destructive !== isDestructive(a.kind)) {
      ctx.addIssue({ code: "custom", path: ["destructive"], message: "flag does not match the action kind" });
    }
    if (a.digest !== actionDigest(a)) {
      ctx.addIssue({ code: "custom", path: ["digest"], message: "digest does not match the action contents" });
    }
  });
export type Action = z.infer<typeof Action>;

export interface NewActionInput {
  incidentId: string;
  siteId: string;
  kind: ActionKind;
  params?: Record<string, string | number | boolean | string[]>;
  requiresApproval: boolean;
  mode: ActionMode;
  reasons?: string[];
}

export function makeAction(input: NewActionInput): Action {
  const params = input.params ?? {};
  return Action.parse({
    v: SCHEMA_VERSION,
    id: randomUUID(),
    incidentId: input.incidentId,
    siteId: input.siteId,
    kind: input.kind,
    params,
    destructive: isDestructive(input.kind),
    requiresApproval: input.requiresApproval,
    mode: input.mode,
    reasons: input.reasons ?? [],
    digest: actionDigest({ incidentId: input.incidentId, siteId: input.siteId, kind: input.kind, params, mode: input.mode }),
  });
}

/* --------------------------------------------------------------- decisions */

export const DecisionMode = z.enum(["none", "notify_only", "needs_approval", "auto"]);
export type DecisionMode = z.infer<typeof DecisionMode>;

export const Decision = z
  .object({
    v: z.literal(SCHEMA_VERSION),
    incidentId: z.string().uuid(),
    siteId: SiteId,
    mode: DecisionMode,
    actions: z.array(Action).max(50),
    reasons: z.array(z.string().max(300)).max(30),
  })
  .strict();
export type Decision = z.infer<typeof Decision>;
