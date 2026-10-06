/**
 * The orchestrator. Subscribes to every worker's events, folds them into one
 * incident per site per time window, classifies it, asks the policy what may
 * happen, and records all of it. It performs NO action itself, and Phase 1 has
 * no LLM in it at all: classification here is deterministic and explainable.
 *
 * Correlation is by site and time. Events for one site within the window join
 * one incident, because on a small site the signals worth joining (a dropped
 * file, a suspicious POST, a changed homepage) do not share an indicator: the
 * page watcher sees no IP. Merged indicators are kept for the responder. The
 * cost is that unrelated minor events can share an incident, which is why a
 * deploy window can only ever explain an incident whose EVERY event is
 * deploy-explainable.
 *
 * Confidence is a noisy-OR over distinct (worker, type) pairs. Independent
 * kinds of evidence compound; the same signal repeated 50 times does not, or a
 * noisy watcher could manufacture certainty on its own.
 */

import {
  Incident, SCHEMA_VERSION, maxSeverity,
  type Classification, type Decision, type Indicators, type SecurityEvent,
} from "./events.js";
import { randomUUID } from "node:crypto";
import { canonicalize, sha256Hex } from "./canonical.js";
import { DETECTION_TYPES, mergeTags } from "./standards.js";
import type { SiteConfig } from "./config.js";
import { isInDeployWindow } from "./deploy-window.js";
import { decide, type DeployMatch, type ProposedAction } from "./policy.js";
import type { EventQueue } from "./queue.js";
import type { Journal } from "./journal.js";

/** Tuning constants. Exported so tests and docs cite the same numbers. */
export const CORRELATION_WINDOW_MS = 15 * 60_000;
export const CONFIRM_MIN_CONFIDENCE = 0.85;
export const CONFIRM_SINGLE_SIGNAL_MIN = 0.95;
const MAX_INCIDENTS_PER_SITE = 200;
const MAX_PROPOSED = 10;

export type DeployContextProvider = (site: SiteConfig, events: SecurityEvent[]) => Promise<DeployMatch>;

/**
 * Default, with no git history to consult. A deploy window says when deploys
 * normally happen, never that THIS change was one, so it can never return
 * "match". It can say "no-match": a change entirely outside every window has no
 * known deploy to explain it. Inside a window, or with no windows configured,
 * the honest answer is "unknown" and a person decides.
 */
export const windowDeployContext: DeployContextProvider = async (site, events) => {
  if (!site.deployWindows.length) return "unknown";
  const anyInside = events.some((e) => isInDeployWindow(site.deployWindows, new Date(e.timestamp), site.timezone));
  return anyInside ? "unknown" : "no-match";
};

export interface OrchestratorOptions {
  queue: EventQueue;
  journal: Journal;
  sites: Map<string, SiteConfig>;
  deploy?: DeployContextProvider;
  /** Restores executed for a site inside the loop-breaker window. Zero until a responder exists. */
  recentRestores?: (siteId: string, windowMinutes: number) => Promise<number>;
  correlationWindowMs?: number;
  onDecision?: (decision: Decision, incident: Incident) => void;
}

interface Tracked {
  id: string;
  openedAt: string;
  updatedAt: string;
  events: SecurityEvent[];
  lastFingerprint?: string;
}

export function noisyOr(events: SecurityEvent[]): number {
  const best = new Map<string, number>();
  for (const e of events) {
    const k = `${e.worker}/${e.type}`;
    best.set(k, Math.max(best.get(k) ?? 0, e.confidence));
  }
  const miss = [...best.values()].reduce((p, c) => p * (1 - c), 1);
  return Math.min(1, Math.max(0, 1 - miss));
}

function mergeIndicators(events: SecurityEvent[]): Indicators {
  const uniq = (xs: string[]) => [...new Set(xs)].slice(0, 50);
  return {
    ips: uniq(events.flatMap((e) => e.indicators.ips)),
    paths: uniq(events.flatMap((e) => e.indicators.paths)),
    fileHashes: uniq(events.flatMap((e) => e.indicators.fileHashes)),
  };
}

export interface Classified {
  classification: Classification;
  windowExplained: boolean;
}

export function classify(
  site: SiteConfig,
  events: SecurityEvent[],
  confidence: number,
  deploy: DeployMatch,
): Classified {
  const explainable = events.every((e) => DETECTION_TYPES[e.type].deployExplainable);
  const allInWindow =
    site.deployWindows.length > 0 &&
    events.every((e) => isInDeployWindow(site.deployWindows, new Date(e.timestamp), site.timezone));
  const windowExplained = explainable && allInWindow;

  if (deploy === "match" && explainable) return { classification: "legitimate", windowExplained };
  if (windowExplained) return { classification: "suspicious", windowExplained };

  const workers = new Set(events.map((e) => e.worker));
  const corroborated = workers.size >= 2 && confidence >= CONFIRM_MIN_CONFIDENCE;
  const loudSignal = events.some((e) => e.type === "page.defacement_signal" && e.confidence >= CONFIRM_SINGLE_SIGNAL_MIN);

  // A set of events that an ordinary deploy could fully produce (a changed file and a
  // changed page) is not a confirmed defacement while a deploy remains possible, however
  // many watchers agree. Corroboration proves the change is real, not that it is hostile.
  // Anything content-bearing (a signature, a dropped executable, hostile traffic) is
  // already beyond what a deploy explains, so it does not wait for deploy to be ruled out.
  const deployStillPossible = explainable && deploy !== "no-match";

  if ((corroborated || loudSignal) && !deployStillPossible) {
    return { classification: "confirmed_defacement", windowExplained };
  }
  return { classification: "suspicious", windowExplained };
}

/** What a human or the responder could do about this incident. The policy decides what is actually allowed. */
export function proposeActions(events: SecurityEvent[], confirmed: boolean): ProposedAction[] {
  const out: ProposedAction[] = [];
  const pathsOf = (types: string[]) => [...new Set(events.filter((e) => types.includes(e.type)).flatMap((e) => e.indicators.paths))].slice(0, 50);

  const changed = pathsOf(["integrity.file_changed"]);
  if (changed.length) out.push({ kind: "restore_files", params: { paths: changed }, reason: "watched files differ from the known-good baseline" });

  const dropped = pathsOf(["integrity.file_added", "integrity.executable_in_uploads"]);
  if (dropped.length) out.push({ kind: "quarantine_file", params: { paths: dropped }, reason: "new or executable files appeared where none belong" });

  if (confirmed && !changed.length) {
    out.push({ kind: "swap_maintenance_page", params: {}, reason: "page content is defaced but no restorable file was identified, so contain it" });
  }

  const hostile = new Set(["traffic.bruteforce", "traffic.path_probe", "traffic.suspicious_upload_post", "traffic.admin_login_unusual"]);
  const ips = [...new Set(events.filter((e) => hostile.has(e.type)).flatMap((e) => e.indicators.ips))].slice(0, 5);
  for (const ip of ips) out.push({ kind: "block_ip", params: { ip }, reason: `${ip} is the source of hostile traffic` });

  return out.slice(0, MAX_PROPOSED);
}

export class Orchestrator {
  private tracked = new Map<string, Tracked[]>(); // siteId -> incidents, oldest first
  private unsubscribe?: () => void;
  private readonly windowMs: number;

  constructor(private readonly o: OrchestratorOptions) {
    this.windowMs = o.correlationWindowMs ?? CORRELATION_WINDOW_MS;
  }

  start(): void {
    this.unsubscribe = this.o.queue.subscribe((e) => this.onEvent(e));
  }

  stop(): void {
    this.unsubscribe?.();
  }

  /** Current snapshot of every tracked incident, for tests and the CLI. */
  incidents(siteId?: string): Incident[] {
    const all = siteId ? (this.tracked.get(siteId) ?? []) : [...this.tracked.values()].flat();
    return all.map((t) => this.snapshot(t, this.o.sites.get(t.events[0].siteId)!, "unknown").incident);
  }

  private async onEvent(event: SecurityEvent): Promise<void> {
    const site = this.o.sites.get(event.siteId);
    if (!site) {
      await this.o.journal.append("event_unknown_site", { eventId: event.id, siteId: event.siteId });
      return;
    }

    const list = this.tracked.get(site.id) ?? [];
    const at = Date.parse(event.timestamp);
    let t = list.find((x) => Math.abs(at - Date.parse(x.updatedAt)) <= this.windowMs);
    if (!t) {
      t = { id: randomUUID(), openedAt: event.timestamp, updatedAt: event.timestamp, events: [] };
      list.push(t);
      if (list.length > MAX_INCIDENTS_PER_SITE) list.shift();
      this.tracked.set(site.id, list);
    }
    t.events.push(event);
    if (Date.parse(event.timestamp) > Date.parse(t.updatedAt)) t.updatedAt = event.timestamp;

    const deploy = await (this.o.deploy ?? windowDeployContext)(site, t.events);
    const { incident, proposed } = this.snapshot(t, site, deploy);
    await this.o.journal.append("incident", incident);

    const recent = await (this.o.recentRestores?.(site.id, site.responder.restoreWindowMinutes) ?? Promise.resolve(0));
    const decision = decide({ incident, site, deploy, recentRestores: recent, proposed });

    // Journal a decision only when it changed, so one noisy incident does not flood the trail.
    const fp = sha256Hex(canonicalize({ mode: decision.mode, actions: decision.actions.map((a) => [a.digest, a.requiresApproval]) }));
    if (fp !== t.lastFingerprint) {
      t.lastFingerprint = fp;
      await this.o.journal.append("decision", decision);
      this.o.onDecision?.(decision, incident);
    }
  }

  private snapshot(t: Tracked, site: SiteConfig, deploy: DeployMatch): { incident: Incident; proposed: ProposedAction[] } {
    const confidence = noisyOr(t.events);
    const { classification, windowExplained } = classify(site, t.events, confidence, deploy);
    const first = t.events[0];
    const workers = [...new Set(t.events.map((e) => e.worker))];
    const incident = Incident.parse({
      v: SCHEMA_VERSION,
      id: t.id,
      siteId: site.id,
      openedAt: t.openedAt,
      updatedAt: t.updatedAt,
      eventIds: t.events.map((e) => e.id).slice(-1000),
      workers,
      severity: maxSeverity(t.events.map((e) => e.severity)),
      confidence,
      classification,
      windowExplained,
      summary: `${t.events.length} signal(s) from ${workers.join(", ")}: ${first.summary}`.slice(0, 500),
      indicators: mergeIndicators(t.events),
      tags: mergeTags(t.events.map((e) => e.tags)),
    });
    return { incident, proposed: proposeActions(t.events, classification === "confirmed_defacement") };
  }
}
