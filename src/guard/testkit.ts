/** Shared fixtures for the guard tests. Not imported by any production code. */

import { mkdtemp, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { SiteConfig } from "./config.js";
import { Incident, SCHEMA_VERSION, createEvent, type NewEventInput, type SecurityEvent } from "./events.js";
import { tagsFor } from "./standards.js";
import { randomUUID } from "node:crypto";

export async function tmpDir(): Promise<{ dir: string; cleanup: () => Promise<void> }> {
  const dir = await mkdtemp(path.join(os.tmpdir(), "guard-test-"));
  return { dir, cleanup: () => rm(dir, { recursive: true, force: true }) };
}

/** A valid site, with deploy windows Mon-Fri 09:00-17:00 Asia/Manila. Override any field. */
export function site(over: Record<string, unknown> = {}): SiteConfig {
  return SiteConfig.parse({
    id: "acme-clinic",
    name: "Acme Clinic",
    baseUrl: "https://acme.example",
    platform: "wordpress",
    transport: { type: "local-fs", root: path.resolve("/srv/sites/acme") },
    deployWindows: [{ days: ["mon", "tue", "wed", "thu", "fri"], start: "09:00", end: "17:00" }],
    ...over,
  });
}

/** 2026-10-06 is a Tuesday. Manila is UTC+8, so 03:00Z is 11:00 (inside the window) and 14:00Z is 22:00 (outside). */
export const INSIDE_WINDOW = "2026-10-06T03:00:00.000Z";
export const OUTSIDE_WINDOW = "2026-10-06T14:00:00.000Z";

export function ev(over: Partial<NewEventInput> = {}): SecurityEvent {
  return createEvent({
    siteId: "acme-clinic",
    type: "integrity.file_changed",
    severity: "high",
    confidence: 0.8,
    summary: "index.php changed",
    indicators: { paths: ["index.php"] },
    timestamp: OUTSIDE_WINDOW,
    ...over,
  });
}

export function incident(over: Record<string, unknown> = {}): Incident {
  const now = OUTSIDE_WINDOW;
  return Incident.parse({
    v: SCHEMA_VERSION,
    id: randomUUID(),
    siteId: "acme-clinic",
    openedAt: now,
    updatedAt: now,
    eventIds: [randomUUID()],
    workers: ["integrity", "page"],
    severity: "high",
    confidence: 0.95,
    classification: "confirmed_defacement",
    windowExplained: false,
    summary: "test incident",
    indicators: { ips: [], paths: [], fileHashes: [] },
    tags: tagsFor("integrity.file_changed"),
    ...over,
  });
}
