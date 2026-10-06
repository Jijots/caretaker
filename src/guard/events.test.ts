import test from "node:test";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import {
  Action, SecurityEvent, actionDigest, createEvent, isDestructive, makeAction, maxSeverity,
} from "./events.js";
import { canonicalize } from "./canonical.js";
import { ev } from "./testkit.js";

const valid = () => JSON.parse(JSON.stringify(ev()));

test("createEvent derives worker and tags from the type table", () => {
  const e = createEvent({ siteId: "acme-clinic", type: "traffic.bruteforce", severity: "medium", confidence: 0.7, summary: "50 failed logins", indicators: { ips: ["203.0.113.9"] } });
  assert.equal(e.worker, "traffic");
  assert.deepEqual(e.tags.owasp, ["A07"]);
  assert.deepEqual(e.tags.attack, ["T1110"]);
  assert.equal(e.v, 1);
});

test("a valid event round-trips through the schema untouched", () => {
  const e = valid();
  assert.deepEqual(SecurityEvent.parse(e), e);
});

const rejects: Array<[string, (e: any) => void, RegExp]> = [
  ["unknown top-level key", (e) => { e.extra = 1; }, /Unrecognized key/],
  ["bad severity", (e) => { e.severity = "catastrophic"; }, /severity/],
  ["confidence above 1", (e) => { e.confidence = 1.2; }, /confidence/],
  ["confidence below 0", (e) => { e.confidence = -0.1; }, /confidence/],
  ["bad site id", (e) => { e.siteId = "Acme Clinic!"; }, /siteId/],
  ["bad timestamp", (e) => { e.timestamp = "yesterday"; }, /timestamp/],
  ["wrong schema version", (e) => { e.v = 2; }, /v/],
  ["not a uuid", (e) => { e.id = "123"; }, /id/],
  ["not an IP address", (e) => { e.indicators.ips = ["999.1.1.1"]; }, /not an IP address/],
  ["overlong summary", (e) => { e.summary = "x".repeat(301); }, /summary/],
  ["overlong evidence value", (e) => { e.evidence = { page: "x".repeat(2001) }; }, /evidence/],
  ["too many evidence keys", (e) => { e.evidence = Object.fromEntries(Array.from({ length: 51 }, (_, i) => [`k${i}`, "v"])); }, /at most 50 keys/],
  ["unknown OWASP id", (e) => { e.tags.owasp = ["A11"]; }, /owasp/],
  ["unknown ATT&CK id", (e) => { e.tags.attack = ["T9999"]; }, /attack/],
  ["empty tag list", (e) => { e.tags.nist = []; }, /nist/],
  ["bad CVE id", (e) => { e.tags.cve = ["CVE-24-1"]; }, /not a CVE id/],
  ["CVSS out of range", (e) => { e.tags.cvss = { version: "3.1", score: 11 }; }, /cvss/],
  ["CVSS unknown version", (e) => { e.tags.cvss = { version: "2.0", score: 5 }; }, /cvss/],
  ["worker may not emit that type", (e) => { e.worker = "traffic"; }, /may not emit/],
  ["file hash that is not sha-256", (e) => { e.indicators.fileHashes = ["abc"]; }, /fileHashes/],
];
for (const [name, mutate, pattern] of rejects) {
  test(`schema rejects: ${name}`, () => {
    const e = valid();
    mutate(e);
    const r = SecurityEvent.safeParse(e);
    assert.equal(r.success, false);
    assert.match(JSON.stringify(r.error?.issues), pattern);
  });
}

test("maxSeverity picks the highest", () => {
  assert.equal(maxSeverity(["low", "critical", "medium"]), "critical");
  assert.equal(maxSeverity(["low"]), "low");
});

test("canonicalize ignores key order and drops undefined, so digests are stable", () => {
  assert.equal(canonicalize({ b: 2, a: { d: 1, c: [1, { z: 1, y: undefined }] } }), canonicalize({ a: { c: [1, { z: 1 }], d: 1 }, b: 2 }));
  assert.throws(() => canonicalize({ n: NaN }), /non-finite/);
});

test("destructive kinds are exactly the ones that change a site or its perimeter", () => {
  for (const k of ["restore_files", "swap_maintenance_page", "quarantine_file", "block_ip"] as const) assert.equal(isDestructive(k), true, k);
  for (const k of ["preserve_evidence", "notify_owner"] as const) assert.equal(isDestructive(k), false, k);
});

const base = { incidentId: randomUUID(), siteId: "acme-clinic", kind: "restore_files" as const, mode: "live" as const };

test("an approval digest is bound to kind, params, site, incident and mode", () => {
  const d = (over: Record<string, unknown> = {}) => actionDigest({ ...base, params: { paths: ["index.php"] }, ...over } as any);
  const ref = d();
  assert.equal(d(), ref);
  assert.equal(actionDigest({ ...base, params: { paths: ["index.php"] } }), ref);
  assert.notEqual(d({ mode: "dry-run" }), ref, "a dry-run approval must not authorise a live run");
  assert.notEqual(d({ incidentId: randomUUID() }), ref, "an approval must not replay against another incident");
  assert.notEqual(d({ siteId: "other-site" }), ref);
  assert.notEqual(d({ kind: "quarantine_file" }), ref);
  assert.notEqual(d({ params: { paths: ["wp-config.php"] } }), ref, "changing the target changes the digest");
});

test("flipping requiresApproval does not change the digest, so an issued approval stays valid for the same action", () => {
  const a = makeAction({ ...base, params: { paths: ["index.php"] }, requiresApproval: true });
  const b = makeAction({ ...base, params: { paths: ["index.php"] }, requiresApproval: false });
  assert.equal(a.digest, b.digest);
});

test("an action with a tampered digest or destructive flag is rejected", () => {
  const a = makeAction({ ...base, params: { paths: ["index.php"] }, requiresApproval: true });
  assert.equal(Action.safeParse({ ...a, params: { paths: ["wp-config.php"] } }).success, false, "params changed under the same digest");
  assert.equal(Action.safeParse({ ...a, destructive: false }).success, false, "destructive flag disagrees with the kind");
  assert.equal(Action.safeParse({ ...a, digest: "0".repeat(64) }).success, false);
  assert.equal(Action.safeParse(a).success, true);
});
