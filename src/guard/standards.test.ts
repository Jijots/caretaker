import test from "node:test";
import assert from "node:assert/strict";
import {
  ATTACK, DETECTION_TYPES, NIST_CSF_FUNCTIONS, OWASP_2025, STANDARDS_PROVENANCE,
  formatTags, mergeTags, tagsFor, type DetectionType,
} from "./standards.js";

test("OWASP 2025 table matches the official list, including the spelling of A09", () => {
  assert.equal(Object.keys(OWASP_2025).length, 10);
  assert.equal(OWASP_2025.A01, "Broken Access Control");
  assert.equal(OWASP_2025.A03, "Software Supply Chain Failures");
  assert.equal(OWASP_2025.A08, "Software or Data Integrity Failures");
  assert.equal(OWASP_2025.A09, "Security Logging and Alerting Failures"); // 'and', not '&'
  assert.equal(OWASP_2025.A10, "Mishandling of Exceptional Conditions");
});

test("NIST CSF 2.0 has six functions, including Govern", () => {
  assert.deepEqual([...NIST_CSF_FUNCTIONS], ["govern", "identify", "protect", "detect", "respond", "recover"]);
});

test("ATT&CK table carries the ids the detections rely on, with official names", () => {
  assert.equal(ATTACK["T1491.002"].name, "External Defacement");
  assert.equal(ATTACK["T1505.003"].name, "Server Software Component: Web Shell");
  assert.equal(ATTACK["T1190"].name, "Exploit Public-Facing Application");
});

test("provenance records when and where the standards were checked", () => {
  assert.match(STANDARDS_PROVENANCE.checkedOn, /^\d{4}-\d{2}-\d{2}$/);
  assert.match(STANDARDS_PROVENANCE.owasp.source, /^https:\/\/top10\.owasp\.org\/2025/);
  assert.match(STANDARDS_PROVENANCE.nist.note, /second-hand/);
});

test("every detection type references only ids that exist in the standards tables", () => {
  for (const [type, spec] of Object.entries(DETECTION_TYPES)) {
    for (const id of spec.owasp) assert.ok(id in OWASP_2025, `${type}: unknown OWASP id ${id}`);
    for (const id of spec.attack) assert.ok(id in ATTACK, `${type}: unknown ATT&CK id ${id}`);
    for (const f of spec.nist) assert.ok((NIST_CSF_FUNCTIONS as readonly string[]).includes(f), `${type}: unknown NIST function ${f}`);
    assert.ok(spec.attack.length > 0 && spec.nist.length > 0, `${type}: needs ATT&CK and NIST tags`);
    if (!("requiresOwaspOverride" in spec)) assert.ok(spec.owasp.length > 0, `${type}: needs an OWASP default`);
    assert.ok(type.startsWith(spec.worker + "."), `${type}: id should be prefixed by its worker '${spec.worker}'`);
  }
});

test("content signals are never deploy-explainable, so a deploy window cannot launder them", () => {
  for (const t of ["page.defacement_signal", "integrity.executable_in_uploads", "page.external_script_added", "page.iframe_injected"] as DetectionType[]) {
    assert.equal(DETECTION_TYPES[t].deployExplainable, false, t);
  }
  for (const t of ["integrity.file_changed", "page.dom_changed", "page.visual_diff"] as DetectionType[]) {
    assert.equal(DETECTION_TYPES[t].deployExplainable, true, t);
  }
});

test("tagsFor returns copies, so callers cannot corrupt the table", () => {
  const a = tagsFor("integrity.file_changed");
  a.owasp.push("A10");
  a.attack.length = 0;
  const b = tagsFor("integrity.file_changed");
  assert.deepEqual(b.owasp, ["A08"]);
  assert.deepEqual(b.attack, ["T1491.002"]);
});

test("a scanner finding has no sane default OWASP category and must supply one", () => {
  assert.throws(() => tagsFor("scanner.vulnerability_found"), /requires the emitting worker to supply an OWASP category/);
  const t = tagsFor("scanner.vulnerability_found", { owasp: ["A05"], cve: ["CVE-2024-12345"], cvss: { version: "3.1", score: 9.8 } });
  assert.deepEqual(t.owasp, ["A05"]);
  assert.equal(t.cvss?.score, 9.8);
});

test("formatTags reads like the report format asks for", () => {
  const line = formatTags(tagsFor("integrity.executable_in_uploads"));
  assert.match(line, /OWASP: Broken Access Control/);
  assert.match(line, /ATT&CK: T1505\.003 Server Software Component: Web Shell, T1190 Exploit Public-Facing Application/);
  assert.match(line, /NIST: Detect$/);
  const withCve = formatTags(tagsFor("scanner.outdated_component", { cve: ["CVE-2025-1111"], cvss: { version: "4.0", score: 8.1 } }));
  assert.match(withCve, /CVE: CVE-2025-1111; CVSS 4\.0: 8\.1/);
});

test("mergeTags unions in first-seen order and keeps the highest CVSS", () => {
  const m = mergeTags([
    tagsFor("integrity.file_changed"),
    tagsFor("integrity.executable_in_uploads"),
    tagsFor("scanner.vulnerability_found", { owasp: ["A05"], cvss: { version: "3.1", score: 5.0 } }),
    tagsFor("scanner.outdated_component", { cvss: { version: "3.1", score: 9.1 }, cve: ["CVE-2024-1000"] }),
  ]);
  assert.deepEqual(m.owasp, ["A08", "A01", "A05", "A03"]);
  assert.deepEqual(m.attack, ["T1491.002", "T1505.003", "T1190"]);
  assert.equal(m.cvss?.score, 9.1);
  assert.deepEqual(m.cve, ["CVE-2024-1000"]);
});
