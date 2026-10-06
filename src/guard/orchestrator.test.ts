import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { Journal, readJournal, verifyJournal } from "./journal.js";
import { InProcessQueue } from "./queue.js";
import { CONFIRM_MIN_CONFIDENCE, Orchestrator, classify, noisyOr, proposeActions, windowDeployContext, type DeployContextProvider } from "./orchestrator.js";
import type { Decision, Incident } from "./events.js";
import type { SiteConfig } from "./config.js";
import { INSIDE_WINDOW, OUTSIDE_WINDOW, ev, site, tmpDir } from "./testkit.js";

interface Rig {
  publish: (...events: unknown[]) => Promise<void>;
  decisions: Array<{ d: Decision; i: Incident }>;
  orch: Orchestrator;
  file: string;
  journal: Journal;
}

async function rig(sites: SiteConfig[], fn: (r: Rig) => Promise<void>, opts: { deploy?: DeployContextProvider; recentRestores?: () => Promise<number>; windowMs?: number } = {}) {
  const { dir, cleanup } = await tmpDir();
  const file = path.join(dir, "events.jsonl");
  const journal = await Journal.open(file);
  const queue = new InProcessQueue(journal);
  const decisions: Rig["decisions"] = [];
  const orch = new Orchestrator({
    queue, journal, sites: new Map(sites.map((s) => [s.id, s])),
    deploy: opts.deploy, recentRestores: opts.recentRestores, correlationWindowMs: opts.windowMs,
    onDecision: (d, i) => decisions.push({ d, i }),
  });
  orch.start();
  const publish = async (...events: unknown[]) => {
    for (const e of events) assert.equal((await queue.publish(e)).ok, true);
    await queue.drain();
  };
  try {
    await fn({ publish, decisions, orch, file, journal });
  } finally {
    orch.stop();
    await queue.close();
    await journal.close();
    await cleanup();
  }
}

const live = { responder: { enabled: true, mode: "live" } };
const at = (iso: string) => ({ timestamp: iso });
const last = (r: Rig) => r.decisions[r.decisions.length - 1];
const kindsOf = (d: Decision) => d.actions.map((a) => a.kind);

/* ------------------------------------------------------------ unit level */

test("noisyOr: independent kinds of evidence compound, repetition of one signal does not", () => {
  assert.equal(noisyOr([ev({ type: "page.dom_changed", confidence: 0.5 }), ev({ type: "page.dom_changed", confidence: 0.5 })]), 0.5);
  assert.equal(noisyOr([ev({ type: "page.dom_changed", confidence: 0.5 }), ev({ type: "integrity.file_changed", confidence: 0.5 })]), 0.75);
  const many = Array.from({ length: 50 }, () => ev({ type: "page.dom_changed", confidence: 0.5 }));
  assert.equal(noisyOr(many), 0.5, "a noisy watcher cannot manufacture certainty");
  assert.equal(noisyOr([ev({ confidence: 0 })]), 0);
  assert.equal(noisyOr([ev({ confidence: 1 })]), 1);
});

test("classify: corroboration, not volume, makes a defacement confirmed", () => {
  const s = site(live);
  const two = (a: number, b: number) => [ev({ type: "integrity.file_changed", confidence: a }), ev({ type: "page.dom_changed", confidence: b })];
  const conf = (evs: ReturnType<typeof two>) => noisyOr(evs);

  const weak = two(0.6, 0.6);
  assert.ok(conf(weak) < CONFIRM_MIN_CONFIDENCE);
  assert.equal(classify(s, weak, conf(weak), "no-match").classification, "suspicious");

  const strong = two(0.6, 0.63);
  assert.ok(conf(strong) >= CONFIRM_MIN_CONFIDENCE);
  assert.equal(classify(s, strong, conf(strong), "no-match").classification, "confirmed_defacement");

  const oneWorker = [ev({ type: "integrity.file_changed", confidence: 0.99 }), ev({ type: "integrity.file_added", confidence: 0.99 })];
  assert.equal(classify(s, oneWorker, noisyOr(oneWorker), "no-match").classification, "suspicious", "one worker is not corroboration");

  const loud = [ev({ type: "page.defacement_signal", confidence: 0.96, severity: "critical" })];
  assert.equal(classify(s, loud, 0.96, "no-match").classification, "confirmed_defacement", "an unmistakable signature stands alone");
  const lessLoud = [ev({ type: "page.defacement_signal", confidence: 0.9 })];
  assert.equal(classify(s, lessLoud, 0.9, "no-match").classification, "suspicious");
});

test("classify: a change a deploy could explain is not 'confirmed' while a deploy remains possible", () => {
  const s = site(live);
  const changeOnly = [ev({ type: "integrity.file_changed", confidence: 0.9 }), ev({ type: "page.dom_changed", confidence: 0.9 })];
  const c = noisyOr(changeOnly);
  assert.ok(c >= CONFIRM_MIN_CONFIDENCE, "two watchers agree strongly");
  assert.equal(classify(s, changeOnly, c, "unknown").classification, "suspicious", "agreement proves the change is real, not that it is hostile");
  assert.equal(classify(s, changeOnly, c, "no-match").classification, "confirmed_defacement", "once a deploy is ruled out, it is");

  const withHostileTraffic = [ev({ type: "integrity.file_changed", confidence: 0.9 }), ev({ type: "traffic.suspicious_upload_post", confidence: 0.8, indicators: { ips: ["203.0.113.9"] } })];
  assert.equal(classify(s, withHostileTraffic, noisyOr(withHostileTraffic), "unknown").classification, "confirmed_defacement", "a deploy does not explain hostile traffic, so it does not wait for one to be ruled out");
});

test("classify: only a positive deploy match can make an incident legitimate, and never for content signals", () => {
  const s = site();
  const edit = [ev({ type: "integrity.file_changed" }), ev({ type: "page.dom_changed" })];
  assert.equal(classify(s, edit, 0.9, "match").classification, "legitimate");
  assert.equal(classify(s, edit, 0.9, "unknown").classification, "suspicious");
  const defaced = [ev({ type: "integrity.file_changed" }), ev({ type: "page.defacement_signal", confidence: 0.99 })];
  assert.notEqual(classify(s, defaced, 0.99, "match").classification, "legitimate", "a deploy never legitimately says 'hacked by'");
  const upload = [ev({ type: "integrity.executable_in_uploads" })];
  assert.notEqual(classify(s, upload, 0.9, "match").classification, "legitimate");
});

test("windowDeployContext: a window is never proof, so it never says 'match'", async () => {
  const s = site();
  const out = [ev(at(OUTSIDE_WINDOW))];
  const inn = [ev(at(INSIDE_WINDOW))];
  assert.equal(await windowDeployContext(s, out), "no-match");
  assert.equal(await windowDeployContext(s, inn), "unknown");
  assert.equal(await windowDeployContext(s, [...out, ...inn]), "unknown", "any event inside a window keeps a deploy possible");
  assert.equal(await windowDeployContext(site({ deployWindows: [] }), out), "unknown", "with no windows configured we cannot rule a deploy out");
});

test("proposeActions maps signals to remediations, bounded", () => {
  const evs = [
    ev({ type: "integrity.file_changed", indicators: { paths: ["index.php", "wp-config.php"] } }),
    ev({ type: "integrity.executable_in_uploads", indicators: { paths: ["uploads/shell.php"] } }),
    ev({ type: "traffic.suspicious_upload_post", indicators: { ips: ["203.0.113.9", "198.51.100.1"] } }),
  ];
  const p = proposeActions(evs, true);
  assert.deepEqual(p.find((a) => a.kind === "restore_files")?.params, { paths: ["index.php", "wp-config.php"] });
  assert.deepEqual(p.find((a) => a.kind === "quarantine_file")?.params, { paths: ["uploads/shell.php"] });
  assert.equal(p.filter((a) => a.kind === "block_ip").length, 2);
  assert.ok(!p.some((a) => a.kind === "swap_maintenance_page"), "files can be restored, so no need to contain with a maintenance page");

  const pageOnly = proposeActions([ev({ type: "page.defacement_signal", indicators: {} })], true);
  assert.deepEqual(pageOnly.map((a) => a.kind), ["swap_maintenance_page"]);
  assert.deepEqual(proposeActions([ev({ type: "page.dom_changed", indicators: {} })], false), [], "an unconfirmed page change proposes nothing");
});

/* --------------------------------------------- the whole chain, for real */

test("full chain: dropped webshell + hostile POST + changed homepage + 'hacked by' become ONE confirmed incident", async () => {
  await rig([site(live)], async (r) => {
    await r.publish(
      ev({ type: "integrity.executable_in_uploads", severity: "critical", confidence: 0.9, indicators: { paths: ["wp-content/uploads/x.php"] }, summary: "x.php in uploads" }),
      ev({ type: "traffic.suspicious_upload_post", severity: "high", confidence: 0.8, indicators: { ips: ["203.0.113.9"] }, summary: "POST to upload endpoint", ...at("2026-10-06T13:58:00.000Z") }),
      ev({ type: "integrity.file_changed", severity: "high", confidence: 0.9, indicators: { paths: ["index.php"] }, ...at("2026-10-06T14:01:00.000Z") }),
      ev({ type: "page.defacement_signal", severity: "critical", confidence: 0.97, summary: "page says hacked by", ...at("2026-10-06T14:03:00.000Z") }),
    );
    const incs = r.orch.incidents();
    assert.equal(incs.length, 1, "one incident, not four");
    const inc = incs[0];
    assert.deepEqual([...inc.workers].sort(), ["integrity", "page", "traffic"]);
    assert.equal(inc.classification, "confirmed_defacement");
    assert.equal(inc.severity, "critical");
    assert.ok(inc.confidence > 0.99);
    assert.deepEqual(inc.indicators.ips, ["203.0.113.9"]);
    assert.ok(inc.indicators.paths.includes("index.php") && inc.indicators.paths.includes("wp-content/uploads/x.php"));
    assert.ok(inc.tags.owasp.includes("A01") && inc.tags.owasp.includes("A08"));
    assert.ok(inc.tags.attack.includes("T1491.002") && inc.tags.attack.includes("T1505.003"));

    const d = last(r).d;
    assert.equal(d.mode, "auto");
    const restore = d.actions.find((a) => a.kind === "restore_files")!;
    const quarantine = d.actions.find((a) => a.kind === "quarantine_file")!;
    assert.equal(restore.requiresApproval, false);
    assert.equal(quarantine.requiresApproval, false);
    assert.deepEqual(restore.params, { paths: ["index.php"] });
    assert.ok(!kindsOf(d).includes("block_ip"), "no firewall adapter exists yet");
    assert.ok(d.reasons.some((x) => /block_ip skipped/.test(x)));
    assert.ok(r.decisions.length <= 4);

    const v = await verifyJournal(r.file);
    assert.equal(v.ok, true, "the audit trail verifies");
    const jk = (await readJournal(r.file)).map((e) => e.kind);
    assert.equal(jk.filter((k) => k === "event").length, 4);
    assert.ok(jk.includes("incident") && jk.includes("decision"));
  });
});

test("the same attack on a dry-run site is recorded in full but marked dry-run", async () => {
  await rig([site({ responder: { enabled: true, mode: "dry-run" } })], async (r) => {
    await r.publish(
      ev({ type: "integrity.file_changed", confidence: 0.9, indicators: { paths: ["index.php"] } }),
      ev({ type: "page.defacement_signal", confidence: 0.97, severity: "critical" }),
    );
    const d = last(r).d;
    assert.ok(d.actions.length >= 3);
    assert.ok(d.actions.every((a) => a.mode === "dry-run"));
  });
});

test("the same attack on a site that never enabled the responder needs approval for everything destructive", async () => {
  await rig([site()], async (r) => {
    await r.publish(ev({ type: "integrity.file_changed", confidence: 0.9 }), ev({ type: "page.defacement_signal", confidence: 0.97, severity: "critical" }));
    const d = last(r).d;
    assert.equal(d.mode, "needs_approval");
    assert.ok(d.actions.filter((a) => a.destructive).every((a) => a.requiresApproval));
  });
});

/* ------------------------------------------------------ false positives */

test("FALSE POSITIVE: a legitimate deploy inside the window triggers no restore and no approval request", async () => {
  await rig([site(live)], async (r) => {
    await r.publish(
      ev({ type: "integrity.file_changed", confidence: 0.9, indicators: { paths: ["wp-content/themes/acme/style.css"] }, ...at(INSIDE_WINDOW) }),
      ev({ type: "integrity.file_changed", confidence: 0.9, indicators: { paths: ["index.php"] }, ...at(INSIDE_WINDOW) }),
      ev({ type: "page.dom_changed", confidence: 0.8, indicators: {}, ...at(INSIDE_WINDOW) }),
    );
    const { d, i } = last(r);
    assert.equal(i.windowExplained, true);
    assert.equal(i.classification, "suspicious", "never silently 'legitimate' on a window alone");
    assert.equal(d.mode, "notify_only", "the owner is still told");
    assert.ok(!d.actions.some((a) => a.destructive), "but nothing is restored, quarantined or proposed");
  });
});

test("FALSE POSITIVE: a normal CMS content edit (one weak page change, outside any window) restores nothing", async () => {
  await rig([site(live)], async (r) => {
    await r.publish(ev({ type: "page.dom_changed", severity: "low", confidence: 0.4, indicators: {}, summary: "homepage text changed", ...at(OUTSIDE_WINDOW) }));
    const { d, i } = last(r);
    assert.equal(i.classification, "suspicious");
    assert.equal(i.confidence, 0.4);
    assert.equal(d.mode, "notify_only");
    assert.ok(!d.actions.some((a) => a.destructive), "no restore, no maintenance page");
  });
});

test("a deploy window cannot launder a real defacement: 'hacked by' inside the window still needs a person", async () => {
  await rig([site(live)], async (r) => {
    await r.publish(
      ev({ type: "integrity.file_changed", confidence: 0.9, ...at(INSIDE_WINDOW) }),
      ev({ type: "page.defacement_signal", confidence: 0.97, severity: "critical", indicators: {}, ...at(INSIDE_WINDOW) }),
    );
    const { d, i } = last(r);
    assert.equal(i.windowExplained, false, "a content signal is not deploy-explainable");
    assert.equal(i.classification, "confirmed_defacement");
    assert.equal(d.mode, "needs_approval", "inside a window a deploy cannot be ruled out, so no automation");
    assert.ok(act(d, "restore_files")!.reasons.some((x) => /cannot be ruled out/.test(x)));
  });
});

const act = (d: Decision, kind: string) => d.actions.find((a) => a.kind === kind);

/* ---------------------------------------------------------- correlation */

test("correlation: same site, separate windows, separate sites, unknown sites", async () => {
  const other = site({ id: "other-site", transport: { type: "none" } });
  await rig([site(live), other], async (r) => {
    await r.publish(
      ev({ type: "page.dom_changed", confidence: 0.4, ...at("2026-10-06T14:00:00.000Z") }),
      ev({ type: "page.dom_changed", confidence: 0.4, ...at("2026-10-06T14:10:00.000Z") }),
      ev({ type: "page.dom_changed", confidence: 0.4, ...at("2026-10-06T15:00:00.000Z") }),
      ev({ type: "page.dom_changed", confidence: 0.4, siteId: "other-site", ...at("2026-10-06T14:05:00.000Z") }),
      ev({ type: "page.dom_changed", confidence: 0.4, siteId: "not-registered", ...at("2026-10-06T14:05:00.000Z") }),
    );
    assert.equal(r.orch.incidents("acme-clinic").length, 2, "10 minutes apart joins, an hour later does not");
    assert.equal(r.orch.incidents("other-site").length, 1, "sites never share an incident");
    assert.equal(r.orch.incidents("not-registered").length, 0);
    assert.ok((await readJournal(r.file)).some((e) => e.kind === "event_unknown_site"), "an event for an unregistered site is journaled, not silently dropped");
  });
});

test("one incident's decision is journaled only when it changes", async () => {
  await rig([site(live)], async (r) => {
    for (let n = 0; n < 5; n++) await r.publish(ev({ type: "page.dom_changed", confidence: 0.4, indicators: {}, ...at(OUTSIDE_WINDOW) }));
    const dec = (await readJournal(r.file)).filter((e) => e.kind === "decision");
    assert.equal(dec.length, 1, "five identical signals, one decision");
    assert.equal((await readJournal(r.file)).filter((e) => e.kind === "incident").length, 5, "but every update to the incident is recorded");
    await r.publish(ev({ type: "page.defacement_signal", confidence: 0.97, severity: "critical", indicators: {}, ...at(OUTSIDE_WINDOW) }));
    assert.equal((await readJournal(r.file)).filter((e) => e.kind === "decision").length, 2);
  });
});

test("severity is the maximum and indicators are merged without duplicates", async () => {
  await rig([site()], async (r) => {
    await r.publish(
      ev({ type: "traffic.path_probe", severity: "low", confidence: 0.3, indicators: { ips: ["203.0.113.9"] } }),
      ev({ type: "traffic.bruteforce", severity: "high", confidence: 0.6, indicators: { ips: ["203.0.113.9", "198.51.100.2"] } }),
    );
    const inc = r.orch.incidents()[0];
    assert.equal(inc.severity, "high");
    assert.deepEqual(inc.indicators.ips, ["203.0.113.9", "198.51.100.2"]);
    assert.deepEqual(inc.tags.attack, ["T1595.003", "T1110"]);
  });
});

test("the loop breaker input reaches the policy", async () => {
  await rig([site(live)], async (r) => {
    await r.publish(ev({ type: "integrity.file_changed", confidence: 0.9, indicators: { paths: ["index.php"] } }), ev({ type: "page.defacement_signal", confidence: 0.97, severity: "critical", indicators: {} }));
    const d = last(r).d;
    assert.equal(act(d, "restore_files")!.requiresApproval, true);
    assert.ok(act(d, "restore_files")!.reasons.some((x) => /loop breaker/.test(x)));
  }, { recentRestores: async () => 2 });
});

test("an injected deploy-context provider is used (the seam the git adapter will plug into)", async () => {
  await rig([site({ ...live, deployWindows: [] })], async (r) => {
    await r.publish(ev({ type: "integrity.file_changed", confidence: 0.9 }), ev({ type: "page.dom_changed", confidence: 0.9, indicators: {} }));
    assert.equal(last(r).i.classification, "legitimate");
    assert.equal(last(r).d.mode, "none");
  }, { deploy: async () => "match" });
});

test("orchestrator performs no action itself: it only emits decisions", async () => {
  await rig([site(live)], async (r) => {
    await r.publish(ev({ type: "integrity.file_changed", confidence: 0.9 }), ev({ type: "page.defacement_signal", confidence: 0.97, severity: "critical", indicators: {} }));
    const kinds = new Set((await readJournal(r.file)).map((e) => e.kind));
    for (const k of kinds) assert.ok(["event", "incident", "decision"].includes(k), `unexpected journal kind: ${k}`);
  });
});

test("a removed file is restorable, a dropped file is quarantined, and neither is confused with the other", () => {
  const removed = ev({ type: "integrity.file_removed", indicators: { paths: ["index.php"] } });
  const added = ev({ type: "integrity.file_added", indicators: { paths: ["x.php"] } });
  const out = proposeActions([removed, added], false);
  assert.deepEqual(out.find((a) => a.kind === "restore_files")?.params, { paths: ["index.php"] });
  assert.deepEqual(out.find((a) => a.kind === "quarantine_file")?.params, { paths: ["x.php"] });
});
