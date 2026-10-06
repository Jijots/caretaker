#!/usr/bin/env node
/**
 * Entrypoint for the guard module: `npm run caretaker -- <command>`.
 *
 * Deliberately separate from the static scanner's CLI (src/index.ts), which
 * stays read-only. Nothing here changes a monitored site, and the
 * responder, when it exists, will be its own command that must be started on
 * purpose.
 */

import path from "node:path";
import { Journal, JournalError, verifyJournal } from "./journal.js";
import { ConfigError, assertDataDirOffHost, loadSiteFile, loadSites, resolveGuardPaths } from "./config.js";
import { InProcessQueue } from "./queue.js";
import { Orchestrator } from "./orchestrator.js";
import { formatTags } from "./standards.js";
import { BaselineError, BaselineStore } from "./baseline.js";
import { IntegrityWatcher } from "./integrity.js";
import { LocalFsTransport } from "./transport-local.js";
import { TransportError } from "./transport.js";
import { prepareIntegrityWorkers } from "./runner.js";

const C = { bold: "\x1b[1m", grey: "\x1b[90m", reset: "\x1b[0m", red: "\x1b[31m", green: "\x1b[32m", yellow: "\x1b[33m" };

function opt(args: string[], name: string): string | undefined {
  const i = args.indexOf(`--${name}`);
  return i !== -1 && args[i + 1] && !args[i + 1].startsWith("--") ? args[i + 1] : undefined;
}
const has = (args: string[], name: string) => args.includes(`--${name}`);

function fail(lines: string | string[]): never {
  for (const l of Array.isArray(lines) ? lines : [lines]) console.error(`${C.red}${l}${C.reset}`);
  process.exit(1);
}

const HELP = `
${C.bold}Caretaker${C.reset}  defacement detection and response, as a module of security-pass

  npm run caretaker -- validate <file.site.json>     check one site config
  npm run caretaker -- validate --all                check every site in GUARD_SITES_DIR, and that the
                                                 data directory is not inside a monitored web root
  npm run caretaker -- journal verify [--file F] [--expected-head HASH]
                                                 verify the hash chain; --expected-head catches
                                                 entries deleted from the end
  npm run caretaker -- journal head [--file F]       print the current head, to store somewhere the
                                                 monitored host cannot reach
  npm run caretaker -- baseline snapshot <site-id>   record the site as it is NOW as the known-good state
  npm run caretaker -- baseline show <site-id>       what the baseline holds, and when it was taken
  npm run caretaker -- integrity check <site-id>     one comparison against the baseline, printed, nothing queued
  npm run caretaker -- run [--once]                  start the orchestrator and the Integrity watcher

Environment
  GUARD_DATA_DIR      journals and baselines. Default ./.guard-data. Keep it OFF the monitored host.
  GUARD_SITES_DIR     *.site.json files. Default ./guard-sites
  GUARD_JOURNAL_KEY   32+ characters. Turns the journal into an HMAC chain a forger cannot continue.

Nothing here changes a monitored site. Baselines and the journal are written to GUARD_DATA_DIR only.
`;

async function main() {
  const [cmd, ...rest] = process.argv.slice(2);

  if (!cmd || cmd === "help" || has(process.argv, "help")) {
    console.log(HELP);
    return;
  }

  let paths;
  try {
    paths = resolveGuardPaths();
  } catch (e) {
    if (e instanceof ConfigError) fail(e.problems);
    throw e;
  }
  const journalFile = path.join(paths.dataDir, "events.jsonl");

  if (cmd === "validate") {
    try {
      if (has(rest, "all")) {
        const sites = await loadSites(paths.sitesDir);
        assertDataDirOffHost(paths.dataDir, sites.values());
        console.log(`${C.green}ok${C.reset} ${sites.size} site(s) in ${paths.sitesDir}; data directory ${paths.dataDir} is outside every monitored root`);
        for (const s of sites.values()) console.log(`  ${s.id}  ${s.platform}  transport=${s.transport.type}  responder=${s.responder.enabled ? s.responder.mode : "off"}`);
      } else {
        const file = rest[0];
        if (!file) fail("usage: validate <file.site.json> | validate --all");
        const s = await loadSiteFile(file);
        console.log(`${C.green}ok${C.reset} ${s.id} (${s.name})`);
        console.log(`  platform=${s.platform} transport=${s.transport.type} timezone=${s.timezone}`);
        console.log(`  deploy windows: ${s.deployWindows.length}, whitelisted page regions: ${s.pageRegions.length}`);
        console.log(`  responder: ${s.responder.enabled ? s.responder.mode : "off"}`);
      }
    } catch (e) {
      if (e instanceof ConfigError) fail(e.problems);
      throw e;
    }
    return;
  }

  if (cmd === "journal") {
    const [sub, ...a] = rest;
    const file = opt(a, "file") ?? journalFile;
    if (sub === "verify") {
      const r = await verifyJournal(file, { key: paths.journalKey, expectedHead: opt(a, "expected-head") });
      if (!r.ok) fail([`journal does not verify: ${r.problem} at line ${r.line}`, r.detail, `(${r.entries} entries were intact before that point)`]);
      console.log(`${C.green}ok${C.reset} ${r.entries} entries, head ${r.head}${paths.journalKey ? " (HMAC keyed)" : " (unkeyed: set GUARD_JOURNAL_KEY to resist forgery)"}`);
      return;
    }
    if (sub === "head") {
      const r = await verifyJournal(file, { key: paths.journalKey });
      if (!r.ok) fail([`refusing to print a head for a journal that does not verify: ${r.problem} at line ${r.line}`, r.detail]);
      console.log(`${r.entries} ${r.head}`);
      return;
    }
    fail("usage: journal verify | journal head");
  }

  if (cmd === "baseline" || cmd === "integrity") {
    const [sub, siteId] = rest;
    if (!siteId || !((cmd === "baseline" && (sub === "snapshot" || sub === "show")) || (cmd === "integrity" && sub === "check"))) {
      fail("usage: baseline snapshot <site-id> | baseline show <site-id> | integrity check <site-id>");
    }
    try {
      const sites = await loadSites(paths.sitesDir);
      assertDataDirOffHost(paths.dataDir, sites.values());
      const site = sites.get(siteId);
      if (!site) fail(`no site '${siteId}' in ${paths.sitesDir}. Known: ${[...sites.keys()].join(", ") || "(none)"}`);
      if (site.transport.type !== "local-fs") fail(`site '${siteId}' uses transport '${site.transport.type}', which cannot be read. The Integrity watcher needs local-fs.`);
      const store = new BaselineStore(paths.dataDir, paths.journalKey);

      if (cmd === "baseline" && sub === "show") {
        const b = await store.load(siteId);
        if (!b) fail(`no baseline for '${siteId}'. Run: npm run caretaker -- baseline snapshot ${siteId}`);
        const files = Object.values(b.files);
        console.log(`${C.green}ok${C.reset} ${siteId}: ${files.length} files, ${files.filter((x) => x.stored).length} restorable, taken ${b.createdAt} (source: ${b.source})`);
        if (b.note) console.log(`  note: ${b.note}`);
        return;
      }

      const transport = await LocalFsTransport.open(site.transport.root);
      if (cmd === "baseline") {
        const r = await store.snapshot(site, transport, { note: opt(rest, "note") });
        console.log(`${C.green}ok${C.reset} baseline for ${siteId}: ${Object.keys(r.body.files).length} files (${r.stored} stored for restore, ${r.hashOnly} hash only)`);
        console.log(`  written to ${store.dir(siteId)}`);
        console.log(`${C.yellow}This records the site exactly as it is right now. If it is already defaced or backdoored, that is now "normal".${C.reset}`);
        console.log(`${C.yellow}Take it from a site you have just deployed or just verified, not one you are unsure about.${C.reset}`);
        if (!paths.journalKey) console.log(`${C.grey}(unkeyed: set GUARD_JOURNAL_KEY so the baseline cannot be forged by someone who can write the data directory)${C.reset}`);
        if (r.skippedUnreadable.length) console.log(`${C.yellow}${r.skippedUnreadable.length} path(s) could not be read and are NOT in the baseline, e.g. ${r.skippedUnreadable[0]}${C.reset}`);
        return;
      }

      const baseline = await store.load(siteId);
      if (!baseline) fail(`no baseline for '${siteId}'. Run: npm run caretaker -- baseline snapshot ${siteId}`);
      const pass = await new IntegrityWatcher({ site, transport, baseline: baseline! }).runOnce();
      console.log(`${siteId}: ${pass.filesChecked} files checked`);
      if (!pass.events.length) console.log(`${C.green}ok${C.reset} nothing differs from the baseline`);
      for (const e of pass.events) {
        console.log(`  ${e.severity.padEnd(8)} ${e.type}  ${e.summary}`);
      }
      if (pass.unreadable.length) console.log(`${C.yellow}${pass.unreadable.length} path(s) could not be read, e.g. ${pass.unreadable[0]}${C.reset}`);
      if (pass.events.length) process.exitCode = 2;
      return;
    } catch (e) {
      if (e instanceof ConfigError) fail(e.problems);
      if (e instanceof BaselineError || e instanceof TransportError) fail(e.message);
      throw e;
    }
  }

  if (cmd === "run") {
    let sites;
    try {
      sites = await loadSites(paths.sitesDir);
      assertDataDirOffHost(paths.dataDir, sites.values());
    } catch (e) {
      if (e instanceof ConfigError) fail(e.problems);
      throw e;
    }
    let journal: Journal;
    try {
      journal = await Journal.open(journalFile, { key: paths.journalKey });
    } catch (e) {
      if (e instanceof JournalError) fail(e.message);
      throw e;
    }

    const queue = new InProcessQueue(journal, (m) => console.error(`${C.yellow}${m}${C.reset}`));
    const orchestrator = new Orchestrator({
      queue, journal, sites,
      onDecision: (d, i) => {
        console.log(`${C.bold}[${i.siteId}]${C.reset} ${i.classification} ${i.severity} confidence=${i.confidence.toFixed(2)} -> ${d.mode}`);
        console.log(`  ${C.grey}${formatTags(i.tags)}${C.reset}`);
        for (const a of d.actions) console.log(`  ${a.destructive ? "!" : " "} ${a.kind}${a.requiresApproval ? " (needs approval)" : ""} [${a.mode}]`);
      },
    });
    orchestrator.start();

    const workers = await prepareIntegrityWorkers({
      sites, queue, journal, store: new BaselineStore(paths.dataDir, paths.journalKey),
      log: (m) => console.log(`${C.grey}${m}${C.reset}`),
      warn: (m) => console.error(`${C.yellow}${m}${C.reset}`),
    });

    console.log(`${C.green}ready${C.reset} ${sites.size} site(s), journal ${journalFile} (head seq ${journal.head().seq})`);
    console.log(
      workers.watching.length
        ? `Integrity watcher on: ${workers.watching.join(", ")}`
        : `${C.grey}No site is being watched yet. A site needs a local-fs transport and a baseline (baseline snapshot <site-id>).${C.reset}`,
    );

    const shutdown = async () => {
      workers.stop();
      orchestrator.stop();
      await queue.close();
      await journal.close();
    };
    if (has(rest, "once")) {
      await workers.passOnce();
      await shutdown();
      return;
    }
    workers.start();
    setInterval(() => undefined, 2 ** 30); // keep the process alive even when nothing is being watched
    const stop = async () => {
      await shutdown();
      process.exit(0);
    };
    process.on("SIGINT", stop);
    process.on("SIGTERM", stop);
    await new Promise<void>(() => undefined); // run until signalled
  }

  fail(`unknown command '${cmd}'. Try: npm run caretaker -- help`);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
