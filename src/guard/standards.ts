/**
 * Standards tables and the default tags for each detection type.
 *
 * Data, not logic: every id and name below was checked against the official
 * source on the date recorded in STANDARDS_PROVENANCE. If a standard changes,
 * this file is the only place to update, and the tests fail loudly if a table
 * and a detection type fall out of step.
 *
 * Tags are DEFAULTS per detection type. A worker sees a symptom (a changed
 * file, a suspicious script), not a cause, so the OWASP category here is the
 * most likely one, not a verdict. Correlated incidents merge the tags of their
 * events and can be refined with evidence. Anything a worker knows better than
 * the default (a scanner that has the CVE) overrides it explicitly.
 */

export const STANDARDS_PROVENANCE = {
  checkedOn: "2026-10-06",
  owasp: {
    source: "https://top10.owasp.org/2025",
    note: "Final release. https://owasp.org/Top10/2025 permanently redirects (308) to this host. Names are quoted exactly; A09 is spelled 'and', not '&'.",
  },
  attack: {
    source: "https://attack.mitre.org/techniques/",
    note: "Each technique page below was fetched individually. T1491.002 (External Defacement) is used rather than the parent T1491 because the Page watcher observes public websites, which is exactly what the sub-technique describes.",
  },
  nist: {
    source: "https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf",
    note: "NIST CSWP 29, CSF 2.0, published 2024-02-26. Function names were confirmed from NIST-hosted search results quoting the document; the PDF text itself could not be parsed by the fetch tool, so this one is a second-hand check. CSF 2.0 has SIX functions: Govern was added to the five in CSF 1.1.",
  },
  cvss: {
    note: "Not checked against FIRST this phase. Phase 1 only validates version in {3.1, 4.0} and score in 0..10. Verify qualitative severity bands in Phase 6, when the scanner supplies real scores.",
  },
} as const;

/* ------------------------------------------------------------------ OWASP */

export const OWASP_2025 = {
  A01: "Broken Access Control",
  A02: "Security Misconfiguration",
  A03: "Software Supply Chain Failures",
  A04: "Cryptographic Failures",
  A05: "Injection",
  A06: "Insecure Design",
  A07: "Authentication Failures",
  A08: "Software or Data Integrity Failures",
  A09: "Security Logging and Alerting Failures",
  A10: "Mishandling of Exceptional Conditions",
} as const;
export type OwaspId = keyof typeof OWASP_2025;
export const OWASP_IDS = Object.keys(OWASP_2025) as [OwaspId, ...OwaspId[]];

/* ----------------------------------------------------------------- ATT&CK */

export const ATTACK = {
  "T1491.002": { name: "External Defacement", tactics: ["Impact"], modified: "2025-10-24" },
  "T1505.003": { name: "Server Software Component: Web Shell", tactics: ["Persistence"], modified: "2026-05-12" },
  "T1190": { name: "Exploit Public-Facing Application", tactics: ["Initial Access"], modified: "2026-05-12" },
  "T1110": { name: "Brute Force", tactics: ["Credential Access"], modified: "2026-05-12" },
  "T1595.003": { name: "Active Scanning: Wordlist Scanning", tactics: ["Reconnaissance"], modified: "2025-10-24" },
  "T1189": { name: "Drive-by Compromise", tactics: ["Initial Access"], modified: "2025-10-24" },
  "T1078": {
    name: "Valid Accounts",
    tactics: ["Stealth", "Persistence", "Privilege Escalation", "Initial Access"],
    modified: "2026-05-12",
  },
} as const;
export type AttackId = keyof typeof ATTACK;
export const ATTACK_IDS = Object.keys(ATTACK) as [AttackId, ...AttackId[]];

/* -------------------------------------------------------------------- NIST */

export const NIST_CSF_FUNCTIONS = ["govern", "identify", "protect", "detect", "respond", "recover"] as const;
export type NistFunction = (typeof NIST_CSF_FUNCTIONS)[number];

/* --------------------------------------------------------- detection types */

export interface DetectionSpec {
  /** Which worker is allowed to emit this type. */
  worker: "integrity" | "page" | "traffic" | "scanner";
  owasp: readonly OwaspId[];
  attack: readonly AttackId[];
  nist: readonly NistFunction[];
  /**
   * Could an ordinary deploy or edit produce this signal? Only these may ever
   * be explained away by a deploy window or a commit match. Content signals
   * ("hacked by", an executable in uploads, a new external script) are never
   * explainable by a deploy, so a deploy window cannot launder them.
   */
  deployExplainable: boolean;
  /** The worker has to supply the OWASP category itself; there is no sane default. */
  requiresOwaspOverride?: boolean;
  description: string;
}

export const DETECTION_TYPES = {
  "integrity.file_changed": {
    worker: "integrity", owasp: ["A08"], attack: ["T1491.002"], nist: ["detect"], deployExplainable: true,
    description: "A watched file's hash differs from the baseline.",
  },
  "integrity.file_added": {
    worker: "integrity", owasp: ["A08"], attack: ["T1491.002"], nist: ["detect"], deployExplainable: true,
    description: "A new file appeared in a watched path.",
  },
  "integrity.file_removed": {
    worker: "integrity", owasp: ["A08"], attack: ["T1491.002"], nist: ["detect"], deployExplainable: true,
    description: "A file in the baseline is gone. Removing an index page or a .htaccess changes what visitors get.",
  },
  "integrity.executable_in_uploads": {
    worker: "integrity", owasp: ["A01"], attack: ["T1505.003", "T1190"], nist: ["detect"], deployExplainable: false,
    description: "An executable script appeared in an upload directory (webshell indicator).",
  },
  "page.dom_changed": {
    worker: "page", owasp: ["A08"], attack: ["T1491.002"], nist: ["detect"], deployExplainable: true,
    description: "The rendered DOM differs from the baseline outside whitelisted regions.",
  },
  "page.visual_diff": {
    worker: "page", owasp: ["A08"], attack: ["T1491.002"], nist: ["detect"], deployExplainable: true,
    description: "The screenshot differs from the baseline beyond tolerance.",
  },
  "page.external_script_added": {
    worker: "page", owasp: ["A08", "A05"], attack: ["T1189", "T1491.002"], nist: ["detect"], deployExplainable: false,
    description: "A script from a new external origin is loaded by the page.",
  },
  "page.iframe_injected": {
    worker: "page", owasp: ["A08", "A05"], attack: ["T1189", "T1491.002"], nist: ["detect"], deployExplainable: false,
    description: "An iframe not present in the baseline was injected.",
  },
  "page.defacement_signal": {
    worker: "page", owasp: ["A08"], attack: ["T1491.002"], nist: ["detect"], deployExplainable: false,
    description: "Known defacement text, group signature, or a sudden script or language change.",
  },
  "traffic.bruteforce": {
    worker: "traffic", owasp: ["A07"], attack: ["T1110"], nist: ["detect"], deployExplainable: false,
    description: "Repeated failed logins against an admin or login endpoint.",
  },
  "traffic.admin_login_unusual": {
    worker: "traffic", owasp: ["A07"], attack: ["T1078"], nist: ["detect"], deployExplainable: false,
    description: "An administrative login from an unfamiliar address or at an unusual time.",
  },
  "traffic.path_probe": {
    worker: "traffic", owasp: ["A02"], attack: ["T1595.003"], nist: ["detect"], deployExplainable: false,
    description: "Requests probing for /.env, /wp-admin, /phpmyadmin and similar paths.",
  },
  "traffic.suspicious_upload_post": {
    worker: "traffic", owasp: ["A01"], attack: ["T1190"], nist: ["detect"], deployExplainable: false,
    description: "A POST to an upload endpoint that looks like exploitation.",
  },
  "scanner.outdated_component": {
    worker: "scanner", owasp: ["A03"], attack: ["T1190"], nist: ["identify"], deployExplainable: false,
    description: "A plugin or framework version with known vulnerabilities.",
  },
  "scanner.vulnerability_found": {
    worker: "scanner", owasp: [], attack: ["T1190"], nist: ["identify"], deployExplainable: false,
    requiresOwaspOverride: true,
    description: "A scanner finding. The scanner must supply the OWASP category, which varies per finding.",
  },
} as const satisfies Record<string, DetectionSpec>;

export type DetectionType = keyof typeof DETECTION_TYPES;
export const DETECTION_TYPE_IDS = Object.keys(DETECTION_TYPES) as [DetectionType, ...DetectionType[]];

/* -------------------------------------------------------------------- tags */

export interface Cvss {
  version: "3.1" | "4.0";
  score: number;
  vector?: string;
}

export interface Tags {
  owasp: OwaspId[];
  attack: AttackId[];
  nist: NistFunction[];
  cve: string[];
  cvss?: Cvss;
}

export type TagOverrides = Partial<Tags>;

/**
 * Default tags for a detection type, with explicit overrides where the worker
 * knows better. Throws if a type that needs an OWASP category does not get one,
 * because silently guessing would put a wrong standard on a report.
 */
export function tagsFor(type: DetectionType, overrides: TagOverrides = {}): Tags {
  const spec: DetectionSpec = DETECTION_TYPES[type];
  const owasp = overrides.owasp ?? [...spec.owasp];
  if (spec.requiresOwaspOverride && !overrides.owasp?.length) {
    throw new Error(`${type} requires the emitting worker to supply an OWASP category.`);
  }
  const tags: Tags = {
    owasp,
    attack: overrides.attack ?? [...spec.attack],
    nist: overrides.nist ?? [...spec.nist],
    cve: overrides.cve ?? [],
  };
  if (overrides.cvss) tags.cvss = overrides.cvss;
  return tags;
}

/** Union of several tag sets, preserving first-seen order. Used when events merge into an incident. */
export function mergeTags(all: Tags[]): Tags {
  const uniq = <T>(xs: T[]) => [...new Set(xs)];
  const withCvss = all.filter((t) => t.cvss).sort((a, b) => b.cvss!.score - a.cvss!.score)[0];
  const merged: Tags = {
    owasp: uniq(all.flatMap((t) => t.owasp)),
    attack: uniq(all.flatMap((t) => t.attack)),
    nist: uniq(all.flatMap((t) => t.nist)),
    cve: uniq(all.flatMap((t) => t.cve)),
  };
  if (withCvss?.cvss) merged.cvss = withCvss.cvss;
  return merged;
}

const cap = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

/**
 * One line for humans, in the shape the report format asks for:
 * "OWASP: Broken Access Control; ATT&CK: T1491.002 External Defacement; NIST: Detect/Recover"
 */
export function formatTags(tags: Tags): string {
  const parts = [
    `OWASP: ${tags.owasp.map((id) => OWASP_2025[id]).join(", ")}`,
    `ATT&CK: ${tags.attack.map((id) => `${id} ${ATTACK[id].name}`).join(", ")}`,
    `NIST: ${tags.nist.map(cap).join("/")}`,
  ];
  if (tags.cve.length) parts.push(`CVE: ${tags.cve.join(", ")}`);
  if (tags.cvss) parts.push(`CVSS ${tags.cvss.version}: ${tags.cvss.score.toFixed(1)}`);
  return parts.join("; ");
}
