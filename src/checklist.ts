/**
 * The checklist. This is the domain knowledge and it is the part that matters.
 *
 * `detect` is what the agent is told to go and find. It is written as detection
 * guidance, not as a fix instruction, because this agent never edits anything.
 *
 * `verifiable`:
 *   "code"   - decidable from the repository alone
 *   "partial"- partly visible in code, but config or hosting may override it
 *   "manual" - not decidable from a repository. Reported as a checklist item
 *              for the human, never as a pass or a finding.
 */

export type Verifiable = "code" | "partial" | "manual";
export type Severity = "critical" | "high" | "medium" | "low";

export interface Check {
  id: string;
  category: string;
  title: string;
  why: string;
  severity: Severity;
  verifiable: Verifiable;
  critical7?: boolean;
  appliesTo?: string[]; // omit = always
  detect: string;
}

export const CHECKS: Check[] = [
  // ---------------------------------------------------------------- secrets
  {
    id: "SEC-01",
    category: "Secrets and keys",
    title: "Keys and secrets kept on the server",
    why: "A key in browser-side code can be read from devtools and spent on the owner's account.",
    severity: "critical",
    verifiable: "code",
    critical7: true,
    detect:
      "Find API keys, secrets or tokens that reach client-side code. Look for hardcoded key-shaped literals, " +
      "and for secrets read into code that ships to the browser: NEXT_PUBLIC_* holding anything secret, " +
      "VITE_* holding anything secret, process.env used inside client components or browser bundles, " +
      "and any direct call to a third-party API with a secret key from the front end. " +
      "Report the file and line, and say which bundle it lands in.",
  },
  {
    id: "SEC-02",
    category: "Secrets and keys",
    title: "Secrets kept out of version control",
    why: "A committed secret stays in history after deletion, and bots scan public repos for exactly this.",
    severity: "critical",
    verifiable: "partial",
    detect:
      "Check .gitignore covers .env and every secret file variant (.env.local, .env.production, *.pem, *.key). " +
      "Check whether a .env file with real values is present in the working tree in a way that suggests it is tracked. " +
      "State clearly that you cannot read git history with the tools you have, so history must be checked manually " +
      "with `git log --all --full-history -- .env`.",
  },
  {
    id: "SEC-03",
    category: "Secrets and keys",
    title: "Public database key on the client, never the admin key",
    why: "The service role key bypasses row-level security entirely.",
    severity: "critical",
    verifiable: "code",
    critical7: true,
    appliesTo: ["supabase", "firebase"],
    detect:
      "Find which database key the front end uses. Flag any service_role key, admin key, or SUPABASE_SERVICE_ROLE_KEY " +
      "reachable from client code. The client should use the anon or publishable key only. " +
      "Report the file and line and which key it is.",
  },

  // ---------------------------------------------------------------- database
  {
    id: "DB-01",
    category: "Database",
    title: "Row-level security enabled on every table",
    why: "Without it, anyone who finds the endpoint can read every user's rows.",
    severity: "critical",
    verifiable: "partial",
    critical7: true,
    detect:
      "Look in migrations, SQL files and policy definitions for ENABLE ROW LEVEL SECURITY and CREATE POLICY. " +
      "List tables that appear to have no policy. Flag any policy using USING (true) or an allow-all shape as unsafe. " +
      "Say explicitly that the live database is the source of truth and the repository may not reflect it.",
  },
  {
    id: "DB-02",
    category: "Database",
    title: "Sensitive data encrypted at rest",
    why: "One leak exposes everything if it is stored in plain text.",
    severity: "high",
    verifiable: "partial",
    detect:
      "Find columns and model fields holding personal data, tokens or credentials that appear to be stored in plain text. " +
      "Look for encryption casts or helpers in the model layer. Report fields you would expect to be encrypted and are not.",
  },

  // ---------------------------------------------------------------- authz
  {
    id: "AUTH-01",
    category: "Auth and access control",
    title: "Authentication enforced on the server",
    why: "Rules that live only in the interface are bypassed by calling the endpoint directly.",
    severity: "critical",
    verifiable: "code",
    detect:
      "List protected routes and check each one has server-side auth. Look for route groups missing auth middleware, " +
      "API handlers with no session check, and any endpoint that takes a user id from the request body or query " +
      "and trusts it rather than reading the authenticated session. Report route, file and line.",
  },
  {
    id: "AUTH-02",
    category: "Auth and access control",
    title: "Ownership checked, not just authentication",
    why: "A logged-in user who changes an id in the request can often read someone else's record.",
    severity: "critical",
    verifiable: "code",
    critical7: true,
    detect:
      "For every handler that reads, updates or deletes a record by id, check the code verifies the authenticated user " +
      "owns that record or has a role permitting it. Being logged in is not enough. " +
      "Report each handler where the id comes from the request and no ownership check follows.",
  },
  {
    id: "AUTH-03",
    category: "Auth and access control",
    title: "Mass assignment locked down",
    why: "An update that accepts any field lets a user send role=admin and promote themselves.",
    severity: "critical",
    verifiable: "code",
    detect:
      "Find create and update paths that accept a whole request payload. In Laravel look for $fillable containing " +
      "role, is_admin, status or permission columns, models using $guarded = [], and Model::create($request->all()) " +
      "or ->update($request->all()). In Node and Prisma look for spreading a request body straight into a write. " +
      "Report the model or handler, the file and the line, and name the dangerous field.",
  },
  {
    id: "AUTH-04",
    category: "Auth and access control",
    title: "Session tokens in secure cookies, not localStorage",
    why: "A token in localStorage is readable by any script that gets onto the page.",
    severity: "high",
    verifiable: "code",
    detect:
      "Find tokens written to or read from localStorage or sessionStorage. Check cookie settings for httpOnly, " +
      "secure and sameSite. Check sessions have an expiry rather than living forever. Report file and line.",
  },
  {
    id: "AUTH-05",
    category: "Auth and access control",
    title: "Passwords hashed with a modern algorithm",
    why: "Plain-text or weak hashing means one leak exposes every account.",
    severity: "critical",
    verifiable: "code",
    detect:
      "If the app stores passwords itself, confirm bcrypt or argon2 is used. Flag md5, sha1, plain storage, " +
      "or a password written to a log. If an auth provider handles this, say so and mark it covered.",
  },

  // ---------------------------------------------------------------- abuse
  {
    id: "RATE-01",
    category: "Rate limiting and abuse",
    title: "API rate limited, especially login and paid calls",
    why: "Without limits one person can guess passwords freely or run up a bill.",
    severity: "high",
    verifiable: "code",
    critical7: true,
    detect:
      "Look for rate limiting middleware or throttling on routes. Check login, signup, password reset and any endpoint " +
      "that calls a paid service such as an AI model, SMS or email provider. Report endpoints with no limit.",
  },
  {
    id: "RATE-02",
    category: "Rate limiting and abuse",
    title: "Billing caps and usage alerts set",
    why: "A spike on a paid service becomes a large invoice before anyone notices.",
    severity: "high",
    verifiable: "manual",
    critical7: true,
    detect:
      "Not decidable from a repository. List the paid services this codebase calls, by reading dependencies and " +
      "environment variable names, so the human knows which dashboards to go and configure.",
  },
  {
    id: "RATE-03",
    category: "Rate limiting and abuse",
    title: "Bot protection on public forms",
    why: "Open signup and public forms attract bots creating accounts and spam.",
    severity: "medium",
    verifiable: "code",
    detect:
      "Find public forms, especially signup and contact. Look for a CAPTCHA or similar challenge, and check it is " +
      "verified on the server before the request is processed rather than only rendered in the browser.",
  },

  // ---------------------------------------------------------------- io
  {
    id: "IO-01",
    category: "Input and output",
    title: "Parameterized queries",
    why: "A query built from raw user input lets a user run commands against the database.",
    severity: "critical",
    verifiable: "code",
    critical7: true,
    detect:
      "Find queries built by string concatenation or interpolation from user input. In Laravel look at DB::raw, " +
      "whereRaw, selectRaw and orderByRaw carrying variables. In Node look at template literals inside query calls. " +
      "Report the file, line and the interpolated variable.",
  },
  {
    id: "IO-02",
    category: "Input and output",
    title: "Server-side validation of all input",
    why: "Front-end validation is a convenience, not a control.",
    severity: "high",
    verifiable: "code",
    detect:
      "Check each endpoint validates type, length and format on the server. Look for form requests, Zod or Joi schemas, " +
      "or validate() calls. Report endpoints that read request data with no server-side validation.",
  },
  {
    id: "IO-03",
    category: "Input and output",
    title: "User content escaped before display",
    why: "Unescaped user content lets someone run script in another user's browser.",
    severity: "high",
    verifiable: "code",
    detect:
      "Find dangerouslySetInnerHTML, v-html, innerHTML assignment, and Blade {!! !!} unescaped output. " +
      "For each, say whether the content is user-supplied and whether it is sanitized first. Report file and line.",
  },
  {
    id: "IO-04",
    category: "Input and output",
    title: "File uploads restricted",
    why: "An unchecked upload can put executable content on the server.",
    severity: "high",
    verifiable: "code",
    detect:
      "If uploads exist, check the server validates mime type and size, restricts extensions to what is needed, " +
      "and stores files outside any executable path. Report handlers missing these.",
  },
  {
    id: "IO-05",
    category: "Input and output",
    title: "Responses return only what the screen needs",
    why: "Whole records often carry fields the screen never uses, including other people's data.",
    severity: "high",
    verifiable: "code",
    detect:
      "Find endpoints returning whole models or select-all rows. Flag responses that could include password hashes, " +
      "tokens, internal flags, negotiated rates or other users' personal fields. Report the endpoint and the field.",
  },

  // ---------------------------------------------------------------- payments
  {
    id: "PAY-01",
    category: "Payments",
    title: "Payment webhook signatures verified",
    why: "An unverified webhook can be forged to mark an order paid.",
    severity: "critical",
    verifiable: "code",
    appliesTo: ["payments"],
    detect:
      "Find webhook handlers for payment providers. Confirm each verifies the provider signature before acting, " +
      "and rejects on failure. Report any handler that trusts the payload.",
  },
  {
    id: "PAY-02",
    category: "Payments",
    title: "Prices set on the server",
    why: "A price sent from the browser can be changed before it arrives.",
    severity: "critical",
    verifiable: "code",
    appliesTo: ["payments"],
    detect:
      "Find where the charged amount comes from. Flag any path where a price, amount or total is read from the request " +
      "body rather than looked up on the server from the product or booking. Report file and line.",
  },

  // ---------------------------------------------------------------- ai
  {
    id: "AI-01",
    category: "AI features",
    title: "Prompt injection and untrusted model output",
    why: "User input can hijack instructions, and model output rendered or executed blindly is dangerous.",
    severity: "high",
    verifiable: "code",
    appliesTo: ["ai"],
    detect:
      "Find where user input is concatenated into a system prompt rather than passed as separate user content. " +
      "Find model output that is rendered as HTML, executed, or written to the database without a human step. " +
      "Report each and say which one it is.",
  },
  {
    id: "AI-02",
    category: "AI features",
    title: "Per-user caps on paid model calls",
    why: "One user looping an AI feature can drain the credits overnight.",
    severity: "high",
    verifiable: "code",
    appliesTo: ["ai"],
    detect:
      "Find endpoints that call a paid model. Check for a per-user usage limit enforced on the server, not the client. " +
      "Report endpoints with no cap.",
  },

  // ---------------------------------------------------------------- ops
  {
    id: "OPS-01",
    category: "Deployment and ops",
    title: "HTTPS forced",
    why: "Without it, traffic is readable by anyone on the same network.",
    severity: "high",
    verifiable: "partial",
    detect:
      "Look for an HTTPS redirect or forceScheme in middleware and config. Note that hosting usually enforces this, " +
      "so say what you found and that the hosting setup must be confirmed separately.",
  },
  {
    id: "OPS-02",
    category: "Deployment and ops",
    title: "Security headers present",
    why: "A handful of standard headers block whole classes of attack.",
    severity: "high",
    verifiable: "code",
    detect:
      "Look for Content-Security-Policy, X-Frame-Options, X-Content-Type-Options and Strict-Transport-Security. " +
      "Flag a CSP containing unsafe-inline or unsafe-eval as a real finding, not a pass. Report where headers are set.",
  },
  {
    id: "OPS-03",
    category: "Deployment and ops",
    title: "Debug off, source maps and .git not exposed",
    why: "Each one hands an attacker a map of the app.",
    severity: "high",
    verifiable: "partial",
    detect:
      "Check APP_DEBUG, NODE_ENV and framework debug flags in committed config and example env files. " +
      "Check whether production source maps are enabled. Note that .git exposure is a hosting question, not a code one.",
  },
  {
    id: "OPS-04",
    category: "Deployment and ops",
    title: "Errors do not leak internals",
    why: "Stack traces and paths handed to a user are a map of the system.",
    severity: "medium",
    verifiable: "code",
    detect:
      "Find handlers returning exception messages, stack traces or file paths to the client. " +
      "Check a generic message is shown while detail goes to a log. Report file and line.",
  },
  {
    id: "OPS-05",
    category: "Deployment and ops",
    title: "Dependencies not known-vulnerable",
    why: "Most breaches come through a known hole in an old package.",
    severity: "medium",
    verifiable: "manual",
    detect:
      "Not decidable by reading files. List the dependency manifests found so the human can run `npm audit` " +
      "and `composer audit` themselves.",
  },
  {
    id: "OPS-06",
    category: "Deployment and ops",
    title: "Logging present, and secrets never logged",
    why: "Without logs an attack is invisible, and careless logs leak the secrets themselves.",
    severity: "medium",
    verifiable: "code",
    detect:
      "Find logging calls that write a password, token, API key, full request body or authorization header. " +
      "Report each. Also note whether any error tracking or monitoring is configured at all.",
  },
  {
    id: "OPS-07",
    category: "Deployment and ops",
    title: "Automatic backups configured and restorable",
    why: "Data wiped without a backup is gone.",
    severity: "high",
    verifiable: "manual",
    detect: "Not decidable from a repository. Report as a manual item naming the database provider in use.",
  },
  {
    id: "OPS-08",
    category: "Deployment and ops",
    title: "Two-factor on hosting, database, domain and email accounts",
    why: "Attackers often get in through the accounts around the code rather than the code.",
    severity: "high",
    verifiable: "manual",
    detect: "Not decidable from a repository. Report as a manual item listing the providers this codebase depends on.",
  },

  // ---------------------------------------------------------------- mobile
  {
    id: "MOB-01",
    category: "Mobile",
    title: "No secrets in the app bundle",
    why: "A mobile bundle can be unpacked and read, so a key inside it is public.",
    severity: "critical",
    verifiable: "code",
    appliesTo: ["mobile"],
    detect: "Find API keys or secrets in mobile source or bundled config. Report file and line.",
  },
  {
    id: "MOB-02",
    category: "Mobile",
    title: "Tokens in secure storage, not AsyncStorage",
    why: "AsyncStorage is not encrypted.",
    severity: "high",
    verifiable: "code",
    appliesTo: ["mobile"],
    detect: "Find auth tokens stored in AsyncStorage. Secure storage such as Keychain or Keystore is expected.",
  },
  {
    id: "MOB-03",
    category: "Mobile",
    title: "Deep links validated",
    why: "A deep link that triggers actions without checks can be abused.",
    severity: "medium",
    verifiable: "code",
    appliesTo: ["mobile"],
    detect: "Find deep link handlers that perform sensitive actions without validating the user and the request.",
  },
  {
    id: "MOB-04",
    category: "Mobile",
    title: "Biometrics gate the interface only",
    why: "A device-side check can be bypassed, so it cannot stand in for server verification.",
    severity: "medium",
    verifiable: "code",
    appliesTo: ["mobile"],
    detect: "Find sensitive actions gated by biometrics alone with no server-side verification.",
  },
];

export const CRITICAL_7 = CHECKS.filter((c) => c.critical7);
