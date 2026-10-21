import test from "node:test";
import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { isEnvFile, redactForModel, redactSecretShapes } from "./redact.js";
import { Sandbox, grep, readFile } from "./tools.js";

// Built at runtime on purpose: a literal token-shaped string in a public repo trips secret scanners.
const fake = {
  openai: "sk-" + "a1B2".repeat(10),
  groq: "gsk_" + "Z9y8".repeat(10),
  github: "ghp_" + "Q7w3".repeat(10),
  aws: "AKIA" + "ABCDEFGH12345678".slice(0, 16),
  google: "AIza" + "Xx9_".repeat(9),
  telegram: "123456789:AA" + "kK3-".repeat(9),
  jwt: ["eyJ" + "hdr".repeat(5), "eyJ" + "pay".repeat(5), "sig".repeat(8)].join("."),
};

async function tmp() {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "redact-test-"));
  return { dir, done: () => fs.rm(dir, { recursive: true, force: true }) };
}

test("env files are recognised, templates are not", () => {
  for (const n of [".env", ".env.local", ".env.production", "config/.env", "app\\.env.staging"]) assert.equal(isEnvFile(n), true, n);
  for (const n of [".env.example", ".env.sample", ".env.template", ".env.dist", "env.ts", "src/environment.ts", "notenv"]) assert.equal(isEnvFile(n), false, n);
});

test("every value in an env file is hidden, names and empty values stay", () => {
  const input = ["# keys", "GROQ_API_KEY=plainwordsecret", 'export TOKEN="quoted secret value"', "EMPTY=", "ALSO_EMPTY=''", "", "PORT=3000"].join("\n");
  const out = redactForModel(".env", input).split("\n");
  assert.equal(out.length, 7, "line count never changes");
  assert.match(out[1], /^GROQ_API_KEY=\[REDACTED env value, 15 chars\]$/);
  assert.match(out[2], /^export TOKEN=\[REDACTED env value, 21 chars\]$/, "the quotes count toward the length");
  assert.equal(out[3], "EMPTY=");
  assert.equal(out[4], "ALSO_EMPTY=''");
  assert.equal(out[6], "PORT=[REDACTED env value, 4 chars]", "even a harmless-looking value, because it cannot be told apart");
  assert.ok(!out.join("\n").includes("plainwordsecret") && !out.join("\n").includes("quoted secret"));
});

test("a comment in an env file cannot smuggle an old key", () => {
  const out = redactForModel(".env", "# old key: " + fake.openai + " rotate me");
  assert.ok(!out.includes(fake.openai));
  assert.match(out, /rotate me/, "the human words survive");
});

test("template files are left exactly as written", () => {
  const t = "GROQ_API_KEY=\nGUARD_JOURNAL_KEY=\n# 32+ characters\n";
  assert.equal(redactForModel(".env.example", t), t);
});

test("credential-shaped values are replaced anywhere, with a label and a length", () => {
  for (const [label, value] of Object.entries(fake)) {
    const out = redactSecretShapes(`const k = "${value}";`);
    assert.ok(!out.includes(value), `${label} still present`);
    assert.match(out, /\[REDACTED [a-z0-9-]+, \d+ chars\]/, label);
  }
});

test("a multi-line private key is replaced without moving any line numbers", () => {
  const pem = ["-----BEGIN RSA PRIVATE KEY-----", "MIIEowIBAAKCAQEA1111", "2222222222222222", "-----END RSA PRIVATE KEY-----"].join("\n");
  const input = ["line one", pem, "line six"].join("\n");
  const out = redactSecretShapes(input);
  assert.equal(out.split("\n").length, input.split("\n").length);
  assert.ok(!out.includes("MIIEow") && !out.includes("2222222222"));
  assert.equal(out.split("\n").at(-1), "line six");
  assert.match(out, /\[REDACTED private-key/);
});

test("a key glued to a word is still caught, like a Telegram bot URL", () => {
  const url = "https://api.telegram.org/bot" + fake.telegram + "/sendMessage";
  const out = redactSecretShapes(url);
  assert.ok(!out.includes(fake.telegram) && !out.includes("AA" + "kK3-"));
  assert.match(out, /sendMessage$/);
  assert.ok(!redactSecretShapes("Bearer" + fake.openai).includes(fake.openai));
});

test("ordinary code and prose are not touched", () => {
  const code = 'const url = "https://example.com/a/b";\nconst id = "sk-learn";\n// task-force-two-alpha\nreturn 42;';
  assert.equal(redactSecretShapes(code), code);
});

test("read_file redacts and keeps line numbers true", async () => {
  const { dir, done } = await tmp();
  try {
    await fs.writeFile(path.join(dir, "config.ts"), ["export const a = 1;", `export const key = "${fake.groq}";`, "export const b = 2;"].join("\n"));
    await fs.writeFile(path.join(dir, ".env"), "SECRET=hunter2hunter2\nNAME=demo\n");
    const sb = new Sandbox(dir);
    const src = (await readFile(sb, { path: "config.ts" })) as { content: string };
    assert.ok(!src.content.includes(fake.groq));
    assert.match(src.content, /\s2\| export const key = "\[REDACTED groq-key, 44 chars\]";/, "still on line 2");
    assert.match(src.content, /\s3\| export const b = 2;/);
    const env = (await readFile(sb, { path: ".env" })) as { content: string };
    assert.ok(!env.content.includes("hunter2"));
    assert.match(env.content, /SECRET=\[REDACTED env value, 14 chars\]/);
  } finally { await done(); }
});

test("grep still FINDS a secret by its real pattern, and reports it redacted", async () => {
  const { dir, done } = await tmp();
  try {
    await fs.writeFile(path.join(dir, "app.ts"), `const a = 1;\nconst key = "${fake.openai}";\n`);
    await fs.writeFile(path.join(dir, ".env"), "API_TOKEN=supersecretvalue\n");
    const sb = new Sandbox(dir);

    const byShape = (await grep(sb, { pattern: "sk-[A-Za-z0-9]{20,}" })) as { hits: { file: string; line: number; text: string }[] };
    assert.equal(byShape.hits.length, 1, "detection is not blinded");
    assert.equal(byShape.hits[0].file, "app.ts");
    assert.equal(byShape.hits[0].line, 2);
    assert.ok(!byShape.hits[0].text.includes(fake.openai));
    assert.match(byShape.hits[0].text, /\[REDACTED openai-style-key/);

    const inEnv = (await grep(sb, { pattern: "API_TOKEN" })) as { hits: { text: string }[] };
    assert.equal(inEnv.hits.length, 1);
    assert.ok(!inEnv.hits[0].text.includes("supersecretvalue"));
    assert.match(inEnv.hits[0].text, /^API_TOKEN=\[REDACTED env value/);
  } finally { await done(); }
});

test("a secret near the 160 character cut is redacted before cutting, never half shown", async () => {
  const { dir, done } = await tmp();
  try {
    const line = "x".repeat(150) + fake.openai;
    await fs.writeFile(path.join(dir, "long.ts"), line + "\n");
    const sb = new Sandbox(dir);
    const r = (await grep(sb, { pattern: "xxxx" })) as { hits: { text: string }[] };
    assert.ok(!r.hits[0].text.includes("sk-"), "no fragment of the key survives the cut");
  } finally { await done(); }
});
