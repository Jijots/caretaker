/**
 * Ownership verification for the active pentest mode.
 *
 * The static checks get authorization for free: you can only point the tool
 * at files you can already read, and the filesystem enforces that for us.
 * A URL has no equivalent gate. Anyone can type anyone's domain. So before
 * anything active runs against a live target, this proves the caller
 * actually controls it, the same way Let's Encrypt's http-01 challenge proves
 * domain control before issuing a certificate: generate a random token, ask
 * for it to be published at a well-known path, then fetch it back.
 *
 * There is no bypass flag anywhere in this module or its caller. That is
 * deliberate. A verification step that can be skipped with a flag is not a
 * verification step, it is a suggestion.
 */

import { randomBytes } from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";

export interface Challenge {
  origin: string;
  token: string;
  verifyUrl: string;
  createdAt: string;
}

const STORE_PATH = path.join(process.cwd(), ".pentest-challenges.json");

export function originOf(target: string): string {
  return new URL(target).origin;
}

export function createChallenge(target: string): Challenge {
  const origin = originOf(target);
  return {
    origin,
    token: randomBytes(24).toString("hex"),
    verifyUrl: `${origin}/.well-known/security-scan-verify.txt`,
    createdAt: new Date().toISOString(),
  };
}

async function loadStore(): Promise<Record<string, Challenge>> {
  try {
    return JSON.parse(await fs.readFile(STORE_PATH, "utf8"));
  } catch {
    return {};
  }
}

async function saveStore(store: Record<string, Challenge>): Promise<void> {
  await fs.writeFile(STORE_PATH, JSON.stringify(store, null, 2), "utf8");
}

/** Create a challenge for this origin and persist it so a later run can check it. */
export async function initChallenge(target: string): Promise<Challenge> {
  const challenge = createChallenge(target);
  const store = await loadStore();
  store[challenge.origin] = challenge;
  await saveStore(store);
  return challenge;
}

export async function getStoredChallenge(target: string): Promise<Challenge | null> {
  const store = await loadStore();
  return store[originOf(target)] ?? null;
}

export interface VerifyResult {
  ok: boolean;
  reason?: string;
}

/** Fetch the well-known path and confirm it contains exactly the expected token. */
export async function checkChallenge(challenge: Challenge, timeoutMs = 10_000): Promise<VerifyResult> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  let res: Response;
  try {
    res = await fetch(challenge.verifyUrl, { signal: ctrl.signal, redirect: "follow" });
  } catch (e) {
    return { ok: false, reason: `Could not reach ${challenge.verifyUrl}: ${(e as Error).message}` };
  } finally {
    clearTimeout(timer);
  }

  if (!res.ok) {
    return { ok: false, reason: `${challenge.verifyUrl} returned HTTP ${res.status}. Make sure the file is published and public.` };
  }

  const body = (await res.text()).trim();
  if (body !== challenge.token) {
    return {
      ok: false,
      reason: "The file exists but its contents don't match the issued token. Copy the exact value shown by --pentest-init, with no extra whitespace or quotes.",
    };
  }

  return { ok: true };
}
