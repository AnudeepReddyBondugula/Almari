import "server-only";
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { DEFAULT_KDF, assertKdfParamsSafe } from "../crypto/kdf";
import type { EncryptedBlob, KdfParams, UserRecord } from "../types";
import type { LoginInput, RegisterInput } from "./schemas";
import { UsernameTakenError, type UserStore } from "./store";
import { checkVerifier, makeVerifier, type Verifier } from "./verifier";

/**
 * The auth rules, with no HTTP or Google Drive code mixed in. Route handlers call these;
 * tests call them directly with an in-memory store.
 */

export interface AuthConfig {
  /** SESSION_SECRET — also used to make fake prelogin salts. */
  serverSecret: string;
  /** If set, sign-up requires this code, so strangers can't fill your Drive. */
  inviteCode?: string;
}

const fromB64 = (s: string) => new Uint8Array(Buffer.from(s, "base64url"));

// ── Prelogin ────────────────────────────────────────────────────────────────

/**
 * Step 1 of login: "what settings do I run Argon2id with?"
 * Unknown usernames get FAKE settings that look real and never change for that name,
 * so this endpoint can't be used to test which usernames exist.
 */
export async function prelogin(store: UserStore, cfg: AuthConfig, username: string): Promise<KdfParams> {
  const user = await store.get(username);
  if (user) return user.kdf;
  const fakeSalt = createHmac("sha256", cfg.serverSecret)
    .update(`almari-prelogin:${username}`)
    .digest()
    .subarray(0, 16);
  return { ...DEFAULT_KDF, salt: fakeSalt.toString("base64url") };
}

// ── Register ────────────────────────────────────────────────────────────────

export type RegisterResult =
  | { ok: true; user: UserRecord }
  | { ok: false; error: "INVITE_REQUIRED" | "USERNAME_TAKEN" | "WEAK_KDF" };

export async function register(store: UserStore, cfg: AuthConfig, input: RegisterInput): Promise<RegisterResult> {
  if (cfg.inviteCode && !safeEqualStrings(input.inviteCode ?? "", cfg.inviteCode)) {
    return { ok: false, error: "INVITE_REQUIRED" };
  }
  // The browser checks this too (Part 1b), but the server is the gatekeeper for what
  // gets STORED: weak settings saved now would weaken every future login.
  try {
    assertKdfParamsSafe(input.kdf);
  } catch {
    return { ok: false, error: "WEAK_KDF" };
  }

  const user: UserRecord = {
    userId: randomBytes(16).toString("base64url"),
    username: input.username,
    createdAt: new Date().toISOString(),
    kdf: input.kdf,
    authVerifier: makeVerifier(fromB64(input.authKey)),
    recoveryVerifier: makeVerifier(fromB64(input.recoveryAuthKey)),
    wrappedVaultKeyByPassword: input.wrappedVaultKeyByPassword,
    wrappedVaultKeyByRecovery: input.wrappedVaultKeyByRecovery,
  };

  try {
    await store.create(user);
  } catch (e) {
    if (e instanceof UsernameTakenError) return { ok: false, error: "USERNAME_TAKEN" };
    throw e;
  }
  return { ok: true, user };
}

// ── Login ───────────────────────────────────────────────────────────────────

/** What the browser needs after login to unlock: its lockbox (wrapped Vault Key). */
export interface LoginSuccess {
  userId: string;
  username: string;
  wrappedVaultKeyByPassword: EncryptedBlob;
}

/** A verifier that matches nothing. Checked for unknown users so both paths do the same work. */
const DUMMY_VERIFIER: Verifier = {
  salt: Buffer.alloc(16).toString("base64url"),
  hash: Buffer.alloc(32).toString("base64url"),
};

export async function login(store: UserStore, input: LoginInput): Promise<LoginSuccess | null> {
  const user = await store.get(input.username);
  const ok = checkVerifier(fromB64(input.authKey), user?.authVerifier ?? DUMMY_VERIFIER);
  if (!user || !ok) return null; // same answer for "no such user" and "wrong password"
  return {
    userId: user.userId,
    username: user.username,
    wrappedVaultKeyByPassword: user.wrappedVaultKeyByPassword,
  };
}

function safeEqualStrings(a: string, b: string): boolean {
  // Hash both first so the lengths match (timingSafeEqual needs equal lengths).
  const ha = createHmac("sha256", "cmp").update(a).digest();
  const hb = createHmac("sha256", "cmp").update(b).digest();
  return timingSafeEqual(ha, hb);
}