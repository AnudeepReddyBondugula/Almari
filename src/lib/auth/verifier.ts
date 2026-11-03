import "server-only";
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import type { B64 } from "../types";

/**
 * Server-side storage of auth keys.
 *
 * The client sends a 32-byte auth key (Part 1c). We never store it as-is: if the Drive
 * folder leaked, a stored auth key could be replayed to log in. Instead we store
 * HMAC-SHA256(salt, authKey) — a one-way fingerprint. At login we recompute the
 * fingerprint from what the client sent and compare.
 *
 * Why not Argon2id here too? The auth key is already the OUTPUT of Argon2id, so it is
 * expensive to guess. Running Argon2id again on the server would cost CPU on every login
 * and add almost nothing.
 */

export interface Verifier {
  salt: B64;
  hash: B64;
}

const SALT_BYTES = 16;
const AUTH_KEY_BYTES = 32;

function fingerprint(salt: Buffer, authKey: Buffer): Buffer {
  return createHmac("sha256", salt).update(authKey).digest();
}

/** Sign-up / password change: turn the client's auth key into something safe to store. */
export function makeVerifier(authKey: Uint8Array): Verifier {
  if (authKey.length !== AUTH_KEY_BYTES) throw new Error("Auth key must be 32 bytes");
  const salt = randomBytes(SALT_BYTES);
  return {
    salt: salt.toString("base64url"),
    hash: fingerprint(salt, Buffer.from(authKey)).toString("base64url"),
  };
}

/**
 * Login: does this auth key match the stored verifier?
 * timingSafeEqual takes the same time whether the first byte or the last byte differs,
 * so an attacker can't learn the hash one byte at a time by measuring response times.
 */
export function checkVerifier(authKey: Uint8Array, verifier: Verifier): boolean {
  if (authKey.length !== AUTH_KEY_BYTES) return false;
  const expected = Buffer.from(verifier.hash, "base64url");
  const actual = fingerprint(Buffer.from(verifier.salt, "base64url"), Buffer.from(authKey));
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}