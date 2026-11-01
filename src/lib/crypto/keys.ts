import { utf8 } from "./encoding";

/**
 * Splits the master key into two independent keys with HKDF-SHA256:
 *
 *   master key ─┬─ HKDF("almari-enc-v1")  → encryption key (stays in the browser)
 *               └─ HKDF("almari-auth-v1") → auth key       (sent to the server at login)
 *
 * HKDF is one-way: knowing the auth key tells you nothing about the encryption key
 * or the master key. So the server can check your login without being able to decrypt.
 */

const INFO_ENC = utf8("almari-enc-v1");
const INFO_AUTH = utf8("almari-auth-v1");
const KEY_BYTES = 32;

export interface SubKeys {
  /** AES-256-GCM key. Non-extractable: JavaScript can use it but can never read its bytes. */
  encryptionKey: CryptoKey;
  /** 32 bytes the server hashes and compares at login. */
  authKey: Uint8Array;
}

async function importForHkdf(masterKey: Uint8Array): Promise<CryptoKey> {
  if (masterKey.length !== KEY_BYTES) throw new Error("Master key must be 32 bytes");
  return crypto.subtle.importKey("raw", masterKey as BufferSource, "HKDF", false, [
    "deriveKey",
    "deriveBits",
  ]);
}

function hkdfParams(info: Uint8Array): HkdfParams {
  // Empty salt is fine here: the master key already came out of Argon2id with a per-user salt.
  return { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: info as BufferSource };
}

export async function deriveSubKeys(masterKey: Uint8Array): Promise<SubKeys> {
  const hkdfKey = await importForHkdf(masterKey);

  const encryptionKey = await crypto.subtle.deriveKey(
    hkdfParams(INFO_ENC),
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    false, // non-extractable
    ["encrypt", "decrypt"],
  );

  const authKey = new Uint8Array(
    await crypto.subtle.deriveBits(hkdfParams(INFO_AUTH), hkdfKey, KEY_BYTES * 8),
  );

  return { encryptionKey, authKey };
}