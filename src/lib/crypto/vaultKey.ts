import type { EncryptedBlob } from "../types";
import { decryptBytes, encryptBytes } from "./aes";
import { randomBytes, wipe } from "./encoding";

/**
 * The Vault Key: 32 random bytes that encrypt the actual vault.
 *
 * It is never derived from a password and never stored in plain form. Instead it is
 * "wrapped" (encrypted) separately by each unlock method — master password, recovery
 * phrase, and later YubiKey/Face. Any one wrapper can unwrap it ("any one unlocks").
 *
 *   password key ──wraps──┐
 *   recovery key ──wraps──┼──▶ Vault Key ──encrypts──▶ vault
 *   (later) YubiKey ──────┘
 */

const VAULT_KEY_BYTES = 32;
/** Bound into every wrap so a wrapped Vault Key can't be passed off as some other blob. */
const WRAP_CONTEXT = "almari:vault-key:v1";

/** Turn raw bytes into a usable AES key that JavaScript can never read back. */
async function importVaultKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", raw as BufferSource, { name: "AES-GCM" }, false, [
    "encrypt",
    "decrypt",
  ]);
}

/**
 * Sign-up: create a brand-new Vault Key and wrap it with every unlock method at once.
 * Returns the usable key plus one wrapped copy per wrapping key, in the same order.
 */
export async function createVaultKey(
  wrappingKeys: CryptoKey[],
): Promise<{ vaultKey: CryptoKey; wrapped: EncryptedBlob[] }> {
  if (wrappingKeys.length === 0) throw new Error("Need at least one wrapping key");
  const raw = randomBytes(VAULT_KEY_BYTES);
  try {
    const wrapped = await Promise.all(wrappingKeys.map((k) => encryptBytes(k, raw, WRAP_CONTEXT)));
    const vaultKey = await importVaultKey(raw);
    return { vaultKey, wrapped };
  } finally {
    wipe(raw); // raw bytes only existed for these few lines
  }
}

/** Unlock: unwrap the Vault Key with any one wrapping key. Throws DecryptionError if it's the wrong one. */
export async function unwrapVaultKey(wrapped: EncryptedBlob, wrappingKey: CryptoKey): Promise<CryptoKey> {
  const raw = await decryptBytes(wrappingKey, wrapped, WRAP_CONTEXT);
  try {
    if (raw.length !== VAULT_KEY_BYTES) throw new Error("Unwrapped Vault Key has the wrong length");
    return await importVaultKey(raw);
  } finally {
    wipe(raw);
  }
}

/**
 * Change password, recover with the phrase, or add a new unlock method:
 * unwrap with a key you have, re-wrap with a new key. The vault itself is untouched.
 */
export async function rewrapVaultKey(
  wrapped: EncryptedBlob,
  currentWrappingKey: CryptoKey,
  newWrappingKey: CryptoKey,
): Promise<EncryptedBlob> {
  const raw = await decryptBytes(currentWrappingKey, wrapped, WRAP_CONTEXT);
  try {
    if (raw.length !== VAULT_KEY_BYTES) throw new Error("Unwrapped Vault Key has the wrong length");
    return await encryptBytes(newWrappingKey, raw, WRAP_CONTEXT);
  } finally {
    wipe(raw);
  }
}