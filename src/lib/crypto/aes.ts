import type { EncryptedBlob } from "../types";
import { fromB64, fromUtf8, randomBytes, toB64, utf8 } from "./encoding";

/**
 * AES-256-GCM: encrypts data AND detects any tampering with it.
 *
 * Every encryption uses a fresh random 12-byte IV. Reusing an IV with the same key
 * breaks GCM badly, so callers never choose the IV — this module always generates it.
 */

const IV_BYTES = 12; // the size GCM is designed for
const TAG_BITS = 128; // 16-byte authentication tag, appended to the ciphertext

export class DecryptionError extends Error {
  constructor() {
    super("Decryption failed: wrong key, or the data was modified or corrupted.");
    this.name = "DecryptionError";
  }
}

/**
 * Encrypt bytes.
 * @param context Optional label bound to the ciphertext (e.g. "vault:<userId>").
 *   Decryption fails unless the exact same label is given, so a blob can't be
 *   swapped into the wrong place. It is NOT secret and NOT stored in the blob.
 */
export async function encryptBytes(
  key: CryptoKey,
  plaintext: Uint8Array,
  context = "",
): Promise<EncryptedBlob> {
  const iv = randomBytes(IV_BYTES);
  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv as BufferSource,
      additionalData: utf8(context) as BufferSource,
      tagLength: TAG_BITS,
    },
    key,
    plaintext as BufferSource,
  );
  return { iv: toB64(iv), ciphertext: toB64(new Uint8Array(ciphertext)) };
}

/** Decrypt bytes. Throws DecryptionError if anything is wrong — never returns garbage. */
export async function decryptBytes(
  key: CryptoKey,
  blob: EncryptedBlob,
  context = "",
): Promise<Uint8Array> {
  const iv = fromB64(blob.iv);
  if (iv.length !== IV_BYTES) throw new DecryptionError();
  try {
    const plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: iv as BufferSource,
        additionalData: utf8(context) as BufferSource,
        tagLength: TAG_BITS,
      },
      key,
      fromB64(blob.ciphertext) as BufferSource,
    );
    return new Uint8Array(plaintext);
  } catch {
    // Web Crypto gives a vague OperationError; replace it with a clear message.
    throw new DecryptionError();
  }
}

/** Convenience: encrypt any JSON-serializable value (e.g. the vault contents). */
export async function encryptJson(key: CryptoKey, value: unknown, context = ""): Promise<EncryptedBlob> {
  return encryptBytes(key, utf8(JSON.stringify(value)), context);
}

export async function decryptJson<T>(key: CryptoKey, blob: EncryptedBlob, context = ""): Promise<T> {
  return JSON.parse(fromUtf8(await decryptBytes(key, blob, context))) as T;
}