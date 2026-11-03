import { generateMnemonic, mnemonicToEntropy, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english";
import { utf8, wipe } from "./encoding";

/**
 * The 12-word recovery phrase (BIP39 standard, the same format crypto wallets use).
 *
 *   12 words ──decode──▶ 16 random bytes ──HKDF─┬─ "almari-recovery-wrap-v1" → recovery wrapping key
 *                                               └─ "almari-recovery-auth-v1" → recovery auth key
 *
 * - The wrapping key opens the second lockbox (the Vault Key copy wrapped by recovery).
 * - The auth key proves to the server that you hold the phrase, so it lets you reset
 *   your master password — without the server ever seeing the words.
 */

const WORD_COUNT = 12;
const ENTROPY_BITS = 128; // 12 words = 128 bits of randomness + 4-bit checksum
const INFO_WRAP = utf8("almari-recovery-wrap-v1");
const INFO_AUTH = utf8("almari-recovery-auth-v1");

export class InvalidRecoveryPhraseError extends Error {
  constructor(reason: string) {
    super(`Invalid recovery phrase: ${reason}`);
    this.name = "InvalidRecoveryPhraseError";
  }
}

/** Sign-up: a brand-new random phrase. Show it to the user once; never store or send it. */
export function generateRecoveryPhrase(): string {
  return generateMnemonic(wordlist, ENTROPY_BITS);
}

/** Forgive how people type: extra spaces, line breaks, capital letters. */
export function normalizePhrase(input: string): string {
  return input.normalize("NFKD").trim().toLowerCase().split(/\s+/).join(" ");
}

/** Checks word count, that every word is in the list, and the built-in checksum (catches most typos). */
export function checkRecoveryPhrase(input: string): { ok: true } | { ok: false; reason: string } {
  const phrase = normalizePhrase(input);
  const words = phrase === "" ? [] : phrase.split(" ");
  if (words.length !== WORD_COUNT) return { ok: false, reason: `expected ${WORD_COUNT} words, got ${words.length}` };
  const unknown = words.find((w) => !wordlist.includes(w));
  if (unknown) return { ok: false, reason: `"${unknown}" is not a recovery word` };
  if (!validateMnemonic(phrase, wordlist)) return { ok: false, reason: "words are in the wrong order or one is mistyped" };
  return { ok: true };
}

export interface RecoveryKeys {
  /** Wraps/unwraps the Vault Key. Non-extractable. */
  wrappingKey: CryptoKey;
  /** Sent to the server during recovery; the server stores only a hash of it. */
  authKey: Uint8Array;
}

/** Phrase → recovery keys. Same phrase always gives the same keys. */
export async function deriveRecoveryKeys(input: string): Promise<RecoveryKeys> {
  const check = checkRecoveryPhrase(input);
  if (!check.ok) throw new InvalidRecoveryPhraseError(check.reason);

  const entropy = mnemonicToEntropy(normalizePhrase(input), wordlist);
  try {
    const hkdfKey = await crypto.subtle.importKey("raw", entropy as BufferSource, "HKDF", false, [
      "deriveKey",
      "deriveBits",
    ]);
    const params = (info: Uint8Array): HkdfParams => ({
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(0),
      info: info as BufferSource,
    });

    const wrappingKey = await crypto.subtle.deriveKey(
      params(INFO_WRAP),
      hkdfKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"],
    );
    const authKey = new Uint8Array(await crypto.subtle.deriveBits(params(INFO_AUTH), hkdfKey, 256));
    return { wrappingKey, authKey };
  } finally {
    wipe(entropy);
  }
}