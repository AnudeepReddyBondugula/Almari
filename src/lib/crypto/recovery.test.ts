import { wordlist } from "@scure/bip39/wordlists/english";
import { describe, expect, it } from "vitest";
import { DecryptionError, decryptJson, encryptJson } from "./aes";
import { toB64 } from "./encoding";
import {
  InvalidRecoveryPhraseError,
  checkRecoveryPhrase,
  deriveRecoveryKeys,
  generateRecoveryPhrase,
} from "./recovery";
import { createVaultKey, unwrapVaultKey } from "./vaultKey";

// Official BIP39 test vector: valid checksum.
const VALID = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
// Same words but last one changed: every word is real, checksum is wrong.
const BAD_CHECKSUM = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";

describe("recovery phrase", () => {
  it("generates 12 real words, different every time", () => {
    const a = generateRecoveryPhrase();
    const b = generateRecoveryPhrase();
    expect(a.split(" ")).toHaveLength(12);
    expect(a.split(" ").every((w) => wordlist.includes(w))).toBe(true);
    expect(a).not.toBe(b);
    expect(checkRecoveryPhrase(a)).toEqual({ ok: true });
  });

  it("accepts messy typing: capitals, extra spaces, line breaks", async () => {
    const messy = "  ABANDON abandon\nabandon   abandon abandon abandon\tabandon abandon abandon abandon abandon About ";
    expect(checkRecoveryPhrase(messy)).toEqual({ ok: true });
    const a = await deriveRecoveryKeys(messy);
    const b = await deriveRecoveryKeys(VALID);
    expect(toB64(a.authKey)).toBe(toB64(b.authKey));
  });

  it("catches a wrong word via the checksum", () => {
    const result = checkRecoveryPhrase(BAD_CHECKSUM);
    expect(result.ok).toBe(false);
  });

  it("names a word that isn't in the list", () => {
    const result = checkRecoveryPhrase(VALID.replace("about", "abuot"));
    expect(result).toEqual({ ok: false, reason: '"abuot" is not a recovery word' });
  });

  it("rejects the wrong number of words", () => {
    expect(checkRecoveryPhrase("abandon about").ok).toBe(false);
    expect(checkRecoveryPhrase("").ok).toBe(false);
  });

  it("deriveRecoveryKeys refuses an invalid phrase", async () => {
    await expect(deriveRecoveryKeys(BAD_CHECKSUM)).rejects.toThrow(InvalidRecoveryPhraseError);
  });

  it("same phrase gives the same keys; different phrase gives different keys", async () => {
    const phrase = generateRecoveryPhrase();
    const a = await deriveRecoveryKeys(phrase);
    const b = await deriveRecoveryKeys(phrase);
    const c = await deriveRecoveryKeys(generateRecoveryPhrase());
    expect(a.authKey).toHaveLength(32);
    expect(toB64(a.authKey)).toBe(toB64(b.authKey));
    expect(toB64(a.authKey)).not.toBe(toB64(c.authKey));
  });

  it("wrapping key is non-extractable", async () => {
    const { wrappingKey } = await deriveRecoveryKeys(VALID);
    expect(wrappingKey.extractable).toBe(false);
  });

  it("end to end: phrase typed later unlocks the vault", async () => {
    const passwordKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, [
      "encrypt",
      "decrypt",
    ]);
    const phrase = generateRecoveryPhrase();

    // Sign-up
    const signup = await deriveRecoveryKeys(phrase);
    const { vaultKey, wrapped } = await createVaultKey([passwordKey, signup.wrappingKey]);
    const vault = { items: [{ title: "Bank", password: "s3cret" }] };
    const encryptedVault = await encryptJson(vaultKey, vault, "vault");

    // Months later, password forgotten: user types the phrase in capitals
    const later = await deriveRecoveryKeys(phrase.toUpperCase());
    const unlocked = await unwrapVaultKey(wrapped[1], later.wrappingKey);
    expect(await decryptJson(unlocked, encryptedVault, "vault")).toEqual(vault);

    // A different phrase can't open it
    const wrong = await deriveRecoveryKeys(generateRecoveryPhrase());
    await expect(unwrapVaultKey(wrapped[1], wrong.wrappingKey)).rejects.toThrow(DecryptionError);
  });
});