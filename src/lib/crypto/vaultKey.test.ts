import { describe, expect, it } from "vitest";
import { DecryptionError, decryptJson, encryptBytes, encryptJson } from "./aes";
import { fromB64, randomBytes, toB64 } from "./encoding";
import { createVaultKey, rewrapVaultKey, unwrapVaultKey } from "./vaultKey";

/** Stand-in for the password key (1c) and recovery key (1f). */
async function newWrappingKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

const vault = { items: [{ title: "Gmail", password: "p@ss" }] };

describe("Vault Key", () => {
  it("any one wrapper unlocks the same vault", async () => {
    const passwordKey = await newWrappingKey();
    const recoveryKey = await newWrappingKey();
    const { vaultKey, wrapped } = await createVaultKey([passwordKey, recoveryKey]);
    const encryptedVault = await encryptJson(vaultKey, vault, "vault");

    const viaPassword = await unwrapVaultKey(wrapped[0], passwordKey);
    const viaRecovery = await unwrapVaultKey(wrapped[1], recoveryKey);
    expect(await decryptJson(viaPassword, encryptedVault, "vault")).toEqual(vault);
    expect(await decryptJson(viaRecovery, encryptedVault, "vault")).toEqual(vault);
  });

  it("the two wrapped copies look nothing alike", async () => {
    const { wrapped } = await createVaultKey([await newWrappingKey(), await newWrappingKey()]);
    expect(wrapped[0].ciphertext).not.toBe(wrapped[1].ciphertext);
  });

  it("wrong wrapping key cannot unwrap", async () => {
    const { wrapped } = await createVaultKey([await newWrappingKey()]);
    await expect(unwrapVaultKey(wrapped[0], await newWrappingKey())).rejects.toThrow(DecryptionError);
  });

  it("a tampered wrapped key is rejected", async () => {
    const passwordKey = await newWrappingKey();
    const { wrapped } = await createVaultKey([passwordKey]);
    const bytes = fromB64(wrapped[0].ciphertext);
    bytes[5] ^= 0x80;
    const tampered = { ...wrapped[0], ciphertext: toB64(bytes) };
    await expect(unwrapVaultKey(tampered, passwordKey)).rejects.toThrow(DecryptionError);
  });

  it("a normal encrypted blob can't be passed off as a wrapped Vault Key", async () => {
    const passwordKey = await newWrappingKey();
    const fake = await encryptBytes(passwordKey, randomBytes(32), "something-else");
    await expect(unwrapVaultKey(fake, passwordKey)).rejects.toThrow(DecryptionError);
  });

  it("password change: re-wrap only, old vault still opens", async () => {
    const oldPasswordKey = await newWrappingKey();
    const { vaultKey, wrapped } = await createVaultKey([oldPasswordKey]);
    const encryptedVault = await encryptJson(vaultKey, vault, "vault"); // encrypted BEFORE the change

    const newPasswordKey = await newWrappingKey();
    const newWrapped = await rewrapVaultKey(wrapped[0], oldPasswordKey, newPasswordKey);

    const unlocked = await unwrapVaultKey(newWrapped, newPasswordKey);
    expect(await decryptJson(unlocked, encryptedVault, "vault")).toEqual(vault);
    await expect(unwrapVaultKey(newWrapped, oldPasswordKey)).rejects.toThrow(DecryptionError);
  });

  it("the Vault Key can never be read out by JavaScript", async () => {
    const passwordKey = await newWrappingKey();
    const { vaultKey, wrapped } = await createVaultKey([passwordKey]);
    const unlocked = await unwrapVaultKey(wrapped[0], passwordKey);
    for (const key of [vaultKey, unlocked]) {
      expect(key.extractable).toBe(false);
      await expect(crypto.subtle.exportKey("raw", key)).rejects.toThrow();
    }
  });

  it("needs at least one wrapping key", async () => {
    await expect(createVaultKey([])).rejects.toThrow(/at least one/);
  });
});