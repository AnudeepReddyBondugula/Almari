import { describe, expect, it } from "vitest";
import { DecryptionError, decryptBytes, decryptJson, encryptBytes, encryptJson } from "./aes";
import { fromB64, fromUtf8, toB64, utf8 } from "./encoding";

async function newKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}

describe("AES-GCM", () => {
  it("decrypts back to the original", async () => {
    const key = await newKey();
    const blob = await encryptBytes(key, utf8("my secret"));
    expect(fromUtf8(await decryptBytes(key, blob))).toBe("my secret");
  });

  it("ciphertext is plaintext length + 16-byte tag", async () => {
    const key = await newKey();
    const blob = await encryptBytes(key, utf8("12345"));
    expect(fromB64(blob.ciphertext)).toHaveLength(5 + 16);
  });

  it("same message encrypted twice looks completely different (fresh IV)", async () => {
    const key = await newKey();
    const a = await encryptBytes(key, utf8("same"));
    const b = await encryptBytes(key, utf8("same"));
    expect(a.iv).not.toBe(b.iv);
    expect(a.ciphertext).not.toBe(b.ciphertext);
  });

  it("detects a single flipped bit", async () => {
    const key = await newKey();
    const blob = await encryptBytes(key, utf8("transfer 100 rupees"));
    const bytes = fromB64(blob.ciphertext);
    bytes[0] ^= 0x01; // flip one bit
    await expect(decryptBytes(key, { ...blob, ciphertext: toB64(bytes) })).rejects.toThrow(DecryptionError);
  });

  it("fails with the wrong key", async () => {
    const blob = await encryptBytes(await newKey(), utf8("secret"));
    await expect(decryptBytes(await newKey(), blob)).rejects.toThrow(DecryptionError);
  });

  it("fails if the context label doesn't match", async () => {
    const key = await newKey();
    const blob = await encryptBytes(key, utf8("alice's vault"), "vault:alice");
    expect(fromUtf8(await decryptBytes(key, blob, "vault:alice"))).toBe("alice's vault");
    await expect(decryptBytes(key, blob, "vault:bob")).rejects.toThrow(DecryptionError);
  });

  it("handles empty input", async () => {
    const key = await newKey();
    const blob = await encryptBytes(key, new Uint8Array(0));
    expect(await decryptBytes(key, blob)).toHaveLength(0);
  });

  it("round-trips JSON", async () => {
    const key = await newKey();
    const vault = { items: [{ title: "Gmail", password: "p@ss🔐" }] };
    expect(await decryptJson(key, await encryptJson(key, vault))).toEqual(vault);
  });
});