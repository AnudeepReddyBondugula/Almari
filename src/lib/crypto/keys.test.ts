import { describe, expect, it } from "vitest";
import { randomBytes, toB64, utf8 } from "./encoding";
import { deriveSubKeys } from "./keys";

describe("deriveSubKeys", () => {
  const masterKey = randomBytes(32);

  it("gives the same auth key every time for the same master key", async () => {
    const a = await deriveSubKeys(masterKey);
    const b = await deriveSubKeys(masterKey);
    expect(a.authKey).toHaveLength(32);
    expect(toB64(a.authKey)).toBe(toB64(b.authKey));
  });

  it("auth key is different from the master key", async () => {
    const { authKey } = await deriveSubKeys(masterKey);
    expect(toB64(authKey)).not.toBe(toB64(masterKey));
  });

  it("re-derived encryption key decrypts what the first one encrypted", async () => {
    const first = await deriveSubKeys(masterKey);
    const iv = randomBytes(12) as BufferSource;
    const ct = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      first.encryptionKey,
      utf8("hello") as BufferSource,
    );

    const second = await deriveSubKeys(masterKey);
    const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, second.encryptionKey, ct);
    expect(new TextDecoder().decode(pt)).toBe("hello");
  });

  it("encryption key bytes cannot be exported", async () => {
    const { encryptionKey } = await deriveSubKeys(masterKey);
    expect(encryptionKey.extractable).toBe(false);
    await expect(crypto.subtle.exportKey("raw", encryptionKey)).rejects.toThrow();
  });

  it("a different master key gives a different auth key", async () => {
    const a = await deriveSubKeys(masterKey);
    const b = await deriveSubKeys(randomBytes(32));
    expect(toB64(a.authKey)).not.toBe(toB64(b.authKey));
  });

  it("rejects a master key of the wrong length", async () => {
    await expect(deriveSubKeys(randomBytes(16))).rejects.toThrow(/32 bytes/);
  });
});