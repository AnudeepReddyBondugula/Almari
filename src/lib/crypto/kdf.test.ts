import { describe, expect, it } from "vitest";
import { toB64 } from "./encoding";
import { deriveMasterKey, newKdfParams } from "./kdf";

describe("kdf", () => {
  const params = newKdfParams();

  it("derives a 32-byte key, the same every time for the same input", async () => {
    const a = await deriveMasterKey("correct horse battery staple", params);
    const b = await deriveMasterKey("correct horse battery staple", params);
    expect(a).toHaveLength(32);
    expect(toB64(a)).toBe(toB64(b));
  });

  it("changes completely with a different password or salt", async () => {
    const base = toB64(await deriveMasterKey("password-one", params));
    expect(toB64(await deriveMasterKey("password-two", params))).not.toBe(base);
    expect(toB64(await deriveMasterKey("password-one", newKdfParams()))).not.toBe(base);
  });

  it("treats composed and decomposed accents as the same password", async () => {
    const composed = "caf\u00e9"; // é as one character
    const decomposed = "cafe\u0301"; // e + combining accent
    expect(toB64(await deriveMasterKey(composed, params))).toBe(
      toB64(await deriveMasterKey(decomposed, params)),
    );
  });

  it("refuses weak params sent by a malicious server", async () => {
    await expect(deriveMasterKey("pw", { ...params, memoryKiB: 1024 })).rejects.toThrow(/minimum/);
    await expect(deriveMasterKey("pw", { ...params, iterations: 1 })).rejects.toThrow(/minimum/);
  });

  it("refuses an empty password", async () => {
    await expect(deriveMasterKey("", params)).rejects.toThrow(/empty/);
  });
});