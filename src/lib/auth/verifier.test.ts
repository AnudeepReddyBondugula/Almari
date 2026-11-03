import { randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { checkVerifier, makeVerifier } from "./verifier";

describe("verifier", () => {
  const authKey = new Uint8Array(randomBytes(32));

  it("accepts the right auth key", () => {
    expect(checkVerifier(authKey, makeVerifier(authKey))).toBe(true);
  });

  it("rejects a wrong auth key, even one bit off", () => {
    const v = makeVerifier(authKey);
    const almost = authKey.slice();
    almost[31] ^= 0x01;
    expect(checkVerifier(almost, v)).toBe(false);
  });

  it("never stores the auth key itself", () => {
    const v = makeVerifier(authKey);
    const asB64 = Buffer.from(authKey).toString("base64url");
    expect(v.hash).not.toBe(asB64);
    expect(JSON.stringify(v)).not.toContain(asB64);
  });

  it("same key, two sign-ups → different stored hashes (random salt)", () => {
    expect(makeVerifier(authKey).hash).not.toBe(makeVerifier(authKey).hash);
  });

  it("rejects keys of the wrong length", () => {
    expect(() => makeVerifier(new Uint8Array(16))).toThrow();
    expect(checkVerifier(new Uint8Array(16), makeVerifier(authKey))).toBe(false);
  });
});