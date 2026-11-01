import { describe, expect, it } from "vitest";
import { fromB64, fromUtf8, randomBytes, toB64, utf8 } from "./encoding";

describe("encoding", () => {
  it("round-trips base64url for every length 0–64", () => {
    for (let len = 0; len <= 64; len++) {
      const bytes = randomBytes(len);
      expect(fromB64(toB64(bytes))).toEqual(bytes);
    }
  });

  it("produces URL-safe output with no padding", () => {
    const b64 = toB64(new Uint8Array([0xfb, 0xff, 0xfe]));
    expect(b64).toBe("-__-");
    expect(b64).not.toMatch(/[+/=]/);
  });

  it("rejects invalid base64url", () => {
    expect(() => fromB64("abc+def")).toThrow();
    expect(() => fromB64("abc=")).toThrow();
  });

  it("round-trips UTF-8 including Telugu and emoji", () => {
    const text = "అల్మారి 🔐 vault";
    expect(fromUtf8(utf8(text))).toBe(text);
  });

  it("gives different random bytes each call", () => {
    expect(toB64(randomBytes(16))).not.toBe(toB64(randomBytes(16)));
  });
});