import { SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { SESSION_TTL_SECONDS, signSession, verifySession } from "./token";

const SECRET = "a-test-secret-that-is-long-enough-123456";
const session = { userId: "abc123abc123abc123abc1", username: "anudeep" };

describe("session token", () => {
  it("round-trips a valid session", async () => {
    const token = await signSession(session, SECRET);
    expect(await verifySession(token, SECRET)).toEqual(session);
  });

  it("rejects a token signed with a different secret (forgery)", async () => {
    const forged = await signSession(session, "attacker-guessed-secret-xxxxxxxxxxxx");
    expect(await verifySession(forged, SECRET)).toBeNull();
  });

  it("rejects a token whose contents were edited", async () => {
    const token = await signSession(session, SECRET);
    const [header, , signature] = token.split(".");
    const evilPayload = Buffer.from(
      JSON.stringify({ sub: "someone-else", username: "victim", iss: "almari", aud: "almari-web", exp: 9999999999 }),
    ).toString("base64url");
    expect(await verifySession(`${header}.${evilPayload}.${signature}`, SECRET)).toBeNull();
  });

  it("rejects an expired token", async () => {
    const longAgo = Math.floor(Date.now() / 1000) - SESSION_TTL_SECONDS - 60;
    const token = await signSession(session, SECRET, longAgo);
    expect(await verifySession(token, SECRET)).toBeNull();
  });

  it('rejects the classic "alg: none" trick', async () => {
    const header = Buffer.from(JSON.stringify({ alg: "none" })).toString("base64url");
    const payload = Buffer.from(
      JSON.stringify({ sub: session.userId, username: "anudeep", iss: "almari", aud: "almari-web" }),
    ).toString("base64url");
    expect(await verifySession(`${header}.${payload}.`, SECRET)).toBeNull();
  });

  it("rejects a valid token from some other app using the same secret", async () => {
    const other = await new SignJWT({ username: "anudeep" })
      .setProtectedHeader({ alg: "HS256" })
      .setSubject(session.userId)
      .setIssuer("other-app")
      .setExpirationTime("1h")
      .sign(new TextEncoder().encode(SECRET));
    expect(await verifySession(other, SECRET)).toBeNull();
  });

  it("missing or garbage token → null", async () => {
    expect(await verifySession(undefined, SECRET)).toBeNull();
    expect(await verifySession("not.a.jwt", SECRET)).toBeNull();
  });
});