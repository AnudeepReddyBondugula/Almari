import "server-only";
import { SignJWT, jwtVerify } from "jose";

/**
 * Session tokens: a signed note saying "this browser logged in as <userId> until <time>".
 *
 * Signed with HMAC-SHA256 using SESSION_SECRET. Anyone can READ the note (it's only
 * base64), but nobody can CHANGE it or forge a new one without the secret — the
 * signature would no longer match.
 *
 * It holds no keys and no vault data. A stolen token lets someone download your
 * ENCRYPTED vault, which they still can't open without your master password.
 */

export const SESSION_TTL_SECONDS = 8 * 60 * 60; // 8 hours
const ISSUER = "almari";
const AUDIENCE = "almari-web";

export interface Session {
  userId: string;
  username: string;
}

const keyFrom = (secret: string) => new TextEncoder().encode(secret);

export async function signSession(session: Session, secret: string, nowSeconds = Math.floor(Date.now() / 1000)) {
  return new SignJWT({ username: session.username })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(session.userId)
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setIssuedAt(nowSeconds)
    .setExpirationTime(nowSeconds + SESSION_TTL_SECONDS)
    .sign(keyFrom(secret));
}

/** Returns the session, or null if the token is missing, forged, tampered with, or expired. */
export async function verifySession(token: string | undefined, secret: string): Promise<Session | null> {
  if (!token) return null;
  try {
    const { payload } = await jwtVerify(token, keyFrom(secret), {
      issuer: ISSUER,
      audience: AUDIENCE,
      algorithms: ["HS256"], // never accept "none" or any other algorithm
    });
    if (typeof payload.sub !== "string" || typeof payload.username !== "string") return null;
    return { userId: payload.sub, username: payload.username };
  } catch {
    return null;
  }
}