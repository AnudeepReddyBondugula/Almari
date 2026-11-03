import "server-only";
import { cookies } from "next/headers";
import { env } from "../env";
import { SESSION_TTL_SECONDS, signSession, verifySession, type Session } from "./token";

/**
 * The session lives in a cookie with these protections:
 *  - httpOnly:  JavaScript on the page can't read it, so an injected script can't steal it.
 *  - secure:    only sent over HTTPS (relaxed on localhost so `npm run dev` works).
 *  - sameSite:  "strict" — other websites can't make your browser send it to Almari.
 */
const COOKIE = "almari_session";

export async function startSession(session: Session): Promise<void> {
  const token = await signSession(session, env().SESSION_SECRET);
  (await cookies()).set(COOKIE, token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/",
    maxAge: SESSION_TTL_SECONDS,
  });
}

export async function endSession(): Promise<void> {
  (await cookies()).delete(COOKIE);
}

export async function getSession(): Promise<Session | null> {
  return verifySession((await cookies()).get(COOKIE)?.value, env().SESSION_SECRET);
}

/**
 * Use at the top of every protected route handler:
 *
 *   const session = await requireSession();
 *   if (session instanceof Response) return session;   // 401, stop here
 */
export async function requireSession(): Promise<Session | Response> {
  const session = await getSession();
  return session ?? Response.json({ error: "NOT_SIGNED_IN" }, { status: 401 });
}