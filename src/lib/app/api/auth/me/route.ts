import { requireSession } from "@/lib/auth/session";
import { handle } from "@/lib/http";

/** GET /api/auth/me — the pattern every protected route follows. */
export const GET = handle(async () => {
  const session = await requireSession();
  if (session instanceof Response) return session; // 401
  return Response.json({ userId: session.userId, username: session.username });
});