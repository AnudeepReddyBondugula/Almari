import { endSession } from "@/lib/auth/session";
import { handle } from "@/lib/http";

/** POST /api/auth/logout — deletes the session cookie on this browser. */
export const POST = handle(async () => {
  await endSession();
  return new Response(null, { status: 204 });
});