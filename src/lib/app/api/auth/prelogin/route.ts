import { authConfig } from "@/lib/auth/config";
import { preloginBody } from "@/lib/auth/schemas";
import { prelogin } from "@/lib/auth/service";
import { driveUserStore } from "@/lib/auth/store";
import { handle, readBody } from "@/lib/http";

/**
 * POST /api/auth/prelogin   { username }  →  { kdf }
 * POST (not GET) so usernames don't end up in URLs and server logs.
 */
export const POST = handle(async (request) => {
  const { username } = await readBody(request, preloginBody);
  const kdf = await prelogin(driveUserStore, authConfig(), username);
  return Response.json({ kdf });
});