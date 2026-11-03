import { loginBody } from "@/lib/auth/schemas";
import { login } from "@/lib/auth/service";
import { startSession } from "@/lib/auth/session";
import { driveUserStore } from "@/lib/auth/store";
import { handle, readBody } from "@/lib/http";

/**
 * POST /api/auth/login   { username, authKey }
 * → 200 { userId, username, wrappedVaultKeyByPassword } + session cookie
 * → 401 for wrong username OR wrong password (same message on purpose)
 */
export const POST = handle(async (request) => {
  const input = await readBody(request, loginBody);
  const result = await login(driveUserStore, input);
  if (!result) return Response.json({ error: "INVALID_CREDENTIALS" }, { status: 401 });

  await startSession({ userId: result.userId, username: result.username });
  return Response.json(result);
});