import { authConfig } from "@/lib/auth/config";
import { registerBody } from "@/lib/auth/schemas";
import { register } from "@/lib/auth/service";
import { startSession } from "@/lib/auth/session";
import { driveUserStore } from "@/lib/auth/store";
import { handle, readBody } from "@/lib/http";

const STATUS = { INVITE_REQUIRED: 403, USERNAME_TAKEN: 409, WEAK_KDF: 400 } as const;

/**
 * POST /api/auth/register
 * Body: username, kdf, authKey, recoveryAuthKey, both wrapped Vault Keys (+ inviteCode).
 * Everything secret was already turned into keys/ciphertext by the browser.
 */
export const POST = handle(async (request) => {
  const input = await readBody(request, registerBody);
  const result = await register(driveUserStore, authConfig(), input);
  if (!result.ok) return Response.json({ error: result.error }, { status: STATUS[result.error] });

  const { userId, username } = result.user;
  await startSession({ userId, username });
  return Response.json({ userId, username }, { status: 201 });
});