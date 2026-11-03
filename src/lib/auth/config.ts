import "server-only";
import { env } from "../env";
import type { AuthConfig } from "./service";

export function authConfig(): AuthConfig {
  const e = env();
  return { serverSecret: e.SESSION_SECRET, inviteCode: e.INVITE_CODE };
}