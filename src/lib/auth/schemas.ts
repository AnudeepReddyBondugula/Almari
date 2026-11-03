import { z } from "zod";
import { USERNAME_RE } from "../drive/paths";

/**
 * Shapes of what the browser is allowed to send. Anything else is rejected before
 * our code touches it — the server must never trust input just because our own
 * frontend "would never send that".
 */

/** base64url text with a length limit, so nobody can upload a 50 MB "salt". */
const b64 = (maxChars: number) =>
  z.string().min(1).max(maxChars).regex(/^[A-Za-z0-9_-]+$/, "must be base64url");

/** Exactly 32 bytes = 43 base64url characters. */
const key32 = z.string().regex(/^[A-Za-z0-9_-]{43}$/, "must be a 32-byte base64url key");

export const usernameSchema = z
  .string()
  .trim()
  .toLowerCase()
  .regex(USERNAME_RE, "3–32 characters: lowercase letters, digits, dot, dash, underscore");

export const kdfSchema = z.object({
  algorithm: z.literal("argon2id"),
  // Upper limits stop a bad sign-up from storing settings that would freeze any browser
  // that later logs in (1 GiB memory, 20 passes).
  memoryKiB: z.number().int().max(1024 * 1024),
  iterations: z.number().int().max(20),
  parallelism: z.number().int().min(1).max(16),
  salt: b64(64),
});

export const encryptedBlobSchema = z.object({
  iv: b64(32),
  ciphertext: b64(512),
});

export const preloginBody = z.object({ username: usernameSchema });

export const registerBody = z.object({
  username: usernameSchema,
  inviteCode: z.string().max(200).optional(),
  kdf: kdfSchema,
  authKey: key32,
  recoveryAuthKey: key32,
  wrappedVaultKeyByPassword: encryptedBlobSchema,
  wrappedVaultKeyByRecovery: encryptedBlobSchema,
});

export const loginBody = z.object({
  username: usernameSchema,
  authKey: key32,
});

export type RegisterInput = z.infer<typeof registerBody>;
export type LoginInput = z.infer<typeof loginBody>;