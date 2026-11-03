import "server-only";
import { z } from "zod";

/**
 * Server-side environment, validated once at first use.
 * Importing this from a client component fails the build ("server-only"),
 * so Drive credentials can never leak into the browser bundle.
 */
const schema = z.object({
  GOOGLE_CLIENT_ID: z.string().min(1),
  GOOGLE_CLIENT_SECRET: z.string().min(1),
  GOOGLE_REFRESH_TOKEN: z.string().min(1),
  SESSION_SECRET: z.string().min(32, "SESSION_SECRET must be at least 32 characters"),
  /** Optional. If set, sign-up requires this code. Strongly recommended on a public URL. */
  INVITE_CODE: z.preprocess((v) => (v === "" ? undefined : v), z.string().min(8).optional()),
});

export type Env = z.infer<typeof schema>;

let cached: Env | undefined;

export function env(): Env {
  if (cached) return cached;
  const parsed = schema.safeParse(process.env);
  if (!parsed.success) {
    const missing = parsed.error.issues.map((i) => i.path.join(".")).join(", ");
    throw new Error(`Invalid or missing environment variables: ${missing}. See .env.example.`);
  }
  cached = parsed.data;
  return cached;
}