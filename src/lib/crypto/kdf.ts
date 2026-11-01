import { argon2id } from "hash-wasm";
import type { KdfParams } from "../types";
import { fromB64, randomBytes, toB64, utf8 } from "./encoding";

/** Settings for new accounts: 64 MiB memory, 3 passes. About 1 second on a mid-range phone. */
export const DEFAULT_KDF = {
  algorithm: "argon2id",
  memoryKiB: 64 * 1024,
  iterations: 3,
  parallelism: 1,
} as const;

/**
 * Floor the client will accept. KDF params come back from the server at login, so a
 * compromised server could send weak ones to make your password easier to crack.
 * The browser refuses anything below this.
 */
export const MIN_KDF = { memoryKiB: 19 * 1024, iterations: 2 } as const;

const MASTER_KEY_BYTES = 32;
const SALT_BYTES = 16;

/** Fresh params with a random salt, for sign-up or password change. */
export function newKdfParams(): KdfParams {
  return { ...DEFAULT_KDF, salt: toB64(randomBytes(SALT_BYTES)) };
}

export function assertKdfParamsSafe(p: KdfParams): void {
  if (p.algorithm !== "argon2id") throw new Error("Unsupported KDF algorithm");
  if (p.memoryKiB < MIN_KDF.memoryKiB || p.iterations < MIN_KDF.iterations) {
    throw new Error("KDF parameters are below the safe minimum");
  }
  if (p.parallelism < 1 || p.parallelism > 16) throw new Error("Invalid KDF parallelism");
  if (fromB64(p.salt).length < SALT_BYTES) throw new Error("KDF salt too short");
}

/**
 * Master password → 32-byte master key.
 * NFKC normalization makes the same password typed on different keyboards/OSes
 * (e.g. composed vs decomposed accented letters) produce the same key.
 */
export async function deriveMasterKey(password: string, params: KdfParams): Promise<Uint8Array> {
  assertKdfParamsSafe(params);
  if (password.length === 0) throw new Error("Master password is empty");
  return argon2id({
    password: utf8(password.normalize("NFKC")),
    salt: fromB64(params.salt),
    memorySize: params.memoryKiB,
    iterations: params.iterations,
    parallelism: params.parallelism,
    hashLength: MASTER_KEY_BYTES,
    outputType: "binary",
  });
}