/**
 * Almari crypto core — the only file the rest of the app should import from.
 * Everything here runs in the browser; the server never sees plaintext or keys.
 */
export { toB64, fromB64, utf8, fromUtf8, randomBytes, wipe } from "./encoding";
export { DEFAULT_KDF, MIN_KDF, newKdfParams, assertKdfParamsSafe, deriveMasterKey } from "./kdf";
export { deriveSubKeys, type SubKeys } from "./keys";
export { encryptBytes, decryptBytes, encryptJson, decryptJson, DecryptionError } from "./aes";
export { createVaultKey, unwrapVaultKey, rewrapVaultKey } from "./vaultKey";
export {
  generateRecoveryPhrase,
  normalizePhrase,
  checkRecoveryPhrase,
  deriveRecoveryKeys,
  InvalidRecoveryPhraseError,
  type RecoveryKeys,
} from "./recovery";