/**
 * Byte helpers shared by the crypto module.
 * Works in browsers and in Node 20+ (both have btoa/atob, TextEncoder and Web Crypto).
 */

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

/** String → UTF-8 bytes. */
export function utf8(text: string): Uint8Array {
  return encoder.encode(text);
}

/** UTF-8 bytes → string. Throws on invalid UTF-8 instead of silently inserting '�'. */
export function fromUtf8(bytes: Uint8Array): string {
  return decoder.decode(bytes);
}

/** Bytes → base64url (URL-safe, no padding). Used for everything we store or send. */
export function toB64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** base64url → bytes. Rejects anything that isn't valid base64url. */
export function fromB64(b64: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(b64)) throw new Error("Invalid base64url string");
  const padded = b64.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((b64.length + 3) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** Cryptographically secure random bytes (salts, IVs, the Vault Key). Never use Math.random for these. */
export function randomBytes(length: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(length));
}

/** Best-effort wipe of key material once we're done with it. */
export function wipe(bytes: Uint8Array): void {
  bytes.fill(0);
}