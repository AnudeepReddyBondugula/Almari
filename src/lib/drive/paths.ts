import "server-only";

/**
 * File naming inside appDataFolder. Usernames are normalized and restricted so
 * a name can never collide with another file type or break a Drive query.
 */
export const USERNAME_RE = /^[a-z0-9][a-z0-9_.-]{2,31}$/;

export function normalizeUsername(raw: string): string {
  return raw.trim().toLowerCase();
}

export function userFile(username: string): string {
  const u = normalizeUsername(username);
  if (!USERNAME_RE.test(u)) throw new Error("Invalid username");
  return `user.${u}.json`;
}

export function vaultFile(userId: string): string {
  if (!/^[A-Za-z0-9_-]{16,64}$/.test(userId)) throw new Error("Invalid userId");
  return `vault.${userId}.bin`;
}