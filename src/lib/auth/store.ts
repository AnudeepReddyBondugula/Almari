import "server-only";
import { createFile, findFile, readJson, updateFile } from "../drive/client";
import { userFile } from "../drive/paths";
import type { UserRecord } from "../types";

/**
 * Where user records live. The auth logic only talks to this interface, so tests can
 * use a fast in-memory version and the real app uses Google Drive.
 */
export interface UserStore {
  get(username: string): Promise<UserRecord | null>;
  /** Must fail with UsernameTakenError if the username already exists. */
  create(record: UserRecord): Promise<void>;
  update(record: UserRecord): Promise<void>;
}

export class UsernameTakenError extends Error {
  constructor() {
    super("That username is already taken");
    this.name = "UsernameTakenError";
  }
}

export const driveUserStore: UserStore = {
  async get(username) {
    const file = await findFile(userFile(username));
    return file ? readJson<UserRecord>(file.id) : null;
  },
  async create(record) {
    const name = userFile(record.username);
    if (await findFile(name)) throw new UsernameTakenError();
    await createFile(name, JSON.stringify(record), "application/json");
  },
  async update(record) {
    const file = await findFile(userFile(record.username));
    if (!file) throw new Error("User not found");
    await updateFile(file.id, JSON.stringify(record), { mimeType: "application/json" });
  },
};

/** For tests only. */
export function createMemoryUserStore(): UserStore & { size(): number } {
  const users = new Map<string, UserRecord>();
  return {
    async get(username) {
      const r = users.get(username);
      return r ? structuredClone(r) : null;
    },
    async create(record) {
      if (users.has(record.username)) throw new UsernameTakenError();
      users.set(record.username, structuredClone(record));
    },
    async update(record) {
      if (!users.has(record.username)) throw new Error("User not found");
      users.set(record.username, structuredClone(record));
    },
    size: () => users.size,
  };
}