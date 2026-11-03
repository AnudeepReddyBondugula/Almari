import "server-only";
import { google, type drive_v3 } from "googleapis";
import { Readable } from "node:stream";
import { env } from "@/lib/env";

/**
 * Google Drive as Almari's database.
 *
 * Everything lives in the owner's hidden `appDataFolder`: it doesn't show up in the
 * Drive UI, and the `drive.appdata` scope means this app can ONLY touch that folder,
 * never the owner's personal files.
 *
 * The server only ever stores ciphertext and public-ish metadata (salts, KDF params,
 * auth verifiers). Plaintext secrets never reach this layer.
 */

let driveSingleton: drive_v3.Drive | undefined;

function drive(): drive_v3.Drive {
  if (driveSingleton) return driveSingleton;
  const { GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, GOOGLE_REFRESH_TOKEN } = env();
  const auth = new google.auth.OAuth2(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET);
  auth.setCredentials({ refresh_token: GOOGLE_REFRESH_TOKEN });
  driveSingleton = google.drive({ version: "v3", auth });
  return driveSingleton;
}

export interface StoredFile {
  id: string;
  name: string;
  /** Drive's revision counter — used for optimistic concurrency on vault writes. */
  version: string;
  modifiedTime: string;
}

const FIELDS = "id, name, version, modifiedTime";

function toStored(f: drive_v3.Schema$File): StoredFile {
  return { id: f.id!, name: f.name!, version: f.version!, modifiedTime: f.modifiedTime! };
}

/** Drive allows duplicate names, so callers must keep names unique (see docs/ARCHITECTURE.md). */
export async function findFile(name: string): Promise<StoredFile | null> {
  const escaped = name.replace(/\\/g, "\\\\").replace(/'/g, "\\'");
  const res = await drive().files.list({
    spaces: "appDataFolder",
    q: `name = '${escaped}' and trashed = false`,
    fields: `files(${FIELDS})`,
    pageSize: 2,
  });
  const files = res.data.files ?? [];
  if (files.length > 1) throw new Error(`Duplicate files named "${name}" in appDataFolder`);
  return files[0] ? toStored(files[0]) : null;
}

export async function readBytes(fileId: string): Promise<Buffer> {
  const res = await drive().files.get(
    { fileId, alt: "media" },
    { responseType: "arraybuffer" },
  );
  return Buffer.from(res.data as ArrayBuffer);
}

export async function readJson<T>(fileId: string): Promise<T> {
  return JSON.parse((await readBytes(fileId)).toString("utf8")) as T;
}

/** Create a new file. Fails if one with the same name already exists. */
export async function createFile(
  name: string,
  body: Buffer | string,
  mimeType = "application/octet-stream",
): Promise<StoredFile> {
  if (await findFile(name)) throw new Error(`File "${name}" already exists`);
  const res = await drive().files.create({
    requestBody: { name, parents: ["appDataFolder"] },
    media: { mimeType, body: Readable.from(Buffer.from(body)) },
    fields: FIELDS,
  });
  return toStored(res.data);
}

/**
 * Overwrite a file's contents. Pass `expectedVersion` to reject the write if someone
 * else (another device) updated the file since you last read it.
 */
export async function updateFile(
  fileId: string,
  body: Buffer | string,
  opts: { mimeType?: string; expectedVersion?: string } = {},
): Promise<StoredFile> {
  if (opts.expectedVersion) {
    const current = await drive().files.get({ fileId, fields: "version" });
    if (current.data.version !== opts.expectedVersion) {
      throw new VersionConflictError(current.data.version ?? "unknown");
    }
  }
  const res = await drive().files.update({
    fileId,
    media: { mimeType: opts.mimeType ?? "application/octet-stream", body: Readable.from(Buffer.from(body)) },
    fields: FIELDS,
  });
  return toStored(res.data);
}

export async function deleteFile(fileId: string): Promise<void> {
  await drive().files.delete({ fileId });
}

/** Cheap call used by /api/health to confirm the credentials work. */
export async function ping(): Promise<{ ok: true; fileCount: number }> {
  const res = await drive().files.list({ spaces: "appDataFolder", fields: "files(id)", pageSize: 100 });
  return { ok: true, fileCount: res.data.files?.length ?? 0 };
}

export class VersionConflictError extends Error {
  constructor(public currentVersion: string) {
    super("Vault was changed on another device. Reload and try again.");
    this.name = "VersionConflictError";
  }
}