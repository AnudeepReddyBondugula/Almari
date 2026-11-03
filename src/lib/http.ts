import "server-only";
import type { z } from "zod";

/** A small error type route handlers can throw; `handle()` turns it into a JSON response. */
export class HttpError extends Error {
  constructor(public status: number, public code: string) {
    super(code);
  }
}

/**
 * Read and validate a JSON body.
 *
 * Requiring `Content-Type: application/json` is a CSRF defence: a malicious website can
 * make your browser submit an HTML form to Almari, but a plain form can't send JSON.
 * Sending JSON cross-site needs the browser's permission check (CORS), which we never grant.
 */
export async function readBody<S extends z.ZodType>(request: Request, schema: S): Promise<z.infer<S>> {
  if (!request.headers.get("content-type")?.toLowerCase().startsWith("application/json")) {
    throw new HttpError(415, "JSON_REQUIRED");
  }
  let raw: unknown;
  try {
    raw = await request.json();
  } catch {
    throw new HttpError(400, "INVALID_JSON");
  }
  const parsed = schema.safeParse(raw);
  if (!parsed.success) throw new HttpError(400, "INVALID_INPUT");
  return parsed.data;
}

/** Wrap a route handler so errors become clean JSON, never a stack trace sent to the browser. */
export function handle(fn: (request: Request) => Promise<Response>) {
  return async (request: Request): Promise<Response> => {
    try {
      return await fn(request);
    } catch (err) {
      if (err instanceof HttpError) return Response.json({ error: err.code }, { status: err.status });
      console.error("[api]", err);
      return Response.json({ error: "SERVER_ERROR" }, { status: 500 });
    }
  };
}