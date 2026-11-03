import { beforeEach, describe, expect, it } from "vitest";
import {
  createVaultKey,
  deriveMasterKey,
  deriveRecoveryKeys,
  deriveSubKeys,
  generateRecoveryPhrase,
  newKdfParams,
  randomBytes,
  toB64,
  unwrapVaultKey,
} from "../crypto";
import { registerBody, type RegisterInput } from "./schemas";
import { login, prelogin, register, type AuthConfig } from "./service";
import { createMemoryUserStore } from "./store";

const cfg: AuthConfig = { serverSecret: "server-secret-for-tests-0123456789abcdef" };

/** A sign-up body with random keys — enough for server-side rules that never run Argon2. */
async function fakeSignup(username: string): Promise<RegisterInput> {
  const k = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const { wrapped } = await createVaultKey([k, k]);
  return {
    username,
    kdf: newKdfParams(),
    authKey: toB64(randomBytes(32)),
    recoveryAuthKey: toB64(randomBytes(32)),
    wrappedVaultKeyByPassword: wrapped[0],
    wrappedVaultKeyByRecovery: wrapped[1],
  };
}

describe("auth service", () => {
  let store: ReturnType<typeof createMemoryUserStore>;
  beforeEach(() => {
    store = createMemoryUserStore();
  });

  it("register → login with the same auth key works; wrong key fails", async () => {
    const body = await fakeSignup("anudeep");
    expect((await register(store, cfg, body)).ok).toBe(true);

    const ok = await login(store, { username: "anudeep", authKey: body.authKey });
    expect(ok?.username).toBe("anudeep");
    expect(ok?.wrappedVaultKeyByPassword).toEqual(body.wrappedVaultKeyByPassword);

    expect(await login(store, { username: "anudeep", authKey: toB64(randomBytes(32)) })).toBeNull();
  });

  it("wrong username and wrong password give the exact same answer", async () => {
    const body = await fakeSignup("anudeep");
    await register(store, cfg, body);
    const wrongPassword = await login(store, { username: "anudeep", authKey: toB64(randomBytes(32)) });
    const noSuchUser = await login(store, { username: "nobody", authKey: body.authKey });
    expect(wrongPassword).toBeNull();
    expect(noSuchUser).toBeNull();
  });

  it("stored record contains no auth keys", async () => {
    const body = await fakeSignup("anudeep");
    await register(store, cfg, body);
    const stored = JSON.stringify(await store.get("anudeep"));
    expect(stored).not.toContain(body.authKey);
    expect(stored).not.toContain(body.recoveryAuthKey);
  });

  it("username can only be taken once", async () => {
    await register(store, cfg, await fakeSignup("anudeep"));
    expect(await register(store, cfg, await fakeSignup("anudeep"))).toEqual({ ok: false, error: "USERNAME_TAKEN" });
    expect(store.size()).toBe(1);
  });

  it("server refuses to STORE weak KDF settings", async () => {
    const body = await fakeSignup("anudeep");
    body.kdf = { ...body.kdf, memoryKiB: 1024 };
    expect(await register(store, cfg, body)).toEqual({ ok: false, error: "WEAK_KDF" });
  });

  it("invite code gate", async () => {
    const gated = { ...cfg, inviteCode: "family-2026" };
    expect(await register(store, gated, await fakeSignup("a1b"))).toEqual({ ok: false, error: "INVITE_REQUIRED" });
    expect(await register(store, gated, { ...(await fakeSignup("a2b")), inviteCode: "wrong" })).toMatchObject({ ok: false });
    expect((await register(store, gated, { ...(await fakeSignup("a3b")), inviteCode: "family-2026" })).ok).toBe(true);
  });

  it("prelogin: real user gets real settings; unknown user gets fake but stable ones", async () => {
    const body = await fakeSignup("anudeep");
    await register(store, cfg, body);
    expect(await prelogin(store, cfg, "anudeep")).toEqual(body.kdf);

    const fake1 = await prelogin(store, cfg, "ghost");
    const fake2 = await prelogin(store, cfg, "ghost");
    const other = await prelogin(store, cfg, "ghost2");
    expect(fake1).toEqual(fake2); // asking twice can't reveal it's fake
    expect(fake1.salt).not.toBe(other.salt);
    expect(Object.keys(fake1).sort()).toEqual(Object.keys(body.kdf).sort()); // same shape as real
  });

  it("schema normalizes usernames and rejects junk", () => {
    expect(registerBody.shape.username.parse("  Anudeep ")).toBe("anudeep");
    expect(registerBody.shape.username.safeParse("a").success).toBe(false);
    expect(registerBody.shape.username.safeParse("../etc/passwd").success).toBe(false);
    expect(registerBody.shape.authKey.safeParse("short").success).toBe(false);
  });

  it("full story with REAL browser crypto: sign up, then log in from another device", async () => {
    const password = "my long master password";

    // ── Browser, sign-up ──
    const kdf = newKdfParams();
    const signupKeys = await deriveSubKeys(await deriveMasterKey(password, kdf));
    const recovery = await deriveRecoveryKeys(generateRecoveryPhrase());
    const { wrapped } = await createVaultKey([signupKeys.encryptionKey, recovery.wrappingKey]);
    const result = await register(store, cfg, {
      username: "anudeep",
      kdf,
      authKey: toB64(signupKeys.authKey),
      recoveryAuthKey: toB64(recovery.authKey),
      wrappedVaultKeyByPassword: wrapped[0],
      wrappedVaultKeyByRecovery: wrapped[1],
    });
    expect(result.ok).toBe(true);

    // ── Another browser, login: knows only username + password ──
    const settings = await prelogin(store, cfg, "anudeep");
    const loginKeys = await deriveSubKeys(await deriveMasterKey(password, settings));
    const session = await login(store, { username: "anudeep", authKey: toB64(loginKeys.authKey) });
    expect(session).not.toBeNull();

    // The lockbox the server sent back opens with the re-derived key
    const vaultKey = await unwrapVaultKey(session!.wrappedVaultKeyByPassword, loginKeys.encryptionKey);
    expect(vaultKey.type).toBe("secret");
  });
});