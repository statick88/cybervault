/**
 * Release path, end to end (service-worker side).
 *
 * Every hop of the chain the audit called "present but unreachable" is driven
 * through the real message listener the worker registers — not a regex over
 * `auditor.ts`, and not a stub of its internals:
 *
 *   UNLOCK_VAULT             → session VEK written, status reports unlocked
 *   AUTHOR_CREDENTIAL        → record + index written (the store's only writer)
 *   LIST_CREDENTIALS_FOR_…   → non-secret candidate *   RELEASE_CREDENTIAL      → plaintext secret for the bound origin only
 *   LOCK_VAULT               → VEK gone, release refused, credential store intact
 *
 * The previous version of this file asserted those properties by reading the
 * source as text. Source assertions pin the SPELLING of a fix, not its effect:
 * a `remove()` that resolves without deleting, a VEK written under a different
 * key, or an authoring handler that validates and then persists nothing would
 * all still match. Each of those is a live defect, and each of these steps
 * fails on it instead.
 */

jest.setTimeout(120_000);

import type { BackgroundMessage } from "../../src/background/message-types";

type Listener = (
  message: unknown,
  sender: unknown,
  sendResponse: (reply: unknown) => void,
) => boolean;

interface Reply {
  ok: boolean;
  data?: unknown;
  error?: string;
}

/* ------------------------------------------------------------------ */
/*  chrome mock — local and session areas are separate stores          */
/* ------------------------------------------------------------------ */

interface Area {
  get: (keys: string | string[]) => Promise<Record<string, unknown>>;
  set: (items: Record<string, unknown>) => Promise<void>;
  remove: (keys: string | string[]) => Promise<void>;
  clear: () => Promise<void>;
}

function createArea(store: Map<string, unknown>): Area {
  return {
    get: async (keys) => {
      const list = Array.isArray(keys) ? keys : [keys];
      const out: Record<string, unknown> = {};
      for (const k of list) if (store.has(k)) out[k] = store.get(k);
      return out;
    },
    set: async (items) => {
      for (const [k, v] of Object.entries(items)) store.set(k, v);
    },
    remove: async (keys) => {
      const list = Array.isArray(keys) ? keys : [keys];
      for (const k of list) store.delete(k);
    },
    clear: async () => store.clear(),
  };
}

const localStore = new Map<string, unknown>();
const sessionStore = new Map<string, unknown>();
const local = createArea(localStore);
const session = createArea(sessionStore);

let onMessage: Listener | null = null;

(globalThis as unknown as { chrome: unknown }).chrome = {
  storage: { local, session },
  runtime: {
    onMessage: { addListener: (fn: Listener) => (onMessage = fn) },
    onInstalled: { addListener: () => undefined },
  },
  tabs: { query: async () => [] },
  alarms: { create: () => undefined, onAlarm: { addListener: () => undefined } },
};

afterAll(() => {
  delete (globalThis as unknown as { chrome?: unknown }).chrome;
});

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

const RECORDS = "cybervault_cred_records";
const INDEX = "cybervault_cred_index";
const VEK = "cybervault_vek";
const SESSION_KEY = "cybervault_session_key";
const UNLOCK_STATE = "cybervault_unlock_state";

const VAULT_ID = "vault-e2e";
const PASSPHRASE = "correct horse battery staple";
const ORIGIN = "https://github.com";
const FOREIGN = "https://evil.example";
const USERNAME = "octocat";
const PASSWORD = "s3cret-in-the-store";

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

/** Send one message through the listener the worker actually registered. */
function dispatch(message: BackgroundMessage): Promise<Reply> {
  if (!onMessage) return Promise.reject(new Error("worker listener not registered"));
  return new Promise((resolve) => {
    onMessage!(message, {}, (reply) => resolve(reply as Reply));
  });
}

function release(credentialId: string, origin = ORIGIN): Promise<Reply> {
  return dispatch({
    type: "RELEASE_CREDENTIAL",
    credentialId,
    origin,
    operation: "AUTOFILL",
    documentOrigin: origin,
    topLevelOrigin: origin,
    isFramed: false,
  });
}

async function unlock(): Promise<Reply> {
  return dispatch({ type: "UNLOCK_VAULT", vaultId: VAULT_ID, passphrase: PASSPHRASE });
}

async function ensureUnlocked(): Promise<void> {
  const status = await dispatch({ type: "CHECK_VAULT_STATUS" });
  if (status.ok && (status.data as { unlocked?: boolean } | undefined)?.unlocked) return;
  const result = await unlock();
  expect(result.ok).toBe(true);
}

/** Author once; later tests reuse the same record so PBKDF2 runs are few. */
async function ensureAuthored(): Promise<string> {
  await ensureUnlocked();
  const records = localStore.get(RECORDS) as Record<string, unknown> | undefined;
  const existing = records ? Object.keys(records)[0] : undefined;
  if (existing) return existing;

  const authored = await dispatch({
    type: "AUTHOR_CREDENTIAL",
    payload: { origin: ORIGIN, username: USERNAME, password: PASSWORD, title: "GitHub" },
  });
  if (!authored.ok) throw new Error(`authoring failed: ${authored.error}`);
  return (authored.data as { id: string }).id;
}

/* ------------------------------------------------------------------ */
/*  The chain                                                          */
/* ------------------------------------------------------------------ */

describe("release path end to end", () => {
  beforeAll(async () => {
    await import("../../src/background/auditor");
    expect(typeof onMessage).toBe("function");
  });

  it("unlocks, authors, lists, releases — then locks and releases nothing", async () => {
    // 0. A fresh worker reports locked, so nothing below is pre-granted.
    expect(await dispatch({ type: "CHECK_VAULT_STATUS" })).toEqual({
      ok: true,
      data: { unlocked: false },
    });

    // 1. Unlock. This is the writer `cybervault_vek` was missing: before it,
    //    `readSessionVek` returned null forever and the whole chain below
    //    returned empty/VAULT_LOCKED for every credential.
    const unlocked = await unlock();
    expect(unlocked.ok).toBe(true);
    expect(unlocked.data).toEqual({ success: true, unlocked: true, vaultId: VAULT_ID });

    // The VEK is the session key, 32 bytes, in session storage where lock
    // can reach it — and nowhere near local storage.
    const vek = sessionStore.get(VEK);
    expect(typeof vek).toBe("string");
    expect(sessionStore.get(VEK)).toBe(sessionStore.get(SESSION_KEY));
    expect(Buffer.from(vek as string, "base64")).toHaveLength(32);
    expect(localStore.has(VEK)).toBe(false);

    expect(await dispatch({ type: "CHECK_VAULT_STATUS" })).toEqual({
      ok: true,
      data: { unlocked: true },
    });

    // 2. Author. This is the writer for the record and index stores.
    const authored = await dispatch({
      type: "AUTHOR_CREDENTIAL",
      payload: { origin: ORIGIN, username: USERNAME, password: PASSWORD, title: "GitHub" },
    });
    expect(authored.ok).toBe(true);
    const credentialId = (authored.data as { id: string }).id;
    expect(typeof credentialId).toBe("string");
    expect(credentialId).not.toBe("");

    const records = localStore.get(RECORDS) as Record<string, Record<string, unknown>>;
    expect(Object.keys(records)).toContain(credentialId);
    // The store holds ciphertext and non-secret metadata only: no bound origin
    // beside the opaque index, and never the plaintext secret.
    expect(records[credentialId].origin).toBeUndefined();
    expect(JSON.stringify(records)).not.toContain(PASSWORD);
    const index = localStore.get(INDEX) as { version?: number; byToken?: Record<string, string[]> };
    expect(index.version).toBe(1);
    expect(Object.values(index.byToken ?? {})).toContainEqual([credentialId]);

    // 3. List. Metadata only — the secret must not appear here either.
    const listed = await dispatch({ type: "LIST_CREDENTIALS_FOR_ORIGIN", origin: ORIGIN });
    expect(listed.ok).toBe(true);
    const candidates = listed.data as Array<Record<string, unknown>>;
    expect(candidates).toHaveLength(1);
    expect(candidates[0].credentialId).toBe(credentialId);
    expect(candidates[0].title).toBe("GitHub");
    expect(JSON.stringify(candidates)).not.toContain(PASSWORD);

    // An origin the credential is not bound to sees nothing.
    const foreignList = await dispatch({
      type: "LIST_CREDENTIALS_FOR_ORIGIN",
      origin: FOREIGN,
    });
    expect(foreignList.data).toEqual([]);

    // 4. Release on the bound origin.
    const released = await release(credentialId);
    expect(released.ok).toBe(true);
    expect(released.data).toEqual({
      id: credentialId,
      username: USERNAME,
      password: PASSWORD,
    });

    // 4b. A caller that lies about the origin gets a denial, never a partial
    //     credential.
    const forged = await release(credentialId, FOREIGN);
    expect(forged.ok).toBe(false);
    expect(forged.error).toBe("ORIGIN_NOT_BOUND");
    expect(forged.data).toEqual({ code: "ORIGIN_NOT_BOUND" });
    expect(JSON.stringify(forged)).not.toContain(PASSWORD);

    // 5. Lock: the key material authorization depends on is removed.
    const locked = await dispatch({ type: "LOCK_VAULT" });
    expect(locked).toEqual({ ok: true, data: { locked: true, vekCleared: true } });
    expect(sessionStore.has(VEK)).toBe(false);
    expect(sessionStore.has(SESSION_KEY)).toBe(false);
    expect(sessionStore.has(UNLOCK_STATE)).toBe(false);

    expect(await dispatch({ type: "CHECK_VAULT_STATUS" })).toEqual({
      ok: true,
      data: { unlocked: false },
    });

    // 6. Locked means unreleasable — the assertion the regex version could
    //    only approximate by reading a `remove()` call as text.
    const afterLock = await release(credentialId);
    expect(afterLock.ok).toBe(false);
    expect(afterLock.error).toBe("VAULT_LOCKED");
    expect(afterLock.data).toEqual({ code: "VAULT_LOCKED" });
    expect(JSON.stringify(afterLock)).not.toContain(PASSWORD);

    const lockedList = await dispatch({ type: "LIST_CREDENTIALS_FOR_ORIGIN", origin: ORIGIN });
    expect(lockedList.data).toEqual([]);

    const lockedAuthor = await dispatch({
      type: "AUTHOR_CREDENTIAL",
      payload: { origin: ORIGIN, username: USERNAME, password: PASSWORD, title: "GitHub" },
    });
    expect(lockedAuthor.ok).toBe(false);
    expect(lockedAuthor.error).toBe("VAULT_LOCKED");

    // ...but locking removes key material, not data.
    expect(localStore.has(RECORDS)).toBe(true);
    expect(localStore.has(INDEX)).toBe(true);

    // 7. Re-unlock with the same passphrase: same VEK (it is derived, not
    //    random per session), so the very same record releases again.
    const vekBefore = vek;
    const relocked = await unlock();
    expect(relocked.ok).toBe(true);
    expect(sessionStore.get(VEK)).toBe(vekBefore);

    const relisted = await dispatch({ type: "LIST_CREDENTIALS_FOR_ORIGIN", origin: ORIGIN });
    expect((relisted.data as unknown[]).map((c) => (c as { credentialId: string }).credentialId)).toEqual([
      credentialId,
    ]);
    const rereleased = await release(credentialId);
    expect(rereleased.data).toEqual({
      id: credentialId,
      username: USERNAME,
      password: PASSWORD,
    });
  });
});

/* ------------------------------------------------------------------ */
/*  Lock really checks its own work                                    */
/* ------------------------------------------------------------------ */

describe("handleLockVault verifies the removal it just performed", () => {
  it("refuses to report success when the VEK survives, and the refusal is load-bearing", async () => {
    const credentialId = await ensureAuthored();
    expect((await release(credentialId)).ok).toBe(true);

    // Simulate a remove() that resolves without deleting — the failure mode
    // chrome.storage can exhibit. A lock that believed it succeeded would tell
    // the user the vault is closed while every credential stays releasable.
    const realRemove = session.remove;
    session.remove = async () => undefined;
    try {
      const reported = await dispatch({ type: "LOCK_VAULT" });
      expect(reported.ok).toBe(false);
      expect(reported.error).toMatch(/VEK/);
      // Why the message must be loud: with the key still resident the release
      // below still works. The handler's job is to refuse the lie, not to
      // paper over it.
      expect((await release(credentialId)).ok).toBe(true);
    } finally {
      session.remove = realRemove;
    }

    // With removal actually working, the same lock succeeds and the VEK goes.
    const fixed = await dispatch({ type: "LOCK_VAULT" });
    expect(fixed).toEqual({ ok: true, data: { locked: true, vekCleared: true } });
    expect(sessionStore.has(VEK)).toBe(false);
    expect((await release(credentialId)).error).toBe("VAULT_LOCKED");
  });
});

/* ------------------------------------------------------------------ */
/*  readSessionVek fails closed                                        */
/* ------------------------------------------------------------------ */

describe("release gate fails closed on an unusable VEK", () => {
  it("refuses when the VEK is absent but the session key is still there", async () => {
    const credentialId = await ensureAuthored();
    await ensureUnlocked();

    // Drop the VEK alone: the gate must read ITS key, not infer one from the
    // session key being present.
    sessionStore.delete(VEK);
    expect((await dispatch({ type: "LIST_CREDENTIALS_FOR_ORIGIN", origin: ORIGIN })).data).toEqual([]);
    const denied = await release(credentialId);
    expect(denied.error).toBe("VAULT_LOCKED");
    expect(denied.data).toEqual({ code: "VAULT_LOCKED" });
  });

  it("refuses a VEK of the wrong length rather than deriving from truncated key material", async () => {
    const credentialId = await ensureAuthored();
    await ensureUnlocked();

    sessionStore.set(VEK, Buffer.from("too-short").toString("base64"));
    expect((await dispatch({ type: "LIST_CREDENTIALS_FOR_ORIGIN", origin: ORIGIN })).data).toEqual([]);
    expect((await release(credentialId)).error).toBe("VAULT_LOCKED");

    sessionStore.set(VEK, "");
    expect((await release(credentialId)).error).toBe("VAULT_LOCKED");
  });

  it("refuses instead of throwing when session storage is unavailable", async () => {
    const credentialId = await ensureAuthored();
    await ensureUnlocked();

    const realGet = session.get;
    session.get = () => Promise.reject(new Error("storage unavailable"));
    try {
      const denied = await release(credentialId);
      expect(denied.ok).toBe(false);
      expect(denied.error).toBe("VAULT_LOCKED");
      expect(JSON.stringify(denied)).not.toContain(PASSWORD);
    } finally {
      session.get = realGet;
    }
  });

  it("expires an unlock and clears the key material when the window has passed", async () => {
    const credentialId = await ensureAuthored();
    await ensureUnlocked();

    const state = sessionStore.get(UNLOCK_STATE) as { expiresAt: number };
    sessionStore.set(UNLOCK_STATE, { ...state, expiresAt: Date.now() - 1 });

    const denied = await release(credentialId);
    expect(denied.error).toBe("VAULT_LOCKED");
    // Fail closed AND forget: the gate drops the key material it found stale,
    // so a later release cannot succeed on the strength of a clock that was
    // only read once.
    expect(sessionStore.has(VEK)).toBe(false);
    expect(sessionStore.has(SESSION_KEY)).toBe(false);
  });
});

/* ------------------------------------------------------------------ */
/*  Authoring validates before it persists                             */
/* ------------------------------------------------------------------ */

describe("AUTHOR_CREDENTIAL rejects unusable bindings", () => {
  beforeAll(() => ensureUnlocked());

  it.each([
    ["no scheme", "github.com"],
    ["empty", ""],
    ["non-http scheme", "javascript:alert(1)"],
    ["not a URL", "not a url"],
  ])("refuses %s origin without writing a record", async (_label, origin) => {
    const before = JSON.stringify([...localStore.entries()]);

    const refused = await dispatch({
      type: "AUTHOR_CREDENTIAL",
      payload: { origin, username: USERNAME, password: PASSWORD, title: "GitHub" },
    });
    expect(refused.ok).toBe(false);
    expect(refused.error).toBeTruthy();

    // Nothing was written — not a record, not an index entry, not the secret.
    expect(JSON.stringify([...localStore.entries()])).toBe(before);
    expect(JSON.stringify([...localStore.entries()])).not.toContain(PASSWORD);
  });
});
