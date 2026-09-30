/**
 * R9 — MV3 worker eviction, measured rather than assumed.
 *
 * ## Why this file exists
 *
 * The threat model claimed eviction is "fail-closed: the user is asked to step
 * up again". That is a claim about behaviour, and nobody had tested it. The
 * gate in `handleReleaseCredential` reads:
 *
 *     if (challengedBindings.has(key)) { ...refuse unless completed... }
 *
 * An `if (has)` gate is a *remembering* gate. When the worker is evicted the
 * maps are empty, `has(key)` is false, and the block is skipped entirely — so
 * the first question is not "does the user step up again" but "does the gate
 * run at all".
 *
 * A restarted module is the honest way to simulate eviction: fresh maps, no
 * leftover state, exactly what a 30-second idle timeout produces. The same
 * harness shape as step-up-wiring.test.ts, with a `jest.resetModules()` between
 * phases so the second phase gets a genuinely new module instance.
 */

import type { BackgroundMessage } from "../../src/background/message-types";
import { deriveManagedEntryKey } from "../../src/infrastructure/crypto/hkdf-derivation";
import { addToIndex, computeLookupToken, deriveDomainIndexKey, emptyIndex, type OpaqueIndex } from "../../src/domain/services/autofill/domain-index";
import { binaryToBase64 } from "../../src/shared/utils";

/* ------------------------------------------------------------------ */
/*  chrome mock                                                        */
/* ------------------------------------------------------------------ */

type Listener = (
  message: unknown,
  sender: unknown,
  sendResponse: (reply: unknown) => void,
) => boolean;

let onMessage: Listener | null = null;

function createArea(initial: Record<string, unknown> = {}) {
  const store = new Map<string, unknown>(Object.entries(initial));
  return {
    get: async (keys?: string | string[] | null) => {
      if (keys === undefined || keys === null) return Object.fromEntries(store);
      const list = Array.isArray(keys) ? keys : [keys];
      const out: Record<string, unknown> = {};
      for (const k of list) if (store.has(k)) out[k] = store.get(k);
      return out;
    },
    set: async (obj: Record<string, unknown>) => {
      for (const [k, v] of Object.entries(obj)) store.set(k, v);
    },
    remove: async (k: string) => { store.delete(k); },
  };
}

const localStore = new Map<string, unknown>();
const sessionStore = new Map<string, unknown>();

/**
 * Reinstall the `chrome` global — not the storage behind it.
 *
 * `localStore` and `sessionStore` are module-level Maps, so this swaps only the
 * API object; every key already written survives the call. That is deliberate:
 * MV3 `storage.local` and `storage.session` outlive service-worker eviction, so
 * a simulated restart that rebuilt the stores would delete the seeded record
 * (and the session VEK) and the post-eviction releases would answer
 * CREDENTIAL_NOT_FOUND instead of reaching the gate. The record therefore does
 * NOT need re-seeding after each simulated restart.
 */
function installChrome(): void {
  (globalThis as unknown as { chrome: unknown }).chrome = {
    runtime: {
      onMessage: { addListener: (fn: Listener) => (onMessage = fn) },
      onInstalled: { addListener: () => undefined },
      sendMessage: () => undefined,
      getURL: (p: string) => `chrome-extension://mock/${p}`,
      lastError: undefined,
    },
    storage: {
      local: {
        get: (keys?: string | string[] | null) => {
          if (keys === undefined || keys === null) return Promise.resolve(Object.fromEntries(localStore));
          const list = Array.isArray(keys) ? keys : [keys];
          const out: Record<string, unknown> = {};
          for (const k of list) if (localStore.has(k)) out[k] = localStore.get(k);
          return Promise.resolve(out);
        },
        set: (obj: Record<string, unknown>) => {
          for (const [k, v] of Object.entries(obj)) localStore.set(k, v);
          return Promise.resolve();
        },
        remove: (k: string) => { localStore.delete(k); return Promise.resolve(); },
      },
      session: {
        get: (keys?: string | string[] | null) => {
          if (keys === undefined || keys === null) return Promise.resolve(Object.fromEntries(sessionStore));
          const list = Array.isArray(keys) ? keys : [keys];
          const out: Record<string, unknown> = {};
          for (const k of list) if (sessionStore.has(k)) out[k] = sessionStore.get(k);
          return Promise.resolve(out);
        },
        set: (obj: Record<string, unknown>) => {
          for (const [k, v] of Object.entries(obj)) sessionStore.set(k, v);
          return Promise.resolve();
        },
        remove: (k: string) => { sessionStore.delete(k); return Promise.resolve(); },
      },
    },
    tabs: { query: () => Promise.resolve([]), sendMessage: () => undefined },
    alarms: { create: () => undefined, onAlarm: { addListener: () => undefined } },
    webNavigation: { onCommitted: { addListener: () => undefined } },
    scripting: { executeScript: () => Promise.resolve([]) },
  };
  void createArea;
}

interface Reply { ok: boolean; data?: unknown; error?: string }
function dispatch(message: BackgroundMessage): Promise<Reply> {
  if (!onMessage) return Promise.reject(new Error("worker listener not registered"));
  return new Promise((resolve) => {
    onMessage!(message, {}, (reply) => resolve(reply as Reply));
  });
}

/* ------------------------------------------------------------------ */
/*  HTTP                                                               */
/* ------------------------------------------------------------------ */

interface RecordedCall { url: string; method: string; headers: Record<string, string>; body?: any }
const calls: RecordedCall[] = [];

/** What Plus answers for a capability request. Flipped per case. */
let plusHasCompletedStepUp = false;

const realFetch = globalThis.fetch;

const CORE = "http://localhost:3010";
const PLUS = "http://localhost:3011";
const TOKEN = "jwt-token";
const MANAGED_ID = "cred-r9";
const PROBE_REF = "ref-r9";
const ORIGIN = "https://github.com";

function json(status: number, payload: unknown) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => payload,
    text: async () => JSON.stringify(payload),
  };
}

const CAPABILITY_TOKEN = {
  payload: { iss: "plus", aud: "core", userId: "u", assurance: 3, jti: "jti-r9" },
  signature: "sig",
  protectedHeader: "hdr",
};
const RELEASE_SHARE_B64 = binaryToBase64(new Uint8Array(32).fill(9));

globalThis.fetch = (async (input: unknown, init?: { method?: string; headers?: Record<string, string>; body?: string }) => {
  const url = String(input);
  const method = init?.method ?? "GET";
  const headers = init?.headers ?? {};
  const body = init?.body ? (JSON.parse(init.body) as Record<string, unknown>) : undefined;
  calls.push({ url, method, headers, body });

  if (url.endsWith("/api/v1/capabilities/request")) {
    return plusHasCompletedStepUp
      ? json(200, { capabilityToken: CAPABILITY_TOKEN, expiresAt: Date.now() + 60_000 })
      : json(200, { challengeRequired: true });
  }
  if (url.includes("/managed-release")) {
    return json(200, { success: true, releaseShare: RELEASE_SHARE_B64, credentialId: body?.credentialId });
  }
  if (url.endsWith("/api/v1/challenges/trigger")) {
    return json(201, { success: true, challengeId: "ch-r9", expiresAt: Date.now() + 120_000 });
  }
  if (url.endsWith("/step-up/approve")) {
    return json(200, { approval: { payload: {}, signature: "s", protectedHeader: "h" } });
  }
  if (url.endsWith("/api/v1/challenges/approve")) {
    return plusHasCompletedStepUp
      ? json(200, { capabilityToken: CAPABILITY_TOKEN })
      : json(400, { error: "no completed challenge" });
  }
  if (url.endsWith("/api/v1/crypto/public-key")) {
    return json(200, { publicKey: "pk" });
  }
  return json(404, { error: `unstubbed: ${url}` });
}) as unknown as typeof fetch;

/* ------------------------------------------------------------------ */
/*  Fixtures                                                           */
/* ------------------------------------------------------------------ */

const RECORDS = "cybervault_cred_records";
const INDEX = "cybervault_cred_index";
const VAULT_ID = "vault-r9";
const PASSPHRASE = "correct horse battery staple";

function toArrayBuffer(d: Uint8Array): ArrayBuffer {
  const b = new ArrayBuffer(d.byteLength);
  new Uint8Array(b).set(d);
  return b;
}

/**
 * Seal `plaintext` into the `salt|iv|ciphertext` layout the store expects.
 *
 * The layout is THREE BYTE RANGES CONCATENATED and then base64-encoded ONCE.
 * It is not three base64 strings joined by `|`: `parseCiphertext`
 * (src/background/credential-release.ts:164) runs `base64ToBinary` over the
 * whole blob and slices bytes 0..32 / 32..44 / 44.. — a pipe-joined string is
 * not valid base64, `atob` throws, and the release dies as DECRYPT_FAILED.
 * The product's own `seal` (credential-authoring.ts:153,
 * managed-authoring.use-case.ts:354) concatenates before encoding.
 */
async function seal(plaintext: string, keyBytes: Uint8Array, salt: Uint8Array): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", toArrayBuffer(keyBytes), "AES-GCM", false, ["encrypt"]);
  const cipher = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: toArrayBuffer(iv) },
      key,
      new TextEncoder().encode(plaintext),
    ),
  );
  const out = new Uint8Array(salt.length + iv.length + cipher.length);
  out.set(salt, 0);
  out.set(iv, salt.length);
  out.set(cipher, salt.length + iv.length);
  return binaryToBase64(out);
}

const PASSWORD = "s3cret-in-the-store";

/**
 * Write the managed record the way Core would have handed it over.
 *
 * Two details are load-bearing and were both wrong in the first draft:
 *
 *  1. `cybervault_cred_records` holds an OBJECT, not a JSON string.
 *     `getRecord` (src/background/auditor.ts:820) guards with
 *     `if (!all || typeof all !== "object") return null` (line 823) before
 *     `all[credentialId]`; a JSON string has `typeof "string"`, so the guard
 *     returns null straight away and every release answered CREDENTIAL_NOT_FOUND
 *     before the step-up gate was ever reached.
 *  2. Records MERGE with whatever is already stored, exactly as
 *     `handleAuthorCredential` does (src/background/auditor.ts:950). Overwriting
 *     the whole map would hide a fixture that only seeds part of the store.
 */
async function writeManagedRecord(vekB64: string): Promise<void> {
  const vek = Uint8Array.from(Buffer.from(vekB64, "base64"));
  const releaseShare = Uint8Array.from(Buffer.from(RELEASE_SHARE_B64, "base64"));
  const salt = crypto.getRandomValues(new Uint8Array(32));

  const entry = await deriveManagedEntryKey(vek, releaseShare, salt, MANAGED_ID, 1);
  const keyBytes = Uint8Array.from(Buffer.from(entry.keyBase64, "base64"));
  const encryptedSecret = await seal(
    JSON.stringify({ u: "octocat", p: PASSWORD }),
    keyBytes,
    salt,
  );

  const indexKey = await deriveDomainIndexKey(vek);
  const token = await computeLookupToken(ORIGIN, indexKey);
  if (!token.ok) throw new Error("fixture token failed");

  const stored = await chrome.storage.local.get([RECORDS, INDEX]);
  const existingRecords = stored[RECORDS] as Record<string, unknown> | undefined;
  const existingIndex = stored[INDEX] as OpaqueIndex | undefined;

  await chrome.storage.local.set({
    [RECORDS]: {
      ...(existingRecords && typeof existingRecords === "object" ? existingRecords : {}),
      [MANAGED_ID]: {
        id: MANAGED_ID, mode: "managed", encryptedSecret,
        encryptedTotpSecret: "", salt: binaryToBase64(salt),
        version: 1, releaseShareRef: PROBE_REF, usernameHint: "oct***",
        title: "GitHub",
      },
    },
    [INDEX]: addToIndex(existingIndex ?? emptyIndex(), token.token, MANAGED_ID),
  });
}

function releaseMessage(): BackgroundMessage {
  return {
    type: "RELEASE_CREDENTIAL",
    credentialId: MANAGED_ID,
    origin: ORIGIN,
    operation: "AUTOFILL",
    documentOrigin: ORIGIN,
    topLevelOrigin: ORIGIN,
    isFramed: false,
  };
}

beforeAll(async () => {
  installChrome();
  await import("../../src/background/auditor");
  expect(typeof onMessage).toBe("function");

  // Real unlock, not a seeded key: the fixture then starts from the same
  // session the product creates. Without it every release answers
  // VAULT_LOCKED and the test would be measuring the wrong refusal.
  const unlocked = await dispatch({
    type: "UNLOCK_VAULT",
    vaultId: VAULT_ID,
    passphrase: PASSPHRASE,
  });
  expect({ ok: unlocked.ok, err: (unlocked as any).error }).toEqual({ ok: true, err: undefined });

  await writeManagedRecord(sessionStore.get("cybervault_vek") as string);

  await chrome.storage.local.set({
    cybervault_token: TOKEN,
    cybervault_userId: "u",
    plus_base_url: PLUS,
    plus_service_secret: "svc",
    core_base_url: CORE,
  });
}, 60_000);

afterAll(() => {
  globalThis.fetch = realFetch;
  delete (globalThis as unknown as { chrome?: unknown }).chrome;
});

describe("R9 — what eviction actually does", () => {
  it("a gated release is refused while the worker remembers the challenge", async () => {
    plusHasCompletedStepUp = false;
    calls.length = 0;

    // First attempt: Plus demands a challenge, so the worker records the
    // binding as needing one.
    const first = await dispatch(releaseMessage());
    expect(first).toMatchObject({ ok: false, error: "CHALLENGE_REQUIRED" });

    // Second attempt, same worker: now the gate has something to remember, and
    // the release is still refused because nothing was completed.
    const second = await dispatch(releaseMessage());
    expect(second).toMatchObject({ ok: false, error: "CHALLENGE_REQUIRED" });
  });

  it("after eviction the worker forgets, and the release is ATTEMPTED anyway", async () => {
    /* ---- Start from a worker that has NOT yet been challenged for this
     * binding. Test 1 left `challengedBindings` populated in the shared module
     * instance (both tests talk to the same `auditor`), so without this
     * bootstrap the dispatch below is refused by the gate before a single byte
     * leaves the extension, and the "reaches Plus" premise underneath it is
     * false. The binding has to be learned first and forgotten afterwards —
     * forgetting something that was never learned proves nothing. */
    jest.resetModules();
    (globalThis as unknown as { chrome: unknown }).chrome = undefined;
    installChrome();

    plusHasCompletedStepUp = false;
    calls.length = 0;
    await import("../../src/background/auditor");

    // First attempt: Plus demands a challenge, so this worker records the
    // binding as needing one — now there IS something to forget.
    await dispatch(releaseMessage());
    expect(callsTo("/api/v1/capabilities/request").length).toBeGreaterThan(0);

    /* ---- Simulate MV3 eviction: a genuinely fresh module instance. ----
     * `jest.resetModules()` plus a fresh import gives new `new Map()`s, which
     * is exactly what a 30-second idle timeout produces. */
    jest.resetModules();
    (globalThis as unknown as { chrome: unknown }).chrome = undefined;
    installChrome();

    calls.length = 0;
    await import("../../src/background/auditor");

    const afterEviction = await dispatch(releaseMessage());

    // The gate `if (challengedBindings.has(key))` is now FALSE, because the
    // worker no longer remembers this release ever needed a step-up. So the
    // block is skipped and the release is attempted with no challenge behind
    // it at all.
    //
    // The threat model calls this fail-closed. It is not, at this layer: the
    // guard is a remembering guard, and eviction erases the memory. The
    // request to Plus still goes out, and Plus refuses it because there is no
    // completed challenge — so the outcome is still a denial, but it comes
    // from the network, not from the extension.
    const askedPlus = callsTo("/api/v1/capabilities/request");
    expect(askedPlus.length).toBe(1);
    expect(afterEviction).toMatchObject({ ok: false, error: "CHALLENGE_REQUIRED" });
  });

  it("so the denial survives only because Plus re-derives it, not because the extension gated it", async () => {
    // This is the honest statement of where the guarantee lives. If Plus were
    // to answer "granted" — which it must not without a completed challenge —
    // the extension would have released the credential after eviction, having
    // never gated this binding itself.
    jest.resetModules();
    (globalThis as unknown as { chrome: unknown }).chrome = undefined;
    installChrome();
    calls.length = 0;
    await import("../../src/background/auditor");

    plusHasCompletedStepUp = true; // simulate a Plus that grants

    const reply = await dispatch(releaseMessage());

    // No step-up was ever completed in this worker, yet the release goes
    // through. That is the fail-open the threat model denies.
    expect(reply.ok).toBe(true);
    expect(callsTo("/api/v1/capabilities/request").length).toBe(1);
  });
});

function callsTo(path: string): RecordedCall[] {
  return calls.filter((c) => c.url.includes(path));
}
