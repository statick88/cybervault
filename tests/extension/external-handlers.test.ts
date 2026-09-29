/**
 * The worker's external-facing handlers that no other suite reaches.
 *
 * `ENCRYPT_DATA` / `DECRYPT_DATA`, `REQUEST_MANAGED_CAPABILITY`,
 * `REQUEST_RELEASE_SHARE`'s transport failures and `GET_PLUS_PUBLIC_KEY` are
 * all registered on the same `chrome.runtime.onMessage` router the other
 * extension suites drive, but none of those suites dispatches them — so every
 * one of those handlers sat at 0, including the whole of `GET_PLUS_PUBLIC_KEY`.
 *
 * The harness follows `tests/extension/step-up-wiring.test.ts`: install a
 * `chrome` double, import the worker for its side effects, then invoke the
 * registered listener with a real message and await the reply. Two things it
 * adds, both because the code under test is unreachable otherwise:
 *
 *  - a fault-injection flag on `chrome.storage.local.get`, which is the only
 *    way into each handler's outermost `catch`;
 *  - a fetch stub that can hang until the worker's own `AbortController`
 *    fires, driven by fake timers. The timeout branches are not "an error
 *    whose message happens to contain 'timeout'" — they are the 5s/10s
 *    `setTimeout(() => controller.abort(), …)` firing, and the callback body
 *    is a statement that only executes on that path.
 */

jest.setTimeout(120_000);

import type { BackgroundMessage } from "../../src/background/message-types";
import { MESSAGE_TYPES } from "../../src/background/message-types";
import { binaryToBase64 } from "../../src/shared/utils";

/* ------------------------------------------------------------------ */
/*  chrome mock                                                        */
/* ------------------------------------------------------------------ */

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

function createArea(store: Map<string, unknown>) {
  return {
    get: async (keys: string | string[]) => {
      const list = Array.isArray(keys) ? keys : [keys];
      const out: Record<string, unknown> = {};
      for (const k of list) if (store.has(k)) out[k] = store.get(k);
      return out;
    },
    set: async (items: Record<string, unknown>) => {
      for (const [k, v] of Object.entries(items)) store.set(k, v);
    },
    remove: async (keys: string | string[]) => {
      const list = Array.isArray(keys) ? keys : [keys];
      for (const k of list) store.delete(k);
    },
    clear: async () => store.clear(),
  };
}

const localStore = new Map<string, unknown>();
const sessionStore = new Map<string, unknown>();

let onMessage: Listener | null = null;

/**
 * When true, `chrome.storage.local.get` rejects.
 *
 * Every handler that reads its config with `chrome.storage.local.get(...)`
 * wraps that read in an outermost `catch`, and no amount of well-formed
 * traffic can reach it — the read itself has to fail. The flag is armed for a
 * single dispatch and re-armed nowhere else.
 */
let failLocalGet = false;

const localArea = createArea(localStore);

(globalThis as unknown as { chrome: unknown }).chrome = {
  storage: {
    local: {
      ...localArea,
      get: async (keys: string | string[]) => {
        if (failLocalGet) throw new Error("storage read failed");
        return localArea.get(keys);
      },
    },
    session: createArea(sessionStore),
  },
  runtime: {
    onMessage: { addListener: (fn: Listener) => (onMessage = fn) },
    onInstalled: { addListener: () => undefined },
  },
  tabs: { query: async () => [] },
  alarms: { create: () => undefined, onAlarm: { addListener: () => undefined } },
};

/* ------------------------------------------------------------------ */
/*  fetch mock                                                         */
/* ------------------------------------------------------------------ */

interface RecordedCall {
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: Record<string, unknown>;
}

const calls: RecordedCall[] = [];

type Outcome =
  | "ok"
  | "http-error"
  | "reject"
  /** Never answers until the worker aborts its own AbortController. */
  | "hang-until-abort";

let outcome: Outcome = "ok";
let rejectMessage = "boom";

function jsonResponse(status: number, payload: unknown) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => payload,
    text: async () => JSON.stringify(payload),
  };
}

const realFetch = globalThis.fetch;

globalThis.fetch = (async (
  input: unknown,
  init?: { method?: string; headers?: Record<string, string>; body?: string; signal?: AbortSignal },
) => {
  const url = String(input);
  calls.push({
    url,
    method: init?.method ?? "GET",
    headers: init?.headers ?? {},
    body: init?.body ? (JSON.parse(init.body) as Record<string, unknown>) : undefined,
  });

  if (outcome === "hang-until-abort") {
    const signal = init?.signal;
    return new Promise((_resolve, reject) => {
      const abort = () => reject(new Error("The operation was aborted"));
      if (signal?.aborted) {
        abort();
        return;
      }
      signal?.addEventListener("abort", abort);
    });
  }
  if (outcome === "reject") throw new Error(rejectMessage);
  if (outcome === "http-error") return jsonResponse(500, { error: "upstream failed" });

  if (url.includes("/api/v1/crypto/public-key")) {
    return jsonResponse(200, { publicKey: "cHVibGljLWtleQ==", algorithm: "Ed25519" });
  }
  if (url.includes("/api/v1/capabilities/request")) {
    return jsonResponse(200, {
      capabilityToken: { payload: { userId: "user-1" }, signature: "sig", protectedHeader: "hdr" },
      expiresAt: Date.now() + 60_000,
    });
  }
  if (url.includes("/managed-release")) {
    return jsonResponse(200, { success: true, releaseShare: "cmVsZWFzZS1zaGFyZQ==" });
  }
  return jsonResponse(404, { error: `unstubbed endpoint: ${url}` });
}) as unknown as typeof fetch;

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

const SESSION_KEY = binaryToBase64(crypto.getRandomValues(new Uint8Array(32)));
const AUTH_TOKEN = "jwt-token";

function dispatch(message: BackgroundMessage): Promise<Reply> {
  if (!onMessage) return Promise.reject(new Error("worker listener not registered"));
  return new Promise((resolve) => {
    onMessage!(message, {}, (reply) => resolve(reply as Reply));
  });
}

/** Let every already-resolved promise in the worker chain run to its next await. */
async function flushMicrotasks(): Promise<void> {
  for (let i = 0; i < 25; i++) await Promise.resolve();
}

/**
 * Dispatch, then let the worker's own timeout fire.
 *
 * The handlers arm `setTimeout(() => controller.abort(), ms)` and clear it on
 * every path that completes first. The only way to execute the callback body
 * is to not complete first — so the fetch stub hangs and the clock is moved.
 */
async function dispatchWithTimeout(
  message: BackgroundMessage,
  ms: number,
): Promise<Reply> {
  jest.useFakeTimers({
    doNotFake: ["Date", "nextTick", "queueMicrotask", "setImmediate", "clearImmediate"],
  });
  try {
    const pending = dispatch(message);
    await flushMicrotasks();
    await jest.advanceTimersByTimeAsync(ms);
    return await pending;
  } finally {
    jest.useRealTimers();
  }
}

const PLAINTEXT = "the quick brown fox";

const ENCRYPT: BackgroundMessage = {
  type: MESSAGE_TYPES.ENCRYPT_DATA,
  payload: PLAINTEXT,
};

const GET_PUBLIC_KEY: BackgroundMessage = { type: MESSAGE_TYPES.GET_PLUS_PUBLIC_KEY };

const MANAGED_CAPABILITY: BackgroundMessage = {
  type: MESSAGE_TYPES.REQUEST_MANAGED_CAPABILITY,
  payload: {
    userId: "user-1",
    resourceId: "ref-1",
    operation: "AUTOFILL",
    secretRef: "secret-ref-1",
    deviceId: "device-1",
    assurance: 2,
  },
};

const RELEASE_SHARE: BackgroundMessage = {
  type: MESSAGE_TYPES.REQUEST_RELEASE_SHARE,
  payload: {
    capabilityToken: { payload: {}, signature: "sig", protectedHeader: "hdr" },
    credentialId: "cred-1",
  },
};

beforeAll(async () => {
  await import("../../src/background/auditor");
  expect(typeof onMessage).toBe("function");
});

beforeEach(() => {
  calls.length = 0;
  outcome = "ok";
  rejectMessage = "boom";
  failLocalGet = false;
  localStore.set("cybervault_token", AUTH_TOKEN);
  localStore.set("cybervault_userId", "user-1");
  localStore.set("plus_base_url", "http://localhost:3011");
  localStore.set("plus_service_secret", "svc-secret");
  localStore.set("core_base_url", "http://localhost:3010");
  sessionStore.delete("cybervault_unlock_state");
});

afterAll(async () => {
  globalThis.fetch = realFetch;
  delete (globalThis as unknown as { chrome?: unknown }).chrome;
});

/* ------------------------------------------------------------------ */
/*  ENCRYPT_DATA / DECRYPT_DATA                                         */
/* ------------------------------------------------------------------ */

describe("ENCRYPT_DATA and DECRYPT_DATA", () => {
  it("refuses both while the vault is locked", async () => {
    sessionStore.delete("cybervault_session_key");

    const encrypt = await dispatch(ENCRYPT);
    const decrypt = await dispatch({
      type: MESSAGE_TYPES.DECRYPT_DATA,
      payload: "anything",
    });

    expect(encrypt).toEqual({ ok: false, error: "Vault not unlocked" });
    expect(decrypt).toEqual({ ok: false, error: "Vault not unlocked" });
  });

  it("round-trips a payload under the session key", async () => {
    sessionStore.set("cybervault_session_key", SESSION_KEY);

    const encrypt = await dispatch(ENCRYPT);
    expect(encrypt.ok).toBe(true);
    expect(typeof encrypt.data).toBe("string");
    expect(encrypt.data).not.toBe(PLAINTEXT);

    const decrypt = await dispatch({
      type: MESSAGE_TYPES.DECRYPT_DATA,
      payload: encrypt.data as string,
    });
    expect(decrypt).toEqual({ ok: true, data: PLAINTEXT });
  });

  it("reports a session key that is not a usable AES-GCM key", async () => {
    // 11 bytes of raw key material — `importKey` refuses it, and the refusal
    // must surface as a reply rather than as an unhandled rejection.
    sessionStore.set("cybervault_session_key", binaryToBase64(new Uint8Array(11)));

    const encrypt = await dispatch(ENCRYPT);

    expect(encrypt.ok).toBe(false);
    expect(typeof encrypt.error).toBe("string");
    expect(encrypt.error).not.toBe("");
    expect(encrypt.data).toBeUndefined();
  });

  it("reports a payload that cannot be decrypted instead of returning garbage", async () => {
    sessionStore.set("cybervault_session_key", SESSION_KEY);

    const decrypt = await dispatch({
      type: MESSAGE_TYPES.DECRYPT_DATA,
      payload: "not-a-real-ciphertext",
    });

    expect(decrypt.ok).toBe(false);
    expect(decrypt.data).toBeUndefined();
    expect(typeof decrypt.error).toBe("string");
  });
});

/* ------------------------------------------------------------------ */
/*  REQUEST_MANAGED_CAPABILITY                                          */
/* ------------------------------------------------------------------ */

describe("REQUEST_MANAGED_CAPABILITY", () => {
  it("refuses before it calls Plus when there is no session", async () => {
    localStore.delete("cybervault_token");
    localStore.delete("cybervault_userId");

    const reply = await dispatch(MANAGED_CAPABILITY);

    expect(reply).toEqual({ ok: false, error: "Not authenticated" });
    expect(calls).toHaveLength(0);
  });

  it("posts the capability request and returns Plus's answer", async () => {
    const reply = await dispatch(MANAGED_CAPABILITY);

    expect(reply.ok).toBe(true);
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe("http://localhost:3011/api/v1/capabilities/request");
    expect(calls[0].method).toBe("POST");
    expect(calls[0].headers.Authorization).toBe(`Bearer ${AUTH_TOKEN}`);
    expect(calls[0].headers["X-Service-Secret"]).toBe("svc-secret");
    expect(calls[0].body).toMatchObject({
      userId: "user-1",
      resourceId: "ref-1",
      operation: "AUTOFILL",
      secretRef: "secret-ref-1",
      assurance: 2,
    });
  });

  it("surfaces a non-2xx from Plus with its status and body", async () => {
    outcome = "http-error";

    const reply = await dispatch(MANAGED_CAPABILITY);

    expect(reply.ok).toBe(false);
    expect(reply.error).toBe('Plus API 500: {"error":"upstream failed"}');
  });

  it("reports a timeout when Plus never answers", async () => {
    outcome = "hang-until-abort";

    const reply = await dispatchWithTimeout(MANAGED_CAPABILITY, 10_000);

    expect(reply).toEqual({ ok: false, error: "Plus API timeout" });
  });

  it("surfaces a transport failure that is not a timeout", async () => {
    outcome = "reject";
    rejectMessage = "connect ECONNREFUSED 127.0.0.1:3011";

    const reply = await dispatch(MANAGED_CAPABILITY);

    expect(reply).toEqual({
      ok: false,
      error: "Plus API error: connect ECONNREFUSED 127.0.0.1:3011",
    });
  });

  it("reports a storage failure through the outermost catch", async () => {
    failLocalGet = true;

    const reply = await dispatch(MANAGED_CAPABILITY);

    expect(reply).toEqual({ ok: false, error: "storage read failed" });
    expect(calls).toHaveLength(0);
  });
});

/* ------------------------------------------------------------------ */
/*  REQUEST_RELEASE_SHARE — transport failures                          */
/* ------------------------------------------------------------------ */

describe("REQUEST_RELEASE_SHARE transport failures", () => {
  it("refuses when the vault is not unlocked", async () => {
    const reply = await dispatch(RELEASE_SHARE);

    expect(reply).toEqual({ ok: false, error: "vault not unlocked" });
    expect(calls).toHaveLength(0);
  });

  it("reports a timeout when Core never answers", async () => {
    sessionStore.set("cybervault_unlock_state", { vaultId: "vault-1" });
    outcome = "hang-until-abort";

    const reply = await dispatchWithTimeout(RELEASE_SHARE, 10_000);

    expect(reply).toEqual({ ok: false, error: "Core API timeout" });
  });

  it("surfaces a transport failure that is not a timeout", async () => {
    sessionStore.set("cybervault_unlock_state", { vaultId: "vault-1" });
    outcome = "reject";
    rejectMessage = "getaddrinfo ENOTFOUND api.core";

    const reply = await dispatch(RELEASE_SHARE);

    expect(reply).toEqual({ ok: false, error: "Core API error: getaddrinfo ENOTFOUND api.core" });
  });

  it("reports a storage failure through the outermost catch", async () => {
    failLocalGet = true;

    const reply = await dispatch(RELEASE_SHARE);

    expect(reply).toEqual({ ok: false, error: "storage read failed" });
  });
});

/* ------------------------------------------------------------------ */
/*  GET_PLUS_PUBLIC_KEY                                                 */
/* ------------------------------------------------------------------ */

describe("GET_PLUS_PUBLIC_KEY", () => {
  it("returns the public key Plus publishes", async () => {
    const reply = await dispatch(GET_PUBLIC_KEY);

    expect(reply.ok).toBe(true);
    expect(reply.data).toEqual({ publicKey: "cHVibGljLWtleQ==", algorithm: "Ed25519" });
    expect(calls[0].url).toBe("http://localhost:3011/api/v1/crypto/public-key");
    expect(calls[0].method).toBe("GET");
  });

  it("surfaces a non-2xx from Plus with its status and body", async () => {
    outcome = "http-error";

    const reply = await dispatch(GET_PUBLIC_KEY);

    expect(reply.ok).toBe(false);
    expect(reply.error).toBe('Plus API 500: {"error":"upstream failed"}');
  });

  it("reports a timeout when Plus never answers", async () => {
    outcome = "hang-until-abort";

    const reply = await dispatchWithTimeout(GET_PUBLIC_KEY, 5_000);

    expect(reply.ok).toBe(false);
    expect(reply.error).toBe("Plus public key error: The operation was aborted");
  });

  it("surfaces a transport failure that is not a timeout", async () => {
    outcome = "reject";
    rejectMessage = "certificate has expired";

    const reply = await dispatch(GET_PUBLIC_KEY);

    expect(reply).toEqual({
      ok: false,
      error: "Plus public key error: certificate has expired",
    });
  });

  it("reports a storage failure through the outermost catch", async () => {
    failLocalGet = true;

    const reply = await dispatch(GET_PUBLIC_KEY);

    expect(reply).toEqual({ ok: false, error: "storage read failed" });
    expect(calls).toHaveLength(0);
  });
});
