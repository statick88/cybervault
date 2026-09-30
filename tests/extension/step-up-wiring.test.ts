/**
 * Step-up wiring and the managed-release round trip (service-worker side).
 *
 * WU-3 makes two dormant paths reachable: the third-factor senders the popup
 * drives (`START_STEP_UP`, `APPROVE_STEP_UP`, `GET_PENDING_STEP_UP`) and the
 * managed release call. Both are pure HTTP contracts, so the only honest way
 * to test them is to stand in for the two servers and inspect what the worker
 * actually sends — a source assertion cannot tell a URL from a comment, and
 * the previous contract was wrong in exactly that way (`/api/v1/vaults/`
 * path segments that did not exist, a request body carrying a field the
 * server ignores).
 *
 * The third group covers the gate `canRetryRelease` exists for: a step-up
 * completed for one binding must release that binding and no other.
 */

jest.setTimeout(120_000);

import type { BackgroundMessage } from "../../src/background/message-types";
import { addToIndex, computeLookupToken, deriveDomainIndexKey, emptyIndex, type OpaqueIndex } from "../../src/domain/services/autofill/domain-index";
import { deriveManagedEntryKey } from "../../src/infrastructure/crypto/hkdf-derivation";
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

(globalThis as unknown as { chrome: unknown }).chrome = {
  storage: { local: createArea(localStore), session: createArea(sessionStore) },
  runtime: {
    onMessage: { addListener: (fn: Listener) => (onMessage = fn) },
    onInstalled: { addListener: () => undefined },
  },
  tabs: { query: async () => [] },
  alarms: { create: () => undefined, onAlarm: { addListener: () => undefined } },
};

/* ------------------------------------------------------------------ */
/*  fetch mock — stands in for Plus (3011) and Core (3010)             */
/* ------------------------------------------------------------------ */

interface RecordedCall {
  url: string;
  method: string;
  headers: Record<string, string>;
  body?: Record<string, unknown>;
}

const calls: RecordedCall[] = [];

/** "challenge" → Plus demands a third factor; "grant" → it issues a token. */
let capabilityMode: "challenge" | "grant" = "challenge";
let coreApproveFails = false;
/** When true, Core's managed-release answers 500. */
let coreFails = false;

const RELEASE_SHARE_B64 = binaryToBase64(new Uint8Array(32).fill(9));
const CAPABILITY_TOKEN = {
  payload: { userId: "user-1", resourceId: "ref-1", operation: "AUTOFILL" },
  signature: "sig",
  protectedHeader: "hdr",
};

function jsonResponse(status: number, payload: unknown) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => payload,
    text: async () => JSON.stringify(payload),
  };
}

const realFetch = globalThis.fetch;

globalThis.fetch = (async (input: unknown, init?: { method?: string; headers?: Record<string, string>; body?: string }) => {
  const url = String(input);
  const method = init?.method ?? "GET";
  const headers = init?.headers ?? {};
  const body = init?.body ? (JSON.parse(init.body) as Record<string, unknown>) : undefined;
  calls.push({ url, method, headers, body });

  if (url.endsWith("/api/v1/capabilities/request")) {
    if (capabilityMode === "challenge") return jsonResponse(200, { challengeRequired: true });
    return jsonResponse(200, { capabilityToken: CAPABILITY_TOKEN, expiresAt: Date.now() + 60_000 });
  }
  if (url.includes("/managed-release")) {
    if (coreFails) return jsonResponse(500, { error: "boom" });
    return jsonResponse(200, { success: true, releaseShare: RELEASE_SHARE_B64, credentialId: body?.credentialId });
  }
  if (url.endsWith("/api/v1/challenges/trigger")) {
    return jsonResponse(200, { success: true, challengeId: "ch-1", expiresAt: Date.now() + 120_000 });
  }
  if (url.endsWith("/api/v1/step-up/approve")) {
    if (coreApproveFails) return jsonResponse(400, { error: "Credential not available for release" });
    // R3: Core signs the approval. The stub returns a stand-in signature; the
    // real verification happens in Plus against Core's pinned public key.
    return jsonResponse(200, { approval: { payload: { typ: "step-up-approval" }, signature: "sig", protectedHeader: "hdr" } });
  }
  if (url.endsWith("/api/v1/challenges/approve")) {
    return jsonResponse(200, { success: true });
  }
  if (url.endsWith("/api/v1/challenges/verify")) {
    // Retired in R3. Kept as a 404 so any surviving caller fails loudly
    // instead of silently receiving a fake success.
    return jsonResponse(404, { error: "retired" });
  }
  return jsonResponse(404, { error: `unstubbed endpoint: ${url}` });
}) as unknown as typeof fetch;

/* ------------------------------------------------------------------ */
/*  Constants and helpers                                              */
/* ------------------------------------------------------------------ */

const RECORDS = "cybervault_cred_records";
const INDEX = "cybervault_cred_index";

const VAULT_ID = "vault-e2e";
const PASSPHRASE = "correct horse battery staple";
const ORIGIN = "https://github.com";
const USERNAME = "octocat";
const PASSWORD = "s3cret-in-the-store";
const CORE = "http://localhost:3010";
const PLUS = "http://localhost:3011";
const TOKEN = "jwt-token";
const MANAGED_ID = "cred-managed-1";

function dispatch(message: BackgroundMessage): Promise<Reply> {
  if (!onMessage) return Promise.reject(new Error("worker listener not registered"));
  return new Promise((resolve) => {
    onMessage!(message, {}, (reply) => resolve(reply as Reply));
  });
}

function toArrayBuffer(d: Uint8Array): ArrayBuffer {
  const b = new ArrayBuffer(d.byteLength);
  new Uint8Array(b).set(d);
  return b;
}

/** Seal `plaintext` into the `salt|iv|ciphertext` layout the store expects. */
async function seal(plaintext: string, keyBytes: Uint8Array, salt: Uint8Array): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey("raw", toArrayBuffer(keyBytes), "AES-GCM", false, ["encrypt"]);
  const enc = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: toArrayBuffer(iv), tagLength: 128 },
    key,
    toArrayBuffer(new TextEncoder().encode(plaintext)),
  );
  const out = new Uint8Array(salt.length + iv.length + enc.byteLength);
  out.set(salt, 0);
  out.set(iv, salt.length);
  out.set(new Uint8Array(enc), salt.length + iv.length);
  return binaryToBase64(out);
}

function callsTo(path: string): RecordedCall[] {
  return calls.filter((c) => c.url.includes(path));
}

/**
 * Write a managed record the way Core would have handed it over.
 *
 * `authorCredential` refuses managed mode by design (the client does not hold
 * the Release Share at authoring time), so the fixture is assembled from the
 * same primitives the reader uses: the entry key is HKDF(VEK ‖ ReleaseShare),
 * the index entry is the real opaque token. A fixture built any other way
 * would test the mock rather than the code.
 *
 * Records MERGE: a second credential must not evict the first, because
 * `START_STEP_UP` resolves the binding against this store and a probe binding
 * with no record would never reach the wire at all.
 */
async function seedManagedRecord(
  vekB64: string,
  opts: { id?: string; origin?: string; releaseShareRef?: string } = {},
): Promise<void> {
  const id = opts.id ?? MANAGED_ID;
  const origin = opts.origin ?? ORIGIN;
  const releaseShareRef = opts.releaseShareRef ?? "ref-1";
  const vek = Uint8Array.from(Buffer.from(vekB64, "base64"));
  const releaseShare = Uint8Array.from(Buffer.from(RELEASE_SHARE_B64, "base64"));
  const salt = crypto.getRandomValues(new Uint8Array(32));

  const entry = await deriveManagedEntryKey(vek, releaseShare, salt, id, 1);
  const keyBytes = Uint8Array.from(Buffer.from(entry.keyBase64, "base64"));
  const encryptedSecret = await seal(JSON.stringify({ u: USERNAME, p: PASSWORD }), keyBytes, salt);

  const indexKey = await deriveDomainIndexKey(vek);
  const token = await computeLookupToken(origin, indexKey);
  if (!token.ok) throw new Error("fixture token failed");

  const existing =
    (localStore.get(RECORDS) as Record<string, unknown> | undefined) ?? {};
  localStore.set(RECORDS, {
    ...existing,
    [id]: {
      id,
      mode: "managed",
      encryptedSecret,
      salt: binaryToBase64(salt),
      version: 1,
      releaseShareRef,
      title: "GitHub (managed)",
      usernameHint: "o******",
    },
  });
  localStore.set(INDEX, addToIndex((localStore.get(INDEX) as OpaqueIndex | undefined) ?? emptyIndex(), token.token, id));
}

const AUTOFILL_BINDING = { credentialId: MANAGED_ID, origin: ORIGIN, operation: "AUTOFILL" as const };
const TOTP_BINDING = { credentialId: MANAGED_ID, origin: ORIGIN, operation: "TOTP" as const };

/**
 * A binding that belongs to no release under test.
 *
 * The sender tests exercise the wire format, and a completion recorded for
 * them must not pre-authorize anything later: using an unrelated binding keeps
 * the two groups from sharing authorization state. It still needs a real
 * managed record, because `START_STEP_UP` resolves the binding's release-share
 * reference from the record store before it can talk to Plus — and the
 * reference it sends is `PROBE_REF`, not the credential id.
 */
const PROBE_REF = "ref-probe";
const PROBE_BINDING: Binding = {
  credentialId: "cred-stepup-probe",
  origin: "https://example.com",
  operation: "AUTOFILL",
};

interface Binding {
  credentialId: string;
  origin: string;
  operation: "AUTOFILL" | "TOTP";
}

function releaseMessage(binding: Binding): BackgroundMessage {
  return {
    type: "RELEASE_CREDENTIAL",
    credentialId: binding.credentialId,
    origin: binding.origin,
    operation: binding.operation,
    documentOrigin: ORIGIN,
    topLevelOrigin: ORIGIN,
    isFramed: false,
  };
}

/* ------------------------------------------------------------------ */
/*  Suite                                                              */
/* ------------------------------------------------------------------ */

beforeAll(async () => {
  await import("../../src/background/auditor");
  expect(typeof onMessage).toBe("function");

  // Real unlock, not a seeded key: the fixture then starts from the same
  // session the product creates, and this is the only PBKDF2 the file pays.
  const unlocked = await dispatch({
    type: "UNLOCK_VAULT",
    vaultId: VAULT_ID,
    passphrase: PASSPHRASE,
  });
  expect(unlocked.ok).toBe(true);

  await seedManagedRecord(sessionStore.get("cybervault_vek") as string);
  // The probe binding's own record, so `START_STEP_UP` has a release-share
  // reference to send for it (see PROBE_BINDING).
  await seedManagedRecord(sessionStore.get("cybervault_vek") as string, {
    id: PROBE_BINDING.credentialId,
    origin: PROBE_BINDING.origin,
    releaseShareRef: PROBE_REF,
  });

  await createArea(localStore).set({
    cybervault_token: TOKEN,
    cybervault_userId: "user-1",
    plus_base_url: PLUS,
    plus_service_secret: "svc-secret",
    core_base_url: CORE,
  });
});

afterAll(async () => {
  globalThis.fetch = realFetch;
  delete (globalThis as unknown as { chrome?: unknown }).chrome;
});

describe("REQUEST_RELEASE_SHARE speaks Core's managed-release contract", () => {
  it("posts capabilityToken + credentialId to the caller's-vault URL with the JWT", async () => {
    calls.length = 0;

    const reply = await dispatch({
      type: "REQUEST_RELEASE_SHARE",
      payload: { capabilityToken: CAPABILITY_TOKEN, credentialId: MANAGED_ID },
    });

    expect(reply.ok).toBe(true);
    expect(reply.data).toEqual({ success: true, releaseShare: RELEASE_SHARE_B64 });

    const [call] = callsTo("/managed-release");
    expect(call).toBeDefined();
    // Exact path: the credential sits under the vault the worker unlocked, not
    // under anything the caller chose, and the share comes back for the
    // credential Core was asked about.
    expect(call.url).toBe(`${CORE}/api/v1/vaults/${VAULT_ID}/managed-release`);
    expect(call.method).toBe("POST");
    expect(call.headers.Authorization).toBe(`Bearer ${TOKEN}`);
    expect(Object.keys(call.body ?? {}).sort()).toEqual(["capabilityToken", "credentialId"]);
    expect(call.body?.credentialId).toBe(MANAGED_ID);
    // The Plus public key is never sent: Core pins that key itself since WU-1,
    // so transporting it would re-open the caller-chosen-key bypass.
    expect(Object.keys(call.body ?? {})).not.toContain("plusPublicKey");
  });

  it("surfaces a Core failure as a readable status line", async () => {
    coreFails = true;
    try {
      const reply = await dispatch({
        type: "REQUEST_RELEASE_SHARE",
        payload: { capabilityToken: CAPABILITY_TOKEN, credentialId: MANAGED_ID },
      });
      expect(reply.ok).toBe(false);
      expect(reply.error).toBe('Core API 500: {"error":"boom"}');
      expect(reply.error).not.toContain(PASSWORD);
    } finally {
      coreFails = false;
    }
  });

  it("refuses when there is no JWT to send", async () => {
    await createArea(localStore).remove("cybervault_token");
    calls.length = 0;
    try {
      const reply = await dispatch({
        type: "REQUEST_RELEASE_SHARE",
        payload: { capabilityToken: CAPABILITY_TOKEN, credentialId: MANAGED_ID },
      });
      expect(reply).toMatchObject({ ok: false, error: "Not authenticated" });
      // Nothing went out: no bearer token, no request at all.
      expect(callsTo("/managed-release")).toHaveLength(0);
    } finally {
      await createArea(localStore).set({ cybervault_token: TOKEN });
    }
  });
});

describe("D1 — every Plus call presents the service secret (R1 regression)", () => {
  /**
   * R1 put every non-probe Plus route behind `X-Service-Secret`. Four call
   * sites existed; two sent the header and two did not, so the step-up and
   * the public-key fetch returned 401 and managed release was dead in the
   * real extension. The stubs above answer 200 unconditionally, which is
   * exactly why the suite stayed green through it.
   *
   * Each case performs its own dispatch and inspects only the calls that
   * dispatch produced, so ordering between describes cannot matter.
   */
  const PLUS_SECRET = "svc-secret";

  it("presents the secret when asking for a capability", async () => {
    // `RELEASE_CREDENTIAL` is the path that actually calls
    // `/capabilities/request`; `REQUEST_RELEASE_SHARE` carries a capability
    // the caller already holds and never asks Plus for one.
    calls.length = 0;
    capabilityMode = "grant";

    const reply = await dispatch(releaseMessage(AUTOFILL_BINDING));
    void reply;

    const call = callsTo("/api/v1/capabilities/request").at(-1);
    expect(call).toBeDefined();
    expect(call!.headers["X-Service-Secret"]).toBe(PLUS_SECRET);
  });

  it("presents the secret when triggering a challenge", async () => {
    calls.length = 0;

    const reply = await dispatch({ type: "START_STEP_UP", binding: PROBE_BINDING });
    void reply;

    const call = callsTo("/api/v1/challenges/trigger").at(-1);
    expect(call).toBeDefined();
    expect(call!.headers["X-Service-Secret"]).toBe(PLUS_SECRET);
  });

  it("presents the secret when verifying a challenge", async () => {
    calls.length = 0;

    const started = await dispatch({ type: "START_STEP_UP", binding: PROBE_BINDING });
    const challengeId = (started.data as { challengeId?: string } | undefined)?.challengeId;
    expect(challengeId).toBeDefined();
    calls.length = 0;

    await dispatch({ type: "APPROVE_STEP_UP", challengeId: challengeId as string });

    const call = callsTo("/api/v1/challenges/approve").at(-1);
    expect(call).toBeDefined();
    expect(call!.headers["X-Service-Secret"]).toBe(PLUS_SECRET);
  });
});

describe("step-up senders reach Plus", () => {
  it("START_STEP_UP triggers a challenge bound to the requested binding", async () => {
    calls.length = 0;

    const reply = await dispatch({ type: "START_STEP_UP", binding: PROBE_BINDING });

    expect(reply.ok).toBe(true);
    expect(reply.data).toMatchObject({ challengeId: "ch-1", binding: PROBE_BINDING });

    const [call] = callsTo("/api/v1/challenges/trigger");
    expect(call).toBeDefined();
    expect(call.url).toBe(`${PLUS}/api/v1/challenges/trigger`);
    expect(call.method).toBe("POST");
    expect(call.headers.Authorization).toBe(`Bearer ${TOKEN}`);
    // The resource and secret reference are the release-share reference, not
    // the credential id: that is the value the capability request sends as
    // `resourceId`, so it is the only name both legs of the step-up agree on.
    expect(call.body).toMatchObject({
      userId: "user-1",
      resourceId: PROBE_REF,
      secretRef: PROBE_REF,
      operation: "AUTOFILL",
    });
    expect(call.body?.resourceId).not.toBe(PROBE_BINDING.credentialId);
  });

  it("refuses to start a step-up for a credential the worker does not hold", async () => {
    calls.length = 0;
    const reply = await dispatch({
      type: "START_STEP_UP",
      binding: { ...PROBE_BINDING, credentialId: "cred-does-not-exist" },
    });
    // Fail closed: there is no release to authorize, so no challenge is asked
    // for and nothing goes out on the wire.
    expect(reply).toMatchObject({ ok: false, error: "BINDING_NOT_MANAGED" });
    expect(callsTo("/api/v1/challenges/trigger")).toHaveLength(0);
  });

  it("APPROVE_STEP_UP signs with Core, then forwards the approval to Plus", async () => {
    calls.length = 0;

    const reply = await dispatch({ type: "APPROVE_STEP_UP", challengeId: "ch-1" });

    expect(reply).toEqual({ ok: true, data: { verified: true } });

    // Core is asked first, and the request names only the credential and the
    // operation. The user comes from the Bearer token and the secretRef from
    // Core's own records, so neither can be supplied by this side.
    const [signed] = callsTo("/api/v1/step-up/approve");
    expect(signed).toBeDefined();
    expect(signed.url).toBe(`${CORE}/api/v1/step-up/approve`);
    expect(signed.headers.Authorization).toBe(`Bearer ${TOKEN}`);
    expect(Object.keys(signed.body ?? {}).sort()).toEqual([
      "challengeId",
      "credentialId",
      "operation",
    ]);
    expect(signed.body).not.toHaveProperty("secretRef");
    expect(signed.body).not.toHaveProperty("userId");

    // Then Plus verifies it.
    const [approved] = callsTo("/api/v1/challenges/approve");
    expect(approved).toBeDefined();
    expect(approved.url).toBe(`${PLUS}/api/v1/challenges/approve`);
    expect(approved.headers.Authorization).toBe(`Bearer ${TOKEN}`);
    expect(Object.keys(approved.body ?? {}).sort()).toEqual(["approval", "challengeId"]);
  });

  it("never sends a PIN on the approve path", async () => {
    calls.length = 0;

    await dispatch({ type: "APPROVE_STEP_UP", challengeId: "ch-1" });

    for (const call of callsTo("/api/v1/step-up/approve").concat(callsTo("/api/v1/challenges/approve"))) {
      expect(call.body).not.toHaveProperty("pin");
      expect(JSON.stringify(call.body)).not.toMatch(/"pin"/i);
    }
  });

  it("does not contact Plus when Core refuses to sign", async () => {
    // A real challenge has to exist first, otherwise this would pass for the
    // wrong reason: an unknown challenge is refused before Core is contacted.
    await dispatch({ type: "START_STEP_UP", binding: PROBE_BINDING });
    calls.length = 0;
    coreApproveFails = true;

    const reply = await dispatch({ type: "APPROVE_STEP_UP", challengeId: "ch-1" });

    // A Core refusal must not be forwarded verbatim: its reason could say
    // "credential not found" or "no signing key configured", which is more than
    // the caller needs to know.
    expect(reply).toMatchObject({ ok: false, error: "the release could not be approved" });
    expect(callsTo("/api/v1/challenges/approve")).toHaveLength(0);
    coreApproveFails = false;
  });

  it("refuses an unknown challenge without contacting Plus", async () => {
    calls.length = 0;

    const reply = await dispatch({ type: "APPROVE_STEP_UP", challengeId: "never-issued" });

    expect(reply).toMatchObject({ ok: false, error: "the approval was not accepted" });
    expect(callsTo("/api/v1/challenges/verify")).toHaveLength(0);
  });

  it("refuses to start a challenge for an incomplete binding", async () => {
    const reply = await dispatch({ type: "START_STEP_UP", binding: { ...PROBE_BINDING, origin: "" } });
    expect(reply).toMatchObject({ ok: false, error: "BINDING_MISSING" });
  });
});

describe("a completed step-up releases its own binding and no other", () => {
  it("gates, unbinds one binding, and leaves the other gated", async () => {
    capabilityMode = "challenge";
    calls.length = 0;

    // 1. Both bindings are refused for want of a third factor. Each refusal
    //    registers its own binding, which is what later gates the retry.
    const refusedAutofill = await dispatch(releaseMessage(AUTOFILL_BINDING));
    expect(refusedAutofill).toEqual({
      ok: false,
      error: "CHALLENGE_REQUIRED",
      data: { code: "CHALLENGE_REQUIRED" },
    });

    const refusedTotp = await dispatch(releaseMessage(TOTP_BINDING));
    expect(refusedTotp).toEqual({
      ok: false,
      error: "CHALLENGE_REQUIRED",
      data: { code: "CHALLENGE_REQUIRED" },
    });

    // 2. The popup asks which releases are still owed a factor.
    const pending = await dispatch({ type: "GET_PENDING_STEP_UP" });
    expect(pending.ok).toBe(true);
    expect(pending.data).toEqual(
      expect.arrayContaining([
        expect.objectContaining(AUTOFILL_BINDING),
        expect.objectContaining(TOTP_BINDING),
      ]),
    );

    // 3. Complete the step-up for ONE of them.
    const started = await dispatch({ type: "START_STEP_UP", binding: AUTOFILL_BINDING });
    expect(started.ok).toBe(true);
    const challengeId = (started.data as { challengeId: string }).challengeId;

    const verified = await dispatch({ type: "APPROVE_STEP_UP", challengeId });
    expect(verified).toEqual({ ok: true, data: { verified: true } });

    // The pending list now names only the binding that is still owed.
    const stillPending = await dispatch({ type: "GET_PENDING_STEP_UP" });
    expect(stillPending.data).toEqual([expect.objectContaining(TOTP_BINDING)]);

    // 4. Plus now issues a capability and Core releases the share: the
    //    completed binding goes through end to end.
    capabilityMode = "grant";
    calls.length = 0;
    const released = await dispatch(releaseMessage(AUTOFILL_BINDING));
    expect(released).toEqual({
      ok: true,
      data: { id: MANAGED_ID, username: USERNAME, password: PASSWORD },
    });
    expect(callsTo("/capabilities/request")).toHaveLength(1);
    expect(callsTo("/managed-release")).toHaveLength(1);

    // 5. The OTHER binding is still gated — and gated without another round
    //    trip: the refusal is remembered, so the page cannot use a completed
    //    step-up as a general-purpose unlock, and cannot even probe Plus.
    const capabilityCallsSoFar = callsTo("/capabilities/request").length;
    const stillGated = await dispatch(releaseMessage(TOTP_BINDING));
    expect(stillGated).toEqual({
      ok: false,
      error: "CHALLENGE_REQUIRED",
      data: { code: "CHALLENGE_REQUIRED" },
    });
    expect(callsTo("/capabilities/request")).toHaveLength(capabilityCallsSoFar);
    expect(JSON.stringify(stillGated)).not.toContain(PASSWORD);
  });
});
