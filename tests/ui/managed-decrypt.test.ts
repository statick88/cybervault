/**
 * S2 batch 3 — `src/ui/content-scripts/managed-decrypt.ts` unit tests.
 *
 * The file is the extension-side half of the split-trust release path: it asks
 * the service worker for a capability, trades that capability for the Release
 * Share, derives the per-entry key with HKDF and opens the AES-GCM payload.
 *
 * Everything real is exercised here — HKDF, AES-GCM, `secureZero` — because a
 * mocked `crypto.subtle` would only prove the mocks agree with themselves. The
 * only double is `chrome.runtime.sendMessage`, which is a browser boundary no
 * unit test can cross.
 *
 * The suite runs in the default Node environment on purpose: jsdom ships a
 * `crypto` object WITHOUT `subtle`, and this module cannot do anything without
 * WebCrypto. Node 24 exposes `crypto.subtle`, `navigator.userAgent` and
 * `atob`, so the extension context is faithful without a DOM.
 *
 * No live database, no Docker, no network, no browser.
 */

import {
  decryptCredential,
  decryptManagedCredential,
  decryptPersonalCredential,
  requestManagedCapability,
  requestReleaseShare,
  type CapabilityRequest,
} from "../../src/ui/content-scripts/managed-decrypt";
import {
  deriveManagedEntryKey,
  derivePersonalEntryKey,
} from "../../src/infrastructure/crypto/hkdf-derivation";
import { base64ToBinary, binaryToBase64 } from "../../src/shared/utils";

/* -------------------------------------------------------------------------- */
/* chrome.runtime double                                                      */
/* -------------------------------------------------------------------------- */

interface SendMessageOutcome {
  response?: unknown;
  lastError?: { message: string };
}

type Responder = (message: any) => SendMessageOutcome;

const runtime: {
  lastError?: { message: string };
  sendMessage: jest.Mock;
} = {
  lastError: undefined,
  sendMessage: jest.fn(),
};

let responder: Responder = () => ({ response: { ok: true, data: {} } });

runtime.sendMessage.mockImplementation(
  (message: unknown, callback?: (response: unknown) => void) => {
    const outcome = responder(message);
    runtime.lastError = outcome.lastError;
    if (callback) {
      callback(outcome.response);
      // Chrome clears lastError once the callback has returned.
      runtime.lastError = undefined;
    }
    return Promise.resolve(outcome.response);
  },
);

(globalThis as unknown as { chrome: unknown }).chrome = { runtime };

beforeEach(() => {
  responder = () => ({ response: { ok: true, data: {} } });
  runtime.sendMessage.mockClear();
  jest.spyOn(console, "error").mockImplementation(() => undefined);
});

afterEach(() => {
  jest.restoreAllMocks();
});

/* -------------------------------------------------------------------------- */
/* Crypto fixtures                                                             */
/* -------------------------------------------------------------------------- */

function toArrayBuffer(data: Uint8Array): ArrayBuffer {
  const buf = new ArrayBuffer(data.byteLength);
  new Uint8Array(buf).set(data);
  return buf;
}

function randomBase64(bytes: number): string {
  return binaryToBase64(crypto.getRandomValues(new Uint8Array(bytes)));
}

/** `salt(32) | iv(12) | ciphertext+tag`, the format `decryptAESGCM` expects. */
async function seal(keyBase64: string, plaintext: string): Promise<string> {
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey(
    "raw",
    toArrayBuffer(base64ToBinary(keyBase64)),
    "AES-GCM",
    false,
    ["encrypt"],
  );
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: toArrayBuffer(iv), tagLength: 128 },
    key,
    toArrayBuffer(new TextEncoder().encode(plaintext)),
  );

  const combined = new Uint8Array(salt.length + iv.length + ciphertext.byteLength);
  combined.set(salt, 0);
  combined.set(iv, salt.length);
  combined.set(new Uint8Array(ciphertext), salt.length + iv.length);
  return binaryToBase64(combined);
}

/* ========================================================================== */
/* Instrumentation                                                            */
/* ========================================================================== */

describe("managed-decrypt — instrumentation", () => {
  it("loads and instruments the module under test", () => {
    expect(typeof decryptCredential).toBe("function");
    expect(typeof decryptManagedCredential).toBe("function");
    expect(typeof decryptPersonalCredential).toBe("function");
    expect(typeof requestManagedCapability).toBe("function");
    expect(typeof requestReleaseShare).toBe("function");
  });
});

/* ========================================================================== */
/* requestManagedCapability                                                    */
/* ========================================================================== */

describe("requestManagedCapability", () => {
  const request: CapabilityRequest = {
    userId: "user-1",
    resourceId: "res-1",
    operation: "AUTOFILL",
    secretRef: "secret-1",
    assurance: 2,
    context: { userAgent: "jest", timestamp: 1 },
  };

  it("sends REQUEST_MANAGED_CAPABILITY and surfaces the issued token", async () => {
    const token = { payload: { jti: "jti-1" }, signature: "sig", protectedHeader: "hdr" };
    responder = (message) => {
      expect(message.type).toBe("REQUEST_MANAGED_CAPABILITY");
      expect(message.payload).toEqual(request);
      return { response: { ok: true, data: { success: true, capabilityToken: token } } };
    };

    const out = await requestManagedCapability(request);

    expect(out.success).toBe(true);
    expect(out.capabilityToken).toEqual(token);
    expect(runtime.sendMessage).toHaveBeenCalledTimes(1);
  });

  it("reports a refused capability from the worker envelope", async () => {
    responder = () => ({
      response: { ok: false, error: "assurance below policy" },
    });

    const out = await requestManagedCapability(request);

    expect(out.success).toBe(false);
    expect(out.error).toBe("assurance below policy");
    expect(out.capabilityToken).toBeUndefined();
  });

  it("reports a broken port rather than resolving as success", async () => {
    responder = () => ({
      response: undefined,
      lastError: { message: "Could not establish connection" },
    });

    const out = await requestManagedCapability(request);

    expect(out.success).toBe(false);
    expect(out.error).toBe("Could not establish connection");
  });

  it("treats an envelope without a token as a failure", async () => {
    responder = () => ({ response: { ok: true, data: { success: true } } });

    const out = await requestManagedCapability(request);

    // `success` is derived from the token, never echoed from the response:
    // a worker that claims success without issuing a capability must not
    // be believed.
    expect(out.success).toBe(false);
    expect(out.capabilityToken).toBeUndefined();
  });

  it("propagates the challenge fields the content script needs to continue", async () => {
    responder = () => ({
      response: {
        ok: true,
        data: { success: false, challengeRequired: true, challengeId: "ch-1", challengeExpiresAt: 42 },
      },
    });

    const out = await requestManagedCapability(request);

    expect(out.success).toBe(false);
    expect(out.challengeRequired).toBe(true);
    expect(out.challengeId).toBe("ch-1");
    expect(out.challengeExpiresAt).toBe(42);
  });
});

/* ========================================================================== */
/* requestReleaseShare                                                         */
/* ========================================================================== */

describe("requestReleaseShare", () => {
  const token = { payload: { jti: "jti-9" }, signature: "sig", protectedHeader: "hdr" };

  it("sends REQUEST_RELEASE_SHARE with the capability and credential id", async () => {
    responder = (message) => {
      expect(message.type).toBe("REQUEST_RELEASE_SHARE");
      expect(message.payload.capabilityToken).toEqual(token);
      expect(message.payload.credentialId).toBe("cred-1");
      return { response: { ok: true, data: { releaseShare: "share-base64" } } };
    };

    const out = await requestReleaseShare(token, "cred-1");

    expect(out).toEqual({ success: true, releaseShare: "share-base64" });
  });

  it("reports a refusal from Core", async () => {
    responder = () => ({ response: { ok: false, error: "capability already consumed" } });

    const out = await requestReleaseShare(token, "cred-1");

    expect(out.success).toBe(false);
    expect(out.error).toBe("capability already consumed");
    expect(out.releaseShare).toBeUndefined();
  });

  it("reports a broken port", async () => {
    responder = () => ({ response: undefined, lastError: { message: "The message port closed" } });

    const out = await requestReleaseShare(token, "cred-1");

    expect(out.success).toBe(false);
    expect(out.error).toBe("The message port closed");
  });

  it("treats an envelope with no share as a failure", async () => {
    responder = () => ({ response: { ok: true, data: {} } });

    const out = await requestReleaseShare(token, "cred-1");

    expect(out.success).toBe(false);
    expect(out.releaseShare).toBeUndefined();
  });
});

/* ========================================================================== */
/* decryptCredential dispatch                                                  */
/* ========================================================================== */

describe("decryptCredential dispatch", () => {
  const vek = randomBase64(32);

  it("routes a managed credential WITH a releaseShareRef down the managed path", async () => {
    responder = () => ({ response: { ok: false, error: "capability denied" } });

    const out = await decryptCredential(
      {
        id: "cred-1",
        encryptedPassword: "x",
        salt: randomBase64(32),
        version: 1,
        mode: "managed",
        releaseShareRef: "ref-1",
      },
      vek,
    );

    expect(out).toBeNull();
    expect(runtime.sendMessage).toHaveBeenCalledWith(
      expect.objectContaining({ type: "REQUEST_MANAGED_CAPABILITY" }),
      expect.any(Function),
    );
    expect(runtime.sendMessage).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "REQUEST_RELEASE_SHARE" }),
      expect.any(Function),
    );
  });

  it("routes a managed credential WITHOUT a releaseShareRef down the personal path", async () => {
    responder = () => ({ response: { ok: false, error: "no share needed" } });

    const out = await decryptCredential(
      {
        id: "cred-2",
        encryptedPassword: "x",
        salt: randomBase64(32),
        version: 1,
        mode: "managed",
      },
      vek,
    );

    expect(out).toBeNull();
    expect(runtime.sendMessage).not.toHaveBeenCalled();
  });

  it("routes a personal credential down the personal path", async () => {
    responder = () => ({ response: { ok: false } });

    const out = await decryptCredential(
      {
        id: "cred-3",
        encryptedPassword: "x",
        salt: randomBase64(32),
        version: 1,
        mode: "personal",
        releaseShareRef: "ref-3",
      },
      vek,
    );

    expect(out).toBeNull();
    expect(runtime.sendMessage).not.toHaveBeenCalled();
  });
});

/* ========================================================================== */
/* decryptManagedCredential — end to end                                       */
/* ========================================================================== */

describe("decryptManagedCredential", () => {
  const credentialId = "cred-managed-1";
  const releaseShareRef = "rs-ref-1";

  it("opens a payload sealed with HKDF(VEK || ReleaseShare, salt, context)", async () => {
    const vek = randomBase64(32);
    const releaseShare = randomBase64(32);
    const salt = randomBase64(32);
    const derived = await deriveManagedEntryKey(
      base64ToBinary(vek),
      base64ToBinary(releaseShare),
      base64ToBinary(salt),
      credentialId,
      1,
    );
    const encryptedPassword = await seal(derived.keyBase64, "super-secret");

    responder = (message) => {
      if (message.type === "REQUEST_MANAGED_CAPABILITY") {
        return {
          response: {
            ok: true,
            data: { success: true, capabilityToken: { payload: {}, signature: "s", protectedHeader: "h" } },
          },
        };
      }
      expect(message.type).toBe("REQUEST_RELEASE_SHARE");
      expect(message.payload.credentialId).toBe(credentialId);
      return { response: { ok: true, data: { releaseShare } } };
    };

    const out = await decryptManagedCredential(
      { encryptedPassword, salt, version: 1, releaseShareRef, id: credentialId },
      vek,
    );

    expect(out).toBe("super-secret");
    expect(runtime.sendMessage).toHaveBeenCalledTimes(2);
  });

  it("refuses when the capability is denied — no share is ever requested", async () => {
    responder = () => ({ response: { ok: false, error: "policy refused" } });

    const out = await decryptManagedCredential(
      { encryptedPassword: "x", salt: randomBase64(32), version: 1, releaseShareRef, id: credentialId },
      randomBase64(32),
    );

    expect(out).toBeNull();
    expect(runtime.sendMessage).toHaveBeenCalledTimes(1);
    expect(runtime.sendMessage).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "REQUEST_RELEASE_SHARE" }),
      expect.any(Function),
    );
  });

  it("refuses when the Release Share never arrives", async () => {
    responder = (message) =>
      message.type === "REQUEST_MANAGED_CAPABILITY"
        ? {
            response: {
              ok: true,
              data: { success: true, capabilityToken: { payload: {}, signature: "s", protectedHeader: "h" } },
            },
          }
        : { response: { ok: false, error: "share withheld" } };

    const out = await decryptManagedCredential(
      { encryptedPassword: "x", salt: randomBase64(32), version: 1, releaseShareRef, id: credentialId },
      randomBase64(32),
    );

    expect(out).toBeNull();
  });

  it("refuses when the share does not match the one the payload was sealed with", async () => {
    const vek = randomBase64(32);
    const salt = randomBase64(32);
    const derived = await deriveManagedEntryKey(
      base64ToBinary(vek),
      base64ToBinary(randomBase64(32)),
      base64ToBinary(salt),
      credentialId,
      1,
    );
    const encryptedPassword = await seal(derived.keyBase64, "super-secret");

    responder = (message) =>
      message.type === "REQUEST_MANAGED_CAPABILITY"
        ? {
            response: {
              ok: true,
              data: { success: true, capabilityToken: { payload: {}, signature: "s", protectedHeader: "h" } },
            },
          }
        : { response: { ok: true, data: { releaseShare: randomBase64(32) } } };

    const out = await decryptManagedCredential(
      { encryptedPassword, salt, version: 1, releaseShareRef, id: credentialId },
      vek,
    );

    expect(out).toBeNull();
  });

  it("refuses malformed ciphertext instead of throwing", async () => {
    const vek = randomBase64(32);
    responder = (message) =>
      message.type === "REQUEST_MANAGED_CAPABILITY"
        ? {
            response: {
              ok: true,
              data: { success: true, capabilityToken: { payload: {}, signature: "s", protectedHeader: "h" } },
            },
          }
        : { response: { ok: true, data: { releaseShare: randomBase64(32) } } };

    const out = await decryptManagedCredential(
      { encryptedPassword: "!!not base64!!", salt: randomBase64(32), version: 1, releaseShareRef, id: credentialId },
      vek,
    );

    expect(out).toBeNull();
  });

  it("refuses malformed VEK / salt input instead of throwing", async () => {
    responder = () => ({
      response: {
        ok: true,
        data: { success: true, capabilityToken: { payload: {}, signature: "s", protectedHeader: "h" } },
      },
    });

    const out = await decryptManagedCredential(
      { encryptedPassword: "x", salt: "!!", version: 1, releaseShareRef, id: credentialId },
      "!!",
    );

    expect(out).toBeNull();
  });
});

/* ========================================================================== */
/* decryptPersonalCredential                                                   */
/* ========================================================================== */

describe("decryptPersonalCredential", () => {
  it("opens a payload sealed with HKDF(VEK, salt, context)", async () => {
    const vek = randomBase64(32);
    const salt = randomBase64(32);
    const derived = await derivePersonalEntryKey(
      base64ToBinary(vek),
      base64ToBinary(salt),
      "cred-personal-1",
      3,
    );
    const encryptedPassword = await seal(derived.keyBase64, "personal-secret");

    const out = await decryptPersonalCredential(
      { encryptedPassword, salt, version: 3, id: "cred-personal-1" },
      vek,
    );

    expect(out).toBe("personal-secret");
  });

  it("refuses the wrong VEK", async () => {
    const salt = randomBase64(32);
    const derived = await derivePersonalEntryKey(
      base64ToBinary(randomBase64(32)),
      base64ToBinary(salt),
      "cred-personal-2",
      1,
    );
    const encryptedPassword = await seal(derived.keyBase64, "personal-secret");

    const out = await decryptPersonalCredential(
      { encryptedPassword, salt, version: 1, id: "cred-personal-2" },
      randomBase64(32),
    );

    expect(out).toBeNull();
  });

  it("refuses ciphertext bound to a different credential id", async () => {
    const vek = randomBase64(32);
    const salt = randomBase64(32);
    const derived = await derivePersonalEntryKey(
      base64ToBinary(vek),
      base64ToBinary(salt),
      "cred-author-A",
      1,
    );
    const encryptedPassword = await seal(derived.keyBase64, "personal-secret");

    const out = await decryptPersonalCredential(
      { encryptedPassword, salt, version: 1, id: "cred-author-B" },
      vek,
    );

    expect(out).toBeNull();
  });

  it("refuses malformed ciphertext instead of throwing", async () => {
    const out = await decryptPersonalCredential(
      { encryptedPassword: "!!", salt: randomBase64(32), version: 1, id: "cred-x" },
      randomBase64(32),
    );

    expect(out).toBeNull();
  });
});
