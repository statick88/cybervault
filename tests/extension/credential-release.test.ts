/**
 * Credential release tests (service-worker side).
 *
 * The properties under test, in order of importance:
 *
 *   1. ORDERING — the guard runs BEFORE any decryption. A credential must not
 *      exist in plaintext while we decide whether to release it.
 *   2. BINDING — a credential bound to origin A can never be released for
 *      origin B, even if the caller lies about the origin.
 *   3. SPLIT TRUST — a managed credential needs a Release Share; the personal
 *      path must not work for a managed record and vice versa.
 *   4. FAIL CLOSED — every failure path returns a denial, never a partial
 *      credential.
 */

import {
  listCandidatesForOrigin,
  releaseCredential,
  type EncryptedCredentialRecord,
  type ReleaseDeps,
  type ReleaseRequest,
} from "../../src/background/credential-release";
import { deriveDomainIndexKey, addToIndex, emptyIndex } from "../../src/domain/services/autofill/domain-index";
import { derivePersonalEntryKey } from "../../src/infrastructure/crypto/hkdf-derivation";
import { binaryToBase64 } from "../../src/shared/utils";

const ORIGIN = "https://github.com";
const PASSWORD = "correct horse battery staple";
const TOTP_SEED = "JBSWY3DPEHPK3PXP";

/* ------------------------------------------------------------------ */
/*  Fixture builders                                                   */
/* ------------------------------------------------------------------ */

function toArrayBuffer(d: Uint8Array): ArrayBuffer {
  const b = new ArrayBuffer(d.byteLength);
  new Uint8Array(b).set(d);
  return b;
}

/** Encrypt `plaintext` into the `salt|iv|ciphertext` layout the store expects. */
async function seal(
  plaintext: string,
  keyBytes: Uint8Array,
  salt: Uint8Array,
): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.importKey(
    "raw",
    toArrayBuffer(keyBytes),
    "AES-GCM",
    false,
    ["encrypt"],
  );
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

interface Fixture {
  deps: ReleaseDeps;
  vek: Uint8Array;
  record: EncryptedCredentialRecord;
  calls: { capability: number; getRecord: number };
  setCapability(
    result:
      | { ok: true; releaseShare: string }
      | { ok: false; challengeRequired: true }
      | { ok: false; challengeRequired?: false; detail: string },
  ): void;
  removeFromIndex(credentialId: string): Promise<void>;
}

async function makePersonalFixture(opts: { origin?: string; withTotp?: boolean } = {}): Promise<Fixture> {
  const origin = opts.origin ?? ORIGIN;
  const vek = crypto.getRandomValues(new Uint8Array(32));
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const recordId = "cred-1";

  const entryKey = await derivePersonalEntryKey(vek, salt, recordId, 1);
  const keyBytes = Uint8Array.from(atob(entryKey.keyBase64), (c) => c.charCodeAt(0));

  // Built through the real authoring path so the writer and the reader can
  // never drift apart: a renamed field would break here rather than silently
  // producing an unreleasable record in production.
  const { authorCredential } = await import(
    "../../src/domain/services/autofill/credential-authoring"
  );
  const authored = await authorCredential(
    {
      origin,
      username: "octocat",
      password: PASSWORD,
      title: "GitHub",
      totpSeedBase32: opts.withTotp ? TOTP_SEED : undefined,
      id: recordId,
    },
    vek,
    null,
  );
  if (!authored.ok) throw new Error(`fixture authoring failed: ${authored.reason}`);

  const record: EncryptedCredentialRecord = {
    id: authored.record.id,
    mode: "personal",
    encryptedSecret: authored.record.encryptedSecret,
    encryptedTotpSecret: authored.record.encryptedTotpSecret,
    salt: authored.record.salt,
    version: authored.record.version,
    usernameHint: authored.record.usernameHint,
    title: authored.record.title,
  };

  const indexKey = await deriveDomainIndexKey(vek);
  const { computeLookupToken } = await import("../../src/domain/services/autofill/domain-index");
  const token = await computeLookupToken(origin, indexKey);
  if (!token.ok) throw new Error("fixture token failed");

  const index = addToIndex(emptyIndex(), token.token, recordId);
  const calls = { capability: 0, getRecord: 0 };
  let capabilityResult: Parameters<ReleaseDeps["requestCapability"]> extends never ? never : Awaited<ReturnType<ReleaseDeps["requestCapability"]>> = {
    ok: false,
    detail: "not configured",
  };

  const deps: ReleaseDeps = {
    getVek: async () => vek,
    getIndex: async () => index,
    getRecord: async (id) => {
      calls.getRecord += 1;
      return id === recordId ? record : null;
    },
    requestCapability: async () => {
      calls.capability += 1;
      return capabilityResult;
    },
  };

  return {
    deps,
    vek,
    record,
    calls,
    setCapability: (result) => {
      capabilityResult = result as never;
    },
    removeFromIndex: async (credentialId) => {
      const next = { version: 1 as const, byToken: { ...index.byToken } };
      for (const k of Object.keys(next.byToken)) {
        next.byToken[k] = next.byToken[k].filter((id) => id !== credentialId);
        if (next.byToken[k].length === 0) delete next.byToken[k];
      }
      deps.getIndex = async () => next;
    },
  };
}

function request(overrides: Partial<ReleaseRequest> = {}): ReleaseRequest {
  return {
    credentialId: "cred-1",
    origin: ORIGIN,
    operation: "AUTOFILL",
    documentOrigin: ORIGIN,
    topLevelOrigin: ORIGIN,
    isFramed: false,
    ...overrides,
  };
}

/* ------------------------------------------------------------------ */

describe("listCandidatesForOrigin", () => {
  it("returns non-secret metadata for a bound origin", async () => {
    const f = await makePersonalFixture({ withTotp: true });
    const list = await listCandidatesForOrigin(ORIGIN, f.deps);

    expect(list).toHaveLength(1);
    expect(list[0]).toMatchObject({
      credentialId: "cred-1",
      origin: "https://github.com:443",
      hasTotp: true,
    });
    // The user-authored title is what disambiguates two accounts on one
    // origin; the redacted username hint cannot.
    expect(list[0].title).toBe("GitHub");
    expect(list[0].usernameHint).toBe("o******");
  });

  it("never includes a username, password or seed", async () => {
    const f = await makePersonalFixture({ withTotp: true });
    const list = await listCandidatesForOrigin(ORIGIN, f.deps);
    const serialized = JSON.stringify(list);

    expect(serialized).not.toContain(PASSWORD);
    expect(serialized).not.toContain(TOTP_SEED);
    expect(serialized).not.toContain("octocat");
  });

  it("returns nothing for an origin with no credentials", async () => {
    const f = await makePersonalFixture();
    expect(await listCandidatesForOrigin("https://gitlab.com", f.deps)).toEqual([]);
  });

  it("returns nothing when the vault is locked", async () => {
    const f = await makePersonalFixture();
    f.deps.getVek = async () => null;
    expect(await listCandidatesForOrigin(ORIGIN, f.deps)).toEqual([]);
  });

  it("skips index entries whose record has vanished", async () => {
    const f = await makePersonalFixture();
    f.deps.getRecord = async () => null;
    expect(await listCandidatesForOrigin(ORIGIN, f.deps)).toEqual([]);
  });

  it("returns nothing for an unusable origin", async () => {
    const f = await makePersonalFixture();
    expect(await listCandidatesForOrigin("not a url", f.deps)).toEqual([]);
  });
});

describe("releaseCredential — happy path", () => {
  it("releases a personal credential on the exact origin", async () => {
    const f = await makePersonalFixture();
    const outcome = await releaseCredential(request(), f.deps);

    expect(outcome.ok).toBe(true);
    if (!outcome.ok) throw new Error("unreachable");
    expect(outcome.credential.password).toBe(PASSWORD);
    expect(outcome.credential.username).toBe("octocat");
  });

  it("returns the TOTP seed as base64 of the original seed bytes", async () => {
    const f = await makePersonalFixture({ withTotp: true });
    const outcome = await releaseCredential(request(), f.deps);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) throw new Error("unreachable");

    // The seed is stored and returned as base64 because that is what
    // generateTOTP() consumes — base32 is the provisioning wire format, not the
    // runtime one. Asserting the byte round-trip rather than string equality
    // keeps the test honest about the representation change.
    const { base32ToBase64 } = await import(
      "../../src/ui/content-scripts/totp-generator"
    );
    expect(outcome.credential.totpSecret).toBe(base32ToBase64(TOTP_SEED));
    expect(
      Buffer.from(outcome.credential.totpSecret as string, "base64").toString("hex"),
    ).toBe(
      Buffer.from(base32ToBase64(TOTP_SEED), "base64").toString("hex"),
    );
  });

  it("omits the TOTP seed when the record has none", async () => {
    const f = await makePersonalFixture();
    const outcome = await releaseCredential(request(), f.deps);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) throw new Error("unreachable");
    expect(outcome.credential.totpSecret).toBeUndefined();
  });

  it("does not request a capability for a personal credential", async () => {
    const f = await makePersonalFixture();
    await releaseCredential(request(), f.deps);
    expect(f.calls.capability).toBe(0);
  });
});

describe("releaseCredential — ordering: guard runs before decryption", () => {
  it("does not decrypt when the guard blocks", async () => {
    const f = await makePersonalFixture();
    const before = f.calls.getRecord;

    const outcome = await releaseCredential(
      request({ documentOrigin: "https://evil.example" }),
      f.deps,
    );

    expect(outcome.ok).toBe(false);
    if (outcome.ok) throw new Error("unreachable");
    expect(outcome.code).toBe("GUARD_BLOCKED");
    // The record is read (needed for the mode check) but nothing is returned.
    expect(f.calls.getRecord).toBe(before + 1);
  });

  it("refuses a hostile top-level frame", async () => {
    const f = await makePersonalFixture();
    const outcome = await releaseCredential(
      request({ isFramed: true, topLevelOrigin: "https://evil.example" }),
      f.deps,
    );
    expect(outcome.ok).toBe(false);
    if (outcome.ok) throw new Error("unreachable");
    expect(outcome.code).toBe("GUARD_BLOCKED");
  });

  it("refuses when the document origin downgrades the scheme", async () => {
    const f = await makePersonalFixture();
    const outcome = await releaseCredential(
      request({ documentOrigin: "http://github.com" }),
      f.deps,
    );
    expect(outcome.ok).toBe(false);
    if (outcome.ok) throw new Error("unreachable");
    expect(outcome.code).toBe("GUARD_BLOCKED");
  });
});

describe("releaseCredential — origin binding (§6.6)", () => {
  it("refuses when the credential is not in the origin's bucket", async () => {
    const f = await makePersonalFixture();
    await f.removeFromIndex("cred-1");

    const outcome = await releaseCredential(request(), f.deps);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) throw new Error("unreachable");
    expect(outcome.code).toBe("ORIGIN_NOT_BOUND");
  });

  it("refuses an origin the caller did not register", async () => {
    const f = await makePersonalFixture();
    // The caller lies: claims evil.example while holding a github credential.
    const outcome = await releaseCredential(
      request({
        origin: "https://evil.example",
        documentOrigin: "https://evil.example",
        topLevelOrigin: "https://evil.example",
      }),
      f.deps,
    );
    expect(outcome.ok).toBe(false);
    if (outcome.ok) throw new Error("unreachable");
    expect(outcome.code).toBe("ORIGIN_NOT_BOUND");
  });

  it("refuses a subdomain of the bound origin", async () => {
    const f = await makePersonalFixture();
    const outcome = await releaseCredential(
      request({
        origin: "https://www.github.com",
        documentOrigin: "https://www.github.com",
      }),
      f.deps,
    );
    expect(outcome.ok).toBe(false);
    if (outcome.ok) throw new Error("unreachable");
    expect(outcome.code).toBe("ORIGIN_NOT_BOUND");
  });

  it("refuses an unusable origin", async () => {
    const f = await makePersonalFixture();
    const outcome = await releaseCredential(request({ origin: "not a url" }), f.deps);
    expect(outcome.ok).toBe(false);
    if (outcome.ok) throw new Error("unreachable");
    expect(outcome.code).toBe("ORIGIN_UNUSABLE");
  });

  it("accepts equivalent spellings of the same origin", async () => {
    const f = await makePersonalFixture();
    const outcome = await releaseCredential(
      request({ origin: "https://GitHub.com:443" }),
      f.deps,
    );
    expect(outcome.ok).toBe(true);
  });
});

describe("releaseCredential — fail closed", () => {
  it("refuses when the vault is locked", async () => {
    const f = await makePersonalFixture();
    f.deps.getVek = async () => null;
    const outcome = await releaseCredential(request(), f.deps);
    expect(outcome).toMatchObject({ ok: false, code: "VAULT_LOCKED" });
  });

  it("refuses an unknown credential", async () => {
    const f = await makePersonalFixture();
    f.deps.getRecord = async () => null;
    const outcome = await releaseCredential(request(), f.deps);
    expect(outcome).toMatchObject({ ok: false, code: "CREDENTIAL_NOT_FOUND" });
  });

  it("refuses a managed record with no Release Share reference", async () => {
    const f = await makePersonalFixture();
    f.record.mode = "managed";
    delete f.record.releaseShareRef;
    const outcome = await releaseCredential(request(), f.deps);
    expect(outcome).toMatchObject({ ok: false, code: "MANAGED_REQUIRED" });
  });

  it("refuses rather than throwing when the index is corrupt", async () => {
    const f = await makePersonalFixture();
    f.deps.getIndex = async () => ({ version: 1, byToken: null }) as never;
    const outcome = await releaseCredential(request(), f.deps);
    expect(outcome.ok).toBe(false);
  });

  it("returns a denial, never a partial credential, on any failure", async () => {
    const f = await makePersonalFixture();
    for (const origin of ["", "nope", "https://evil.example", "http://github.com"]) {
      const outcome = await releaseCredential(
        request({ origin, documentOrigin: origin || ORIGIN }),
        f.deps,
      );
      if (outcome.ok) {
        throw new Error(`unexpectedly released for origin "${origin}"`);
      }
      expect(outcome).not.toHaveProperty("credential");
    }
  });
});

describe("releaseCredential — managed split trust", () => {
  async function makeManagedFixture(): Promise<Fixture & { releaseShare: Uint8Array }> {
    const f = await makePersonalFixture();
    const { deriveManagedEntryKey } = await import(
      "../../src/infrastructure/crypto/hkdf-derivation"
    );
    const releaseShare = crypto.getRandomValues(new Uint8Array(32));
    const salt = Uint8Array.from(atob(f.record.salt), (c) => c.charCodeAt(0));

    const derived = await deriveManagedEntryKey(
      f.vek,
      releaseShare,
      salt,
      f.record.id,
      f.record.version,
    );
    const keyBytes = Uint8Array.from(atob(derived.keyBase64), (c) => c.charCodeAt(0));

    f.record.mode = "managed";
    f.record.releaseShareRef = "opaque-ref-1";
    // Managed entries are sealed to HKDF(VEK || ReleaseShare); personal
    // authoring cannot produce that, so the fixture re-seals the envelope.
    f.record.encryptedSecret = await seal(
      JSON.stringify({ u: "octocat", p: PASSWORD }),
      keyBytes,
      salt,
    );

    return Object.assign(f, { releaseShare });
  }

  it("releases with the correct VEK + Release Share", async () => {
    const f = await makeManagedFixture();
    f.setCapability({ ok: true, releaseShare: binaryToBase64(f.releaseShare) });

    const outcome = await releaseCredential(request(), f.deps);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) throw new Error("unreachable");
    expect(outcome.credential.password).toBe(PASSWORD);
    expect(f.calls.capability).toBe(1);
  });

  it("refuses when the Release Share is wrong", async () => {
    const f = await makeManagedFixture();
    const wrong = crypto.getRandomValues(new Uint8Array(32));
    f.setCapability({ ok: true, releaseShare: binaryToBase64(wrong) });

    const outcome = await releaseCredential(request(), f.deps);
    expect(outcome).toMatchObject({ ok: false, code: "DECRYPT_FAILED" });
  });

  it("reports a required step-up instead of a generic failure", async () => {
    const f = await makeManagedFixture();
    f.setCapability({ ok: false, challengeRequired: true });

    const outcome = await releaseCredential(request(), f.deps);
    expect(outcome).toMatchObject({ ok: false, code: "CHALLENGE_REQUIRED" });
  });

  it("reports a capability denial", async () => {
    const f = await makeManagedFixture();
    f.setCapability({ ok: false, detail: "entitlement closed" });

    const outcome = await releaseCredential(request(), f.deps);
    expect(outcome).toMatchObject({ ok: false, code: "CAPABILITY_DENIED" });
  });

  it("does not request a capability when the guard blocks", async () => {
    const f = await makeManagedFixture();
    f.setCapability({ ok: true, releaseShare: binaryToBase64(f.releaseShare) });

    // The caller holds a genuine github credential and names github as the
    // origin, so the binding proof passes. The GUARD is what must catch the
    // hostile document — and it must do so before any capability is minted.
    const outcome = await releaseCredential(
      request({ documentOrigin: "https://evil.example" }),
      f.deps,
    );

    expect(outcome).toMatchObject({ ok: false, code: "GUARD_BLOCKED" });
    expect(f.calls.capability).toBe(0);
  });

  it("does not request a capability when the origin binding fails", async () => {
    const f = await makeManagedFixture();
    f.setCapability({ ok: true, releaseShare: binaryToBase64(f.releaseShare) });

    // Here the binding proof itself fails, before the guard is even reached.
    const outcome = await releaseCredential(
      request({ origin: "https://evil.example", documentOrigin: "https://evil.example" }),
      f.deps,
    );

    expect(outcome).toMatchObject({ ok: false, code: "ORIGIN_NOT_BOUND" });
    expect(f.calls.capability).toBe(0);
  });
});
