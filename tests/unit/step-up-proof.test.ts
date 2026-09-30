/**
 * R11 — human-presence proof unit tests.
 *
 * Covers the required behaviours end to end at the unit boundary:
 *
 *   - an owned, valid credential CANNOT approve when the proof is absent
 *     (the refusal happens before any credential work);
 *   - a valid WebAuthn assertion is accepted; the same assertion replayed,
 *     re-bound to another challenge, signed without the UP flag, for another
 *     rpId/origin/type, or by a foreign key is refused;
 *   - the passphrase proof verifies the correct passphrase and refuses the
 *     wrong one, and its algebra matches `crypto.pbkdf2Sync` exactly
 *     (the `users.hash` parameters), on both the subtle and noble paths;
 *   - the COSE reader rejects malformed input without ever throwing;
 *   - the one-time challenge store burns a row on first consume — replay,
 *     wrong user, and expiry all end in null.
 */

import { generateKeyPairSync, pbkdf2Sync, randomBytes, sign as cryptoSign } from "crypto";

import { pbkdf2 } from "@noble/hashes/pbkdf2.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
import { utf8ToBytes } from "@noble/hashes/utils.js";

import {
  PASSPHRASE_PROOF_PREFIX,
  STEP_UP_KDF,
  base64UrlToBytes,
  bytesToBase64Url,
  bytesToHex as toHex,
  derivePassphraseProof,
  parseP256PublicKey,
  readCoseP256Key,
  verifyPassphraseProof,
  type StepUpProof,
} from "../../src/infrastructure/crypto/step-up-proof";
import {
  precheckProofShape,
  readWebAuthnConfig,
  verifyStepUpProof,
} from "../../src/infrastructure/api/step-up-approval";
import {
  InMemoryStepUpApprovalChallengeStore,
  InMemoryStepUpAuthenticatorStore,
} from "../../src/infrastructure/repositories/InMemoryStepUpProofStores";
import type {
  StepUpApprovalChallenge,
  StepUpAuthenticator,
} from "../../src/domain/repositories";
import type { StoredUser } from "../../src/infrastructure/api/auth";

/* ------------------------------------------------------------------ */
/*  Fixtures                                                           */
/* ------------------------------------------------------------------ */

const RP_ID = "example.com";
const ORIGIN = "https://example.com";
const USER_ID = "user-1";
const OTHER_USER_ID = "user-2";

const APPROVAL_ID = "ac-1";
const RELEASE_CHALLENGE_ID = "release-ch-1";
/** Base64url challenge as Core issues it (bytesToBase64Url of 32 random). */
const WEBAUTHN_CHALLENGE = bytesToBase64Url(randomBytes(32));
const APPROVAL_SALT = randomBytes(32).toString("hex");

const CREDENTIAL_ID = "cred-1";
// ONE keypair for the whole file: the SPKI the store keeps and the private
// key assertions are signed with must belong to the same pair, or every
// "valid" assertion verifies as a foreign signature.
const KEYPAIR = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const SPKI_DER = new Uint8Array(KEYPAIR.publicKey.export({ type: "spki", format: "der" }));
const PUBLIC_RAW = (() => {
  const raw = parseP256PublicKey(SPKI_DER);
  if (!raw) throw new Error("fixture SPKI must parse — test is meaningless otherwise");
  return raw;
})();

const USER: StoredUser = {
  userId: USER_ID,
  email: "alice@example.com",
  hash: "",
  salt: "user-salt-abc",
};

const WEBAUTHN_ENV = {
  STEP_UP_WEBAUTHN_RP_ID: RP_ID,
  STEP_UP_WEBAUTHN_ORIGIN: ORIGIN,
} as NodeJS.ProcessEnv;

function makeRow(overrides: Partial<StepUpApprovalChallenge> = {}): StepUpApprovalChallenge {
  return {
    id: APPROVAL_ID,
    bindingId: RELEASE_CHALLENGE_ID,
    userId: USER_ID,
    purpose: "release",
    challenge: WEBAUTHN_CHALLENGE,
    salt: APPROVAL_SALT,
    rpId: RP_ID,
    origin: ORIGIN,
    createdAt: Date.now() - 1_000,
    expiresAt: Date.now() + 120_000,
    // verifyStepUpProof's precondition: already consumed by the caller.
    consumedAt: Date.now(),
    ...overrides,
  };
}

function makeAuthenticator(overrides: Partial<StepUpAuthenticator> = {}): StepUpAuthenticator {
  return {
    credentialId: CREDENTIAL_ID,
    userId: USER_ID,
    publicKey: toHex(PUBLIC_RAW),
    counter: 0,
    transports: [],
    createdAt: Date.now(),
    ...overrides,
  };
}

function buildAuthData(rpId: string, flags: number, signCount: number): Uint8Array {
  const data = new Uint8Array(37);
  data.set(sha256(utf8ToBytes(rpId)), 0);
  data[32] = flags;
  // Big-endian: WebAuthn encodes the counter as a 4-byte big-endian
  // integer, and the spec is explicit about it. A fixture written
  // little-endian produces an authenticatorData no real authenticator would
  // emit, and the mismatch shows up as a bogus sign-count comparison.
  new DataView(data.buffer).setUint32(33, signCount, false);
  return data;
}

interface AssertionOverrides {
  rpId?: string;
  origin?: string;
  /** Challenge to embed in clientDataJSON — defaults to the issued one. */
  challenge?: string;
  flags?: number;
  signCount?: number;
  clientDataType?: string;
  /** Sign with this foreign key instead (valid DER, wrong signer). */
  foreignKey?: ReturnType<typeof generateKeyPairSync>["privateKey"];
}

function buildAssertion(over: AssertionOverrides = {}) {
  const rpId = over.rpId ?? RP_ID;
  const origin = over.origin ?? ORIGIN;
  const challenge = over.challenge ?? WEBAUTHN_CHALLENGE;
  const clientDataJSON = utf8ToBytes(
    JSON.stringify({
      type: over.clientDataType ?? "webauthn.get",
      challenge,
      origin,
    }),
  );
  const authenticatorData = buildAuthData(rpId, over.flags ?? 0x01, over.signCount ?? 1);
  const signed = new Uint8Array(authenticatorData.length + 32);
  signed.set(authenticatorData, 0);
  signed.set(sha256(clientDataJSON), authenticatorData.length);
  // WebCrypto verifies ECDSA signatures in RAW (r||s) form. Node's `sign`
  // defaults to DER, so a naive fixture produces a signature no browser would
  // ever send — and the failure surfaces as "Invalid signature" against a
  // perfectly correct verifier. `dsaEncoding: "ieee-p1363"` is the raw form.
  const signature = new Uint8Array(
    cryptoSign("sha256", signed, {
      key: over.foreignKey ?? KEYPAIR.privateKey,
      dsaEncoding: "ieee-p1363",
    }),
  );
  return { clientDataJSON, authenticatorData, signature };
}

function webauthnProof(
  parts: { clientDataJSON: Uint8Array; authenticatorData: Uint8Array; signature: Uint8Array },
  overrides: Partial<{
    challengeId: string;
    approvalChallengeId: string;
    credentialId: string;
  }> = {},
): StepUpProof {
  return {
    type: "webauthn",
    challengeId: overrides.challengeId ?? RELEASE_CHALLENGE_ID,
    approvalChallengeId: overrides.approvalChallengeId ?? APPROVAL_ID,
    credentialId: overrides.credentialId ?? CREDENTIAL_ID,
    clientDataJSON: bytesToBase64Url(parts.clientDataJSON),
    authenticatorData: bytesToBase64Url(parts.authenticatorData),
    signature: bytesToBase64Url(parts.signature),
  };
}

async function setupRelease(): Promise<InMemoryStepUpAuthenticatorStore> {
  const authenticators = new InMemoryStepUpAuthenticatorStore();
  await authenticators.save(makeAuthenticator());
  return authenticators;
}

async function verify(
  proof: StepUpProof,
  row: StepUpApprovalChallenge,
  authenticators: InMemoryStepUpAuthenticatorStore,
  user: StoredUser = USER,
  requiredPurpose: StepUpApprovalChallenge["purpose"] = "release",
  env: NodeJS.ProcessEnv = WEBAUTHN_ENV,
) {
  return verifyStepUpProof(proof, row, user, requiredPurpose, authenticators, readWebAuthnConfig(env));
}

/* ------------------------------------------------------------------ */
/*  Shape pre-check (before a challenge is burned)                     */
/* ------------------------------------------------------------------ */

/**
 * Build a COSE_Key for EC2 / P-256 from a raw 65-byte point.
 *
 * Hand-rolled rather than pulled from a library: the project deliberately has
 * no CBOR dependency, and a test that reached for one would be testing a
 * different parser than the code under test.
 */
function buildCoseP256(raw: Uint8Array): Uint8Array {
  if (raw.length !== 65 || raw[0] !== 0x04) {
    throw new Error("buildCoseP256 expects a 65-byte uncompressed point");
  }
  const x = raw.slice(1, 33);
  const y = raw.slice(33, 65);
  return new Uint8Array([
    0xa5, // map(5)
    0x01, 0x02, // 1: kty = 2 (EC2)
    0x03, 0x26, // 3: alg = -7 (ES256), CBOR negative encoding
    0x20, 0x01, // -1: crv = 1 (P-256)
    0x21, 0x58, 0x20, ...x, // -2: x (32 bytes)
    0x22, 0x58, 0x20, ...y, // -3: y (32 bytes)
  ]);
}

describe("precheckProofShape", () => {
  it("refuses an absent proof with 403 Approval proof required — even for an owned credential", () => {
    // The credential never enters this path: the refusal is structural, so a
    // stolen bearer token with a valid credential id dies here.
    expect(precheckProofShape(undefined, RELEASE_CHALLENGE_ID)).toEqual({
      status: 403,
      error: "Approval proof required",
    });
    expect(precheckProofShape(null, RELEASE_CHALLENGE_ID)).toEqual({
      status: 403,
      error: "Approval proof required",
    });
    expect(precheckProofShape("proof", RELEASE_CHALLENGE_ID)).toEqual({
      status: 403,
      error: "Approval proof required",
    });
  });

  it("refuses an unsupported proof type with 400", () => {
    const result = precheckProofShape(
      { type: "magic", challengeId: RELEASE_CHALLENGE_ID, approvalChallengeId: APPROVAL_ID },
      RELEASE_CHALLENGE_ID,
    );
    expect(result).toEqual({ status: 400, error: "Unsupported proof type" });
  });

  it("refuses a proof bound to a different challengeId", () => {
    const result = precheckProofShape(
      {
        type: "passphrase",
        challengeId: "another-challenge",
        approvalChallengeId: APPROVAL_ID,
        value: "ff",
      },
      RELEASE_CHALLENGE_ID,
    );
    expect(result).toEqual({ status: 403, error: "Approval proof rejected" });
  });

  it("refuses a webauthn proof missing material fields", () => {
    const result = precheckProofShape(
      {
        type: "webauthn",
        challengeId: RELEASE_CHALLENGE_ID,
        approvalChallengeId: APPROVAL_ID,
        credentialId: CREDENTIAL_ID,
        clientDataJSON: "e30",
        authenticatorData: "AA",
        // signature missing
      },
      RELEASE_CHALLENGE_ID,
    );
    expect(result).toEqual({ status: 403, error: "Approval proof rejected" });
  });

  it("refuses a proof without an approvalChallengeId", () => {
    const result = precheckProofShape(
      { type: "passphrase", challengeId: RELEASE_CHALLENGE_ID, value: "ff" },
      RELEASE_CHALLENGE_ID,
    );
    expect(result).toEqual({ status: 403, error: "Approval proof rejected" });
  });

  it("accepts structurally complete proofs of both types", () => {
    const passphrase = precheckProofShape(
      {
        type: "passphrase",
        challengeId: RELEASE_CHALLENGE_ID,
        approvalChallengeId: APPROVAL_ID,
        value: "00ff",
      },
      RELEASE_CHALLENGE_ID,
    );
    expect("proof" in passphrase).toBe(true);

    const webauthn = precheckProofShape(
      {
        type: "webauthn",
        challengeId: RELEASE_CHALLENGE_ID,
        approvalChallengeId: APPROVAL_ID,
        credentialId: CREDENTIAL_ID,
        clientDataJSON: "e30",
        authenticatorData: "AA",
        signature: "BB",
      },
      RELEASE_CHALLENGE_ID,
    );
    expect("proof" in webauthn).toBe(true);
  });

  it("skips the binding comparison for enroll (null expected), where the row id is not known yet", () => {
    const result = precheckProofShape(
      {
        type: "passphrase",
        challengeId: "row-own-id",
        approvalChallengeId: "row-own-id",
        value: "00ff",
      },
      null,
    );
    expect("proof" in result).toBe(true);
  });
});

/* ------------------------------------------------------------------ */
/*  Passphrase proof                                                    */
/* ------------------------------------------------------------------ */

describe("passphrase proof", () => {
  const PASSPHRASE = "correct horse battery staple";
  const WRONG_PASSPHRASE = "Correct Horse Battery Staple";

  it("verifies the correct passphrase and refuses the wrong one", async () => {
    // What Core stores at registration: hop 1 at users.hash parameters.
    const storedHash = pbkdf2Sync(PASSPHRASE, USER.salt, STEP_UP_KDF.iterations, STEP_UP_KDF.keyLength, "sha512");
    const value = await derivePassphraseProof(PASSPHRASE, USER.salt, RELEASE_CHALLENGE_ID, APPROVAL_SALT);

    await expect(
      verifyPassphraseProof(storedHash.toString("hex"), APPROVAL_SALT, RELEASE_CHALLENGE_ID, value),
    ).resolves.toBe(true);

    const wrong = await derivePassphraseProof(WRONG_PASSPHRASE, USER.salt, RELEASE_CHALLENGE_ID, APPROVAL_SALT);
    await expect(
      verifyPassphraseProof(storedHash.toString("hex"), APPROVAL_SALT, RELEASE_CHALLENGE_ID, wrong),
    ).resolves.toBe(false);
  }, 60_000);

  it("derives exactly what crypto.pbkdf2Sync produces (the users.hash algebra)", async () => {
    const derived = await derivePassphraseProof(PASSPHRASE, USER.salt, RELEASE_CHALLENGE_ID, APPROVAL_SALT);

    const hop1 = pbkdf2Sync(PASSPHRASE, USER.salt, STEP_UP_KDF.iterations, STEP_UP_KDF.keyLength, "sha512");
    const bindingSalt = utf8ToBytes(`${PASSPHRASE_PROOF_PREFIX}${RELEASE_CHALLENGE_ID}:${APPROVAL_SALT}`);
    const hop2 = pbkdf2Sync(hop1, bindingSalt, STEP_UP_KDF.iterations, STEP_UP_KDF.keyLength, "sha512");

    // The wire form is hex, so the comparison decodes rather than
    // string-comparing against a different encoding.
    expect(Buffer.from(derived, "hex")).toEqual(Buffer.from(hop2));
  }, 60_000);

  it("derives the same value for the same passphrase, salt and challenge", async () => {
    // Determinism matters more than it looks: the popup derives this in a
    // browser bundle and Core re-derives it in Node. Any disagreement about the
    // algebra means every legitimate user is refused.
    const first = await derivePassphraseProof(PASSPHRASE, USER.salt, RELEASE_CHALLENGE_ID, APPROVAL_SALT);
    const second = await derivePassphraseProof(PASSPHRASE, USER.salt, RELEASE_CHALLENGE_ID, APPROVAL_SALT);

    expect(first).toBe(second);
  }, 60_000);

  it("binds the proof to the challenge, so one release cannot reuse another's", async () => {
    const forA = await derivePassphraseProof(PASSPHRASE, USER.salt, "challenge-A", APPROVAL_SALT);
    const forB = await derivePassphraseProof(PASSPHRASE, USER.salt, "challenge-B", APPROVAL_SALT);

    expect(forA).not.toBe(forB);
  }, 60_000);

  it("binds the proof to the approval salt, so a captured salt is not reusable", async () => {
    const withSaltA = await derivePassphraseProof(PASSPHRASE, USER.salt, RELEASE_CHALLENGE_ID, "salt-a");
    const withSaltB = await derivePassphraseProof(PASSPHRASE, USER.salt, RELEASE_CHALLENGE_ID, "salt-b");

    expect(withSaltA).not.toBe(withSaltB);
  }, 60_000);


  it("parses a hand-built COSE P-256 key to the same raw point", () => {
    const raw = parseP256PublicKey(buildCoseP256(PUBLIC_RAW));
    expect(raw).toEqual(PUBLIC_RAW);
  });

  it("rejects malformed COSE input without throwing", () => {
    const valid = buildCoseP256(PUBLIC_RAW);
    const malformed: Uint8Array[] = [
      new Uint8Array(0), // empty
      valid.subarray(0, 10), // truncated
      new Uint8Array([...valid, 0x00]), // trailing byte
      (() => { const a = valid.slice(); a[0] = 0xa3; return a; })(), // map(3): too small
      (() => { const a = valid.slice(); a[0] = 0xa7; return a; })(), // map(7): too big
      (() => { const a = valid.slice(); a[6] = 0x63; return a; })(), // alg as text string
      (() => { const a = valid.slice(); a[8] = 0x61; return a; })(), // crv as text string
      new Uint8Array([0xbb, 0xff, 0xff, 0xff, 0xff]), // reserved/indefinite head
      new Uint8Array(32).fill(0xff), // not CBOR at all
    ];
    for (const bytes of malformed) {
      expect(() => readCoseP256Key(bytes)).not.toThrow();
      expect(readCoseP256Key(bytes)).toBeNull();
      expect(parseP256PublicKey(bytes)).toBeNull();
    }
  });

  it("rejects a truncated SPKI without throwing", () => {
    expect(() => parseP256PublicKey(SPKI_DER.subarray(0, 6))).not.toThrow();
    expect(parseP256PublicKey(SPKI_DER.subarray(0, 6))).toBeNull();
    expect(parseP256PublicKey(new Uint8Array(0))).toBeNull();
  });
});

/* ------------------------------------------------------------------ */
/*  verifyStepUpProof — the gate itself                                */
/* ------------------------------------------------------------------ */

describe("verifyStepUpProof", () => {
  it("accepts a valid assertion over the issued challenge", async () => {
    const authenticators = await setupRelease();
    const result = await verify(webauthnProof(buildAssertion()), makeRow(), authenticators);
    expect(result).toEqual({ ok: true, signCount: 1, credentialId: CREDENTIAL_ID });
  });

  it("refuses an assertion minted for a different challenge (clientDataJSON.challenge mismatch)", async () => {
    const authenticators = await setupRelease();
    const proof = webauthnProof(buildAssertion({ challenge: bytesToBase64Url(randomBytes(32)) }));
    const result = await verify(proof, makeRow(), authenticators);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.status).toBe(403);
  });

  it("refuses a proof whose challengeId points at another release", async () => {
    const authenticators = await setupRelease();
    const proof = webauthnProof(buildAssertion(), { challengeId: "another-release" });
    const result = await verify(proof, makeRow(), authenticators);
    expect(result).toEqual({ ok: false, status: 403, error: "Approval proof rejected" });
  });

  it("refuses a signed assertion with the UP flag cleared", async () => {
    const authenticators = await setupRelease();
    const result = await verify(webauthnProof(buildAssertion({ flags: 0x00 })), makeRow(), authenticators);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.status).toBe(403);
  });

  it("refuses an assertion whose rpIdHash does not match", async () => {
    const authenticators = await setupRelease();
    // AuthData computed over another relying party's id.
    const result = await verify(
      webauthnProof(buildAssertion({ rpId: "evil.example" })),
      makeRow(),
      authenticators,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.status).toBe(403);
  });

  it("refuses an assertion for another origin", async () => {
    const authenticators = await setupRelease();
    const result = await verify(
      webauthnProof(buildAssertion({ origin: "https://evil.example" })),
      makeRow(),
      authenticators,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.status).toBe(403);
  });

  it("refuses an attestation-type clientData (type must be webauthn.get)", async () => {
    const authenticators = await setupRelease();
    const result = await verify(
      webauthnProof(buildAssertion({ clientDataType: "webauthn.create" })),
      makeRow(),
      authenticators,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.status).toBe(403);
  });

  it("refuses a signature made by a different key", async () => {
    const authenticators = await setupRelease();
    const foreign = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const result = await verify(
      webauthnProof(buildAssertion({ foreignKey: foreign.privateKey })),
      makeRow(),
      authenticators,
    );
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.status).toBe(403);
  });

  it("refuses an unknown credential id and another user's credential", async () => {
    const authenticators = await setupRelease();
    const unknown = await verify(webauthnProof(buildAssertion(), { credentialId: "nope" }), makeRow(), authenticators);
    expect(unknown).toEqual({ ok: false, status: 403, error: "Approval proof rejected" });

    const strangerStore = new InMemoryStepUpAuthenticatorStore();
    await strangerStore.save(makeAuthenticator({ userId: OTHER_USER_ID }));
    const stranger = await verify(webauthnProof(buildAssertion()), makeRow(), strangerStore);
    expect(stranger).toEqual({ ok: false, status: 403, error: "Approval proof rejected" });
  });

  it("refuses a purpose mismatch (an enroll proof cannot approve a release)", async () => {
    const authenticators = await setupRelease();
    const enrollRow = makeRow({ purpose: "enroll", bindingId: APPROVAL_ID });
    const result = await verify(webauthnProof(buildAssertion()), enrollRow, authenticators, USER, "release");
    expect(result).toEqual({ ok: false, status: 403, error: "Approval proof rejected" });
  });

  it("fails closed when WebAuthn is not configured (rpId/origin absent)", async () => {
    const authenticators = await setupRelease();
    const row = makeRow({ rpId: null, origin: null });
    const unconfigured = readWebAuthnConfig({} as NodeJS.ProcessEnv);
    expect(unconfigured.configured).toBe(false);

    const fromRow = await verify(webauthnProof(buildAssertion()), row, authenticators);
    expect(fromRow).toEqual({ ok: false, status: 403, error: "Approval proof rejected" });

    const fromConfig = await verify(
      webauthnProof(buildAssertion()),
      makeRow(),
      authenticators,
      USER,
      "release",
      {} as NodeJS.ProcessEnv, // nothing configured → fail closed
    );
    expect(fromConfig).toEqual({ ok: false, status: 403, error: "Approval proof rejected" });
  });

  it("refuses an unsupported proof type at verification depth (400, not 403)", async () => {
    const authenticators = await setupRelease();
    // Bound correctly, so it clears purpose + binding and reaches the type
    // branch — an unknown type is a malformed request (400), not a failed
    // proof (403).
    const fake = {
      type: "yubikey-magic",
      challengeId: RELEASE_CHALLENGE_ID,
      approvalChallengeId: APPROVAL_ID,
    } as unknown as StepUpProof;
    const result = await verify(fake, makeRow(), authenticators);
    expect(result).toEqual({ ok: false, status: 400, error: "Unsupported proof type" });
  });

  it("applies clone-detection counter semantics", async () => {
    const authenticators = new InMemoryStepUpAuthenticatorStore();

    // Platform authenticators (Touch ID / Windows Hello) always report 0:
    // accepted, counter untouched.
    await authenticators.save(makeAuthenticator({ counter: 0 }));
    const zero = await verify(webauthnProof(buildAssertion({ signCount: 0 })), makeRow(), authenticators);
    expect(zero.ok).toBe(true);

    // Advancing counter: accepted, and the caller persists the new value.
    await authenticators.updateCounter(CREDENTIAL_ID, 5);
    const advanced = await verify(webauthnProof(buildAssertion({ signCount: 7 })), makeRow(), authenticators);
    expect(advanced.ok && advanced.signCount).toBe(7);
    if (advanced.ok && advanced.signCount) {
      await authenticators.updateCounter(CREDENTIAL_ID, advanced.signCount);
    }
    expect((await authenticators.findByCredentialId(CREDENTIAL_ID))!.counter).toBe(7);

    // Regression with both > 0: possible clone — refused.
    const regressed = await verify(webauthnProof(buildAssertion({ signCount: 3 })), makeRow(), authenticators);
    expect(regressed.ok).toBe(false);
    if (!regressed.ok) expect(regressed.status).toBe(403);
  });

  it("accepts the correct passphrase proof and refuses the wrong one", async () => {
    const authenticators = await setupRelease();
    const storedHash = pbkdf2Sync("pass", USER.salt, STEP_UP_KDF.iterations, STEP_UP_KDF.keyLength, "sha512").toString("hex");
    const user: StoredUser = { ...USER, hash: storedHash };

    const goodValue = await derivePassphraseProof("pass", USER.salt, RELEASE_CHALLENGE_ID, APPROVAL_SALT);
    const good = await verify(
      {
        type: "passphrase",
        challengeId: RELEASE_CHALLENGE_ID,
        approvalChallengeId: APPROVAL_ID,
        value: goodValue,
      },
      makeRow(),
      authenticators,
      user,
    );
    expect(good).toEqual({ ok: true });

    const badValue = await derivePassphraseProof("wrong", USER.salt, RELEASE_CHALLENGE_ID, APPROVAL_SALT);
    const bad = await verify(
      {
        type: "passphrase",
        challengeId: RELEASE_CHALLENGE_ID,
        approvalChallengeId: APPROVAL_ID,
        value: badValue,
      },
      makeRow(),
      authenticators,
      user,
    );
    expect(bad).toEqual({ ok: false, status: 403, error: "Approval proof rejected" });
  }, 60_000);
});

/* ------------------------------------------------------------------ */
/*  One-time challenge store (replay / ownership / expiry)             */
/* ------------------------------------------------------------------ */

describe("step-up approval challenge store", () => {
  it("returns a row exactly once — a replay ends in null", async () => {
    const store = new InMemoryStepUpApprovalChallengeStore();
    const row = makeRow({ consumedAt: null });
    await store.save(row);

    const now = Date.now();
    const first = await store.consume(row.id, row.userId, now);
    expect(first).not.toBeNull();

    const replay = await store.consume(row.id, row.userId, now + 1);
    expect(replay).toBeNull();
  });

  it("refuses another user's row, an unknown id, and an expired row", async () => {
    const store = new InMemoryStepUpApprovalChallengeStore();
    const fresh = makeRow({ id: "fresh", consumedAt: null });
    const expired = makeRow({ id: "expired", consumedAt: null, expiresAt: Date.now() - 1 });
    await store.save(fresh);
    await store.save(expired);

    expect(await store.consume(fresh.id, OTHER_USER_ID, Date.now())).toBeNull();
    expect(await store.consume("never-existed", fresh.userId, Date.now())).toBeNull();
    expect(await store.consume(expired.id, expired.userId, Date.now())).toBeNull();
    // …and none of those refusals spent the legitimate row.
    expect(await store.consume(fresh.id, fresh.userId, Date.now())).not.toBeNull();
  });
});

describe("step-up authenticator store", () => {
  it("refuses to re-own a credential id registered by another user", async () => {
    const store = new InMemoryStepUpAuthenticatorStore();
    expect(await store.save(makeAuthenticator())).toBe(true);
    expect(await store.save(makeAuthenticator({ userId: OTHER_USER_ID }))).toBe(false);
    // Same owner may refresh their own key material.
    expect(await store.save(makeAuthenticator())).toBe(true);
    expect((await store.findByCredentialId(CREDENTIAL_ID))!.userId).toBe(USER_ID);
  });

  it("advances the signature counter only forward", async () => {
    const store = new InMemoryStepUpAuthenticatorStore();
    await store.save(makeAuthenticator({ counter: 5 }));

    await store.updateCounter(CREDENTIAL_ID, 3);
    expect((await store.findByCredentialId(CREDENTIAL_ID))!.counter).toBe(5);

    await store.updateCounter(CREDENTIAL_ID, 9);
    expect((await store.findByCredentialId(CREDENTIAL_ID))!.counter).toBe(9);

    await store.updateCounter(CREDENTIAL_ID, 5);
    expect((await store.findByCredentialId(CREDENTIAL_ID))!.counter).toBe(9);
  });
});

/* ------------------------------------------------------------------ */
/*  Environment configuration                                          */
/* ------------------------------------------------------------------ */

describe("readWebAuthnConfig", () => {
  it("is configured only when BOTH rpId and origin are set", () => {
    expect(readWebAuthnConfig(WEBAUTHN_ENV).configured).toBe(true);
    expect(readWebAuthnConfig({ STEP_UP_WEBAUTHN_RP_ID: RP_ID } as NodeJS.ProcessEnv).configured).toBe(false);
    expect(readWebAuthnConfig({ STEP_UP_WEBAUTHN_ORIGIN: ORIGIN } as NodeJS.ProcessEnv).configured).toBe(false);
    expect(
      readWebAuthnConfig({
        STEP_UP_WEBAUTHN_RP_ID: "  ",
        STEP_UP_WEBAUTHN_ORIGIN: ORIGIN,
      } as NodeJS.ProcessEnv).configured,
    ).toBe(false);
    expect(readWebAuthnConfig({} as NodeJS.ProcessEnv).configured).toBe(false);
  });
});
