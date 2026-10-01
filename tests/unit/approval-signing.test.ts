/**
 * Signed user approval (R3).
 *
 * These cases are the ones that matter for a cross-service artifact, and each
 * exists because a specific wrong behaviour would otherwise be silent:
 *
 *   - an approval must not verify as a capability, and vice versa
 *   - every binding field must be checked, and a missing context is a failure
 *   - a tampered field must break the signature
 *   - a token with an over-long TTL must be refused at verification, not just
 *     at signing, because the signer cannot be trusted
 *   - `__proto__` must not pass operation validation (the bug that
 *     `plus/domain/operations.ts` had for capabilities)
 */
import {
  APPROVAL_VERSION,
  DEFAULT_APPROVAL_TTL_SECONDS,
  MAX_APPROVAL_TTL_SECONDS,
  decodeApprovalPayload,
  encodeApprovalPayload,
  generateApprovalKeyPair,
  isValidApprovalOperation,
  loadApprovalPrivateKey,
  loadApprovalPublicKey,
  signApproval,
  verifyApproval,
  type ApprovalPayload,
  type SignedApproval,
} from "../../src/infrastructure/crypto/ed25519-approval";

const NOW = 1_700_000_000;

function makePayload(overrides: Partial<ApprovalPayload> = {}): ApprovalPayload {
  const iat = NOW;
  return {
    version: APPROVAL_VERSION,
    typ: "step-up-approval",
    challengeId: "ch-1",
    userId: "user-1",
    resourceId: "res-1",
    operation: "AUTOFILL",
    secretRef: "ref-1",
    iat,
    exp: iat + DEFAULT_APPROVAL_TTL_SECONDS,
    jti: "jti-1",
    ...overrides,
  };
}

const EXPECTED = {
  challengeId: "ch-1",
  userId: "user-1",
  resourceId: "res-1",
  operation: "AUTOFILL" as const,
  secretRef: "ref-1",
};

describe("approval signing round trip", () => {
  const keys = generateApprovalKeyPair();
  const priv = loadApprovalPrivateKey(keys.privateKeyBase64);
  const pub = loadApprovalPublicKey(keys.publicKeyBase64);

  it("verifies an approval it just signed", async () => {
    const signed = await signApproval(makePayload(), priv);

    const result = await verifyApproval(signed, pub, EXPECTED, NOW + 1);
    expect(result).toEqual({ valid: true });
  });

  it("rejects a tampered secretRef", async () => {
    const signed = await signApproval(makePayload(), priv);
    // The signature covers the encoded payload, so changing any field after
    // signing must break it.
    signed.payload.secretRef = "ref-attacker";

    const result = await verifyApproval(signed, pub, { ...EXPECTED, secretRef: "ref-attacker" }, NOW + 1);
    expect(result.valid).toBe(false);
    expect(result.error).toBe("Invalid signature");
  });

  it("rejects an approval signed by a different key", async () => {
    const attacker = generateApprovalKeyPair();
    const signed = await signApproval(makePayload(), loadApprovalPrivateKey(attacker.privateKeyBase64));

    const result = await verifyApproval(signed, pub, EXPECTED, NOW + 1);
    expect(result.valid).toBe(false);
    expect(result.error).toBe("Invalid signature");
  });

  it("rejects an expired approval", async () => {
    const signed = await signApproval(makePayload(), priv);

    const result = await verifyApproval(signed, pub, EXPECTED, NOW + DEFAULT_APPROVAL_TTL_SECONDS + 1);
    expect(result.valid).toBe(false);
    expect(result.error).toBe("Approval expired");
  });

  it("refuses an over-long TTL even though the signature is genuine", async () => {
    // The signature is perfectly valid. The point is that verification clamps,
    // because it cannot assume the signer enforced the ceiling.
    const iat = NOW;
    const signed = await signApproval(
      makePayload({ iat, exp: iat + MAX_APPROVAL_TTL_SECONDS + 3600 }),
      priv,
    );

    const result = await verifyApproval(signed, pub, EXPECTED, iat + 1);
    expect(result.valid).toBe(false);
    expect(result.error).toBe("Approval TTL exceeds the maximum");
  });
});

describe("approval bindings", () => {
  const keys = generateApprovalKeyPair();
  const priv = loadApprovalPrivateKey(keys.privateKeyBase64);
  const pub = loadApprovalPublicKey(keys.publicKeyBase64);

  it.each([
    ["challengeId", "ch-other"],
    ["userId", "user-other"],
    ["resourceId", "res-other"],
    ["operation", "TOTP" as const],
    ["secretRef", "ref-other"],
  ])("refuses a mismatch on %s", async (field, wrong) => {
    const signed = await signApproval(makePayload(), priv);

    const result = await verifyApproval(signed, pub, { ...EXPECTED, [field]: wrong }, NOW + 1);
    expect(result.valid).toBe(false);
    expect(result.error).toContain("Binding mismatch");
    expect(result.error).toContain(field);
  });

  it("refuses when the context is incomplete rather than skipping the check", async () => {
    const signed = await signApproval(makePayload(), priv);

    // An empty context must not be read as "no expectations".
    const result = await verifyApproval(signed, pub, { ...EXPECTED, userId: "" }, NOW + 1);
    expect(result.valid).toBe(false);
    expect(result.error).toContain("userId");
  });

  it("an approval for one credential does not release another", async () => {
    // The specific claim that makes signing worth doing.
    const signed = await signApproval(makePayload(), priv);

    const forOtherSecret = await verifyApproval(
      signed,
      pub,
      { ...EXPECTED, secretRef: "ref-victim" },
      NOW + 1,
    );
    expect(forOtherSecret.valid).toBe(false);
  });
});

describe("approval is not a capability", () => {
  const keys = generateApprovalKeyPair();
  const priv = loadApprovalPrivateKey(keys.privateKeyBase64);
  const pub = loadApprovalPublicKey(keys.publicKeyBase64);

  it("refuses a protected header that claims a capability", async () => {
    const signed = await signApproval(makePayload(), priv);
    const capability = require("../../src/infrastructure/crypto/ed25519-capability");
    const forged: SignedApproval = {
      ...signed,
      protectedHeader: capability
        .signCapability === undefined
        ? signed.protectedHeader
        : Buffer.from(JSON.stringify({ alg: "Ed25519", typ: "capability" })).toString("base64"),
    };

    const result = await verifyApproval(forged, pub, EXPECTED, NOW + 1);
    expect(result.valid).toBe(false);
    expect(result.error).toBe("Wrong protected header");
  });

  it("refuses a payload that is not marked as an approval", async () => {
    const signed = await signApproval(makePayload({ typ: "capability" as never }), priv);

    const result = await verifyApproval(signed, pub, EXPECTED, NOW + 1);
    expect(result.valid).toBe(false);
  });
});

describe("operation validation", () => {
  it("accepts the three listed operations", () => {
    for (const op of ["AUTOFILL", "TOTP", "EXPORT_SECRET"]) {
      expect(isValidApprovalOperation(op)).toBe(true);
    }
  });

  it("rejects inherited object keys", () => {
    // `"__proto__" in OPERATIONS` is true, so a naive `in` check would pass a
    // prototype key straight through to the switch that consumes it.
    for (const bogus of ["__proto__", "constructor", "toString", "hasOwnProperty"]) {
      expect(isValidApprovalOperation(bogus)).toBe(false);
    }
  });

  it("rejects non-strings", () => {
    for (const bogus of [undefined, null, 1, {}, []]) {
      expect(isValidApprovalOperation(bogus)).toBe(false);
    }
  });
});

describe("payload decoding", () => {
  it("round-trips through encode and decode", () => {
    const payload = makePayload();
    expect(decodeApprovalPayload(encodeApprovalPayload(payload))).toEqual(payload);
  });

  it("returns null rather than throwing on garbage", () => {
    expect(decodeApprovalPayload(new TextEncoder().encode("not json"))).toBeNull();
    expect(decodeApprovalPayload(new TextEncoder().encode("[]"))).toBeNull();
    expect(decodeApprovalPayload(new TextEncoder().encode("null"))).toBeNull();
  });

  it("rejects a payload missing a required field", () => {
    const partial = { ...makePayload() } as Record<string, unknown>;
    delete partial.secretRef;

    expect(decodeApprovalPayload(new TextEncoder().encode(JSON.stringify(partial)))).toBeNull();
  });
});
