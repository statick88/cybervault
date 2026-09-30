/**
 * Signed user approval for a step-up release (R3).
 *
 * ## Why this exists
 *
 * The step-up used to require a 6-digit PIN that `createChallenge` generated
 * and then discarded: never emailed, never returned, never persisted. The
 * third factor was therefore not weak, it was **unobtainable** — and R4's
 * per-user lockout was guarding a secret nobody held.
 *
 * This replaces the PIN with the decision itself. The user, already
 * authenticated to Core, approves a specific release. Core signs that
 * approval. Plus verifies the signature and issues the capability.
 *
 * ## What the signature does and does not buy
 *
 * It proves **Core** authorised this exact release, to this user, for this
 * resource, operation and secret, once, for a short window. It is
 * tamper-evident and single-use, so it cannot be replayed against another
 * credential or after the challenge expires.
 *
 * It does **not** by itself prove a human clicked. A compromised background
 * worker holding a live session token can call Core's approve endpoint and
 * receive a validly signed approval. Closing that requires the user to
 * re-prove something at approve time, which is deliberately out of scope here
 * and is recorded in the threat model rather than implied away.
 *
 * ## Why JSON and not the capability binary encoding
 *
 * `encodeCapabilityPayload` produces a length-prefixed binary form that exists
 * to be compact and fast. This artifact crosses a service boundary and is
 * verified against a pinned key by a different service, where a wrong or
 * ambiguous encoding is a security bug rather than a performance one.
 * JSON is longer and impossible to misparse ambiguously: every field is
 * named, and an absent field cannot be confused with an empty one the way
 * length-0 can.
 *
 * The separation is deliberate. A capability and an approval are different
 * things signed by different keys for different reasons, and they must never
 * be interchangeable — a token that satisfies `verifyCapability` must not
 * satisfy `verifyApproval`, or the two would collapse into one.
 */

import { ed25519 } from "@noble/curves/ed25519.js";
import { binaryToBase64, base64ToBinary } from "../../shared/utils";

/** Env var pinning Core's approval-signing public key, verified by Plus. */
export const CORE_APPROVAL_PUBLIC_KEY_ENV = "CORE_APPROVAL_PUBLIC_KEY";

/** Env var holding Core's approval-signing private key seed. */
export const CORE_APPROVAL_PRIVATE_KEY_ENV = "CORE_APPROVAL_PRIVATE_KEY";

export const APPROVAL_VERSION = 1;

/**
 * How long an approval stays usable, in seconds.
 *
 * Short on purpose: the approval covers one challenge completion, and the user
 * is looking at the popup while doing it. Five minutes is generous for that and
 * short enough that a captured token is not a standing credential.
 */
export const DEFAULT_APPROVAL_TTL_SECONDS = 300;

export const MAX_APPROVAL_TTL_SECONDS = 600;

/** The operations an approval may authorise. Mirrors `CapabilityOperation`. */
export const APPROVAL_OPERATIONS = ["AUTOFILL", "TOTP", "EXPORT_SECRET"] as const;

export type ApprovalOperation = (typeof APPROVAL_OPERATIONS)[number];

/** The context an approval is verified against, built by Plus from the challenge. */
export interface ApprovalBindingContext {
  readonly challengeId: string;
  readonly userId: string;
  readonly resourceId: string;
  readonly operation: ApprovalOperation;
  readonly secretRef: string;
}

export interface ApprovalPayload {
  /** Distinguishes this artifact from a capability. Always `1` for now. */
  version: number;
  /** Constant discriminator. A capability does not carry this field. */
  typ: "step-up-approval";
  /** The challenge this approval answers. */
  challengeId: string;
  userId: string;
  resourceId: string;
  operation: ApprovalOperation;
  secretRef: string;
  /** Seconds since epoch. */
  iat: number;
  /** Seconds since epoch. */
  exp: number;
  /** Single-use nonce, consumed atomically by Plus. */
  jti: string;
}

export interface SignedApproval {
  payload: ApprovalPayload;
  signature: string;
  protectedHeader: string;
}

export interface Ed25519ApprovalKeyPair {
  publicKeyBase64: string;
  privateKeyBase64: string;
}

/**
 * True when `value` is a listed operation.
 *
 * `includes` alone is the correct and sufficient check here, and it is
 * prototype-safe: `"__proto__"` is not an element of the array, so it returns
 * false regardless of what the prototype carries.
 *
 * The guard I first wrote combined this with
 * `hasOwnProperty.call(APPROVAL_OPERATIONS, value)` — which is always false
 * for a real operation, because `hasOwnProperty` on an array looks up numeric
 * indices, not element values. It rejected every valid operation while still
 * rejecting `__proto__`, so a test that only checked the happy path would have
 * shipped it. The unit test now asserts the valid operations too, which is what
 * caught it.
 *
 * `plus/domain/operations.ts` has the mirror-image bug for capabilities, where
 * `"__proto__" in CAPABILITY_OPERATIONS` is true.
 */
export function isValidApprovalOperation(value: unknown): value is ApprovalOperation {
  return typeof value === "string" && (APPROVAL_OPERATIONS as readonly string[]).includes(value);
}

/**
 * Canonical JSON.
 *
 * Keys are emitted in a fixed literal order rather than sorted, so the bytes
 * signed are exactly the bytes documented here. `JSON.stringify` with a
 * fixed-shape object literal is sufficient and cannot be made to differ
 * between the signer and the verifier as long as both use this function.
 */
export function encodeApprovalPayload(payload: ApprovalPayload): Uint8Array {
  return new TextEncoder().encode(
    JSON.stringify({
      version: payload.version,
      typ: payload.typ,
      challengeId: payload.challengeId,
      userId: payload.userId,
      resourceId: payload.resourceId,
      operation: payload.operation,
      secretRef: payload.secretRef,
      iat: payload.iat,
      exp: payload.exp,
      jti: payload.jti,
    }),
  );
}

/** Parse and shape-check. Returns `null` rather than throwing on bad input. */
export function decodeApprovalPayload(data: Uint8Array): ApprovalPayload | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(new TextDecoder().decode(data));
  } catch {
    return null;
  }

  if (typeof parsed !== "object" || parsed === null) return null;
  const o = parsed as Record<string, unknown>;

  const str = (key: string): string | null => (typeof o[key] === "string" ? (o[key] as string) : null);
  const num = (key: string): number | null => (typeof o[key] === "number" ? (o[key] as number) : null);

  const challengeId = str("challengeId");
  const userId = str("userId");
  const resourceId = str("resourceId");
  const secretRef = str("secretRef");
  const jti = str("jti");
  const iat = num("iat");
  const exp = num("exp");
  const version = num("version");
  const operation = o["operation"];

  if (
    o["typ"] !== "step-up-approval" ||
    version !== APPROVAL_VERSION ||
    !challengeId ||
    !userId ||
    !resourceId ||
    !secretRef ||
    !jti ||
    iat === null ||
    exp === null ||
    !isValidApprovalOperation(operation)
  ) {
    return null;
  }

  return {
    version: APPROVAL_VERSION,
    typ: "step-up-approval",
    challengeId,
    userId,
    resourceId,
    operation,
    secretRef,
    iat,
    exp,
    jti,
  };
}

export function generateApprovalKeyPair(): Ed25519ApprovalKeyPair {
  // Same construction as `generateEd25519KeyPair`: a 32-byte seed expanded into
  // the 64-byte (seed || public) form, so the two key types stay familiar to
  // whoever operates this and `signApproval`'s `slice(0, 32)` is correct.
  const seed = ed25519.utils.randomSecretKey();
  const publicKey = ed25519.getPublicKey(seed);
  const privateKey = new Uint8Array(64);
  privateKey.set(seed, 0);
  privateKey.set(publicKey, 32);

  return {
    publicKeyBase64: binaryToBase64(publicKey),
    privateKeyBase64: binaryToBase64(privateKey),
  };
}

export function loadApprovalPublicKey(base64: string): Uint8Array {
  return base64ToBinary(base64);
}

export function loadApprovalPrivateKey(seedOrSecretBase64: string): Uint8Array {
  return base64ToBinary(seedOrSecretBase64);
}

export async function signApproval(
  payload: ApprovalPayload,
  privateKey: Uint8Array,
): Promise<SignedApproval> {
  const seed = privateKey.slice(0, 32);
  const signature = ed25519.sign(encodeApprovalPayload(payload), seed);
  const protectedHeader = binaryToBase64(
    new TextEncoder().encode(JSON.stringify({ alg: "Ed25519", typ: "step-up-approval" })),
  );

  return { payload, signature: binaryToBase64(signature), protectedHeader };
}

/**
 * Verify a signed approval.
 *
 * Checks the header, the signature, the version, `typ`, expiry, the operation,
 * and — when `expected` is supplied — every field of the binding. An
 * incomplete context is itself a failure: a binding is never skipped because
 * the caller forgot to pass it.
 *
 * Replay is NOT handled here. This proves the signature and the bindings; it
 * cannot know whether the approval was already spent. Plus consumes `jti`
 * atomically before issuing, exactly as it does for capabilities.
 */
export async function verifyApproval(
  signed: SignedApproval,
  publicKey: Uint8Array,
  expected?: ApprovalBindingContext,
  nowSeconds: number = Math.floor(Date.now() / 1000),
): Promise<{ valid: boolean; error?: string }> {
  try {
    // The header is not cosmetic: an approval presented as a capability (or
    // vice versa) must fail here rather than reaching the payload checks.
    const header = JSON.parse(new TextDecoder().decode(base64ToBinary(signed.protectedHeader)));
    if (header?.typ !== "step-up-approval" || header?.alg !== "Ed25519") {
      return { valid: false, error: "Wrong protected header" };
    }
  } catch {
    return { valid: false, error: "Malformed protected header" };
  }

  const decoded = decodeApprovalPayload(encodeApprovalPayload(signed.payload));
  if (!decoded) {
    return { valid: false, error: "Malformed approval payload" };
  }

  // Re-encode from the decoded value, so a caller cannot smuggle extra fields
  // past the shape check by attaching them to the object it hands us.
  const encoded = encodeApprovalPayload(decoded);
  const signature = base64ToBinary(signed.signature);
  if (!ed25519.verify(signature, encoded, publicKey)) {
    return { valid: false, error: "Invalid signature" };
  }

  if (decoded.exp <= nowSeconds) {
    return { valid: false, error: "Approval expired" };
  }

  // Clamp, never trust: an approval claiming a day-long window is a bug or an
  // attack, and the ceiling is enforced on verification because the signer
  // cannot be trusted to have enforced it.
  if (decoded.exp - decoded.iat > MAX_APPROVAL_TTL_SECONDS) {
    return { valid: false, error: "Approval TTL exceeds the maximum" };
  }

  if (!expected) {
    return { valid: true };
  }

  const mismatches: string[] = [];
  const compare = (field: keyof ApprovalBindingContext, actual: string): void => {
    if (typeof expected[field] !== "string" || expected[field] === "") {
      mismatches.push(`${field}: missing context`);
    } else if (expected[field] !== actual) {
      mismatches.push(field);
    }
  };

  compare("challengeId", decoded.challengeId);
  compare("userId", decoded.userId);
  compare("resourceId", decoded.resourceId);
  compare("operation", decoded.operation);
  compare("secretRef", decoded.secretRef);

  if (mismatches.length > 0) {
    return { valid: false, error: `Binding mismatch: ${mismatches.join(", ")}` };
  }

  return { valid: true };
}
