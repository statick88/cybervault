/**
 * Ed25519 Capability Crypto — Cryptographic Capability Tokens for CyberVault
 *
 * Implements Ed25519 signing/verification for capability tokens using @noble/curves.
 * Capability tokens are signed by Plus (private key) and verified by Core (public key).
 *
 * Capability token structure (CBOR-like binary format):
 * {
 *   issuer: string,           // "cybervault-plus"
 *   audience: string,         // "cybervault-core"
 *   userId: string,           // User identifier
 *   resourceId: string,       // Resource identifier (e.g., "db-prod-001")
 *   operation: string,        // Operation (AUTOFILL, VIEW, TOTP, CONNECT, etc.)
 *   secretRef: string,        // Opaque secret reference
 *   deviceId?: string,        // Device identifier (optional)
 *   assurance: number,        // Assurance level (1, 2, 3)
 *   iat: number,              // Issued at (Unix timestamp)
 *   exp: number,              // Expiry (Unix timestamp)
 *   jti: string,              // JWT ID - unique one-time identifier
 * }
 */

import { ed25519 } from "@noble/curves/ed25519.js";
import { binaryToBase64, base64ToBinary } from "../../shared/utils";

/** Assurance level asserted by a capability token. */
type AssuranceLevel = 1 | 2 | 3;

/** Capability token version */
export const CAPABILITY_VERSION = 1;

/** Default capability TTL in seconds (5 minutes) */
export const DEFAULT_CAPABILITY_TTL_SECONDS = 300;

/** Maximum capability TTL in seconds (1 hour) */
export const MAX_CAPABILITY_TTL_SECONDS = 3600;

/** Supported operations */
export const CAPABILITY_OPERATIONS = [
  "AUTOFILL",
  "VIEW",
  "TOTP",
  "CONNECT",
  "READ",
  "ADMIN",
  "BACKUP",
  "RESTORE",
  "ROTATE_SECRET",
  "EDIT_SECRET",
  "DELETE_SECRET",
  "EXPORT_SECRET",
] as const;

export type CapabilityOperation = (typeof CAPABILITY_OPERATIONS)[number];

/** Capability token payload */
export interface CapabilityPayload {
  issuer: string;
  audience: string;
  userId: string;
  resourceId: string;
  operation: CapabilityOperation;
  secretRef: string;
  deviceId?: string;
  assurance: AssuranceLevel;
  iat: number;
  exp: number;
  jti: string;
  version: number;
}

/** Signed capability token */
export interface SignedCapability {
  payload: CapabilityPayload;
  signature: string; // base64 Ed25519 signature
  protectedHeader: string; // base64 encoded header
}

/**
 * The context a verifier is expected to check the capability against.
 *
 * Every field is REQUIRED — there is no optional binding. A field the caller
 * does not know must be resolved to a concrete value by the caller (for
 * example an empty `deviceId` means "this deployment binds no device"), never
 * omitted, because an omitted field would silently disable its check.
 *
 * `expected` is built by the SERVER from the session, the URL and its own
 * store — never from the capability being verified, and never from the
 * request body's key material.
 */
export interface CapabilityBindingContext {
  /** Authenticated user the capability must be issued to. */
  readonly userId: string;
  /** Resource the capability must authorize (here: the secret being released). */
  readonly resourceId: string;
  /** Secret reference the capability must authorize. */
  readonly secretRef: string;
  /** Device the capability must be bound to; "" means "no device bound". */
  readonly deviceId: string;
}

/** Environment variable that pins the Ed25519 capability verification key. */
export const PLUS_PUBLIC_KEY_ENV = "PLUS_PUBLIC_KEY";

/** Base64 length of a pinned Ed25519 public key, in bytes. */
export const PLUS_PUBLIC_KEY_BYTES = 32;

/** Ed25519 key pair */
export interface Ed25519KeyPair {
  publicKey: Uint8Array; // 32 bytes
  privateKey: Uint8Array; // 64 bytes (seed + public)
  publicKeyBase64: string;
  privateKeyBase64: string;
}

/**
 * Generate Ed25519 key pair for capability signing
 * Private key is 64 bytes (32-byte seed + 32-byte public key)
 * Public key is 32 bytes
 */
export function generateEd25519KeyPair(): Ed25519KeyPair {
  const seed = ed25519.utils.randomSecretKey();
  const publicKey = ed25519.getPublicKey(seed);
  const privateKey = new Uint8Array(64);
  privateKey.set(seed, 0);
  privateKey.set(publicKey, 32);

  return {
    publicKey,
    privateKey,
    publicKeyBase64: binaryToBase64(publicKey),
    privateKeyBase64: binaryToBase64(privateKey),
  };
}

/**
 * Load Ed25519 private key from base64 (64 bytes: seed + public)
 */
export function loadEd25519PrivateKey(privateKeyBase64: string): Uint8Array {
  const key = base64ToBinary(privateKeyBase64);
  if (key.length !== 64) {
    throw new Error("Invalid Ed25519 private key length: expected 64 bytes");
  }
  return key;
}

/**
 * Load Ed25519 public key from base64 (32 bytes)
 */
export function loadEd25519PublicKey(publicKeyBase64: string): Uint8Array {
  const key = base64ToBinary(publicKeyBase64);
  if (key.length !== 32) {
    throw new Error("Invalid Ed25519 public key length: expected 32 bytes");
  }
  return key;
}

/**
 * Load the PINNED Plus verification key from its textual (base64)
 * configuration form (`PLUS_PUBLIC_KEY`).
 *
 * Follows the `loadReleaseShareKekSecret` convention: typed, no default,
 * returns null — rather than throwing — when the value is absent, empty or
 * malformed (not base64, or not exactly 32 bytes). Callers MUST treat null as
 * "managed release is unavailable" and refuse: there is deliberately no
 * fallback to a request-supplied key, a default key or the VEK.
 */
export function loadPlusPublicKey(raw: string | undefined | null): Uint8Array | null {
  if (!raw || raw.trim() === "") return null;
  try {
    const bytes = base64ToBinary(raw.trim());
    if (bytes.byteLength !== PLUS_PUBLIC_KEY_BYTES) return null;
    return bytes;
  } catch {
    return null;
  }
}

/**
 * Encode capability payload to canonical binary format for signing
 * Uses a simple deterministic binary encoding (not full CBOR to avoid dependency)
 * Format: version(1) | issuer_len(1) | issuer | audience_len(1) | audience | userId_len(2) | userId
 *         | resourceId_len(2) | resourceId | operation_len(1) | operation | secretRef_len(2) | secretRef
 *         | deviceId_present(1) | deviceId_len(2) | deviceId? | assurance(1) | iat(8) | exp(8) | jti_len(1) | jti
 * All lengths are big-endian. Strings are UTF-8.
 */
export function encodeCapabilityPayload(payload: CapabilityPayload): Uint8Array {
  const parts: Uint8Array[] = [];

  // Version (1 byte)
  parts.push(new Uint8Array([payload.version]));

  // Helper to push length-prefixed string
  const pushString = (str: string, lengthBytes: 1 | 2 = 1) => {
    const encoded = new TextEncoder().encode(str);
    if (lengthBytes === 1) {
      if (encoded.length > 255) throw new Error("String too long for 1-byte length");
      parts.push(new Uint8Array([encoded.length]));
    } else {
      if (encoded.length > 65535) throw new Error("String too long for 2-byte length");
      const lenBuf = new Uint8Array(2);
      new DataView(lenBuf.buffer).setUint16(0, encoded.length, false);
      parts.push(lenBuf);
    }
    parts.push(encoded);
  };

  // Helper to push optional string
  const pushOptionalString = (str?: string, lengthBytes: 1 | 2 = 2) => {
    if (str === undefined || str === "") {
      parts.push(new Uint8Array([0])); // not present
      return;
    }
    parts.push(new Uint8Array([1])); // present
    pushString(str, lengthBytes);
  };

  pushString(payload.issuer);
  pushString(payload.audience);
  pushString(payload.userId, 2);
  pushString(payload.resourceId, 2);
  pushString(payload.operation);
  pushString(payload.secretRef, 2);
  pushOptionalString(payload.deviceId, 2);

  // Assurance (1 byte)
  parts.push(new Uint8Array([payload.assurance]));

  // iat (8 bytes, big-endian)
  const iatBuf = new Uint8Array(8);
  new DataView(iatBuf.buffer).setBigUint64(0, BigInt(payload.iat), false);
  parts.push(iatBuf);

  // exp (8 bytes, big-endian)
  const expBuf = new Uint8Array(8);
  new DataView(expBuf.buffer).setBigUint64(0, BigInt(payload.exp), false);
  parts.push(expBuf);

  pushString(payload.jti);

  // Concatenate all parts
  const totalLength = parts.reduce((sum, p) => sum + p.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }

  return result;
}

/**
 * Decode capability payload from binary format
 */
export function decodeCapabilityPayload(data: Uint8Array): CapabilityPayload {
  // Ensure we have a proper ArrayBuffer for DataView
  const buffer = data.buffer instanceof ArrayBuffer ? data.buffer : new Uint8Array(data).buffer;
  let offset = 0;
  const view = new DataView(buffer, data.byteOffset, data.byteLength);

  const readUint8 = () => view.getUint8(offset++);
  const readUint16 = () => {
    const val = view.getUint16(offset, false);
    offset += 2;
    return val;
  };
  const readUint64 = () => {
    const val = view.getBigUint64(offset, false);
    offset += 8;
    return Number(val);
  };
  const readString = (lengthBytes: 1 | 2 = 1) => {
    const len = lengthBytes === 1 ? readUint8() : readUint16();
    const str = new TextDecoder().decode(data.slice(offset, offset + len));
    offset += len;
    return str;
  };
  const readOptionalString = (lengthBytes: 1 | 2 = 2) => {
    const present = readUint8();
    if (!present) return undefined;
    return readString(lengthBytes);
  };

  const version = readUint8();
  const issuer = readString();
  const audience = readString();
  const userId = readString(2);
  const resourceId = readString(2);
  const operation = readString();
  const secretRef = readString(2);
  const deviceId = readOptionalString(2);
  const assurance = readUint8() as AssuranceLevel;
  const iat = readUint64();
  const exp = readUint64();
  const jti = readString();

  return {
    version,
    issuer,
    audience,
    userId,
    resourceId,
    operation: operation as CapabilityOperation,
    secretRef,
    deviceId,
    assurance,
    iat,
    exp,
    jti,
  };
}

/**
 * Sign a capability payload with Ed25519 private key
 */
export async function signCapability(
  payload: CapabilityPayload,
  privateKey: Uint8Array,
): Promise<SignedCapability> {
  // Encode payload to canonical binary
  const encoded = encodeCapabilityPayload(payload);

  // Sign with Ed25519 (uses seed - first 32 bytes of private key)
  const seed = privateKey.slice(0, 32);
  const signature = ed25519.sign(encoded, seed);

  // Protected header (base64 encoded)
  const protectedHeader = binaryToBase64(
    new TextEncoder().encode(JSON.stringify({ alg: "Ed25519", typ: "capability" })),
  );

  return {
    payload,
    signature: binaryToBase64(signature),
    protectedHeader,
  };
}

/**
 * Verify a signed capability with Ed25519 public key.
 *
 * Checks, in this order: signature, expiry, iat, issuer, audience, operation,
 * assurance level, version, and — when `expected` is supplied — every declared
 * binding on the payload: `userId`, `resourceId`, `secretRef` and `deviceId`.
 *
 * `expected` is the context the capability must match. All four of its fields
 * are validated: a mismatch is a verification failure, and an incomplete
 * context (a non-string or, for everything but `deviceId`, an empty value) is
 * itself a failure — a binding is never silently skipped because the caller
 * forgot to pass it.
 *
 * SECURITY NOTE — the optional third argument exists ONLY because
 * `plus/domain/services/capability-issuer.ts` (4 call sites) and
 * `plus/domain/services/challenge.ts` verify capabilities they just signed,
 * from inside the Plus service, which is out of scope for this work unit and
 * must keep compiling and passing its tests. Those calls pass no context and
 * therefore get signature/structure checks only. EVERY authorization path in
 * Core (managed release, credential-with-capability) is required to pass a
 * complete `CapabilityBindingContext`: its use case refuses to run without
 * one. Do not add a Core caller that omits `expected`.
 */
export async function verifyCapability(
  signed: SignedCapability,
  publicKey: Uint8Array,
  expected?: CapabilityBindingContext,
): Promise<{ valid: boolean; error?: string }> {
  try {
    // Re-encode payload for verification
    const encoded = encodeCapabilityPayload(signed.payload);

    // Verify signature
    const signature = base64ToBinary(signed.signature);
    const valid = ed25519.verify(signature, encoded, publicKey);

    if (!valid) {
      return { valid: false, error: "Invalid signature" };
    }

    // Check expiry
    const now = Math.floor(Date.now() / 1000);
    if (signed.payload.exp < now) {
      return { valid: false, error: "Capability expired" };
    }

    // Check not before (iat <= now)
    if (signed.payload.iat > now + 60) {
      // Allow 60s clock skew
      return { valid: false, error: "Capability not yet valid" };
    }

    // Check issuer and audience
    if (signed.payload.issuer !== "cybervault-plus") {
      return { valid: false, error: "Invalid issuer" };
    }
    if (signed.payload.audience !== "cybervault-core") {
      return { valid: false, error: "Invalid audience" };
    }

    // Check operation is valid
    if (!CAPABILITY_OPERATIONS.includes(signed.payload.operation)) {
      return { valid: false, error: "Invalid operation" };
    }

    // Check assurance level
    if (signed.payload.assurance < 1 || signed.payload.assurance > 3) {
      return { valid: false, error: "Invalid assurance level" };
    }

    // Check version
    if (signed.payload.version !== CAPABILITY_VERSION) {
      return { valid: false, error: "Unsupported capability version" };
    }

    // Check every declared binding against the expected context.
    if (expected !== undefined) {
      return verifyCapabilityBindings(signed.payload, expected);
    }

    return { valid: true };
  } catch (err) {
    return { valid: false, error: err instanceof Error ? err.message : "Verification failed" };
  }
}

/**
 * Compare a capability payload against the expected binding context.
 *
 * Exported so callers (and tests) can assert the binding rules directly. An
 * incomplete context fails closed — it never downgrades to "check skipped".
 */
export function verifyCapabilityBindings(
  payload: CapabilityPayload,
  expected: CapabilityBindingContext,
): { valid: boolean; error?: string } {
  if (
    typeof expected.userId !== "string" ||
    typeof expected.resourceId !== "string" ||
    typeof expected.secretRef !== "string" ||
    typeof expected.deviceId !== "string" ||
    expected.userId === "" ||
    expected.resourceId === "" ||
    expected.secretRef === ""
  ) {
    return { valid: false, error: "Capability binding context is incomplete" };
  }

  if (payload.userId !== expected.userId) {
    return { valid: false, error: "Capability userId does not match the authenticated user" };
  }
  if (payload.resourceId !== expected.resourceId) {
    return { valid: false, error: "Capability resourceId does not match the requested resource" };
  }
  if (payload.secretRef !== expected.secretRef) {
    return { valid: false, error: "Capability secretRef does not match the requested secret" };
  }
  // `deviceId` is optional on the payload: absent means "unbound", which must
  // equal an equally unbound expectation (""), never a bound device.
  if ((payload.deviceId ?? "") !== expected.deviceId) {
    return { valid: false, error: "Capability deviceId does not match the bound device" };
  }

  return { valid: true };
}

/**
 * Create a capability token with all required fields
 */
export function createCapabilityPayload(params: {
  userId: string;
  resourceId: string;
  operation: CapabilityOperation;
  secretRef: string;
  deviceId?: string;
  assurance: AssuranceLevel;
  ttlSeconds?: number;
}): CapabilityPayload {
  const now = Math.floor(Date.now() / 1000);
  const ttl = params.ttlSeconds ?? DEFAULT_CAPABILITY_TTL_SECONDS;

  if (ttl > MAX_CAPABILITY_TTL_SECONDS) {
    throw new Error(`TTL exceeds maximum of ${MAX_CAPABILITY_TTL_SECONDS} seconds`);
  }

  // Generate cryptographically random JTI
  const jtiBytes = ed25519.utils.randomSecretKey();
  const jti = binaryToBase64(jtiBytes.slice(0, 16)); // 16 bytes = 128 bits

  return {
    issuer: "cybervault-plus",
    audience: "cybervault-core",
    userId: params.userId,
    resourceId: params.resourceId,
    operation: params.operation,
    secretRef: params.secretRef,
    deviceId: params.deviceId,
    assurance: params.assurance,
    iat: now,
    exp: now + ttl,
    jti,
    version: CAPABILITY_VERSION,
  };
}

/**
 * Verify capability payload structure without signature (for pre-validation)
 */
export function validateCapabilityPayload(payload: CapabilityPayload): { valid: boolean; error?: string } {
  if (payload.version !== CAPABILITY_VERSION) {
    return { valid: false, error: "Unsupported capability version" };
  }
  if (payload.issuer !== "cybervault-plus") {
    return { valid: false, error: "Invalid issuer" };
  }
  if (payload.audience !== "cybervault-core") {
    return { valid: false, error: "Invalid audience" };
  }
  if (!CAPABILITY_OPERATIONS.includes(payload.operation)) {
    return { valid: false, error: "Invalid operation" };
  }
  if (payload.assurance < 1 || payload.assurance > 3) {
    return { valid: false, error: "Invalid assurance level" };
  }
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp < now) {
    return { valid: false, error: "Capability expired" };
  }
  if (payload.iat > now + 60) {
    return { valid: false, error: "Capability not yet valid" };
  }
  if (!payload.jti || payload.jti.length < 16) {
    return { valid: false, error: "Invalid or missing JTI" };
  }
  return { valid: true };
}

// Constants already exported at top of file