/**
 * Release Share KEK — Core-side wrapping key for a managed Release Share.
 *
 * WHY THIS EXISTS
 * ---------------
 * Managed authoring (ODD decision "Option C", 2026-09-26) happens server-side
 * because only Core ever holds both halves of `EntryKey = HKDF(VEK ||
 * ReleaseShare, ...)`. That makes Core the single holder of the Release Share,
 * so the share must never sit in a table in the clear: it is wrapped under a
 * dedicated "Release Share KEK" and persisted as an opaque blob keyed by
 * `secretRef`.
 *
 * KEY SEPARATION
 * --------------
 * The KEK is HKDF-expanded from an injected 32-byte server secret using its
 * OWN info string. It is intentionally distinct from:
 *   - the VEK and every per-entry key (hkdf-derivation.ts contexts), and
 *   - the DomainIndexKey (`cybervault|domain-index|v1`).
 * Reusing any of those strings would be cross-protocol key reuse: the same
 * input key material would produce interchangeable keys, and a leak in one
 * protocol would become a leak in another.
 *
 * FAIL CLOSED
 * -----------
 * There is no default secret anywhere in this module. A missing, empty or
 * wrong-length server secret raises `ReleaseShareKekError` instead of falling
 * back to a constant, an empty key or the VEK.
 *
 * CONFIGURATION
 * -------------
 * Core reads the secret from `RELEASE_SHARE_KEK_SECRET`: base64 of exactly 32
 * random bytes (e.g. `openssl rand -base64 32`). `loadReleaseShareKekSecret`
 * validates it and returns null when it is absent or malformed; the API server
 * logs a warning at boot and every managed release then refuses.
 *
 * FORMAT
 * ------
 * `wrappedShare` = base64( iv(12) | AES-256-GCM ciphertext+tag ).
 * The `secretRef` is bound as GCM additional authenticated data, so a blob
 * cannot be relocated to a different reference by anyone who can write to the
 * store.
 *
 * @module infrastructure/crypto/release-share-kek
 */

import { secureZero } from "./secure-memory";
import { base64ToBinary, binaryToBase64 } from "../../shared/utils";

/** Distinct HKDF info string for the Release Share KEK. Never reuse another. */
export const RELEASE_SHARE_KEK_INFO = "cybervault|release-share-kek|v1";

/** The server secret backing the KEK must be exactly 32 bytes. */
export const RELEASE_SHARE_KEK_SECRET_BYTES = 32;

const KEK_BITS = 256;
const WRAP_IV_LEN = 12;
const GCM_TAG_BITS = 128;

/** Typed failure codes. Every one of them is a fail-closed outcome. */
export type ReleaseShareKekErrorCode =
  | "SECRET_MISSING"
  | "SECRET_WRONG_LENGTH"
  | "WRAP_FAILED"
  | "UNWRAP_FAILED";

/**
 * Typed, catchable error for Release Share KEK failures.
 *
 * `code` is stable and safe to surface in logs; `message` never contains key
 * material or ciphertext.
 */
export class ReleaseShareKekError extends Error {
  readonly code: ReleaseShareKekErrorCode;

  constructor(code: ReleaseShareKekErrorCode, message: string) {
    super(message);
    this.name = "ReleaseShareKekError";
    this.code = code;
  }
}

function toArrayBuffer(data: Uint8Array): ArrayBuffer {
  const buf = new ArrayBuffer(data.byteLength);
  new Uint8Array(buf).set(data);
  return buf;
}

/**
 * Derive the Release Share KEK from the injected server secret.
 *
 * @param serverSecret Raw 32-byte server secret. Never defaulted.
 * @throws {ReleaseShareKekError} SECRET_MISSING | SECRET_WRONG_LENGTH
 */
export async function deriveReleaseShareKek(
  serverSecret: Uint8Array | null | undefined,
): Promise<Uint8Array> {
  if (!serverSecret || serverSecret.byteLength === 0) {
    throw new ReleaseShareKekError(
      "SECRET_MISSING",
      "Release Share KEK secret is not configured",
    );
  }
  if (serverSecret.byteLength !== RELEASE_SHARE_KEK_SECRET_BYTES) {
    throw new ReleaseShareKekError(
      "SECRET_WRONG_LENGTH",
      `Release Share KEK secret must be ${RELEASE_SHARE_KEK_SECRET_BYTES} bytes, got ${serverSecret.byteLength}`,
    );
  }

  const baseKey = await crypto.subtle.importKey(
    "raw",
    toArrayBuffer(serverSecret),
    { name: "HKDF" },
    false,
    ["deriveBits"],
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(32),
      info: new TextEncoder().encode(RELEASE_SHARE_KEK_INFO),
    },
    baseKey,
    KEK_BITS,
  );

  return new Uint8Array(bits);
}

/**
 * Load the server secret from its textual (base64) configuration form.
 *
 * Returns null — rather than throwing — so callers can decide when to fail:
 * a process that never performs managed release must still start.
 *
 * @param raw Base64-encoded 32-byte secret, or undefined/empty.
 */
export function loadReleaseShareKekSecret(raw: string | undefined | null): Uint8Array | null {
  if (!raw || raw.trim() === "") return null;
  try {
    const bytes = base64ToBinary(raw.trim());
    if (bytes.byteLength !== RELEASE_SHARE_KEK_SECRET_BYTES) return null;
    return bytes;
  } catch {
    return null;
  }
}

/**
 * Wrap a Release Share under the Release Share KEK.
 *
 * @param kek Result of {@link deriveReleaseShareKek}.
 * @param releaseShare The 32-byte share. Not zeroized here; the caller owns it.
 * @param secretRef Bound as GCM additional authenticated data.
 * @throws {ReleaseShareKekError} WRAP_FAILED
 */
export async function wrapReleaseShare(
  kek: Uint8Array,
  releaseShare: Uint8Array,
  secretRef: string,
): Promise<string> {
  if (kek.byteLength !== KEK_BITS / 8) {
    throw new ReleaseShareKekError("WRAP_FAILED", "Release Share KEK has an unexpected length");
  }
  if (releaseShare.byteLength === 0) {
    throw new ReleaseShareKekError("WRAP_FAILED", "Release Share is empty");
  }

  try {
    const iv = crypto.getRandomValues(new Uint8Array(WRAP_IV_LEN));
    const key = await crypto.subtle.importKey("raw", toArrayBuffer(kek), "AES-GCM", false, [
      "encrypt",
    ]);
    const ct = await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: toArrayBuffer(iv),
        tagLength: GCM_TAG_BITS,
        additionalData: toArrayBuffer(new TextEncoder().encode(secretRef)),
      },
      key,
      toArrayBuffer(releaseShare),
    );

    const out = new Uint8Array(iv.byteLength + ct.byteLength);
    out.set(iv, 0);
    out.set(new Uint8Array(ct), iv.byteLength);
    return binaryToBase64(out);
  } catch (error) {
    if (error instanceof ReleaseShareKekError) throw error;
    const message = error instanceof Error ? error.message : "unknown failure";
    throw new ReleaseShareKekError("WRAP_FAILED", `could not wrap the Release Share: ${message}`);
  }
}

/**
 * Unwrap a Release Share. Fails closed: a wrong KEK, tampered blob or
 * relocated blob all surface as UNWRAP_FAILED, never as a partial result.
 *
 * @returns The raw 32-byte share. The caller MUST `secureZero` it after use.
 * @throws {ReleaseShareKekError} UNWRAP_FAILED
 */
export async function unwrapReleaseShare(
  kek: Uint8Array,
  wrappedShare: string,
  secretRef: string,
): Promise<Uint8Array> {
  if (kek.byteLength !== KEK_BITS / 8) {
    throw new ReleaseShareKekError("UNWRAP_FAILED", "Release Share KEK has an unexpected length");
  }

  let combined: Uint8Array;
  try {
    combined = base64ToBinary(wrappedShare);
  } catch {
    throw new ReleaseShareKekError("UNWRAP_FAILED", "wrapped Release Share is not valid base64");
  }

  if (combined.byteLength <= WRAP_IV_LEN) {
    throw new ReleaseShareKekError("UNWRAP_FAILED", "wrapped Release Share is truncated");
  }

  const iv = combined.slice(0, WRAP_IV_LEN);
  const ciphertext = combined.slice(WRAP_IV_LEN);

  try {
    const key = await crypto.subtle.importKey("raw", toArrayBuffer(kek), "AES-GCM", false, [
      "decrypt",
    ]);
    const plaintext = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: toArrayBuffer(iv),
        tagLength: GCM_TAG_BITS,
        additionalData: toArrayBuffer(new TextEncoder().encode(secretRef)),
      },
      key,
      toArrayBuffer(ciphertext),
    );
    return new Uint8Array(plaintext);
  } catch {
    // Deliberately opaque: no distinction between wrong KEK and tampering.
    throw new ReleaseShareKekError(
      "UNWRAP_FAILED",
      "Release Share could not be unwrapped with the configured Release Share KEK",
    );
  } finally {
    secureZero(iv);
    secureZero(ciphertext);
  }
}
