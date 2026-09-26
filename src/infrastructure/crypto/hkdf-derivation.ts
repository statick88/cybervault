/**
 * HKDF Derivation Service — Per-Entry Key Derivation for CyberVault
 *
 * Implements HKDF-SHA256 per RFC 5869 for deriving per-credential EntryKeys.
 * Two modes:
 * - PERSONAL: EntryKey = HKDF(VEK, salt, context: credential-id + version + "personal")
 * - MANAGED: EntryKey = HKDF(VEK || ReleaseShare, salt, context: credential-id + version + "managed")
 *
 * Uses Web Crypto API (SubtleCrypto) for HKDF.
 */

import { secureZero } from "./secure-memory";
import { binaryToBase64, base64ToBinary } from "../../shared/utils";

/** Convert Uint8Array to ArrayBuffer for Web Crypto API */
function toArrayBuffer(data: Uint8Array): ArrayBuffer {
  const buf = new ArrayBuffer(data.byteLength);
  new Uint8Array(buf).set(data);
  return buf;
}

/** HKDF configuration */
const HKDF_CONFIG = {
  HASH: "SHA-256" as const,
  KEY_LENGTH: 256, // bits (32 bytes for AES-256)
  SALT_LENGTH: 32, // 256-bit salt per credential
} as const;

/** Entry derivation mode */
export type EntryMode = "personal" | "managed";

/** Context for key derivation */
export interface DerivationContext {
  credentialId: string;
  version: number;
  mode: EntryMode;
}

/** Result of key derivation */
export interface DerivedEntryKey {
  keyBase64: string;
  saltBase64: string;
  context: DerivationContext;
}

/**
 * Generate a cryptographically random salt for per-entry derivation
 */
export function generateEntrySalt(): Uint8Array {
  const salt = new Uint8Array(HKDF_CONFIG.SALT_LENGTH);
  crypto.getRandomValues(salt);
  return salt;
}

/**
 * Build HKDF context info string from derivation context
 * Format: "cybervault|{credentialId}|v{version}|{mode}"
 */
function buildContextInfo(ctx: DerivationContext): string {
  return `cybervault|${ctx.credentialId}|v${ctx.version}|${ctx.mode}`;
}

/**
 * Convert context info string to Uint8Array for HKDF info parameter
 */
function contextInfoToBuffer(info: string): Uint8Array {
  return new TextEncoder().encode(info);
}

/**
 * Derive an EntryKey using HKDF-SHA256
 *
 * @param inputKeyMaterial - VEK (personal) or VEK || ReleaseShare (managed) as Uint8Array
 * @param salt - Per-entry random salt (32 bytes)
 * @param context - Derivation context (credentialId, version, mode)
 * @returns DerivedEntryKey with keyBase64, saltBase64, and context
 */
export async function deriveEntryKey(
  inputKeyMaterial: Uint8Array,
  salt: Uint8Array,
  context: DerivationContext,
): Promise<DerivedEntryKey> {
  // Import input key material as HKDF base key
  const baseKey = await crypto.subtle.importKey(
    "raw",
    toArrayBuffer(inputKeyMaterial),
    { name: "HKDF" },
    false,
    ["deriveKey"],
  );

  const info = contextInfoToBuffer(buildContextInfo(context));

  // Derive the entry key using HKDF
  const entryKey = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: HKDF_CONFIG.HASH,
      salt: toArrayBuffer(salt),
      info: toArrayBuffer(info),
    },
    baseKey,
    { name: "AES-GCM", length: HKDF_CONFIG.KEY_LENGTH },
    true, // Extractable: needed to export raw key for AES-GCM import
    ["encrypt", "decrypt"],
  );

  // Export the derived key for use (base64)
  const exportedKey = await crypto.subtle.exportKey("raw", entryKey);
  const keyBase64 = binaryToBase64(new Uint8Array(exportedKey));
  const saltBase64 = binaryToBase64(salt);

  // NOTE: Caller is responsible for secureZero on inputKeyMaterial
  // (deriveEntryKey does not own the input buffer)

  return {
    keyBase64,
    saltBase64,
    context,
  };
}

/**
 * Derive EntryKey for a PERSONAL credential
 * EntryKey = HKDF(VEK, salt, context: credential-id + version + "personal")
 */
export async function derivePersonalEntryKey(
  vek: Uint8Array,
  salt: Uint8Array,
  credentialId: string,
  version: number = 1,
): Promise<DerivedEntryKey> {
  return deriveEntryKey(vek, salt, {
    credentialId,
    version,
    mode: "personal",
  });
}

/**
 * Derive EntryKey for a MANAGED credential
 * EntryKey = HKDF(VEK || ReleaseShare, salt, context: credential-id + version + "managed")
 *
 * @param vek - Vault Encryption Key (32 bytes)
 * @param releaseShare - Release Share from Plus (32 bytes)
 * @param salt - Per-entry random salt (32 bytes)
 * @param credentialId - Credential identifier
 * @param version - Credential version (default 1)
 */
export async function deriveManagedEntryKey(
  vek: Uint8Array,
  releaseShare: Uint8Array,
  salt: Uint8Array,
  credentialId: string,
  version: number = 1,
): Promise<DerivedEntryKey> {
  // Concatenate VEK || ReleaseShare (64 bytes total)
  const combined = new Uint8Array(vek.length + releaseShare.length);
  combined.set(vek, 0);
  combined.set(releaseShare, vek.length);

  try {
    return await deriveEntryKey(combined, salt, {
      credentialId,
      version,
      mode: "managed",
    });
  } finally {
    // Secure cleanup of combined key material
    secureZero(combined);
  }
}

/**
 * Verify that a derived key matches expected parameters (for testing/validation)
 * Re-derives and compares using timing-safe comparison
 */
export async function verifyEntryKey(
  inputKeyMaterial: Uint8Array,
  salt: Uint8Array,
  context: DerivationContext,
  expectedKeyBase64: string,
): Promise<boolean> {
  const derived = await deriveEntryKey(inputKeyMaterial, salt, context);
  return timingSafeEqualBase64(derived.keyBase64, expectedKeyBase64);
}

/**
 * Timing-safe base64 string comparison
 */
function timingSafeEqualBase64(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}

/**
 * Re-derive EntryKey from stored parameters (for decryption)
 * Used when decrypting existing credentials
 */
export async function rederiveEntryKey(
  inputKeyMaterial: Uint8Array,
  saltBase64: string,
  context: DerivationContext,
): Promise<string> {
  const salt = base64ToBinary(saltBase64);
  const derived = await deriveEntryKey(inputKeyMaterial, salt, context);
  return derived.keyBase64;
}

// Export config for testing
export { HKDF_CONFIG };