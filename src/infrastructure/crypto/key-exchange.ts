/**
 * X25519 Key Exchange — ECDH for Secure Session Establishment
 *
 * Implements X25519 key agreement using Web Crypto API.
 * Private keys are stored in SecureBuffer with auto-zero on free.
 *
 * @module infrastructure/crypto/key-exchange
 */

import { SecureBuffer } from "./secure-memory";

/** Convert Uint8Array to ArrayBuffer for Web Crypto API compatibility */
function toArrayBuffer(data: Uint8Array): ArrayBuffer {
  const buf = new ArrayBuffer(data.byteLength);
  new Uint8Array(buf).set(data);
  return buf;
}

/**
 * Key pair for ECDH key exchange
 */
export interface KeyPair {
  publicKey: SecureBuffer;
  privateKey: SecureBuffer;
  curve: "X25519" | "P-256";
  privateKeyFormat: "raw" | "pkcs8";
}

/**
 * Create a SecureBuffer from raw bytes
 */
function secureBufferFromBytes(data: Uint8Array): SecureBuffer {
  const buf = new SecureBuffer(data.length);
  buf.copyFrom(data);
  return buf;
}

/**
 * Generate an X25519 key pair using Web Crypto API
 * Falls back to P-256 if X25519 is not supported
 */
export async function generateKeyPair(): Promise<KeyPair> {
  try {
    const keyPair = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "X25519" },
      true,
      ["deriveKey", "deriveBits"],
    );

    const publicKeyRaw = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
    const privateKeyRaw = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.privateKey));

    return {
      publicKey: secureBufferFromBytes(publicKeyRaw),
      privateKey: secureBufferFromBytes(privateKeyRaw),
      curve: "X25519",
      privateKeyFormat: "raw",
    };
  } catch {
    const keyPair = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      true,
      ["deriveKey", "deriveBits"],
    );

    const publicKeyRaw = new Uint8Array(await crypto.subtle.exportKey("raw", keyPair.publicKey));
    const privateKeyRaw = new Uint8Array(await crypto.subtle.exportKey("pkcs8", keyPair.privateKey));

    return {
      publicKey: secureBufferFromBytes(publicKeyRaw),
      privateKey: secureBufferFromBytes(privateKeyRaw),
      curve: "P-256",
      privateKeyFormat: "pkcs8",
    };
  }
}

/**
 * Derive shared secret from private key and peer's public key
 * Uses HKDF-SHA256 with context "cybervault_key_exchange_v1"
 */
export async function deriveSharedSecret(
  keyPair: KeyPair,
  publicKey: SecureBuffer,
  context: string = "cybervault_key_exchange_v1",
): Promise<Uint8Array> {
  if (keyPair.privateKey.freed) {
    throw new Error("Private key has been freed");
  }

  const contextBytes = new TextEncoder().encode(context);
  const curveName = keyPair.curve === "X25519" ? "X25519" : "P-256";

  const importedPrivate = await crypto.subtle.importKey(
    keyPair.privateKeyFormat,
    toArrayBuffer(keyPair.privateKey.view),
    { name: "ECDH", namedCurve: curveName },
    false,
    ["deriveBits"],
  );

  const importedPublic = await crypto.subtle.importKey(
    "raw",
    toArrayBuffer(publicKey.view),
    { name: "ECDH", namedCurve: curveName },
    false,
    [],
  );

  const sharedSecret = await crypto.subtle.deriveBits(
    { name: "ECDH", public: importedPublic },
    importedPrivate,
    256,
  );

  const hkdfKey = await crypto.subtle.importKey(
    "raw",
    sharedSecret,
    "HKDF",
    false,
    ["deriveKey"],
  );

  const derivedKey = await crypto.subtle.deriveKey(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: contextBytes,
      info: contextBytes,
    },
    hkdfKey,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"],
  );

  const rawKey = await crypto.subtle.exportKey("raw", derivedKey);
  return new Uint8Array(rawKey);
}

/**
 * Export public key as base64 string for exchange
 */
export function exportPublicKeyBase64(keyPair: KeyPair): string {
  const binary = Array.from(keyPair.publicKey.view)
    .map((b) => String.fromCharCode(b))
    .join("");
  return btoa(binary);
}

/**
 * Import public key from base64 string
 */
export async function importPublicKeyFromBase64(
  base64: string,
): Promise<SecureBuffer> {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return secureBufferFromBytes(bytes);
}

/**
 * Constant-time comparison to prevent timing attacks
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }
  return result === 0;
}
