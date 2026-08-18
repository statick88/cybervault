/**
 * Encryption Service
 * AES-GCM-256 encryption with PBKDF2 key derivation
 */

import { secureZero, generateSecureSalt } from "./secure-memory";
import { binaryToBase64, base64ToBinary } from "../../shared/utils";

const ENCRYPTION_CONFIG = {
  AES: {
    ALGORITHM: "AES-GCM",
    KEY_LENGTH: 256,
    IV_LENGTH: 12,
    TAG_LENGTH: 128,
  },
  PBKDF2: {
    ALGORITHM: "PBKDF2",
    HASH: "SHA-512",
    ITERATIONS: 600000,
    SALT_LENGTH: 16,
  },
} as const;

function toArrayBuffer(data: Uint8Array): ArrayBuffer {
  const buf = new ArrayBuffer(data.byteLength);
  new Uint8Array(buf).set(data);
  return buf;
}

/**
 * Encrypt with a pre-derived AES-GCM key (base64)
 */
export async function encryptWithKey(
  data: string,
  keyBase64: string,
): Promise<string> {
  const keyData = base64ToBinary(keyBase64);

  const aesKey = await crypto.subtle.importKey(
    "raw",
    keyData.buffer as ArrayBuffer,
    "AES-GCM",
    false,
    ["encrypt"],
  );

  secureZero(keyData);

  const iv = new Uint8Array(ENCRYPTION_CONFIG.AES.IV_LENGTH);
  crypto.getRandomValues(iv);

  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);

  const encryptedBuffer = await crypto.subtle.encrypt(
    {
      name: ENCRYPTION_CONFIG.AES.ALGORITHM,
      iv: iv,
      tagLength: ENCRYPTION_CONFIG.AES.TAG_LENGTH,
    },
    aesKey,
    dataBuffer,
  );

  secureZero(dataBuffer);

  const combined = new Uint8Array(iv.length + encryptedBuffer.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(encryptedBuffer), iv.length);

  return binaryToBase64(combined);
}

/**
 * Decrypt with a pre-derived AES-GCM key (base64)
 */
export async function decryptWithKey(
  encryptedData: string,
  keyBase64: string,
): Promise<string> {
  const keyData = base64ToBinary(keyBase64);

  const aesKey = await crypto.subtle.importKey(
    "raw",
    keyData.buffer as ArrayBuffer,
    "AES-GCM",
    false,
    ["decrypt"],
  );

  const combined = base64ToBinary(encryptedData);

  const ivLength = ENCRYPTION_CONFIG.AES.IV_LENGTH;

  const iv = combined.slice(0, ivLength);
  const ciphertextWithTag = combined.slice(ivLength);

  try {
    const decryptedBuffer = await crypto.subtle.decrypt(
      {
        name: ENCRYPTION_CONFIG.AES.ALGORITHM,
        iv: iv,
        tagLength: ENCRYPTION_CONFIG.AES.TAG_LENGTH,
      },
      aesKey,
      ciphertextWithTag,
    );

    const decoder = new TextDecoder();
    return decoder.decode(decryptedBuffer);
  } catch (error) {
    throw new Error("Decryption failed");
  } finally {
    secureZero(keyData);
    secureZero(iv);
    secureZero(ciphertextWithTag);
  }
}

/**
 * Encrypt with PBKDF2 key derivation from master key
 */
export async function encrypt(
  data: string,
  masterKey: string,
): Promise<string> {
  const salt = generateSecureSalt(ENCRYPTION_CONFIG.PBKDF2.SALT_LENGTH);

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(masterKey) as BufferSource,
    "PBKDF2",
    false,
    ["deriveKey"],
  );

  const aesKey = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt as unknown as BufferSource,
      iterations: ENCRYPTION_CONFIG.PBKDF2.ITERATIONS,
      hash: ENCRYPTION_CONFIG.PBKDF2.HASH,
    },
    keyMaterial,
    {
      name: ENCRYPTION_CONFIG.AES.ALGORITHM,
      length: ENCRYPTION_CONFIG.AES.KEY_LENGTH,
    },
    false,
    ["encrypt", "decrypt"],
  );

  const iv = new Uint8Array(ENCRYPTION_CONFIG.AES.IV_LENGTH);
  crypto.getRandomValues(iv);

  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);

  const encryptedBuffer = await crypto.subtle.encrypt(
    {
      name: ENCRYPTION_CONFIG.AES.ALGORITHM,
      iv: iv,
      tagLength: ENCRYPTION_CONFIG.AES.TAG_LENGTH,
    },
    aesKey,
    dataBuffer,
  );

  secureZero(dataBuffer);

  const combined = new Uint8Array(
    salt.length + iv.length + encryptedBuffer.byteLength,
  );
  combined.set(salt, 0);
  combined.set(iv, salt.length);
  combined.set(new Uint8Array(encryptedBuffer), salt.length + iv.length);

  return binaryToBase64(combined);
}

/**
 * Decrypt with PBKDF2 key derivation from master key
 */
export async function decrypt(
  encryptedData: string,
  masterKey: string,
): Promise<string> {
  const combined = base64ToBinary(encryptedData);

  const saltLength = ENCRYPTION_CONFIG.PBKDF2.SALT_LENGTH;
  const ivLength = ENCRYPTION_CONFIG.AES.IV_LENGTH;

  const salt = combined.slice(0, saltLength);
  const iv = combined.slice(saltLength, saltLength + ivLength);
  const ciphertextWithTag = combined.slice(saltLength + ivLength);

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(masterKey) as BufferSource,
    "PBKDF2",
    false,
    ["deriveKey"],
  );

  const aesKey = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt as unknown as BufferSource,
      iterations: ENCRYPTION_CONFIG.PBKDF2.ITERATIONS,
      hash: ENCRYPTION_CONFIG.PBKDF2.HASH,
    },
    keyMaterial,
    {
      name: ENCRYPTION_CONFIG.AES.ALGORITHM,
      length: ENCRYPTION_CONFIG.AES.KEY_LENGTH,
    },
    false,
    ["decrypt"],
  );

  try {
    const decryptedBuffer = await crypto.subtle.decrypt(
      {
        name: ENCRYPTION_CONFIG.AES.ALGORITHM,
        iv: iv,
        tagLength: ENCRYPTION_CONFIG.AES.TAG_LENGTH,
      },
      aesKey,
      ciphertextWithTag,
    );

    const decoder = new TextDecoder();
    return decoder.decode(decryptedBuffer);
  } catch (error) {
    throw new Error("Decryption failed");
  } finally {
    secureZero(salt);
    secureZero(iv);
    secureZero(ciphertextWithTag);
  }
}

/**
 * EncryptionService class wrapper for backward compatibility
 */
export class EncryptionService {
  async encrypt(data: string, masterKey: string): Promise<string> {
    return encrypt(data, masterKey);
  }

  async decrypt(encryptedData: string, masterKey: string): Promise<string> {
    return decrypt(encryptedData, masterKey);
  }
}
