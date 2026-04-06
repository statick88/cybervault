// Encryption Service
// Implementación del servicio de encriptación usando Web Crypto API
// Stateless - NO usar this

import { secureZero, generateSecureSalt } from "./secure-memory";
import { binaryToBase64, base64ToBinary } from "@/shared/utils";

/**
 * Constantes de configuración de encriptación
 */
const ENCRYPTION_CONFIG = {
  AES: {
    ALGORITHM: "AES-GCM",
    KEY_LENGTH: 256, // bits
    IV_LENGTH: 12, // bytes (recommended for GCM)
    TAG_LENGTH: 128, // bits
  },
  PBKDF2: {
    ALGORITHM: "PBKDF2",
    HASH: "SHA-512",
    ITERATIONS: 600000, // 600k iteraciones (recomendación NIST)
    SALT_LENGTH: 16, // bytes (128-bit)
  },
} as const;

/**
 * Encripta datos usando AES-GCM-256 con una clave ya derivada
 * SECURITY: No deriva clave - usa directamente la clave proporcionada
 * @param data Datos a encriptar
 * @param keyBase64 Clave AES-GCM ya derivada (base64)
 * @returns Datos encriptados en formato: iv|ciphertext (base64)
 */
export async function encryptWithKey(
  data: string,
  keyBase64: string,
): Promise<string> {
  // Convertir clave de base64 a Uint8Array
  const keyData = base64ToBinary(keyBase64);

  // Importar clave AES-GCM usando el buffer subyacente (ArrayBuffer)
  const aesKey = await crypto.subtle.importKey(
    "raw",
    keyData.buffer as ArrayBuffer,
    "AES-GCM",
    false,
    ["encrypt"],
  );

  // SECURITY: Clean up key data after import
  secureZero(keyData);

  // Generate unique IV
  const iv = new Uint8Array(ENCRYPTION_CONFIG.AES.IV_LENGTH);
  crypto.getRandomValues(iv);

  // Encrypt data
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

  // SECURITY: Clean up sensitive data
  secureZero(dataBuffer);

  // Format: iv|ciphertext
  const combined = new Uint8Array(iv.length + encryptedBuffer.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(encryptedBuffer), iv.length);

  return binaryToBase64(combined);
}

/**
 * Desencripta datos usando AES-GCM-256 con una clave ya derivada
 * SECURITY: No deriva clave - usa directamente la clave proporcionada
 * @param encryptedData Datos encriptados en formato: iv|ciphertext (base64)
 * @param keyBase64 Clave AES-GCM ya derivada (base64)
 * @returns Datos originales
 */
export async function decryptWithKey(
  encryptedData: string,
  keyBase64: string,
): Promise<string> {
  // Convertir clave de base64 a Uint8Array
  const keyData = base64ToBinary(keyBase64);

  // Importar clave AES-GCM usando el buffer subyacente (ArrayBuffer)
  const aesKey = await crypto.subtle.importKey(
    "raw",
    keyData.buffer as ArrayBuffer,
    "AES-GCM",
    false,
    ["decrypt"],
  );

  // Decode base64 del encryptedData
  const combined = base64ToBinary(encryptedData);

  // Extract components: iv|ciphertext (sin salt)
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
    // SECURITY: Generic error message
    throw new Error("Decryption failed");
  } finally {
    // SECURITY: Secure cleanup
    secureZero(keyData);
    secureZero(iv);
    secureZero(ciphertextWithTag);
  }
}

/**
 * Encripta datos usando AES-GCM-256 con derivación de clave PBKDF2
 * SECURITY: Uses proper key derivation - master key derives the encryption key
 * @param data Datos a encriptar
 * @param masterKey Clave maestra (usada para derivar clave de encriptación)
 * @returns Datos encriptados en formato: salt|iv|ciphertext (base64)
 */
export async function encrypt(
  data: string,
  masterKey: string,
): Promise<string> {
  // SECURITY: Generate random salt for key derivation
  const salt = generateSecureSalt(ENCRYPTION_CONFIG.PBKDF2.SALT_LENGTH);

  // SECURITY: Derive key from master using PBKDF2
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
    false, // SECURITY: Key is not extractable
    ["encrypt", "decrypt"],
  );

  // Clean up key material
  const keyMaterialExported = await crypto.subtle.exportKey("raw", keyMaterial);
  secureZero(new Uint8Array(keyMaterialExported));

  // Generate unique IV
  const iv = new Uint8Array(ENCRYPTION_CONFIG.AES.IV_LENGTH);
  crypto.getRandomValues(iv);

  // Encrypt data
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

  // SECURITY: Clean up sensitive data
  secureZero(dataBuffer);

  // Format: salt|iv|ciphertext (no key!)
  const combined = new Uint8Array(
    salt.length + iv.length + encryptedBuffer.byteLength,
  );
  combined.set(salt, 0);
  combined.set(iv, salt.length);
  combined.set(new Uint8Array(encryptedBuffer), salt.length + iv.length);

  return binaryToBase64(combined);
}

/**
 * Desencripta datos usando AES-GCM-256 con derivación de clave PBKDF2
 * SECURITY: Proper key derivation from master key
 * @param encryptedData Datos encriptados en formato: salt|iv|ciphertext (base64)
 * @param masterKey Clave maestra para derivar clave de desencriptación
 * @returns Datos originales
 */
export async function decrypt(
  encryptedData: string,
  masterKey: string,
): Promise<string> {
  // Decode base64
  const combined = base64ToBinary(encryptedData);

  // Extract components: salt|iv|ciphertext
  const saltLength = ENCRYPTION_CONFIG.PBKDF2.SALT_LENGTH;
  const ivLength = ENCRYPTION_CONFIG.AES.IV_LENGTH;

  const salt = combined.slice(0, saltLength);
  const iv = combined.slice(saltLength, saltLength + ivLength);
  const ciphertextWithTag = combined.slice(saltLength + ivLength);

  // Derive key from master using the same salt
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
    false, // SECURITY: Key is not extractable
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
    // SECURITY: Generic error message
    throw new Error("Decryption failed");
  } finally {
    // SECURITY: Secure cleanup
    secureZero(salt);
    secureZero(iv);
    secureZero(ciphertextWithTag);
  }
}
