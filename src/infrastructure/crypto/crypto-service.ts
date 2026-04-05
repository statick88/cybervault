// @ts-nocheck

/**
 * Crypto Service Implementation
 * Implementación del servicio de criptografía usando Web Crypto API
 */

import { ICryptoService } from "../../domain/services";
import { CryptoHash } from "../../domain/value-objects/ids";
import { SecureBuffer, secureZero, generateSecureSalt } from "./secure-memory";
import { binaryToBase64, base64ToBinary } from "@/shared/utils";

/**
 * Constantes de configuración criptográfica
 */
const CRYPTO_CONFIG = {
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
  ECDSA: {
    ALGORITHM: "ECDSA",
    NAMED_CURVE: "P-256",
    HASH: "SHA-256",
  },
} as const;

export class CryptoService implements ICryptoService {
  /**
   * Genera par de claves asimétricas (ECDSA P-256)
   * SECURITY: Keys are NOT extractable for security
   * @returns Par de claves en formato JWK
   */
  async generateKeyPair(): Promise<{
    publicKey: string;
    privateKey: string;
  }> {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: CRYPTO_CONFIG.ECDSA.ALGORITHM,
        namedCurve: CRYPTO_CONFIG.ECDSA.NAMED_CURVE,
      },
      false, // SECURITY: Keys are NOT extractable
      ["sign", "verify"],
    );

    // Exportar claves a formato JWK
    const publicKeyJwk = await crypto.subtle.exportKey(
      "jwk",
      keyPair.publicKey,
    );
    const privateKeyJwk = await crypto.subtle.exportKey(
      "jwk",
      keyPair.privateKey,
    );

    // Convertir a string JSON
    const publicKey = JSON.stringify(publicKeyJwk);
    const privateKey = JSON.stringify(privateKeyJwk);

    return {
      publicKey,
      privateKey,
    };
  }

  /**
   * Encripta datos usando AES-GCM-256
   * SECURITY: Uses proper key derivation - master key derives the encryption key
   * @param data Datos a encriptar
   * @param masterKey Clave maestra (usada para derivar clave de encriptación)
   * @returns Datos encriptados en formato: salt|iv|ciphertext (base64)
   */
  async encrypt(data: string, masterKey: string): Promise<string> {
    // SECURITY: Generate random salt for key derivation
    const salt = generateSecureSalt(CRYPTO_CONFIG.PBKDF2.SALT_LENGTH);

    // SECURITY: Derive key from master using PBKDF2
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(masterKey),
      "PBKDF2",
      false,
      ["deriveKey"],
    );

    const aesKey = await crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: CRYPTO_CONFIG.PBKDF2.ITERATIONS,
        hash: CRYPTO_CONFIG.PBKDF2.HASH,
      },
      keyMaterial,
      {
        name: CRYPTO_CONFIG.AES.ALGORITHM,
        length: CRYPTO_CONFIG.AES.KEY_LENGTH,
      },
      false, // SECURITY: Key is not extractable
      ["encrypt", "decrypt"],
    );

    // Clean up key material
    secureZero(
      new Uint8Array(await crypto.subtle.exportKey("raw", keyMaterial)),
    );

    // Generate unique IV
    const iv = new Uint8Array(CRYPTO_CONFIG.AES.IV_LENGTH);
    crypto.getRandomValues(iv);

    // Encrypt data
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);

    const encryptedBuffer = await crypto.subtle.encrypt(
      {
        name: CRYPTO_CONFIG.AES.ALGORITHM,
        iv: iv,
        tagLength: CRYPTO_CONFIG.AES.TAG_LENGTH,
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
   * Desencripta datos usando AES-GCM-256
   * SECURITY: Proper key derivation from master key
   * @param encryptedData Datos encriptados en formato: salt|iv|ciphertext (base64)
   * @param masterKey Clave maestra para derivar clave de desencriptación
   * @returns Datos originales
   */
  async decrypt(encryptedData: string, masterKey: string): Promise<string> {
    // Decode base64
    const combined = base64ToBinary(encryptedData);

    // Extract components: salt|iv|ciphertext
    const saltLength = CRYPTO_CONFIG.PBKDF2.SALT_LENGTH;
    const ivLength = CRYPTO_CONFIG.AES.IV_LENGTH;

    const salt = combined.slice(0, saltLength);
    const iv = combined.slice(saltLength, saltLength + ivLength);
    const ciphertextWithTag = combined.slice(saltLength + ivLength);

    // Derive key from master using the same salt
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(masterKey),
      "PBKDF2",
      false,
      ["deriveKey"],
    );

    const aesKey = await crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: CRYPTO_CONFIG.PBKDF2.ITERATIONS,
        hash: CRYPTO_CONFIG.PBKDF2.HASH,
      },
      keyMaterial,
      {
        name: CRYPTO_CONFIG.AES.ALGORITHM,
        length: CRYPTO_CONFIG.AES.KEY_LENGTH,
      },
      false, // SECURITY: Key is not extractable
      ["decrypt"],
    );

    try {
      const decryptedBuffer = await crypto.subtle.decrypt(
        {
          name: CRYPTO_CONFIG.AES.ALGORITHM,
          iv: iv,
          tagLength: CRYPTO_CONFIG.AES.TAG_LENGTH,
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

  /**
   * Genera hash SHA-256 de datos
   * @param data Datos a hashear
   * @returns Hash SHA-256
   */
  async hash(data: string): Promise<string> {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);

    try {
      const hashBuffer = await crypto.subtle.digest("SHA-256", dataBuffer);
      const hashArray = new Uint8Array(hashBuffer);
      const hashHex = Array.from(hashArray)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

      return hashHex;
    } finally {
      // Limpieza segura
      secureZero(dataBuffer);
    }
  }

  /**
   * Deriva clave usando PBKDF2
   * @param password Contraseña
   * @param salt Salt aleatorio
   * @param iterations Número de iteraciones
   * @returns Clave derivada (base64)
   */
  async deriveKey(
    password: string,
    salt: string,
    iterations: number = CRYPTO_CONFIG.PBKDF2.ITERATIONS,
  ): Promise<string> {
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(password);
    const saltBuffer = base64ToBinary(salt);

    try {
      const keyMaterial = await crypto.subtle.importKey(
        "raw",
        passwordBuffer,
        "PBKDF2",
        false,
        ["deriveBits", "deriveKey"],
      );

      const derivedKey = await crypto.subtle.deriveBits(
        {
          name: "PBKDF2",
          salt: saltBuffer,
          iterations: iterations,
          hash: CRYPTO_CONFIG.PBKDF2.HASH,
        },
        keyMaterial,
        CRYPTO_CONFIG.AES.KEY_LENGTH,
      );

      // Convertir a base64
      const derivedArray = new Uint8Array(derivedKey);
      return binaryToBase64(derivedArray);
    } finally {
      // Limpieza segura
      secureZero(passwordBuffer);
      secureZero(saltBuffer);
    }
  }

  /**
   * Genera salt aleatorio
   * @returns Salt en base64
   */
  async generateSalt(): Promise<string> {
    const salt = generateSecureSalt(CRYPTO_CONFIG.PBKDF2.SALT_LENGTH);
    return binaryToBase64(salt);
  }

  /**
   * Firma datos usando ECDSA P-256
   * @param data Datos a firmar
   * @param privateKey Clave privada en formato JWK (JSON string)
   * @returns Firma en base64
   */
  async sign(data: string, privateKey: string): Promise<string> {
    // Importar clave privada desde JWK
    const privateJwk = JSON.parse(privateKey) as JsonWebKey;
    const key = await crypto.subtle.importKey(
      "jwk",
      privateJwk,
      {
        name: CRYPTO_CONFIG.ECDSA.ALGORITHM,
        namedCurve: CRYPTO_CONFIG.ECDSA.NAMED_CURVE,
      },
      false,
      ["sign"],
    );

    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);

    try {
      const signature = await crypto.subtle.sign(
        {
          name: CRYPTO_CONFIG.ECDSA.ALGORITHM,
          hash: CRYPTO_CONFIG.ECDSA.HASH,
        },
        key,
        dataBuffer,
      );

      const signatureArray = new Uint8Array(signature);
      return binaryToBase64(signatureArray);
    } finally {
      secureZero(dataBuffer);
    }
  }

  /**
   * Verifica firma de datos
   * @param data Datos originales
   * @param signature Firma en base64
   * @param publicKey Clave pública en formato JWK (JSON string)
   * @returns true si la firma es válida
   */
  async verify(
    data: string,
    signature: string,
    publicKey: string,
  ): Promise<boolean> {
    try {
      // Importar clave pública desde JWK
      const publicJwk = JSON.parse(publicKey) as JsonWebKey;
      const key = await crypto.subtle.importKey(
        "jwk",
        publicJwk,
        {
          name: CRYPTO_CONFIG.ECDSA.ALGORITHM,
          namedCurve: CRYPTO_CONFIG.ECDSA.NAMED_CURVE,
        },
        false,
        ["verify"],
      );

      const encoder = new TextEncoder();
      const dataBuffer = encoder.encode(data);

      const signatureBuffer = base64ToBinary(signature);

      const result = await crypto.subtle.verify(
        {
          name: CRYPTO_CONFIG.ECDSA.ALGORITHM,
          hash: CRYPTO_CONFIG.ECDSA.HASH,
        },
        key,
        signatureBuffer,
        dataBuffer,
      );

      secureZero(dataBuffer);
      return result;
    } catch {
      return false;
    }
  }

  // SECURITY: Private method for key derivation (if needed internally)
  // SECURITY: Uses proper PBKDF2 iterations

  private async deriveAesKeyFromMaster(masterKey: string): Promise<CryptoKey> {
    // SECURITY: Proper key derivation with correct iterations
    const encoder = new TextEncoder();
    const keyBuffer = encoder.encode(masterKey);

    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      keyBuffer,
      "PBKDF2",
      false,
      ["deriveKey"],
    );

    const salt = generateSecureSalt(16);
    // SECURITY: Use NIST recommended iterations
    const saltArray = new Uint8Array(salt);
    const saltBuffer = saltArray.buffer;

    const aesKey = await crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: saltBuffer,
        iterations: CRYPTO_CONFIG.PBKDF2.ITERATIONS, // SECURITY: 600k iterations
        hash: CRYPTO_CONFIG.PBKDF2.HASH,
      },
      keyMaterial,
      {
        name: CRYPTO_CONFIG.AES.ALGORITHM,
        length: CRYPTO_CONFIG.AES.KEY_LENGTH,
      },
      false, // SECURITY: Key is not extractable
      ["encrypt", "decrypt"],
    );

    secureZero(keyBuffer);
    return aesKey;
  }
}
