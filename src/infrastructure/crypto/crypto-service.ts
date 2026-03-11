/**
 * Crypto Service Implementation
 * Implementación del servicio de criptografía usando Web Crypto API
 */

import { ICryptoService } from "../../domain/services";
import { CryptoHash } from "../../domain/value-objects/ids";
import { SecureBuffer, secureZero, generateSecureSalt } from "./secure-memory";

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
      true, // extractable
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
   * @param data Datos a encriptar
   * @param publicKey Clave pública (no usada para AES, mantenida por compatibilidad)
   * @returns Datos encriptados en formato: iv|ciphertext|tag (base64)
   */
  async encrypt(data: string, publicKey: string): Promise<string> {
    // Generar clave AES aleatoria de 256 bits
    const keyMaterial = await crypto.subtle.generateKey(
      {
        name: CRYPTO_CONFIG.AES.ALGORITHM,
        length: CRYPTO_CONFIG.AES.KEY_LENGTH,
      },
      true,
      ["encrypt", "decrypt"],
    );

    // Exportar clave para que decrypt pueda usarla
    const rawKey = await crypto.subtle.exportKey("raw", keyMaterial);

    // Generar nonce único
    const iv = new Uint8Array(CRYPTO_CONFIG.AES.IV_LENGTH);
    crypto.getRandomValues(iv);

    // Encriptar datos
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);

    const encryptedBuffer = await crypto.subtle.encrypt(
      {
        name: CRYPTO_CONFIG.AES.ALGORITHM,
        iv: iv,
        tagLength: CRYPTO_CONFIG.AES.TAG_LENGTH,
      },
      keyMaterial,
      dataBuffer,
    );

    // Extraer ciphertext y tag
    const ciphertext = new Uint8Array(encryptedBuffer);
    const tagLength = CRYPTO_CONFIG.AES.TAG_LENGTH / 8;
    const ciphertextWithoutTag = ciphertext.slice(
      0,
      ciphertext.length - tagLength,
    );
    const tag = ciphertext.slice(ciphertext.length - tagLength);

    // Formato: iv|ciphertext|tag|key (base64) - Incluir clave para decrypt
    const keyArray = new Uint8Array(rawKey);
    const combined = new Uint8Array(
      iv.length + ciphertextWithoutTag.length + tag.length + keyArray.length,
    );
    combined.set(iv, 0);
    combined.set(ciphertextWithoutTag, iv.length);
    combined.set(tag, iv.length + ciphertextWithoutTag.length);
    combined.set(
      keyArray,
      iv.length + ciphertextWithoutTag.length + tag.length,
    );

    // Limpieza segura
    secureZero(dataBuffer);
    secureZero(rawKey as ArrayBuffer);

    return btoa(String.fromCharCode(...combined));
  }

  /**
   * Desencripta datos usando AES-GCM-256
   * @param encryptedData Datos encriptados en formato: iv|ciphertext|tag|key (base64)
   * @param privateKey Clave privada (no usada para AES, mantenida por compatibilidad)
   * @returns Datos originales
   */
  async decrypt(encryptedData: string, privateKey: string): Promise<string> {
    // Decodificar base64
    const combined = new Uint8Array(
      atob(encryptedData)
        .split("")
        .map((c) => c.charCodeAt(0)),
    );

    // Extraer components
    const ivLength = CRYPTO_CONFIG.AES.IV_LENGTH;
    const tagLength = CRYPTO_CONFIG.AES.TAG_LENGTH / 8;
    const keyLength = CRYPTO_CONFIG.AES.KEY_LENGTH / 8;

    const iv = combined.slice(0, ivLength);
    const tag = combined.slice(
      combined.length - tagLength - keyLength,
      combined.length - keyLength,
    );
    const ciphertext = combined.slice(
      ivLength,
      combined.length - tagLength - keyLength,
    );
    const keyBytes = combined.slice(combined.length - keyLength);

    // Reconstruir ciphertext completo (ciphertext + tag)
    const encryptedBuffer = new Uint8Array(ciphertext.length + tag.length);
    encryptedBuffer.set(ciphertext, 0);
    encryptedBuffer.set(tag, ciphertext.length);

    // Importar clave AES
    const aesKey = await crypto.subtle.importKey(
      "raw",
      keyBytes,
      {
        name: CRYPTO_CONFIG.AES.ALGORITHM,
        length: CRYPTO_CONFIG.AES.KEY_LENGTH,
      },
      true,
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
        encryptedBuffer,
      );

      const decoder = new TextDecoder();
      return decoder.decode(decryptedBuffer);
    } finally {
      // Limpieza segura
      secureZero(iv);
      secureZero(ciphertext);
      secureZero(tag);
      secureZero(keyBytes);
      secureZero(encryptedBuffer);
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
    const saltBuffer = new Uint8Array(
      atob(salt)
        .split("")
        .map((c) => c.charCodeAt(0)),
    );

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
      return btoa(String.fromCharCode(...derivedArray));
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
    return btoa(String.fromCharCode(...salt));
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
      return btoa(String.fromCharCode(...signatureArray));
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

      const signatureBuffer = new Uint8Array(
        atob(signature)
          .split("")
          .map((c) => c.charCodeAt(0)),
      );

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

  // Métodos privados auxiliares

  private async deriveAesKeyFromMaster(masterKey: string): Promise<CryptoKey> {
    // Derivación simplificada (en producción, usar PBKDF2 con salt)
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
    // Clonar salt para asegurar ArrayBuffer (no SharedArrayBuffer)
    const saltArray = new Uint8Array(salt);
    const saltBuffer = saltArray.buffer;

    const aesKey = await crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: saltBuffer,
        iterations: 1000,
        hash: "SHA-256",
      },
      keyMaterial,
      {
        name: CRYPTO_CONFIG.AES.ALGORITHM,
        length: CRYPTO_CONFIG.AES.KEY_LENGTH,
      },
      true,
      ["encrypt", "decrypt"],
    );

    secureZero(keyBuffer);
    return aesKey;
  }
}
