// Key Derivation Service
// Servicio para derivar claves usando PBKDF2

import { secureZero } from "./secure-memory";
import { binaryToBase64 } from "@/shared/utils";

/**
 * Configuración de derivación de claves
 */
const KEY_DERIVATION_CONFIG = {
  ALGORITHM: "PBKDF2" as const,
  HASH: "SHA-512",
  ITERATIONS: 600000,
  SALT_LENGTH: 32, // 256-bit salt (para master key)
  SESSION_KEY_INFO: "cybervault_session_key_v1",
} as const;

/**
 * Servicio para derivación de claves criptográficas
 */
export class KeyDerivationService {
  /**
   * Deriva una clave desde una contraseña usando PBKDF2
   * Devuelve la clave en base64
   */
  async deriveKey(
    password: string,
    salt: Uint8Array,
    iterations: number = KEY_DERIVATION_CONFIG.ITERATIONS,
    keyLength: number = 256,
    info?: string,
  ): Promise<string> {
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(password);

    try {
      const keyMaterial = await crypto.subtle.importKey(
        "raw",
        passwordBuffer as BufferSource,
        KEY_DERIVATION_CONFIG.ALGORITHM,
        false,
        ["deriveBits", "deriveKey"],
      );

      // Si hay info, derivar clave (para session key)
      if (info) {
        const derivedKey = await crypto.subtle.deriveKey(
          {
            name: KEY_DERIVATION_CONFIG.ALGORITHM,
            salt: salt as unknown as BufferSource,
            iterations: iterations,
            hash: KEY_DERIVATION_CONFIG.HASH,
            info: encoder.encode(info),
          },
          keyMaterial,
          { name: "AES-GCM", length: keyLength },
          true, // Extractable (necesario para exportar)
          ["encrypt", "decrypt"],
        );

        const exported = await crypto.subtle.exportKey("raw", derivedKey);
        const derivedArray = new Uint8Array(exported);
        return binaryToBase64(derivedArray);
      }

      // Si no hay info, derivar bits (para hash de verificación)
      const derivedBits = await crypto.subtle.deriveBits(
        {
          name: KEY_DERIVATION_CONFIG.ALGORITHM,
          salt: salt as unknown as BufferSource,
          iterations: iterations,
          hash: KEY_DERIVATION_CONFIG.HASH,
        },
        keyMaterial,
        keyLength,
      );

      const derivedArray = new Uint8Array(derivedBits);
      return binaryToBase64(derivedArray);
    } finally {
      secureZero(passwordBuffer);
    }
  }

  /**
   * Deriva clave para verificación de master key (512 bits, sin info)
   */
  async deriveVerificationHash(
    masterKey: string,
    salt: Uint8Array,
  ): Promise<string> {
    return this.deriveKey(masterKey, salt, undefined, 512);
  }

  /**
   * Deriva session key desde master key (256 bits, con info)
   */
  async deriveSessionKey(masterKey: string, salt: Uint8Array): Promise<string> {
    return this.deriveKey(
      masterKey,
      salt,
      undefined,
      256,
      KEY_DERIVATION_CONFIG.SESSION_KEY_INFO,
    );
  }

  /**
   * Genera salt aleatorio para derivación
   */
  generateSalt(length: number = KEY_DERIVATION_CONFIG.SALT_LENGTH): Uint8Array {
    const salt = new Uint8Array(length);
    crypto.getRandomValues(salt);
    return salt;
  }
}

// Exportar instancia singleton para uso común
export const keyDerivationService = new KeyDerivationService();
