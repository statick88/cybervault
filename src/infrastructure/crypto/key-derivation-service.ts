// Key Derivation Service
// Servicio para derivar claves usando PBKDF2 + HKDF
//
// Cadena de derivación (esquema v2):
//   1. PBKDF2-SHA512(passphrase, salt, 600000) -> secreto maestro de 512 bits
//      (NUNCA se persiste, solo se usa como IKM).
//   2. HKDF-SHA256(secreto maestro, salt, info) -> salida de 256 bits.
//
// El `info` de HKDF es el parámetro de separación de contexto: es real, a
// diferencia del `info` que se pasaba a PBKDF2 en el esquema anterior (PBKDF2
// no tiene ese campo y lo ignoraba silenciosamente, con el resultado de que el
// verificador persistido era exactamente el prefijo de la session key).
//
// Cada propósito usa una etiqueta distinta:
//   - verificador persistido : cybervault|master_key_verify|v2
//   - session key efímera    : cybervault|session_key|v2
// Dado que HKDF es un PRF bajo la etiqueta, ambas salidas son independientes:
// conocer el verificador no revela la session key ni ningún otro material de
// clave, y ninguna de ellas es un prefijo/sufijo/subcadena de la otra.

import { secureZero } from "./secure-memory";
import { binaryToBase64 } from "../../shared/utils";

/**
 * Configuración de derivación de claves
 */
export const KEY_DERIVATION_CONFIG = {
  /** PBKDF2 estira la contraseña hasta el secreto maestro. */
  ALGORITHM: "PBKDF2" as const,
  HASH: "SHA-512",
  ITERATIONS: 600000,
  SALT_LENGTH: 32, // 256-bit salt (para master key)
  /** Longitud del secreto maestro (512 bits, jamás persistido). */
  MASTER_SECRET_BITS: 512,
  /** HKDF sí tiene campo `info`; es lo que separa verificador de session key. */
  HKDF_ALGORITHM: "HKDF" as const,
  HKDF_HASH: "SHA-256",
  /** Longitud de verificador y session key (256 bits / 32 bytes). */
  OUTPUT_BITS: 256,
  /** Identificador de esquema persistido junto al verificador. */
  SCHEME: "hkdf-sha256-v2",
  VERIFIER_INFO: "cybervault|master_key_verify|v2",
  SESSION_KEY_INFO: "cybervault|session_key|v2",
  DEFAULT_INFO: "cybervault|derive_key|v2",
} as const;

/**
 * Prefijo auto-descriptivo del verificador persistido.
 *
 * Un valor en `master_key_verify` que no empieza por este prefijo fue escrito
 * por un esquema anterior y debe rechazarse de forma explícita (no interpretarse
 * como "contraseña incorrecta").
 */
export const VERIFIER_SCHEME_PREFIX = `${KEY_DERIVATION_CONFIG.SCHEME}$`;

/** Convierte un Uint8Array en ArrayBuffer para Web Crypto API */
function toArrayBuffer(data: Uint8Array): ArrayBuffer {
  const buf = new ArrayBuffer(data.byteLength);
  new Uint8Array(buf).set(data);
  return buf;
}

/**
 * HKDF-SHA256 con `info` real (RFC 5869).
 *
 * Este es el único punto del esquema donde una etiqueta de contexto tiene
 * efecto sobre la salida; PBKDF2 no acepta `info`.
 */
async function hkdfDerive(
  inputKeyMaterial: Uint8Array,
  salt: Uint8Array,
  info: string,
  lengthBits: number,
): Promise<Uint8Array> {
  const ikmBuffer = toArrayBuffer(inputKeyMaterial);
  try {
    const baseKey = await crypto.subtle.importKey(
      "raw",
      ikmBuffer,
      { name: KEY_DERIVATION_CONFIG.HKDF_ALGORITHM },
      false,
      ["deriveBits"],
    );

    const derivedBits = await crypto.subtle.deriveBits(
      {
        name: KEY_DERIVATION_CONFIG.HKDF_ALGORITHM,
        hash: KEY_DERIVATION_CONFIG.HKDF_HASH,
        salt: toArrayBuffer(salt),
        info: toArrayBuffer(new TextEncoder().encode(info)),
      },
      baseKey,
      lengthBits,
    );

    return new Uint8Array(derivedBits);
  } finally {
    secureZero(ikmBuffer);
  }
}

/**
 * Servicio para derivación de claves criptográficas
 */
export class KeyDerivationService {
  /**
   * Deriva una clave usando PBKDF2 (estiramiento) + HKDF (contexto).
   *
   * El `info` determina la salida: dos etiquetas distintas producen salidas
   * independientes aunque todos los demás inputs sean idénticos.
   *
   * @param password Contraseña o passphrase
   * @param salt Salt aleatorio por bóveda
   * @param iterations Iteraciones de PBKDF2
   * @param keyLength Longitud de salida en bits
   * @param info Etiqueta de contexto HKDF (opcional; usa una por defecto)
   * @returns Clave en base64
   */
  async deriveKey(
    password: string,
    salt: Uint8Array,
    iterations: number = KEY_DERIVATION_CONFIG.ITERATIONS,
    keyLength: number = KEY_DERIVATION_CONFIG.OUTPUT_BITS,
    info?: string,
  ): Promise<string> {
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(password);

    let masterSecret: Uint8Array | undefined;
    try {
      const keyMaterial = await crypto.subtle.importKey(
        "raw",
        passwordBuffer as BufferSource,
        KEY_DERIVATION_CONFIG.ALGORITHM,
        false,
        ["deriveBits"],
      );

      const derivedBits = await crypto.subtle.deriveBits(
        {
          name: KEY_DERIVATION_CONFIG.ALGORITHM,
          salt: toArrayBuffer(salt),
          iterations: iterations,
          hash: KEY_DERIVATION_CONFIG.HASH,
        },
        keyMaterial,
        KEY_DERIVATION_CONFIG.MASTER_SECRET_BITS,
      );
      masterSecret = new Uint8Array(derivedBits);

      const derived = await hkdfDerive(
        masterSecret,
        salt,
        info ?? KEY_DERIVATION_CONFIG.DEFAULT_INFO,
        keyLength,
      );
      return binaryToBase64(derived);
    } finally {
      secureZero(passwordBuffer);
      if (masterSecret) {
        secureZero(masterSecret);
      }
    }
  }

  /**
   * Deriva el verificador de la master key que se PERSISTE (256 bits).
   *
   * No es, no contiene y no revela ninguna clave de cifrado: es la salida de
   * HKDF bajo la etiqueta `cybervault|master_key_verify|v2`, independiente de
   * la session key derivada bajo otra etiqueta con el mismo secreto maestro.
   */
  async deriveVerificationHash(
    masterKey: string,
    salt: Uint8Array,
  ): Promise<string> {
    return this.deriveKey(
      masterKey,
      salt,
      KEY_DERIVATION_CONFIG.ITERATIONS,
      KEY_DERIVATION_CONFIG.OUTPUT_BITS,
      KEY_DERIVATION_CONFIG.VERIFIER_INFO,
    );
  }

  /**
   * Deriva la session key (256 bits) con la etiqueta de contexto propia.
   * Vive solo en chrome.storage.session.
   */
  async deriveSessionKey(masterKey: string, salt: Uint8Array): Promise<string> {
    return this.deriveKey(
      masterKey,
      salt,
      KEY_DERIVATION_CONFIG.ITERATIONS,
      KEY_DERIVATION_CONFIG.OUTPUT_BITS,
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
