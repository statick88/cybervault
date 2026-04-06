// @ts-nocheck

/**
 * Signature Service Implementation
 * Implementación del servicio de firmas digitales usando ECDSA P-256
 */

import { binaryToBase64, base64ToBinary } from "@/shared/utils";
import { secureZero } from "./secure-memory";

/**
 * Constantes de configuración ECDSA
 */
const ECDSA_CONFIG = {
  ALGORITHM: "ECDSA",
  NAMED_CURVE: "P-256",
  HASH: "SHA-256",
} as const;

/**
 * Servicio de firmas digitales
 * Provee funcionalidad para firmar y verificar datos usando ECDSA
 */
export class SignatureService {
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
        name: ECDSA_CONFIG.ALGORITHM,
        namedCurve: ECDSA_CONFIG.NAMED_CURVE,
      },
      false,
      ["sign"],
    );

    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);

    try {
      const signature = await crypto.subtle.sign(
        {
          name: ECDSA_CONFIG.ALGORITHM,
          hash: ECDSA_CONFIG.HASH,
        },
        key,
        dataBuffer,
      );

      const signatureArray = new Uint8Array(signature);
      return binaryToBase64(signatureArray);
    } finally {
      // Limpieza segura del buffer de datos
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
          name: ECDSA_CONFIG.ALGORITHM,
          namedCurve: ECDSA_CONFIG.NAMED_CURVE,
        },
        false,
        ["verify"],
      );

      const encoder = new TextEncoder();
      const dataBuffer = encoder.encode(data);

      const signatureBuffer = base64ToBinary(signature);

      const result = await crypto.subtle.verify(
        {
          name: ECDSA_CONFIG.ALGORITHM,
          hash: ECDSA_CONFIG.HASH,
        },
        key,
        signatureBuffer,
        dataBuffer,
      );

      // Limpieza segura del buffer de datos
      secureZero(dataBuffer);

      return result;
    } catch {
      return false;
    }
  }
}
