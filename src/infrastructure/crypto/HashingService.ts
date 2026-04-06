/**
 * Hashing Service Implementation
 * Servicio independiente para hashing SHA-256
 */

import { secureZero } from "./secure-memory";

/**
 * Servicio para operaciones de hashing criptográfico
 */
export class HashingService {
  /**
   * Genera hash SHA-256 de datos
   * @param data Datos a hashear
   * @returns Hash SHA-256 en formato hexadecimal
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
      // Limpieza segura del buffer temporal
      secureZero(dataBuffer);
    }
  }
}
