/**
 * Encryption Service
 * Wrapper para operaciones de encriptación using encryption-service functions
 */

import { encrypt, decrypt } from "./encryption-service";

export class EncryptionService {
  /**
   * Encripta datos usando AES-GCM-256 con derivación de clave PBKDF2
   * @param data Datos a encriptar
   * @param masterKey Clave maestra (usada para derivar clave de encriptación)
   * @returns Datos encriptados en formato: salt|iv|ciphertext (base64)
   */
  async encrypt(data: string, masterKey: string): Promise<string> {
    return encrypt(data, masterKey);
  }

  /**
   * Desencripta datos usando AES-GCM-256 con derivación de clave PBKDF2
   * @param encryptedData Datos encriptados en formato: salt|iv|ciphertext (base64)
   * @param masterKey Clave maestra para derivar clave de desencriptación
   * @returns Datos originales
   */
  async decrypt(encryptedData: string, masterKey: string): Promise<string> {
    return decrypt(encryptedData, masterKey);
  }
}
