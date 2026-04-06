/**
 * Key Management Service
 * Gestión de claves criptográficas: generación, almacenamiento, rotación
 */

export class KeyManagementService {
  /**
   * Genera par de claves asimétricas (ECDSA P-256)
   * @returns Par de claves en formato JWK
   */
  async generateKeyPair(): Promise<{ publicKey: string; privateKey: string }> {
    const keyPair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign", "verify"],
    );

    const publicJwk = await crypto.subtle.exportKey("jwk", keyPair.publicKey);
    const privateJwk = await crypto.subtle.exportKey("jwk", keyPair.privateKey);

    return {
      publicKey: JSON.stringify(publicJwk),
      privateKey: JSON.stringify(privateJwk),
    };
  }
}
