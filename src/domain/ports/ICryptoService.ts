export interface EncryptedPayload {
  readonly ciphertext: Uint8Array;
  readonly nonce: Uint8Array;
  readonly authTag: Uint8Array;
  readonly algorithm: 'AES-256-GCM' | 'ChaCha20-Poly1305';
  readonly keyId: string;
  readonly aad?: Uint8Array;
}

export interface SignedPayload {
  readonly data: Uint8Array;
  readonly signature: Uint8Array;
  readonly algorithm: 'ECDSA-P256-SHA256';
  readonly keyId: string;
}

export interface ICryptoService {
  generateX25519KeyPair(): Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }>;
  deriveSharedSecret(privateKey: Uint8Array, peerPublicKey: Uint8Array): Promise<Uint8Array>;
  deriveKeyPBKDF2(password: Uint8Array, salt: Uint8Array, opts?: { mem?: number; iter?: number; parallelism?: number }): Promise<Uint8Array>;
  encryptAES256GCM(key: Uint8Array, plaintext: Uint8Array, aad?: Uint8Array): Promise<EncryptedPayload>;
  decryptAES256GCM(key: Uint8Array, payload: EncryptedPayload): Promise<Uint8Array>;
  encryptChaCha20Poly1305(key: Uint8Array, plaintext: Uint8Array, aad?: Uint8Array): Promise<EncryptedPayload>;
  decryptChaCha20Poly1305(key: Uint8Array, payload: EncryptedPayload): Promise<Uint8Array>;
  generateECDSAP256KeyPair(): Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }>;
  signECDSAP256(privateKey: Uint8Array, data: Uint8Array): Promise<SignedPayload>;
  verifyECDSAP256(publicKey: Uint8Array, payload: SignedPayload): Promise<boolean>;
  randomBytes(length: number): Uint8Array;
  constantTimeEquals(a: Uint8Array, b: Uint8Array): boolean;
}