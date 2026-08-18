import type { ICryptoService, EncryptedPayload, SignedPayload } from '../../domain/ports/ICryptoService';

export class KeyExchangeService implements ICryptoService {
  private readonly subtle = globalThis.crypto.subtle;

  async generateX25519KeyPair(): Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }> {
    const keyPair = await this.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'X25519' },
      true,
      ['deriveBits', 'deriveKey']
    );

    const publicKey = new Uint8Array(await this.subtle.exportKey('raw', keyPair.publicKey));
    const privateKey = new Uint8Array(await this.subtle.exportKey('pkcs8', keyPair.privateKey));

    return { publicKey, privateKey };
  }

  async deriveSharedSecret(privateKey: Uint8Array, peerPublicKey: Uint8Array): Promise<Uint8Array> {
    const privKey = await this.subtle.importKey('pkcs8', this.toArrayBuffer(privateKey), { name: 'ECDH', namedCurve: 'X25519' }, false, ['deriveBits']);
    const pubKey = await this.subtle.importKey('raw', this.toArrayBuffer(peerPublicKey), { name: 'ECDH', namedCurve: 'X25519' }, false, []);

    const sharedSecret = await this.subtle.deriveBits({ name: 'ECDH', public: pubKey }, privKey, 256);
    return new Uint8Array(sharedSecret);
  }

  async deriveKeyPBKDF2(
    password: Uint8Array,
    salt: Uint8Array,
    opts: { mem?: number; iter?: number; parallelism?: number } = {}
  ): Promise<Uint8Array> {
    const { iter = 3 } = opts;

    const key = await this.subtle.importKey('raw', this.toArrayBuffer(password), 'PBKDF2', false, ['deriveBits']);
    const derived = await this.subtle.deriveBits(
      {
        name: 'PBKDF2',
        hash: 'SHA-512',
        salt: this.toArrayBuffer(salt),
        iterations: iter * 100000
      },
      key,
      256
    );

    return new Uint8Array(derived);
  }

  async encryptAES256GCM(key: Uint8Array, plaintext: Uint8Array, aad?: Uint8Array): Promise<EncryptedPayload> {
    const cryptoKey = await this.subtle.importKey('raw', this.toArrayBuffer(key), { name: 'AES-GCM' }, false, ['encrypt']);
    const nonce = this.randomBytes(12);

    const encryptParams: AesGcmParams = { name: 'AES-GCM', iv: this.toArrayBuffer(nonce), tagLength: 128 };
    if (aad) (encryptParams as any).additionalData = this.toArrayBuffer(aad);
    const ciphertextWithTag = await this.subtle.encrypt(encryptParams, cryptoKey, this.toArrayBuffer(plaintext));

    const ciphertext = new Uint8Array(ciphertextWithTag);
    const authTag = ciphertext.slice(-16);
    const actualCiphertext = ciphertext.slice(0, -16);

    return {
      ciphertext: actualCiphertext,
      nonce,
      authTag,
      algorithm: 'AES-256-GCM',
      keyId: this.bytesToHex(this.randomBytes(8))
    };
  }

  async decryptAES256GCM(key: Uint8Array, payload: EncryptedPayload): Promise<Uint8Array> {
    const cryptoKey = await this.subtle.importKey('raw', this.toArrayBuffer(key), { name: 'AES-GCM' }, false, ['decrypt']);

    const ciphertextWithTag = new Uint8Array(payload.ciphertext.length + payload.authTag.length);
    ciphertextWithTag.set(payload.ciphertext);
    ciphertextWithTag.set(payload.authTag, payload.ciphertext.length);

    const decryptParams: any = { name: 'AES-GCM', iv: this.toArrayBuffer(payload.nonce), tagLength: 128 };
    if (payload.aad) decryptParams.additionalData = this.toArrayBuffer(payload.aad);
    const plaintext = await this.subtle.decrypt(decryptParams, cryptoKey, ciphertextWithTag.buffer);

    return new Uint8Array(plaintext);
  }

  async encryptChaCha20Poly1305(key: Uint8Array, plaintext: Uint8Array, aad?: Uint8Array): Promise<EncryptedPayload> {
    const { chacha20poly1305 } = await import('@noble/ciphers/chacha');

    const nonce = this.randomBytes(12);
    const cipher = chacha20poly1305(key, nonce, aad);
    const ciphertextWithTag = cipher.encrypt(plaintext);
    const authTag = ciphertextWithTag.slice(-16);
    const ciphertext = ciphertextWithTag.slice(0, -16);

    return {
      ciphertext,
      nonce,
      authTag,
      algorithm: 'ChaCha20-Poly1305',
      keyId: this.bytesToHex(this.randomBytes(8))
    };
  }

  async decryptChaCha20Poly1305(key: Uint8Array, payload: EncryptedPayload): Promise<Uint8Array> {
    const { chacha20poly1305 } = await import('@noble/ciphers/chacha');

    const ciphertextWithTag = new Uint8Array(payload.ciphertext.length + payload.authTag.length);
    ciphertextWithTag.set(payload.ciphertext);
    ciphertextWithTag.set(payload.authTag, payload.ciphertext.length);
    const cipher = chacha20poly1305(key, payload.nonce);
    return cipher.decrypt(ciphertextWithTag);
  }

  async generateECDSAP256KeyPair(): Promise<{ publicKey: Uint8Array; privateKey: Uint8Array }> {
    const keyPair = await this.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );

    const publicKey = new Uint8Array(await this.subtle.exportKey('raw', keyPair.publicKey));
    const privateKey = new Uint8Array(await this.subtle.exportKey('pkcs8', keyPair.privateKey));

    return { publicKey, privateKey };
  }

  async signECDSAP256(privateKey: Uint8Array, data: Uint8Array): Promise<SignedPayload> {
    const key = await this.subtle.importKey('pkcs8', this.toArrayBuffer(privateKey), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
    const signature = await this.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, this.toArrayBuffer(data));

    return {
      data,
      signature: new Uint8Array(signature),
      algorithm: 'ECDSA-P256-SHA256',
      keyId: this.bytesToHex(this.randomBytes(8))
    };
  }

  async verifyECDSAP256(publicKey: Uint8Array, payload: SignedPayload): Promise<boolean> {
    const key = await this.subtle.importKey('raw', this.toArrayBuffer(publicKey), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    return this.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, this.toArrayBuffer(payload.signature), this.toArrayBuffer(payload.data));
  }

  randomBytes(length: number): Uint8Array {
    const bytes = new Uint8Array(length);
    globalThis.crypto.getRandomValues(bytes);
    return bytes;
  }

  constantTimeEquals(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }
    return result === 0;
  }

  private toArrayBuffer(data: Uint8Array): ArrayBuffer {
    const buf = new ArrayBuffer(data.byteLength);
    new Uint8Array(buf).set(data);
    return buf;
  }

  private bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  }
}