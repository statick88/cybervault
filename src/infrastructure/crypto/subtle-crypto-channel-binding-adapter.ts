/**
 * Subtle Crypto Channel Binding Adapter
 * Implements IChannelBindingProtocol using Web Crypto API (crypto.subtle)
 * Provides cryptographic channel binding for AiTM defense
 */

import type { IChannelBindingProtocol, ChannelBindingContext, BindingKey } from "../../domain/ports/interfaces/i-channel-binding-protocol";
import { BindingSignature } from "../../domain/value-objects/binding-signature";
import { getSessionKey } from "./master-key-manager";
import { secureZero } from "./secure-memory";

const BINDING_CONFIG = {
  HKDF_HASH: 'SHA-256' as const,
  HMAC_HASH: 'SHA-256' as const,
  HMAC_ALGORITHM: { name: 'HMAC', hash: 'SHA-256' as const },
  NONCE_LENGTH: 32, // bytes
  KEY_LENGTH: 32, // bytes (256-bit for HMAC-SHA256)
  HKDF_INFO_PREFIX: 'cybervault-channel-binding',
  ALGORITHM: 'HMAC-SHA256' as const,
} as const;

export interface SubtleCryptoLike {
  subtle: Crypto['subtle'];
  getRandomValues: Crypto['getRandomValues'];
}

export class SubtleCryptoChannelBindingAdapter implements IChannelBindingProtocol {
  private readonly subtle: SubtleCrypto;
  private readonly getRandomValues: (array: Uint8Array) => Uint8Array;

  /**
   * Creates a new SubtleCryptoChannelBindingAdapter
   * @param cryptoProvider Optional crypto provider (defaults to globalThis.crypto)
   *                       Useful for testing with mocked crypto
   */
  constructor(cryptoProvider: SubtleCryptoLike = globalThis.crypto) {
    this.subtle = cryptoProvider.subtle;
    this.getRandomValues = cryptoProvider.getRandomValues.bind(cryptoProvider);
  }

  /**
   * Sign a channel binding for the given context
   * Uses HKDF-SHA256 to derive binding key from session key + domain + timestamp
   * Then creates HMAC-SHA256 signature
   */
  async signChannelBinding(context: ChannelBindingContext): Promise<BindingSignature> {
    // Validate context
    this.validateContext(context);

    // Get session key from MasterKeyManager
    const sessionKey = getSessionKey();
    if (!sessionKey) {
      throw new Error('No active session key available. Vault must be unlocked.');
    }

    // Derive binding key using HKDF-SHA256
    const bindingKey = await this.deriveBindingKey(sessionKey, context.domain, context.timestamp);

    // Create message to sign: domain|timestamp|nonce
    const message = this.createSigningMessage(context);

    // Generate HMAC-SHA256 signature
    const signature = await this.computeHMAC(bindingKey.key, message);

    // Convert to base64
    const signatureB64 = this.toBase64(signature);
    const nonceB64 = this.toBase64(context.nonce);

    // Clean up sensitive key material
    secureZero(bindingKey.key);

    return BindingSignature.create(
      context.domain,
      context.timestamp,
      nonceB64,
      signatureB64
    );
  }

  /**
   * Verify a channel binding signature
   * Validates signature, timestamp, domain, and nonce
   */
  async verifyChannelBinding(
    signature: BindingSignature,
    context: ChannelBindingContext
  ): Promise<boolean> {
    try {
      // Validate context
      this.validateContext(context);

      // Check domain matches
      if (signature.domain !== context.domain.toLowerCase().trim()) {
        return false;
      }

      // Check timestamp is within acceptable window
      if (!signature.isValid(context.timestamp)) {
        return false;
      }

      // Get session key
      const sessionKey = getSessionKey();
      if (!sessionKey) {
        return false;
      }

      // Derive binding key
      const bindingKey = await this.deriveBindingKey(sessionKey, context.domain, context.timestamp);

      // Create message to verify
      const message = this.createSigningMessage(context);

      // Compute expected HMAC
      const expectedSignature = await this.computeHMAC(bindingKey.key, message);

      // Convert provided signature to Uint8Array for comparison
      const providedSignature = this.fromBase64(signature.signature);

      // Clean up sensitive key material
      secureZero(bindingKey.key);

      // Constant-time comparison
      return this.constantTimeEquals(expectedSignature, providedSignature);
    } catch {
      // Any error during verification = invalid
      return false;
    }
  }

  /**
   * Derive a binding key from session key using HKDF-SHA256
   * Context: domain + timestamp
   */
  async deriveBindingKey(
    sessionKey: string,
    domain: string,
    timestamp: number
  ): Promise<BindingKey> {
    // Convert session key to Uint8Array
    const sessionKeyBytes = this.fromBase64(sessionKey);

    try {
      // Import session key as raw key material for HKDF
      const keyMaterial = await this.subtle.importKey(
        'raw',
        sessionKeyBytes as unknown as BufferSource,
        { name: 'HKDF' },
        false,
        ['deriveBits']
      );

      // Create HKDF info parameter: prefix|domain|timestamp
      const info = this.createHKDFInfo(domain, timestamp);

      // Derive key using HKDF-SHA256
      const derivedBits = await this.subtle.deriveBits(
        {
          name: 'HKDF',
          hash: BINDING_CONFIG.HKDF_HASH,
          salt: new Uint8Array(0) as unknown as BufferSource, // No salt - session key is already high entropy
          info: info as unknown as BufferSource,
        },
        keyMaterial,
        BINDING_CONFIG.KEY_LENGTH * 8 // bits
      );

      const derivedKey = new Uint8Array(derivedBits as ArrayBuffer);

      return {
        key: derivedKey,
        algorithm: BINDING_CONFIG.ALGORITHM,
        domain: domain.toLowerCase().trim(),
        derivedAt: Date.now(),
      };
    } finally {
      // Clean up session key bytes
      secureZero(sessionKeyBytes);
    }
  }

  /**
   * Generate a cryptographically secure random nonce
   */
  generateNonce(length: number = BINDING_CONFIG.NONCE_LENGTH): Uint8Array {
    const nonce = new Uint8Array(length);
    this.getRandomValues(nonce);
    return nonce;
  }

  /**
   * Validate channel binding context
   */
  private validateContext(context: ChannelBindingContext): void {
    if (!context.domain || context.domain.trim().length === 0) {
      throw new Error('Domain is required for channel binding');
    }
    if (context.timestamp <= 0) {
      throw new Error('Valid timestamp is required');
    }
    if (!context.nonce || context.nonce.length !== BINDING_CONFIG.NONCE_LENGTH) {
      throw new Error(`Nonce must be exactly ${BINDING_CONFIG.NONCE_LENGTH} bytes`);
    }
  }

  /**
   * Create the message to sign/verify: domain|timestamp|nonce
   */
  private createSigningMessage(context: ChannelBindingContext): Uint8Array {
    const domain = context.domain.toLowerCase().trim();
    const timestampStr = context.timestamp.toString();
    const nonceB64 = this.toBase64(context.nonce);

    const messageStr = `${domain}|${timestampStr}|${nonceB64}`;
    return new TextEncoder().encode(messageStr);
  }

  /**
   * Create HKDF info parameter
   */
  private createHKDFInfo(domain: string, timestamp: number): Uint8Array {
    const infoStr = `${BINDING_CONFIG.HKDF_INFO_PREFIX}|${domain.toLowerCase().trim()}|${timestamp}`;
    return new TextEncoder().encode(infoStr);
  }

  /**
   * Compute HMAC-SHA256
   */
  private async computeHMAC(key: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
    const cryptoKey = await this.subtle.importKey(
      'raw',
      key as unknown as BufferSource,
      BINDING_CONFIG.HMAC_ALGORITHM,
      false,
      ['sign']
    );

    const signature = await this.subtle.sign(
      BINDING_CONFIG.HMAC_ALGORITHM,
      cryptoKey,
      message as unknown as BufferSource
    );

    return new Uint8Array(signature as ArrayBuffer);
  }

  /**
   * Constant-time comparison of two Uint8Arrays
   */
  private constantTimeEquals(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) {
      return false;
    }
    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }
    return result === 0;
  }

  /**
   * Convert Uint8Array to base64 string
   */
  private toBase64(bytes: Uint8Array): string {
    // Use btoa with String.fromCharCode for binary-safe conversion
    let binary = '';
    for (let i = 0; i < bytes.length; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
  }

  /**
   * Convert base64 string to Uint8Array
   */
  private fromBase64(base64: string): Uint8Array {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }
}

/**
 * Factory function to create adapter with default crypto provider
 */
export function createChannelBindingAdapter(): SubtleCryptoChannelBindingAdapter {
  return new SubtleCryptoChannelBindingAdapter();
}
