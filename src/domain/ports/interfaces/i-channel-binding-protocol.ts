/**
 * Channel Binding Protocol Port Interface
 * Defines the contract for cryptographic channel binding operations
 * Used to defend against Adversary-in-the-Middle (AiTM) attacks
 */

import type { BindingSignature } from "../../value-objects/binding-signature";

export interface ChannelBindingContext {
  readonly domain: string;
  readonly timestamp: number;
  readonly nonce: Uint8Array;
}

export interface BindingKey {
  readonly key: Uint8Array;
  readonly algorithm: 'HMAC-SHA256';
  readonly domain: string;
  readonly derivedAt: number;
}

export interface IChannelBindingProtocol {
  /**
   * Sign a channel binding for the given context
   * Creates a BindingSignature that binds the request to the TLS channel
   * 
   * @param context Channel binding context (domain, timestamp, nonce)
   * @returns BindingSignature containing the cryptographic signature
   * @throws Error if signing fails or context is invalid
   */
  signChannelBinding(context: ChannelBindingContext): Promise<BindingSignature>;

  /**
   * Verify a channel binding signature
   * Validates the signature, timestamp, domain, and nonce
   * 
   * @param signature The BindingSignature to verify
   * @param context Expected channel binding context
   * @returns true if signature is valid and context matches
   * @throws Error if verification fails due to unexpected error
   */
  verifyChannelBinding(signature: BindingSignature, context: ChannelBindingContext): Promise<boolean>;

  /**
   * Derive a binding key from the session key and domain
   * Uses HKDF-SHA256 with domain and timestamp as context
   * 
   * @param sessionKey Base session key from MasterKeyManager
   * @param domain Target domain for binding
   * @param timestamp Timestamp for key derivation
   * @returns Derived BindingKey for HMAC operations
   * @throws Error if key derivation fails
   */
  deriveBindingKey(sessionKey: string, domain: string, timestamp: number): Promise<BindingKey>;

  /**
   * Generate a cryptographically secure random nonce
   * 
   * @param length Nonce length in bytes (default: 32)
   * @returns Random nonce as Uint8Array
   */
  generateNonce(length?: number): Uint8Array;
}

export interface ChannelBindingVerificationResult {
  readonly valid: boolean;
  readonly reason?: 'INVALID_SIGNATURE' | 'TIMESTAMP_EXPIRED' | 'DOMAIN_MISMATCH' | 'NONCE_REPLAY' | 'ALGORITHM_MISMATCH';
}
