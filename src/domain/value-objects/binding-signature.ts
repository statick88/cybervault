/**
 * BindingSignature — immutable value object for cryptographic channel binding.
 *
 * Binds a request to a TLS channel via domain, timestamp, nonce, and signature.
 * Used by IChannelBindingProtocol implementations to sign/verify channel bindings.
 *
 * @module domain/value-objects/binding-signature
 */

export interface BindingSignaturePlain {
  readonly domain: string;
  readonly timestamp: number;
  readonly nonce: string;
  readonly signature: string;
}

export class BindingSignature {
  readonly domain: string;
  readonly timestamp: number;
  readonly nonce: string;
  readonly signature: string;

  private constructor(
    domain: string,
    timestamp: number,
    nonce: string,
    signature: string,
  ) {
    this.domain = domain;
    this.timestamp = timestamp;
    this.nonce = nonce;
    this.signature = signature;
    Object.freeze(this);
  }

  /**
   * Factory — normalises domain to lowercase/trimmed before storing.
   */
  static create(
    domain: string,
    timestamp: number,
    nonce: string,
    signature: string,
  ): BindingSignature {
    if (!domain || domain.trim().length === 0) {
      throw new Error('BindingSignature: domain is required');
    }
    if (timestamp <= 0) {
      throw new Error('BindingSignature: timestamp must be positive');
    }
    if (!nonce || nonce.length === 0) {
      throw new Error('BindingSignature: nonce is required');
    }
    if (!signature || signature.length === 0) {
      throw new Error('BindingSignature: signature is required');
    }

    return new BindingSignature(
      domain.toLowerCase().trim(),
      timestamp,
      nonce,
      signature,
    );
  }

  /**
   * Validate age against a maximum allowed window.
   *
   * @param currentTimestamp - typically Date.now()
   * @param maxAgeMs - maximum age in milliseconds (default 300 000 = 5 min)
   */
  isValid(currentTimestamp: number, maxAgeMs = 300_000): boolean {
    return Math.abs(currentTimestamp - this.timestamp) <= maxAgeMs;
  }

  toPlainObject(): BindingSignaturePlain {
    return {
      domain: this.domain,
      timestamp: this.timestamp,
      nonce: this.nonce,
      signature: this.signature,
    };
  }

  static fromPlainObject(obj: BindingSignaturePlain): BindingSignature {
    return BindingSignature.create(obj.domain, obj.timestamp, obj.nonce, obj.signature);
  }
}
