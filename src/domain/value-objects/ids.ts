/**
 * Branded ID value objects for the CyberVault domain.
 *
 * Each ID is a branded string type that prevents accidental cross-entity
 * assignment while remaining serializable as a plain string.
 *
 * @module domain/value-objects/ids
 */

function generateUUID(): string {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  try {
    const { randomBytes } = require("crypto");
    const bytes = randomBytes(16);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = bytes.toString("hex");
    return [
      hex.slice(0, 8),
      hex.slice(8, 12),
      hex.slice(12, 16),
      hex.slice(16, 20),
      hex.slice(20),
    ].join("-");
  } catch {
    // SECURITY: Use crypto.getRandomValues() — Math.random() is NOT cryptographically secure
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40; // Version 4
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // Variant 1
    const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
    return [
      hex.slice(0, 8),
      hex.slice(8, 12),
      hex.slice(12, 16),
      hex.slice(16, 20),
      hex.slice(20),
    ].join("-");
  }
}

class DomainId<Brand extends symbol> {
  private readonly value: string;
  private readonly brand: Brand;

  protected constructor(value: string, brand: Brand) {
    if (!value) {
      throw new Error("DomainId value must not be empty");
    }
    this.value = value;
    this.brand = brand;
  }

  toString(): string {
    return this.value;
  }

  equals(other: DomainId<Brand>): boolean {
    return this.value === other.value;
  }
}

const VaultIdBrand = Symbol("VaultId");
const CredentialIdBrand = Symbol("CredentialId");
const VulnerabilityIdBrand = Symbol("VulnerabilityId");
const CryptoHashBrand = Symbol("CryptoHash");

export class VaultId extends DomainId<typeof VaultIdBrand> {
  private constructor(value: string) {
    super(value, VaultIdBrand);
  }

  static generate(): VaultId {
    return new VaultId(generateUUID());
  }

  static fromString(value: string): VaultId {
    return new VaultId(value);
  }
}

export class CredentialId extends DomainId<typeof CredentialIdBrand> {
  private constructor(value: string) {
    super(value, CredentialIdBrand);
  }

  static generate(): CredentialId {
    return new CredentialId(generateUUID());
  }

  static fromString(value: string): CredentialId {
    return new CredentialId(value);
  }
}

export class VulnerabilityId extends DomainId<typeof VulnerabilityIdBrand> {
  private constructor(value: string) {
    super(value, VulnerabilityIdBrand);
  }

  static generate(): VulnerabilityId {
    return new VulnerabilityId(generateUUID());
  }

  static fromString(value: string): VulnerabilityId {
    return new VulnerabilityId(value);
  }
}

export class CryptoHash extends DomainId<typeof CryptoHashBrand> {
  private constructor(value: string) {
    super(value, CryptoHashBrand);
  }

  static fromString(value: string): CryptoHash {
    return new CryptoHash(value);
  }
}
