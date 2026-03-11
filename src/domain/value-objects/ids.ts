// Value Objects: Identificadores únicos

/**
 * Identificador único para Vault
 * Usa UUID v4 para garantizar unicidad global
 */
export class VaultId {
  private readonly value: string;

  constructor(value: string) {
    if (!this.isValidUUID(value)) {
      throw new Error(`VaultId inválido: ${value}`);
    }
    this.value = value;
  }

  /**
   * Genera un nuevo VaultId aleatorio
   */
  static generate(): VaultId {
    const uuid = crypto.randomUUID();
    return new VaultId(uuid);
  }

  /**
   * Crea desde string (útil para deserialización)
   */
  static fromString(value: string): VaultId {
    return new VaultId(value);
  }

  /**
   * Valida formato UUID
   */
  private isValidUUID(value: string): boolean {
    const uuidRegex =
      /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(value);
  }

  toString(): string {
    return this.value;
  }

  equals(other: VaultId): boolean {
    return this.value === other.value;
  }
}

/**
 * Identificador único para Vulnerabilidad
 */
export class VulnerabilityId {
  private readonly value: string;

  constructor(value: string) {
    if (!this.isValidUUID(value)) {
      throw new Error(`VulnerabilityId inválido: ${value}`);
    }
    this.value = value;
  }

  static generate(): VulnerabilityId {
    const uuid = crypto.randomUUID();
    return new VulnerabilityId(uuid);
  }

  static fromString(value: string): VulnerabilityId {
    return new VulnerabilityId(value);
  }

  private isValidUUID(value: string): boolean {
    const uuidRegex =
      /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(value);
  }

  toString(): string {
    return this.value;
  }

  equals(other: VulnerabilityId): boolean {
    return this.value === other.value;
  }
}

/**
 * Identificador único para Credencial
 */
export class CredentialId {
  private readonly value: string;

  constructor(value: string) {
    if (!this.isValidUUID(value)) {
      throw new Error(`CredentialId inválido: ${value}`);
    }
    this.value = value;
  }

  static generate(): CredentialId {
    const uuid = crypto.randomUUID();
    return new CredentialId(uuid);
  }

  static fromString(value: string): CredentialId {
    return new CredentialId(value);
  }

  private isValidUUID(value: string): boolean {
    const uuidRegex =
      /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(value);
  }

  toString(): string {
    return this.value;
  }

  equals(other: CredentialId): boolean {
    return this.value === other.value;
  }
}

/**
 * Hash criptográfico (SHA-256)
 */
export class CryptoHash {
  private readonly value: string;

  constructor(value: string) {
    if (!this.isValidHash(value)) {
      throw new Error(`Hash inválido: ${value}`);
    }
    this.value = value;
  }

  private isValidHash(value: string): boolean {
    // SHA-256 produce 64 caracteres hexadecimales
    return /^[a-f0-9]{64}$/i.test(value);
  }

  toString(): string {
    return this.value;
  }

  equals(other: CryptoHash): boolean {
    return this.value === other.value;
  }
}
