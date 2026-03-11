// Entidad: Vault (Bóveda de Claves)

import { VaultId, CryptoHash } from '../value-objects/ids';

export interface VaultProps {
  id: VaultId;
  name: string;
  description?: string;
  encryptedData: string; // Datos encriptados (ciphertext)
  encryptionKeyId: string; // ID de la clave de encriptación usada
  metadata?: Record<string, unknown>;
  createdAt: Date;
  updatedAt: Date;
}

export class Vault {
  private readonly props: VaultProps;

  constructor(props: VaultProps) {
    this.props = { ...props };
  }

  // Getters
  get id(): VaultId {
    return this.props.id;
  }

  get name(): string {
    return this.props.name;
  }

  get description(): string | undefined {
    return this.props.description;
  }

  get encryptedData(): string {
    return this.props.encryptedData;
  }

  get encryptionKeyId(): string {
    return this.props.encryptionKeyId;
  }

  get metadata(): Record<string, unknown> | undefined {
    return this.props.metadata;
  }

  get createdAt(): Date {
    return this.props.createdAt;
  }

  get updatedAt(): Date {
    return this.props.updatedAt;
  }

  // Métodos de negocio
  updateData(newEncryptedData: string, newEncryptionKeyId: string): void {
    this.props.encryptedData = newEncryptedData;
    this.props.encryptionKeyId = newEncryptionKeyId;
    this.props.updatedAt = new Date();
  }

  updateMetadata(metadata: Record<string, unknown>): void {
    this.props.metadata = { ...this.props.metadata, ...metadata };
    this.props.updatedAt = new Date();
  }

  /**
   * Factory method para crear nuevo Vault
   */
  static create(props: {
    name: string;
    description?: string;
    encryptedData: string;
    encryptionKeyId: string;
    metadata?: Record<string, unknown>;
  }): Vault {
    const now = new Date();
    return new Vault({
      id: VaultId.generate(),
      name: props.name,
      description: props.description,
      encryptedData: props.encryptedData,
      encryptionKeyId: props.encryptionKeyId,
      metadata: props.metadata,
      createdAt: now,
      updatedAt: now,
    });
  }

  /**
   * Deserializa desde objeto plano (útil para repositorios)
   */
  static fromPlainObject(obj: {
    id: string;
    name: string;
    description?: string;
    encryptedData: string;
    encryptionKeyId: string;
    metadata?: Record<string, unknown>;
    createdAt: string;
    updatedAt: string;
  }): Vault {
    return new Vault({
      id: VaultId.fromString(obj.id),
      name: obj.name,
      description: obj.description,
      encryptedData: obj.encryptedData,
      encryptionKeyId: obj.encryptionKeyId,
      metadata: obj.metadata,
      createdAt: new Date(obj.createdAt),
      updatedAt: new Date(obj.updatedAt),
    });
  }

  /**
   * Convierte a objeto plano para serialización
   */
  toPlainObject(): {
    id: string;
    name: string;
    description?: string;
    encryptedData: string;
    encryptionKeyId: string;
    metadata?: Record<string, unknown>;
    createdAt: string;
    updatedAt: string;
  } {
    return {
      id: this.props.id.toString(),
      name: this.props.name,
      description: this.props.description,
      encryptedData: this.props.encryptedData,
      encryptionKeyId: this.props.encryptionKeyId,
      metadata: this.props.metadata,
      createdAt: this.props.createdAt.toISOString(),
      updatedAt: this.props.updatedAt.toISOString(),
    };
  }
}
