// Entidad: Credential (Credencial)

import { CredentialId, VaultId } from "../value-objects/ids";

export interface CredentialProps {
  id: CredentialId;
  vaultId: VaultId;
  title: string;
  username: string;
  encryptedPassword: string; // Contraseña cifrada
  url?: string;
  notes?: string;
  tags: string[];
  favorite: boolean;
  createdAt: Date;
  updatedAt: Date;
  lastUsed?: Date;
}

export class Credential {
  private readonly props: CredentialProps;

  constructor(props: CredentialProps) {
    this.props = { ...props };
  }

  // Getters
  get id(): CredentialId {
    return this.props.id;
  }

  get vaultId(): VaultId {
    return this.props.vaultId;
  }

  get title(): string {
    return this.props.title;
  }

  get username(): string {
    return this.props.username;
  }

  get encryptedPassword(): string {
    return this.props.encryptedPassword;
  }

  get url(): string | undefined {
    return this.props.url;
  }

  get notes(): string | undefined {
    return this.props.notes;
  }

  get tags(): string[] {
    return [...this.props.tags];
  }

  get favorite(): boolean {
    return this.props.favorite;
  }

  get createdAt(): Date {
    return this.props.createdAt;
  }

  get updatedAt(): Date {
    return this.props.updatedAt;
  }

  get lastUsed(): Date | undefined {
    return this.props.lastUsed;
  }

  // Métodos de negocio
  updatePassword(newEncryptedPassword: string): void {
    this.props.encryptedPassword = newEncryptedPassword;
    this.props.updatedAt = new Date();
  }

  updateTitle(newTitle: string): void {
    this.props.title = newTitle;
    this.props.updatedAt = new Date();
  }

  updateUsername(newUsername: string): void {
    this.props.username = newUsername;
    this.props.updatedAt = new Date();
  }

  toggleFavorite(): void {
    this.props.favorite = !this.props.favorite;
    this.props.updatedAt = new Date();
  }

  addTag(tag: string): void {
    if (!this.props.tags.includes(tag)) {
      this.props.tags.push(tag);
      this.props.updatedAt = new Date();
    }
  }

  removeTag(tag: string): void {
    const index = this.props.tags.indexOf(tag);
    if (index > -1) {
      this.props.tags.splice(index, 1);
      this.props.updatedAt = new Date();
    }
  }

  markAsUsed(): void {
    this.props.lastUsed = new Date();
  }

  /**
   * Factory method para crear nueva credencial
   */
  static create(props: {
    vaultId: VaultId;
    title: string;
    username: string;
    encryptedPassword: string;
    url?: string;
    notes?: string;
    tags?: string[];
    favorite?: boolean;
  }): Credential {
    const now = new Date();
    return new Credential({
      id: CredentialId.generate(),
      vaultId: props.vaultId,
      title: props.title,
      username: props.username,
      encryptedPassword: props.encryptedPassword,
      url: props.url,
      notes: props.notes,
      tags: props.tags || [],
      favorite: props.favorite || false,
      createdAt: now,
      updatedAt: now,
    });
  }

  /**
   * Deserializa desde objeto plano
   */
  static fromPlainObject(obj: {
    id: string;
    vaultId: string;
    title: string;
    username: string;
    encryptedPassword: string;
    url?: string;
    notes?: string;
    tags: string[];
    favorite: boolean;
    createdAt: string;
    updatedAt: string;
    lastUsed?: string;
  }): Credential {
    return new Credential({
      id: CredentialId.fromString(obj.id),
      vaultId: VaultId.fromString(obj.vaultId),
      title: obj.title,
      username: obj.username,
      encryptedPassword: obj.encryptedPassword,
      url: obj.url,
      notes: obj.notes,
      tags: obj.tags,
      favorite: obj.favorite,
      createdAt: new Date(obj.createdAt),
      updatedAt: new Date(obj.updatedAt),
      lastUsed: obj.lastUsed ? new Date(obj.lastUsed) : undefined,
    });
  }

  /**
   * Convierte a objeto plano para serialización
   */
  toPlainObject(): {
    id: string;
    vaultId: string;
    title: string;
    username: string;
    encryptedPassword: string;
    url?: string;
    notes?: string;
    tags: string[];
    favorite: boolean;
    createdAt: string;
    updatedAt: string;
    lastUsed?: string;
  } {
    return {
      id: this.props.id.toString(),
      vaultId: this.props.vaultId.toString(),
      title: this.props.title,
      username: this.props.username,
      encryptedPassword: this.props.encryptedPassword,
      url: this.props.url,
      notes: this.props.notes,
      tags: this.props.tags,
      favorite: this.props.favorite,
      createdAt: this.props.createdAt.toISOString(),
      updatedAt: this.props.updatedAt.toISOString(),
      lastUsed: this.props.lastUsed?.toISOString(),
    };
  }
}
