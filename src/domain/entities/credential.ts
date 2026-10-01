/**
 * Credential Entity — Personal & Managed Credentials with Split-Trust Support
 *
 * Supports two credential types:
 * - PERSONAL: Encrypted with EntryKey = HKDF(VEK, salt, context)
 * - MANAGED: Encrypted with EntryKey = HKDF(VEK || ReleaseShare, salt, context)
 *
 * Each credential has a unique salt, version, and mode for cryptographic separation.
 */

import { CredentialId, VaultId } from "../value-objects/ids";

/** Credential encryption mode */
export type CredentialMode = "personal" | "managed";

/** Credential properties */
export interface CredentialProps {
  id: CredentialId;
  vaultId: VaultId;
  title: string;
  username: string;
  encryptedPassword: string; // AES-256-GCM ciphertext (base64: salt|iv|ciphertext)
  mode: CredentialMode;
  salt: string; // Base64 encoded 32-byte salt for HKDF derivation
  version: number; // Credential version for key rotation
  releaseShareRef?: string; // Opaque reference to ReleaseShare (managed only)
  url?: string;
  notes?: string;
  tags: string[];
  favorite: boolean;
  createdAt: Date;
  updatedAt: Date;
  lastUsed?: Date;
  /**
   * Optimistic-lock counter (H5). Owned by the DATABASE, never written by the
   * application — repositories read it on load and hand it back as
   * `expectedVersion` on the next write. Distinct from `version`, which is the
   * CRYPTOGRAPHIC entry version folded into the HKDF salt and must never be
   * repurposed.
   */
  lockVersion?: number;
}

/** Credential creation input */
export interface CredentialCreateInput {
  vaultId: VaultId;
  title: string;
  username: string;
  encryptedPassword: string;
  mode: CredentialMode;
  salt: string;
  version?: number;
  releaseShareRef?: string;
  url?: string;
  notes?: string;
  tags?: string[];
  favorite?: boolean;
}

/** Credential update input */
export interface CredentialUpdateInput {
  title?: string;
  username?: string;
  encryptedPassword?: string;
  url?: string;
  notes?: string;
  tags?: string[];
  favorite?: boolean;
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

  get mode(): CredentialMode {
    return this.props.mode;
  }

  get salt(): string {
    return this.props.salt;
  }

  get version(): number {
    return this.props.version;
  }

  get releaseShareRef(): string | undefined {
    return this.props.releaseShareRef;
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

  /** Optimistic-lock counter as read from the repository (H5). */
  get lockVersion(): number | undefined {
    return this.props.lockVersion;
  }

  // Type guards
  isPersonal(): boolean {
    return this.props.mode === "personal";
  }

  isManaged(): boolean {
    return this.props.mode === "managed";
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

  updateUrl(newUrl: string | undefined): void {
    this.props.url = newUrl;
    this.props.updatedAt = new Date();
  }

  updateNotes(newNotes: string | undefined): void {
    this.props.notes = newNotes;
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

  setTags(tags: string[]): void {
    this.props.tags = [...tags];
    this.props.updatedAt = new Date();
  }

  markAsUsed(): void {
    this.props.lastUsed = new Date();
  }

  /**
   * Increment version (for key rotation)
   */
  incrementVersion(): void {
    this.props.version += 1;
    this.props.updatedAt = new Date();
  }

  /**
   * Factory method para crear nueva credencial PERSONAL
   */
  static createPersonal(props: {
    vaultId: VaultId;
    title: string;
    username: string;
    encryptedPassword: string;
    salt: string; // Base64 encoded 32-byte salt
    url?: string;
    notes?: string;
    tags?: string[];
    favorite?: boolean;
    version?: number;
  }): Credential {
    const now = new Date();
    return new Credential({
      id: CredentialId.generate(),
      vaultId: props.vaultId,
      title: props.title,
      username: props.username,
      encryptedPassword: props.encryptedPassword,
      mode: "personal",
      salt: props.salt,
      version: props.version ?? 1,
      url: props.url,
      notes: props.notes,
      tags: props.tags || [],
      favorite: props.favorite || false,
      createdAt: now,
      updatedAt: now,
    });
  }

  /**
   * Factory method para crear nueva credencial MANAGED
   */
  static createManaged(props: {
    vaultId: VaultId;
    title: string;
    username: string;
    encryptedPassword: string;
    salt: string; // Base64 encoded 32-byte salt
    releaseShareRef: string; // Opaque reference to ReleaseShare
    url?: string;
    notes?: string;
    tags?: string[];
    favorite?: boolean;
    version?: number;
  }): Credential {
    const now = new Date();
    return new Credential({
      id: CredentialId.generate(),
      vaultId: props.vaultId,
      title: props.title,
      username: props.username,
      encryptedPassword: props.encryptedPassword,
      mode: "managed",
      salt: props.salt,
      version: props.version ?? 1,
      releaseShareRef: props.releaseShareRef,
      url: props.url,
      notes: props.notes,
      tags: props.tags || [],
      favorite: props.favorite || false,
      createdAt: now,
      updatedAt: now,
    });
  }

  /**
   * Factory method genérico (mantiene compatibilidad)
   */
  static create(props: CredentialCreateInput): Credential {
    if (props.mode === "personal") {
      return Credential.createPersonal({
        vaultId: props.vaultId,
        title: props.title,
        username: props.username,
        encryptedPassword: props.encryptedPassword,
        salt: props.salt,
        version: props.version,
        url: props.url,
        notes: props.notes,
        tags: props.tags,
        favorite: props.favorite,
      });
    } else {
      return Credential.createManaged({
        vaultId: props.vaultId,
        title: props.title,
        username: props.username,
        encryptedPassword: props.encryptedPassword,
        salt: props.salt,
        releaseShareRef: props.releaseShareRef!,
        version: props.version,
        url: props.url,
        notes: props.notes,
        tags: props.tags,
        favorite: props.favorite,
      });
    }
  }

  /**
   * Deserializa desde objeto plano (repository)
   */
  static fromPlainObject(obj: {
    id: string;
    vaultId: string;
    title: string;
    username: string;
    encryptedPassword: string;
    mode: CredentialMode;
    salt: string;
    version: number;
    releaseShareRef?: string;
    url?: string;
    notes?: string;
    tags: string[];
    favorite: boolean;
    createdAt: string;
    updatedAt: string;
    lastUsed?: string;
    lockVersion?: number | string;
  }): Credential {
    return new Credential({
      id: CredentialId.fromString(obj.id),
      vaultId: VaultId.fromString(obj.vaultId),
      title: obj.title,
      username: obj.username,
      encryptedPassword: obj.encryptedPassword,
      mode: obj.mode,
      salt: obj.salt,
      version: obj.version,
      releaseShareRef: obj.releaseShareRef,
      url: obj.url,
      notes: obj.notes,
      tags: obj.tags,
      favorite: obj.favorite,
      createdAt: new Date(obj.createdAt),
      updatedAt: new Date(obj.updatedAt),
      lastUsed: obj.lastUsed ? new Date(obj.lastUsed) : undefined,
      // PostgreSQL returns BIGINT columns as strings.
      lockVersion: obj.lockVersion === undefined || obj.lockVersion === null
        ? undefined
        : Number(obj.lockVersion),
    });
  }

  /**
   * Convierte a objeto plano para serialización (repository)
   */
  toPlainObject(): {
    id: string;
    vaultId: string;
    title: string;
    username: string;
    encryptedPassword: string;
    mode: CredentialMode;
    salt: string;
    version: number;
    releaseShareRef?: string;
    url?: string;
    notes?: string;
    tags: string[];
    favorite: boolean;
    createdAt: string;
    updatedAt: string;
    lastUsed?: string;
    lockVersion?: number;
  } {
    const plain: any = {
      id: this.props.id.toString(),
      vaultId: this.props.vaultId.toString(),
      title: this.props.title,
      username: this.props.username,
      encryptedPassword: this.props.encryptedPassword,
      mode: this.props.mode,
      salt: this.props.salt,
      version: this.props.version,
      url: this.props.url,
      notes: this.props.notes,
      tags: [...this.props.tags],
      favorite: this.props.favorite,
      createdAt: this.props.createdAt.toISOString(),
      updatedAt: this.props.updatedAt.toISOString(),
      lastUsed: this.props.lastUsed?.toISOString(),
      lockVersion: this.props.lockVersion,
    };

    if (this.props.releaseShareRef !== undefined) {
      plain.releaseShareRef = this.props.releaseShareRef;
    }

    return plain;
  }

  /**
   * Safe serialization — excludes encryptedPassword for API responses
   */
  toSafeObject(): {
    id: string;
    vaultId: string;
    title: string;
    username: string;
    mode: CredentialMode;
    version: number;
    hasReleaseShareRef: boolean;
    url?: string;
    notes?: string;
    tags: string[];
    favorite: boolean;
    createdAt: string;
    updatedAt: string;
    lastUsed?: string;
    lockVersion?: number;
  } {
    return {
      id: this.props.id.toString(),
      vaultId: this.props.vaultId.toString(),
      title: this.props.title,
      username: this.props.username,
      mode: this.props.mode,
      version: this.props.version,
      hasReleaseShareRef: this.props.releaseShareRef !== undefined,
      url: this.props.url,
      notes: this.props.notes,
      tags: [...this.props.tags],
      favorite: this.props.favorite,
      createdAt: this.props.createdAt.toISOString(),
      updatedAt: this.props.updatedAt.toISOString(),
      lastUsed: this.props.lastUsed?.toISOString(),
      lockVersion: this.props.lockVersion,
    };
  }
}