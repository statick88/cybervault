import type { Vault } from "../entities/vault";
import type { Credential } from "../entities/credential";
import type { Vulnerability } from "../entities/vulnerability";
import type { VaultId, CredentialId, VulnerabilityId } from "../value-objects/ids";

export interface IVaultRepository {
  save(vault: Vault): Promise<Vault>;
  findById(id: VaultId): Promise<Vault | null>;
  findByVaultIdAndOwnerId(vaultId: string, ownerId: string): Promise<Vault | null>;
  delete(id: VaultId): Promise<boolean>;
  list(): Promise<Vault[]>;
  listByOwnerId(ownerId: string): Promise<Vault[]>;
  updateMetadata(vaultId: string, metadata: Record<string, unknown>): Promise<void>;
}

export interface ICredentialRepository {
  save(credential: Credential): Promise<Credential>;
  findById(id: CredentialId): Promise<Credential | null>;
  findByVaultId(vaultId: VaultId): Promise<Credential[]>;
  findBySecretRef(secretRef: string): Promise<Credential | null>;
  delete(id: CredentialId): Promise<boolean>;
  list(): Promise<Credential[]>;
}

export interface IUserRepository {
  findByEmail(email: string): Promise<any | null>;
  findById(userId: string): Promise<any | null>;
  setPasswordResetToken(userId: string, tokenHash: string, expiresAt: number): Promise<void>;
  clearPasswordResetToken(userId: string): Promise<void>;
  updatePassword(userId: string, hash: string, salt: string): Promise<void>;
  incrementSessionVersion(userId: string): Promise<void>;
  setRecoveryKeyHash(userId: string, hash: string): Promise<void>;
}

export interface IVulnerabilityRepository {
  save(vulnerability: Vulnerability): Promise<Vulnerability>;
  findById(id: VulnerabilityId): Promise<Vulnerability | null>;
  search(criteria: {
    severity?: string;
    status?: string;
    dateFrom?: Date;
    dateTo?: Date;
  }): Promise<Vulnerability[]>;
  delete(id: VulnerabilityId): Promise<boolean>;
}

export interface TrustEntry {
  domain: string;
  trustLevel: "verified" | "trusted" | "distrusted" | "suspicious" | "unknown";
  firstSeen: number;
  lastSeen: number;
  fingerprint?: string;
  visitCount: number;
}

export interface ITrustStoreRepository {
  save(entry: TrustEntry): Promise<void>;
  findByDomain(domain: string): Promise<TrustEntry | null>;
  revoke(domain: string): Promise<void>;
  list(): Promise<TrustEntry[]>;
  removeExpired(maxAgeMs: number): Promise<number>;
  saveFingerprint(domain: string, fingerprint: string): Promise<void>;
  getFingerprint(domain: string): Promise<string | null>;
  removeFingerprint(domain: string): Promise<void>;
}
