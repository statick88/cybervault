import type { Vault } from "../entities/vault";
import type { Credential } from "../entities/credential";
import type { Vulnerability } from "../entities/vulnerability";
import type { VaultId, CredentialId, VulnerabilityId } from "../value-objects/ids";

export interface IVaultRepository {
  /**
   * Persist a vault.
   *
   * H5 (lost update): when `expectedVersion` is supplied the write is GUARDED
   * by the row's `lock_version` and an `OptimisticLockConflictError` is thrown
   * if it no longer matches — see `OptimisticLockConflictError`. When it is
   * omitted the original blind-write behaviour applies unchanged, so no
   * existing caller can start failing.
   */
  save(vault: Vault, expectedVersion?: number): Promise<Vault>;
  findById(id: VaultId): Promise<Vault | null>;
  findByVaultIdAndOwnerId(vaultId: string, ownerId: string): Promise<Vault | null>;
  delete(id: VaultId): Promise<boolean>;
  list(): Promise<Vault[]>;
  listByOwnerId(ownerId: string): Promise<Vault[]>;
  /**
   * Merge-free metadata overwrite, guarded the same way as `save` when
   * `expectedVersion` is supplied.
   */
  updateMetadata(
    vaultId: string,
    metadata: Record<string, unknown>,
    expectedVersion?: number,
  ): Promise<void>;
}

export interface ICredentialRepository {
  /** Same `expectedVersion` contract as `IVaultRepository.save`. */
  save(credential: Credential, expectedVersion?: number): Promise<Credential>;
  findById(id: CredentialId): Promise<Credential | null>;
  findByVaultId(vaultId: VaultId): Promise<Credential[]>;
  findBySecretRef(secretRef: string): Promise<Credential | null>;
  delete(id: CredentialId): Promise<boolean>;
  list(): Promise<Credential[]>;
}

/**
 * A Release Share that Core holds on behalf of a managed credential.
 *
 * Core is the ONLY holder of a Release Share (split trust: Plus authorizes,
 * never sees; the client holds it transiently for one authorized release). What
 * is persisted here is therefore never the share itself — it is the share
 * wrapped under the Core-held "Release Share KEK", keyed by the opaque
 * `secretRef` that Plus also sees.
 *
 * `wrappedShare` layout and the KEK derivation live in
 * `infrastructure/crypto/release-share-kek.ts`; this layer only stores the
 * opaque blob, which keeps the port testable without any key material.
 */
export interface WrappedReleaseShare {
  /** Opaque reference shared with Plus as `capability.secretRef`. */
  readonly secretRef: string;
  /** Base64 `iv|ciphertext` of the 32-byte Release Share under the Release Share KEK. */
  readonly wrappedShare: string;
  readonly createdAt: Date;
}

/**
 * Persistence port for wrapped Release Shares.
 *
 * Deliberately dumb: no key material, no unwrap logic. The use cases derive the
 * Release Share KEK from an injected server secret and wrap/unwrap around this
 * store, so a test can swap the secret without swapping the storage.
 */
export interface IReleaseShareStore {
  /** Persist (or replace) the wrapped share for `secretRef`. */
  save(entry: WrappedReleaseShare): Promise<void>;
  /** Return the wrapped blob, or null when the reference is unknown. */
  findBySecretRef(secretRef: string): Promise<WrappedReleaseShare | null>;
  /** Drop a wrapped share (credential deletion / rotation). */
  delete(secretRef: string): Promise<boolean>;
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

/**
 * One approval challenge Core issued for R11's human-presence proof.
 *
 * `bindingId` is what the proof binds to: the release `challengeId` for
 * `purpose: "release"`, the row's own id for `purpose: "enroll"`. The
 * WebAuthn `challenge` and the PBKDF2 `salt` are per-row random material —
 * never derived from anything an attacker controls, never reused.
 * `rpId`/`origin` are null exactly when WebAuthn is not configured, and a
 * null there must make every webauthn proof against the row refuse.
 */
export interface StepUpApprovalChallenge {
  readonly id: string;
  readonly bindingId: string;
  readonly userId: string;
  readonly purpose: "release" | "enroll";
  /** Base64url WebAuthn challenge. */
  readonly challenge: string;
  /** Hex per-approval PBKDF2 salt. */
  readonly salt: string;
  readonly rpId: string | null;
  readonly origin: string | null;
  /** Unix milliseconds (converted to TIMESTAMPTZ at the boundary). */
  readonly createdAt: number;
  readonly expiresAt: number;
  readonly consumedAt: number | null;
}

/**
 * Persistence port for approval challenges.
 *
 * `consume` is THE one-time-use guarantee: it must mark the row spent in one
 * atomic step (a single guarded UPDATE in SQL; a synchronous check-and-set in
 * memory) and return the row only to the caller that won the race. A
 * read-then-write implementation would let a captured assertion be spent
 * twice — R2's lesson: state that is not enforced where it is stored is not
 * enforced at all.
 */
export interface IStepUpApprovalChallengeStore {
  save(challenge: StepUpApprovalChallenge): Promise<void>;
  /**
   * Atomically consume `id` for `userId`: returns the row exactly once, or
   * null when it is unknown, another user's, already consumed, or expired.
   */
  consume(id: string, userId: string, now: number): Promise<StepUpApprovalChallenge | null>;
  /** Read without consuming — used by tests and operator diagnostics only. */
  findById(id: string): Promise<StepUpApprovalChallenge | null>;
}

/**
 * A WebAuthn credential the user registered as their approval authenticator.
 * Only verification material lives here: credential id, the normalized
 * P-256 public key (`04||x||y`, hex), the signature counter, transports.
 * The private key never leaves the authenticator and never reaches Core.
 */
export interface StepUpAuthenticator {
  /** Base64url of the credential's rawId — globally unique (PK). */
  readonly credentialId: string;
  readonly userId: string;
  readonly publicKey: string;
  readonly counter: number;
  readonly transports: readonly string[];
  readonly createdAt: number;
}

/**
 * Persistence port for registered authenticators.
 *
 * `save` must refuse to re-own a credential id registered to a different
 * user (return false) — overwriting someone else's public key would break
 * their approvals, and re-binding their authenticator to us would be worse.
 */
export interface IStepUpAuthenticatorStore {
  /** Register, or refresh the key material of the SAME owner. False if owned by another user. */
  save(authenticator: StepUpAuthenticator): Promise<boolean>;
  findByCredentialId(credentialId: string): Promise<StepUpAuthenticator | null>;
  listByUserId(userId: string): Promise<StepUpAuthenticator[]>;
  /** Persist a higher signature counter (clone detection advances it). */
  updateCounter(credentialId: string, counter: number): Promise<void>;
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
