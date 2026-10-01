/**
 * Challenge Service — Step-Up Authentication Flow for CyberVault Plus
 *
 * Implements the third factor authentication flow:
 * 1. Risk engine triggers challenge (or pestillo STEP_UP forces it)
 * 2. Plus creates challenge with random nonce, sends single-use URL via email
 * 3. User approves the release in the popup; Core signs that approval
 * 4. Plus verifies the signed approval against its PINNED Core public key and
 *    issues a capability with assurance level 3
 * 5. Challenge consumed (one-time use)
 *
 * R3 replaced the previous 6-digit PIN with Core's signed approval. There is
 * no PIN anywhere in this service any more: nothing generated, nothing hashed,
 * nothing stored, nothing logged and nothing returned.
 */

import { logger } from "@/shared/logger";
import { secureZero } from "@/infrastructure/crypto/secure-memory";
import { binaryToBase64 } from "@/shared/utils";
import type { CapabilityOperation, SignedCapability } from "@/infrastructure/crypto/ed25519-capability";
import { signCapability, createCapabilityPayload, verifyCapability, loadEd25519PrivateKey } from "@/infrastructure/crypto/ed25519-capability";
import { verifyAndConsumeJti } from "@/infrastructure/crypto/jti-store";
import type { PinLockoutState } from "../entities/user";
import type { ApprovalBindingContext, SignedApproval } from "@/infrastructure/crypto/ed25519-approval";
import {
  CORE_APPROVAL_PUBLIC_KEY_ENV,
  isValidApprovalOperation,
  loadApprovalPublicKey,
  verifyApproval as verifySignedApproval,
} from "@/infrastructure/crypto/ed25519-approval";

/** Challenge types */
export type ChallengeType = "step_up" | "risk_based" | "forced";

// R4 — the per-USER failed-PIN lockout thresholds.
//
// These survive R3 as the policy that `006_pin_lockout.sql`, `IPinLockoutStore`
// and `PostgresPlusUserRepository` still encode. Nothing in THIS service reads
// them any more: there is no PIN left to guess, so there is nothing to lock
// out. They are exported rather than deleted so the surviving R4 artifacts keep
// one shared definition of the thresholds.

/** Failed PIN verifications tolerated across ALL of a user's challenges. */
export const PIN_LOCKOUT_THRESHOLD = 5;
/** How long the account is locked once the threshold is reached (15 minutes). */
export const PIN_LOCKOUT_MS = 15 * 60 * 1000;

/**
 * The persistence the lockout runs on.
 *
 * Narrow on purpose — a lockout consumer needs to read, increment and write one
 * user's lockout, nothing else about the user directory. The production
 * implementation is `PostgresPlusUserRepository`.
 *
 * R3 note: `ChallengeService` no longer takes this store. The port and the
 * repository methods that implement it are separate committed artifacts and
 * stay; only the wiring from PIN verification was removed, because a lockout
 * guards a secret and there is no secret left.
 */
export interface IPinLockoutStore {
  getPinLockout(userId: string): Promise<PinLockoutState>;
  recordFailedPinAttempt(userId: string): Promise<PinLockoutState>;
  setPinLockout(userId: string, state: PinLockoutState): Promise<void>;
}

/** Challenge status */
export type ChallengeStatus = "pending" | "email_sent" | "url_accessed" | "completed" | "expired" | "failed";

/** Challenge entity */
export interface ChallengeProps {
  id: string; // UUID
  userId: string;
  resourceId: string;
  operation: CapabilityOperation;
  secretRef: string;
  deviceId?: string;
  type: ChallengeType;
  status: ChallengeStatus;
  nonce: string; // Base64 encoded random nonce
  /**
   * Legacy R4 columns. R3 removed the PIN, so `createChallenge` no longer
   * produces either value and a freshly created challenge carries no `pinHmac`
   * and no `pinSalt` key at all. The properties stay optional because the
   * `challenges` table still has both columns (migration `005_plus_schema.sql`
   * has already run) and rows written before R3 still map back onto this type.
   */
  pinHmac?: string;
  pinSalt?: string;
  emailSentAt?: number; // Unix ms
  accessedAt?: number; // Unix ms
  completedAt?: number; // Unix ms
  expiresAt: number; // Unix ms
  attempts: number;
  maxAttempts: number;
  riskScore?: number; // Risk score that triggered challenge
  riskReasons?: string[]; // Risk factor reasons
  assuranceLevel: 3; // Third factor = assurance 3
  createdAt: number;
  updatedAt: number;
  metadata?: Record<string, unknown>;
}

/** Challenge creation input */
export interface ChallengeCreateInput {
  userId: string;
  resourceId: string;
  operation: CapabilityOperation;
  secretRef: string;
  deviceId?: string;
  type: ChallengeType;
  riskScore?: number;
  riskReasons?: string[];
  ttlMinutes?: number; // Default 10 minutes
  maxAttempts?: number; // Default 3
}

/**
 * The identity a challenge is scoped to.
 *
 * All four fields must match for a challenge to satisfy a capability request.
 * Plus holds no credential store, so these values are the ONLY thing tying a
 * challenge to the release it authorizes: the capability route and the
 * step-up trigger have to name the resource the same way (by its release-share
 * reference, which is also what Core pins as `expected.resourceId`), or a
 * challenge completed on one leg can never satisfy the other.
 */
export interface ChallengeBinding {
  userId: string;
  resourceId: string;
  operation: CapabilityOperation;
  secretRef: string;
}

/** Approval verification input */
export interface ApprovalVerifyInput {
  /** The challenge being completed. Also the approval's own `challengeId`. */
  challengeId: string;
  /** The signed approval Core issued for this challenge. */
  approval: SignedApproval;
  deviceId?: string;
}

/** Approval verification result */
export interface ApprovalVerifyResult {
  success: boolean;
  capabilityToken?: SignedCapability;
  error?: string;
}

/** Challenge repository interface */
export interface IChallengeRepository {
  save(challenge: ChallengeProps): Promise<ChallengeProps>;
  findById(id: string): Promise<ChallengeProps | null>;
  findByUserId(userId: string): Promise<ChallengeProps[]>;
  findPendingByUserId(userId: string): Promise<ChallengeProps[]>;
  update(challenge: ChallengeProps): Promise<ChallengeProps>;
  delete(id: string): Promise<boolean>;
  cleanupExpired(): Promise<number>;
}

/** Email service interface */
export interface IEmailService {
  sendChallengeEmail(email: string, challengeUrl: string, expiresInMinutes: number): Promise<void>;
}

/** Challenge Service */
export class ChallengeService {
  private challengeRepo: IChallengeRepository;
  private emailService: IEmailService;
  private baseUrl: string; // Base URL for challenge links (e.g., https://plus.company.com)
  private plusPrivateKey: Uint8Array; // Ed25519 private key for signing capabilities

  constructor(
    challengeRepo: IChallengeRepository,
    emailService: IEmailService,
    baseUrl: string,
    plusPrivateKeyBase64: string,
  ) {
    this.challengeRepo = challengeRepo;
    this.emailService = emailService;
    this.baseUrl = baseUrl.replace(/\/$/, ""); // Remove trailing slash
    this.plusPrivateKey = loadEd25519PrivateKey(plusPrivateKeyBase64);
  }

  /**
   * Statuses that mean "a third factor has been demanded but not proven".
   *
   * `failed` and `expired` are deliberately absent: those challenges are spent,
   * and a spent challenge must never be resurrected by a later request.
   */
  private static readonly OUTSTANDING: ChallengeStatus[] = ["pending", "email_sent", "url_accessed"];

  private sameBinding(challenge: ChallengeProps, binding: ChallengeBinding): boolean {
    return (
      challenge.userId === binding.userId &&
      challenge.resourceId === binding.resourceId &&
      challenge.operation === binding.operation &&
      challenge.secretRef === binding.secretRef
    );
  }

  /**
   * The challenge for this binding that is still waiting on proof, if any.
   *
   * Used by `createChallenge` so one release produces ONE challenge and one
   * email: the id the capability route returns alongside `challengeRequired`,
   * the id `START_STEP_UP` resolves and the id `/challenges/approve` consumes
   * are then all the same id. Two challenges for one release would mean the
   * user proves a factor against a challenge the capability gate never sees.
   */
  private async findOutstandingChallenge(binding: ChallengeBinding): Promise<ChallengeProps | null> {
    const now = Date.now();
    const challenges = await this.challengeRepo.findByUserId(binding.userId);
    return (
      challenges.find(
        (challenge) =>
          this.sameBinding(challenge, binding) &&
          ChallengeService.OUTSTANDING.includes(challenge.status) &&
          challenge.expiresAt > now,
      ) ?? null
    );
  }

  /**
   * The challenge for this binding that has been PROVEN — a Core-signed
   * approval accepted against it, one-time use, and still inside its own
   * expiry.
   *
   * This is the only thing the capability route accepts in place of a fresh
   * challenge. A challenge that is merely outstanding is exactly what it must
   * NOT accept, because that is the case the capability has to be withheld for.
   */
  async findCompletedChallenge(binding: ChallengeBinding): Promise<ChallengeProps | null> {
    const now = Date.now();
    const challenges = await this.challengeRepo.findByUserId(binding.userId);
    return (
      challenges.find(
        (challenge) =>
          this.sameBinding(challenge, binding) &&
          challenge.status === "completed" &&
          challenge.expiresAt > now,
      ) ?? null
    );
  }

  /**
   * Create a new challenge and send email
   */
  async createChallenge(input: ChallengeCreateInput): Promise<{ challengeId: string; expiresAt: number }> {
    const binding: ChallengeBinding = {
      userId: input.userId,
      resourceId: input.resourceId,
      operation: input.operation,
      secretRef: input.secretRef,
    };

    // Reuse rather than re-issue: the capability route asks for a challenge
    // before the user has had the chance to approve, so without this the
    // popup's trigger would mint a second challenge and the completion of one
    // would never unlock the other.
    const outstanding = await this.findOutstandingChallenge(binding);
    if (outstanding) {
      logger.info(`Reusing outstanding challenge ${outstanding.id} for user ${input.userId}`, "ChallengeService");
      return { challengeId: outstanding.id, expiresAt: outstanding.expiresAt };
    }

    const now = Date.now();
    const ttlMinutes = input.ttlMinutes ?? 10;
    const maxAttempts = input.maxAttempts ?? 3;

    // Generate cryptographic nonce
    const nonce = crypto.getRandomValues(new Uint8Array(32));
    const nonceBase64 = binaryToBase64(nonce);

    // Generate challenge ID (use nonce as base)
    const challengeId = binaryToBase64(crypto.getRandomValues(new Uint8Array(16)))
      .replace(/[+/=]/g, "")
      .substring(0, 24);

    // R3 — no PIN. The third factor is Core's signed approval, so nothing
    // secret is minted here: no PIN, no pinSalt, no pinHmac, and no
    // `metadata.generatedPin`. The record below is the whole record.
    const challenge: ChallengeProps = {
      id: challengeId,
      userId: input.userId,
      resourceId: input.resourceId,
      operation: input.operation,
      secretRef: input.secretRef,
      deviceId: input.deviceId,
      type: input.type,
      status: "pending",
      nonce: nonceBase64,
      expiresAt: now + ttlMinutes * 60 * 1000,
      attempts: 0,
      maxAttempts,
      riskScore: input.riskScore,
      riskReasons: input.riskReasons,
      assuranceLevel: 3,
      createdAt: now,
      updatedAt: now,
    };

    await this.challengeRepo.save(challenge);

    // Send challenge email
    const challengeUrl = `${this.baseUrl}/challenge/${challengeId}`;
    await this.emailService.sendChallengeEmail(
      // Email would be fetched from user repository
      "user@example.com", // Placeholder
      challengeUrl,
      ttlMinutes,
    );

    // Update status
    challenge.status = "email_sent";
    challenge.emailSentAt = now;
    challenge.updatedAt = now;
    await this.challengeRepo.update(challenge);

    logger.info(`Challenge created: ${challengeId} for user ${input.userId}`, "ChallengeService");

    // Secure cleanup
    secureZero(nonce);

    return { challengeId, expiresAt: challenge.expiresAt };
  }

  /**
   * Verify Core's signed approval and issue the capability token.
   *
   * R3 replaced `verifyPin`. The third factor is no longer a secret the user
   * types — it is a decision Core signed. Plus's whole job here is to check
   * that signature against a key it pinned itself, that it was signed for
   * THIS challenge, and that it has not been spent.
   *
   * Fail closed at every step: an unknown challenge, a spent challenge, an
   * expired challenge, a missing or malformed pinned key, and any mismatch
   * between the approval's binding and the STORED challenge all refuse.
   */
  async verifyApproval(input: ApprovalVerifyInput): Promise<ApprovalVerifyResult> {
    // 1. The challenge must exist.
    const challenge = await this.challengeRepo.findById(input.challengeId);
    if (!challenge) {
      return { success: false, error: "Challenge not found" };
    }

    // 2. Only an outstanding challenge may still be completed. A spent one
    //    (`completed`, `failed`, `expired`) must never be resurrected by a
    //    later request, however valid the approval that arrives with it is.
    if (!ChallengeService.OUTSTANDING.includes(challenge.status)) {
      return { success: false, error: `Challenge not in valid state: ${challenge.status}` };
    }

    // 3. Expiry, marked on the record exactly as the previous verifier did so
    //    the row stops being offered as outstanding.
    if (Date.now() > challenge.expiresAt) {
      challenge.status = "expired";
      challenge.updatedAt = Date.now();
      await this.challengeRepo.update(challenge);
      return { success: false, error: "Challenge expired" };
    }

    // 4. The pinned Core public key.
    //
    //    PINNED KEY PATH: the verification key comes from the environment this
    //    Plus process was deployed with — NEVER from the request body, never
    //    from the approval itself. Accepting a public key from the caller
    //    would let anyone sign their own approval and pass every check below.
    //    Unset or malformed means NO approvals, not "approvals we cannot
    //    check": fail closed with an explicit configuration error.
    const pinnedKey = process.env[CORE_APPROVAL_PUBLIC_KEY_ENV];
    if (!pinnedKey) {
      logger.error("CORE_APPROVAL_PUBLIC_KEY is not set; refusing approval", "ChallengeService");
      return { success: false, error: "Core approval public key is not configured" };
    }
    let publicKey: Uint8Array;
    try {
      publicKey = loadApprovalPublicKey(pinnedKey);
      if (publicKey.byteLength !== 32) {
        throw new Error(`unexpected key length ${publicKey.byteLength}`);
      }
    } catch (error) {
      logger.error(`CORE_APPROVAL_PUBLIC_KEY is unusable; refusing approval: ${String(error)}`, "ChallengeService");
      return { success: false, error: "Core approval public key is not configured" };
    }

    // An approval only ever carries one of the three operations Core is
    // willing to sign. A challenge for anything else can never be satisfied by
    // an approval that exists, so refuse before touching the signature.
    if (!isValidApprovalOperation(challenge.operation)) {
      return { success: false, error: `Operation cannot be approved: ${challenge.operation}` };
    }

    // 5. Every binding field comes from the STORED challenge, never from the
    //    request. The caller only names the challenge id; what the approval
    //    must have been signed FOR is whatever Plus already knows about it.
    const expected: ApprovalBindingContext = {
      challengeId: challenge.id,
      userId: challenge.userId,
      resourceId: challenge.resourceId,
      operation: challenge.operation,
      secretRef: challenge.secretRef,
    };

    let verification: { valid: boolean; error?: string };
    try {
      verification = await verifySignedApproval(input.approval, publicKey, expected);
    } catch (error) {
      // A structurally broken token must not surface as a 500 either.
      logger.warn(`Malformed approval for challenge ${challenge.id}: ${String(error)}`, "ChallengeService");
      return { success: false, error: "Malformed approval" };
    }
    if (!verification.valid) {
      return { success: false, error: verification.error ?? "Approval rejected" };
    }

    // Single use, enforced atomically and before anything is issued, exactly
    // as `verifyApproval`'s own contract promises. The challenge state machine
    // already refuses a second completion of the SAME challenge; this closes
    // the gap for a token that somehow outlives the state it was spent in.
    const replay = await verifyAndConsumeJti(
      input.approval.payload.jti,
      input.approval.payload.exp - input.approval.payload.iat,
    );
    if (!replay.allowed) {
      logger.warn(`Replay of approval jti ${input.approval.payload.jti} for challenge ${challenge.id}`, "ChallengeService");
      return { success: false, error: "Approval already used" };
    }

    // 6. The approval is good — mint the capability exactly as before.
    const capabilityPayload = createCapabilityPayload({
      userId: challenge.userId,
      resourceId: challenge.resourceId,
      operation: challenge.operation,
      secretRef: challenge.secretRef,
      deviceId: challenge.deviceId ?? input.deviceId,
      assurance: 3,
      ttlSeconds: 300, // 5 minutes for capability
    });

    const signedCapability = await signCapability(capabilityPayload, this.plusPrivateKey);

    // Verify the capability we just signed (defense in depth)
    const verifyResult = await verifyCapability(signedCapability, this.plusPrivateKey.slice(32));
    if (!verifyResult.valid) {
      logger.error("Self-verification of signed capability failed", "ChallengeService");
      return { success: false, error: "Internal error: capability signing failed" };
    }

    // Consume challenge (mark completed)
    challenge.status = "completed";
    challenge.completedAt = Date.now();
    challenge.updatedAt = Date.now();
    await this.challengeRepo.update(challenge);

    // Verify and consume JTI for replay protection
    const jtiResult = await verifyAndConsumeJti(
      capabilityPayload.jti,
      Math.floor((capabilityPayload.exp - capabilityPayload.iat)),
    );
    if (!jtiResult.allowed) {
      logger.warn(`JTI replay detected for capability: ${capabilityPayload.jti}`, "ChallengeService");
    }

    logger.info(`Challenge completed: ${challenge.id} for user ${challenge.userId}`, "ChallengeService");

    return {
      success: true,
      capabilityToken: signedCapability,
    };
  }

  /**
   * Get challenge by ID (for status checking)
   */
  async getChallenge(id: string): Promise<ChallengeProps | null> {
    return this.challengeRepo.findById(id);
  }

  /**
   * List pending challenges for a user
   */
  async getPendingChallenges(userId: string): Promise<ChallengeProps[]> {
    return this.challengeRepo.findPendingByUserId(userId);
  }

  /**
   * Cleanup expired challenges (cron job)
   */
  async cleanupExpired(): Promise<number> {
    return this.challengeRepo.cleanupExpired();
  }
}

/** Singleton getter */
let _challengeService: ChallengeService | null = null;

export function getChallengeService(
  challengeRepo: IChallengeRepository,
  emailService: IEmailService,
  baseUrl: string,
  plusPrivateKeyBase64: string,
): ChallengeService {
  if (!_challengeService) {
    _challengeService = new ChallengeService(
      challengeRepo,
      emailService,
      baseUrl,
      plusPrivateKeyBase64,
    );
  }
  return _challengeService;
}

export function setChallengeService(service: ChallengeService | null): void {
  _challengeService = service;
}
