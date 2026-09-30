/**
 * Challenge Service — Step-Up Authentication Flow for CyberVault Plus
 *
 * Implements the third factor authentication flow:
 * 1. Risk engine triggers challenge (or pestillo STEP_UP forces it)
 * 2. Plus creates challenge with random nonce, sends single-use URL via email
 * 3. User clicks URL, enters PIN
 * 4. Plus verifies PIN (HMAC), issues capability with assurance level 3
 * 5. Challenge consumed (one-time use)
 */

import { logger } from "@/shared/logger";
import { secureZero } from "@/infrastructure/crypto/secure-memory";
import { binaryToBase64, base64ToBinary } from "@/shared/utils";
import type { CapabilityOperation, SignedCapability } from "@/infrastructure/crypto/ed25519-capability";
import { signCapability, createCapabilityPayload, verifyCapability, loadEd25519PrivateKey } from "@/infrastructure/crypto/ed25519-capability";
import { verifyAndConsumeJti } from "@/infrastructure/crypto/jti-store";
import type { PinLockoutState } from "../entities/user";

/** Challenge types */
export type ChallengeType = "step_up" | "risk_based" | "forced";

// R4 — the per-USER failed-PIN lockout thresholds.
//
// `challenges.attempts` (default `maxAttempts` 3) is a brake on ONE challenge.
// Minting the next challenge resets it, and minting is exactly what
// `/api/v1/challenges/trigger` and the capability gate do for free — so with
// the R1 rate limit alone the per-challenge counter still admits ~180 guesses
// a minute against a 6-digit PIN space. These thresholds move the brake onto
// the user, where recreating a challenge cannot refresh it.

/** Failed PIN verifications tolerated across ALL of a user's challenges. */
export const PIN_LOCKOUT_THRESHOLD = 5;
/** How long the account is locked once the threshold is reached (15 minutes). */
export const PIN_LOCKOUT_MS = 15 * 60 * 1000;
/** A step-up PIN is exactly this many characters. */
export const PIN_LENGTH = 6;

/**
 * The persistence the lockout runs on.
 *
 * Narrow on purpose — the challenge service needs to read, increment and
 * write one user's lockout, nothing else about the user directory. The
 * production implementation is `PostgresPlusUserRepository`, so the state
 * survives a Plus restart, a Core restart and is shared by every replica:
 * an in-memory map would be defeated by the very restart R2 taught us not to
 * rely on.
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
  pinHmac: string; // HMAC-SHA256 of PIN (never store plaintext PIN)
  pinSalt: string; // Salt for PIN derivation
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

/** PIN verification input */
export interface PinVerifyInput {
  challengeId: string;
  pin: string;
  deviceId?: string;
}

/** PIN verification result */
export interface PinVerifyResult {
  success: boolean;
  capabilityToken?: SignedCapability;
  error?: string;
  attemptsRemaining?: number;
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
  private pinLockout: IPinLockoutStore; // R4: DB-backed per-user failed-PIN lockout

  constructor(
    challengeRepo: IChallengeRepository,
    emailService: IEmailService,
    baseUrl: string,
    plusPrivateKeyBase64: string,
    pinLockout: IPinLockoutStore,
  ) {
    this.challengeRepo = challengeRepo;
    this.emailService = emailService;
    this.baseUrl = baseUrl.replace(/\/$/, ""); // Remove trailing slash
    this.plusPrivateKey = loadEd25519PrivateKey(plusPrivateKeyBase64);
    // Required, not optional: a service constructed without a lockout store
    // would silently enforce nothing, which is the R4 bug wearing a hat.
    this.pinLockout = pinLockout;
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
   * The challenge for this binding that is still waiting on the PIN, if any.
   *
   * Used by `createChallenge` so one release produces ONE challenge and one
   * email: the id the capability route returns alongside `challengeRequired`,
   * the id `START_STEP_UP` resolves and the id `/challenges/verify` consumes are
   * then all the same id. Two challenges for one release would mean the user
   * proves a factor against a challenge the capability gate never sees.
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
   * The challenge for this binding that has been PROVEN — correct PIN, one-time
   * use, and still inside its own expiry.
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
    // before the user has any way to enter a PIN, so without this the popup's
    // trigger would mint a second challenge and the completion of one would
    // never unlock the other.
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

    // PIN will be generated by user via UI - we store HMAC of PIN
    // For now, we generate a random PIN for the user (in production, user sets it)
    const pin = this.generateRandomPin();
    const pinSalt = crypto.getRandomValues(new Uint8Array(32));
    const pinHmac = await this.computePinHmac(pin, binaryToBase64(pinSalt));

    // Create challenge
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
      pinHmac,
      pinSalt: binaryToBase64(pinSalt),
      expiresAt: now + ttlMinutes * 60 * 1000,
      attempts: 0,
      maxAttempts,
      riskScore: input.riskScore,
      riskReasons: input.riskReasons,
      assuranceLevel: 3,
      createdAt: now,
      updatedAt: now,
      metadata: {
        generatedPin: pin, // In production, this would NOT be stored - user sets their own PIN
      },
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
    secureZero(pinSalt);

    return { challengeId, expiresAt: challenge.expiresAt };
  }

  /**
   * Verify PIN and issue capability token
   */
  async verifyPin(input: PinVerifyInput): Promise<PinVerifyResult> {
    const challenge = await this.challengeRepo.findById(input.challengeId);
    if (!challenge) {
      return { success: false, error: "Challenge not found" };
    }

    // R4 — the lockout belongs to the challenge's OWN user, is checked before
    // any PIN HMAC is computed, and answers with exactly what a wrong PIN
    // answers: no HMAC means no timing/content oracle for the correct PIN, and
    // an error string identical to "Invalid PIN" means the caller cannot tell
    // "locked" from "wrong" either. The lock outlives the challenge it was
    // earned on, so minting a fresh challenge does not dodge it.
    const lockout = await this.pinLockout.getPinLockout(challenge.userId);
    if (lockout.lockedUntil !== null && lockout.lockedUntil > Date.now()) {
      logger.warn(
        `Refusing PIN verification: user ${challenge.userId} is locked until ${new Date(lockout.lockedUntil).toISOString()}`,
        "ChallengeService",
      );
      return {
        success: false,
        error: "Invalid PIN",
        attemptsRemaining: Math.max(0, challenge.maxAttempts - challenge.attempts),
      };
    }

    // Check status
    if (challenge.status !== "email_sent" && challenge.status !== "url_accessed") {
      return { success: false, error: `Challenge not in valid state: ${challenge.status}` };
    }

    // Check expiry
    if (Date.now() > challenge.expiresAt) {
      challenge.status = "expired";
      challenge.updatedAt = Date.now();
      await this.challengeRepo.update(challenge);
      return { success: false, error: "Challenge expired" };
    }

    // Check max attempts
    if (challenge.attempts >= challenge.maxAttempts) {
      challenge.status = "failed";
      challenge.updatedAt = Date.now();
      await this.challengeRepo.update(challenge);
      return { success: false, error: "Maximum attempts exceeded" };
    }

    // R4 — format gate before the HMAC. An input that is not exactly
    // PIN_LENGTH characters can never equal a generated PIN, so hashing it
    // would hand free CPU to the caller and would record a "wrong PIN" for
    // something that was never a PIN at all. It is also NOT counted against
    // the user: otherwise anyone who can reach this route could lock an
    // account by sending garbage five times.
    if (typeof input.pin !== "string" || input.pin.length !== PIN_LENGTH) {
      return {
        success: false,
        error: "Invalid PIN format",
        attemptsRemaining: challenge.maxAttempts - challenge.attempts,
      };
    }

    // Verify PIN HMAC
    const providedHmac = await this.computePinHmac(input.pin, challenge.pinSalt);
    if (providedHmac !== challenge.pinHmac) {
      challenge.attempts++;
      challenge.updatedAt = Date.now();
      await this.challengeRepo.update(challenge);
      // Wrong PIN: count it against the USER as well as the challenge, so the
      // budget cannot be reset by minting the next challenge.
      await this.registerWrongPin(challenge.userId);
      return {
        success: false,
        error: "Invalid PIN",
        attemptsRemaining: challenge.maxAttempts - challenge.attempts,
      };
    }

    // PIN correct — the only event that clears the user's failure budget and
    // any lock left over from earlier mistakes (the read above is that state,
    // so a clean user costs no write at all).
    if (lockout.failedPinAttempts !== 0 || lockout.lockedUntil !== null) {
      await this.pinLockout.setPinLockout(challenge.userId, {
        failedPinAttempts: 0,
        lockedUntil: null,
      });
      logger.info(
        `PIN lockout cleared for user ${challenge.userId} after a correct PIN`,
        "ChallengeService",
      );
    }

    // PIN correct - mark as accessed if first time
    if (challenge.status === "email_sent") {
      challenge.status = "url_accessed";
      challenge.accessedAt = Date.now();
    }

    // Issue capability token
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

    // Secure cleanup - best effort for string
    input.pin = "";

    return {
      success: true,
      capabilityToken: signedCapability,
    };
  }

  /**
   * R4 — count a wrong PIN against the USER, not only against the challenge.
   *
   * The increment happens in the database (`failed_pin_attempts + 1`) so
   * concurrent guesses cannot overwrite each other's increment. When the
   * returned total reaches `PIN_LOCKOUT_THRESHOLD` the lock is armed for
   * `PIN_LOCKOUT_MS`.
   *
   * The counter is deliberately sticky: it is cleared only by a correct PIN,
   * so letting a lock expire does not hand the caller a fresh budget — the
   * very next mistake re-arms it. Both policies bound a brute force to
   * `PIN_LOCKOUT_THRESHOLD` guesses per `PIN_LOCKOUT_MS` regardless of how
   * many challenges are minted in between.
   */
  private async registerWrongPin(userId: string): Promise<void> {
    const state = await this.pinLockout.recordFailedPinAttempt(userId);
    if (state.failedPinAttempts < PIN_LOCKOUT_THRESHOLD) {
      return;
    }

    await this.pinLockout.setPinLockout(userId, {
      failedPinAttempts: state.failedPinAttempts,
      lockedUntil: Date.now() + PIN_LOCKOUT_MS,
    });
    logger.warn(
      `PIN lockout engaged for user ${userId} after ${state.failedPinAttempts} failed attempts`,
      "ChallengeService",
    );
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
   * Generate a random 6-digit PIN for a step-up challenge.
   *
   * This is a third authentication factor, so the source of randomness is a
   * security boundary, not a convenience. The previous implementation used
   * `Math.random()`, which is a non-cryptographic PRNG: its internal state is
   * recoverable from observed outputs, so an attacker able to trigger their own
   * challenges could reconstruct the state and predict the PIN issued to a
   * victim. Every other secret in this file already used `crypto.getRandomValues`.
   *
   * `100000 + x % 900000` is used rather than a direct modulo of a 32-bit draw
   * so the PIN space is exactly 6 digits, and the single rejection below
   * removes the residual modulo bias of mapping 2^32 onto 900000 values.
   */
  private generateRandomPin(): string {
    const MAX = 900_000;
    // Largest multiple of MAX that fits in a uint32; values at or above this
    // are discarded rather than reduced, which is what removes the bias.
    const limit = Math.floor(0x1_0000_0000 / MAX) * MAX;
    for (;;) {
      const draw = crypto.getRandomValues(new Uint32Array(1))[0];
      if (draw < limit) {
        return (100_000 + (draw % MAX)).toString();
      }
    }
  }

  /**
   * Compute HMAC-SHA256 of PIN with salt
   */
  private async computePinHmac(pin: string, saltBase64: string): Promise<string> {
    const salt = base64ToBinary(saltBase64);
    const pinKey = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(pin),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const signature = await crypto.subtle.sign("HMAC", pinKey, this.toArrayBuffer(salt));
    return binaryToBase64(new Uint8Array(signature));
  }

  /**
   * Convert Uint8Array to ArrayBuffer for Web Crypto API
   */
  private toArrayBuffer(data: Uint8Array): ArrayBuffer {
    const buf = new ArrayBuffer(data.byteLength);
    new Uint8Array(buf).set(data);
    return buf;
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
  pinLockout: IPinLockoutStore,
): ChallengeService {
  if (!_challengeService) {
    _challengeService = new ChallengeService(
      challengeRepo,
      emailService,
      baseUrl,
      plusPrivateKeyBase64,
      pinLockout,
    );
  }
  return _challengeService;
}

export function setChallengeService(service: ChallengeService | null): void {
  _challengeService = service;
}