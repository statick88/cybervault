/**
 * Capability Issuer Service — Ed25519 Capability Token Signing for CyberVault Plus
 *
 * Dedicated service for issuing cryptographically signed capability tokens.
 * Plus holds the private signing key; Core holds the public verification key.
 *
 * Capability token structure (signed payload):
 * {
 *   issuer: "cybervault-plus",
 *   audience: "cybervault-core",
 *   userId: string,
 *   resourceId: string,
 *   operation: CapabilityOperation,
 *   secretRef: string,
 *   deviceId?: string,
 *   assurance: 1 | 2 | 3,
 *   iat: number,
 *   exp: number,
 *   jti: string, // Unique one-time identifier
 *   version: 1
 * }
 */

import { logger } from "@/shared/logger";
import { binaryToBase64 } from "@/shared/utils";
import type { CapabilityOperation, CapabilityPayload, SignedCapability } from "@/infrastructure/crypto/ed25519-capability";
import { signCapability, createCapabilityPayload, verifyCapability, loadEd25519PrivateKey, loadEd25519PublicKey, DEFAULT_CAPABILITY_TTL_SECONDS, MAX_CAPABILITY_TTL_SECONDS } from "@/infrastructure/crypto/ed25519-capability";
import { verifyAndConsumeJti } from "@/infrastructure/crypto/jti-store";

/** Capability issuance request */
export interface CapabilityIssueRequest {
  userId: string;
  resourceId: string;
  operation: CapabilityOperation;
  secretRef: string;
  deviceId?: string;
  assurance: 1 | 2 | 3;
  ttlSeconds?: number; // Default: 300 (5 min), Max: 3600 (1 hour)
  context?: {
    riskScore?: number;
    riskReasons?: string[];
    challengeId?: string;
  };
}

/** Capability issuance result */
export interface CapabilityIssueResult {
  success: boolean;
  capabilityToken?: SignedCapability;
  error?: string;
  expiresAt?: number;
}

/** Capability verification request (for Core → Plus verification) */
export interface CapabilityVerifyRequest {
  capabilityToken: SignedCapability;
  plusPublicKeyBase64: string;
}

/** Capability verification result */
export interface CapabilityVerifyResult {
  valid: boolean;
  error?: string;
  payload?: CapabilityPayload;
}

/** Capability Issuer Service */
export class CapabilityIssuer {
  private privateKey: Uint8Array; // 64 bytes (seed + public)
  private publicKey: Uint8Array; // 32 bytes
  private defaultTtlSeconds: number;
  private maxTtlSeconds: number;

  constructor(
    privateKeyBase64: string,
    options: {
      defaultTtlSeconds?: number;
      maxTtlSeconds?: number;
    } = {},
  ) {
    this.privateKey = loadEd25519PrivateKey(privateKeyBase64);
    this.publicKey = this.privateKey.slice(32); // Last 32 bytes = public key
    this.defaultTtlSeconds = options.defaultTtlSeconds ?? DEFAULT_CAPABILITY_TTL_SECONDS;
    this.maxTtlSeconds = options.maxTtlSeconds ?? MAX_CAPABILITY_TTL_SECONDS;

    logger.info("CapabilityIssuer initialized", "CapabilityIssuer", {
      publicKey: binaryToBase64(this.publicKey).substring(0, 16) + "...",
      defaultTtl: this.defaultTtlSeconds,
      maxTtl: this.maxTtlSeconds,
    });
  }

  /**
   * Issue a new capability token
   */
  async issue(request: CapabilityIssueRequest): Promise<CapabilityIssueResult> {
    const ttl = request.ttlSeconds ?? this.defaultTtlSeconds;

    if (ttl > this.maxTtlSeconds) {
      return {
        success: false,
        error: `TTL exceeds maximum of ${this.maxTtlSeconds} seconds`,
      };
    }

    if (ttl < 60) {
      return {
        success: false,
        error: "TTL must be at least 60 seconds",
      };
    }

    try {
      // Create capability payload
      const payload = createCapabilityPayload({
        userId: request.userId,
        resourceId: request.resourceId,
        operation: request.operation,
        secretRef: request.secretRef,
        deviceId: request.deviceId,
        assurance: request.assurance,
        ttlSeconds: ttl,
      });

      // Add context if provided
      if (request.context) {
        (payload as any).context = request.context;
      }

      // Sign the capability
      const signedCapability = await signCapability(payload, this.privateKey);

      // Verify our own signature (defense in depth)
      const verifyResult = await verifyCapability(signedCapability, this.publicKey);
      if (!verifyResult.valid) {
        logger.error("Self-verification of issued capability failed", "CapabilityIssuer");
        return {
          success: false,
          error: "Internal error: capability signing verification failed",
        };
      }

      logger.info("Capability issued", "CapabilityIssuer", {
        userId: request.userId,
        resourceId: request.resourceId,
        operation: request.operation,
        assurance: request.assurance,
        jti: payload.jti,
        ttl,
      });

      return {
        success: true,
        capabilityToken: signedCapability,
        expiresAt: payload.exp * 1000, // Convert to ms
      };
    } catch (error) {
      logger.error("Capability issuance failed", "CapabilityIssuer", undefined, String(error));
      return {
        success: false,
        error: error instanceof Error ? error.message : "Unknown error",
      };
    }
  }

  /**
   * Verify a capability token (for Core or internal validation)
   */
  async verify(capabilityToken: SignedCapability, publicKeyBase64?: string): Promise<CapabilityVerifyResult> {
    const pubKey = publicKeyBase64
      ? loadEd25519PublicKey(publicKeyBase64)
      : this.publicKey;

    const result = await verifyCapability(capabilityToken, pubKey);

    if (!result.valid) {
      return { valid: false, error: result.error };
    }

    // The payload is already decoded in the signed capability
    return { valid: true, payload: capabilityToken.payload };
  }

  /**
   * Get public key for distribution to Core
   */
  getPublicKey(): string {
    return binaryToBase64(this.publicKey);
  }

  /**
   * Get public key as JWK for interoperability
   */
  getPublicKeyJwk(): string {
    // Convert raw public key to JWK format
    const jwk = {
      kty: "OKP",
      crv: "Ed25519",
      x: binaryToBase64(this.publicKey),
      alg: "EdDSA",
      use: "sig",
      kid: "cybervault-plus-capability-v1",
    };
    return JSON.stringify(jwk);
  }

  /**
   * Issue capability for step-up completion (assurance 3)
   */
  async issueStepUpCapability(params: {
    userId: string;
    resourceId: string;
    operation: CapabilityOperation;
    secretRef: string;
    deviceId?: string;
    challengeId: string;
    ttlSeconds?: number;
  }): Promise<CapabilityIssueResult> {
    return this.issue({
      userId: params.userId,
      resourceId: params.resourceId,
      operation: params.operation,
      secretRef: params.secretRef,
      deviceId: params.deviceId,
      assurance: 3, // Step-up = assurance level 3
      ttlSeconds: params.ttlSeconds,
      context: {
        challengeId: params.challengeId,
      },
    });
  }

  /**
   * Issue capability for risk-based access (assurance 2)
   */
  async issueRiskBasedCapability(params: {
    userId: string;
    resourceId: string;
    operation: CapabilityOperation;
    secretRef: string;
    deviceId?: string;
    riskScore: number;
    riskReasons: string[];
    ttlSeconds?: number;
  }): Promise<CapabilityIssueResult> {
    return this.issue({
      userId: params.userId,
      resourceId: params.resourceId,
      operation: params.operation,
      secretRef: params.secretRef,
      deviceId: params.deviceId,
      assurance: 2, // Risk-based = assurance level 2
      ttlSeconds: params.ttlSeconds,
      context: {
        riskScore: params.riskScore,
        riskReasons: params.riskReasons,
      },
    });
  }

  /**
   * Issue capability for direct access (assurance 1)
   */
  async issueDirectCapability(params: {
    userId: string;
    resourceId: string;
    operation: CapabilityOperation;
    secretRef: string;
    deviceId?: string;
    ttlSeconds?: number;
  }): Promise<CapabilityIssueResult> {
    return this.issue({
      userId: params.userId,
      resourceId: params.resourceId,
      operation: params.operation,
      secretRef: params.secretRef,
      deviceId: params.deviceId,
      assurance: 1, // Direct = assurance level 1
      ttlSeconds: params.ttlSeconds,
    });
  }
}

/** Singleton getter */
let _capabilityIssuer: CapabilityIssuer | null = null;

export function getCapabilityIssuer(
  privateKeyBase64: string,
  options?: { defaultTtlSeconds?: number; maxTtlSeconds?: number },
): CapabilityIssuer {
  if (!_capabilityIssuer) {
    _capabilityIssuer = new CapabilityIssuer(privateKeyBase64, options);
  }
  return _capabilityIssuer;
}

export function setCapabilityIssuer(issuer: CapabilityIssuer | null): void {
  _capabilityIssuer = issuer;
}

/**
 * Core-side capability verification (Core calls this to verify Plus-issued tokens)
 */
export async function verifyCapabilityCore(
  capabilityToken: any,
  plusPublicKeyBase64: string,
): Promise<CapabilityVerifyResult> {
  const publicKey = loadEd25519PublicKey(plusPublicKeyBase64);
  const result = await verifyCapability(capabilityToken, publicKey);

  if (!result.valid) {
    return { valid: false, error: result.error };
  }

  // The payload is already decoded in the signed capability
  return { valid: true, payload: capabilityToken.payload };
}

/**
 * Consume JTI atomically (Core calls this after verifying capability)
 */
export async function consumeCapabilityJti(
  jti: string,
  ttlSeconds: number,
): Promise<{ allowed: boolean; error?: string }> {
  const result = await verifyAndConsumeJti(jti, ttlSeconds);
  return result;
}