/**
 * Plus Bridge — Core ↔ Plus API Communication
 *
 * HTTP client for Core to communicate with Plus service.
 * Used for: capability requests, entitlement checks, challenge triggers, audit.
 */

import type { CapabilityPayload } from "../crypto/ed25519-capability";
import type { CapabilityOperation } from "../crypto/ed25519-capability";
import type { SignedApproval } from "../crypto/ed25519-approval";
import { logger } from "../../shared/logger";

export interface PlusConfig {
  baseUrl: string;
  serviceSecret: string; // Shared secret for Core↔Plus auth
  timeoutMs: number;
}

export interface CapabilityRequest {
  userId: string;
  resourceId: string;
  operation: CapabilityOperation;
  secretRef: string;
  deviceId?: string;
  assurance: 1 | 2 | 3;
  context?: {
    country?: string;
    ip?: string;
    userAgent?: string;
    timestamp?: number;
  };
}

export interface CapabilityResponse {
  success: boolean;
  capabilityToken?: {
    payload: CapabilityPayload;
    signature: string;
    protectedHeader: string;
  };
  error?: string;
  challengeRequired?: boolean;
  challengeId?: string;
  challengeExpiresAt?: number;
}

export interface EntitlementCheckRequest {
  userId: string;
  resourceId: string;
  operation: CapabilityOperation;
}

export interface EntitlementCheckResponse {
  success: boolean;
  entitlement?: {
    pestilloState: "closed" | "enabled" | "step_up" | "temporary";
    allowedOperations: CapabilityOperation[];
    validFrom?: number;
    validUntil?: number;
  };
  error?: string;
  riskScore?: number;
  riskReasons?: string[];
}

export interface ChallengeTriggerRequest {
  userId: string;
  resourceId: string;
  operation: CapabilityOperation;
  secretRef: string;
  deviceId?: string;
  context: {
    country?: string;
    ip?: string;
    userAgent?: string;
    timestamp: number;
  };
}

export interface ChallengeTriggerResponse {
  success: boolean;
  challengeId?: string;
  challengeExpiresAt?: number;
  error?: string;
}

export interface AuditLogEntry {
  timestamp: number;
  event: string;
  userId: string;
  resourceId?: string;
  operation?: CapabilityOperation;
  decision: "allow" | "deny" | "challenge" | "revoke";
  riskScore?: number;
  riskReasons?: string[];
  context?: Record<string, any>;
}

/**
 * Plus Bridge Client
 * Handles all Core→Plus API communication with retries, circuit breaker, and auth.
 */
export class PlusBridge {
  private config: PlusConfig;
  private circuitOpen = false;
  private circuitOpenTime = 0;
  private readonly CIRCUIT_RESET_MS = 30_000; // 30 seconds
  private failureCount = 0;
  private readonly FAILURE_THRESHOLD = 5;

  constructor(config: PlusConfig) {
    this.config = config;
  }

  /**
   * Make HTTP request to Plus API with auth and error handling
   */
  private async request<T>(
    path: string,
    method: "GET" | "POST" | "PUT" | "DELETE",
    body?: any,
  ): Promise<T> {
    // Check circuit breaker
    if (this.circuitOpen) {
      if (Date.now() - this.circuitOpenTime > this.CIRCUIT_RESET_MS) {
        this.circuitOpen = false;
        this.failureCount = 0;
        logger.info("Plus bridge circuit breaker reset", "PlusBridge");
      } else {
        throw new Error("Plus bridge circuit breaker OPEN");
      }
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.timeoutMs);

    try {
      const response = await fetch(`${this.config.baseUrl}${path}`, {
        method,
        headers: {
          "Content-Type": "application/json",
          "X-Core-Service": "cybervault-core",
          "X-Service-Secret": this.config.serviceSecret,
        },
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Plus API ${response.status}: ${errorText}`);
      }

      const data = await response.json();
      this.failureCount = 0; // Reset on success
      return data;
    } catch (error) {
      clearTimeout(timeoutId);
      this.failureCount++;
      if (this.failureCount >= this.FAILURE_THRESHOLD) {
        this.circuitOpen = true;
        this.circuitOpenTime = Date.now();
        logger.error("Plus bridge circuit breaker OPENED", "PlusBridge", undefined, String(error));
      }
      throw error;
    }
  }

  /**
   * Request a capability token from Plus
   * Plus evaluates entitlement, risk, pestillo state and either:
   * - Returns signed capability token (allow)
   * - Returns challengeRequired=true (step-up needed)
   * - Returns error (deny)
   */
  async requestCapability(request: CapabilityRequest): Promise<CapabilityResponse> {
    return this.request<CapabilityResponse>("/api/v1/capabilities/request", "POST", request);
  }

  /**
   * Check entitlement without requesting capability
   * Used for pre-flight checks
   */
  async checkEntitlement(request: EntitlementCheckRequest): Promise<EntitlementCheckResponse> {
    return this.request<EntitlementCheckResponse>("/api/v1/entitlements/check", "POST", request);
  }

  /**
   * Trigger a step-up challenge via Plus
   *
   * R3: this creates the challenge and returns its id. It no longer sends
   * anything to the user — there is no PIN, and the third factor is now the
   * user's approval, carried by `submitApproval`.
   */
  async triggerChallenge(request: ChallengeTriggerRequest): Promise<ChallengeTriggerResponse> {
    return this.request<ChallengeTriggerResponse>("/api/v1/challenges/trigger", "POST", request);
  }

  /**
   * Submit Core's signed approval so Plus can issue the capability.
   *
   * Replaces `verifyChallenge(challengeId, pin)`. Plus verifies the approval
   * against its pinned Core public key; it is never given a public key from
   * the caller. No secret travels on this call — the approval IS the proof.
   */
  async submitApproval(challengeId: string, approval: SignedApproval, deviceId?: string): Promise<{
    success: boolean;
    capabilityToken?: CapabilityResponse["capabilityToken"];
    error?: string;
  }> {
    return this.request("/api/v1/challenges/approve", "POST", { challengeId, approval, deviceId });
  }

  /**
   * Get Plus public key for capability verification
   * Cached by Core, refreshed periodically
   */
  async getPublicKey(): Promise<{ publicKey: string; keyId: string }> {
    return this.request("/api/v1/crypto/public-key", "GET");
  }

  /**
   * Send audit log entry to Plus
   * Fire-and-forget (best effort)
   */
  async sendAuditLog(entry: AuditLogEntry): Promise<void> {
    try {
      await this.request("/api/v1/audit", "POST", entry);
    } catch (error) {
      // Audit logging failures should not block operations
      logger.warn("Failed to send audit log to Plus", "PlusBridge", { error: String(error) });
    }
  }

  /**
   * Health check for Plus service
   */
  async healthCheck(): Promise<{ status: "healthy" | "degraded" | "unhealthy"; checks: any }> {
    return this.request("/health", "GET");
  }

  /**
   * Check if circuit breaker is open
   */
  isCircuitOpen(): boolean {
    return this.circuitOpen;
  }

  /**
   * Manually reset circuit breaker (for testing/admin)
   */
  resetCircuit(): void {
    this.circuitOpen = false;
    this.failureCount = 0;
  }
}

/**
 * Singleton instance getter (initialized on first use)
 */
let _plusBridge: PlusBridge | null = null;

export function getPlusBridge(config?: PlusConfig): PlusBridge {
  if (!_plusBridge) {
    if (!config) {
      throw new Error("PlusBridge not initialized - provide config on first call");
    }
    _plusBridge = new PlusBridge(config);
  }
  return _plusBridge;
}

export function setPlusBridge(bridge: PlusBridge | null): void {
  _plusBridge = bridge;
}