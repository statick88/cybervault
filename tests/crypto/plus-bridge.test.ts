/**
 * Plus Bridge Tests — Strict TDD
 *
 * Tests for Core↔Plus API communication
 * Following: RED -> GREEN -> REFACTOR
 */

import { PlusBridge, PlusConfig, getPlusBridge, setPlusBridge } from "../../src/infrastructure/plus/plus-bridge";
import type { CapabilityOperation } from "../../src/infrastructure/crypto/ed25519-capability";

// Mock fetch globally
global.fetch = jest.fn();

describe("PlusBridge", () => {
  let bridge: PlusBridge;
  const mockConfig: PlusConfig = {
    baseUrl: "http://plus:3001",
    serviceSecret: "test-secret",
    timeoutMs: 5000,
  };

  beforeEach(() => {
    jest.clearAllMocks();
    setPlusBridge(null); // Reset singleton
    bridge = new PlusBridge(mockConfig);
    (global.fetch as jest.Mock).mockReset();
  });

  afterEach(() => {
    setPlusBridge(null);
  });

  describe("constructor", () => {
    test("creates instance with config", () => {
      expect(bridge).toBeInstanceOf(PlusBridge);
    });
  });

  describe("requestCapability", () => {
    test("sends POST request with correct payload", async () => {
      const mockResponse = {
        success: true,
        capabilityToken: {
          payload: { issuer: "cybervault-plus" },
          signature: "sig",
          protectedHeader: "header",
        },
      };
      (global.fetch as jest.Mock).mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      });

      const request = {
        userId: "user-123",
        resourceId: "db-prod-001",
        operation: "AUTOFILL" as CapabilityOperation,
        secretRef: "secret-abc",
        assurance: 2 as const,
      };

      const result = await bridge.requestCapability(request);

      expect(global.fetch).toHaveBeenCalledWith(
        "http://plus:3001/api/v1/capabilities/request",
        expect.objectContaining({
          method: "POST",
          headers: expect.objectContaining({
            "Content-Type": "application/json",
            "X-Core-Service": "cybervault-core",
            "X-Service-Secret": "test-secret",
          }),
          body: JSON.stringify(request),
        }),
      );
      expect(result).toEqual(mockResponse);
    });

    test("includes optional deviceId and context", async () => {
      (global.fetch as jest.Mock).mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ success: true }),
      });

      const request = {
        userId: "user-123",
        resourceId: "db-prod-001",
        operation: "VIEW" as CapabilityOperation,
        secretRef: "secret-abc",
        assurance: 1 as const,
        deviceId: "device-xyz",
        context: { country: "US", ip: "1.2.3.4" },
      };

      await bridge.requestCapability(request);

      const callBody = JSON.parse((global.fetch as jest.Mock).mock.calls[0][1].body);
      expect(callBody.deviceId).toBe("device-xyz");
      expect(callBody.context.country).toBe("US");
    });

    test("throws on HTTP error", async () => {
      (global.fetch as jest.Mock).mockResolvedValue({
        ok: false,
        status: 403,
        text: () => Promise.resolve("Forbidden"),
      });

      await expect(
        bridge.requestCapability({
          userId: "user-123",
          resourceId: "db-prod-001",
          operation: "AUTOFILL" as CapabilityOperation,
          secretRef: "secret-abc",
          assurance: 2 as const,
        }),
      ).rejects.toThrow("Plus API 403: Forbidden");
    });

    test("handles network timeout", async () => {
      (global.fetch as jest.Mock).mockImplementation(() => {
        return new Promise((_, reject) => {
          setTimeout(() => reject(new Error("AbortError")), 100);
        });
      });

      await expect(
        bridge.requestCapability({
          userId: "user-123",
          resourceId: "db-prod-001",
          operation: "AUTOFILL" as CapabilityOperation,
          secretRef: "secret-abc",
          assurance: 2 as const,
        }),
      ).rejects.toThrow();
    });
  });

  describe("checkEntitlement", () => {
    test("sends GET request with correct params", async () => {
      const mockResponse = {
        success: true,
        entitlement: {
          pestilloState: "enabled",
          allowedOperations: ["VIEW", "AUTOFILL"],
        },
      };
      (global.fetch as jest.Mock).mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      });

      const result = await bridge.checkEntitlement({
        userId: "user-123",
        resourceId: "db-prod-001",
        operation: "VIEW",
      });

      expect(global.fetch).toHaveBeenCalledWith(
        "http://plus:3001/api/v1/entitlements/check",
        expect.objectContaining({ method: "POST" }),
      );
      expect(result).toEqual(mockResponse);
    });

    test("returns risk score and reasons", async () => {
      const mockResponse = {
        success: true,
        entitlement: {
          pestilloState: "step_up",
          allowedOperations: ["VIEW"],
        },
        riskScore: 75,
        riskReasons: ["new_country", "outside_business_hours"],
      };
      (global.fetch as jest.Mock).mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      });

      const result = await bridge.checkEntitlement({
        userId: "user-123",
        resourceId: "db-prod-001",
        operation: "AUTOFILL",
      });

      expect(result.riskScore).toBe(75);
      expect(result.riskReasons).toContain("new_country");
    });
  });

  describe("triggerChallenge", () => {
    test("sends challenge request with context", async () => {
      const mockResponse = {
        success: true,
        challengeId: "challenge-123",
        challengeExpiresAt: Date.now() + 300000,
      };
      (global.fetch as jest.Mock).mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      });

      const result = await bridge.triggerChallenge({
        userId: "user-123",
        resourceId: "db-prod-001",
        operation: "AUTOFILL",
        secretRef: "secret-abc",
        deviceId: "device-xyz",
        context: { country: "US", ip: "1.2.3.4", userAgent: "Chrome", timestamp: Date.now() },
      });

      expect(result.challengeId).toBe("challenge-123");
      expect(result.challengeExpiresAt).toBeDefined();
    });
  });

  describe("verifyChallenge", () => {
    test("verifies PIN and returns capability token", async () => {
      const mockResponse = {
        success: true,
        capabilityToken: {
          payload: { issuer: "cybervault-plus" },
          signature: "sig",
          protectedHeader: "header",
        },
      };
      (global.fetch as jest.Mock).mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      });

      // R3: no PIN. The caller forwards Core's signed approval, and Plus
      // verifies it against its pinned key.
      const approval = {
        payload: { typ: "step-up-approval", challengeId: "challenge-123" },
        signature: "sig",
        protectedHeader: "header",
      };

      const result = await bridge.submitApproval("challenge-123", approval as never, "device-xyz");

      expect(global.fetch).toHaveBeenCalledWith(
        "http://plus:3001/api/v1/challenges/approve",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({
            challengeId: "challenge-123",
            approval,
            deviceId: "device-xyz",
          }),
        }),
      );
      // The body must not carry a PIN field, whatever else changes.
      const body = JSON.parse(
        (global.fetch as jest.Mock).mock.calls[0][1].body as string,
      );
      expect(body).not.toHaveProperty("pin");
      expect(result.capabilityToken).toBeDefined();
    });
  });

  describe("getPublicKey", () => {
    test("fetches Ed25519 public key from Plus", async () => {
      const mockResponse = { publicKey: "base64-key", keyId: "key-1" };
      (global.fetch as jest.Mock).mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      });

      const result = await bridge.getPublicKey();

      expect(global.fetch).toHaveBeenCalledWith(
        "http://plus:3001/api/v1/crypto/public-key",
        expect.objectContaining({ method: "GET" }),
      );
      expect(result.publicKey).toBe("base64-key");
    });
  });

  describe("sendAuditLog", () => {
    test("sends audit entry (fire-and-forget)", async () => {
      (global.fetch as jest.Mock).mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({}),
      });

      await bridge.sendAuditLog({
        timestamp: Date.now(),
        event: "capability_requested",
        userId: "user-123",
        resourceId: "db-prod-001",
        operation: "AUTOFILL",
        decision: "allow",
        riskScore: 10,
      });

      expect(global.fetch).toHaveBeenCalledWith(
        "http://plus:3001/api/v1/audit",
        expect.objectContaining({ method: "POST" }),
      );
    });

    test("does not throw on failure", async () => {
      (global.fetch as jest.Mock).mockRejectedValue(new Error("Network error"));

      // Should not throw
      await expect(
        bridge.sendAuditLog({
          timestamp: Date.now(),
          event: "test",
          userId: "user-123",
          decision: "allow",
        }),
      ).resolves.toBeUndefined();
    });
  });

  describe("healthCheck", () => {
    test("returns Plus health status", async () => {
      const mockResponse = { status: "healthy", checks: { database: "ok" } };
      (global.fetch as jest.Mock).mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockResponse),
      });

      const result = await bridge.healthCheck();
      expect(result.status).toBe("healthy");
    });
  });

  describe("circuit breaker", () => {
    test("opens after threshold failures", async () => {
      (global.fetch as jest.Mock).mockRejectedValue(new Error("Connection refused"));

      // Make 5 failing requests
      for (let i = 0; i < 5; i++) {
        try {
          await bridge.requestCapability({
            userId: "user-123",
            resourceId: "db-prod-001",
            operation: "AUTOFILL" as CapabilityOperation,
            secretRef: "secret-abc",
            assurance: 2 as const,
          });
        } catch {
          // Expected to fail
        }
      }

      // 6th request should fail fast due to circuit breaker
      await expect(
        bridge.requestCapability({
          userId: "user-123",
          resourceId: "db-prod-001",
          operation: "AUTOFILL" as CapabilityOperation,
          secretRef: "secret-abc",
          assurance: 2 as const,
        }),
      ).rejects.toThrow("Plus bridge circuit breaker OPEN");
    });

    test("resets after timeout", async () => {
      // Manually open circuit
      (bridge as any).circuitOpen = true;
      (bridge as any).circuitOpenTime = Date.now() - 40000; // Older than reset time

      (global.fetch as jest.Mock).mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ success: true }),
      });

      // Should succeed after reset
      const result = await bridge.requestCapability({
        userId: "user-123",
        resourceId: "db-prod-001",
        operation: "AUTOFILL" as CapabilityOperation,
        secretRef: "secret-abc",
        assurance: 2 as const,
      });
      expect(result.success).toBe(true);
    });

    test("isCircuitOpen returns state", () => {
      expect(bridge.isCircuitOpen()).toBe(false);
      (bridge as any).circuitOpen = true;
      expect(bridge.isCircuitOpen()).toBe(true);
    });

    test("resetCircuit clears state", () => {
      (bridge as any).circuitOpen = true;
      (bridge as any).failureCount = 10;
      bridge.resetCircuit();
      expect(bridge.isCircuitOpen()).toBe(false);
    });
  });

  describe("singleton", () => {
    test("getPlusBridge returns singleton", () => {
      setPlusBridge(null);
      const b1 = getPlusBridge(mockConfig);
      const b2 = getPlusBridge(mockConfig);
      expect(b1).toBe(b2);
    });

    test("throws if not initialized", () => {
      setPlusBridge(null);
      expect(() => getPlusBridge()).toThrow("PlusBridge not initialized");
    });

    test("setPlusBridge replaces instance", () => {
      const b1 = new PlusBridge(mockConfig);
      setPlusBridge(b1);
      const b2 = getPlusBridge(mockConfig);
      expect(b2).toBe(b1);
    });
  });
});