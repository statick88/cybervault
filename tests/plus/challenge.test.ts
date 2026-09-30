/**
 * Challenge Service Tests — Strict TDD
 *
 * Tests for step-up challenge flow (PIN verification, capability issuance)
 * Following: RED -> GREEN -> REFACTOR
 */

import { ChallengeService, getChallengeService, setChallengeService, ChallengeType, ChallengeStatus, type IPinLockoutStore } from "../../plus/domain/services/challenge";
import { NoOpEmailService } from "../../plus/domain/services/email-service";
import { PlusUser } from "../../plus/domain/entities/user";
import { Resource } from "../../plus/domain/entities/resource";
import { signCapability, createCapabilityPayload, verifyCapability, generateEd25519KeyPair } from "../../src/infrastructure/crypto/ed25519-capability";
import type { CapabilityOperation, SignedCapability } from "../../src/infrastructure/crypto/ed25519-capability";

/**
 * R4 — the per-user failed-PIN lockout store, kept unlocked and empty here.
 * These cases exercise the challenge flow itself, not the lockout; the
 * lockout has its own suite in `tests/unit/plus-pin-lockout.test.ts`.
 */
function emptyLockoutStore(): IPinLockoutStore {
  return {
    getPinLockout: async () => ({ failedPinAttempts: 0, lockedUntil: null }),
    recordFailedPinAttempt: async () => ({ failedPinAttempts: 0, lockedUntil: null }),
    setPinLockout: async () => undefined,
  };
}

describe("ChallengeService", () => {
  let challengeService: ChallengeService;
  let mockChallengeRepo: any;
  let emailService: NoOpEmailService;
  let testUser: PlusUser;
  let testResource: Resource;
  let plusKeyPair: { publicKey: Uint8Array; privateKey: Uint8Array; publicKeyBase64: string; privateKeyBase64: string };

  beforeEach(() => {
    setChallengeService(null);

    // Generate Ed25519 key pair for testing
    plusKeyPair = generateEd25519KeyPair();

    mockChallengeRepo = {
      save: jest.fn().mockImplementation((c) => Promise.resolve(c)),
      findById: jest.fn(),
      findByUserId: jest.fn().mockResolvedValue([]),
      findPendingByUserId: jest.fn().mockResolvedValue([]),
      update: jest.fn().mockImplementation((c) => Promise.resolve(c)),
      delete: jest.fn().mockResolvedValue(true),
      cleanupExpired: jest.fn().mockResolvedValue(0),
    };

    emailService = new NoOpEmailService();

    testUser = PlusUser.create({
      id: "user-123",
      email: "operator@company.com",
      name: "Test Operator",
      role: "operator",
      habitualCountries: ["EC", "US"],
      timezone: "America/Guayaquil",
    });

    testResource = Resource.create({
      id: "db-prod-001",
      name: "Production Database",
      type: "database",
      endpoint: "db01.internal:5432",
      environment: "production",
      criticality: "high",
    });

    challengeService = new ChallengeService(
      mockChallengeRepo,
      emailService,
      "https://plus.example.com",
      plusKeyPair.privateKeyBase64,
      emptyLockoutStore(),
    );
  });

  afterEach(() => {
    setChallengeService(null);
    if (plusKeyPair.privateKey) {
      plusKeyPair.privateKey.fill(0);
    }
  });

  describe("createChallenge", () => {
    test("creates challenge with correct properties", async () => {
      const result = await challengeService.createChallenge({
        userId: testUser.id,
        resourceId: testResource.id,
        operation: "AUTOFILL",
        secretRef: "secret-abc",
        deviceId: "device-xyz",
        type: "risk_based",
        riskScore: 65,
        riskReasons: ["new_country", "new_device"],
      });

      expect(result.challengeId).toBeDefined();
      expect(result.challengeId.length).toBeGreaterThan(10);
      expect(result.expiresAt).toBeGreaterThan(Date.now());

      // Verify repo save was called
      expect(mockChallengeRepo.save).toHaveBeenCalled();
      const savedChallenge = mockChallengeRepo.save.mock.calls[0][0];
      expect(savedChallenge.userId).toBe(testUser.id);
      expect(savedChallenge.resourceId).toBe(testResource.id);
      expect(savedChallenge.operation).toBe("AUTOFILL");
      expect(savedChallenge.type).toBe("risk_based");
      expect(savedChallenge.status).toBe("email_sent");
      expect(savedChallenge.assuranceLevel).toBe(3);
      expect(savedChallenge.maxAttempts).toBe(3);
      expect(savedChallenge.pinHmac).toBeDefined();
      expect(savedChallenge.pinSalt).toBeDefined();
    });

    test("creates STEP_UP challenge with correct type", async () => {
      await challengeService.createChallenge({
        userId: testUser.id,
        resourceId: testResource.id,
        operation: "ADMIN",
        secretRef: "secret-abc",
        type: "step_up",
      });

      const savedChallenge = mockChallengeRepo.save.mock.calls[0][0];
      expect(savedChallenge.type).toBe("step_up");
    });

    test("uses default TTL and maxAttempts when not provided", async () => {
      await challengeService.createChallenge({
        userId: testUser.id,
        resourceId: testResource.id,
        operation: "VIEW",
        secretRef: "secret-abc",
        type: "risk_based",
      });

      const savedChallenge = mockChallengeRepo.save.mock.calls[0][0];
      expect(savedChallenge.expiresAt).toBeGreaterThan(Date.now() + 9 * 60 * 1000); // ~10 min
      expect(savedChallenge.maxAttempts).toBe(3);
    });
  });

  describe("verifyPin", () => {
    let testChallenge: any;

    beforeEach(() => {
      // Create a test challenge with known PIN
      testChallenge = {
        id: "challenge-test-123",
        userId: testUser.id,
        resourceId: testResource.id,
        operation: "AUTOFILL",
        secretRef: "secret-abc",
        deviceId: "device-xyz",
        type: "risk_based",
        status: "email_sent",
        nonce: "test-nonce",
        pinSalt: "c2FsdDEyMw==", // base64 "salt123"
        // HMAC of "123456" with salt "salt123"
        pinHmac: "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3", // SHA256("123456"+"salt123")
        expiresAt: Date.now() + 10 * 60 * 1000,
        attempts: 0,
        maxAttempts: 3,
        assuranceLevel: 3,
        createdAt: Date.now(),
        updatedAt: Date.now(),
      };
    });

    test("verifies correct PIN and returns capability token", async () => {
      mockChallengeRepo.findById.mockResolvedValue(testChallenge);

      // We need to create a real challenge with computable PIN HMAC
      // For this test, we'll mock the computePinHmac to return expected HMAC
      const service = new ChallengeService(
        mockChallengeRepo,
        emailService,
        "https://plus.example.com",
        plusKeyPair.privateKeyBase64,
        emptyLockoutStore(),
      );

      // Create a real challenge with known PIN "123456"
      const pin = "123456";
      const salt = crypto.getRandomValues(new Uint8Array(32));
      const pinKey = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(pin),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"],
      );
      const pinHmac = await crypto.subtle.sign("HMAC", pinKey, salt);
      const pinHmacBase64 = btoa(String.fromCharCode(...new Uint8Array(pinHmac)));
      const pinSaltBase64 = btoa(String.fromCharCode(...salt));

      const realChallenge = {
        ...testChallenge,
        pinHmac: pinHmacBase64,
        pinSalt: pinSaltBase64,
      };

      mockChallengeRepo.findById.mockResolvedValue(realChallenge);
      mockChallengeRepo.update.mockResolvedValue({ ...realChallenge, status: "completed" });

      // Mock signCapability to return a valid capability
      const capabilityPayload = createCapabilityPayload({
        userId: testUser.id,
        resourceId: testResource.id,
        operation: "AUTOFILL",
        secretRef: "secret-abc",
        assurance: 3,
      });
      const signedCapability = await signCapability(capabilityPayload, plusKeyPair.privateKey);

      // Temporarily replace signCapability
      // Temporarily replace signCapability
      jest.spyOn(require("../../src/infrastructure/crypto/ed25519-capability"), "signCapability")
        .mockResolvedValue(signedCapability);

      const result = await service.verifyPin({
        challengeId: realChallenge.id,
        pin: "123456",
        deviceId: "device-xyz",
      });

      expect(result.success).toBe(true);
      expect(result.capabilityToken).toBeDefined();
      expect(result.capabilityToken!.payload.userId).toBe(testUser.id);
      expect(result.capabilityToken!.payload.operation).toBe("AUTOFILL");
      expect(result.capabilityToken!.payload.assurance).toBe(3);

      jest.restoreAllMocks();
    });

    test("rejects invalid PIN", async () => {
      const pin = "123456";
      const salt = crypto.getRandomValues(new Uint8Array(32));
      const pinKey = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(pin),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"],
      );
      const pinHmac = await crypto.subtle.sign("HMAC", pinKey, salt);
      const pinHmacBase64 = btoa(String.fromCharCode(...new Uint8Array(pinHmac)));
      const pinSaltBase64 = btoa(String.fromCharCode(...salt));

      const realChallenge = {
        ...testChallenge,
        pinHmac: pinHmacBase64,
        pinSalt: pinSaltBase64,
      };

      mockChallengeRepo.findById.mockResolvedValue(realChallenge);
      mockChallengeRepo.update.mockResolvedValue({ ...realChallenge, attempts: 1 });

      const service = new ChallengeService(
        mockChallengeRepo,
        emailService,
        "https://plus.example.com",
        plusKeyPair.privateKeyBase64,
        emptyLockoutStore(),
      );

      const result = await service.verifyPin({
        challengeId: realChallenge.id,
        pin: "654321", // Wrong PIN
        deviceId: "device-xyz",
      });

      expect(result.success).toBe(false);
      expect(result.error).toBe("Invalid PIN");
      expect(result.attemptsRemaining).toBe(2);
    });

    test("rejects expired challenge", async () => {
      const expiredChallenge = {
        ...testChallenge,
        expiresAt: Date.now() - 1000, // Already expired
      };
      mockChallengeRepo.findById.mockResolvedValue(expiredChallenge);

      const service = new ChallengeService(
        mockChallengeRepo,
        emailService,
        "https://plus.example.com",
        plusKeyPair.privateKeyBase64,
        emptyLockoutStore(),
      );

      const result = await service.verifyPin({
        challengeId: expiredChallenge.id,
        pin: "123456",
      });

      expect(result.success).toBe(false);
      expect(result.error).toBe("Challenge expired");
    });

    test("rejects challenge with max attempts exceeded", async () => {
      const maxedChallenge = {
        ...testChallenge,
        attempts: 3,
        maxAttempts: 3,
      };
      mockChallengeRepo.findById.mockResolvedValue(maxedChallenge);

      const service = new ChallengeService(
        mockChallengeRepo,
        emailService,
        "https://plus.example.com",
        plusKeyPair.privateKeyBase64,
        emptyLockoutStore(),
      );

      const result = await service.verifyPin({
        challengeId: maxedChallenge.id,
        pin: "123456",
      });

      expect(result.success).toBe(false);
      expect(result.error).toBe("Maximum attempts exceeded");
    });

    test("rejects challenge in invalid state", async () => {
      const completedChallenge = {
        ...testChallenge,
        status: "completed",
      };
      mockChallengeRepo.findById.mockResolvedValue(completedChallenge);

      const service = new ChallengeService(
        mockChallengeRepo,
        emailService,
        "https://plus.example.com",
        plusKeyPair.privateKeyBase64,
        emptyLockoutStore(),
      );

      const result = await service.verifyPin({
        challengeId: completedChallenge.id,
        pin: "123456",
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain("not in valid state");
    });
  });

  describe("getChallenge / getPendingChallenges", () => {
    test("getChallenge returns challenge by ID", async () => {
      const testChallenge = { id: "challenge-123" };
      mockChallengeRepo.findById.mockResolvedValue(testChallenge);

      const result = await challengeService.getChallenge("challenge-123");
      expect(result).toEqual(testChallenge);
    });

    test("getPendingChallenges returns user's pending challenges", async () => {
      const pendingChallenges = [{ id: "c1" }, { id: "c2" }];
      mockChallengeRepo.findPendingByUserId.mockResolvedValue(pendingChallenges);

      const result = await challengeService.getPendingChallenges(testUser.id);
      expect(result).toEqual(pendingChallenges);
    });
  });

  describe("Singleton", () => {
    test("getChallengeService returns singleton", () => {
      setChallengeService(null);
      const s1 = getChallengeService(mockChallengeRepo, emailService, "https://plus.example.com", plusKeyPair.privateKeyBase64, emptyLockoutStore());
      const s2 = getChallengeService(mockChallengeRepo, emailService, "https://plus.example.com", plusKeyPair.privateKeyBase64, emptyLockoutStore());
      expect(s1).toBe(s2);
    });

    test("setChallengeService replaces singleton", () => {
      const s1 = new ChallengeService(mockChallengeRepo, emailService, "https://plus.example.com", plusKeyPair.privateKeyBase64, emptyLockoutStore());
      setChallengeService(s1);
      const s2 = getChallengeService(mockChallengeRepo, emailService, "https://plus.example.com", plusKeyPair.privateKeyBase64, emptyLockoutStore());
      expect(s2).toBe(s1);
    });
  });
});