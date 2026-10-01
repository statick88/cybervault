/**
 * Challenge Service Tests — Strict TDD
 *
 * Tests for the step-up challenge flow: challenge creation and the R3 signed
 * approval that replaces the retired PIN.
 * Following: RED -> GREEN -> REFACTOR
 */

import {
  ChallengeService,
  getChallengeService,
  setChallengeService,
} from "../../plus/domain/services/challenge";
import { NoOpEmailService } from "../../plus/domain/services/email-service";
import { PlusUser } from "../../plus/domain/entities/user";
import { Resource } from "../../plus/domain/entities/resource";
import {
  generateEd25519KeyPair,
  loadEd25519PublicKey,
  verifyCapability,
} from "../../src/infrastructure/crypto/ed25519-capability";
import {
  APPROVAL_VERSION,
  CORE_APPROVAL_PUBLIC_KEY_ENV,
  generateApprovalKeyPair,
  loadApprovalPrivateKey,
  signApproval,
  type ApprovalPayload,
  type Ed25519ApprovalKeyPair,
  type SignedApproval,
} from "../../src/infrastructure/crypto/ed25519-approval";

describe("ChallengeService", () => {
  let challengeService: ChallengeService;
  let mockChallengeRepo: any;
  let emailService: NoOpEmailService;
  let testUser: PlusUser;
  let testResource: Resource;
  let plusKeyPair: { publicKey: Uint8Array; privateKey: Uint8Array; publicKeyBase64: string; privateKeyBase64: string };
  /** Core's approval key pair. Its PUBLIC half is what Plus pins. */
  let coreKeyPair: Ed25519ApprovalKeyPair;
  let previousPinnedKey: string | undefined;

  /**
   * Build an approval the way Core's `POST /api/v1/step-up/approve` does:
   * every binding field taken from the STORED challenge, a fresh `jti`, and a
   * short TTL. `overrides` exists so a case can forge a field without having
   * to reimplement the encoding.
   */
  function approvalFor(
    challenge: {
      id: string;
      userId: string;
      resourceId: string;
      operation: string;
      secretRef: string;
    },
    overrides: Partial<ApprovalPayload> = {},
    signer: Ed25519ApprovalKeyPair = coreKeyPair,
  ): Promise<SignedApproval> {
    const iat = Math.floor(Date.now() / 1000);
    return signApproval(
      {
        version: APPROVAL_VERSION,
        typ: "step-up-approval",
        challengeId: challenge.id,
        userId: challenge.userId,
        resourceId: challenge.resourceId,
        operation: challenge.operation as ApprovalPayload["operation"],
        secretRef: challenge.secretRef,
        iat,
        exp: iat + 300,
        jti: crypto.randomUUID(),
        ...overrides,
      },
      // `signApproval` takes the 64-byte (seed || public) form.
      loadApprovalPrivateKey(signer.privateKeyBase64),
    );
  }

  beforeEach(() => {
    setChallengeService(null);

    // Generate Ed25519 key pair for testing
    plusKeyPair = generateEd25519KeyPair();
    coreKeyPair = generateApprovalKeyPair();
    previousPinnedKey = process.env[CORE_APPROVAL_PUBLIC_KEY_ENV];
    process.env[CORE_APPROVAL_PUBLIC_KEY_ENV] = coreKeyPair.publicKeyBase64;

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
    );
  });

  afterEach(() => {
    setChallengeService(null);
    if (previousPinnedKey === undefined) {
      delete process.env[CORE_APPROVAL_PUBLIC_KEY_ENV];
    } else {
      process.env[CORE_APPROVAL_PUBLIC_KEY_ENV] = previousPinnedKey;
    }
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

    /**
     * R3 — the PIN is gone, not merely hidden.
     *
     * The original defect was that `createChallenge` generated a PIN, kept the
     * HMAC, and stashed the plaintext in `metadata.generatedPin` where a fake
     * test repository could read it back. This case is the regression guard:
     * the stored record must contain no `pinHmac`, no `pinSalt`, and no
     * plaintext PIN anywhere in its JSON.
     */
    test("stores no PIN material anywhere in the record", async () => {
      await challengeService.createChallenge({
        userId: testUser.id,
        resourceId: testResource.id,
        operation: "AUTOFILL",
        secretRef: "secret-abc",
        type: "risk_based",
      });

      const savedChallenge = mockChallengeRepo.save.mock.calls[0][0];
      expect(savedChallenge).not.toHaveProperty("pinHmac");
      expect(savedChallenge).not.toHaveProperty("pinSalt");
      expect(savedChallenge.metadata?.generatedPin).toBeUndefined();
      expect(savedChallenge.metadata).toBeUndefined();

      const serialized = JSON.stringify(savedChallenge);
      expect(serialized).not.toContain("pinHmac");
      expect(serialized).not.toContain("pinSalt");
      expect(serialized).not.toContain("generatedPin");
      expect(serialized).not.toContain("pin");
      // A 6-digit run would be a generated PIN hiding in a free-form field.
      expect(serialized).not.toMatch(/\b\d{6}\b/);
    });
  });

  describe("verifyApproval", () => {
    /** A challenge waiting for proof, stored under its own id. */
    function outstandingChallenge(overrides: Record<string, unknown> = {}) {
      const now = Date.now();
      return {
        id: "challenge-test-123",
        userId: testUser.id,
        resourceId: testResource.id,
        operation: "AUTOFILL",
        secretRef: "secret-abc",
        deviceId: "device-xyz",
        type: "risk_based",
        status: "email_sent",
        nonce: "test-nonce",
        expiresAt: now + 10 * 60 * 1000,
        attempts: 0,
        maxAttempts: 3,
        assuranceLevel: 3,
        createdAt: now,
        updatedAt: now,
        ...overrides,
      };
    }

    test("accepts an approval Core signed for this challenge and returns a capability", async () => {
      const challenge = outstandingChallenge();
      mockChallengeRepo.findById.mockResolvedValue(challenge);

      const approval = await approvalFor(challenge);
      const result = await challengeService.verifyApproval({
        challengeId: challenge.id,
        approval,
        deviceId: "device-xyz",
      });

      expect(result.success).toBe(true);
      expect(result.capabilityToken).toBeDefined();
      expect(result.capabilityToken!.payload.userId).toBe(testUser.id);
      expect(result.capabilityToken!.payload.resourceId).toBe(testResource.id);
      expect(result.capabilityToken!.payload.operation).toBe("AUTOFILL");
      expect(result.capabilityToken!.payload.assurance).toBe(3);

      // And it verifies against the public half of the SAME key the server
      // publishes — the single-signing-key property from the route fix.
      const verification = await verifyCapability(
        result.capabilityToken!,
        loadEd25519PublicKey(plusKeyPair.publicKeyBase64),
      );
      expect(verification.valid).toBe(true);

      expect(challenge.status).toBe("completed");
      expect(mockChallengeRepo.update).toHaveBeenCalled();
    });

    test("refuses an unknown challenge", async () => {
      mockChallengeRepo.findById.mockResolvedValue(null);

      const result = await challengeService.verifyApproval({
        challengeId: "challenge-does-not-exist",
        approval: await approvalFor(outstandingChallenge()),
      });

      expect(result.success).toBe(false);
      expect(result.error).toBe("Challenge not found");
      expect(result.capabilityToken).toBeUndefined();
    });

    test("refuses a challenge that is no longer outstanding", async () => {
      const challenge = outstandingChallenge({ status: "completed" });
      mockChallengeRepo.findById.mockResolvedValue(challenge);

      const result = await challengeService.verifyApproval({
        challengeId: challenge.id,
        approval: await approvalFor(challenge),
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain("not in valid state");
      expect(result.capabilityToken).toBeUndefined();
    });

    test("refuses an expired challenge and marks it expired", async () => {
      const challenge = outstandingChallenge({ expiresAt: Date.now() - 1000 });
      mockChallengeRepo.findById.mockResolvedValue(challenge);

      const result = await challengeService.verifyApproval({
        challengeId: challenge.id,
        approval: await approvalFor(challenge),
      });

      expect(result.success).toBe(false);
      expect(result.error).toBe("Challenge expired");
      expect(result.capabilityToken).toBeUndefined();
      expect(challenge.status).toBe("expired");
      expect(mockChallengeRepo.update).toHaveBeenCalled();
    });

    test("refuses to verify at all when the pinned Core public key is not configured", async () => {
      delete process.env[CORE_APPROVAL_PUBLIC_KEY_ENV];
      const challenge = outstandingChallenge();
      mockChallengeRepo.findById.mockResolvedValue(challenge);

      const result = await challengeService.verifyApproval({
        challengeId: challenge.id,
        approval: await approvalFor(challenge),
      });

      expect(result.success).toBe(false);
      expect(result.error).toBe("Core approval public key is not configured");
      expect(result.capabilityToken).toBeUndefined();
      // Fail closed: nothing was consumed, nothing was signed.
      expect(challenge.status).toBe("email_sent");
    });

    test("refuses a pinned Core public key that is malformed", async () => {
      process.env[CORE_APPROVAL_PUBLIC_KEY_ENV] = "not a key";
      const challenge = outstandingChallenge();
      mockChallengeRepo.findById.mockResolvedValue(challenge);

      const result = await challengeService.verifyApproval({
        challengeId: challenge.id,
        approval: await approvalFor(challenge),
      });

      expect(result.success).toBe(false);
      expect(result.error).toBe("Core approval public key is not configured");
    });

    test("refuses an approval signed by any key other than the pinned one", async () => {
      const challenge = outstandingChallenge();
      mockChallengeRepo.findById.mockResolvedValue(challenge);
      const impostor = generateApprovalKeyPair();

      const result = await challengeService.verifyApproval({
        challengeId: challenge.id,
        approval: await approvalFor(challenge, {}, impostor),
      });

      expect(result.success).toBe(false);
      expect(result.error).toBe("Invalid signature");
      expect(result.capabilityToken).toBeUndefined();
      expect(challenge.status).toBe("email_sent");
    });

    test("refuses an approval whose binding does not match the stored challenge", async () => {
      const challenge = outstandingChallenge();
      mockChallengeRepo.findById.mockResolvedValue(challenge);

      // Signed by the right key, but for a DIFFERENT secret reference: this is
      // the case where a valid token must not release the wrong credential.
      const result = await challengeService.verifyApproval({
        challengeId: challenge.id,
        approval: await approvalFor(challenge, { secretRef: "someone-elses-secret" }),
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain("secretRef");
      expect(result.capabilityToken).toBeUndefined();
      expect(challenge.status).toBe("email_sent");
    });

    test("refuses an approval signed for a different challenge id", async () => {
      const challenge = outstandingChallenge();
      mockChallengeRepo.findById.mockResolvedValue(challenge);

      const result = await challengeService.verifyApproval({
        challengeId: challenge.id,
        approval: await approvalFor(challenge, { challengeId: "another-challenge" }),
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain("challengeId");
      expect(result.capabilityToken).toBeUndefined();
    });

    test("refuses a structurally broken approval without throwing", async () => {
      const challenge = outstandingChallenge();
      mockChallengeRepo.findById.mockResolvedValue(challenge);

      const result = await challengeService.verifyApproval({
        challengeId: challenge.id,
        approval: { payload: undefined, signature: "AA", protectedHeader: "AA" } as any,
      });

      expect(result.success).toBe(false);
      expect(result.capabilityToken).toBeUndefined();
    });

    test("consumes the approval: a second use of the same token is refused", async () => {
      const challenge = outstandingChallenge();
      mockChallengeRepo.findById.mockResolvedValue(challenge);
      const approval = await approvalFor(challenge);

      const first = await challengeService.verifyApproval({ challengeId: challenge.id, approval });
      expect(first.success).toBe(true);

      // Put the record back into an outstanding state to isolate the replay
      // guard: the challenge status machine already refuses a second
      // completion, this asserts the JTI does too.
      challenge.status = "email_sent";

      const second = await challengeService.verifyApproval({ challengeId: challenge.id, approval });
      expect(second.success).toBe(false);
      expect(second.error).toBe("Approval already used");
      expect(second.capabilityToken).toBeUndefined();
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
      const s1 = getChallengeService(mockChallengeRepo, emailService, "https://plus.example.com", plusKeyPair.privateKeyBase64);
      const s2 = getChallengeService(mockChallengeRepo, emailService, "https://plus.example.com", plusKeyPair.privateKeyBase64);
      expect(s1).toBe(s2);
    });

    test("setChallengeService replaces singleton", () => {
      const s1 = new ChallengeService(mockChallengeRepo, emailService, "https://plus.example.com", plusKeyPair.privateKeyBase64);
      setChallengeService(s1);
      const s2 = getChallengeService(mockChallengeRepo, emailService, "https://plus.example.com", plusKeyPair.privateKeyBase64);
      expect(s2).toBe(s1);
    });
  });
});
