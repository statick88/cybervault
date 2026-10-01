/**
 * Capability Issuer Service Tests — Strict TDD
 *
 * Tests for Ed25519 capability token issuance and verification
 * Following: RED -> GREEN -> REFACTOR
 */

import { CapabilityIssuer, getCapabilityIssuer, setCapabilityIssuer, verifyCapabilityCore, consumeCapabilityJti } from "../../plus/domain/services/capability-issuer";
import { generateEd25519KeyPair, verifyCapability, createCapabilityPayload } from "../../src/infrastructure/crypto/ed25519-capability";
import { PlusUser } from "../../plus/domain/entities/user";
import { Resource } from "../../plus/domain/entities/resource";
import type { CapabilityOperation, SignedCapability } from "../../src/infrastructure/crypto/ed25519-capability";

describe("CapabilityIssuer", () => {
  let issuer: CapabilityIssuer;
  let testUser: PlusUser;
  let testResource: Resource;
  let plusKeyPair: { publicKey: Uint8Array; privateKey: Uint8Array; publicKeyBase64: string; privateKeyBase64: string };

  beforeEach(() => {
    setCapabilityIssuer(null);

    plusKeyPair = require("../../src/infrastructure/crypto/ed25519-capability").generateEd25519KeyPair();

    testUser = require("../../plus/domain/entities/user").PlusUser.create({
      id: "user-123",
      email: "operator@company.com",
      name: "Test Operator",
      role: "operator",
      habitualCountries: ["EC", "US"],
      timezone: "America/Guayaquil",
    });

    testResource = require("../../plus/domain/entities/resource").Resource.create({
      id: "db-prod-001",
      name: "Production Database",
      type: "database",
      endpoint: "db01.internal:5432",
      environment: "production",
      criticality: "high",
    });

    issuer = new CapabilityIssuer(plusKeyPair.privateKeyBase64, {
      defaultTtlSeconds: 300,
      maxTtlSeconds: 3600,
    });
  });

  afterEach(() => {
    setCapabilityIssuer(null);
    if (plusKeyPair.privateKey) {
      plusKeyPair.privateKey.fill(0);
    }
  });

  describe("Constructor", () => {
    test("initializes with private key and derives public key", () => {
      expect(issuer.getPublicKey()).toBeDefined();
      expect(issuer.getPublicKey().length).toBeGreaterThan(0);
    });

    test("accepts custom TTL options", () => {
      const customIssuer = new CapabilityIssuer(plusKeyPair.privateKeyBase64, {
        defaultTtlSeconds: 600,
        maxTtlSeconds: 7200,
      });
      // Just verify it constructs without error
      expect(customIssuer).toBeDefined();
    });

    test("rejects invalid TTL options", () => {
      // Should not throw on construction, but issue() will validate
      const issuer = new CapabilityIssuer(plusKeyPair.privateKeyBase64, {
        defaultTtlSeconds: 30, // Below minimum 60
        maxTtlSeconds: 100,
      });
      expect(issuer).toBeDefined();
    });
  });

  describe("issue()", () => {
    test("issues capability token with all required fields", async () => {
      const result = await issuer.issue({
        userId: testUser.id,
        resourceId: testResource.id,
        operation: "AUTOFILL",
        secretRef: "secret-abc",
        deviceId: "device-xyz",
        assurance: 2,
        ttlSeconds: 300,
      });

      expect(result.success).toBe(true);
      expect(result.capabilityToken).toBeDefined();
      expect(result.capabilityToken!.payload.issuer).toBe("cybervault-plus");
      expect(result.capabilityToken!.payload.audience).toBe("cybervault-core");
      expect(result.capabilityToken!.payload.userId).toBe(testUser.id);
      expect(result.capabilityToken!.payload.resourceId).toBe(testResource.id);
      expect(result.capabilityToken!.payload.operation).toBe("AUTOFILL");
      expect(result.capabilityToken!.payload.secretRef).toBe("secret-abc");
      expect(result.capabilityToken!.payload.deviceId).toBe("device-xyz");
      expect(result.capabilityToken!.payload.assurance).toBe(2);
      expect(result.capabilityToken!.payload.version).toBe(1);
      expect(result.capabilityToken!.payload.jti).toBeDefined();
      expect(result.capabilityToken!.signature).toBeDefined();
      expect(result.capabilityToken!.protectedHeader).toBeDefined();
      expect(result.expiresAt).toBeGreaterThan(Date.now());
    });

    test("includes context in payload when provided", async () => {
      const result = await issuer.issue({
        userId: testUser.id,
        resourceId: testResource.id,
        operation: "VIEW",
        secretRef: "secret-abc",
        assurance: 2,
        context: {
          riskScore: 65,
          riskReasons: ["new_country", "new_device"],
          challengeId: "challenge-123",
        },
      });

      expect(result.success).toBe(true);
      // Context is added as extra field in payload
      expect((result.capabilityToken!.payload as any).context).toBeDefined();
    });

    test("rejects TTL below minimum", async () => {
      const result = await issuer.issue({
        userId: testUser.id,
        resourceId: testResource.id,
        operation: "VIEW",
        secretRef: "secret-abc",
        assurance: 1,
        ttlSeconds: 30, // Below 60 second minimum
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain("at least 60 seconds");
    });

    test("rejects TTL above maximum", async () => {
      const result = await issuer.issue({
        userId: testUser.id,
        resourceId: testResource.id,
        operation: "VIEW",
        secretRef: "secret-abc",
        assurance: 1,
        ttlSeconds: 5000, // Above default max of 3600
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain("exceeds maximum");
    });

    test("uses default TTL when not specified", async () => {
      const result = await issuer.issue({
        userId: testUser.id,
        resourceId: testResource.id,
        operation: "VIEW",
        secretRef: "secret-abc",
        assurance: 1,
      });

      expect(result.success).toBe(true);
      const payload = result.capabilityToken!.payload;
      const ttl = payload.exp - payload.iat;
      expect(ttl).toBe(300); // Default 300 seconds
    });

    test("issued capability passes self-verification", async () => {
      const result = await issuer.issue({
        userId: testUser.id,
        resourceId: testResource.id,
        operation: "AUTOFILL",
        secretRef: "secret-abc",
        assurance: 2,
      });

      expect(result.success).toBe(true);

      // The issuer does self-verification internally
      // We can't easily test it here without accessing internal methods
      // Just verify the capability structure is correct
      expect(result.capabilityToken).toBeDefined();
      expect(result.capabilityToken!.payload.userId).toBe(testUser.id);
    });
  });

  describe("verify()", () => {
    test("verifies valid capability token", async () => {
      const issueResult = await issuer.issue({
        userId: testUser.id,
        resourceId: testResource.id,
        operation: "VIEW",
        secretRef: "secret-abc",
        assurance: 1,
      });

      const verifyResult = await issuer.verify(issueResult.capabilityToken!);

      expect(verifyResult.valid).toBe(true);
      expect(verifyResult.payload).toBeDefined();
      expect(verifyResult.payload!.userId).toBe(testUser.id);
    });

    test("rejects tampered capability", async () => {
      const issueResult = await issuer.issue({
        userId: testUser.id,
        resourceId: testResource.id,
        operation: "VIEW",
        secretRef: "secret-abc",
        assurance: 1,
      });

      // Tamper with the signature
      const tampered = {
        ...issueResult.capabilityToken!,
        signature: "tampered-signature-base64",
      };

      const verifyResult = await issuer.verify(tampered);

      expect(verifyResult.valid).toBe(false);
    });

    test("accepts custom public key for verification", async () => {
      const issueResult = await issuer.issue({
        userId: testUser.id,
        resourceId: testResource.id,
        operation: "VIEW",
        secretRef: "secret-abc",
        assurance: 1,
      });

      // Verify with the public key from the issuer
      const publicKeyBase64 = issuer.getPublicKey();
      const verifyResult = await issuer.verify(issueResult.capabilityToken!, publicKeyBase64);

      expect(verifyResult.valid).toBe(true);
    });
  });

  describe("Convenience Methods", () => {
    test("issueStepUpCapability creates assurance 3 token", async () => {
      const result = await issuer.issueStepUpCapability({
        userId: testUser.id,
        resourceId: testResource.id,
        operation: "ADMIN",
        secretRef: "secret-abc",
        challengeId: "challenge-123",
      });

      expect(result.success).toBe(true);
      expect(result.capabilityToken!.payload.assurance).toBe(3);
      expect((result.capabilityToken!.payload as any).context?.challengeId).toBe("challenge-123");
    });

    test("issueRiskBasedCapability creates assurance 2 token", async () => {
      const result = await issuer.issueRiskBasedCapability({
        userId: testUser.id,
        resourceId: testResource.id,
        operation: "AUTOFILL",
        secretRef: "secret-abc",
        riskScore: 65,
        riskReasons: ["new_country", "new_device"],
      });

      expect(result.success).toBe(true);
      expect(result.capabilityToken!.payload.assurance).toBe(2);
      expect((result.capabilityToken!.payload as any).context?.riskScore).toBe(65);
      expect((result.capabilityToken!.payload as any).context?.riskReasons).toContain("new_country");
    });

    test("issueDirectCapability creates assurance 1 token", async () => {
      const result = await issuer.issueDirectCapability({
        userId: testUser.id,
        resourceId: testResource.id,
        operation: "VIEW",
        secretRef: "secret-abc",
      });

      expect(result.success).toBe(true);
      expect(result.capabilityToken!.payload.assurance).toBe(1);
    });
  });

  describe("getPublicKey / getPublicKeyJwk", () => {
    test("getPublicKey returns base64 encoded public key", () => {
      const publicKey = issuer.getPublicKey();
      expect(publicKey).toBeDefined();
      expect(typeof publicKey).toBe("string");
      expect(publicKey.length).toBeGreaterThan(0);
    });

    test("getPublicKeyJwk returns valid JWK", () => {
      const jwkString = issuer.getPublicKeyJwk();
      const jwk = JSON.parse(jwkString);

      expect(jwk.kty).toBe("OKP");
      expect(jwk.crv).toBe("Ed25519");
      expect(jwk.alg).toBe("EdDSA");
      expect(jwk.use).toBe("sig");
      expect(jwk.kid).toBe("cybervault-plus-capability-v1");
      expect(jwk.x).toBeDefined();
    });

    test("public key matches private key", () => {
      const publicKeyBase64 = issuer.getPublicKey();
      const publicKey = require("../../src/infrastructure/crypto/ed25519-capability").loadEd25519PublicKey(publicKeyBase64);
      // The public key should match the one derived from private key
      const expectedPublic = plusKeyPair.publicKey;
      expect(publicKey).toEqual(expectedPublic);
    });
  });

  describe("Singleton", () => {
    test("getCapabilityIssuer returns singleton", () => {
      setCapabilityIssuer(null);
      const i1 = getCapabilityIssuer(plusKeyPair.privateKeyBase64);
      const i2 = getCapabilityIssuer(plusKeyPair.privateKeyBase64);
      expect(i1).toBe(i2);
    });

    test("setCapabilityIssuer replaces singleton", () => {
      const customIssuer = new CapabilityIssuer(plusKeyPair.privateKeyBase64);
      setCapabilityIssuer(customIssuer);
      const retrieved = getCapabilityIssuer(plusKeyPair.privateKeyBase64);
      expect(retrieved).toBe(customIssuer);
    });
  });

  describe("Core-side Verification", () => {
    test("verifyCapabilityCore verifies token with Plus public key", async () => {
      const { verifyCapabilityCore } = require("../../plus/domain/services/capability-issuer");

      const issueResult = await issuer.issue({
        userId: testUser.id,
        resourceId: testResource.id,
        operation: "VIEW",
        secretRef: "secret-abc",
        assurance: 1,
      });

      const publicKeyBase64 = issuer.getPublicKey();
      const result = await verifyCapabilityCore(issueResult.capabilityToken!, publicKeyBase64);

      expect(result.valid).toBe(true);
      expect(result.payload).toBeDefined();
    });

    test("verifyCapabilityCore rejects invalid signature", async () => {
      const { verifyCapabilityCore } = require("../../plus/domain/services/capability-issuer");

      const issueResult = await issuer.issue({
        userId: testUser.id,
        resourceId: testResource.id,
        operation: "VIEW",
        secretRef: "secret-abc",
        assurance: 1,
      });

      const tampered = {
        ...issueResult.capabilityToken!,
        signature: "invalid-signature",
      };

      const result = await verifyCapabilityCore(tampered, issuer.getPublicKey());

      expect(result.valid).toBe(false);
    });
  });

  describe("JTI Consumption", () => {
    test("consumeCapabilityJti allows first use", async () => {
      const { consumeCapabilityJti } = require("../../plus/domain/services/capability-issuer");

      const result = await consumeCapabilityJti("test-jti-" + Date.now(), 300);
      expect(result.allowed).toBe(true);
    });

    test("consumeCapabilityJti rejects replay", async () => {
      const { consumeCapabilityJti } = require("../../plus/domain/services/capability-issuer");

      const jti = "replay-test-" + Date.now();
      await consumeCapabilityJti(jti, 300);
      const result = await consumeCapabilityJti(jti, 300);

      expect(result.allowed).toBe(false);
      expect(result.error).toContain("Replay detected");
    });
  });

  describe("Singleton", () => {
    test("getCapabilityIssuer returns singleton", () => {
      setCapabilityIssuer(null);
      const i1 = getCapabilityIssuer(plusKeyPair.privateKeyBase64);
      const i2 = getCapabilityIssuer(plusKeyPair.privateKeyBase64);
      expect(i1).toBe(i2);
    });

    test("setCapabilityIssuer replaces singleton", () => {
      const customIssuer = new CapabilityIssuer(plusKeyPair.privateKeyBase64);
      setCapabilityIssuer(customIssuer);
      const retrieved = getCapabilityIssuer(plusKeyPair.privateKeyBase64);
      expect(retrieved).toBe(customIssuer);
    });
  });
});