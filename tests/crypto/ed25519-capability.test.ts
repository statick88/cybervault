/**
 * Ed25519 Capability Tests — Strict TDD
 *
 * Tests for capability token signing, verification, and validation
 * Following: RED -> GREEN -> REFACTOR
 */

import {
  generateEd25519KeyPair,
  loadEd25519PrivateKey,
  loadEd25519PublicKey,
  signCapability,
  verifyCapability,
  createCapabilityPayload,
  validateCapabilityPayload,
  encodeCapabilityPayload,
  decodeCapabilityPayload,
  CAPABILITY_OPERATIONS,
  CAPABILITY_VERSION,
  DEFAULT_CAPABILITY_TTL_SECONDS,
} from "../../src/infrastructure/crypto/ed25519-capability";
import { secureZero } from "../../src/infrastructure/crypto/secure-memory";
import { binaryToBase64 } from "../../src/shared/utils";
import { ed25519 } from "@noble/curves/ed25519.js";

describe("Ed25519 Capability Crypto", () => {
  let keyPair: ReturnType<typeof generateEd25519KeyPair>;
  let testPayload: ReturnType<typeof createCapabilityPayload>;

  beforeAll(() => {
    keyPair = generateEd25519KeyPair();
    testPayload = createCapabilityPayload({
      userId: "user-123",
      resourceId: "db-prod-001",
      operation: "AUTOFILL",
      secretRef: "secret-ref-abc",
      deviceId: "device-xyz",
      assurance: 2,
    });
  });

  afterAll(() => {
    if (keyPair?.privateKey) secureZero(keyPair.privateKey);
  });

  describe("generateEd25519KeyPair", () => {
    test("generates valid key pair with correct lengths", () => {
      const kp = generateEd25519KeyPair();
      expect(kp.publicKey).toBeInstanceOf(Uint8Array);
      expect(kp.publicKey.length).toBe(32);
      expect(kp.privateKey).toBeInstanceOf(Uint8Array);
      expect(kp.privateKey.length).toBe(64);
      expect(kp.publicKeyBase64).toBeDefined();
      expect(kp.privateKeyBase64).toBeDefined();

      // Verify private key format: seed (32 bytes) + public key (32 bytes)
      const seed = kp.privateKey.slice(0, 32);
      const publicKeyFromPrivate = kp.privateKey.slice(32);
      expect(publicKeyFromPrivate).toEqual(kp.publicKey); // public key is second 32

      // Verify seed can derive public key
      const derivedPublic = ed25519.getPublicKey(seed);
      expect(derivedPublic).toEqual(kp.publicKey);

      secureZero(kp.privateKey);
      secureZero(seed);
    });

    test("generates different key pairs on each call", () => {
      const kp1 = generateEd25519KeyPair();
      const kp2 = generateEd25519KeyPair();
      expect(kp1.publicKey).not.toEqual(kp2.publicKey);
      expect(kp1.privateKey).not.toEqual(kp2.privateKey);
      secureZero(kp1.privateKey);
      secureZero(kp2.privateKey);
    });

    test("public key can be derived from private key seed", () => {
      const kp = generateEd25519KeyPair();
      const derivedPublic = kp.privateKey.slice(32); // public key is stored at offset 32
      expect(derivedPublic).toEqual(kp.publicKey);
      secureZero(kp.privateKey);
    });
  });

  describe("loadEd25519PrivateKey / loadEd25519PublicKey", () => {
    test("loads private key from base64", () => {
      const loaded = loadEd25519PrivateKey(keyPair.privateKeyBase64);
      expect(loaded).toEqual(keyPair.privateKey);
      secureZero(loaded);
    });

    test("loads public key from base64", () => {
      const loaded = loadEd25519PublicKey(keyPair.publicKeyBase64);
      expect(loaded).toEqual(keyPair.publicKey);
    });

    test("throws on invalid private key length", () => {
      const shortKey = binaryToBase64(new Uint8Array(32));
      expect(() => loadEd25519PrivateKey(shortKey)).toThrow("Invalid Ed25519 private key length");
    });

    test("throws on invalid public key length", () => {
      const shortKey = binaryToBase64(new Uint8Array(16));
      expect(() => loadEd25519PublicKey(shortKey)).toThrow("Invalid Ed25519 public key length");
    });
  });

  describe("createCapabilityPayload", () => {
    test("creates payload with all required fields", () => {
      const payload = createCapabilityPayload({
        userId: "user-123",
        resourceId: "db-prod-001",
        operation: "VIEW",
        secretRef: "secret-ref",
        assurance: 1,
      });

      expect(payload.issuer).toBe("cybervault-plus");
      expect(payload.audience).toBe("cybervault-core");
      expect(payload.userId).toBe("user-123");
      expect(payload.resourceId).toBe("db-prod-001");
      expect(payload.operation).toBe("VIEW");
      expect(payload.secretRef).toBe("secret-ref");
      expect(payload.deviceId).toBeUndefined();
      expect(payload.assurance).toBe(1);
      expect(payload.version).toBe(CAPABILITY_VERSION);
      expect(payload.iat).toBeDefined();
      expect(payload.exp).toBe(payload.iat + DEFAULT_CAPABILITY_TTL_SECONDS);
      expect(payload.jti).toBeDefined();
      expect(payload.jti.length).toBeGreaterThanOrEqual(16);
    });

    test("includes deviceId when provided", () => {
      const payload = createCapabilityPayload({
        userId: "user-123",
        resourceId: "db-prod-001",
        operation: "TOTP",
        secretRef: "secret-ref",
        deviceId: "device-456",
        assurance: 3,
      });
      expect(payload.deviceId).toBe("device-456");
    });

    test("uses custom TTL when provided", () => {
      const customTtl = 600; // 10 minutes
      const payload = createCapabilityPayload({
        userId: "user-123",
        resourceId: "db-prod-001",
        operation: "CONNECT",
        secretRef: "secret-ref",
        assurance: 2,
        ttlSeconds: customTtl,
      });
      expect(payload.exp).toBe(payload.iat + customTtl);
    });

    test("throws when TTL exceeds maximum", () => {
      expect(() =>
        createCapabilityPayload({
          userId: "user-123",
          resourceId: "db-prod-001",
          operation: "READ",
          secretRef: "secret-ref",
          assurance: 1,
          ttlSeconds: 10000, // exceeds MAX_CAPABILITY_TTL_SECONDS
        }),
      ).toThrow("TTL exceeds maximum");
    });

    test("generates unique JTI for each payload", () => {
      const p1 = createCapabilityPayload({
        userId: "user-123",
        resourceId: "db-prod-001",
        operation: "AUTOFILL",
        secretRef: "secret-ref",
        assurance: 1,
      });
      const p2 = createCapabilityPayload({
        userId: "user-123",
        resourceId: "db-prod-001",
        operation: "AUTOFILL",
        secretRef: "secret-ref",
        assurance: 1,
      });
      expect(p1.jti).not.toBe(p2.jti);
    });
  });

  describe("validateCapabilityPayload", () => {
    test("validates correct payload", () => {
      const result = validateCapabilityPayload(testPayload);
      expect(result.valid).toBe(true);
    });

    test("rejects wrong version", () => {
      const payload = { ...testPayload, version: 999 };
      const result = validateCapabilityPayload(payload);
      expect(result.valid).toBe(false);
      expect(result.error).toBe("Unsupported capability version");
    });

    test("rejects wrong issuer", () => {
      const payload = { ...testPayload, issuer: "evil-issuer" };
      const result = validateCapabilityPayload(payload);
      expect(result.valid).toBe(false);
      expect(result.error).toBe("Invalid issuer");
    });

    test("rejects wrong audience", () => {
      const payload = { ...testPayload, audience: "evil-audience" };
      const result = validateCapabilityPayload(payload);
      expect(result.valid).toBe(false);
      expect(result.error).toBe("Invalid audience");
    });

    test("rejects invalid operation", () => {
      const payload = { ...testPayload, operation: "INVALID_OP" as any };
      const result = validateCapabilityPayload(payload);
      expect(result.valid).toBe(false);
      expect(result.error).toBe("Invalid operation");
    });

    test("rejects invalid assurance level", () => {
      const payload = { ...testPayload, assurance: 5 as any };
      const result = validateCapabilityPayload(payload);
      expect(result.valid).toBe(false);
      expect(result.error).toBe("Invalid assurance level");
    });

    test("rejects expired capability", () => {
      const payload = { ...testPayload, exp: Math.floor(Date.now() / 1000) - 100 };
      const result = validateCapabilityPayload(payload);
      expect(result.valid).toBe(false);
      expect(result.error).toBe("Capability expired");
    });

    test("rejects future-dated capability (beyond clock skew)", () => {
      const payload = { ...testPayload, iat: Math.floor(Date.now() / 1000) + 120 };
      const result = validateCapabilityPayload(payload);
      expect(result.valid).toBe(false);
      expect(result.error).toBe("Capability not yet valid");
    });

    test("rejects missing or short JTI", () => {
      const payload1 = { ...testPayload, jti: "" };
      expect(validateCapabilityPayload(payload1).valid).toBe(false);

      const payload2 = { ...testPayload, jti: "short" };
      expect(validateCapabilityPayload(payload2).valid).toBe(false);
    });
  });

  describe("signCapability / verifyCapability", () => {
    let signedCapability: Awaited<ReturnType<typeof signCapability>>;

    beforeAll(async () => {
      signedCapability = await signCapability(testPayload, keyPair.privateKey);
    });

    test("signs capability and produces valid signature", () => {
      expect(signedCapability.payload).toEqual(testPayload);
      expect(signedCapability.signature).toBeDefined();
      expect(signedCapability.protectedHeader).toBeDefined();
    });

    test("verifies valid capability with correct public key", async () => {
      const result = await verifyCapability(signedCapability, keyPair.publicKey);
      expect(result.valid).toBe(true);
      expect(result.error).toBeUndefined();
    });

    test("rejects capability with wrong public key", async () => {
      const otherKeyPair = generateEd25519KeyPair();
      const result = await verifyCapability(signedCapability, otherKeyPair.publicKey);
      expect(result.valid).toBe(false);
      expect(result.error).toBe("Invalid signature");
      secureZero(otherKeyPair.privateKey);
    });

    test("rejects tampered payload", async () => {
      const tampered = { ...signedCapability, payload: { ...testPayload, operation: "ADMIN" as any } };
      const result = await verifyCapability(tampered, keyPair.publicKey);
      expect(result.valid).toBe(false);
      expect(result.error).toBe("Invalid signature");
    });

    test("rejects expired capability", async () => {
      const expiredPayload = createCapabilityPayload({
        userId: "user-123",
        resourceId: "db-prod-001",
        operation: "VIEW",
        secretRef: "secret-ref",
        assurance: 1,
        ttlSeconds: -100, // Already expired
      });
      const expiredSigned = await signCapability(expiredPayload, keyPair.privateKey);
      const result = await verifyCapability(expiredSigned, keyPair.publicKey);
      expect(result.valid).toBe(false);
      expect(result.error).toBe("Capability expired");
    });

    test("rejects capability with wrong issuer", async () => {
      const badPayload = { ...testPayload, issuer: "evil-plus" };
      const badSigned = await signCapability(badPayload, keyPair.privateKey);
      const result = await verifyCapability(badSigned, keyPair.publicKey);
      expect(result.valid).toBe(false);
      expect(result.error).toBe("Invalid issuer");
    });

    test("rejects capability with wrong audience", async () => {
      const badPayload = { ...testPayload, audience: "evil-core" };
      const badSigned = await signCapability(badPayload, keyPair.privateKey);
      const result = await verifyCapability(badSigned, keyPair.publicKey);
      expect(result.valid).toBe(false);
      expect(result.error).toBe("Invalid audience");
    });

    test("rejects capability with invalid operation", async () => {
      const badPayload = { ...testPayload, operation: "INVALID_OP" as any };
      const badSigned = await signCapability(badPayload, keyPair.privateKey);
      const result = await verifyCapability(badSigned, keyPair.publicKey);
      expect(result.valid).toBe(false);
      expect(result.error).toBe("Invalid operation");
    });

    test("rejects capability with unsupported version", async () => {
      const badPayload = { ...testPayload, version: 999 };
      const badSigned = await signCapability(badPayload, keyPair.privateKey);
      const result = await verifyCapability(badSigned, keyPair.publicKey);
      expect(result.valid).toBe(false);
      expect(result.error).toBe("Unsupported capability version");
    });
  });

  describe("encodeCapabilityPayload / decodeCapabilityPayload", () => {
    test("round-trips payload correctly", () => {
      const encoded = encodeCapabilityPayload(testPayload);
      const decoded = decodeCapabilityPayload(encoded);
      expect(decoded).toEqual(testPayload);
    });

    test("handles optional deviceId correctly", () => {
      const payloadWithDevice = createCapabilityPayload({
        userId: "user-123",
        resourceId: "db-prod-001",
        operation: "AUTOFILL",
        secretRef: "secret-ref",
        deviceId: "device-789",
        assurance: 2,
      });
      const encoded = encodeCapabilityPayload(payloadWithDevice);
      const decoded = decodeCapabilityPayload(encoded);
      expect(decoded.deviceId).toBe("device-789");

      const payloadWithoutDevice = createCapabilityPayload({
        userId: "user-123",
        resourceId: "db-prod-001",
        operation: "VIEW",
        secretRef: "secret-ref",
        assurance: 1,
      });
      const encoded2 = encodeCapabilityPayload(payloadWithoutDevice);
      const decoded2 = decodeCapabilityPayload(encoded2);
      expect(decoded2.deviceId).toBeUndefined();
    });

    test("produces deterministic encoding for same payload", () => {
      const encoded1 = encodeCapabilityPayload(testPayload);
      const encoded2 = encodeCapabilityPayload(testPayload);
      expect(encoded1).toEqual(encoded2);
    });
  });

  describe("All supported operations", () => {
    test("accepts all defined operations", async () => {
      for (const op of CAPABILITY_OPERATIONS) {
        const payload = createCapabilityPayload({
          userId: "user-123",
          resourceId: "db-prod-001",
          operation: op,
          secretRef: "secret-ref",
          assurance: 1,
        });
        const signed = await signCapability(payload, keyPair.privateKey);
        const result = await verifyCapability(signed, keyPair.publicKey);
        expect(result.valid).toBe(true);
      }
    });
  });

  describe("Security properties", () => {
    test("signature is bound to all payload fields", async () => {
      const signed = await signCapability(testPayload, keyPair.privateKey);

      // Tamper each field individually
      const fieldsToTamper = [
        "userId",
        "resourceId",
        "operation",
        "secretRef",
        "deviceId",
        "assurance",
        "iat",
        "exp",
        "jti",
      ] as const;

      for (const field of fieldsToTamper) {
        const tampered = { ...signed.payload, [field]: "tampered" } as any;
        const tamperedSigned = { ...signed, payload: tampered };
        const result = await verifyCapability(tamperedSigned, keyPair.publicKey);
        expect(result.valid).toBe(false);
      }
    });

    test("different private keys produce different signatures", async () => {
      const kp1 = generateEd25519KeyPair();
      const kp2 = generateEd25519KeyPair();

      const sig1 = await signCapability(testPayload, kp1.privateKey);
      const sig2 = await signCapability(testPayload, kp2.privateKey);

      expect(sig1.signature).not.toBe(sig2.signature);
      secureZero(kp1.privateKey);
      secureZero(kp2.privateKey);
    });
  });
});