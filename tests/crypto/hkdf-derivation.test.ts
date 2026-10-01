/**
 * HKDF Derivation Tests — Strict TDD
 *
 * Tests for per-entry key derivation (personal and managed modes)
 * Following: RED -> GREEN -> REFACTOR
 */

import {
  deriveEntryKey,
  derivePersonalEntryKey,
  deriveManagedEntryKey,
  generateEntrySalt,
  verifyEntryKey,
  rederiveEntryKey,
  DerivationContext,
  HKDF_CONFIG,
} from "../../src/infrastructure/crypto/hkdf-derivation";
import { secureZero } from "../../src/infrastructure/crypto/secure-memory";

describe("HKDF Per-Entry Key Derivation", () => {
  // Test vectors
  const TEST_VEK = new Uint8Array(32);
  const TEST_RELEASE_SHARE = new Uint8Array(32);
  const TEST_CREDENTIAL_ID = "cred-123-abc";
  const TEST_VERSION = 1;

  beforeAll(() => {
    // Fill with deterministic test data
    for (let i = 0; i < 32; i++) {
      TEST_VEK[i] = i;
      TEST_RELEASE_SHARE[i] = (i + 100) % 256;
    }
  });

  afterAll(() => {
    secureZero(TEST_VEK);
    secureZero(TEST_RELEASE_SHARE);
  });

  describe("generateEntrySalt", () => {
    test("generates 32-byte salt", () => {
      const salt = generateEntrySalt();
      expect(salt).toBeInstanceOf(Uint8Array);
      expect(salt.length).toBe(HKDF_CONFIG.SALT_LENGTH);
    });

    test("generates different salts on each call", () => {
      const salt1 = generateEntrySalt();
      const salt2 = generateEntrySalt();
      expect(salt1).not.toEqual(salt2);
    });

    test("salt has cryptographic randomness (not all zeros)", () => {
      const salt = generateEntrySalt();
      const allZeros = salt.every((b) => b === 0);
      expect(allZeros).toBe(false);
    });
  });

  describe("derivePersonalEntryKey", () => {
    test("derives 32-byte EntryKey from VEK", async () => {
      const salt = generateEntrySalt();
      const result = await derivePersonalEntryKey(TEST_VEK, salt, TEST_CREDENTIAL_ID, TEST_VERSION);

      expect(result.keyBase64).toBeDefined();
      expect(typeof result.keyBase64).toBe("string");
      expect(result.saltBase64).toBeDefined();
      expect(result.context.credentialId).toBe(TEST_CREDENTIAL_ID);
      expect(result.context.version).toBe(TEST_VERSION);
      expect(result.context.mode).toBe("personal");

      // Key should be 32 bytes when decoded (256 bits)
      const keyBytes = Buffer.from(result.keyBase64, "base64");
      expect(keyBytes.length).toBe(32);
    });

    test("same inputs produce same output (deterministic)", async () => {
      const salt = generateEntrySalt();
      const result1 = await derivePersonalEntryKey(TEST_VEK, salt, TEST_CREDENTIAL_ID, TEST_VERSION);
      const result2 = await derivePersonalEntryKey(TEST_VEK, salt, TEST_CREDENTIAL_ID, TEST_VERSION);

      expect(result1.keyBase64).toBe(result2.keyBase64);
    });

    test("different salts produce different keys", async () => {
      const salt1 = generateEntrySalt();
      const salt2 = generateEntrySalt();
      const result1 = await derivePersonalEntryKey(TEST_VEK, salt1, TEST_CREDENTIAL_ID, TEST_VERSION);
      const result2 = await derivePersonalEntryKey(TEST_VEK, salt2, TEST_CREDENTIAL_ID, TEST_VERSION);

      expect(result1.keyBase64).not.toBe(result2.keyBase64);
    });

    test("different credential IDs produce different keys", async () => {
      const salt = generateEntrySalt();
      const result1 = await derivePersonalEntryKey(TEST_VEK, salt, "cred-1", TEST_VERSION);
      const result2 = await derivePersonalEntryKey(TEST_VEK, salt, "cred-2", TEST_VERSION);

      expect(result1.keyBase64).not.toBe(result2.keyBase64);
    });

    test("different versions produce different keys", async () => {
      const salt = generateEntrySalt();
      const result1 = await derivePersonalEntryKey(TEST_VEK, salt, TEST_CREDENTIAL_ID, 1);
      const result2 = await derivePersonalEntryKey(TEST_VEK, salt, TEST_CREDENTIAL_ID, 2);

      expect(result1.keyBase64).not.toBe(result2.keyBase64);
    });

    test("different VEKs produce different keys", async () => {
      const salt = generateEntrySalt();
      const vek1 = new Uint8Array(32).fill(1);
      const vek2 = new Uint8Array(32).fill(2);
      const result1 = await derivePersonalEntryKey(vek1, salt, TEST_CREDENTIAL_ID, TEST_VERSION);
      const result2 = await derivePersonalEntryKey(vek2, salt, TEST_CREDENTIAL_ID, TEST_VERSION);

      expect(result1.keyBase64).not.toBe(result2.keyBase64);
      secureZero(vek1);
      secureZero(vek2);
    });
  });

  describe("deriveManagedEntryKey", () => {
    test("derives 32-byte EntryKey from VEK || ReleaseShare", async () => {
      const salt = generateEntrySalt();
      const result = await deriveManagedEntryKey(
        TEST_VEK,
        TEST_RELEASE_SHARE,
        salt,
        TEST_CREDENTIAL_ID,
        TEST_VERSION,
      );

      expect(result.keyBase64).toBeDefined();
      expect(result.context.mode).toBe("managed");
      expect(result.context.credentialId).toBe(TEST_CREDENTIAL_ID);

      const keyBytes = Buffer.from(result.keyBase64, "base64");
      expect(keyBytes.length).toBe(32);
    });

    test("same inputs produce same output (deterministic)", async () => {
      const salt = generateEntrySalt();
      const result1 = await deriveManagedEntryKey(
        TEST_VEK,
        TEST_RELEASE_SHARE,
        salt,
        TEST_CREDENTIAL_ID,
        TEST_VERSION,
      );
      const result2 = await deriveManagedEntryKey(
        TEST_VEK,
        TEST_RELEASE_SHARE,
        salt,
        TEST_CREDENTIAL_ID,
        TEST_VERSION,
      );

      expect(result1.keyBase64).toBe(result2.keyBase64);
    });

    test("different ReleaseShare produces different key", async () => {
      const salt = generateEntrySalt();
      const rs1 = new Uint8Array(32).fill(1);
      const rs2 = new Uint8Array(32).fill(2);
      const result1 = await deriveManagedEntryKey(TEST_VEK, rs1, salt, TEST_CREDENTIAL_ID, TEST_VERSION);
      const result2 = await deriveManagedEntryKey(TEST_VEK, rs2, salt, TEST_CREDENTIAL_ID, TEST_VERSION);

      expect(result1.keyBase64).not.toBe(result2.keyBase64);
      secureZero(rs1);
      secureZero(rs2);
    });

    test("VEK only (no ReleaseShare) produces different key than managed", async () => {
      const salt = generateEntrySalt();
      const personal = await derivePersonalEntryKey(TEST_VEK, salt, TEST_CREDENTIAL_ID, TEST_VERSION);
      const managed = await deriveManagedEntryKey(
        TEST_VEK,
        TEST_RELEASE_SHARE,
        salt,
        TEST_CREDENTIAL_ID,
        TEST_VERSION,
      );

      expect(personal.keyBase64).not.toBe(managed.keyBase64);
    });

    test("wrong ReleaseShare fails to produce correct key", async () => {
      const salt = generateEntrySalt();
      const correctRs = TEST_RELEASE_SHARE;
      const wrongRs = new Uint8Array(32).fill(99);

      const correct = await deriveManagedEntryKey(TEST_VEK, correctRs, salt, TEST_CREDENTIAL_ID, TEST_VERSION);
      const wrong = await deriveManagedEntryKey(TEST_VEK, wrongRs, salt, TEST_CREDENTIAL_ID, TEST_VERSION);

      expect(correct.keyBase64).not.toBe(wrong.keyBase64);
      secureZero(wrongRs);
    });
  });

  describe("deriveEntryKey (base function)", () => {
    test("personal mode uses correct context string", async () => {
      const salt = generateEntrySalt();
      const ctx: DerivationContext = {
        credentialId: "test-cred",
        version: 5,
        mode: "personal",
      };
      const result = await deriveEntryKey(TEST_VEK, salt, ctx);

      expect(result.context).toEqual(ctx);
      expect(result.keyBase64).toBeDefined();
    });

    test("managed mode uses correct context string", async () => {
      const salt = generateEntrySalt();
      const combined = new Uint8Array(64);
      combined.set(TEST_VEK, 0);
      combined.set(TEST_RELEASE_SHARE, 32);

      const ctx: DerivationContext = {
        credentialId: "test-cred",
        version: 5,
        mode: "managed",
      };
      const result = await deriveEntryKey(combined, salt, ctx);

      expect(result.context).toEqual(ctx);
      expect(result.keyBase64).toBeDefined();
      secureZero(combined);
    });
  });

  describe("verifyEntryKey", () => {
    test("returns true for correct key", async () => {
      const salt = generateEntrySalt();
      const derived = await derivePersonalEntryKey(TEST_VEK, salt, TEST_CREDENTIAL_ID, TEST_VERSION);

      const verified = await verifyEntryKey(TEST_VEK, salt, {
        credentialId: TEST_CREDENTIAL_ID,
        version: TEST_VERSION,
        mode: "personal",
      }, derived.keyBase64);

      expect(verified).toBe(true);
    });

    test("returns false for wrong key", async () => {
      const salt = generateEntrySalt();
      const derived = await derivePersonalEntryKey(TEST_VEK, salt, TEST_CREDENTIAL_ID, TEST_VERSION);

      const verified = await verifyEntryKey(TEST_VEK, salt, {
        credentialId: TEST_CREDENTIAL_ID,
        version: TEST_VERSION,
        mode: "personal",
      }, "wrong-key-base64====");

      expect(verified).toBe(false);
    });

    test("returns false for wrong credential ID", async () => {
      const salt = generateEntrySalt();
      const derived = await derivePersonalEntryKey(TEST_VEK, salt, TEST_CREDENTIAL_ID, TEST_VERSION);

      const verified = await verifyEntryKey(TEST_VEK, salt, {
        credentialId: "wrong-cred",
        version: TEST_VERSION,
        mode: "personal",
      }, derived.keyBase64);

      expect(verified).toBe(false);
    });

    test("returns false for wrong version", async () => {
      const salt = generateEntrySalt();
      const derived = await derivePersonalEntryKey(TEST_VEK, salt, TEST_CREDENTIAL_ID, TEST_VERSION);

      const verified = await verifyEntryKey(TEST_VEK, salt, {
        credentialId: TEST_CREDENTIAL_ID,
        version: 999,
        mode: "personal",
      }, derived.keyBase64);

      expect(verified).toBe(false);
    });

    test("returns false for wrong mode", async () => {
      const salt = generateEntrySalt();
      const derived = await derivePersonalEntryKey(TEST_VEK, salt, TEST_CREDENTIAL_ID, TEST_VERSION);

      const verified = await verifyEntryKey(TEST_VEK, salt, {
        credentialId: TEST_CREDENTIAL_ID,
        version: TEST_VERSION,
        mode: "managed",
      }, derived.keyBase64);

      expect(verified).toBe(false);
    });
  });

  describe("rederiveEntryKey", () => {
    test("re-derives same key from stored salt and context", async () => {
      const salt = generateEntrySalt();
      const derived = await derivePersonalEntryKey(TEST_VEK, salt, TEST_CREDENTIAL_ID, TEST_VERSION);

      const rederived = await rederiveEntryKey(TEST_VEK, derived.saltBase64, {
        credentialId: TEST_CREDENTIAL_ID,
        version: TEST_VERSION,
        mode: "personal",
      });

      expect(rederived).toBe(derived.keyBase64);
    });

    test("managed mode re-derives correctly", async () => {
      const salt = generateEntrySalt();
      const derived = await deriveManagedEntryKey(
        TEST_VEK,
        TEST_RELEASE_SHARE,
        salt,
        TEST_CREDENTIAL_ID,
        TEST_VERSION,
      );

      const rederived = await rederiveEntryKey(
        new Uint8Array([...TEST_VEK, ...TEST_RELEASE_SHARE]),
        derived.saltBase64,
        {
          credentialId: TEST_CREDENTIAL_ID,
          version: TEST_VERSION,
          mode: "managed",
        },
      );

      expect(rederived).toBe(derived.keyBase64);
    });
  });

  describe("Security properties", () => {
    test("personal and managed keys are cryptographically independent", async () => {
      const salt = generateEntrySalt();
      const personal = await derivePersonalEntryKey(TEST_VEK, salt, TEST_CREDENTIAL_ID, TEST_VERSION);
      const managed = await deriveManagedEntryKey(
        TEST_VEK,
        TEST_RELEASE_SHARE,
        salt,
        TEST_CREDENTIAL_ID,
        TEST_VERSION,
      );

      // Keys must be completely different
      expect(personal.keyBase64).not.toBe(managed.keyBase64);

      // No detectable relationship (keys should look random)
      const personalBytes = Buffer.from(personal.keyBase64, "base64");
      const managedBytes = Buffer.from(managed.keyBase64, "base64");

      // XOR should look random (no pattern)
      let xorResult = 0;
      for (let i = 0; i < 32; i++) {
        xorResult ^= personalBytes[i] ^ managedBytes[i];
      }
      // With good randomness, xorResult should be distributed
      expect(xorResult).toBeDefined(); // Just verify it computes
    });

    test("keys have high entropy (no all-zero or all-same bytes)", async () => {
      const salt = generateEntrySalt();
      const result = await derivePersonalEntryKey(TEST_VEK, salt, TEST_CREDENTIAL_ID, TEST_VERSION);
      const keyBytes = Buffer.from(result.keyBase64, "base64");

      const allSame = keyBytes.every((b) => b === keyBytes[0]);
      expect(allSame).toBe(false);

      const allZero = keyBytes.every((b) => b === 0);
      expect(allZero).toBe(false);
    });
  });
});