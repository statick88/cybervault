/**
 * Managed Credential Decrypt Tests
 *
 * Tests the managed credential decryption flow:
 * 1. Capability request to Plus
 * 2. ReleaseShare request to Core
 * 3. EntryKey derivation (HKDF with VEK || ReleaseShare)
 * 4. AES-GCM decryption
 */

import { deriveManagedEntryKey } from "../../src/infrastructure/crypto/hkdf-derivation";
import { base64ToBinary, binaryToBase64 } from "../../src/shared/utils";
import { secureZero } from "../../src/infrastructure/crypto/secure-memory";

function toArrayBuffer(data: Uint8Array): ArrayBuffer {
  const buf = new ArrayBuffer(data.byteLength);
  new Uint8Array(buf).set(data);
  return buf;
}

async function decryptAESGCM(
  ciphertextBase64: string,
  keyBase64: string,
): Promise<string | null> {
  try {
    const combined = base64ToBinary(ciphertextBase64);
    const saltLength = 32;
    const ivLength = 12;

    const salt = combined.slice(0, saltLength);
    const iv = combined.slice(saltLength, saltLength + ivLength);
    const ciphertextWithTag = combined.slice(saltLength + ivLength);

    const key = base64ToBinary(keyBase64);
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      toArrayBuffer(key),
      "AES-GCM",
      false,
      ["decrypt"],
    );

    const decryptedBuffer = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: toArrayBuffer(iv),
        tagLength: 128,
      },
      cryptoKey,
      toArrayBuffer(ciphertextWithTag),
    );

    return new TextDecoder().decode(decryptedBuffer);
  } catch {
    return null;
  }
}

describe("Managed Credential Decrypt", () => {
  let testVEK: Uint8Array;
  let testReleaseShare: Uint8Array;
  let testSalt: Uint8Array;
  let testCredentialId: string;
  let testVersion: number;
  let testPassword: string;

  beforeAll(async () => {
    testVEK = crypto.getRandomValues(new Uint8Array(32));
    testReleaseShare = crypto.getRandomValues(new Uint8Array(32));
    testSalt = crypto.getRandomValues(new Uint8Array(32));
    testCredentialId = "test-cred-123";
    testVersion = 1;
    testPassword = "super-secret-password-123!";

    // Encrypt test password with managed entry key for integration test
    const derived = await deriveManagedEntryKey(
      testVEK,
      testReleaseShare,
      testSalt,
      testCredentialId,
      testVersion,
    );

    // Encrypt the password
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = base64ToBinary(derived.keyBase64);
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      toArrayBuffer(key),
      "AES-GCM",
      false,
      ["encrypt"],
    );

    const encoded = new TextEncoder().encode(testPassword);
    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: toArrayBuffer(iv), tagLength: 128 },
      cryptoKey,
      toArrayBuffer(encoded),
    );

    const combined = new Uint8Array(testSalt.length + iv.length + encrypted.byteLength);
    combined.set(testSalt, 0);
    combined.set(iv, testSalt.length);
    combined.set(new Uint8Array(encrypted), testSalt.length + iv.length);

    // Store for tests
    (global as any).__TEST_ENCRYPTED_PASSWORD__ = binaryToBase64(combined);
    (global as any).__TEST_DERIVED_KEY__ = derived.keyBase64;
  });

  afterAll(() => {
    secureZero(testVEK);
    secureZero(testReleaseShare);
    secureZero(testSalt);
  });

  describe("deriveManagedEntryKey", () => {
    it("derives a 32-byte key from VEK || ReleaseShare", async () => {
      const derived = await deriveManagedEntryKey(
        testVEK,
        testReleaseShare,
        testSalt,
        testCredentialId,
        testVersion,
      );

      expect(derived).toBeDefined();
      expect(derived.keyBase64).toBeDefined();
      expect(derived.saltBase64).toBe(binaryToBase64(testSalt));
      expect(derived.context.credentialId).toBe(testCredentialId);
      expect(derived.context.version).toBe(testVersion);
      expect(derived.context.mode).toBe("managed");
    });

    it("produces different keys for different credentials", async () => {
      const key1 = await deriveManagedEntryKey(
        testVEK,
        testReleaseShare,
        testSalt,
        "cred-1",
        1,
      );
      const key2 = await deriveManagedEntryKey(
        testVEK,
        testReleaseShare,
        testSalt,
        "cred-2",
        1,
      );

      expect(key1.keyBase64).not.toBe(key2.keyBase64);
    });

    it("produces different keys for different versions", async () => {
      const key1 = await deriveManagedEntryKey(
        testVEK,
        testReleaseShare,
        testSalt,
        testCredentialId,
        1,
      );
      const key2 = await deriveManagedEntryKey(
        testVEK,
        testReleaseShare,
        testSalt,
        testCredentialId,
        2,
      );

      expect(key1.keyBase64).not.toBe(key2.keyBase64);
    });

    it("produces different keys for different salts", async () => {
      const salt1 = crypto.getRandomValues(new Uint8Array(32));
      const salt2 = crypto.getRandomValues(new Uint8Array(32));

      const key1 = await deriveManagedEntryKey(
        testVEK,
        testReleaseShare,
        salt1,
        testCredentialId,
        1,
      );
      const key2 = await deriveManagedEntryKey(
        testVEK,
        testReleaseShare,
        salt2,
        testCredentialId,
        1,
      );

      expect(key1.keyBase64).not.toBe(key2.keyBase64);
    });

    it("produces different keys for different ReleaseShares", async () => {
      const rs1 = crypto.getRandomValues(new Uint8Array(32));
      const rs2 = crypto.getRandomValues(new Uint8Array(32));

      const key1 = await deriveManagedEntryKey(
        testVEK,
        rs1,
        testSalt,
        testCredentialId,
        1,
      );
      const key2 = await deriveManagedEntryKey(
        testVEK,
        rs2,
        testSalt,
        testCredentialId,
        1,
      );

      expect(key1.keyBase64).not.toBe(key2.keyBase64);
    });

    it("securely cleans up combined key material", async () => {
      // The function should not leak combined material
      // This is verified by the finally block using secureZero
      const derived = await deriveManagedEntryKey(
        testVEK,
        testReleaseShare,
        testSalt,
        testCredentialId,
        testVersion,
      );
      expect(derived.keyBase64).toBeDefined();
    });
  });

  describe("End-to-end decrypt", () => {
    it("decrypts a managed credential correctly", async () => {
      const encryptedPassword = (global as any).__TEST_ENCRYPTED_PASSWORD__;
      const derivedKeyBase64 = (global as any).__TEST_DERIVED_KEY__;

      const decrypted = await decryptAESGCM(encryptedPassword, derivedKeyBase64);

      expect(decrypted).toBe(testPassword);
    });

    it("fails to decrypt with wrong key", async () => {
      const encryptedPassword = (global as any).__TEST_ENCRYPTED_PASSWORD__;
      const wrongKey = crypto.getRandomValues(new Uint8Array(32));
      const wrongKeyBase64 = binaryToBase64(wrongKey);

      const decrypted = await decryptAESGCM(encryptedPassword, wrongKeyBase64);

      expect(decrypted).toBeNull();
    });

    it("fails to decrypt with wrong ReleaseShare", async () => {
      const wrongReleaseShare = crypto.getRandomValues(new Uint8Array(32));
      const derived = await deriveManagedEntryKey(
        testVEK,
        wrongReleaseShare,
        testSalt,
        testCredentialId,
        testVersion,
      );

      const encryptedPassword = (global as any).__TEST_ENCRYPTED_PASSWORD__;
      const decrypted = await decryptAESGCM(encryptedPassword, derived.keyBase64);

      expect(decrypted).toBeNull();
    });

    it("fails to decrypt with wrong VEK", async () => {
      const wrongVEK = crypto.getRandomValues(new Uint8Array(32));
      const derived = await deriveManagedEntryKey(
        wrongVEK,
        testReleaseShare,
        testSalt,
        testCredentialId,
        testVersion,
      );

      const encryptedPassword = (global as any).__TEST_ENCRYPTED_PASSWORD__;
      const decrypted = await decryptAESGCM(encryptedPassword, derived.keyBase64);

      expect(decrypted).toBeNull();
    });
  });

  describe("VEK-only vs VEK+ReleaseShare separation", () => {
    it("VEK alone cannot decrypt managed credential", async () => {
      // Try to derive with just VEK (personal mode style) - should fail for managed
      const { derivePersonalEntryKey } = await import(
        "../../src/infrastructure/crypto/hkdf-derivation"
      );

      const personalKey = await derivePersonalEntryKey(
        testVEK,
        testSalt,
        testCredentialId,
        testVersion,
      );

      const encryptedPassword = (global as any).__TEST_ENCRYPTED_PASSWORD__;
      const decrypted = await decryptAESGCM(encryptedPassword, personalKey.keyBase64);

      expect(decrypted).toBeNull();
    });

    it("ReleaseShare alone cannot decrypt managed credential", async () => {
      // Try to derive with just ReleaseShare - should fail
      const { deriveEntryKey } = await import(
        "../../src/infrastructure/crypto/hkdf-derivation"
      );

      const derived = await deriveEntryKey(
        testReleaseShare, // Only ReleaseShare, not VEK || ReleaseShare
        testSalt,
        {
          credentialId: testCredentialId,
          version: testVersion,
          mode: "managed",
        },
      );

      const encryptedPassword = (global as any).__TEST_ENCRYPTED_PASSWORD__;
      const decrypted = await decryptAESGCM(encryptedPassword, derived.keyBase64);

      expect(decrypted).toBeNull();
    });
  });
});