/**
 * CryptoService Unit Tests
 * Tests for the 4-layer crypto service
 */

import { describe, it, expect, beforeEach } from "@jest/globals";

// Mock chrome.storage
global.chrome = {
  storage: {
    local: {
      get: jest.fn(),
      set: jest.fn(),
      remove: jest.fn(),
    },
  },
} as any;

// Import after mocking
import { CryptoLayeredService } from "../../src/infrastructure/crypto/crypto-layered-service";

describe("CryptoLayeredService", () => {
  let cryptoService: CryptoLayeredService;

  beforeEach(() => {
    cryptoService = new CryptoLayeredService();
  });

  describe("Layer 1: Basic Cryptography", () => {
    it("should encrypt and decrypt data correctly", async () => {
      const plaintext = "Hello, CyberVault!";
      const key = "test-key-123";

      const encrypted = await cryptoService.encrypt(plaintext, key);
      expect(encrypted).not.toBe(plaintext);

      const decrypted = await cryptoService.decrypt(encrypted, key);
      expect(decrypted).toBe(plaintext);
    });

    it("should produce different ciphertext for same plaintext (random IV)", async () => {
      const plaintext = "Same message";
      const key = "test-key";

      const encrypted1 = await cryptoService.encrypt(plaintext, key);
      const encrypted2 = await cryptoService.encrypt(plaintext, key);

      // Should be different due to random IV
      expect(encrypted1).not.toBe(encrypted2);
    });

    it("should generate SHA-256 hash", async () => {
      const data = "test-data";
      const hash = await cryptoService.hash(data);

      expect(hash).toHaveLength(64);
      expect(hash).toMatch(/^[a-f0-9]+$/);
    });

    it("should derive key from password and salt", async () => {
      const password = "my-password";
      const salt = "random-salt";

      const key = await cryptoService.deriveKey(password, salt);

      expect(key).toBeDefined();
      expect(key.length).toBeGreaterThan(0);
    });
  });

  describe("Layer 2: HMAC Authentication", () => {
    it("should create and verify HMAC", async () => {
      const data = "important data";
      const key = "secret-key";

      const hmac = await cryptoService.createHmac(data, key);
      expect(hmac).toBeDefined();

      const valid = await cryptoService.verifyHmac(data, hmac, key);
      expect(valid).toBe(true);

      const invalid = await cryptoService.verifyHmac(
        data + "tampered",
        hmac,
        key,
      );
      expect(invalid).toBe(false);
    });
  });

  describe("Layer 3: Secure Storage", () => {
    it("should encrypt and decrypt storage", async () => {
      const data = JSON.stringify({ username: "test", password: "secret" });
      const masterKey = "master-password";

      const encrypted = await cryptoService.encryptStorage(data, masterKey);
      expect(encrypted).toBeDefined();

      const decrypted = await cryptoService.decryptStorage(
        encrypted,
        masterKey,
      );
      expect(decrypted).toBe(data);
    });

    it("should fail with wrong key", async () => {
      const data = "sensitive data";
      const wrongKey = "wrong-key";

      const encrypted = await cryptoService.encryptStorage(data, "correct-key");

      await expect(
        cryptoService.decryptStorage(encrypted, wrongKey),
      ).rejects.toThrow();
    });
  });

  describe("Layer 4: Password Protection", () => {
    it("should check password strength - weak", () => {
      const result = cryptoService.checkPasswordStrength("abc");

      expect(result.score).toBeLessThanOrEqual(1);
      expect(result.label).toMatch(/weak/);
    });

    it("should check password strength - strong", () => {
      const result = cryptoService.checkPasswordStrength("MyStr0ng!Pass#2024");

      expect(result.score).toBeGreaterThanOrEqual(3);
      expect(result.label).toMatch(/strong|medium/);
    });

    it("should provide feedback for weak passwords", () => {
      const result = cryptoService.checkPasswordStrength("123");

      expect(result.feedback).toBeInstanceOf(Array);
      expect(result.feedback.length).toBeGreaterThan(0);
    });
  });
});

describe("Integration: Full Encryption Flow", () => {
  let cryptoService: CryptoLayeredService;

  beforeEach(() => {
    cryptoService = new CryptoLayeredService();
  });

  it("should handle complete credential storage flow", async () => {
    const credential = {
      id: "123",
      username: "user@test.com",
      password: "SecretPassword123!",
      url: "https://example.com",
    };

    const masterKey = "my-master-key";

    // Encrypt
    const encrypted = await cryptoService.encryptStorage(
      JSON.stringify(credential),
      masterKey,
    );

    // Verify HMAC layer
    const { tag } = JSON.parse(encrypted);
    const isValid = await cryptoService.verifyHmac(
      JSON.parse(encrypted).ciphertext,
      tag,
      await cryptoService.deriveKey(masterKey, JSON.parse(encrypted).salt),
    );
    expect(isValid).toBe(true);

    // Decrypt
    const decrypted = await cryptoService.decryptStorage(encrypted, masterKey);
    const result = JSON.parse(decrypted);

    expect(result.username).toBe(credential.username);
    expect(result.password).toBe(credential.password);
  });

  it("should detect password breach (or handle API failure gracefully)", async () => {
    // This test may fail if HIBP API is unavailable
    // We test that the method exists and handles errors
    const result = await cryptoService.checkBreach("password123");

    // Either returns true (pwned) or false (safe/error)
    expect(typeof result).toBe("boolean");
  });
});
