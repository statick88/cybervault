import { encrypt, decrypt } from "../../../src/infrastructure/crypto/EncryptionService";

describe("EncryptionService", () => {
  // PBKDF2 with 600k iterations is slow
  jest.setTimeout(30_000);

  const masterKey = "test-master-key-2024";

  describe("encrypt", () => {
    it("returns a base64 string", async () => {
      const result = await encrypt("hello world", masterKey);

      // Should be valid base64
      expect(() => atob(result)).not.toThrow();
      expect(typeof result).toBe("string");
      expect(result.length).toBeGreaterThan(0);
    });

    it("produces output in salt|iv|ciphertext format (3 components when decoded)", async () => {
      const result = await encrypt("hello world", masterKey);
      const decoded = Uint8Array.from(atob(result), (c) => c.charCodeAt(0));

      // salt (16) + iv (12) + ciphertext+tag (>= 16+12 = 28 minimum for GCM tag)
      expect(decoded.length).toBeGreaterThan(28);
    });
  });

  describe("decrypt", () => {
    it("round-trips: decrypt(encrypt(data, key), key) === data", async () => {
      const plaintext = "sensitive data to encrypt";
      const encrypted = await encrypt(plaintext, masterKey);
      const decrypted = await decrypt(encrypted, masterKey);

      expect(decrypted).toBe(plaintext);
    });

    it("round-trips with unicode content", async () => {
      const plaintext = "Datos en español: ñ, á, é — カタカナ 🎉";
      const encrypted = await encrypt(plaintext, masterKey);
      const decrypted = await decrypt(encrypted, masterKey);

      expect(decrypted).toBe(plaintext);
    });

    it("throws with wrong key", async () => {
      const encrypted = await encrypt("secret", masterKey);

      await expect(decrypt(encrypted, "wrong-key")).rejects.toThrow(
        "Decryption failed",
      );
    });

    it("throws with tampered ciphertext", async () => {
      const encrypted = await encrypt("secret", masterKey);
      const decoded = Uint8Array.from(atob(encrypted), (c) => c.charCodeAt(0));

      // Tamper with a byte in the ciphertext portion (after salt+iv = 28 bytes in)
      decoded[30] ^= 0xff;

      const tampered = btoa(String.fromCharCode(...decoded));

      await expect(decrypt(tampered, masterKey)).rejects.toThrow(
        "Decryption failed",
      );
    });

    it("different encryptions of same data produce different ciphertexts", async () => {
      const plaintext = "same data encrypted twice";
      const encrypted1 = await encrypt(plaintext, masterKey);
      const encrypted2 = await encrypt(plaintext, masterKey);

      // Random salt and IV ensure different output each time
      expect(encrypted1).not.toBe(encrypted2);
    });

    it("throws with empty ciphertext", async () => {
      await expect(decrypt("", masterKey)).rejects.toThrow();
    });
  });
});
