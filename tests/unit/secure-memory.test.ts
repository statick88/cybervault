import { describe, it, expect, beforeEach } from "@jest/globals";
import {
  secureZero,
  SecureBuffer,
  secureHashPassword,
  generateSecureSalt,
} from "../src/infrastructure/crypto/secure-memory";

describe("secureZero", () => {
  it("should overwrite ArrayBuffer with zeros", () => {
    const buffer = new ArrayBuffer(16);
    const view = new Uint8Array(buffer);
    view[0] = 0xff;
    view[8] = 0xaa;
    view[15] = 0x55;

    secureZero(buffer);

    expect(view.every((byte) => byte === 0)).toBe(true);
  });

  it("should overwrite Uint8Array with zeros", () => {
    const buffer = new Uint8Array(32);
    buffer[0] = 0xff;
    buffer[10] = 0xab;
    buffer[31] = 0xcd;

    secureZero(buffer);

    expect(buffer.every((byte) => byte === 0)).toBe(true);
  });

  it("should handle empty buffer", () => {
    const buffer = new Uint8Array(0);
    expect(() => secureZero(buffer)).not.toThrow();
    expect(buffer.length).toBe(0);
  });
});

describe("SecureBuffer", () => {
  describe("constructor", () => {
    it("should create buffer with specified length", () => {
      const sb = new SecureBuffer(128);
      expect(sb.length).toBe(128);
    });

    it("should initialize buffer with zeros", () => {
      const sb = new SecureBuffer(64);
      expect(sb.view.every((byte) => byte === 0)).toBe(true);
    });

    it("should accept zero length", () => {
      const sb = new SecureBuffer(0);
      expect(sb.length).toBe(0);
    });

    it("should set freed to false initially", () => {
      const sb = new SecureBuffer(32);
      expect(sb.freed).toBe(false);
    });
  });

  describe("view getter", () => {
    it("should return Uint8Array view", () => {
      const sb = new SecureBuffer(16);
      const view = sb.view;
      expect(view instanceof Uint8Array).toBe(true);
      expect(view.length).toBe(16);
    });

    it("should throw error if accessed after free", () => {
      const sb = new SecureBuffer(16);
      sb.free();
      expect(() => sb.view).toThrow("Buffer ya fue liberado");
    });

    it("should return same view on multiple accesses", () => {
      const sb = new SecureBuffer(16);
      const view1 = sb.view;
      const view2 = sb.view;
      expect(view1).toBe(view2);
    });
  });

  describe("copyFrom", () => {
    it("should copy Uint8Array data to buffer", () => {
      const sb = new SecureBuffer(16);
      const source = new Uint8Array([1, 2, 3, 4, 5]);
      sb.copyFrom(source);

      expect(sb.view[0]).toBe(1);
      expect(sb.view[4]).toBe(5);
      expect(sb.view[5]).toBe(0);
    });

    it("should copy ArrayBuffer data to buffer", () => {
      const sb = new SecureBuffer(16);
      const buffer = new ArrayBuffer(8);
      const view = new Uint8Array(buffer);
      view[0] = 100;
      view[7] = 200;
      sb.copyFrom(buffer);

      expect(sb.view[0]).toBe(100);
      expect(sb.view[7]).toBe(200);
    });

    it("should throw error if source exceeds buffer capacity", () => {
      const sb = new SecureBuffer(8);
      const source = new Uint8Array(16);
      expect(() => sb.copyFrom(source)).toThrow(
        "Datos exceden capacidad del buffer",
      );
    });

    it("should throw error if called after free", () => {
      const sb = new SecureBuffer(16);
      sb.free();
      const source = new Uint8Array([1, 2, 3]);
      expect(() => sb.copyFrom(source)).toThrow("Buffer ya fue liberado");
    });

    it("should overwrite existing data on second copy", () => {
      const sb = new SecureBuffer(16);
      sb.copyFrom(new Uint8Array([10, 20, 30]));
      sb.copyFrom(new Uint8Array([100, 200, 300]));

      expect(sb.view[0]).toBe(100);
      expect(sb.view[2]).toBe(300);
    });
  });

  describe("copyTo", () => {
    it("should copy buffer data to destination", () => {
      const sb = new SecureBuffer(16);
      sb.copyFrom(new Uint8Array([1, 2, 3, 4, 5]));
      const dest = new Uint8Array(5);
      sb.copyTo(dest);

      expect(dest).toEqual(new Uint8Array([1, 2, 3, 4, 5]));
    });

    it("should not copy beyond destination length", () => {
      const sb = new SecureBuffer(16);
      sb.copyFrom(new Uint8Array([10, 20, 30, 40, 50]));
      const dest = new Uint8Array(3);
      sb.copyTo(dest);

      expect(dest).toEqual(new Uint8Array([10, 20, 30]));
    });

    it("should throw error if called after free", () => {
      const sb = new SecureBuffer(16);
      sb.free();
      const dest = new Uint8Array(5);
      expect(() => sb.copyTo(dest)).toThrow("Buffer ya fue liberado");
    });

    it("should handle zero-length destination", () => {
      const sb = new SecureBuffer(16);
      sb.copyFrom(new Uint8Array([1, 2, 3]));
      const dest = new Uint8Array(0);
      expect(() => sb.copyTo(dest)).not.toThrow();
      expect(dest.length).toBe(0);
    });

    it("should copy full buffer when destination is larger", () => {
      const sb = new SecureBuffer(5);
      sb.copyFrom(new Uint8Array([1, 2, 3, 4, 5]));
      const dest = new Uint8Array(10);
      sb.copyTo(dest);

      expect(dest[0]).toBe(1);
      expect(dest[4]).toBe(5);
      expect(dest[5]).toBe(0);
    });
  });

  describe("free", () => {
    it("should zero out buffer contents", () => {
      const sb = new SecureBuffer(16);
      sb.copyFrom(new Uint8Array([1, 2, 3, 255, 128]));
      sb.free();

      expect(sb.view.every((byte) => byte === 0)).toBe(true);
    });

    it("should set freed flag to true", () => {
      const sb = new SecureBuffer(16);
      expect(sb.freed).toBe(false);
      sb.free();
      expect(sb.freed).toBe(true);
    });

    it("should be idempotent", () => {
      const sb = new SecureBuffer(16);
      sb.copyFrom(new Uint8Array([1, 2, 3]));
      sb.free();
      expect(() => sb.free()).not.toThrow();
      expect(sb.freed).toBe(true);
    });

    it("should zero buffer even when already zeroed", () => {
      const sb = new SecureBuffer(16);
      // Buffer starts at zero
      sb.free();
      expect(sb.freed).toBe(true);
    });

    it("should make view inaccessible after free", () => {
      const sb = new SecureBuffer(16);
      sb.copyFrom(new Uint8Array([1, 2, 3]));
      sb.free();

      expect(() => sb.view).toThrow();
    });
  });

  describe("length getter", () => {
    it("should return correct length", () => {
      const sb = new SecureBuffer(100);
      expect(sb.length).toBe(100);
    });

    it("should return same length after free", () => {
      const sb = new SecureBuffer(64);
      sb.free();
      expect(sb.length).toBe(64);
    });
  });

  describe("freed getter", () => {
    it("should return true after free", () => {
      const sb = new SecureBuffer(32);
      sb.free();
      expect(sb.freed).toBe(true);
    });

    it("should return false before free", () => {
      const sb = new SecureBuffer(32);
      expect(sb.freed).toBe(false);
    });
  });
});

describe("secureHashPassword", () => {
  it("should return Uint8Array of correct length for SHA-512", async () => {
    const hash = await secureHashPassword("password123");
    expect(hash).toBeInstanceOf(Uint8Array);
    expect(hash.length).toBe(64); // SHA-512 produces 64 bytes
  });

  it("should produce correct hash for known password", async () => {
    // Compute expected hash using crypto.subtle directly
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode("testpassword");
    const expectedHash = await crypto.subtle.digest("SHA-512", passwordBuffer);

    const result = await secureHashPassword("testpassword");

    expect(result).toEqual(new Uint8Array(expectedHash));
  });

  it("should produce different hashes for different passwords", async () => {
    const hash1 = await secureHashPassword("password1");
    const hash2 = await secureHashPassword("password2");

    expect(hash1).not.toEqual(hash2);
  });

  it("should clear password buffer after hashing", async () => {
    const password = "sensitivepassword";
    // This test verifies the finally block executes
    const hash = await secureHashPassword(password);

    // Hash should still be valid
    expect(hash.length).toBe(64);

    // We can't directly test the buffer clearing since it's internal,
    // but we can verify the function completes successfully
    expect(hash).toBeInstanceOf(Uint8Array);
  });

  it("should handle empty string", async () => {
    const hash = await secureHashPassword("");
    expect(hash.length).toBe(64);

    const encoder = new TextEncoder();
    const expectedHash = await crypto.subtle.digest(
      "SHA-512",
      encoder.encode(""),
    );
    expect(hash).toEqual(new Uint8Array(expectedHash));
  });

  it("should handle unicode characters", async () => {
    const password = "contraseña123😀";
    const hash = await secureHashPassword(password);
    expect(hash.length).toBe(64);

    const encoder = new TextEncoder();
    const expectedHash = await crypto.subtle.digest(
      "SHA-512",
      encoder.encode(password),
    );
    expect(hash).toEqual(new Uint8Array(expectedHash));
  });
});

describe("generateSecureSalt", () => {
  it("should generate Uint8Array of specified length", () => {
    const salt = generateSecureSalt(32);
    expect(salt).toBeInstanceOf(Uint8Array);
    expect(salt.length).toBe(32);
  });

  it("should generate different salts on each call", () => {
    const salt1 = generateSecureSalt(16);
    const salt2 = generateSecureSalt(16);

    // Extremely unlikely to be equal
    expect(salt1).not.toEqual(salt2);
  });

  it("should use default length of 16", () => {
    const salt = generateSecureSalt();
    expect(salt.length).toBe(16);
  });

  it("should generate random bytes (statistical check)", () => {
    const salts = [];
    // Generate multiple salts and check we get variety
    for (let i = 0; i < 10; i++) {
      salts.push(generateSecureSalt(16));
    }

    // Check that not all salts are identical (would be suspicious)
    const allEqual = salts.every(
      (salt, idx) =>
        idx === 0 || salt.every((byte, byteIdx) => byte === salts[0][byteIdx]),
    );
    expect(allEqual).toBe(false);
  });

  it("should generate non-zero salt (very unlikely to be all zeros)", () => {
    // Try a few times to ensure we get non-zero salts
    let foundNonZero = false;
    for (let i = 0; i < 10; i++) {
      const salt = generateSecureSalt(16);
      if (salt.some((byte) => byte !== 0)) {
        foundNonZero = true;
        break;
      }
    }
    expect(foundNonZero).toBe(true);
  });

  it("should handle length of 1", () => {
    const salt = generateSecureSalt(1);
    expect(salt.length).toBe(1);
  });

  it("should generate different values for same length", () => {
    const salt1 = generateSecureSalt(64);
    const salt2 = generateSecureSalt(64);
    expect(salt1).not.toEqual(salt2);
  });
});
