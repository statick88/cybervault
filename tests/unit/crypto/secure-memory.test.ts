import {
  secureZero,
  SecureBuffer,
  generateSecureSalt,
  allocateForBinding,
} from "../../../src/infrastructure/crypto/secure-memory";

describe("secure-memory", () => {
  describe("secureZero", () => {
    it("zeros out a Uint8Array", () => {
      const buf = new Uint8Array([1, 2, 3, 4, 5]);
      secureZero(buf);
      expect(Array.from(buf)).toEqual([0, 0, 0, 0, 0]);
    });

    it("zeros out an ArrayBuffer", () => {
      const ab = new ArrayBuffer(4);
      new Uint8Array(ab).set([0xff, 0xab, 0xcd, 0xef]);
      secureZero(ab);
      expect(Array.from(new Uint8Array(ab))).toEqual([0, 0, 0, 0]);
    });

    it("handles empty buffer", () => {
      const buf = new Uint8Array(0);
      expect(() => secureZero(buf)).not.toThrow();
    });
  });

  describe("SecureBuffer", () => {
    it("creates buffer with specified length", () => {
      const sb = new SecureBuffer(32);
      expect(sb.length).toBe(32);
      expect(sb.freed).toBe(false);
    });

    it("copyFrom and view round-trip data", () => {
      const sb = new SecureBuffer(4);
      const data = new Uint8Array([10, 20, 30, 40]);
      sb.copyFrom(data);
      expect(Array.from(sb.view)).toEqual([10, 20, 30, 40]);
    });

    it("copyTo writes to destination buffer", () => {
      const sb = new SecureBuffer(4);
      sb.copyFrom(new Uint8Array([1, 2, 3, 4]));
      const dest = new Uint8Array(4);
      sb.copyTo(dest);
      expect(Array.from(dest)).toEqual([1, 2, 3, 4]);
    });

    it("free zeros the buffer and sets freed flag", () => {
      const sb = new SecureBuffer(4);
      sb.copyFrom(new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd]));
      sb.free();
      expect(sb.freed).toBe(true);
      expect(() => sb.view).toThrow("Buffer ya fue liberado");
    });

    it("double-free is a no-op (idempotent)", () => {
      const sb = new SecureBuffer(2);
      sb.free();
      expect(() => sb.free()).not.toThrow();
    });

    it("copyFrom throws after free", () => {
      const sb = new SecureBuffer(2);
      sb.free();
      expect(() => sb.copyFrom(new Uint8Array([1, 2]))).toThrow("Buffer ya fue liberado");
    });

    it("copyTo throws after free", () => {
      const sb = new SecureBuffer(2);
      sb.free();
      expect(() => sb.copyTo(new Uint8Array(2))).toThrow("Buffer ya fue liberado");
    });

    it("copyFrom throws when data exceeds capacity", () => {
      const sb = new SecureBuffer(2);
      expect(() => sb.copyFrom(new Uint8Array([1, 2, 3]))).toThrow(
        "Datos exceden capacidad del buffer",
      );
    });
  });

  describe("generateSecureSalt", () => {
    it("returns Uint8Array of default length 16", () => {
      const salt = generateSecureSalt();
      expect(salt).toBeInstanceOf(Uint8Array);
      expect(salt.length).toBe(16);
    });

    it("returns Uint8Array of custom length", () => {
      const salt = generateSecureSalt(32);
      expect(salt.length).toBe(32);
    });

    it("generates different salts each call", () => {
      const a = generateSecureSalt();
      const b = generateSecureSalt();
      expect(Array.from(a)).not.toEqual(Array.from(b));
    });
  });

  describe("allocateForBinding", () => {
    it("returns SecureBuffer with default size 64", () => {
      const sb = allocateForBinding();
      expect(sb).toBeInstanceOf(SecureBuffer);
      expect(sb.length).toBe(64);
    });

    it("returns SecureBuffer with custom size", () => {
      const sb = allocateForBinding(128);
      expect(sb.length).toBe(128);
    });
  });
});
