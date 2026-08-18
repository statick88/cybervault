import { BindingSignature } from "../../../src/domain/value-objects/binding-signature";

describe("BindingSignature", () => {
  const validArgs = {
    domain: "Example.COM",
    timestamp: Date.now(),
    nonce: "abc123",
    signature: "sig-data",
  };

  describe("create()", () => {
    it("creates a valid signature with normalized domain", () => {
      const sig = BindingSignature.create(
        validArgs.domain,
        validArgs.timestamp,
        validArgs.nonce,
        validArgs.signature,
      );
      expect(sig.domain).toBe("example.com");
      expect(sig.timestamp).toBe(validArgs.timestamp);
      expect(sig.nonce).toBe("abc123");
      expect(sig.signature).toBe("sig-data");
    });

    it("trims whitespace from domain", () => {
      const sig = BindingSignature.create(
        "  Example.COM  ",
        validArgs.timestamp,
        validArgs.nonce,
        validArgs.signature,
      );
      expect(sig.domain).toBe("example.com");
    });

    it("throws on empty domain", () => {
      expect(() =>
        BindingSignature.create("", validArgs.timestamp, validArgs.nonce, validArgs.signature),
      ).toThrow("domain is required");
    });

    it("throws on whitespace-only domain", () => {
      expect(() =>
        BindingSignature.create("   ", validArgs.timestamp, validArgs.nonce, validArgs.signature),
      ).toThrow("domain is required");
    });

    it("throws on zero timestamp", () => {
      expect(() =>
        BindingSignature.create("example.com", 0, validArgs.nonce, validArgs.signature),
      ).toThrow("timestamp must be positive");
    });

    it("throws on negative timestamp", () => {
      expect(() =>
        BindingSignature.create("example.com", -1, validArgs.nonce, validArgs.signature),
      ).toThrow("timestamp must be positive");
    });

    it("throws on empty nonce", () => {
      expect(() =>
        BindingSignature.create("example.com", validArgs.timestamp, "", validArgs.signature),
      ).toThrow("nonce is required");
    });

    it("throws on empty signature", () => {
      expect(() =>
        BindingSignature.create("example.com", validArgs.timestamp, validArgs.nonce, ""),
      ).toThrow("signature is required");
    });
  });

  describe("isValid()", () => {
    it("returns true when within age window", () => {
      const now = Date.now();
      const sig = BindingSignature.create("example.com", now, "n", "s");
      expect(sig.isValid(now, 300_000)).toBe(true);
    });

    it("returns true when timestamp is slightly before current", () => {
      const now = Date.now();
      const sig = BindingSignature.create("example.com", now - 100_000, "n", "s");
      expect(sig.isValid(now, 300_000)).toBe(true);
    });

    it("returns false when timestamp exceeds max age", () => {
      const now = Date.now();
      const sig = BindingSignature.create("example.com", now - 600_000, "n", "s");
      expect(sig.isValid(now, 300_000)).toBe(false);
    });

    it("returns true when timestamp is slightly after current", () => {
      const now = Date.now();
      const sig = BindingSignature.create("example.com", now + 100_000, "n", "s");
      expect(sig.isValid(now, 300_000)).toBe(true);
    });

    it("returns false when future timestamp exceeds max age", () => {
      const now = Date.now();
      const sig = BindingSignature.create("example.com", now + 600_000, "n", "s");
      expect(sig.isValid(now, 300_000)).toBe(false);
    });
  });

  describe("toPlainObject() / fromPlainObject()", () => {
    it("roundtrips through plain object", () => {
      const sig = BindingSignature.create(
        "Example.COM",
        1700000000000,
        "nonce-val",
        "sig-val",
      );
      const plain = sig.toPlainObject();
      expect(plain).toEqual({
        domain: "example.com",
        timestamp: 1700000000000,
        nonce: "nonce-val",
        signature: "sig-val",
      });

      const restored = BindingSignature.fromPlainObject(plain);
      expect(restored.domain).toBe(sig.domain);
      expect(restored.timestamp).toBe(sig.timestamp);
      expect(restored.nonce).toBe(sig.nonce);
      expect(restored.signature).toBe(sig.signature);
    });
  });

  describe("immutability", () => {
    it("is frozen after creation", () => {
      const sig = BindingSignature.create("example.com", 1, "n", "s");
      expect(Object.isFrozen(sig)).toBe(true);
    });
  });
});
