import { HashingService } from "../../../src/infrastructure/crypto/HashingService";

describe("HashingService", () => {
  const svc = new HashingService();

  describe("hash", () => {
    it("returns a 64-char hex string (SHA-256)", async () => {
      const result = await svc.hash("hello");
      expect(result).toMatch(/^[0-9a-f]{64}$/);
    });

    it("is deterministic for the same input", async () => {
      const a = await svc.hash("same-input");
      const b = await svc.hash("same-input");
      expect(a).toBe(b);
    });

    it("produces different hashes for different inputs", async () => {
      const a = await svc.hash("input-1");
      const b = await svc.hash("input-2");
      expect(a).not.toBe(b);
    });

    it("hashes empty string", async () => {
      // SHA-256 of "" is e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
      const result = await svc.hash("");
      expect(result).toMatch(/^[0-9a-f]{64}$/);
      expect(result).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    });

    it("handles unicode input", async () => {
      const result = await svc.hash("café ñoño");
      expect(result).toMatch(/^[0-9a-f]{64}$/);
    });
  });
});
