import { SignatureService } from "../../../src/infrastructure/crypto/signature-service";
import { KeyManagementService } from "../../../src/infrastructure/crypto/KeyManagementService";

describe("SignatureService", () => {
  const kms = new KeyManagementService();
  const svc = new SignatureService();
  let keyPair: { publicKey: string; privateKey: string };

  beforeAll(async () => {
    keyPair = await kms.generateKeyPair();
  });

  describe("sign", () => {
    it("returns a base64 string", async () => {
      const sig = await svc.sign("hello", keyPair.privateKey);
      expect(typeof sig).toBe("string");
      expect(sig.length).toBeGreaterThan(0);
      // base64 characters only
      expect(sig).toMatch(/^[A-Za-z0-9+/]+=*$/);
    });

    it("produces different signatures for different data", async () => {
      const sig1 = await svc.sign("data-a", keyPair.privateKey);
      const sig2 = await svc.sign("data-b", keyPair.privateKey);
      expect(sig1).not.toBe(sig2);
    });
  });

  describe("verify", () => {
    it("returns true for a valid signature", async () => {
      const data = "verify me";
      const sig = await svc.sign(data, keyPair.privateKey);
      const result = await svc.verify(data, sig, keyPair.publicKey);
      expect(result).toBe(true);
    });

    it("returns false when data is tampered", async () => {
      const sig = await svc.sign("original", keyPair.privateKey);
      const result = await svc.verify("tampered", sig, keyPair.publicKey);
      expect(result).toBe(false);
    });

    it("returns false with wrong public key", async () => {
      const otherKeys = await kms.generateKeyPair();
      const sig = await svc.sign("secret", keyPair.privateKey);
      const result = await svc.verify("secret", sig, otherKeys.publicKey);
      expect(result).toBe(false);
    });

    it("returns false for invalid signature format", async () => {
      const result = await svc.verify("data", "not-a-sig", keyPair.publicKey);
      expect(result).toBe(false);
    });

    it("round-trips with unicode content", async () => {
      const data = "café — ñoño — 日本語";
      const sig = await svc.sign(data, keyPair.privateKey);
      const result = await svc.verify(data, sig, keyPair.publicKey);
      expect(result).toBe(true);
    });
  });
});
