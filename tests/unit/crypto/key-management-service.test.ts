import { KeyManagementService } from "../../../src/infrastructure/crypto/KeyManagementService";

describe("KeyManagementService", () => {
  const kms = new KeyManagementService();

  describe("generateKeyPair", () => {
    it("returns publicKey and privateKey as JSON strings", async () => {
      const keys = await kms.generateKeyPair();

      expect(typeof keys.publicKey).toBe("string");
      expect(typeof keys.privateKey).toBe("string");

      const pub = JSON.parse(keys.publicKey);
      const priv = JSON.parse(keys.privateKey);
      expect(pub.kty).toBe("EC");
      expect(pub.crv).toBe("P-256");
      expect(priv.kty).toBe("EC");
      expect(priv.crv).toBe("P-256");
    });

    it("generates unique key pairs each call", async () => {
      const a = await kms.generateKeyPair();
      const b = await kms.generateKeyPair();
      expect(a.publicKey).not.toBe(b.publicKey);
      expect(a.privateKey).not.toBe(b.privateKey);
    });

    it("private key contains required JWK fields (d, x, y)", async () => {
      const keys = await kms.generateKeyPair();
      const priv = JSON.parse(keys.privateKey);

      expect(priv).toHaveProperty("d");
      expect(priv).toHaveProperty("x");
      expect(priv).toHaveProperty("y");
      expect(typeof priv.d).toBe("string");
      expect(typeof priv.x).toBe("string");
      expect(typeof priv.y).toBe("string");
    });

    it("public key contains required JWK fields (x, y) but no d", async () => {
      const keys = await kms.generateKeyPair();
      const pub = JSON.parse(keys.publicKey);

      expect(pub).toHaveProperty("x");
      expect(pub).toHaveProperty("y");
      expect(pub).not.toHaveProperty("d");
    });
  });
});
