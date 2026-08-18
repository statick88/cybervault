import {
  VaultId,
  CredentialId,
  VulnerabilityId,
  CryptoHash,
} from "../../../src/domain/value-objects/ids";

describe("Branded ID value objects", () => {
  describe("VaultId", () => {
    it("generates unique IDs", () => {
      const a = VaultId.generate();
      const b = VaultId.generate();
      expect(a.toString()).not.toBe(b.toString());
    });

    it("creates from string", () => {
      const id = VaultId.fromString("vault-123");
      expect(id.toString()).toBe("vault-123");
    });

    it("throws on empty string", () => {
      expect(() => VaultId.fromString("")).toThrow("DomainId value must not be empty");
    });

    it("equals same value", () => {
      const a = VaultId.fromString("v1");
      const b = VaultId.fromString("v1");
      expect(a.equals(b)).toBe(true);
    });

    it("not equal to different value", () => {
      const a = VaultId.fromString("v1");
      const b = VaultId.fromString("v2");
      expect(a.equals(b)).toBe(false);
    });
  });

  describe("CredentialId", () => {
    it("generates unique IDs", () => {
      const a = CredentialId.generate();
      const b = CredentialId.generate();
      expect(a.toString()).not.toBe(b.toString());
    });

    it("creates from string", () => {
      const id = CredentialId.fromString("cred-456");
      expect(id.toString()).toBe("cred-456");
    });

    it("throws on empty string", () => {
      expect(() => CredentialId.fromString("")).toThrow("DomainId value must not be empty");
    });

    it("equals same value", () => {
      const a = CredentialId.fromString("c1");
      const b = CredentialId.fromString("c1");
      expect(a.equals(b)).toBe(true);
    });

    it("not equal to different value", () => {
      const a = CredentialId.fromString("c1");
      const b = CredentialId.fromString("c2");
      expect(a.equals(b)).toBe(false);
    });
  });

  describe("VulnerabilityId", () => {
    it("generates unique IDs", () => {
      const a = VulnerabilityId.generate();
      const b = VulnerabilityId.generate();
      expect(a.toString()).not.toBe(b.toString());
    });

    it("creates from string", () => {
      const id = VulnerabilityId.fromString("vuln-789");
      expect(id.toString()).toBe("vuln-789");
    });

    it("throws on empty string", () => {
      expect(() => VulnerabilityId.fromString("")).toThrow("DomainId value must not be empty");
    });

    it("equals same value", () => {
      const a = VulnerabilityId.fromString("v1");
      const b = VulnerabilityId.fromString("v1");
      expect(a.equals(b)).toBe(true);
    });
  });

  describe("CryptoHash", () => {
    it("creates from string", () => {
      const hash = CryptoHash.fromString("abc123def456");
      expect(hash.toString()).toBe("abc123def456");
    });

    it("throws on empty string", () => {
      expect(() => CryptoHash.fromString("")).toThrow("DomainId value must not be empty");
    });

    it("equals same value", () => {
      const a = CryptoHash.fromString("h1");
      const b = CryptoHash.fromString("h1");
      expect(a.equals(b)).toBe(true);
    });

    it("not equal to different value", () => {
      const a = CryptoHash.fromString("h1");
      const b = CryptoHash.fromString("h2");
      expect(a.equals(b)).toBe(false);
    });
  });
});
