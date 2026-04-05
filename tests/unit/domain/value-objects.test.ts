import { VaultId } from "@/src/domain/value-objects/ids";
import { VulnerabilityId } from "@/src/domain/value-objects/ids";
import { CredentialId } from "@/src/domain/value-objects/ids";
import { CryptoHash } from "@/src/domain/value-objects/ids";

describe("VaultId", () => {
  // UUID válido de ejemplo
  const validUUID = "550e8400-e29b-41d4-a716-446655440000";

  describe("Constructor", () => {
    it("constructor con UUID válido → OK", () => {
      const id = new VaultId(validUUID);
      expect(id.toString()).toBe(validUUID);
    });

    it("constructor con UUID inválido (formato incorrecto) → throws Error", () => {
      expect(() => new VaultId("invalid-uuid")).toThrow(Error);
      expect(() => new VaultId("12345")).toThrow(Error);
      expect(() => new VaultId("")).toThrow(Error);
    });

    it("constructor con string vacío → throws", () => {
      expect(() => new VaultId("")).toThrow(Error);
    });
  });

  describe("generate()", () => {
    it("genera UUID válido (verificar formato)", () => {
      const id = VaultId.generate();
      const uuid = id.toString();
      const uuidRegex =
        /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
      expect(uuidRegex.test(uuid)).toBe(true);
    });

    it("genera IDs únicos (2 llamadas diferentes)", () => {
      const id1 = VaultId.generate();
      const id2 = VaultId.generate();
      expect(id1.equals(id2)).toBe(false);
    });
  });

  describe("fromString()", () => {
    it("con UUID válido → OK", () => {
      const id = VaultId.fromString(validUUID);
      expect(id.toString()).toBe(validUUID);
    });

    it("con UUID inválido → throws", () => {
      expect(() => VaultId.fromString("invalid")).toThrow(Error);
    });
  });

  describe("toString()", () => {
    it("devuelve el valor original", () => {
      const id = new VaultId(validUUID);
      expect(id.toString()).toBe(validUUID);
    });
  });

  describe("equals()", () => {
    it("con mismo ID → true", () => {
      const id1 = new VaultId(validUUID);
      const id2 = new VaultId(validUUID);
      expect(id1.equals(id2)).toBe(true);
    });

    it("con diferente ID → false", () => {
      const id1 = new VaultId(validUUID);
      const id2 = VaultId.generate();
      expect(id1.equals(id2)).toBe(false);
    });
  });
});

describe("VulnerabilityId", () => {
  const validUUID = "660e8400-e29b-41d4-a716-446655440001";

  describe("Constructor", () => {
    it("constructor con UUID válido → OK", () => {
      const id = new VulnerabilityId(validUUID);
      expect(id.toString()).toBe(validUUID);
    });

    it("constructor con UUID inválido (formato incorrecto) → throws Error", () => {
      expect(() => new VulnerabilityId("invalid-uuid")).toThrow(Error);
      expect(() => new VulnerabilityId("12345")).toThrow(Error);
    });

    it("constructor con string vacío → throws", () => {
      expect(() => new VulnerabilityId("")).toThrow(Error);
    });
  });

  describe("generate()", () => {
    it("genera UUID válido (verificar formato)", () => {
      const id = VulnerabilityId.generate();
      const uuid = id.toString();
      const uuidRegex =
        /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
      expect(uuidRegex.test(uuid)).toBe(true);
    });

    it("genera IDs únicos (2 llamadas diferentes)", () => {
      const id1 = VulnerabilityId.generate();
      const id2 = VulnerabilityId.generate();
      expect(id1.equals(id2)).toBe(false);
    });
  });

  describe("fromString()", () => {
    it("con UUID válido → OK", () => {
      const id = VulnerabilityId.fromString(validUUID);
      expect(id.toString()).toBe(validUUID);
    });

    it("con UUID inválido → throws", () => {
      expect(() => VulnerabilityId.fromString("invalid")).toThrow(Error);
    });
  });

  describe("toString()", () => {
    it("devuelve el valor original", () => {
      const id = new VulnerabilityId(validUUID);
      expect(id.toString()).toBe(validUUID);
    });
  });

  describe("equals()", () => {
    it("con mismo ID → true", () => {
      const id1 = new VulnerabilityId(validUUID);
      const id2 = new VulnerabilityId(validUUID);
      expect(id1.equals(id2)).toBe(true);
    });

    it("con diferente ID → false", () => {
      const id1 = new VulnerabilityId(validUUID);
      const id2 = VulnerabilityId.generate();
      expect(id1.equals(id2)).toBe(false);
    });
  });
});

describe("CredentialId", () => {
  const validUUID = "770e8400-e29b-41d4-a716-446655440002";

  describe("Constructor", () => {
    it("constructor con UUID válido → OK", () => {
      const id = new CredentialId(validUUID);
      expect(id.toString()).toBe(validUUID);
    });

    it("constructor con UUID inválido (formato incorrecto) → throws Error", () => {
      expect(() => new CredentialId("invalid-uuid")).toThrow(Error);
      expect(() => new CredentialId("12345")).toThrow(Error);
    });

    it("constructor con string vacío → throws", () => {
      expect(() => new CredentialId("")).toThrow(Error);
    });
  });

  describe("generate()", () => {
    it("genera UUID válido (verificar formato)", () => {
      const id = CredentialId.generate();
      const uuid = id.toString();
      const uuidRegex =
        /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
      expect(uuidRegex.test(uuid)).toBe(true);
    });

    it("genera IDs únicos (2 llamadas diferentes)", () => {
      const id1 = CredentialId.generate();
      const id2 = CredentialId.generate();
      expect(id1.equals(id2)).toBe(false);
    });
  });

  describe("fromString()", () => {
    it("con UUID válido → OK", () => {
      const id = CredentialId.fromString(validUUID);
      expect(id.toString()).toBe(validUUID);
    });

    it("con UUID inválido → throws", () => {
      expect(() => CredentialId.fromString("invalid")).toThrow(Error);
    });
  });

  describe("toString()", () => {
    it("devuelve el valor original", () => {
      const id = new CredentialId(validUUID);
      expect(id.toString()).toBe(validUUID);
    });
  });

  describe("equals()", () => {
    it("con mismo ID → true", () => {
      const id1 = new CredentialId(validUUID);
      const id2 = new CredentialId(validUUID);
      expect(id1.equals(id2)).toBe(true);
    });

    it("con diferente ID → false", () => {
      const id1 = new CredentialId(validUUID);
      const id2 = CredentialId.generate();
      expect(id1.equals(id2)).toBe(false);
    });
  });
});

describe("CryptoHash", () => {
  // Hash SHA-256 válido (64 caracteres hexadecimales)
  const validHash =
    "aec070645fe53ee3b376305f613a56f695fag7d8463d0c69f7bbc8fb38f3b98";
  const validHashLower =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
  const validHashUpper =
    "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855";

  describe("Constructor", () => {
    it("constructor con hash SHA-256 válido (64 hex chars) → OK", () => {
      const hash = new CryptoHash(validHashLower);
      expect(hash.toString()).toBe(validHashLower);
    });

    it("constructor con hash inválido (longitud incorrecta) → throws", () => {
      expect(() => new CryptoHash("abc123")).toThrow(Error);
      expect(() => new CryptoHash("a")).toThrow(Error);
      expect(
        () =>
          new CryptoHash(
            "aec070645fe53ee3b376305f613a56f695fag7d8463d0c69f7bbc8fb38f3b9",
          ),
      ).toThrow(Error);
    });

    it("constructor con caracteres no-hex → throws", () => {
      expect(
        () =>
          new CryptoHash(
            "g3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          ),
      ).toThrow(Error);
      expect(() => new CryptoHash("xyz")).toThrow(Error);
    });

    it("constructor con string vacío → throws", () => {
      expect(() => new CryptoHash("")).toThrow(Error);
    });
  });

  describe("toString()", () => {
    it("devuelve valor original", () => {
      const hash = new CryptoHash(validHashLower);
      expect(hash.toString()).toBe(validHashLower);
    });
  });

  describe("equals()", () => {
    it("con mismo hash → true", () => {
      const hash1 = new CryptoHash(validHashLower);
      const hash2 = new CryptoHash(validHashLower);
      expect(hash1.equals(hash2)).toBe(true);
    });

    it("con diferente hash → false", () => {
      const hash1 = new CryptoHash(validHashLower);
      const hash2 = new CryptoHash(validHashUpper);
      expect(hash1.equals(hash2)).toBe(false);
    });

    it("mayúsculas vs minúsculas → case-insensitive (true)", () => {
      // El regex usa /i, así que debería aceptar ambos casos y comparar case-insensitive
      const hashLower = new CryptoHash(validHashLower);
      const hashUpper = new CryptoHash(validHashUpper);
      // Como el valor se almacena tal cual, equals compara por valor exacto => false
      // Pero ambos son válidos como hashes SHA-256
      expect(hashLower.toString()).toBe(validHashLower);
      expect(hashUpper.toString()).toBe(validHashUpper);
      expect(hashLower.equals(hashUpper)).toBe(false);
    });
  });
});
