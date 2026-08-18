import { Vault } from "../../../src/domain/entities/vault";
import { VaultId } from "../../../src/domain/value-objects/ids";

describe("Vault entity", () => {
  const validProps = {
    name: "My Vault",
    description: "Personal credentials",
    encryptedData: "encrypted-payload-base64",
    encryptionKeyId: "key-abc-123",
    ownerId: "user-001",
    metadata: { color: "blue", count: 42 },
  };

  describe("create (factory method)", () => {
    it("creates a Vault with generated id and timestamps", () => {
      const vault = Vault.create(validProps);

      expect(vault.id).toBeInstanceOf(VaultId);
      expect(vault.name).toBe("My Vault");
      expect(vault.description).toBe("Personal credentials");
      expect(vault.encryptedData).toBe("encrypted-payload-base64");
      expect(vault.encryptionKeyId).toBe("key-abc-123");
      expect(vault.ownerId).toBe("user-001");
      expect(vault.createdAt).toBeInstanceOf(Date);
      expect(vault.updatedAt).toBeInstanceOf(Date);
    });

    it("sets optional fields to undefined when omitted", () => {
      const vault = Vault.create({
        name: "Minimal Vault",
        encryptedData: "",
        encryptionKeyId: "key-1",
      });

      expect(vault.description).toBeUndefined();
      expect(vault.ownerId).toBeUndefined();
      expect(vault.metadata).toBeUndefined();
    });

    it("generates unique ids across calls", () => {
      const a = Vault.create({ ...validProps, name: "A" });
      const b = Vault.create({ ...validProps, name: "B" });
      expect(a.id.equals(b.id)).toBe(false);
    });
  });

  describe("getters return defensive copies", () => {
    it("metadata returns a deep copy", () => {
      const vault = Vault.create(validProps);
      const m1 = vault.metadata;
      const m2 = vault.metadata;
      expect(m1).toEqual(m2);
      expect(m1).not.toBe(m2);
    });
  });

  describe("updateData", () => {
    it("replaces encryptedData and encryptionKeyId, bumps updatedAt", () => {
      const vault = Vault.create(validProps);
      const before = vault.updatedAt.getTime();

      vault.updateData("new-ciphertext", "new-key-id");

      expect(vault.encryptedData).toBe("new-ciphertext");
      expect(vault.encryptionKeyId).toBe("new-key-id");
      expect(vault.updatedAt.getTime()).toBeGreaterThanOrEqual(before);
    });
  });

  describe("updateMetadata", () => {
    it("merges new metadata into existing", () => {
      const vault = Vault.create(validProps);
      vault.updateMetadata({ color: "red" });

      const meta = vault.metadata;
      expect(meta?.color).toBe("red");
      expect(meta?.count).toBe(42);
    });

    it("creates metadata if none existed", () => {
      const vault = Vault.create({
        name: "No Meta",
        encryptedData: "",
        encryptionKeyId: "k",
      });
      vault.updateMetadata({ newKey: "val" });

      expect(vault.metadata).toEqual({ newKey: "val" });
    });
  });

  describe("toPlainObject", () => {
    it("serializes all fields including dates as ISO strings", () => {
      const vault = Vault.create(validProps);
      const obj = vault.toPlainObject();

      expect(obj.id).toBe(vault.id.toString());
      expect(obj.name).toBe("My Vault");
      expect(obj.createdAt).toBe(vault.createdAt.toISOString());
      expect(obj.updatedAt).toBe(vault.updatedAt.toISOString());
      expect(obj.metadata).toEqual(validProps.metadata);
    });
  });

  describe("toSafeObject", () => {
    it("excludes encryptedData from output", () => {
      const vault = Vault.create(validProps);
      const safe = vault.toSafeObject();

      expect(safe).not.toHaveProperty("encryptedData");
      expect(safe.id).toBe(vault.id.toString());
      expect(safe.name).toBe("My Vault");
    });
  });

  describe("fromPlainObject", () => {
    it("deserializes from a plain object round-trip", () => {
      const original = Vault.create(validProps);
      const plain = original.toPlainObject();
      const restored = Vault.fromPlainObject(plain);

      expect(restored.id.equals(original.id)).toBe(true);
      expect(restored.name).toBe(original.name);
      expect(restored.encryptedData).toBe(original.encryptedData);
      expect(restored.createdAt.toISOString()).toBe(original.createdAt.toISOString());
    });
  });

  describe("constructor", () => {
    it("accepts a fully formed VaultProps directly", () => {
      const id = VaultId.fromString("direct-id");
      const now = new Date("2025-01-01T00:00:00Z");
      const vault = new Vault({
        id,
        name: "Direct",
        encryptedData: "data",
        encryptionKeyId: "k",
        createdAt: now,
        updatedAt: now,
      });

      expect(vault.id.equals(id)).toBe(true);
      expect(vault.name).toBe("Direct");
    });
  });
});
