import { Vault } from "@/src/domain/entities/vault";
import { VaultId } from "@/src/domain/value-objects/ids";

describe("Vault Entity", () => {
  // Helpers
  const createTestVaultId = (): VaultId =>
    VaultId.fromString("550e8400-e29b-41d4-a716-446655440000");

  const createTestDate = (): Date => new Date("2024-01-01T00:00:00.000Z");

  describe("Factory Method create()", () => {
    it("creates vault with minimal props → generates id, current dates", () => {
      const beforeCreation = new Date();

      const vault = Vault.create({
        name: "Test Vault",
        encryptedData: "encrypted-data",
        encryptionKeyId: "key-123",
      });

      const afterCreation = new Date();

      expect(vault.id).toBeInstanceOf(VaultId);
      expect(vault.name).toBe("Test Vault");
      expect(vault.description).toBeUndefined();
      expect(vault.encryptedData).toBe("encrypted-data");
      expect(vault.encryptionKeyId).toBe("key-123");
      expect(vault.metadata).toBeUndefined();
      expect(vault.createdAt.getTime()).toBeGreaterThanOrEqual(
        beforeCreation.getTime(),
      );
      expect(vault.createdAt.getTime()).toBeLessThanOrEqual(
        afterCreation.getTime(),
      );
      expect(vault.updatedAt.getTime()).toBeGreaterThanOrEqual(
        beforeCreation.getTime(),
      );
      expect(vault.updatedAt.getTime()).toBeLessThanOrEqual(
        afterCreation.getTime(),
      );
    });

    it("creates vault with all props → respects all values", () => {
      const id = createTestVaultId();
      const createdAt = createTestDate();
      const metadata = { version: 1, tags: ["work"] };

      const vault = Vault.create({
        name: "Complete Vault",
        description: "A complete vault",
        encryptedData: "full-encrypted-data",
        encryptionKeyId: "key-full",
        metadata,
      });

      expect(vault.id).toBeInstanceOf(VaultId);
      expect(vault.name).toBe("Complete Vault");
      expect(vault.description).toBe("A complete vault");
      expect(vault.encryptedData).toBe("full-encrypted-data");
      expect(vault.encryptionKeyId).toBe("key-full");
      expect(vault.metadata).toEqual(metadata);
      expect(vault.createdAt).toBeInstanceOf(Date);
      expect(vault.updatedAt).toBeInstanceOf(Date);
    });

    it("verifies metadata default is undefined", () => {
      const vault = Vault.create({
        name: "No Metadata",
        encryptedData: "data",
        encryptionKeyId: "key",
      });

      expect(vault.metadata).toBeUndefined();
    });

    it("verifies createdAt === updatedAt when creating", () => {
      const vault = Vault.create({
        name: "Equal Dates",
        encryptedData: "data",
        encryptionKeyId: "key",
      });

      expect(vault.createdAt.getTime()).toBe(vault.updatedAt.getTime());
    });
  });

  describe("fromPlainObject()", () => {
    const createPlainObject = (overrides = {}) => ({
      id: "770e8400-e29b-41d4-a716-446655440000",
      name: "Plain Object Vault",
      description: "Plain description",
      encryptedData: "plain-encrypted-data",
      encryptionKeyId: "plain-key",
      metadata: { plain: "metadata" },
      createdAt: "2024-01-01T00:00:00.000Z",
      updatedAt: "2024-01-02T00:00:00.000Z",
      ...overrides,
    });

    it("deserializes complete plain object → correct vault", () => {
      const plain = createPlainObject();

      const vault = Vault.fromPlainObject(plain);

      expect(vault.id.toString()).toBe(plain.id);
      expect(vault.name).toBe(plain.name);
      expect(vault.description).toBe(plain.description);
      expect(vault.encryptedData).toBe(plain.encryptedData);
      expect(vault.encryptionKeyId).toBe(plain.encryptionKeyId);
      expect(vault.metadata).toEqual(plain.metadata);
      expect(vault.createdAt.toISOString()).toBe(plain.createdAt);
      expect(vault.updatedAt.toISOString()).toBe(plain.updatedAt);
    });

    it("deserializes without description → undefined", () => {
      const plain = createPlainObject({ description: undefined });

      const vault = Vault.fromPlainObject(plain);

      expect(vault.description).toBeUndefined();
    });

    it("deserializes without metadata → undefined", () => {
      const plain = createPlainObject({ metadata: undefined });

      const vault = Vault.fromPlainObject(plain);

      expect(vault.metadata).toBeUndefined();
    });

    it("fails with invalid id (VaultId.fromString)", () => {
      const plain = createPlainObject({ id: "invalid-id" });

      expect(() => Vault.fromPlainObject(plain)).toThrow("VaultId inválido");
    });

    it("fails with invalid dates (new Date('invalid'))", () => {
      const plain = createPlainObject({
        createdAt: "invalid-date",
        updatedAt: "invalid-date",
      });

      expect(() => Vault.fromPlainObject(plain)).toThrow();
    });
  });

  describe("toPlainObject()", () => {
    const createVault = (overrides = {}) => {
      const plain = {
        id: "880e8400-e29b-41d4-a716-446655440000",
        name: "Serialization Vault",
        description: "Serialization description",
        encryptedData: "serial-encrypted-data",
        encryptionKeyId: "serial-key",
        metadata: { serial: "metadata" },
        createdAt: "2024-01-01T00:00:00.000Z",
        updatedAt: "2024-01-02T00:00:00.000Z",
        ...overrides,
      };

      return Vault.fromPlainObject(plain);
    };

    it("serializes complete vault → correct plain object", () => {
      const vault = createVault();

      const plain = vault.toPlainObject();

      expect(plain.id).toBe(vault.id.toString());
      expect(plain.name).toBe(vault.name);
      expect(plain.description).toBe(vault.description);
      expect(plain.encryptedData).toBe(vault.encryptedData);
      expect(plain.encryptionKeyId).toBe(vault.encryptionKeyId);
      expect(plain.metadata).toEqual(vault.metadata);
      expect(plain.createdAt).toBe(vault.createdAt.toISOString());
      expect(plain.updatedAt).toBe(vault.updatedAt.toISOString());
    });

    it("verifies date strings are ISO format", () => {
      const vault = createVault();

      const plain = vault.toPlainObject();

      expect(() => new Date(plain.createdAt)).not.toThrow();
      expect(() => new Date(plain.updatedAt)).not.toThrow();
      expect(plain.createdAt).toMatch(
        /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/,
      );
      expect(plain.updatedAt).toMatch(
        /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/,
      );
    });

    it("metadata is included if exists", () => {
      const vault = createVault();

      const plain = vault.toPlainObject();

      expect(plain.metadata).toBeDefined();
      expect(plain.metadata).toEqual(vault.metadata);
    });

    it("metadata is not included if undefined", () => {
      const vault = Vault.fromPlainObject({
        id: "990e8400-e29b-41d4-a716-446655440000",
        name: "No Metadata Vault",
        encryptedData: "data",
        encryptionKeyId: "key",
        createdAt: "2024-01-01T00:00:00.000Z",
        updatedAt: "2024-01-01T00:00:00.000Z",
      });

      const plain = vault.toPlainObject();

      expect(plain.metadata).toBeUndefined();
    });
  });

  describe("Getters", () => {
    const createTestVault = () => {
      const vault = Vault.create({
        name: "Getter Vault",
        description: "Getter description",
        encryptedData: "getter-encrypted-data",
        encryptionKeyId: "getter-key",
        metadata: { getter: "metadata" },
      });

      return vault;
    };

    it("get id → returns VaultId", () => {
      const vault = createTestVault();

      expect(vault.id).toBeInstanceOf(VaultId);
    });

    it("get name → returns string", () => {
      const vault = createTestVault();

      expect(typeof vault.name).toBe("string");
      expect(vault.name).toBe("Getter Vault");
    });

    it("get description → returns string | undefined", () => {
      const vault = createTestVault();

      expect(typeof vault.description).toBe("string");
      expect(vault.description).toBe("Getter description");

      const vaultNoDesc = Vault.create({
        name: "No Desc",
        encryptedData: "data",
        encryptionKeyId: "key",
      });
      expect(vaultNoDesc.description).toBeUndefined();
    });

    it("get encryptedData → returns string", () => {
      const vault = createTestVault();

      expect(typeof vault.encryptedData).toBe("string");
      expect(vault.encryptedData).toBe("getter-encrypted-data");
    });

    it("get encryptionKeyId → returns string", () => {
      const vault = createTestVault();

      expect(typeof vault.encryptionKeyId).toBe("string");
      expect(vault.encryptionKeyId).toBe("getter-key");
    });

    it("get metadata → returns Record | undefined", () => {
      const vault = createTestVault();

      expect(typeof vault.metadata).toBe("object");
      expect(vault.metadata).toEqual({ getter: "metadata" });
    });

    it("get createdAt → returns Date", () => {
      const vault = createTestVault();

      expect(vault.createdAt).toBeInstanceOf(Date);
    });

    it("get updatedAt → returns Date", () => {
      const vault = createTestVault();

      expect(vault.updatedAt).toBeInstanceOf(Date);
    });
  });

  describe("Mutator methods", () => {
    let vault: Vault;
    let vaultId: VaultId;

    beforeEach(() => {
      vaultId = createTestVaultId();
      const fixedCreatedAt = new Date("2024-01-01T00:00:00.000Z");
      const fixedUpdatedAt = new Date("2024-01-01T00:00:00.000Z");

      vault = Vault.fromPlainObject({
        id: vaultId.toString(),
        name: "Original Vault",
        description: "Original description",
        encryptedData: "original-encrypted-data",
        encryptionKeyId: "original-key",
        metadata: { existing: "value" },
        createdAt: fixedCreatedAt.toISOString(),
        updatedAt: fixedUpdatedAt.toISOString(),
      });
    });

    describe("updateData()", () => {
      it("changes encryptedData, encryptionKeyId, and updatedAt", () => {
        const originalUpdatedAt = vault.updatedAt.getTime();
        const newEncryptedData = "new-encrypted-data";
        const newEncryptionKeyId = "new-key";

        // Advance time slightly to ensure updatedAt changes
        const now = new Date();
        jest.spyOn(global, "Date").mockImplementation(() => now);

        vault.updateData(newEncryptedData, newEncryptionKeyId);

        expect(vault.encryptedData).toBe(newEncryptedData);
        expect(vault.encryptionKeyId).toBe(newEncryptionKeyId);
        expect(vault.updatedAt.getTime()).toBeGreaterThan(originalUpdatedAt);

        jest.restoreAllMocks();
      });

      it("does not change name", () => {
        const originalName = vault.name;

        vault.updateData("new-data", "new-key");

        expect(vault.name).toBe(originalName);
      });

      it("does not change metadata", () => {
        const originalMetadata = vault.metadata;

        vault.updateData("new-data", "new-key");

        expect(vault.metadata).toEqual(originalMetadata);
      });
    });

    describe("updateMetadata()", () => {
      it("merges with existing metadata and updates updatedAt", () => {
        const originalUpdatedAt = vault.updatedAt.getTime();
        const newMetadata = { newKey: "newValue" };

        // Advance time
        const now = new Date();
        jest.spyOn(global, "Date").mockImplementation(() => now);

        vault.updateMetadata(newMetadata);

        expect(vault.metadata).toEqual({
          existing: "value",
          newKey: "newValue",
        });
        expect(vault.updatedAt.getTime()).toBeGreaterThan(originalUpdatedAt);

        jest.restoreAllMocks();
      });

      it("overwrites existing keys", () => {
        const overwriteMetadata = { existing: "newValue" };

        vault.updateMetadata(overwriteMetadata);

        expect(vault.metadata).toEqual({ existing: "newValue" });
      });

      it("with empty metadata → merged (no changes) but updatedAt updates", () => {
        const originalUpdatedAt = vault.updatedAt.getTime();
        const originalMetadata = { ...vault.metadata };

        // Advance time
        const now = new Date();
        jest.spyOn(global, "Date").mockImplementation(() => now);

        vault.updateMetadata({});

        expect(vault.metadata).toEqual(originalMetadata);
        expect(vault.updatedAt.getTime()).toBeGreaterThan(originalUpdatedAt);

        jest.restoreAllMocks();
      });

      it("multiple updates accumulate correctly", () => {
        vault.updateMetadata({ key1: "value1" });
        expect(vault.metadata).toEqual({ existing: "value", key1: "value1" });

        vault.updateMetadata({ key2: "value2" });
        expect(vault.metadata).toEqual({
          existing: "value",
          key1: "value1",
          key2: "value2",
        });

        vault.updateMetadata({ key1: "updated" });
        expect(vault.metadata).toEqual({
          existing: "value",
          key1: "updated",
          key2: "value2",
        });
      });
    });
  });

  describe("Immutability", () => {
    it("metadata getter returns copy, mutations don't affect internal", () => {
      const vault = Vault.create({
        name: "Immutability Test",
        encryptedData: "data",
        encryptionKeyId: "key",
        metadata: { original: "value" },
      });

      const metadataCopy = vault.metadata;
      if (metadataCopy) {
        metadataCopy.newKey = "external";
        delete metadataCopy.original;
      }

      expect(vault.metadata).toEqual({ original: "value" });
    });

    it("toPlainObject() returns new objects, not references", () => {
      const vault = Vault.create({
        name: "Reference Test",
        encryptedData: "data",
        encryptionKeyId: "key",
        metadata: { deep: { nested: "value" } },
      });

      const plain = vault.toPlainObject();

      // Modify the returned object
      if (plain.metadata) {
        plain.metadata.newProp = "tampered";
        if (plain.metadata.deep) {
          (plain.metadata.deep as any).nested = "modified";
        }
      }

      // Original vault should be unchanged
      expect(vault.metadata).toEqual({ deep: { nested: "value" } });
    });

    it("description getter returns primitive (string copy)", () => {
      const vault = Vault.create({
        name: "Desc Test",
        encryptedData: "data",
        encryptionKeyId: "key",
        description: "original",
      });

      const desc = vault.description;
      if (desc) {
        desc = "modified";
      }

      expect(vault.description).toBe("original");
    });
  });

  describe("Edge cases", () => {
    it("creates vault with empty name → allowed", () => {
      const vault = Vault.create({
        name: "",
        encryptedData: "data",
        encryptionKeyId: "key",
      });

      expect(vault.name).toBe("");
    });

    it("creates vault with empty encryptedData → allowed", () => {
      const vault = Vault.create({
        name: "Vault",
        encryptedData: "",
        encryptionKeyId: "key",
      });

      expect(vault.encryptedData).toBe("");
    });

    it("creates vault with empty encryptionKeyId → allowed", () => {
      const vault = Vault.create({
        name: "Vault",
        encryptedData: "data",
        encryptionKeyId: "",
      });

      expect(vault.encryptionKeyId).toBe("");
    });

    it("handles complex metadata objects", () => {
      const complexMetadata = {
        deep: {
          nested: {
            veryDeep: {
              value: 123,
              array: [1, 2, 3],
            },
          },
        },
        array: ["a", "b", "c"],
        nullValue: null,
        boolean: true,
      };

      const vault = Vault.create({
        name: "Complex Metadata Vault",
        encryptedData: "data",
        encryptionKeyId: "key",
        metadata: complexMetadata,
      });

      expect(vault.metadata).toEqual(complexMetadata);
    });

    it("fromPlainObject() preserves all metadata types", () => {
      const plain = {
        id: "aa0e8400-e29b-41d4-a716-446655440000",
        name: "Types Vault",
        encryptedData: "data",
        encryptionKeyId: "key",
        metadata: {
          string: "text",
          number: 42,
          boolean: false,
          null: null,
          array: [1, 2, 3],
          object: { inner: "value" },
        },
        createdAt: "2024-01-01T00:00:00.000Z",
        updatedAt: "2024-01-01T00:00:00.000Z",
      };

      const vault = Vault.fromPlainObject(plain);

      expect(vault.metadata).toEqual(plain.metadata);
    });
  });
});
