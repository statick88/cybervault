/**
 * Tests Unitarios: ChromeStorageVaultRepository
 * Prueba la implementación del repositorio de vaults usando Chrome Storage
 */

import { ChromeStorageVaultRepository } from "../../../../src/infrastructure/repositories/ChromeStorageVaultRepository";
import { Vault } from "../../../../src/domain/entities/vault";
import { VaultId } from "../../../../src/domain/value-objects/ids";

// Mock storage variable (mutable)
let mockStorage: Record<string, unknown> = {};

// Implementaciones base de los mocks (funciones que usan mockStorage)
const baseGet = async (
  keys: string | string[],
): Promise<Record<string, unknown>> => {
  if (Array.isArray(keys)) {
    const result: Record<string, unknown> = {};
    keys.forEach((key) => {
      if (mockStorage[key] !== undefined) {
        result[key] = mockStorage[key];
      }
    });
    return result;
  }
  return { [keys]: mockStorage[keys] };
};

const baseSet = async (items: Record<string, unknown>): Promise<void> => {
  Object.assign(mockStorage, items);
};

const baseRemove = async (keys: string | string[]): Promise<void> => {
  if (Array.isArray(keys)) {
    keys.forEach((key) => {
      delete mockStorage[key];
    });
  } else {
    delete mockStorage[keys];
  }
};

const baseClear = async (): Promise<void> => {
  Object.keys(mockStorage).forEach((key) => {
    delete mockStorage[key];
  });
};

// Mock de chrome.storage
const mockChromeStorage = {
  local: {
    get: jest.fn(baseGet),
    set: jest.fn(baseSet),
    remove: jest.fn(baseRemove),
    clear: jest.fn(baseClear),
  },
};

// Mock del API de Chrome
beforeAll(() => {
  global.chrome = {
    storage: mockChromeStorage,
  } as any;
});

describe("ChromeStorageVaultRepository", () => {
  let repository: ChromeStorageVaultRepository;
  let testVault: Vault;
  let testVaultId: VaultId;

  beforeEach(() => {
    // Reset storage a vacío
    mockStorage = {};

    // Restaurar implementaciones base de los mocks
    mockChromeStorage.local.get = jest.fn(baseGet);
    mockChromeStorage.local.set = jest.fn(baseSet);
    mockChromeStorage.local.remove = jest.fn(baseRemove);
    mockChromeStorage.local.clear = jest.fn(baseClear);

    // Limpiar contadores de llamadas
    jest.clearAllMocks();

    repository = new ChromeStorageVaultRepository();
    testVaultId = VaultId.generate();
    testVault = Vault.create({
      name: "Test Vault",
      description: "Test Description",
      encryptedData: "encrypted-data-123",
      encryptionKeyId: "key-123",
      metadata: { test: "value" },
    });
  });

  describe("save", () => {
    it("debería guardar un vault correctamente", async () => {
      const result = await repository.save(testVault);

      expect(result).toEqual(testVault);
      expect(mockChromeStorage.local.set).toHaveBeenCalledWith({
        vault_data: testVault.toPlainObject(),
      });
    });

    it("debería sobreescribir vault existente", async () => {
      await repository.save(testVault);

      const updatedVault = Vault.create({
        name: "Updated Vault",
        encryptedData: "updated-data",
        encryptionKeyId: "key-456",
      });
      const result = await repository.save(updatedVault);

      expect(result).toEqual(updatedVault);
      const stored = await repository.findById(updatedVault.id);
      expect(stored?.name).toBe("Updated Vault");
    });

    it("debería persistir todos los campos incluyendo metadata", async () => {
      await repository.save(testVault);

      const stored = await repository.findById(testVault.id);
      expect(stored?.metadata).toEqual({ test: "value" });
    });
  });

  describe("findById", () => {
    beforeEach(async () => {
      await repository.save(testVault);
    });

    it("debería encontrar vault por ID existente", async () => {
      const result = await repository.findById(testVault.id);

      expect(result).toEqual(testVault);
      expect(result?.id.equals(testVault.id)).toBe(true);
    });

    it("debería retornar null para ID inexistente", async () => {
      const nonExistentId = VaultId.generate();
      const result = await repository.findById(nonExistentId);

      expect(result).toBeNull();
    });

    it("debería retornar null cuando no hay datos en storage", async () => {
      mockChromeStorage.local.clear();
      const result = await repository.findById(testVault.id);

      expect(result).toBeNull();
    });

    it("debería reconstruir Vault desde plainObject correctamente", async () => {
      const plain = testVault.toPlainObject();
      mockChromeStorage.local.set({ vault_data: plain });

      const result = await repository.findById(testVault.id);

      expect(result).not.toBeNull();
      expect(result?.id.equals(testVault.id)).toBe(true);
      expect(result?.name).toBe(testVault.name);
      expect(result?.encryptedData).toBe(testVault.encryptedData);
      expect(result?.encryptionKeyId).toBe(testVault.encryptionKeyId);
      expect(result?.createdAt.getTime()).toBe(testVault.createdAt.getTime());
      expect(result?.updatedAt.getTime()).toBe(testVault.updatedAt.getTime());
    });
  });

  describe("delete", () => {
    beforeEach(async () => {
      await repository.save(testVault);
    });

    it("debería eliminar vault por ID existente", async () => {
      const result = await repository.delete(testVault.id);

      expect(result).toBe(true);
      expect(mockChromeStorage.local.remove).toHaveBeenCalledWith("vault_data");
    });

    it("debería retornar false para ID inexistente", async () => {
      const nonExistentId = VaultId.generate();
      const result = await repository.delete(nonExistentId);

      expect(result).toBe(false);
      expect(mockChromeStorage.local.remove).not.toHaveBeenCalled();
    });

    it("debería retornar false cuando no hay datos en storage", async () => {
      mockChromeStorage.local.clear();
      const result = await repository.delete(testVault.id);

      expect(result).toBe(false);
    });

    it("debería eliminar completamente los datos", async () => {
      await repository.delete(testVault.id);
      const result = await repository.findById(testVault.id);

      expect(result).toBeNull();
    });
  });

  describe("list", () => {
    it("debería retornar array vacío cuando no hay vaults", async () => {
      const result = await repository.list();

      expect(result).toEqual([]);
    });

    it("debería retornar array con un vault", async () => {
      await repository.save(testVault);

      const result = await repository.list();

      expect(result).toHaveLength(1);
      expect(result[0]).toEqual(testVault);
    });

    it("debería retornar array con todos los vaults", async () => {
      const vault1 = Vault.create({
        name: "Vault 1",
        encryptedData: "data1",
        encryptionKeyId: "key1",
      });
      const vault2 = Vault.create({
        name: "Vault 2",
        encryptedData: "data2",
        encryptionKeyId: "key2",
      });

      // Nota: ChromeStorageVaultRepository solo guarda un vault a la vez
      // Este test verifica el comportamiento actual
      await repository.save(vault1);

      const result = await repository.list();

      expect(result).toHaveLength(1);
      expect(result[0].name).toBe("Vault 1");
    });

    it("debería reconstruir vaults desde plainObjects", async () => {
      const plain = testVault.toPlainObject();
      mockChromeStorage.local.set({ vault_data: plain });

      const result = await repository.list();

      expect(result).toHaveLength(1);
      expect(result[0].id.equals(testVault.id)).toBe(true);
      expect(result[0].name).toBe(testVault.name);
    });
  });

  describe("Serialización/Deserialización", () => {
    it("debería serializar y deserializar correctamente Vault", async () => {
      const plain = testVault.toPlainObject();
      const restored = Vault.fromPlainObject(plain);

      expect(restored.id.equals(testVault.id)).toBe(true);
      expect(restored.name).toBe(testVault.name);
      expect(restored.description).toBe(testVault.description);
      expect(restored.encryptedData).toBe(testVault.encryptedData);
      expect(restored.encryptionKeyId).toBe(testVault.encryptionKeyId);
      expect(restored.metadata).toEqual(testVault.metadata);
      expect(restored.createdAt.getTime()).toBe(testVault.createdAt.getTime());
      expect(restored.updatedAt.getTime()).toBe(testVault.updatedAt.getTime());
    });

    it("debería manejar vault sin description", async () => {
      const vaultNoDesc = Vault.create({
        name: "No Description",
        encryptedData: "data",
        encryptionKeyId: "key",
      });
      const plain = vaultNoDesc.toPlainObject();
      const restored = Vault.fromPlainObject(plain);

      expect(restored.description).toBeUndefined();
    });

    it("debería manejar vault sin metadata", async () => {
      const vaultNoMeta = Vault.create({
        name: "No Metadata",
        encryptedData: "data",
        encryptionKeyId: "key",
      });
      const plain = vaultNoMeta.toPlainObject();
      const restored = Vault.fromPlainObject(plain);

      expect(restored.metadata).toBeUndefined();
    });

    it("debería convertir fechas ISO strings a Date objects", async () => {
      const now = new Date();
      const vaultWithDates = new Vault({
        id: testVaultId,
        name: "Test",
        encryptedData: "data",
        encryptionKeyId: "key",
        createdAt: now,
        updatedAt: now,
      });
      const plain = vaultWithDates.toPlainObject();
      const restored = Vault.fromPlainObject(plain);

      expect(restored.createdAt instanceof Date).toBe(true);
      expect(restored.updatedAt instanceof Date).toBe(true);
      expect(restored.createdAt.getTime()).toBe(now.getTime());
    });
  });

  describe("Manejo de errores de chrome.storage", () => {
    it("debería propagar errores de storage.get", async () => {
      const error = new Error("Storage error");
      mockChromeStorage.local.get = jest.fn().mockRejectedValue(error);

      await expect(repository.findById(testVaultId)).rejects.toThrow(
        "Storage error",
      );
    });

    it("debería propagar errores de storage.set", async () => {
      const error = new Error("Storage set error");
      mockChromeStorage.local.set = jest.fn().mockRejectedValue(error);

      await expect(repository.save(testVault)).rejects.toThrow(
        "Storage set error",
      );
    });

    it("debería propagar errores de storage.remove", async () => {
      await repository.save(testVault);
      const error = new Error("Storage remove error");
      mockChromeStorage.local.remove = jest.fn().mockRejectedValue(error);

      await expect(repository.delete(testVault.id)).rejects.toThrow(
        "Storage remove error",
      );
    });
  });

  describe("Tests de integración completos", () => {
    it("debería completar ciclo completo CRUD", async () => {
      // Create
      const saved = await repository.save(testVault);
      expect(saved).toEqual(testVault);

      // Read
      const found = await repository.findById(testVault.id);
      expect(found).toEqual(testVault);

      // Update
      const updated = Vault.create({
        name: "Updated Name",
        encryptedData: "updated-data",
        encryptionKeyId: "new-key",
      });
      const savedUpdated = await repository.save(updated);
      const foundUpdated = await repository.findById(updated.id);
      expect(foundUpdated?.name).toBe("Updated Name");

      // Delete
      const deleted = await repository.delete(updated.id);
      expect(deleted).toBe(true);
      const afterDelete = await repository.findById(updated.id);
      expect(afterDelete).toBeNull();
    });

    it("debería mantener datos entre operaciones", async () => {
      await repository.save(testVault);

      const found1 = await repository.findById(testVault.id);
      const list = await repository.list();
      const found2 = await repository.findById(testVault.id);

      expect(found1).toEqual(testVault);
      expect(list).toHaveLength(1);
      expect(list[0]).toEqual(testVault);
      expect(found2).toEqual(testVault);
    });

    it("debería manejar vaults con datos grandes en encryptedData", async () => {
      const largeVault = Vault.create({
        name: "Large Vault",
        encryptedData: "a".repeat(10000),
        encryptionKeyId: "key-large",
      });
      await repository.save(largeVault);

      const found = await repository.findById(largeVault.id);
      expect(found?.encryptedData).toHaveLength(10000);
    });

    it("debería manejar metadata complejo", async () => {
      const complexMetadata = {
        nested: {
          deep: {
            value: "test",
            array: [1, 2, 3],
          },
        },
        dates: {
          created: new Date().toISOString(),
          modified: new Date().toISOString(),
        },
      };
      const vaultWithComplexMetadata = Vault.create({
        name: "Complex Metadata",
        encryptedData: "data",
        encryptionKeyId: "key",
        metadata: complexMetadata,
      });
      await repository.save(vaultWithComplexMetadata);

      const found = await repository.findById(vaultWithComplexMetadata.id);
      expect(found?.metadata).toEqual(complexMetadata);
    });
  });
});
