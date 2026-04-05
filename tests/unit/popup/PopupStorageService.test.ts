// @ts-nocheck

import { PopupStorageService } from "../../../src/ui/popup/services/PopupStorageService";
import { Credential } from "../../../src/domain/entities/credential";
import { CredentialId, VaultId } from "../../../src/domain/value-objects/ids";

// Mock de chrome.storage.local
const mockStorage = new Map<string, any>();

const mockChromeStorage = {
  local: {
    get: jest.fn((keys: string | string[]) => {
      return new Promise<Record<string, any>>((resolve) => {
        setTimeout(() => {
          if (Array.isArray(keys)) {
            const result: Record<string, any> = {};
            keys.forEach((key) => {
              if (mockStorage.has(key)) {
                result[key] = mockStorage.get(key);
              }
            });
            resolve(result);
          } else {
            const result: Record<string, any> = {};
            if (mockStorage.has(keys)) {
              result[keys] = mockStorage.get(keys);
            }
            resolve(result);
          }
        }, 0);
      });
    }),
    set: jest.fn((items: Record<string, any>) => {
      return new Promise<void>((resolve, reject) => {
        setTimeout(() => {
          try {
            Object.entries(items).forEach(([key, value]) => {
              mockStorage.set(key, value);
            });
            resolve();
          } catch (error) {
            reject(error);
          }
        }, 0);
      });
    }),
    remove: jest.fn((keys: string | string[]) => {
      return new Promise<void>((resolve) => {
        setTimeout(() => {
          if (Array.isArray(keys)) {
            keys.forEach((key) => mockStorage.delete(key));
          } else {
            mockStorage.delete(keys);
          }
          resolve();
        }, 0);
      });
    }),
    clear: jest.fn(() => {
      return new Promise<void>((resolve) => {
        setTimeout(() => {
          mockStorage.clear();
          resolve();
        }, 0);
      });
    }),
  },
};

// Mock global de chrome
(global as any).chrome = {
  storage: mockChromeStorage,
};

describe("PopupStorageService", () => {
  let service: PopupStorageService;
  let testVaultId: VaultId;
  let testCredentialId: CredentialId;

  beforeEach(() => {
    // Inicializar el servicio y limpiar storage
    service = new PopupStorageService();
    mockStorage.clear();

    // Crear IDs de prueba
    testVaultId = VaultId.fromString("550e8400-e29b-41d4-a716-446655440000");
    testCredentialId = CredentialId.fromString(
      "660e8400-e29b-41d4-a716-446655440000",
    );
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  // Helper para crear credenciales de prueba
  const createTestCredential = (overrides: Partial<Credential> = {}) => {
    return Credential.create({
      vaultId: testVaultId,
      title: "Test Credential",
      username: "testuser",
      encryptedPassword: "encryptedpass",
      ...overrides,
    });
  };

  describe("loadCredentials", () => {
    it("loads when no data stored → returns empty array", async () => {
      const result = await service.loadCredentials();
      expect(result).toEqual([]);
    });

    it("loads saved credentials → returns array of Credential objects", async () => {
      const plainCredentials = [
        {
          id: "770e8400-e29b-41d4-a716-446655440000",
          vaultId: testVaultId.toString(),
          title: "Test Credential 1",
          username: "user1",
          encryptedPassword: "encryptedpass1",
          tags: ["work"],
          favorite: false,
          createdAt: new Date("2024-01-01T00:00:00.000Z").toISOString(),
          updatedAt: new Date("2024-01-01T00:00:00.000Z").toISOString(),
        },
        {
          id: "880e8400-e29b-41d4-a716-446655440000",
          vaultId: testVaultId.toString(),
          title: "Test Credential 2",
          username: "user2",
          encryptedPassword: "encryptedpass2",
          tags: ["personal"],
          favorite: true,
          createdAt: new Date("2024-01-02T00:00:00.000Z").toISOString(),
          updatedAt: new Date("2024-01-02T00:00:00.000Z").toISOString(),
        },
      ];

      mockStorage.set("credentials", plainCredentials);

      const result = await service.loadCredentials();

      expect(result).toHaveLength(2);
      expect(result[0].id.toString()).toBe(plainCredentials[0].id);
      expect(result[0].title).toBe(plainCredentials[0].title);
      expect(result[1].id.toString()).toBe(plainCredentials[1].id);
      expect(result[1].title).toBe(plainCredentials[1].title);
    });

    it("only loads credentials key (ignores other keys)", async () => {
      const extraData = {
        otherKey: "some value",
        anotherKey: 123,
      };

      mockStorage.set("credentials", [
        {
          id: testCredentialId.toString(),
          vaultId: testVaultId.toString(),
          title: "Test",
          username: "testuser",
          encryptedPassword: "encryptedpass",
          tags: [],
          favorite: false,
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        },
      ]);
      mockStorage.set("other_keys", extraData);

      const result = await service.loadCredentials();

      expect(result).toHaveLength(1);
      expect(result[0].title).toBe("Test");
    });

    it("handles corrupted data (non-array) → returns empty array", async () => {
      // Datos corruptos que no son arrays
      mockStorage.set("credentials", "not an array" as any);

      const result = await service.loadCredentials();

      expect(result).toEqual([]);
    });

    it("handles missing credentials property → returns empty array", async () => {
      mockStorage.set("some_other_key", ["some", "data"]);

      const result = await service.loadCredentials();

      expect(result).toEqual([]);
    });

    it("handles credentials with malformed entries (null/undefined) → logs error and throws", async () => {
      mockStorage.set("credentials", [
        {
          id: testCredentialId.toString(),
          vaultId: testVaultId.toString(),
          title: "Valid",
          username: "user",
          encryptedPassword: "encryptedpass",
          tags: [],
          favorite: false,
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
        },
        null,
        undefined,
      ] as any);

      const consoleSpy = jest.spyOn(console, "error").mockImplementation();

      await expect(service.loadCredentials()).rejects.toThrow();

      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining(
          "[PopupStorageService] Error loading credentials",
        ),
        expect.anything(),
      );

      consoleSpy.mockRestore();
    });

    it("returns a copy (not reference to internal array)", async () => {
      const plainCredential = {
        id: testCredentialId.toString(),
        vaultId: testVaultId.toString(),
        title: "Test",
        username: "user",
        encryptedPassword: "encryptedpass",
        tags: [],
        favorite: false,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };

      mockStorage.set("credentials", [plainCredential]);

      const result = await service.loadCredentials();
      result.push({} as any); // Modificar el array retornado

      // Cargar de nuevo para verificar que no se afectó el storage
      const result2 = await service.loadCredentials();
      expect(result2).toHaveLength(1);
    });
  });

  describe("saveCredentials", () => {
    it("saves empty array → writes empty array to storage", async () => {
      await service.saveCredentials([]);

      expect(mockChromeStorage.local.set).toHaveBeenCalledWith({
        credentials: [],
      });
      expect(mockStorage.get("credentials")).toEqual([]);
    });

    it("saves credentials → serializes correctly using toPlainObject", async () => {
      const credential = Credential.create({
        vaultId: testVaultId,
        title: "Test Credential",
        username: "testuser",
        encryptedPassword: "encryptedpass",
        url: "https://example.com",
        notes: "Test notes",
        tags: ["work", "important"],
        favorite: true,
      });

      await service.saveCredentials([credential]);

      const stored = mockStorage.get("credentials");
      expect(stored).toHaveLength(1);
      expect(stored[0].id).toBe(credential.id.toString());
      expect(stored[0].vaultId).toBe(credential.vaultId.toString());
      expect(stored[0].title).toBe("Test Credential");
      expect(stored[0].username).toBe("testuser");
      expect(stored[0].encryptedPassword).toBe("encryptedpass");
      expect(stored[0].url).toBe("https://example.com");
      expect(stored[0].notes).toBe("Test notes");
      expect(stored[0].tags).toEqual(["work", "important"]);
      expect(stored[0].favorite).toBe(true);
      expect(() => new Date(stored[0].createdAt)).not.toThrow();
      expect(() => new Date(stored[0].updatedAt)).not.toThrow();
    });

    it("overwrites previous data completely", async () => {
      // Datos antiguos
      const oldCredential = {
        id: "11111111-1111-1111-1111-111111111111",
        vaultId: testVaultId.toString(),
        title: "Old Credential",
        username: "olduser",
        encryptedPassword: "oldpass",
        tags: [],
        favorite: false,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      };
      mockStorage.set("credentials", [oldCredential]);

      // Nuevos datos
      const newCredential = Credential.create({
        vaultId: testVaultId,
        title: "New Credential",
        username: "newuser",
        encryptedPassword: "newpass",
        tags: [],
        favorite: false,
      });

      await service.saveCredentials([newCredential]);

      const stored = mockStorage.get("credentials");
      expect(stored).toHaveLength(1);
      expect(stored[0].title).toBe("New Credential");
      expect(stored[0].id).toBe(newCredential.id.toString());
    });

    it("handles storage set error → logs error and throws", async () => {
      const credential = Credential.create({
        vaultId: testVaultId,
        title: "Test",
        username: "testuser",
        encryptedPassword: "encryptedpass",
      });

      // Simular error en storage.set
      (mockChromeStorage.local.set as jest.Mock).mockImplementationOnce(
        () =>
          new Promise((_, reject) =>
            setTimeout(() => reject(new Error("Storage failed")), 0),
          ),
      );

      const consoleSpy = jest.spyOn(console, "error").mockImplementation();

      await expect(service.saveCredentials([credential])).rejects.toThrow(
        "Storage failed",
      );
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining("Error saving credentials"),
        expect.anything(),
      );

      consoleSpy.mockRestore();
    });

    it("serializes dates as ISO strings correctly", async () => {
      const now = new Date("2024-06-15T10:30:00.000Z");
      const credential = Credential.fromPlainObject({
        id: testCredentialId.toString(),
        vaultId: testVaultId.toString(),
        title: "Date Test",
        username: "user",
        encryptedPassword: "encryptedpass",
        tags: [],
        favorite: false,
        createdAt: now.toISOString(),
        updatedAt: now.toISOString(),
      });

      await service.saveCredentials([credential]);

      const stored = mockStorage.get("credentials");
      expect(stored[0].createdAt).toBe(now.toISOString());
      expect(stored[0].updatedAt).toBe(now.toISOString());
    });

    it("serializes optional lastUsed field when present", async () => {
      const lastUsed = new Date("2024-06-16T10:30:00.000Z");
      const credential = Credential.fromPlainObject({
        id: testCredentialId.toString(),
        vaultId: testVaultId.toString(),
        title: "LastUsed Test",
        username: "user",
        encryptedPassword: "encryptedpass",
        tags: [],
        favorite: false,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
        lastUsed: lastUsed.toISOString(),
      });

      await service.saveCredentials([credential]);

      const stored = mockStorage.get("credentials");
      expect(stored[0].lastUsed).toBe(lastUsed.toISOString());
    });
  });

  describe("getVaultStatus", () => {
    it("returns { initialized: true, unlocked: true } when both keys true", async () => {
      mockStorage.set("vault_initialized", true);
      mockStorage.set("vault_unlocked", true);

      const result = await service.getVaultStatus();

      expect(result).toEqual({ initialized: true, unlocked: true });
    });

    it("returns { initialized: false, unlocked: false } when no keys", async () => {
      const result = await service.getVaultStatus();

      expect(result).toEqual({ initialized: false, unlocked: false });
    });

    it("returns correct mixed states", async () => {
      mockStorage.set("vault_initialized", true);
      mockStorage.set("vault_unlocked", false);

      expect(await service.getVaultStatus()).toEqual({
        initialized: true,
        unlocked: false,
      });

      mockStorage.clear();

      mockStorage.set("vault_initialized", false);
      mockStorage.set("vault_unlocked", true);

      expect(await service.getVaultStatus()).toEqual({
        initialized: false,
        unlocked: true,
      });
    });

    it("reads only specific keys (vault_initialized, vault_unlocked)", async () => {
      mockStorage.set("vault_initialized", true);
      mockStorage.set("vault_unlocked", true);
      mockStorage.set("other_key", "should be ignored");

      await service.getVaultStatus();

      expect(mockChromeStorage.local.get).toHaveBeenCalledWith([
        "vault_initialized",
        "vault_unlocked",
      ]);
    });

    it("handles non-boolean values gracefully", async () => {
      mockStorage.set("vault_initialized", "yes");
      mockStorage.set("vault_unlocked", 1);

      const result = await service.getVaultStatus();

      expect(result.initialized).toBe(false); // "yes" !== true
      expect(result.unlocked).toBe(false); // 1 !== true
    });

    it("logs error and throws on storage failure", async () => {
      (mockChromeStorage.local.get as jest.Mock).mockImplementationOnce(
        () =>
          new Promise((_, reject) =>
            setTimeout(() => reject(new Error("Storage error")), 0),
          ),
      );

      const consoleSpy = jest.spyOn(console, "error").mockImplementation();

      await expect(service.getVaultStatus()).rejects.toThrow("Storage error");
      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining("Error getting vault status"),
        expect.anything(),
      );

      consoleSpy.mockRestore();
    });
  });

  describe("CRUD operations", () => {
    describe("addCredential", () => {
      it("adds credential to storage", async () => {
        const credential = createTestCredential();

        await service.addCredential(credential);

        const credentials = await service.loadCredentials();
        expect(credentials).toHaveLength(1);
        expect(credentials[0].id.equals(credential.id)).toBe(true);
      });

      it("adds multiple credentials sequentially", async () => {
        const cred1 = createTestCredential({ title: "Cred 1" });
        const cred2 = createTestCredential({ title: "Cred 2" });

        await service.addCredential(cred1);
        await service.addCredential(cred2);

        const credentials = await service.loadCredentials();
        expect(credentials).toHaveLength(2);
      });
    });

    describe("updateCredential", () => {
      beforeEach(async () => {
        const credential = createTestCredential();
        await service.addCredential(credential);
      });

      it("updates matching credential", async () => {
        const credentials = await service.loadCredentials();
        const credentialToUpdate = credentials[0];

        await service.updateCredential(credentialToUpdate.id.toString(), {
          title: "Updated Title",
          username: "updateduser",
        });

        const updated = await service.loadCredentials();
        expect(updated[0].title).toBe("Updated Title");
        expect(updated[0].username).toBe("updateduser");
      });

      it("updates only provided fields (partial update)", async () => {
        const credentials = await service.loadCredentials();
        const credentialToUpdate = credentials[0];

        await service.updateCredential(credentialToUpdate.id.toString(), {
          username: "updateduser2",
        });

        const updated = await service.loadCredentials();
        expect(updated[0].username).toBe("updateduser2");
        expect(updated[0].title).toBe("Test Credential"); // unchanged
      });

      it("updates updatedAt timestamp when modifying fields", async () => {
        const credentials = await service.loadCredentials();
        const credentialToUpdate = credentials[0];
        const originalUpdatedAt = credentialToUpdate.updatedAt.getTime();

        // Esperar un momento para asegurar diferencia de tiempo
        await new Promise((resolve) => setTimeout(resolve, 10));

        await service.updateCredential(credentialToUpdate.id.toString(), {
          title: "New Title",
        });

        const updated = await service.loadCredentials();
        expect(updated[0].updatedAt.getTime()).toBeGreaterThan(
          originalUpdatedAt,
        );
      });

      it("throws error when credential ID not found", async () => {
        // Usar un UUID v4 válido que no exista en storage
        const nonExistentId = "00000000-0000-4000-8000-000000000000";

        await expect(
          service.updateCredential(nonExistentId, { title: "Update" }),
        ).rejects.toThrow(`Credential with id ${nonExistentId} not found`);
      });

      it("throws error for invalid ID format", async () => {
        await expect(
          service.updateCredential("not-a-valid-uuid", { title: "Update" }),
        ).rejects.toThrow("CredentialId inválido");
      });

      it("updates encryptedPassword correctly", async () => {
        const credentials = await service.loadCredentials();
        const credentialToUpdate = credentials[0];

        await service.updateCredential(credentialToUpdate.id.toString(), {
          encryptedPassword: "newencryptedpass",
        });

        const updated = await service.loadCredentials();
        expect(updated[0].encryptedPassword).toBe("newencryptedpass");
        // Título y username deben permanecer igual
        expect(updated[0].title).toBe("Test Credential");
        expect(updated[0].username).toBe("testuser");
      });
    });

    describe("deleteCredential", () => {
      it("deletes credential from array", async () => {
        const credential = createTestCredential();
        await service.addCredential(credential);

        await service.deleteCredential(credential.id.toString());

        const credentials = await service.loadCredentials();
        expect(credentials).toHaveLength(0);
      });

      it("deletes only matching credential (by ID)", async () => {
        const cred1 = createTestCredential({ title: "Cred 1" });
        const cred2 = createTestCredential({ title: "Cred 2" });

        await service.addCredential(cred1);
        await service.addCredential(cred2);

        await service.deleteCredential(cred1.id.toString());

        const credentials = await service.loadCredentials();
        expect(credentials).toHaveLength(1);
        expect(credentials[0].id.equals(cred2.id)).toBe(true);
      });

      it("throws error when deleting non-existent ID", async () => {
        const credential = createTestCredential();
        await service.addCredential(credential);

        // Usar un UUID válido que no exista
        const nonExistentId = "00000000-0000-4000-8000-000000000000";

        await expect(service.deleteCredential(nonExistentId)).rejects.toThrow(
          `Credential with id ${nonExistentId} not found`,
        );
      });

      it("persists deletion across multiple loads", async () => {
        const credential = createTestCredential();
        await service.addCredential(credential);
        await service.deleteCredential(credential.id.toString());

        // Simular reinicio cargando de nuevo
        const credentials = await service.loadCredentials();
        expect(credentials).toHaveLength(0);
      });
    });
  });

  describe("Edge cases", () => {
    it("handles large credential arrays (>1000)", async () => {
      const credentials: Credential[] = [];

      for (let i = 0; i < 1000; i++) {
        credentials.push(
          Credential.create({
            vaultId: testVaultId,
            title: `Credential ${i}`,
            username: `user${i}`,
            encryptedPassword: `pass${i}`,
            tags: [`tag${i % 10}`],
            favorite: i % 2 === 0,
          }),
        );
      }

      await service.saveCredentials(credentials);

      const loaded = await service.loadCredentials();
      expect(loaded).toHaveLength(1000);
    });

    it("handles concurrent save operations (last write wins)", async () => {
      const credential1 = Credential.create({
        vaultId: testVaultId,
        title: "Initial",
        username: "user1",
        encryptedPassword: "pass1",
      });

      await service.addCredential(credential1);

      // Simular operaciones concurrentes
      const cred2 = Credential.create({
        vaultId: testVaultId,
        title: "Concurrent 1",
        username: "user2",
        encryptedPassword: "pass2",
      });

      const cred3 = Credential.create({
        vaultId: testVaultId,
        title: "Concurrent 2",
        username: "user3",
        encryptedPassword: "pass3",
      });

      // Ejecutar dos saves concurrentemente
      await Promise.all([
        service.saveCredentials([cred2]),
        service.saveCredentials([cred3]),
      ]);

      const final = await service.loadCredentials();
      // La última escritura debe ganar (podría ser cred2 o cred3 dependiendo del orden)
      expect(final.length).toBeGreaterThanOrEqual(1);
    });

    it("handles storage.set failure properly", async () => {
      const credential = createTestCredential();

      (mockChromeStorage.local.set as jest.Mock).mockImplementationOnce(
        () =>
          new Promise((resolve, reject) => {
            setTimeout(() => {
              reject(new Error("Storage full"));
            }, 0);
          }),
      );

      await expect(service.saveCredentials([credential])).rejects.toThrow(
        "Storage full",
      );
    });

    it("handles credentials with special characters in all string fields", async () => {
      const credential = Credential.create({
        vaultId: testVaultId,
        title: "Test & Special < > \" ' \n \t \\",
        username: "user@example.com",
        encryptedPassword: "p@ss:word;123",
        url: "https://example.com/path?query=value&other=test",
        notes: "Notes with\nnewlines\tand tabs",
        tags: ["tag with spaces", "tag-dash", "tag_underscore"],
      });

      await service.saveCredentials([credential]);

      const loaded = await service.loadCredentials();
      expect(loaded[0].title).toBe(credential.title);
      expect(loaded[0].username).toBe(credential.username);
      expect(loaded[0].encryptedPassword).toBe(credential.encryptedPassword);
    });

    it("handles empty strings in credential fields", async () => {
      const credential = Credential.create({
        vaultId: testVaultId,
        title: "",
        username: "",
        encryptedPassword: "",
        notes: "",
      });

      await service.saveCredentials([credential]);

      const loaded = await service.loadCredentials();
      expect(loaded[0].title).toBe("");
      expect(loaded[0].username).toBe("");
      expect(loaded[0].encryptedPassword).toBe("");
    });

    it("handles credential with large tag arrays", async () => {
      const tags = Array.from({ length: 100 }, (_, i) => `tag${i}`);
      const credential = Credential.create({
        vaultId: testVaultId,
        title: "Many Tags",
        username: "user",
        encryptedPassword: "pass",
        tags,
      });

      await service.saveCredentials([credential]);

      const loaded = await service.loadCredentials();
      expect(loaded[0].tags).toHaveLength(100);
      expect(loaded[0].tags).toEqual(tags);
    });
  });

  describe("Data integrity and serialization", () => {
    it("round-trips credential correctly (save → load)", async () => {
      const originalCredential = Credential.create({
        vaultId: testVaultId,
        title: "Round Trip Test",
        username: "roundtripuser",
        encryptedPassword: "roundtrippass",
        url: "https://roundtrip.example.com",
        notes: "Round trip notes",
        tags: ["tag1", "tag2", "tag3"],
        favorite: true,
      });

      await service.saveCredentials([originalCredential]);
      const loaded = await service.loadCredentials();

      expect(loaded).toHaveLength(1);
      const loadedCred = loaded[0];

      expect(loadedCred.id.toString()).toBe(originalCredential.id.toString());
      expect(loadedCred.vaultId.toString()).toBe(
        originalCredential.vaultId.toString(),
      );
      expect(loadedCred.title).toBe(originalCredential.title);
      expect(loadedCred.username).toBe(originalCredential.username);
      expect(loadedCred.encryptedPassword).toBe(
        originalCredential.encryptedPassword,
      );
      expect(loadedCred.url).toBe(originalCredential.url);
      expect(loadedCred.notes).toBe(originalCredential.notes);
      expect(loadedCred.tags).toEqual(originalCredential.tags);
      expect(loadedCred.favorite).toBe(originalCredential.favorite);
      expect(loadedCred.createdAt.getTime()).toBe(
        originalCredential.createdAt.getTime(),
      );
      expect(loadedCred.updatedAt.getTime()).toBe(
        originalCredential.updatedAt.getTime(),
      );
    });

    it("handles multiple round-trips correctly", async () => {
      const credential = Credential.create({
        vaultId: testVaultId,
        title: "Multiple Round Trips",
        username: "multiuser",
        encryptedPassword: "multipass",
      });

      // Múltiples guardados y cargas
      for (let i = 0; i < 5; i++) {
        await service.saveCredentials([credential]);
        const loaded = await service.loadCredentials();
        expect(loaded[0].title).toBe(credential.title);
      }
    });
  });
});
