// Full corrected test file with all fixes incorporated.
// See the uploaded file for the complete content.

// @ts-nocheck

import {
  describe,
  it,
  expect,
  beforeEach,
  afterEach,
  jest,
} from "@jest/globals";

let storageData: Record<string, any> = {};

const mockStorage = {
  get: jest.fn(async (keys: any) => {
    if (Array.isArray(keys)) {
      const result: Record<string, any> = {};
      for (const key of keys) {
        if (storageData[key] !== undefined) {
          result[key] = storageData[key];
        }
      }
      return result;
    }
    return { [keys]: storageData[keys] };
  }),
  set: jest.fn(async (items: Record<string, any>) => {
    for (const key in items) {
      storageData[key] = items[key];
    }
  }),
  remove: jest.fn(async (keys: string | string[]) => {
    if (Array.isArray(keys)) {
      keys.forEach((key) => delete storageData[key]);
    } else {
      delete storageData[keys];
    }
  }),
};

(global as any).chrome = {
  storage: {
    local: mockStorage,
  },
};

const mockIsVaultUnlocked = jest.fn();
const mockGetStatus = jest.fn();

jest.mock("@/infrastructure/crypto/master-key-manager", () => ({
  isVaultUnlocked: mockIsVaultUnlocked,
}));

import { PopupStorageService } from "../../../src/ui/popup/services/PopupStorageService";
import { CredentialsService } from "../../../src/ui/popup/services/CredentialsService";
import { Credential } from "../../../src/domain/entities/credential";
import { CredentialId, VaultId } from "../../../src/domain/value-objects/ids";

describe("CredentialsService", () => {
  let service: CredentialsService;
  let storageService: PopupStorageService;
  let testVaultId: VaultId;
  let testCredentialId: CredentialId;

  beforeEach(() => {
    jest.clearAllMocks();
    storageData = {};

    mockIsVaultUnlocked.mockReturnValue(true);
    mockGetStatus.mockReturnValue({
      initialized: true,
      unlocked: true,
      sessionValid: true,
      unlockTime: Date.now(),
    });

    storageService = new PopupStorageService();
    service = new CredentialsService(storageService, {
      getStatus: mockGetStatus,
      isSessionValid: jest.fn(() => true),
    } as any);

    testVaultId = VaultId.fromString("550e8400-e29b-41d4-a716-446655440000");
    testCredentialId = CredentialId.fromString(
      "660e8400-e29b-41d4-a716-446655440000",
    );
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  const createTestCredential = (overrides: Partial<Credential> = {}) => {
    return Credential.create({
      vaultId: testVaultId,
      title: "Test Credential",
      username: "testuser",
      encryptedPassword: "encryptedpass",
      ...overrides,
    });
  };

  const createPlainCredential = (overrides: Record<string, any> = {}) => {
    return {
      vaultId: testVaultId.toString(),
      title: "Test Credential",
      username: "testuser",
      encryptedPassword: "encryptedpass",
      tags: [],
      favorite: false,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
      ...overrides,
      id: CredentialId.generate().toString(),
    };
  };

  describe("loadAll", () => {
    it("carga desde storage, setea estado, emite credentials:loaded", async () => {
      const plainCredentials = [
        createPlainCredential({ title: "Cred 1" }),
        createPlainCredential({ title: "Cred 2" }),
      ];
      mockStorage.set({ credentials: plainCredentials });

      const result = await service.loadAll();

      expect(result).toHaveLength(2);
      expect(service.getAll()).toHaveLength(2);
      expect(service.getFiltered()).toHaveLength(2);
      expect(mockStorage.get).toHaveBeenCalledWith(["credentials"]);
    });

    it("si vault bloqueado → lanza error", async () => {
      mockGetStatus.mockReturnValue({
        initialized: true,
        unlocked: false,
        sessionValid: false,
        unlockTime: null,
      });

      mockStorage.set({ credentials: [] });

      await expect(service.loadAll()).rejects.toThrow(
        "Vault is locked. Unlock the vault first.",
      );
    });

    it("si storage vacío → retorna []", async () => {
      const result = await service.loadAll();
      expect(result).toEqual([]);
      expect(service.getAll()).toEqual([]);
      expect(service.getFiltered()).toEqual([]);
    });

    it("aplica ordenamiento después de cargar", async () => {
      const plainCredentials = [
        createPlainCredential({ title: "Zebra", favorite: false }),
        createPlainCredential({ title: "Apple", favorite: true }),
        createPlainCredential({ title: "Mango", favorite: false }),
      ];
      mockStorage.set({ credentials: plainCredentials });

      await service.loadAll();

      const all = service.getAll();
      expect(all[0].title).toBe("Apple");
      expect(all[1].title).toBe("Mango");
      expect(all[2].title).toBe("Zebra");
    });

    it("emite eventos credentials:loaded y credentials:changed", async () => {
      const loadedCallback = jest.fn();
      const changedCallback = jest.fn();

      service.on("credentials:loaded", loadedCallback);
      service.on("credentials:changed", changedCallback);

      mockStorage.set({
        credentials: [createPlainCredential({ title: "Test" })],
      });

      await service.loadAll();

      expect(loadedCallback).toHaveBeenCalledTimes(1);
      expect(changedCallback).toHaveBeenCalledTimes(1);
    });
  });

  describe("getAll", () => {
    it("retorna copia (no referencia interna)", async () => {
      await service.loadAll();
      const all1 = service.getAll();
      all1.push({} as any);
      const all2 = service.getAll();
      expect(all2.length).toBe(0);
    });

    it("retorna array ordenado: favorites first, luego alfabético por title", async () => {
      const plainCredentials = [
        createPlainCredential({ title: "Z", favorite: false }),
        createPlainCredential({ title: "A", favorite: true }),
      ];
      mockStorage.set({ credentials: plainCredentials });
      await service.loadAll();
      const all = service.getAll();
      expect(all.map((c) => c.title)).toEqual(["A", "Z"]);
    });
  });

  describe("getFiltered", () => {
    it("retorna copia (no referencia interna)", async () => {
      await service.loadAll();
      const filtered1 = service.getFiltered();
      filtered1.push({} as any);
      const filtered2 = service.getFiltered();
      expect(filtered2.length).toBe(0);
    });

    it("retorna array ordenado igual que getAll", async () => {
      const plainCredentials = [
        createPlainCredential({ title: "Z", favorite: false }),
        createPlainCredential({ title: "A", favorite: true }),
      ];
      mockStorage.set({ credentials: plainCredentials });
      await service.loadAll();
      const filtered = service.getFiltered();
      expect(filtered.map((c) => c.title)).toEqual(["A", "Z"]);
    });
  });

  describe("add", () => {
    it("crea nueva Credential con ID, fechas, guarda en storage, emite changed", async () => {
      const initialTime = Date.now();
      await new Promise((resolve) => setTimeout(resolve, 10));
      mockStorage.set({ credentials: [] });

      const newCredential = await service.add({
        vaultId: testVaultId,
        title: "New Credential",
        username: "newuser",
        encryptedPassword: "newpass",
        favorite: true,
      });

      expect(newCredential.id).toBeDefined();
      expect(newCredential.title).toBe("New Credential");
      expect(newCredential.createdAt.getTime()).toBeGreaterThanOrEqual(
        initialTime,
      );
      expect(newCredential.updatedAt.getTime()).toBeGreaterThanOrEqual(
        initialTime,
      );
      expect(newCredential.favorite).toBe(true);

      const saved = await storageService.loadCredentials();
      expect(saved).toHaveLength(1);
      expect(saved[0].id.equals(newCredential.id)).toBe(true);
    });

    it("add con vault locked → lanza error", async () => {
      mockGetStatus.mockReturnValue({
        initialized: true,
        unlocked: false,
        sessionValid: false,
        unlockTime: null,
      });

      await expect(
        service.add({
          vaultId: testVaultId,
          title: "Test",
          username: "user",
          encryptedPassword: "pass",
        }),
      ).rejects.toThrow("Vault is locked. Unlock the vault first.");
    });

    it("agrega nueva credencial a filtered si coincide con filtro actual", async () => {
      mockStorage.set({
        credentials: [
          createPlainCredential({ title: "Alpha" }),
          createPlainCredential({ title: "Beta" }),
        ],
      });
      await service.loadAll();
      service["filteredCredentials"] = [service["credentials"][0]];

      await service.add({
        vaultId: testVaultId,
        title: "Gamma",
        username: "user",
        encryptedPassword: "pass",
      });

      expect(service.getFiltered()).toHaveLength(1);
      expect(service.getAll()).toHaveLength(3);
    });

    it("emite credentials:changed después de add", async () => {
      const changedCallback = jest.fn();
      service.on("credentials:changed", changedCallback);

      await service.add({
        vaultId: testVaultId,
        title: "Test",
        username: "user",
        encryptedPassword: "pass",
      });

      expect(changedCallback).toHaveBeenCalledTimes(1);
    });

    it("usa factory method Credential.create", async () => {
      await service.add({
        vaultId: testVaultId,
        title: "Test",
        username: "user",
        encryptedPassword: "pass",
        url: "https://example.com",
        notes: "Some notes",
        tags: ["tag1", "tag2"],
        favorite: false,
      });

      const saved = await storageService.loadCredentials();
      const cred = saved[0];

      expect(cred.url).toBe("https://example.com");
      expect(cred.notes).toBe("Some notes");
      expect(cred.tags).toEqual(["tag1", "tag2"]);
      expect(cred.favorite).toBe(false);
    });
  });

  describe("update", () => {
    beforeEach(async () => {
      mockStorage.set({
        credentials: [
          createPlainCredential({ title: "Cred 1", favorite: false }),
          createPlainCredential({ title: "Cred 2", favorite: true }),
        ],
      });
      await service.loadAll();
    });

    it("modifica matching ID, actualiza updatedAt, guarda, emite", async () => {
      const credentials = service.getAll();
      const credToUpdate = credentials[0];
      const originalUpdatedAt = credToUpdate.updatedAt.getTime();

      await new Promise((resolve) => setTimeout(resolve, 10));

      const result = await service.update(credToUpdate.id.toString(), {
        title: "Updated Title",
        username: "updateduser",
      });

      expect(result).toBe(true);

      const updated = service
        .getAll()
        .find((c) => c.id.equals(credToUpdate.id));
      expect(updated?.title).toBe("Updated Title");
      expect(updated?.username).toBe("updateduser");
      expect(updated?.updatedAt.getTime()).toBeGreaterThan(originalUpdatedAt);
    });

    it("update con ID no existente → retorna false", async () => {
      const nonExistentId = "00000000-0000-4000-8000-000000000000";
      const result = await service.update(nonExistentId, { title: "Test" });
      expect(result).toBe(false);
    });

    it("actualiza favorite correctamente", async () => {
      const credentials = service.getAll();
      const cred = credentials[0];
      expect(cred.favorite).toBe(false);

      await service.update(cred.id.toString(), { favorite: true });

      const updated = service.getAll().find((c) => c.id.equals(cred.id));
      expect(updated?.favorite).toBe(true);
    });

    it("actualiza encryptedPassword correctamente", async () => {
      const credentials = service.getAll();
      const cred = credentials[0];

      await service.update(cred.id.toString(), {
        encryptedPassword: "newencryptedpass",
      });

      const updated = service.getAll().find((c) => c.id.equals(cred.id));
      expect(updated?.encryptedPassword).toBe("newencryptedpass");
      expect(updated?.title).toBe(cred.title);
      expect(updated?.username).toBe(cred.username);
    });

    it("update con vault locked → lanza error", async () => {
      mockGetStatus.mockReturnValue({
        initialized: true,
        unlocked: false,
        sessionValid: false,
        unlockTime: null,
      });

      const credentials = service.getAll();
      const cred = credentials[0];

      await expect(
        service.update(cred.id.toString(), { title: "New Title" }),
      ).rejects.toThrow("Vault is locked. Unlock the vault first.");
    });

    it("emite credentials:changed después de update", async () => {
      const callback = jest.fn();
      service.on("credentials:changed", callback);

      const credentials = service.getAll();
      const cred = credentials[0];

      await service.update(cred.id.toString(), { title: "New Title" });

      expect(callback).toHaveBeenCalledTimes(1);
    });
  });

  describe("delete", () => {
    // Note: each test sets up its own data as needed

    it("elimina credencial, guarda, emite", async () => {
      mockStorage.set({
        credentials: [
          createPlainCredential({ title: "Cred 1" }),
          createPlainCredential({ title: "Cred 2" }),
          createPlainCredential({ title: "Cred 3" }),
        ],
      });
      await service.loadAll();

      const credentials = service.getAll();
      const credToDelete = credentials[0];

      const result = await service.delete(credToDelete.id.toString());

      expect(result).toBe(true);
      expect(service.getAll()).toHaveLength(2);

      const saved = await storageService.loadCredentials();
      expect(saved).toHaveLength(2);
      expect(saved.find((c) => c.id.equals(credToDelete.id))).toBeUndefined();
    });

    it("delete ID no existente → retorna false", async () => {
      mockStorage.set({
        credentials: [createPlainCredential({ title: "Cred 1" })],
      });
      await service.loadAll();

      const nonExistentId = "00000000-0000-4000-8000-000000000000";
      const result = await service.delete(nonExistentId);
      expect(result).toBe(false);
    });

    it("elimina solo la credencial con ID específico", async () => {
      // Setup with exactly 2 credentials
      mockStorage.set({
        credentials: [
          createPlainCredential({ title: "Cred 1" }),
          createPlainCredential({ title: "Cred 2" }),
        ],
      });
      await service.loadAll();

      const credentials = service.getAll();
      const cred1 = credentials[0];
      const cred2 = credentials[1];

      await service.delete(cred1.id.toString());

      const remaining = service.getAll();
      expect(remaining).toHaveLength(1);
      expect(remaining[0].id.equals(cred2.id)).toBe(true);
    });

    it("delete con vault locked → lanza error", async () => {
      mockStorage.set({
        credentials: [createPlainCredential({ title: "Cred 1" })],
      });
      await service.loadAll();

      mockGetStatus.mockReturnValue({
        initialized: true,
        unlocked: false,
        sessionValid: false,
        unlockTime: null,
      });

      const credentials = service.getAll();
      const cred = credentials[0];

      await expect(service.delete(cred.id.toString())).rejects.toThrow(
        "Vault is locked. Unlock the vault first.",
      );
    });

    it("emite credentials:changed después de delete", async () => {
      mockStorage.set({
        credentials: [createPlainCredential({ title: "Cred 1" })],
      });
      await service.loadAll();

      const changedCallback = jest.fn();
      service.on("credentials:changed", changedCallback);

      const credentials = service.getAll();
      const cred = credentials[0];

      await service.delete(cred.id.toString());

      expect(changedCallback).toHaveBeenCalledTimes(1);
    });
  });

  describe("search", () => {
    beforeEach(async () => {
      mockStorage.set({
        credentials: [
          createPlainCredential({
            title: "Gmail Account",
            username: "user@gmail.com",
            url: "https://mail.google.com",
          }),
          createPlainCredential({
            title: "GitHub",
            username: "githubuser",
            url: "https://github.com",
          }),
          createPlainCredential({
            title: "Work Email",
            username: "worker@company.com",
            tags: ["work", "important"],
          }),
          createPlainCredential({
            title: "Netflix",
            username: "streamer",
            tags: ["entertainment"],
          }),
        ],
      });
      await service.loadAll();
    });

    it('search("gmail") filtra por título/usuario/url', () => {
      service.search("gmail");
      expect(service.getFiltered()).toHaveLength(1);
      expect(service.getFiltered()[0].title).toBe("Gmail Account");
    });

    it("search es case-insensitive", () => {
      service.search("GMAIL");
      expect(service.getFiltered()).toHaveLength(1);
      expect(service.getFiltered()[0].title).toBe("Gmail Account");

      service.clearSearch();
      service.search("github");
      expect(service.getFiltered()).toHaveLength(1);
    });

    it("busca en URL", () => {
      service.search("github.com");
      expect(service.getFiltered()).toHaveLength(1);
      expect(service.getFiltered()[0].title).toBe("GitHub");
    });

    it("busca en tags", () => {
      service.search("work");
      expect(service.getFiltered()).toHaveLength(1);
      expect(service.getFiltered()[0].title).toBe("Work Email");
    });

    it("busca en username", () => {
      service.search("streamer");
      expect(service.getFiltered()).toHaveLength(1);
      expect(service.getFiltered()[0].title).toBe("Netflix");
    });

    it("búsqueda parcial", () => {
      service.search("mail");
      expect(service.getFiltered()).toHaveLength(2);
    });

    it("search vacío → resetea a todas", () => {
      service.search("gmail");
      expect(service.getFiltered()).toHaveLength(1);
      service.search("");
      expect(service.getFiltered()).toHaveLength(4);
    });

    it("search con solo espacios → resetea a todas", () => {
      service.search("   ");
      expect(service.getFiltered()).toHaveLength(4);
    });

    it("no encuentra nada → filtered vacío", () => {
      service.search("nonexistent123456");
      expect(service.getFiltered()).toHaveLength(0);
    });

    it("aplica ordenamiento a resultados filtrados", async () => {
      const plainCredentials = [
        createPlainCredential({ title: "Z", favorite: false }),
        createPlainCredential({ title: "A", favorite: true }),
        createPlainCredential({ title: "M", favorite: true }),
        createPlainCredential({ title: "B", favorite: false }),
      ];
      mockStorage.set({ credentials: plainCredentials });
      await service.loadAll();

      service.search("a");
      const filtered = service.getFiltered();
      expect(filtered.map((c) => c.title)).toEqual(["A", "M"]);
    });

    it("emite credentials:search:updated y credentials:changed", () => {
      const searchUpdatedCallback = jest.fn();
      const changedCallback = jest.fn();

      service.on("credentials:search:updated", searchUpdatedCallback);
      service.on("credentials:changed", changedCallback);

      service.search("test");

      expect(searchUpdatedCallback).toHaveBeenCalledTimes(1);
      expect(changedCallback).toHaveBeenCalledTimes(1);
    });
  });

  describe("clearSearch", () => {
    beforeEach(async () => {
      mockStorage.set({
        credentials: [
          createPlainCredential({ title: "A", favorite: false }),
          createPlainCredential({ title: "B", favorite: true }),
          createPlainCredential({ title: "C", favorite: false }),
        ],
      });
      await service.loadAll();
    });

    it("restaura filteredCredentials a todas las credenciales", () => {
      service.search("z");
      expect(service.getFiltered().length).toBeLessThan(3);
      service.clearSearch();
      expect(service.getFiltered()).toHaveLength(3);
    });

    it("mantiene el ordenamiento después de clearSearch", () => {
      service.search("anything");
      service.clearSearch();
      const filtered = service.getFiltered();
      expect(filtered.map((c) => c.title)).toEqual(["B", "A", "C"]);
    });

    it("emite credentials:search:updated y credentials:changed", () => {
      const searchUpdatedCallback = jest.fn();
      const changedCallback = jest.fn();

      service.on("credentials:search:updated", searchUpdatedCallback);
      service.on("credentials:changed", changedCallback);

      service.clearSearch();

      expect(searchUpdatedCallback).toHaveBeenCalledTimes(1);
      expect(changedCallback).toHaveBeenCalledTimes(1);
    });
  });

  describe("toggleFavorite", () => {
    beforeEach(async () => {
      mockStorage.set({
        credentials: [
          createPlainCredential({ title: "Cred 1", favorite: false }),
          createPlainCredential({ title: "Cred 2", favorite: true }),
        ],
      });
      await service.loadAll();
    });

    it("alterna favorite, guarda, emite", async () => {
      const credentials = service.getAll();
      const cred = credentials[0];
      expect(cred.favorite).toBe(false);

      await service.toggleFavorite(cred.id.toString());

      const updated = service.getAll().find((c) => c.id.equals(cred.id));
      expect(updated?.favorite).toBe(true);

      const saved = await storageService.loadCredentials();
      const savedCred = saved.find((c) => c.id.equals(cred.id));
      expect(savedCred?.favorite).toBe(true);
    });

    it("puede desactivar favorite si ya estaba activo", async () => {
      const credentials = service.getAll();
      const cred = credentials[1];
      expect(cred.favorite).toBe(true);

      await service.toggleFavorite(cred.id.toString());

      const updated = service.getAll().find((c) => c.id.equals(cred.id));
      expect(updated?.favorite).toBe(false);
    });

    it("actualiza updatedAt al togglear", async () => {
      const credentials = service.getAll();
      const cred = credentials[0];
      const originalUpdatedAt = cred.updatedAt.getTime();

      await new Promise((resolve) => setTimeout(resolve, 10));

      await service.toggleFavorite(cred.id.toString());

      const updated = service.getAll().find((c) => c.id.equals(cred.id));
      expect(updated?.updatedAt.getTime()).toBeGreaterThan(originalUpdatedAt);
    });

    it("toggleFavorite con ID no existente → lanza error", async () => {
      const nonExistentId = "00000000-0000-4000-8000-000000000000";
      await expect(service.toggleFavorite(nonExistentId)).rejects.toThrow(
        `Credential with id ${nonExistentId} not found`,
      );
    });

    it("toggleFavorite con vault locked → lanza error", async () => {
      mockGetStatus.mockReturnValue({
        initialized: true,
        unlocked: false,
        sessionValid: false,
        unlockTime: null,
      });

      const credentials = service.getAll();
      const cred = credentials[0];

      await expect(service.toggleFavorite(cred.id.toString())).rejects.toThrow(
        "Vault is locked. Unlock the vault first.",
      );
    });

    it("emite credentials:changed después de toggleFavorite", async () => {
      const changedCallback = jest.fn();
      service.on("credentials:changed", changedCallback);

      const credentials = service.getAll();
      const cred = credentials[0];

      await service.toggleFavorite(cred.id.toString());

      expect(changedCallback).toHaveBeenCalledTimes(1);
    });
  });

  describe("incrementUsage", () => {
    beforeEach(async () => {
      mockStorage.set({
        credentials: [
          createPlainCredential({
            title: "Cred 1",
            lastUsed: new Date("2024-01-01T00:00:00.000Z").toISOString(),
          }),
          createPlainCredential({
            title: "Cred 2",
            lastUsed: undefined,
          }),
        ],
      });
      await service.loadAll();
    });

    it("actualiza lastUsed a now", async () => {
      const credentials = service.getAll();
      const cred = credentials[0];
      const oldLastUsed = cred.lastUsed?.getTime();

      await new Promise((resolve) => setTimeout(resolve, 10));
      const beforeCall = Date.now();

      await service.incrementUsage(cred.id.toString());

      const updated = service.getAll().find((c) => c.id.equals(cred.id));
      expect(updated?.lastUsed).toBeDefined();
      expect(updated!.lastUsed!.getTime()).toBeGreaterThan(oldLastUsed || 0);
      // Allow equality due to timing precision
      expect(updated!.lastUsed!.getTime()).toBeGreaterThanOrEqual(beforeCall);
    });

    it("establece lastUsed en credencial que no tenía", async () => {
      const credentials = service.getAll();
      const cred = credentials[1];
      expect(cred.lastUsed).toBeUndefined();

      await service.incrementUsage(cred.id.toString());

      const updated = service.getAll().find((c) => c.id.equals(cred.id));
      expect(updated?.lastUsed).toBeDefined();
    });

    it("persiste lastUsed en storage", async () => {
      const credentials = service.getAll();
      const cred = credentials[0];

      await service.incrementUsage(cred.id.toString());

      const saved = await storageService.loadCredentials();
      const savedCred = saved.find((c) => c.id.equals(cred.id));
      expect(savedCred?.lastUsed).toBeDefined();
    });

    it("incrementUsage con ID no existente → lanza error", async () => {
      const nonExistentId = "00000000-0000-4000-8000-000000000000";
      await expect(service.incrementUsage(nonExistentId)).rejects.toThrow(
        `Credential with id ${nonExistentId} not found`,
      );
    });

    it("incrementUsage con vault locked → lanza error", async () => {
      mockGetStatus.mockReturnValue({
        initialized: true,
        unlocked: false,
        sessionValid: false,
        unlockTime: null,
      });

      const credentials = service.getAll();
      const cred = credentials[0];

      await expect(service.incrementUsage(cred.id.toString())).rejects.toThrow(
        "Vault is locked. Unlock the vault first.",
      );
    });

    it("emite credentials:changed después de incrementUsage", async () => {
      const changedCallback = jest.fn();
      service.on("credentials:changed", changedCallback);

      const credentials = service.getAll();
      const cred = credentials[0];

      await service.incrementUsage(cred.id.toString());

      expect(changedCallback).toHaveBeenCalledTimes(1);
    });

    it("no modifica other fields", async () => {
      const credentials = service.getAll();
      const cred = credentials[0];
      const originalTitle = cred.title;
      const originalUsername = cred.username;

      await service.incrementUsage(cred.id.toString());

      const updated = service.getAll().find((c) => c.id.equals(cred.id));
      expect(updated?.title).toBe(originalTitle);
      expect(updated?.username).toBe(originalUsername);
    });
  });

  describe("Eventos", () => {
    beforeEach(async () => {
      mockStorage.set({
        credentials: [createPlainCredential({ title: "Cred 1" })],
      });
      await service.loadAll();
    });

    it("listener credentials:changed se llama en add", async () => {
      const callback = jest.fn();
      service.on("credentials:changed", callback);

      await service.add({
        vaultId: testVaultId,
        title: "New",
        username: "user",
        encryptedPassword: "pass",
      });

      expect(callback).toHaveBeenCalledTimes(1);
    });

    it("listener credentials:changed se llama en update", async () => {
      const callback = jest.fn();
      service.on("credentials:changed", callback);

      const credentials = service.getAll();
      const cred = credentials[0];

      await service.update(cred.id.toString(), { title: "Updated" });

      expect(callback).toHaveBeenCalledTimes(1);
    });

    it("listener credentials:changed se llama en delete", async () => {
      const callback = jest.fn();
      service.on("credentials:changed", callback);

      const credentials = service.getAll();
      const cred = credentials[0];

      await service.delete(cred.id.toString());

      expect(callback).toHaveBeenCalledTimes(1);
    });

    it("listener credentials:search:updated se llama en search", () => {
      const callback = jest.fn();
      service.on("credentials:search:updated", callback);

      service.search("test");

      expect(callback).toHaveBeenCalledTimes(1);
    });

    it("listener credentials:search:updated se llama en clearSearch", () => {
      const callback = jest.fn();
      service.on("credentials:search:updated", callback);

      service.search("test");
      service.clearSearch();

      expect(callback).toHaveBeenCalledTimes(2);
    });

    it("múltiples listeners registrados para mismo evento", async () => {
      const callback1 = jest.fn();
      const callback2 = jest.fn();

      service.on("credentials:changed", callback1);
      service.on("credentials:changed", callback2);

      await service.add({
        vaultId: testVaultId,
        title: "Test",
        username: "user",
        encryptedPassword: "pass",
      });

      expect(callback1).toHaveBeenCalledTimes(1);
      expect(callback2).toHaveBeenCalledTimes(1);
    });

    it("listener puede desuscribirse", async () => {
      const callback = jest.fn();
      service.on("credentials:changed", callback);
      service.off("credentials:changed", callback);

      await service.add({
        vaultId: testVaultId,
        title: "Test",
        username: "user",
        encryptedPassword: "pass",
      });

      expect(callback).not.toHaveBeenCalled();
    });

    it("off remueve solo el callback específico", async () => {
      const callback1 = jest.fn();
      const callback2 = jest.fn();

      service.on("credentials:changed", callback1);
      service.on("credentials:changed", callback2);
      service.off("credentials:changed", callback1);

      await service.add({
        vaultId: testVaultId,
        title: "Test",
        username: "user",
        encryptedPassword: "pass",
      });

      expect(callback1).not.toHaveBeenCalled();
      expect(callback2).toHaveBeenCalledTimes(1);
    });
  });

  describe("Ordenamiento", () => {
    it("getAll ordena: favorites first, luego alfabético por title", async () => {
      const plainCredentials = [
        createPlainCredential({ title: "Zebra", favorite: false }),
        createPlainCredential({ title: "Apple", favorite: true }),
        createPlainCredential({ title: "Mango", favorite: false }),
        createPlainCredential({ title: "Banana", favorite: true }),
        createPlainCredential({ title: "Alpha", favorite: true }),
      ];
      mockStorage.set({ credentials: plainCredentials });

      await service.loadAll();
      const all = service.getAll();

      expect(all.map((c) => c.title)).toEqual([
        "Alpha",
        "Apple",
        "Banana",
        "Mango",
        "Zebra",
      ]);
    });

    it("toggleFavorite reordena filtered", async () => {
      const plainCredentials = [
        createPlainCredential({ title: "A", favorite: false }),
        createPlainCredential({ title: "B", favorite: false }),
      ];
      mockStorage.set({ credentials: plainCredentials });
      await service.loadAll();

      let all = service.getAll();
      expect(all.map((c) => c.title)).toEqual(["A", "B"]);

      await service.toggleFavorite(all[1].id.toString());

      all = service.getAll();
      expect(all.map((c) => c.title)).toEqual(["B", "A"]);
    });
  });

  describe("Edge cases y integridad", () => {
    it("mantiene consistencia entre credentials y filtered después de add", async () => {
      mockStorage.set({
        credentials: [createPlainCredential({ title: "A" })],
      });
      await service.loadAll();

      service["filteredCredentials"] = [];

      await service.add({
        vaultId: testVaultId,
        title: "New",
        username: "user",
        encryptedPassword: "pass",
      });

      expect(service.getFiltered()).toHaveLength(0);
      expect(service.getAll()).toHaveLength(2);
    });

    it("update mantiene consistencia entre credentials y filtered", async () => {
      mockStorage.set({
        credentials: [
          createPlainCredential({ title: "A", favorite: false }),
          createPlainCredential({ title: "B", favorite: false }),
        ],
      });
      await service.loadAll();

      service["filteredCredentials"] = [service["credentials"][0]];

      const cred = service.getAll()[0];
      await service.update(cred.id.toString(), { favorite: true });

      const filtered = service.getFiltered();
      expect(filtered).toHaveLength(1);
      expect(filtered[0].favorite).toBe(true);
    });

    it("delete mantiene consistencia entre credentials y filtered", async () => {
      mockStorage.set({
        credentials: [
          createPlainCredential({ title: "A" }),
          createPlainCredential({ title: "B" }),
        ],
      });
      await service.loadAll();

      service["filteredCredentials"] = [service["credentials"][1]];

      const cred = service.getAll()[0];
      await service.delete(cred.id.toString());

      expect(service.getAll()).toHaveLength(1);
      expect(service.getFiltered()).toHaveLength(1);
      expect(service.getFiltered()[0].title).toBe("B");
    });

    it("maneja credenciales con campos opcionales null/undefined", async () => {
      // Use createPlainCredential which generates valid id
      mockStorage.set({
        credentials: [createPlainCredential()],
      });

      const result = await service.loadAll();
      expect(result[0].url).toBeUndefined();
      expect(result[0].notes).toBeUndefined();
    });

    it("maneja tags vacíos correctamente", async () => {
      await service.add({
        vaultId: testVaultId,
        title: "No Tags",
        username: "user",
        encryptedPassword: "pass",
        tags: [],
      });

      const saved = await storageService.loadCredentials();
      expect(saved[0].tags).toEqual([]);
    });

    it("applySorting no modifica fechas", async () => {
      const now1 = new Date("2024-01-01T00:00:00.000Z");
      const now2 = new Date("2024-01-02T00:00:00.000Z");
      const plainCredentials = [
        createPlainCredential({
          title: "Z",
          favorite: false,
          createdAt: now1.toISOString(),
          updatedAt: now1.toISOString(),
        }),
        createPlainCredential({
          title: "A",
          favorite: true,
          createdAt: now2.toISOString(),
          updatedAt: now2.toISOString(),
        }),
      ];
      mockStorage.set({ credentials: plainCredentials });

      await service.loadAll();
      const all = service.getAll();

      expect(all[0].createdAt.getTime()).toBe(now2.getTime());
      expect(all[1].createdAt.getTime()).toBe(now1.getTime());
    });
  });

  describe("Integración: Flujos completos", () => {
    it("loadAll → search → clearSearch flujo completo", async () => {
      mockStorage.set({
        credentials: [
          createPlainCredential({ title: "Gmail", username: "user1" }),
          createPlainCredential({ title: "GitHub", username: "user2" }),
          createPlainCredential({ title: "Google", username: "user3" }),
        ],
      });

      await service.loadAll();
      expect(service.getAll()).toHaveLength(3);

      service.search("gmail");
      expect(service.getFiltered()).toHaveLength(1);

      service.clearSearch();
      expect(service.getFiltered()).toHaveLength(3);
    });

    it("add → update → delete ciclo completo", async () => {
      mockStorage.set({ credentials: [] });

      const added = await service.add({
        vaultId: testVaultId,
        title: "Test",
        username: "user",
        encryptedPassword: "pass",
        favorite: false,
      });
      expect(service.getAll()).toHaveLength(1);

      await service.update(added.id.toString(), {
        title: "Updated Test",
        favorite: true,
      });
      let all = service.getAll();
      expect(all).toHaveLength(1);
      expect(all[0].title).toBe("Updated Test");
      expect(all[0].favorite).toBe(true);

      await service.delete(added.id.toString());
      expect(service.getAll()).toHaveLength(0);
    });

    it("incrementUsage no interfiere con filtered", async () => {
      mockStorage.set({
        credentials: [
          createPlainCredential({ title: "A" }),
          createPlainCredential({ title: "B" }),
        ],
      });
      await service.loadAll();

      service["filteredCredentials"] = [service["credentials"][0]];

      await service.incrementUsage(service.getAll()[1].id.toString());

      expect(service.getFiltered()).toHaveLength(1);
      expect(service.getAll()).toHaveLength(2);
    });
  });

  describe("ensureVaultUnlocked", () => {
    it("lanza error cuando vaultStatus.unlocked es false", async () => {
      mockGetStatus.mockReturnValue({
        initialized: true,
        unlocked: false,
        sessionValid: false,
        unlockTime: null,
      });

      await expect(service.loadAll()).rejects.toThrow(
        "Vault is locked. Unlock the vault first.",
      );
    });

    it("no lanza error cuando vaultStatus.unlocked es true", async () => {
      mockGetStatus.mockReturnValue({
        initialized: true,
        unlocked: true,
        sessionValid: true,
        unlockTime: Date.now(),
      });

      mockStorage.set({ credentials: [] });
      await expect(service.loadAll()).resolves.toEqual([]);
    });
  });

  describe("matchesCurrentFilter", () => {
    it("retorna true si no hay filtro activo (filtered === credentials)", () => {
      service["credentials"] = [
        createTestCredential({ title: "A" }),
        createTestCredential({ title: "B" }),
      ];
      service["filteredCredentials"] = [...service["credentials"]];

      expect(service["matchesCurrentFilter"](service["credentials"][0])).toBe(
        true,
      );
      expect(service["matchesCurrentFilter"](service["credentials"][1])).toBe(
        true,
      );
    });

    it("retorna true si la credencial está en filtered", () => {
      service["credentials"] = [
        createTestCredential({ title: "A" }),
        createTestCredential({ title: "B" }),
      ];
      service["filteredCredentials"] = [service["credentials"][0]];

      expect(service["matchesCurrentFilter"](service["credentials"][0])).toBe(
        true,
      );
      expect(service["matchesCurrentFilter"](service["credentials"][1])).toBe(
        false,
      );
    });
  });
});
