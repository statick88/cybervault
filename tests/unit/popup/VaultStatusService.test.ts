// @ts-nocheck

/**
 * VaultStatusService Unit Tests
 * Tests for vault state management, event notifications, and session handling
 */

import {
  describe,
  it,
  expect,
  beforeEach,
  afterEach,
  jest,
} from "@jest/globals";

// Mock chrome.storage.local before importing module
let storageData: Record<string, any> = {};

const storageMock = {
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
  remove: jest.fn(async (keys: string[]) => {
    for (const key of Array.isArray(keys) ? keys : [keys]) {
      delete storageData[key];
    }
  }),
};

global.chrome = {
  storage: {
    local: storageMock,
  },
} as any;

// Mock master-key-manager module
const mockIsVaultInitialized = jest.fn();
const mockIsVaultUnlocked = jest.fn();
const mockUnlockVault = jest.fn();
const mockLockVault = jest.fn();
const mockIsSessionValid = jest.fn();
const mockRefreshSession = jest.fn();

jest.mock("@/infrastructure/crypto/master-key-manager", () => ({
  isVaultInitialized: mockIsVaultInitialized,
  isVaultUnlocked: mockIsVaultUnlocked,
  unlockVault: mockUnlockVault,
  lockVault: mockLockVault,
  isSessionValid: mockIsSessionValid,
  refreshSession: mockRefreshSession,
}));

// Import after mocks are set up
import {
  VaultStatusService,
  VaultStatusEvent,
} from "../../src/ui/popup/services/VaultStatusService";

describe("VaultStatusService", () => {
  let service: VaultStatusService;

  beforeEach(() => {
    jest.clearAllMocks();
    storageData = {};

    // Setup default mock implementations
    mockIsVaultInitialized.mockResolvedValue(false);
    mockIsVaultUnlocked.mockReturnValue(false);
    mockIsSessionValid.mockReturnValue(false);
    mockUnlockVault.mockResolvedValue({ success: true });
    mockRefreshSession.mockImplementation(() => {});

    service = new VaultStatusService();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("Estado inicial", () => {
    it("estado inicial: initialized=false, unlocked=false", () => {
      const status = service.getStatus();
      expect(status.initialized).toBe(false);
      expect(status.unlocked).toBe(false);
      expect(status.sessionValid).toBe(false);
      expect(status.unlockTime).toBeNull();
    });

    it("isSessionValid() devuelve false sin unlockTime", () => {
      expect(service.isSessionValid()).toBe(false);
    });
  });

  describe("initialize()", () => {
    it("lee storage y setea initialized/unlocked correctamente", async () => {
      // Mock vault as initialized and unlocked
      mockIsVaultInitialized.mockResolvedValue(true);
      mockIsVaultUnlocked.mockReturnValue(true);

      // Mock current time for unlockTime
      const now = Date.now();
      jest.spyOn(global, "Date").mockImplementation(
        () =>
          ({
            now: () => now,
          }) as any,
      );

      await service.initialize();

      expect(mockIsVaultInitialized).toHaveBeenCalled();
      expect(mockIsVaultUnlocked).toHaveBeenCalled();

      const status = service.getStatus();
      expect(status.initialized).toBe(true);
      expect(status.unlocked).toBe(true);
      expect(status.sessionValid).toBe(true);
      expect(status.unlockTime).toBe(now);

      // Restore Date mock
      (global.Date as any).mockRestore?.();
    });

    it("initialize() con vault no inicializado mantiene unlocked=false", async () => {
      mockIsVaultInitialized.mockResolvedValue(false);

      await service.initialize();

      const status = service.getStatus();
      expect(status.initialized).toBe(false);
      expect(status.unlocked).toBe(false);
      expect(status.sessionValid).toBe(false);
      expect(status.unlockTime).toBeNull();
    });

    it("initialize() emite evento 'initialized'", async () => {
      mockIsVaultInitialized.mockResolvedValue(true);
      mockIsVaultUnlocked.mockReturnValue(false);

      const callback = jest.fn();
      service.onStatusChange("initialized", callback);

      await service.initialize();

      expect(callback).toHaveBeenCalled();
    });
  });

  describe("checkStatus()", () => {
    it("actualiza estado basado en storage", async () => {
      mockIsVaultInitialized.mockResolvedValue(true);
      mockIsVaultUnlocked.mockReturnValue(false);

      await service.checkStatus();

      expect(mockIsVaultInitialized).toHaveBeenCalled();
      expect(mockIsVaultUnlocked).toHaveBeenCalled();

      const status = service.getStatus();
      expect(status.initialized).toBe(true);
      expect(status.unlocked).toBe(false);
    });

    it("checkStatus() emite evento 'status_change'", async () => {
      mockIsVaultInitialized.mockResolvedValue(true);
      mockIsVaultUnlocked.mockReturnValue(false);

      const callback = jest.fn();
      service.onStatusChange("status_change", callback);

      await service.checkStatus();

      expect(callback).toHaveBeenCalled();
    });

    it("checkStatus() calcula sessionValid correctamente", async () => {
      mockIsVaultInitialized.mockResolvedValue(true);
      mockIsVaultUnlocked.mockReturnValue(true);

      const now = Date.now();
      jest.spyOn(global, "Date").mockImplementation(
        () =>
          ({
            now: () => now,
          }) as any,
      );

      await service.checkStatus();

      const status = service.getStatus();
      expect(status.sessionValid).toBe(true);
      expect(status.unlockTime).toBe(now);

      (global.Date as any).mockRestore?.();
    });
  });

  describe("unlockVault()", () => {
    it("con password correcto → success, unlocked=true, unlockTime seteado", async () => {
      mockIsVaultInitialized.mockResolvedValue(true);
      mockIsVaultUnlocked.mockReturnValue(false);
      mockIsSessionValid.mockReturnValue(false);

      const now = Date.now();
      jest.spyOn(global, "Date").mockImplementation(
        () =>
          ({
            now: () => now,
          }) as any,
      );

      const result = await service.unlockVault("correct-password");

      expect(result.success).toBe(true);
      expect(mockUnlockVault).toHaveBeenCalledWith("correct-password");

      const status = service.getStatus();
      expect(status.unlocked).toBe(true);
      expect(status.unlockTime).toBe(now);
      expect(status.sessionValid).toBe(true);

      (global.Date as any).mockRestore?.();
    });

    it("con password incorrecto → success=false, error message", async () => {
      mockUnlockVault.mockResolvedValue({
        success: false,
        error: "Clave maestra incorrecta",
      });

      const result = await service.unlockVault("wrong-password");

      expect(result.success).toBe(false);
      expect(result.error).toBe("Clave maestra incorrecta");

      const status = service.getStatus();
      expect(status.unlocked).toBe(false);
      expect(status.unlockTime).toBeNull();
    });

    it("emite eventos 'unlocked' y 'status_change' cuando exitoso", async () => {
      mockIsVaultInitialized.mockResolvedValue(true);
      mockIsVaultUnlocked.mockReturnValue(false);
      mockIsSessionValid.mockReturnValue(false);

      const unlockedCallback = jest.fn();
      const statusChangeCallback = jest.fn();

      service.onStatusChange("unlocked", unlockedCallback);
      service.onStatusChange("status_change", statusChangeCallback);

      await service.unlockVault("correct-password");

      expect(unlockedCallback).toHaveBeenCalled();
      expect(statusChangeCallback).toHaveBeenCalled();
    });
  });

  describe("lockVault()", () => {
    it("locked=false, unlockTime=null", () => {
      // Set initial state as unlocked
      service["status"] = {
        initialized: true,
        unlocked: true,
        sessionValid: true,
        unlockTime: Date.now(),
      };

      service.lockVault();

      expect(mockLockVault).toHaveBeenCalled();

      const status = service.getStatus();
      expect(status.unlocked).toBe(false);
      expect(status.sessionValid).toBe(false);
      expect(status.unlockTime).toBeNull();
    });

    it("emite evento 'locked'", () => {
      service["status"] = {
        initialized: true,
        unlocked: true,
        sessionValid: true,
        unlockTime: Date.now(),
      };

      const callback = jest.fn();
      service.onStatusChange("locked", callback);

      service.lockVault();

      expect(callback).toHaveBeenCalled();
    });
  });

  describe("refreshSession()", () => {
    it("actualiza unlockTime a now", () => {
      // Set initial state as unlocked with old unlockTime
      const oldTime = Date.now() - 5 * 60 * 1000; // 5 minutes ago
      service["status"] = {
        initialized: true,
        unlocked: true,
        sessionValid: true,
        unlockTime: oldTime,
      };

      const now = Date.now();
      jest.spyOn(global, "Date").mockImplementation(
        () =>
          ({
            now: () => now,
          }) as any,
      );

      service.refreshSession();

      expect(mockRefreshSession).toHaveBeenCalled();

      const status = service.getStatus();
      expect(status.unlockTime).toBe(now);
      expect(status.sessionValid).toBe(true);

      (global.Date as any).mockRestore?.();
    });

    it("emite evento 'status_change'", () => {
      service["status"] = {
        initialized: true,
        unlocked: true,
        sessionValid: true,
        unlockTime: Date.now(),
      };

      const callback = jest.fn();
      service.onStatusChange("status_change", callback);

      service.refreshSession();

      expect(callback).toHaveBeenCalled();
    });
  });

  describe("isSessionValid()", () => {
    it("devuelve true si unlockTime reciente (<15min)", () => {
      const now = Date.now();
      const recentTime = now - 5 * 60 * 1000; // 5 minutes ago

      mockIsVaultUnlocked.mockReturnValue(true);
      // The service's isSessionValid calls master-key-manager's isSessionValid
      // But we test the service's method which delegates
      mockIsSessionValid.mockReturnValue(true);

      expect(service.isSessionValid()).toBe(true);
    });

    it("devuelve false si unlockTime antiguo (>15min)", () => {
      const oldTime = Date.now() - 20 * 60 * 1000; // 20 minutes ago

      mockIsVaultUnlocked.mockReturnValue(true);
      mockIsSessionValid.mockReturnValue(false);

      expect(service.isSessionValid()).toBe(false);
    });

    it("devuelve false si no hay unlockTime", () => {
      service["status"] = {
        initialized: true,
        unlocked: false,
        sessionValid: false,
        unlockTime: null,
      };

      mockIsVaultUnlocked.mockReturnValue(false);

      expect(service.isSessionValid()).toBe(false);
    });
  });

  describe("Event listeners", () => {
    it("onStatusChange registra callback", () => {
      const callback = jest.fn();
      service.onStatusChange("status_change", callback);

      // Verify it's in the listeners map
      const listeners = service["listeners"].get("status_change");
      expect(listeners).toContain(callback);
    });

    it("offStatusChange desuscribe callback", () => {
      const callback = jest.fn();
      service.onStatusChange("status_change", callback);

      expect(service["listeners"].get("status_change")?.has(callback)).toBe(
        true,
      );

      service.offStatusChange("status_change", callback);

      expect(service["listeners"].get("status_change")?.has(callback)).toBe(
        false,
      );
    });

    it("múltiples listeners registrados para mismo evento", () => {
      const callback1 = jest.fn();
      const callback2 = jest.fn();
      const callback3 = jest.fn();

      service.onStatusChange("status_change", callback1);
      service.onStatusChange("status_change", callback2);
      service.onStatusChange("status_change", callback3);

      const listeners = service["listeners"].get("status_change");
      expect(listeners?.size).toBe(3);
      expect(listeners?.has(callback1)).toBe(true);
      expect(listeners?.has(callback2)).toBe(true);
      expect(listeners?.has(callback3)).toBe(true);
    });

    it("múltiples listeners registrados para diferentes eventos", () => {
      const unlockedCallback = jest.fn();
      const lockedCallback = jest.fn();
      const statusChangeCallback = jest.fn();

      service.onStatusChange("unlocked", unlockedCallback);
      service.onStatusChange("locked", lockedCallback);
      service.onStatusChange("status_change", statusChangeCallback);

      expect(service["listeners"].get("unlocked")?.has(unlockedCallback)).toBe(
        true,
      );
      expect(service["listeners"].get("locked")?.has(lockedCallback)).toBe(
        true,
      );
      expect(
        service["listeners"].get("status_change")?.has(statusChangeCallback),
      ).toBe(true);
    });

    it("callback individual puede removerse sin afectar otros", () => {
      const callback1 = jest.fn();
      const callback2 = jest.fn();

      service.onStatusChange("status_change", callback1);
      service.onStatusChange("status_change", callback2);

      service.offStatusChange("status_change", callback1);

      const listeners = service["listeners"].get("status_change");
      expect(listeners?.has(callback1)).toBe(false);
      expect(listeners?.has(callback2)).toBe(true);
    });

    it("offStatusChange con callback no registrado no causa error", () => {
      const callback = jest.fn();

      // Should not throw
      service.offStatusChange("status_change", callback);

      expect(service["listeners"].get("status_change")).toBeUndefined();
    });

    it("onStatusChange para evento 'unlocked' se llama cuando unlocked=true", () => {
      mockIsVaultInitialized.mockResolvedValue(true);
      mockIsVaultUnlocked.mockReturnValue(false);
      mockIsSessionValid.mockReturnValue(false);

      const callback = jest.fn();
      service.onStatusChange("unlocked", callback);

      service["status"] = {
        initialized: true,
        unlocked: false,
        sessionValid: false,
        unlockTime: null,
      };

      // Simulate state change to unlocked
      mockIsVaultUnlocked.mockReturnValue(true);
      const now = Date.now();
      jest.spyOn(global, "Date").mockImplementation(
        () =>
          ({
            now: () => now,
          }) as any,
      );

      service.updateStatus({
        unlocked: true,
        sessionValid: true,
        unlockTime: now,
      });

      expect(callback).toHaveBeenCalled();

      (global.Date as any).mockRestore?.();
    });

    it("onStatusChange para evento 'locked' se llama cuando unlocked=false", () => {
      service["status"] = {
        initialized: true,
        unlocked: true,
        sessionValid: true,
        unlockTime: Date.now(),
      };

      const callback = jest.fn();
      service.onStatusChange("locked", callback);

      service.updateStatus({
        unlocked: false,
        sessionValid: false,
        unlockTime: null,
      });

      expect(callback).toHaveBeenCalled();
    });

    it("onStatusChange para evento 'session_expired' se llama solo cuando expire", () => {
      service["status"] = {
        initialized: true,
        unlocked: true,
        sessionValid: true,
        unlockTime: Date.now(),
      };

      const callback = jest.fn();
      service.onStatusChange("session_expired", callback);

      // Change to invalid session (should trigger)
      service.updateStatus({
        sessionValid: false,
      });

      expect(callback).toHaveBeenCalled();
    });

    it("onStatusChange para evento 'session_expired' NO se llama si ya era invalid", () => {
      service["status"] = {
        initialized: true,
        unlocked: false,
        sessionValid: false,
        unlockTime: null,
      };

      const callback = jest.fn();
      service.onStatusChange("session_expired", callback);

      // Change to invalid session (but was already invalid)
      service.updateStatus({
        sessionValid: false,
      });

      expect(callback).not.toHaveBeenCalled();
    });
  });

  describe("getStatus()", () => {
    it("devuelve copia immutable del estado", () => {
      service["status"] = {
        initialized: true,
        unlocked: true,
        sessionValid: true,
        unlockTime: Date.now(),
      };

      const status = service.getStatus();

      // Modify returned object
      (status as any).initialized = false;

      // Original should be unchanged
      const original = service.getStatus();
      expect(original.initialized).toBe(true);
    });
  });

  describe("Integración: Flujo completo", () => {
    it("initialize + unlock + lock flujo completo", async () => {
      mockIsVaultInitialized.mockResolvedValue(true);
      mockIsVaultUnlocked.mockReturnValue(false);

      // Initialize
      await service.initialize();
      let status = service.getStatus();
      expect(status.initialized).toBe(true);
      expect(status.unlocked).toBe(false);

      // Unlock
      mockIsVaultUnlocked.mockReturnValue(true);
      mockIsSessionValid.mockReturnValue(true);
      mockUnlockVault.mockResolvedValue({ success: true });

      const now = Date.now();
      jest.spyOn(global, "Date").mockImplementation(
        () =>
          ({
            now: () => now,
          }) as any,
      );

      await service.unlockVault("password123");
      status = service.getStatus();
      expect(status.unlocked).toBe(true);
      expect(status.unlockTime).toBe(now);

      // Lock
      mockLockVault.mockImplementation(() => {});

      service.lockVault();
      status = service.getStatus();
      expect(status.unlocked).toBe(false);
      expect(status.unlockTime).toBeNull();

      (global.Date as any).mockRestore?.();
    });

    it("unlock + refreshSession actualiza timer", async () => {
      mockIsVaultInitialized.mockResolvedValue(true);
      mockIsVaultUnlocked.mockReturnValue(false);

      const initialTime = Date.now() - 10 * 60 * 1000;
      service["status"] = {
        initialized: true,
        unlocked: true,
        sessionValid: true,
        unlockTime: initialTime,
      };

      const refreshTime = Date.now();
      jest.spyOn(global, "Date").mockImplementation(
        () =>
          ({
            now: () => refreshTime,
          }) as any,
      );

      service.refreshSession();

      const status = service.getStatus();
      expect(status.unlockTime).toBe(refreshTime);
      expect(status.sessionValid).toBe(true);

      (global.Date as any).mockRestore?.();
    });

    it("updateStatus emite eventos correctos basados en cambios", () => {
      // Test initialized event
      const initCallback = jest.fn();
      service.onStatusChange("initialized", initCallback);

      service["status"] = {
        initialized: false,
        unlocked: false,
        sessionValid: false,
        unlockTime: null,
      };
      service.updateStatus({ initialized: true });

      expect(initCallback).toHaveBeenCalled();

      // Test locked to unlocked transition
      const unlockedCallback = jest.fn();
      service.onStatusChange("unlocked", unlockedCallback);

      service["status"] = {
        initialized: true,
        unlocked: false,
        sessionValid: false,
        unlockTime: null,
      };
      service.updateStatus({ unlocked: true });

      expect(unlockedCallback).toHaveBeenCalled();
    });
  });

  describe("Edge cases", () => {
    it("updateStatus mantiene valores no modificados", () => {
      service["status"] = {
        initialized: true,
        unlocked: true,
        sessionValid: true,
        unlockTime: 12345,
      };

      service.updateStatus({ initialized: false });

      const status = service.getStatus();
      expect(status.unlocked).toBe(true);
      expect(status.sessionValid).toBe(true);
      expect(status.unlockTime).toBe(12345);
    });

    it("getUnlockTimeFromMemory retorna unlockTime del estado", () => {
      const time = Date.now();
      service["status"] = {
        initialized: true,
        unlocked: true,
        sessionValid: true,
        unlockTime: time,
      };

      // Access private method via bracket notation
      const getUnlockTimeFromMemory = (service as any)
        .getUnlockTimeFromMemory as () => number | null;
      expect(getUnlockTimeFromMemory()).toBe(time);
    });

    it("checkStatus no llama isVaultUnlocked si no está inicializado", async () => {
      mockIsVaultInitialized.mockResolvedValue(false);

      await service.checkStatus();

      expect(mockIsVaultUnlocked).not.toHaveBeenCalled();
    });
  });
});
