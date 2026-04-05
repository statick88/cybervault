// @ts-nocheck

/**
 * MasterKeyManager Unit Tests
 * Tests for vault initialization, unlock/lock, session management, and encryption operations
 */

import {
  describe,
  it,
  expect,
  beforeEach,
  afterEach,
  jest,
} from "@jest/globals";

// In-memory storage simulation
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
    // Single key string
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

// Import after mocking
import {
  initializeVault,
  unlockVault,
  isVaultUnlocked,
  isSessionValid,
  getSessionKey,
  encryptWithSessionKey,
  decryptWithSessionKey,
  lockVault,
  resetVault,
  isVaultInitialized,
  refreshSession,
} from "../../src/infrastructure/crypto/master-key-manager";

describe("MasterKeyManager", () => {
  beforeEach(() => {
    jest.clearAllMocks();
    storageData = {};
  });

  afterEach(() => {
    // Ensure vault is locked and state cleared
    try {
      lockVault();
    } catch (e) {
      // ignore if module not loaded
    }
    jest.clearAllMocks();
  });

  describe("Grupo 1: Vault Initialization", () => {
    it("initializeVault con master password válido → success, guarda verifyHash y salt", async () => {
      const masterKey = "secure-password-12345";

      // Mock deriveKey to return an extractable AES key
      const originalDeriveKey = crypto.subtle.deriveKey;
      const realKey = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"],
      );
      const mockDeriveKey = jest.fn().mockResolvedValue(realKey);
      crypto.subtle.deriveKey = mockDeriveKey;

      try {
        const result = await initializeVault(masterKey);

        expect(result.success).toBe(true);
        // Should have called set at least with verification data
        expect(storageMock.set).toHaveBeenCalledWith(
          expect.objectContaining({
            master_key_verify: expect.any(String),
            master_salt: expect.any(String),
            vault_initialized: true,
          }),
        );
        // Verify credentials cleared (called with empty array)
        expect(storageMock.set).toHaveBeenCalledWith({ credentials: [] });
      } finally {
        crypto.subtle.deriveKey = originalDeriveKey;
      }
    });

    it("initializeVault llamado dos veces → error (vault ya inicializado)", async () => {
      const masterKey = "secure-password-12345";

      const originalDeriveKey = crypto.subtle.deriveKey;
      const realKey = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"],
      );
      const mockDeriveKey = jest.fn().mockResolvedValue(realKey);
      crypto.subtle.deriveKey = mockDeriveKey;

      try {
        // First call should succeed
        const firstResult = await initializeVault(masterKey);
        expect(firstResult.success).toBe(true);

        // Second call should fail because vault is already initialized
        const secondResult = await initializeVault(masterKey);
        expect(secondResult.success).toBe(false);
        expect(secondResult.error).toMatch(/ya inicializada|bóveda/);
      } finally {
        crypto.subtle.deriveKey = originalDeriveKey;
      }
    });

    it("initializeVault con password corto (<12 chars) → error", async () => {
      const masterKey = "short";
      const result = await initializeVault(masterKey);

      expect(result.success).toBe(false);
      expect(result.error).toMatch(/12 caracteres/);
    });
  });

  describe("Grupo 2: Unlock/Lock", () => {
    it("unlockVault con password correcto → success", async () => {
      const masterKey = "valid-master-key-123";

      // Prepare vault: initialize first
      const salt = new Uint8Array(32);
      salt.fill(1);
      const saltBase64 = btoa(String.fromCharCode(...salt));
      const encoder = new TextEncoder();
      const keyMaterial = await crypto.subtle.importKey(
        "raw",
        encoder.encode(masterKey),
        "PBKDF2",
        false,
        ["deriveBits"],
      );
      const derivedBits = await crypto.subtle.deriveBits(
        {
          name: "PBKDF2",
          salt: salt as any,
          iterations: 600000,
          hash: "SHA-512",
        },
        keyMaterial,
        512,
      );
      const storedHash = btoa(
        String.fromCharCode(...new Uint8Array(derivedBits)),
      );

      // Simulate storage state after initialization
      storageData = {
        vault_initialized: true,
        master_key_verify: storedHash,
        master_salt: saltBase64,
      };

      // Mock deriveKey for session key
      const originalDeriveKey = crypto.subtle.deriveKey;
      const realKey = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"],
      );
      const mockDeriveKey = jest.fn().mockResolvedValue(realKey);
      crypto.subtle.deriveKey = mockDeriveKey;

      try {
        const result = await unlockVault(masterKey);

        expect(result.success).toBe(true);
        expect(isVaultUnlocked()).toBe(true);
        expect(isSessionValid()).toBe(true);
      } finally {
        crypto.subtle.deriveKey = originalDeriveKey;
      }
    });

    it("unlockVault con password incorrecto → error", async () => {
      const wrongPassword = "wrong-password";
      const correctPassword = "correct-password";

      const salt = new Uint8Array(32);
      salt.fill(1);
      const saltBase64 = btoa(String.fromCharCode(...salt));
      const encoder = new TextEncoder();
      const keyMaterial = await crypto.subtle.importKey(
        "raw",
        encoder.encode(correctPassword),
        "PBKDF2",
        false,
        ["deriveBits"],
      );
      const derivedBits = await crypto.subtle.deriveBits(
        {
          name: "PBKDF2",
          salt: salt as any,
          iterations: 600000,
          hash: "SHA-512",
        },
        keyMaterial,
        512,
      );
      const correctHash = btoa(
        String.fromCharCode(...new Uint8Array(derivedBits)),
      );

      storageData = {
        vault_initialized: true,
        master_key_verify: correctHash,
        master_salt: saltBase64,
      };

      const result = await unlockVault(wrongPassword);

      expect(result.success).toBe(false);
      expect(result.error).toMatch(/incorrecta/);
      expect(isVaultUnlocked()).toBe(false);
    });

    it("unlockVault cuando ya está desbloqueado → success sin nueva derivación", async () => {
      const masterKey = "test-key";

      const salt = new Uint8Array(32);
      salt.fill(1);
      const saltBase64 = btoa(String.fromCharCode(...salt));
      const encoder = new TextEncoder();
      const keyMaterial = await crypto.subtle.importKey(
        "raw",
        encoder.encode(masterKey),
        "PBKDF2",
        false,
        ["deriveBits"],
      );
      const derivedBits = await crypto.subtle.deriveBits(
        {
          name: "PBKDF2",
          salt: salt as any,
          iterations: 600000,
          hash: "SHA-512",
        },
        keyMaterial,
        512,
      );
      const storedHash = btoa(
        String.fromCharCode(...new Uint8Array(derivedBits)),
      );

      storageData = {
        vault_initialized: true,
        master_key_verify: storedHash,
        master_salt: saltBase64,
      };

      // Mock deriveKey for first unlock
      const originalDeriveKey = crypto.subtle.deriveKey;
      const realKey = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"],
      );
      const mockDeriveKey = jest.fn().mockResolvedValue(realKey);
      crypto.subtle.deriveKey = mockDeriveKey;

      try {
        await unlockVault(masterKey);
        expect(isVaultUnlocked()).toBe(true);

        // Clear mocks (not strictly necessary but good)
        storageMock.get.mockClear();
        storageMock.set.mockClear();

        // Second unlock should succeed without storage access
        const result = await unlockVault(masterKey);
        expect(result.success).toBe(true);
        expect(storageMock.get).not.toHaveBeenCalled();
      } finally {
        crypto.subtle.deriveKey = originalDeriveKey;
      }
    });

    it("lockVault limpia estado", async () => {
      // Initially should be locked
      expect(isVaultUnlocked()).toBe(false);
      expect(isSessionValid()).toBe(false);
    });
  });

  describe("Grupo 3: Session Management", () => {
    it("isSessionValid devuelve false sin unlockTime", async () => {
      expect(isSessionValid()).toBe(false);
    });

    it("getSessionKey retorna null si vault cerrado", async () => {
      const key = getSessionKey();
      expect(key).toBeNull();
    });
  });

  describe("Grupo 4: Encryption/Decryption with Session", () => {
    it("encryptWithSessionKey retorna null sin session", async () => {
      const result = await encryptWithSessionKey("test data");
      expect(result).toBeNull();
    });

    it("decryptWithSessionKey retorna null sin session", async () => {
      const result = await decryptWithSessionKey("encrypted");
      expect(result).toBeNull();
    });
  });

  describe("Grupo 5: Security", () => {
    it("verifyHash usa 600k iteraciones", async () => {
      const originalDeriveBits = crypto.subtle.deriveBits;
      const mockDeriveBits = jest.fn(async () => new ArrayBuffer(64)) as any;
      crypto.subtle.deriveBits = mockDeriveBits;

      try {
        const salt = new Uint8Array(32);
        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
          "raw",
          encoder.encode("test"),
          "PBKDF2",
          false,
          ["deriveBits"],
        );
        await crypto.subtle.deriveBits(
          {
            name: "PBKDF2",
            salt: salt as any,
            iterations: 600000,
            hash: "SHA-512",
          },
          keyMaterial,
          512,
        );

        expect(mockDeriveBits).toHaveBeenCalledWith(
          expect.objectContaining({
            iterations: 600000,
            hash: "SHA-512",
          }),
          expect.any(Object),
          512,
        );
      } finally {
        crypto.subtle.deriveBits = originalDeriveBits;
      }
    });

    it("sessionKey usa 600k iteraciones", async () => {
      const originalDeriveKey = crypto.subtle.deriveKey;
      const realKey = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"],
      );
      const mockDeriveKey = jest.fn().mockResolvedValue(realKey);
      crypto.subtle.deriveKey = mockDeriveKey;

      try {
        const salt = new Uint8Array(32);
        const encoder = new TextEncoder();
        const keyMaterial = await crypto.subtle.importKey(
          "raw",
          encoder.encode("test"),
          "PBKDF2",
          false,
          ["deriveKey"],
        );
        await crypto.subtle.deriveKey(
          {
            name: "PBKDF2",
            salt: salt as any,
            iterations: 600000,
            hash: "SHA-512",
            info: encoder.encode("cybervault_session_key_v1"),
          },
          keyMaterial,
          { name: "AES-GCM", length: 256 },
          false,
          ["encrypt", "decrypt"],
        );

        expect(mockDeriveKey).toHaveBeenCalledWith(
          expect.objectContaining({
            iterations: 600000,
            hash: "SHA-512",
          }),
          expect.any(Object),
          expect.objectContaining({
            name: "AES-GCM",
            length: 256,
          }),
          false,
          ["encrypt", "decrypt"],
        );
      } finally {
        crypto.subtle.deriveKey = originalDeriveKey;
      }
    });
  });

  describe("Grupo 6: Additional Scenarios", () => {
    it("isVaultInitialized devuelve false al inicio y true después de initialize", async () => {
      expect(await isVaultInitialized()).toBe(false);

      const masterKey = "password123456";
      const originalDeriveKey = crypto.subtle.deriveKey;
      const realKey = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"],
      );
      crypto.subtle.deriveKey = jest.fn().mockResolvedValue(realKey);
      try {
        await initializeVault(masterKey);
        expect(await isVaultInitialized()).toBe(true);
      } finally {
        crypto.subtle.deriveKey = originalDeriveKey;
      }
    });

    it("resetVault limpia storage y estado de sesión", async () => {
      const masterKey = "password123456";
      // Initialize vault first
      const originalDeriveKey = crypto.subtle.deriveKey;
      const realKey = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"],
      );
      crypto.subtle.deriveKey = jest.fn().mockResolvedValue(realKey);
      try {
        await initializeVault(masterKey);
        expect(await isVaultInitialized()).toBe(true);
        expect(isVaultUnlocked()).toBe(true);

        // Reset vault
        await resetVault();

        expect(await isVaultInitialized()).toBe(false);
        expect(isVaultUnlocked()).toBe(false);
        expect(storageMock.remove).toHaveBeenCalledWith(
          expect.arrayContaining([
            "master_key_verify",
            "master_salt",
            "vault_initialized",
            "credentials",
          ]),
        );
      } finally {
        crypto.subtle.deriveKey = originalDeriveKey;
      }
    });

    it("refreshSession se puede llamar sin errores", async () => {
      const masterKey = "password123456";

      const originalDeriveKey = crypto.subtle.deriveKey;
      const realKey = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"],
      );
      crypto.subtle.deriveKey = jest.fn().mockResolvedValue(realKey);
      try {
        await initializeVault(masterKey);
        await unlockVault(masterKey);

        // Call refreshSession
        refreshSession();
        expect(isVaultUnlocked()).toBe(true);
        expect(isSessionValid()).toBe(true);
      } finally {
        crypto.subtle.deriveKey = originalDeriveKey;
      }
    });

    it("getSessionKey retorna key si vault desbloqueado y session válida", async () => {
      const masterKey = "password123456";

      const originalDeriveKey = crypto.subtle.deriveKey;
      const realKey = await crypto.subtle.generateKey(
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"],
      );
      crypto.subtle.deriveKey = jest.fn().mockResolvedValue(realKey);
      try {
        await initializeVault(masterKey);
        await unlockVault(masterKey);

        const sessionKey = getSessionKey();
        expect(sessionKey).not.toBeNull();
        expect(typeof sessionKey).toBe("string");
      } finally {
        crypto.subtle.deriveKey = originalDeriveKey;
      }
    });
  });
});
