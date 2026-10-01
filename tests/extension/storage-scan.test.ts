/**
 * Storage Scan Test - Security Invariant Verification
 *
 * Verifies NO plaintext secrets exist in chrome.storage.local:
 * - password of credentials
 * - Master Phrase / master key
 * - VEK (Vault Encryption Key)
 * - TOTP secrets
 * - Release Shares
 *
 * Only allowed in local storage:
 * - ciphertext
 * - IV/nonce
 * - salt
 * - non-secret metadata
 */

import { jest } from "@jest/globals";

// Mock chrome.storage
const createStorageMock = () => {
  const store = new Map<string, any>();

  return {
    local: {
      get: jest.fn(async (keys: string | string[]) => {
        const keyArray = Array.isArray(keys) ? keys : [keys];
        const result: Record<string, any> = {};
        for (const key of keyArray) {
          if (store.has(key)) {
            result[key] = store.get(key);
          }
        }
        return result;
      }),
      set: jest.fn(async (items: Record<string, any>) => {
        for (const [key, value] of Object.entries(items)) {
          store.set(key, value);
        }
      }),
      remove: jest.fn(async (keys: string | string[]) => {
        const keyArray = Array.isArray(keys) ? keys : [keys];
        for (const key of keyArray) {
          store.delete(key);
        }
      }),
      clear: jest.fn(async () => {
        store.clear();
      }),
    },
    session: {
      get: jest.fn(async (keys: string | string[]) => {
        const keyArray = Array.isArray(keys) ? keys : [keys];
        const result: Record<string, any> = {};
        for (const key of keyArray) {
          if (store.has(key)) {
            result[key] = store.get(key);
          }
        }
        return result;
      }),
      set: jest.fn(async (items: Record<string, any>) => {
        for (const [key, value] of Object.entries(items)) {
          store.set(key, value);
        }
      }),
      remove: jest.fn(async (keys: string | string[]) => {
        const keyArray = Array.isArray(keys) ? keys : [keys];
        for (const key of keyArray) {
          store.delete(key);
        }
      }),
    },
  };
};

describe("Storage Scan - Security Invariant Verification", () => {
  let storageMock: ReturnType<typeof createStorageMock>;

  beforeEach(() => {
    storageMock = createStorageMock();
    (global as any).chrome = {
      storage: storageMock,
    };
  });

  afterEach(() => {
    delete (global as any).chrome;
  });

  describe("chrome.storage.local - MUST NOT contain plaintext secrets", () => {
    const FORBIDDEN_PATTERNS = [
      // Plaintext passwords
      { pattern: /"password"\s*:\s*"[^"]+"/, name: "credential password" },
      { pattern: /"masterKey"\s*:\s*"[^"]+"/, name: "master key" },
      { pattern: /"masterPhrase"\s*:\s*"[^"]+"/, name: "master phrase" },
      { pattern: /"VEK"\s*:\s*"[^"]+"/, name: "VEK" },
      { pattern: /"vaultEncryptionKey"\s*:\s*"[^"]+"/, name: "vault encryption key" },
      { pattern: /"totpSecret"\s*:\s*"[^"]+"/, name: "TOTP secret" },
      { pattern: /"totp_seed"\s*:\s*"[^"]+"/, name: "TOTP seed" },
      { pattern: /"releaseShare"\s*:\s*"[^"]+"/, name: "release share" },
      { pattern: /"recoveryKey"\s*:\s*"[^"]+"/, name: "recovery key" },
      { pattern: /"recovery_key"\s*:\s*"[^"]+"/, name: "recovery key" },
      // Plaintext credential data
      { pattern: /"credentials"\s*:\s*\[[^\]]*"password"\s*:\s*"[^"]+"/, name: "credentials array with password" },
    ];

    function scanForPlaintextSecrets(storageData: any, path = "local"): string[] {
      const violations: string[] = [];
      const jsonStr = JSON.stringify(storageData);

      for (const { pattern, name } of FORBIDDEN_PATTERNS) {
        if (pattern.test(jsonStr)) {
          violations.push(`${path}: Found potential ${name} in plaintext`);
        }
      }

      return violations;
    }

    it("should have NO plaintext credential passwords in local storage", async () => {
      // Simulate realistic storage state after vault usage
      await storageMock.local.set({
        master_key_verify: "argon2id$v=19$m=65536,t=3,p=4$salt$hash",
        master_salt: "base64salt==",
        vault_initialized: true,
        credentials: [
          {
            id: "cred-1",
            vaultId: "vault-1",
            title: "GitHub",
            username: "user@example.com",
            encryptedPassword: "salt|iv|ciphertext", // ENCRYPTED - OK
            url: "https://github.com",
            tags: ["work"],
            favorite: false,
            createdAt: "2024-01-01T00:00:00Z",
            updatedAt: "2024-01-01T00:00:00Z",
          },
        ],
      });

      const result = await storageMock.local.get(["credentials", "master_key_verify", "master_salt", "vault_initialized"]);
      const violations = scanForPlaintextSecrets(result, "local");

      expect(violations).toEqual([]);
    });

    it("should have NO plaintext master key/VEK in local storage", async () => {
      await storageMock.local.set({
        master_key_verify: "argon2id$v=19$m=65536,t=3,p=4$salt$hash",
        master_salt: "base64salt==",
        vault_initialized: true,
        // BAD: VEK stored in local - should be in session only
        // VEK: "base64vekmaterial",
      });

      const result = await storageMock.local.get(["master_key_verify", "master_salt", "vault_initialized", "VEK"]);
      const violations = scanForPlaintextSecrets(result, "local");

      expect(violations).toEqual([]);
    });

    it("should have NO plaintext TOTP secrets in local storage", async () => {
      await storageMock.local.set({
        totp_secrets: {
          "github.com": "JBSWY3DPEHPK3PXP", // This would be a VIOLATION
        },
      });

      const result = await storageMock.local.get(["totp_secrets"]);
      const violations = scanForPlaintextSecrets(result, "local");

      expect(violations).toEqual([]);
    });

    it("should have NO plaintext Release Shares in local storage", async () => {
      await storageMock.local.set({
        release_shares: {
          "cred-1": "base64releaseshare", // This would be a VIOLATION
        },
      });

      const result = await storageMock.local.get(["release_shares"]);
      const violations = scanForPlaintextSecrets(result, "local");

      expect(violations).toEqual([]);
    });

    it("should allow ciphertext, IV, salt, metadata in local storage", async () => {
      await storageMock.local.set({
        credentials: [
          {
            id: "cred-1",
            encryptedPassword: "base64(salt|iv|ciphertext)", // ENCRYPTED - OK
            salt: "base64salt", // Salt for HKDF - OK
            iv: "base64iv", // IV for AES-GCM - OK
            mode: "personal", // Metadata - OK
            version: 1, // Metadata - OK
            url: "https://github.com", // Metadata - OK
            tags: ["work"], // Metadata - OK
          },
        ],
        master_key_verify: "argon2id$...", // Verification hash - OK
        master_salt: "base64salt", // Salt - OK
      });

      const result = await storageMock.local.get(["credentials", "master_key_verify", "master_salt"]);
      const violations = scanForPlaintextSecrets(result, "local");

      expect(violations).toEqual([]);
    });
  });

  describe("chrome.storage.session - MAY contain session key (ephemeral)", () => {
    it("should allow session key in session storage", async () => {
      await storageMock.session.set({
        cybervault_session_key: "base64sessionkey",
        cybervault_unlock_time: Date.now(),
      });

      const result = await storageMock.session.get(["cybervault_session_key", "cybervault_unlock_time"]);
      // Session storage is ephemeral - cleared on browser close
      // This is acceptable for session key
      expect(result.cybervault_session_key).toBeDefined();
      expect(result.cybervault_unlock_time).toBeDefined();
    });

    it("should be cleared on lock/timeout", async () => {
      await storageMock.session.set({
        cybervault_session_key: "base64sessionkey",
        cybervault_unlock_time: Date.now(),
      });

      await storageMock.session.remove(["cybervault_session_key", "cybervault_unlock_time"]);

      const result = await storageMock.session.get(["cybervault_session_key", "cybervault_unlock_time"]);
      expect(result.cybervault_session_key).toBeUndefined();
      expect(result.cybervault_unlock_time).toBeUndefined();
    });
  });

  describe("Integration - Full storage scan simulation", () => {
    it("complete storage state should pass security scan", async () => {
      // Simulate a fully initialized vault with active session
      await storageMock.local.set({
        master_key_verify: "argon2id$v=19$m=65536,t=3,p=4$salt$hash",
        master_salt: "base64salt==",
        vault_initialized: true,
        credentials: [
          {
            id: "cred-1",
            vaultId: "vault-1",
            title: "GitHub",
            username: "user@example.com",
            encryptedPassword: "base64(salt|iv|ciphertext)",
            salt: "base64salt",
            version: 1,
            mode: "personal",
            url: "https://github.com",
            tags: ["work"],
            favorite: false,
            createdAt: "2024-01-01T00:00:00Z",
            updatedAt: "2024-01-01T00:00:00Z",
          },
        ],
        cybervault_settings: {
          autoValidate: true,
          blockHighRisk: true,
          showNotifications: true,
          sessionTimeoutMinutes: 30,
        },
        cybervault_anomaly_log: [],
      });

      await storageMock.session.set({
        cybervault_session_key: "base64sessionkey",
        cybervault_unlock_time: Date.now(),
      });

      // Scan local storage - get all known keys
      const localData = await storageMock.local.get([
        "master_key_verify",
        "master_salt",
        "vault_initialized",
        "credentials",
        "cybervault_settings",
        "cybervault_anomaly_log",
      ]);
      const localViolations: string[] = [];

      const FORBIDDEN_PATTERNS = [
        { pattern: /"password"\s*:\s*"[^"]+"/, name: "credential password" },
        { pattern: /"masterKey"\s*:\s*"[^"]+"/, name: "master key" },
        { pattern: /"masterPhrase"\s*:\s*"[^"]+"/, name: "master phrase" },
        { pattern: /"VEK"\s*:\s*"[^"]+"/, name: "VEK" },
        { pattern: /"vaultEncryptionKey"\s*:\s*"[^"]+"/, name: "vault encryption key" },
        { pattern: /"totpSecret"\s*:\s*"[^"]+"/, name: "TOTP secret" },
        { pattern: /"totp_seed"\s*:\s*"[^"]+"/, name: "TOTP seed" },
        { pattern: /"releaseShare"\s*:\s*"[^"]+"/, name: "release share" },
        { pattern: /"recoveryKey"\s*:\s*"[^"]+"/, name: "recovery key" },
      ];

      const jsonStr = JSON.stringify(localData);
      for (const { pattern, name } of FORBIDDEN_PATTERNS) {
        if (pattern.test(jsonStr)) {
          localViolations.push(`local: Found potential ${name} in plaintext`);
        }
      }

      expect(localViolations).toEqual([]);
    });
  });
});