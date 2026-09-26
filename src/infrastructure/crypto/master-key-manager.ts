/**
 * Master Key Manager - Zero Knowledge Architecture with Session Storage
 *
 * SECURITY INVARIANTS:
 * - Master Key (VEK) NEVER stored in chrome.storage.local
 * - Master Key (VEK) ONLY stored in chrome.storage.session (cleared on browser close/lock/timeout)
 * - chrome.storage.local contains ONLY ciphertext, IV/nonce, salt, non-secret metadata
 * - No plaintext secrets persist across sessions
 *
 * Flow:
 * 1. First time: User creates master key → store only verification hash in local
 * 2. Each session: User unlocks with master key → verify hash → derive session key → store in SESSION storage
 * 3. All operations use session key from SESSION storage
 * 4. On lock/timeout/close: session storage cleared, VEK eliminated
 */

import { encryptWithKey, decryptWithKey } from "./EncryptionService";
import { KeyDerivationService } from "./key-derivation-service";
import { binaryToBase64, base64ToBinary } from "../../shared/utils";

const keyDerivationService = new KeyDerivationService();

const STORAGE_KEYS = {
  // chrome.storage.local (PERSISTENT - survives browser restart)
  MASTER_KEY_VERIFY: "master_key_verify", // Verification hash only (Argon2id/PBKDF2)
  SALT: "master_salt", // Salt for key derivation
  VAULT_INITIALIZED: "vault_initialized", // Whether vault is set up

  // chrome.storage.session (EPHEMERAL - cleared on browser close/tab close)
  SESSION_KEY: "cybervault_session_key", // Session key (derived from master key + salt)
  SESSION_UNLOCK_TIME: "cybervault_unlock_time", // Session start timestamp
} as const;

const SESSION_DURATION_MS = 15 * 60 * 1000; // 15 minutes

/**
 * Result of master key verification
 */
export interface MasterKeyVerifyResult {
  success: boolean;
  error?: string;
}

/**
 * Generate a secure random salt
 */
function generateSalt(): Uint8Array {
  const salt = new Uint8Array(32); // 256-bit salt
  crypto.getRandomValues(salt);
  return salt;
}

/**
 * Hash the master key for verification (NOT the key itself)
 * Uses PBKDF2 with high iterations
 */
async function hashMasterKey(
  masterKey: string,
  salt: Uint8Array,
): Promise<string> {
  return await keyDerivationService.deriveVerificationHash(masterKey, salt);
}

/**
 * Generate a session key from master key
 * This is used for actual encryption/decryption
 */
async function deriveSessionKey(
  masterKey: string,
  salt: Uint8Array,
): Promise<string> {
  return await keyDerivationService.deriveSessionKey(masterKey, salt);
}

/**
 * Check if vault is initialized (master key set up)
 */
export async function isVaultInitialized(): Promise<boolean> {
  try {
    const result = await chrome.storage.local.get(
      STORAGE_KEYS.VAULT_INITIALIZED,
    );
    return result[STORAGE_KEYS.VAULT_INITIALIZED] === true;
  } catch {
    return false;
  }
}

/**
 * Initialize vault with new master key
 * SECURITY: Only stores verification hash in local, never the actual key
 */
export async function initializeVault(
  masterKey: string,
): Promise<MasterKeyVerifyResult> {
  try {
    // Validate master key strength
    if (masterKey.length < 12) {
      return {
        success: false,
        error: "La clave maestra debe tener al menos 12 caracteres",
      };
    }

    // Check if vault already initialized
    const alreadyInitialized = await isVaultInitialized();
    if (alreadyInitialized) {
      return {
        success: false,
        error: "La bóveda ya ha sido inicializada",
      };
    }

    // Generate unique salt for this vault
    const salt = generateSalt();
    const saltBase64 = binaryToBase64(salt);

    // Create verification hash (for authentication)
    const verifyHash = await hashMasterKey(masterKey, salt);

    // Store verification data in LOCAL storage (NOT the key!)
    await chrome.storage.local.set({
      [STORAGE_KEYS.MASTER_KEY_VERIFY]: verifyHash,
      [STORAGE_KEYS.SALT]: saltBase64,
      [STORAGE_KEYS.VAULT_INITIALIZED]: true,
    });

    // Derive session key and store in SESSION storage
    const sessionKey = await deriveSessionKey(masterKey, salt);
    await chrome.storage.session.set({
      [STORAGE_KEYS.SESSION_KEY]: sessionKey,
      [STORAGE_KEYS.SESSION_UNLOCK_TIME]: Date.now(),
    });

    // Clear any existing credentials (fresh start)
    await chrome.storage.local.set({ credentials: [] });

    return { success: true };
  } catch (error) {
    console.error("Error initializing vault:", error);
    return { success: false, error: "Error al inicializar la bóveda" };
  }
}

/**
 * Unlock vault with master key
 * SECURITY: Verifies hash, then derives session key into SESSION storage
 */
export async function unlockVault(
  masterKey: string,
): Promise<MasterKeyVerifyResult> {
  try {
    // Check if already unlocked with valid session (from session storage)
    if (await isSessionValid()) {
      await refreshSession();
      return { success: true };
    }

    // Get stored verification data from LOCAL storage
    const stored = await chrome.storage.local.get([
      STORAGE_KEYS.MASTER_KEY_VERIFY,
      STORAGE_KEYS.SALT,
    ]);

    const storedHash = stored[STORAGE_KEYS.MASTER_KEY_VERIFY] as string;
    const storedSalt = stored[STORAGE_KEYS.SALT] as string;

    if (!storedHash || !storedSalt) {
      return { success: false, error: "Bóveda no inicializada" };
    }

    const salt = base64ToBinary(storedSalt);

    // Verify master key
    const verifyHash = await hashMasterKey(masterKey, salt);

    // Timing-safe comparison
    if (!timingSafeEqual(verifyHash, storedHash)) {
      // SECURITY: Generic error message
      return { success: false, error: "Clave maestra incorrecta" };
    }

    // Derive session key and store in SESSION storage
    const sessionKey = await deriveSessionKey(masterKey, salt);
    await chrome.storage.session.set({
      [STORAGE_KEYS.SESSION_KEY]: sessionKey,
      [STORAGE_KEYS.SESSION_UNLOCK_TIME]: Date.now(),
    });

    return { success: true };
  } catch (error) {
    console.error("Error unlocking vault:", error);
    return { success: false, error: "Error al desbloquear la bóveda" };
  }
}

/**
 * Lock vault (clear session key from SESSION storage)
 * This is the primary security boundary - VEK eliminated from session
 */
export async function lockVault(): Promise<void> {
  await chrome.storage.session.remove([
    STORAGE_KEYS.SESSION_KEY,
    STORAGE_KEYS.SESSION_UNLOCK_TIME,
  ]);
}

/**
 * Check if vault is currently unlocked (session exists and is valid)
 */
export async function isVaultUnlocked(): Promise<boolean> {
  return await isSessionValid();
}

/**
 * Check if current session is still valid (not expired)
 */
export async function isSessionValid(): Promise<boolean> {
  try {
    const session = await chrome.storage.session.get([
      STORAGE_KEYS.SESSION_KEY,
      STORAGE_KEYS.SESSION_UNLOCK_TIME,
    ]);

    const sessionKey = session[STORAGE_KEYS.SESSION_KEY] as string | undefined;
    const unlockTime = session[STORAGE_KEYS.SESSION_UNLOCK_TIME] as number | undefined;

    if (!sessionKey || !unlockTime) {
      return false;
    }

    return Date.now() - unlockTime < SESSION_DURATION_MS;
  } catch {
    return false;
  }
}

/**
 * Refresh session timer (call on each operation)
 */
export async function refreshSession(): Promise<void> {
  const isValid = await isSessionValid();
  if (isValid) {
    await chrome.storage.session.set({
      [STORAGE_KEYS.SESSION_UNLOCK_TIME]: Date.now(),
    });
  }
}

/**
 * Get session key (only if session valid)
 * Returns null if session expired or not unlocked
 */
export async function getSessionKey(): Promise<string | null> {
  const isValid = await isSessionValid();
  if (!isValid) {
    // Session expired, lock immediately
    await lockVault();
    return null;
  }

  try {
    const session = await chrome.storage.session.get([
      STORAGE_KEYS.SESSION_KEY,
    ]);
    const sessionKey = session[STORAGE_KEYS.SESSION_KEY] as string | undefined;

    if (!sessionKey) {
      return null;
    }

    // Refresh session timer on access
    await refreshSession();

    return sessionKey;
  } catch {
    return null;
  }
}

/**
 * Encrypt data using session key from SESSION storage
 */
export async function encryptWithSessionKey(
  data: string,
): Promise<string | null> {
  const sessionKey = await getSessionKey();
  if (!sessionKey) {
    return null;
  }

  return await encryptWithKey(data, sessionKey);
}

/**
 * Decrypt data using session key from SESSION storage
 */
export async function decryptWithSessionKey(
  encryptedData: string,
): Promise<string | null> {
  const sessionKey = await getSessionKey();
  if (!sessionKey) {
    return null;
  }

  try {
    return await decryptWithKey(encryptedData, sessionKey);
  } catch {
    return null;
  }
}

/**
 * Reset vault (dangerous - deletes everything from both storages)
 */
export async function resetVault(): Promise<void> {
  await lockVault();
  await chrome.storage.local.remove([
    STORAGE_KEYS.MASTER_KEY_VERIFY,
    STORAGE_KEYS.SALT,
    STORAGE_KEYS.VAULT_INITIALIZED,
    "credentials",
  ]);
}

/**
 * Timing-safe string comparison
 */
function timingSafeEqual(a: string, b: string): boolean {
  const maxLen = Math.max(a.length, b.length);
  let result = a.length ^ b.length;
  for (let i = 0; i < maxLen; i++) {
    result |= a.charCodeAt(i % a.length) ^ b.charCodeAt(i % b.length);
  }
  return result === 0;
}