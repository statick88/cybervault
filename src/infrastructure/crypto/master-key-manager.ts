/**
 * Master Key Manager - Zero Knowledge Architecture
 *
 * SECURITY: This module handles the master key for Zero Knowledge encryption.
 * The master key is NEVER stored - only a verification hash is stored.
 * All encryption/decryption happens in memory during the session.
 *
 * Flow:
 * 1. First time: User creates master key → store only verification hash
 * 2. Each session: User unlocks with master key → verify hash → derive session key
 * 3. All operations use session key derived from master key
 */

import { CryptoService } from "./crypto-service";
import { binaryToBase64, base64ToBinary } from "@/shared/utils";

const STORAGE_KEYS = {
  MASTER_KEY_VERIFY: "master_key_verify", // Hash for verification only
  SALT: "master_salt", // Salt for key derivation
  VAULT_INITIALIZED: "vault_initialized", // Whether vault is set up
  SESSION_KEY: "session_key", // In-memory session key (not persisted)
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
 * Session state
 */
interface SessionState {
  isUnlocked: boolean;
  sessionKey: string | null;
  unlockTime: number | null;
}

const sessionState: SessionState = {
  isUnlocked: false,
  sessionKey: null,
  unlockTime: null,
};

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
      salt: salt as BufferSource,
      iterations: 600000, // NIST recommended
      hash: "SHA-512",
    },
    keyMaterial,
    512, // 512 bits
  );

  return binaryToBase64(new Uint8Array(derivedBits));
}

/**
 * Generate a session key from master key
 * This is used for actual encryption/decryption
 */
async function deriveSessionKey(
  masterKey: string,
  salt: Uint8Array,
): Promise<string> {
  const encoder = new TextEncoder();
  // Use different info for session key vs verification
  const sessionInfo = encoder.encode("cybervault_session_key_v1");

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(masterKey),
    "PBKDF2",
    false,
    ["deriveKey"],
  );

  const sessionKey = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt as BufferSource,
      iterations: 600000, // Consistent with NIST recommendation
      hash: "SHA-512",
      info: sessionInfo,
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    true, // Extractable to allow export for in-memory use
    ["encrypt", "decrypt"],
  );

  // Export for use (will be kept in memory only)
  const exported = await crypto.subtle.exportKey("raw", sessionKey);
  return binaryToBase64(new Uint8Array(exported));
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
 * SECURITY: Only stores verification hash, never the actual key
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

    // Store verification data (NOT the key!)
    await chrome.storage.local.set({
      [STORAGE_KEYS.MASTER_KEY_VERIFY]: verifyHash,
      [STORAGE_KEYS.SALT]: saltBase64,
      [STORAGE_KEYS.VAULT_INITIALIZED]: true,
    });

    // Derive and store session key in memory
    sessionState.sessionKey = await deriveSessionKey(masterKey, salt);
    sessionState.isUnlocked = true;
    sessionState.unlockTime = Date.now();

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
 * SECURITY: Verifies hash, then derives session key into memory
 */
export async function unlockVault(
  masterKey: string,
): Promise<MasterKeyVerifyResult> {
  try {
    // Check if already unlocked with valid session
    if (sessionState.isUnlocked && isSessionValid()) {
      refreshSession();
      return { success: true };
    }

    // If unlocked but expired, lock first
    if (sessionState.isUnlocked && !isSessionValid()) {
      lockVault();
    }

    // Get stored verification data
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

    // Derive session key into memory
    sessionState.sessionKey = await deriveSessionKey(masterKey, salt);
    sessionState.isUnlocked = true;
    sessionState.unlockTime = Date.now();

    return { success: true };
  } catch (error) {
    console.error("Error unlocking vault:", error);
    return { success: false, error: "Error al desbloquear la bóveda" };
  }
}

/**
 * Lock vault (clear session key from memory)
 */
export function lockVault(): void {
  sessionState.isUnlocked = false;
  sessionState.sessionKey = null;
  sessionState.unlockTime = null;
}

/**
 * Check if vault is currently unlocked
 */
export function isVaultUnlocked(): boolean {
  return sessionState.isUnlocked;
}

/**
 * Check if current session is still valid (not expired)
 */
export function isSessionValid(): boolean {
  if (!sessionState.unlockTime) return false;
  return Date.now() - sessionState.unlockTime < SESSION_DURATION_MS;
}

/**
 * Refresh session timer (call on each operation)
 */
export function refreshSession(): void {
  if (sessionState.isUnlocked) {
    sessionState.unlockTime = Date.now();
  }
}

/**
 * Get session key (only if unlocked and session valid)
 * Throws error if session expired
 */
export function getSessionKey(): string | null {
  if (!sessionState.isUnlocked) {
    return null;
  }

  if (!isSessionValid()) {
    // Session expired, lock immediately
    lockVault();
    return null;
  }

  // Refresh session timer on access
  refreshSession();

  return sessionState.sessionKey;
}

/**
 * Encrypt data using session key
 */
export async function encryptWithSessionKey(
  data: string,
): Promise<string | null> {
  const sessionKey = getSessionKey();
  if (!sessionKey) {
    return null;
  }

  const cryptoService = new CryptoService();
  return await cryptoService.encrypt(data, sessionKey);
}

/**
 * Decrypt data using session key
 */
export async function decryptWithSessionKey(
  encryptedData: string,
): Promise<string | null> {
  const sessionKey = getSessionKey();
  if (!sessionKey) {
    return null;
  }

  const cryptoService = new CryptoService();
  try {
    return await cryptoService.decrypt(encryptedData, sessionKey);
  } catch {
    return null;
  }
}

/**
 * Reset vault (dangerous - deletes everything)
 */
export async function resetVault(): Promise<void> {
  lockVault();
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
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}
