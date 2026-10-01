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
 *
 * Scheme versioning (CRITICAL-2):
 * The persisted verifier carries a scheme id (`master_key_scheme`) and a
 * self-describing prefix (`hkdf-sha256-v2$`). A verifier written by the old
 * scheme — where PBKDF2 silently ignored `info`, so the verifier WAS the first
 * 256 bits of the session key — is rejected with an explicit
 * SCHEME_UNSUPPORTED result instead of a misleading "wrong password", and the
 * vault must be re-initialized (resetVault → initializeVault). Persisted-data
 * invalidation is explicitly authorized by the user.
 */

import { encryptWithKey, decryptWithKey } from "./EncryptionService";
import {
  KeyDerivationService,
  KEY_DERIVATION_CONFIG,
  VERIFIER_SCHEME_PREFIX,
} from "./key-derivation-service";
import { binaryToBase64, base64ToBinary } from "../../shared/utils";

const keyDerivationService = new KeyDerivationService();

const STORAGE_KEYS = {
  // chrome.storage.local (PERSISTENT - survives browser restart)
  MASTER_KEY_VERIFY: "master_key_verify", // Verifier only (scheme-prefixed, never key material)
  SALT: "master_salt", // Salt for key derivation
  SCHEME: "master_key_scheme", // Derivation scheme id of the stored verifier
  VAULT_INITIALIZED: "vault_initialized", // Whether vault is set up

  // chrome.storage.session (EPHEMERAL - cleared on browser close/tab close)
  SESSION_KEY: "cybervault_session_key", // Session key (derived from master key + salt)
  SESSION_UNLOCK_TIME: "cybervault_unlock_time", // Session start timestamp
} as const;

const SESSION_DURATION_MS = 15 * 60 * 1000; // 15 minutes

/** Error returned when the persisted verifier comes from an older scheme. */
export const SCHEME_UNSUPPORTED_ERROR =
  "Esquema de bóveda no compatible: los datos persistidos fueron escritos por un esquema anterior y deben descartarse. Reinicialice la bóveda (resetVault → initializeVault) para continuar.";

/**
 * Machine-readable failure reasons, so callers never have to parse the
 * localized message to tell "wrong password" from "old scheme".
 */
export type MasterKeyFailureCode =
  | "VAULT_NOT_INITIALIZED"
  | "SCHEME_UNSUPPORTED"
  | "WRONG_PASSPHRASE";

/**
 * Result of master key verification
 */
export interface MasterKeyVerifyResult {
  success: boolean;
  error?: string;
  code?: MasterKeyFailureCode;
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
 * Derive the persisted verifier for the master key (NOT the key itself).
 * PBKDF2-SHA512 stretches the passphrase, then HKDF-SHA256 binds the result to
 * the `master_key_verify` context label. The returned value is not, does not
 * contain, and cannot reveal the session key.
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
 * True when a persisted verifier was written by the current derivation scheme.
 * Anything else (missing scheme id, missing prefix, foreign scheme id) is an
 * old/foreign verifier and must be rejected explicitly.
 */
function hasCurrentScheme(
  storedScheme: unknown,
  storedVerifier: unknown,
): boolean {
  return (
    storedScheme === KEY_DERIVATION_CONFIG.SCHEME &&
    typeof storedVerifier === "string" &&
    storedVerifier.startsWith(VERIFIER_SCHEME_PREFIX)
  );
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
      // A vault whose verifier comes from an older scheme must be reset
      // explicitly first: initializeVault never silently destroys data.
      const existing = await chrome.storage.local.get([
        STORAGE_KEYS.MASTER_KEY_VERIFY,
        STORAGE_KEYS.SCHEME,
      ]);
      if (
        !hasCurrentScheme(
          existing[STORAGE_KEYS.SCHEME],
          existing[STORAGE_KEYS.MASTER_KEY_VERIFY],
        )
      ) {
        return {
          success: false,
          code: "SCHEME_UNSUPPORTED",
          error: SCHEME_UNSUPPORTED_ERROR,
        };
      }
      return {
        success: false,
        error: "La bóveda ya ha sido inicializada",
      };
    }

    // Generate unique salt for this vault
    const salt = generateSalt();
    const saltBase64 = binaryToBase64(salt);

    // Create the persisted verifier (for authentication) — context-bound, not key material
    const verifyHash = await hashMasterKey(masterKey, salt);

    // Store verification data in LOCAL storage (NOT the key!)
    await chrome.storage.local.set({
      [STORAGE_KEYS.MASTER_KEY_VERIFY]: `${VERIFIER_SCHEME_PREFIX}${verifyHash}`,
      [STORAGE_KEYS.SALT]: saltBase64,
      [STORAGE_KEYS.SCHEME]: KEY_DERIVATION_CONFIG.SCHEME,
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
      STORAGE_KEYS.SCHEME,
      STORAGE_KEYS.VAULT_INITIALIZED,
    ]);

    const storedHash = stored[STORAGE_KEYS.MASTER_KEY_VERIFY];
    const storedSalt = stored[STORAGE_KEYS.SALT] as string;

    if (stored[STORAGE_KEYS.VAULT_INITIALIZED] !== true) {
      return {
        success: false,
        code: "VAULT_NOT_INITIALIZED",
        error: "Bóveda no inicializada",
      };
    }

    // Fail closed on any verifier that this scheme did not write. This is a
    // scheme error, NOT a passphrase error: the user must re-initialize.
    if (!hasCurrentScheme(stored[STORAGE_KEYS.SCHEME], storedHash)) {
      return {
        success: false,
        code: "SCHEME_UNSUPPORTED",
        error: SCHEME_UNSUPPORTED_ERROR,
      };
    }

    if (!storedSalt) {
      return {
        success: false,
        code: "VAULT_NOT_INITIALIZED",
        error: "Bóveda no inicializada",
      };
    }

    const salt = base64ToBinary(storedSalt);

    // Strip the public scheme prefix; what remains is the 256-bit verifier.
    const expectedVerifier = (storedHash as string).slice(
      VERIFIER_SCHEME_PREFIX.length,
    );

    // Verify master key
    const verifyHash = await hashMasterKey(masterKey, salt);

    // Timing-safe comparison
    if (!timingSafeEqual(verifyHash, expectedVerifier)) {
      // SECURITY: Generic error message
      return {
        success: false,
        code: "WRONG_PASSPHRASE",
        error: "Clave maestra incorrecta",
      };
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
    STORAGE_KEYS.SCHEME,
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