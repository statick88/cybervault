/**
 * Argon2id KDF — Memory-Hard Key Derivation Function
 *
 * Provides memory-hard key derivation using Argon2id (via hash-wasm WASM).
 * Falls back to PBKDF2-SHA512 when WASM is unavailable.
 *
 * @module infrastructure/crypto/argon2-kdf
 */

import { argon2id } from "hash-wasm";
import { pbkdf2 } from "@noble/hashes/pbkdf2.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { secureZero } from "./secure-memory";

/** Argon2id configuration parameters (hash-wasm v4 API) */
export interface Argon2Config {
  /** Memory size in KB (default: 65536 KB = 64 MB) */
  memorySize: number;
  /** Time cost/iterations (default: 3) */
  iterations: number;
  /** Parallelism factor (default: 4) */
  parallelism: number;
  /** Output hash length in bytes (default: 32) */
  hashLength: number;
}

/** Default Argon2id configuration */
export const DEFAULT_ARGON2_CONFIG: Argon2Config = {
  memorySize: 65536,
  iterations: 3,
  parallelism: 4,
  hashLength: 32,
};

/** PBKDF2 fallback configuration */
export const DEFAULT_PBKDF2_CONFIG = {
  iterations: 600000,
  hashLength: 32,
};

/** Result of key derivation */
export interface KDFResult {
  /** Derived key */
  key: Uint8Array;
  /** Algorithm used */
  algorithm: "argon2id" | "pbkdf2-fallback";
  /** Time taken in milliseconds */
  timeMs: number;
  /** Memory used in KB (Argon2id only) */
  memoryUsedKb?: number;
  /** Parameters used */
  params: Argon2Config | typeof DEFAULT_PBKDF2_CONFIG;
}

/** Maximum concurrent Argon2id derivations to prevent memory exhaustion */
const MAX_CONCURRENT_DERIVATIONS = 3;
let activeDerivations = 0;

/** Check if Argon2id WASM is available */
let wasmAvailable = false;

export async function initializeArgon2(): Promise<void> {
  if (wasmAvailable) return;
  try {
    // hash-wasm v4: argon2id is a function, not a class with createArgon2id
    // Use minimal valid params for initialization test
    await argon2id({
      password: new Uint8Array([1,2,3,4,5,6,7,8]),
      salt: new Uint8Array(16).fill(1),
      memorySize: 65536,
      iterations: 1,
      parallelism: 1,
      hashLength: 32,
    });
    wasmAvailable = true;
  } catch {
    wasmAvailable = false;
  }
}

export function isArgon2Available(): boolean {
  return wasmAvailable;
}

/**
 * Derive key using Argon2id (memory-hard KDF)
 */
export async function deriveWithArgon2(
  password: Uint8Array,
  salt: Uint8Array,
  config: Argon2Config = DEFAULT_ARGON2_CONFIG,
): Promise<KDFResult> {
  if (!wasmAvailable) {
    throw new Error("Argon2id not initialized. Call initializeArgon2() first.");
  }

  // Concurrency control
  while (activeDerivations >= MAX_CONCURRENT_DERIVATIONS) {
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  activeDerivations++;

  const startTime = performance.now();

  try {
    // hash-wasm v4: argon2id returns hex string
    const hashHex = await argon2id({
      password,
      salt,
      memorySize: config.memorySize,
      iterations: config.iterations,
      parallelism: config.parallelism,
      hashLength: config.hashLength,
    });

    const timeMs = performance.now() - startTime;

    // Convert hex string to Uint8Array
    const key = new Uint8Array(hashHex.length / 2);
    for (let i = 0; i < hashHex.length; i += 2) {
      key[i / 2] = parseInt(hashHex.slice(i, i + 2), 16);
    }

    return {
      key,
      algorithm: "argon2id",
      timeMs,
      memoryUsedKb: config.memorySize,
      params: { ...config },
    };
  } finally {
    activeDerivations--;
  }
}

/**
 * Derive key using PBKDF2-SHA512 (fallback)
 */
export async function deriveWithPBKDF2(
  password: Uint8Array,
  salt: Uint8Array,
  config: typeof DEFAULT_PBKDF2_CONFIG = DEFAULT_PBKDF2_CONFIG,
): Promise<KDFResult> {
  const startTime = performance.now();

  const key = pbkdf2(sha512, password, salt, {
    c: config.iterations,
    dkLen: config.hashLength,
  });

  const timeMs = performance.now() - startTime;

  return {
    key: new Uint8Array(key),
    algorithm: "pbkdf2-fallback",
    timeMs,
    params: { ...config },
  };
}

/**
 * Main key derivation function with automatic fallback
 */
export async function deriveKey(
  password: string | Uint8Array,
  salt: string | Uint8Array,
  config?: Partial<Argon2Config>,
): Promise<KDFResult> {
  // Normalize inputs
  const passwordBytes =
    typeof password === "string" ? new TextEncoder().encode(password) : password;
  const saltBytes =
    typeof salt === "string" ? new TextEncoder().encode(salt) : salt;

  // Validate parameters
  const finalConfig = { ...DEFAULT_ARGON2_CONFIG, ...config };
  if (finalConfig.memorySize < 65536) {
    throw new Error("memorySize must be >= 65536 KB");
  }
  if (finalConfig.iterations < 1) {
    throw new Error("iterations must be >= 1");
  }
  if (finalConfig.parallelism < 1) {
    throw new Error("parallelism must be >= 1");
  }

  // Initialize Argon2 if not already done
  await initializeArgon2();

  let result: KDFResult;

  if (wasmAvailable) {
    try {
      result = await deriveWithArgon2(passwordBytes, saltBytes, finalConfig);
    } catch (err) {
      console.warn("[Argon2KDF] Argon2id failed, falling back to PBKDF2-SHA512:", err instanceof Error ? err.message : err);
      result = await deriveWithPBKDF2(passwordBytes, saltBytes);
    }
  } else {
    console.warn("[Argon2KDF] Argon2id WASM unavailable, using PBKDF2-SHA512 fallback");
    result = await deriveWithPBKDF2(passwordBytes, saltBytes);
  }

  // Securely wipe password from memory
  if (typeof password === "object") {
    secureZero(passwordBytes);
  }
  if (typeof salt === "object") {
    secureZero(saltBytes);
  }

  return result;
}

/**
 * Derive key using PBKDF2 only (for compatibility with existing vaults)
 */
export async function deriveKeyPBKDF2Only(
  password: string | Uint8Array,
  salt: string | Uint8Array,
  iterations: number = 600000,
  hashLength: number = 32,
): Promise<Uint8Array> {
  const passwordBytes =
    typeof password === "string" ? new TextEncoder().encode(password) : password;
  const saltBytes =
    typeof salt === "string" ? new TextEncoder().encode(salt) : salt;

  const key = pbkdf2(sha512, passwordBytes, saltBytes, {
    c: iterations,
    dkLen: hashLength,
  });

  secureZero(passwordBytes);
  secureZero(saltBytes);

  return new Uint8Array(key);
}

/**
 * Migration helper: re-derive key with Argon2id and re-encrypt vault
 */
export async function migrateVaultToArgon2(
  password: string,
  oldSalt: Uint8Array,
  oldEncryptedVault: Uint8Array,
  newSalt: Uint8Array,
): Promise<{ newKey: Uint8Array; reEncryptedVault: Uint8Array }> {
  // Derive old key with PBKDF2 (for decryption)
  await deriveKeyPBKDF2Only(password, oldSalt);

  // Decrypt old vault (assuming AES-GCM)
  // This would use the existing encryption service
  // For now, return the new Argon2id-derived key
  const result = await deriveKey(password, newSalt);

  // In a real implementation, you would:
  // 1. Decrypt oldEncryptedVault with oldKey
  // 2. Re-encrypt with result.key
  // 3. Return both newKey and reEncryptedVault

  return {
    newKey: result.key,
    reEncryptedVault: oldEncryptedVault, // Placeholder
  };
}