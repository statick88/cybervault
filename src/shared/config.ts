/**
 * CyberVault Configuration
 *
 * All configuration should be externalized via environment variables.
 * This file provides defaults for development only.
 *
 * Usage:
 *   import { Config } from './shared/config';
 *   const port = Config.api.port;
 */

// Helper to get env with default
function env(key: string, defaultValue: string): string {
  return process.env[key] || defaultValue;
}

function envInt(key: string, defaultValue: string): number {
  return parseInt(process.env[key] || defaultValue, 10);
}

function envBool(key: string, defaultValue: boolean): boolean {
  const val = process.env[key];
  if (val === undefined) return defaultValue;
  return val === "true";
}

// ============================================================================
// API Server
// ============================================================================
export const API_CONFIG = {
  port: envInt("PORT", "3000"),
  env: env("NODE_ENV", "development"),
  baseUrl: env("API_BASE_URL", "http://localhost:3000"),
};

// ============================================================================
// Security
// ============================================================================
export const SECURITY_CONFIG = {
  jwtSecret: env("JWT_SECRET", "dev-only-change-in-production"),
  jwtExpiry: env("JWT_EXPIRY", "24h"),
  sessionTimeoutMinutes: envInt("SESSION_TIMEOUT_MINUTES", "15"),
  rateLimitMaxRequests: envInt("RATE_LIMIT_MAX_REQUESTS", "100"),
  rateLimitWindowMs: envInt("RATE_LIMIT_WINDOW_MS", "60000"),
  masterKey: process.env.VAULT_MASTER_KEY,
  encryptionSalt: process.env.VAULT_ENCRYPTION_SALT,
};

// ============================================================================
// Database
// ============================================================================
export const DATABASE_CONFIG = {
  url: env("DATABASE_URL", "sqlite://cybervault.db"),
  host: env("DB_HOST", "localhost"),
  port: envInt("DB_PORT", "5432"),
  name: env("DB_NAME", "cybervault"),
  user: env("DB_USER", "cybervault"),
  password: process.env.DB_PASSWORD,
};

// ============================================================================
// Redis
// ============================================================================
export const REDIS_CONFIG = {
  host: env("REDIS_HOST", "localhost"),
  port: envInt("REDIS_PORT", "6379"),
  password: process.env.REDIS_PASSWORD,
  db: envInt("REDIS_DB", "0"),
};

// ============================================================================
// IPFS (Optional)
// ============================================================================
export const IPFS_CONFIG = {
  enabled: envBool("IPFS_ENABLED", false),
  host: env("IPFS_HOST", "localhost"),
  port: envInt("IPFS_PORT", "5001"),
  protocol: env("IPFS_PROTOCOL", "http"),
  apiKey: process.env.IPFS_API_KEY,
  peerId: process.env.IPFS_PEER_ID,
};

// ============================================================================
// External APIs
// ============================================================================
export const EXTERNAL_APIS_CONFIG = {
  pwnedPasswordsUrl: env("PWNED_URL", "https://api.pwnedpasswords.com"),
  alienVaultUrl: env("ALIENVAULT_URL", "https://otx.alienvault.com"),
  alienVaultApiKey: process.env.ALIENVAULT_API_KEY,
  githubApiUrl: env("GITHUB_API_URL", "https://api.github.com"),
  githubToken: process.env.GITHUB_TOKEN,
};

// ============================================================================
// Logging
// ============================================================================
export const LOGGING_CONFIG = {
  level: env("LOG_LEVEL", "info"),
  format: env("LOG_FORMAT", "json"),
};

// ============================================================================
// Features (Feature Flags)
// ============================================================================
export const FEATURES_CONFIG = {
  breachScanning: envBool("FEATURE_BREACH_SCANNING", true),
  threatIntel: envBool("FEATURE_THREAT_INTEL", true),
  ipfsSync: envBool("FEATURE_IPFS_SYNC", false),
  biometricUnlock: envBool("FEATURE_BIOMETRIC", false),
};

// ============================================================================
// Consolidated Config Object
// ============================================================================
export const Config = {
  api: API_CONFIG,
  security: SECURITY_CONFIG,
  database: DATABASE_CONFIG,
  redis: REDIS_CONFIG,
  ipfs: IPFS_CONFIG,
  externalApis: EXTERNAL_APIS_CONFIG,
  logging: LOGGING_CONFIG,
  features: FEATURES_CONFIG,
};

// ============================================================================
// Validation
// ============================================================================
export function validateConfig(): void {
  const errors: string[] = [];

  // Production validations
  if (process.env.NODE_ENV === "production") {
    if (!process.env.JWT_SECRET) {
      errors.push("JWT_SECRET is required in production");
    }
    if (!process.env.VAULT_MASTER_KEY) {
      errors.push("VAULT_MASTER_KEY is required in production");
    }
    if (!process.env.VAULT_ENCRYPTION_SALT) {
      errors.push("VAULT_ENCRYPTION_SALT is required in production");
    }
    if (
      !process.env.DB_PASSWORD &&
      !process.env.DATABASE_URL?.startsWith("sqlite")
    ) {
      errors.push("DB_PASSWORD is required in production");
    }

    // Warn about weak JWT secret
    if (process.env.JWT_SECRET && process.env.JWT_SECRET.length < 32) {
      errors.push("JWT_SECRET must be at least 32 characters in production");
    }
    // Reject default JWT secret value in production
    if (process.env.JWT_SECRET === "dev-only-change-in-production") {
      errors.push("JWT_SECRET must NOT be the default value in production");
    }
  }

  if (errors.length > 0) {
    throw new Error(`Configuration validation failed:\n${errors.join("\n")}`);
  }
}

// Validate on import in production
if (process.env.NODE_ENV === "production") {
  validateConfig();
}
