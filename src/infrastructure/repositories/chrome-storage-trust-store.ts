/**
 * Chrome Storage Trust Store — ITrustStoreRepository implementation
 *
 * Persists domain trust decisions in chrome.storage.local.
 * Known fingerprints are stored in chrome.storage.session
 * to survive service worker restarts within a session.
 *
 * @module infrastructure/repositories/chrome-storage-trust-store
 */

import type {
  ITrustStoreRepository,
  TrustEntry,
} from "../../domain/repositories";
import { dnsNormalize } from "../../domain/utils/dns-normalize";

/** Storage key for trust entries array */
const TRUST_STORE_KEY = "cybervault_trust_store";

/** Storage key prefix for fingerprints (session storage) */
const FINGERPRINT_KEY_PREFIX = "cybervault_fp_";

/** Maximum number of entries allowed in the trust store */
const MAX_TRUST_STORE_ENTRIES = 10_000;

/**
 * Validates a domain name for safety.
 * Rejects domains containing characters that could be used for injection.
 * Only allows: alphanumeric, hyphen, dot (for subdomains).
 * Must not start or end with hyphen or dot.
 */
function validateDomain(domain: string): string {
  // First, check raw input for dangerous characters that normalization might hide
  // Control characters (ASCII 0-31, 127)
  if (/[\x00-\x1F\x7F]/.test(domain)) {
    throw new Error("Invalid domain: contains control characters");
  }

  // Check for HTML/script injection attempts in raw input
  if (/[<>"'&]/.test(domain)) {
    throw new Error("Invalid domain: contains dangerous characters");
  }

  // Check for null bytes
  if (domain.includes("\0")) {
    throw new Error("Invalid domain: contains null byte");
  }

  const normalized = dnsNormalize(domain);

  // Check for empty after normalization
  if (!normalized) {
    throw new Error("Invalid domain: empty after normalization");
  }

  // Check for invalid characters (only alphanumeric, hyphen, dot allowed)
  // This regex allows: a-z, 0-9, hyphen, dot
  if (!/^[a-z0-9.-]+$/.test(normalized)) {
    throw new Error("Invalid domain: contains invalid characters");
  }

  // Check for leading/trailing hyphen or dot
  if (normalized.startsWith("-") || normalized.startsWith(".") ||
      normalized.endsWith("-") || normalized.endsWith(".")) {
    throw new Error("Invalid domain: cannot start or end with hyphen or dot");
  }

  // Check for consecutive dots (invalid in domain names)
  if (normalized.includes("..")) {
    throw new Error("Invalid domain: consecutive dots not allowed");
  }

  // Check each label (part between dots) for validity
  const labels = normalized.split(".");
  for (const label of labels) {
    if (label.length === 0) {
      throw new Error("Invalid domain: empty label");
    }
    if (label.length > 63) {
      throw new Error("Invalid domain: label too long (max 63 chars)");
    }
    // Label cannot start or end with hyphen
    if (label.startsWith("-") || label.endsWith("-")) {
      throw new Error("Invalid domain: label cannot start or end with hyphen");
    }
  }

  return normalized;
}

/**
 * Chrome Storage Trust Store Implementation.
 */
export class ChromeStorageTrustStore implements ITrustStoreRepository {
  async save(entry: TrustEntry): Promise<void> {
    const store = await this.getAll();

    // Validate and normalize domain
    const domain = validateDomain(entry.domain);

    const existing = store.find((e) => e.domain === domain);
    const now = Date.now();

    if (existing) {
      // Update existing entry
      existing.trustLevel = entry.trustLevel;
      existing.lastSeen = now;
      existing.visitCount += 1;
      if (entry.fingerprint) {
        existing.fingerprint = entry.fingerprint;
      }
    } else {
      // Check max entries limit before adding new entry
      if (store.length >= MAX_TRUST_STORE_ENTRIES) {
        throw new Error("Trust store limit exceeded");
      }

      store.push({
        domain,
        trustLevel: entry.trustLevel,
        firstSeen: entry.firstSeen ?? now,
        lastSeen: now,
        fingerprint: entry.fingerprint,
        visitCount: 1,
      });
    }

    await chrome.storage.local.set({ [TRUST_STORE_KEY]: store });
  }

  async findByDomain(domain: string): Promise<TrustEntry | null> {
    const store = await this.getAll();
    const normalized = dnsNormalize(domain);
    return store.find((e) => e.domain === normalized) ?? null;
  }

  async revoke(domain: string): Promise<void> {
    const store = await this.getAll();
    const normalized = dnsNormalize(domain);
    const filtered = store.filter((e) => e.domain !== normalized);
    await chrome.storage.local.set({ [TRUST_STORE_KEY]: filtered });
  }

  async list(): Promise<TrustEntry[]> {
    return this.getAll();
  }

  async removeExpired(maxAgeMs: number): Promise<number> {
    const store = await this.getAll();
    const now = Date.now();
    const before = store.length;
    const filtered = store.filter((e) => now - e.lastSeen < maxAgeMs);
    await chrome.storage.local.set({ [TRUST_STORE_KEY]: filtered });
    return before - filtered.length;
  }

  /**
   * Persist a DOM fingerprint for a domain (session storage).
   * Survives service worker restarts during a browser session.
   */
  async saveFingerprint(domain: string, fingerprint: string): Promise<void> {
    const normalized = validateDomain(domain);
    const key = `${FINGERPRINT_KEY_PREFIX}${normalized}`;
    await chrome.storage.session.set({ [key]: { fingerprint, timestamp: Date.now() } });
  }

  /**
   * Get stored fingerprint for a domain.
   */
  async getFingerprint(domain: string): Promise<string | null> {
    const normalized = dnsNormalize(domain);
    const key = `${FINGERPRINT_KEY_PREFIX}${normalized}`;
    const result = await chrome.storage.session.get(key);
    const stored = result[key];
    if (stored && typeof stored === "object" && "fingerprint" in stored) {
      return (stored as { fingerprint: string }).fingerprint;
    }
    return null;
  }

  /**
   * Remove stored fingerprint for a domain.
   */
  async removeFingerprint(domain: string): Promise<void> {
    const normalized = dnsNormalize(domain);
    const key = `${FINGERPRINT_KEY_PREFIX}${normalized}`;
    await chrome.storage.session.remove(key);
  }

  private async getAll(): Promise<TrustEntry[]> {
    const result = await chrome.storage.local.get(TRUST_STORE_KEY);
    const entries = result[TRUST_STORE_KEY];
    if (!Array.isArray(entries)) return [];
    return entries;
  }
}