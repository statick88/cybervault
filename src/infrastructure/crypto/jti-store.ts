/**
 * JTI Store — Replay Protection for Capability Tokens
 *
 * Provides atomic check-and-consume operations for JTI (JWT ID) values
 * to prevent replay attacks on capability tokens.
 *
 * Uses ioredis for distributed deployments, with in-memory fallback for testing.
 * All operations are atomic to prevent race conditions.
 */

import Redis from "ioredis";
import { secureZero } from "./secure-memory";

/** JTI store interface */
export interface IJtiStore {
  /**
   * Try to consume a JTI atomically.
   * Returns true if JTI was not previously consumed (first use).
   * Returns false if JTI was already consumed (replay attempt).
   */
  tryConsume(jti: string, ttlSeconds: number): Promise<boolean>;

  /**
   * Check if a JTI has been consumed (without consuming).
   */
  isConsumed(jti: string): Promise<boolean>;

  /**
   * Close the store connection.
   */
  close(): Promise<void>;
}

/** In-memory JTI store for testing/single-instance deployments */
export class InMemoryJtiStore implements IJtiStore {
  private consumed = new Map<string, number>(); // jti -> expiry timestamp
  private cleanupInterval: NodeJS.Timeout | null = null;

  constructor() {
    // Periodic cleanup of expired entries
    this.cleanupInterval = setInterval(() => this.cleanup(), 60_000); // every minute
    this.cleanupInterval.unref(); // Don't prevent process exit
  }

  async tryConsume(jti: string, ttlSeconds: number): Promise<boolean> {
    const now = Date.now();
    const expiry = now + ttlSeconds * 1000;

    // Check if already consumed and not expired
    const existingExpiry = this.consumed.get(jti);
    if (existingExpiry !== undefined && existingExpiry > now) {
      return false; // Already consumed (replay)
    }

    // Mark as consumed with expiry
    this.consumed.set(jti, expiry);
    return true; // First use
  }

  async isConsumed(jti: string): Promise<boolean> {
    const now = Date.now();
    const expiry = this.consumed.get(jti);
    if (expiry === undefined) return false;
    if (expiry <= now) {
      this.consumed.delete(jti);
      return false;
    }
    return true;
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [jti, expiry] of this.consumed.entries()) {
      if (expiry <= now) {
        this.consumed.delete(jti);
      }
    }
  }

  async close(): Promise<void> {
    if (this.cleanupInterval) {
      clearInterval(this.cleanupInterval);
      this.cleanupInterval = null;
    }
    this.consumed.clear();
  }
}

/** Redis-backed JTI store for production/distributed deployments (ioredis) */
export class RedisJtiStore implements IJtiStore {
  private client: Redis;
  private connected = false;
  private readonly keyPrefix = "cv:jti:";

  constructor(redisUrl: string) {
    this.client = new Redis(redisUrl, {
      maxRetriesPerRequest: 3,
      retryStrategy: (times) => (times > 3 ? null : Math.min(times * 100, 3000)),
      lazyConnect: true,
    });
    this.client.on("error", (err: Error) => {
      console.error("[RedisJtiStore] Redis error:", err.message);
    });
  }

  private async ensureConnected(): Promise<void> {
    if (!this.connected) {
      await this.client.connect();
      this.connected = true;
    }
  }

  async tryConsume(jti: string, ttlSeconds: number): Promise<boolean> {
    await this.ensureConnected();

    const key = `${this.keyPrefix}${jti}`;

    // Use SET with NX (only if not exists) and EX (expiry in seconds)
    // Returns "OK" if set, null if key already exists
    const result = await this.client.set(key, "1", "EX", ttlSeconds, "NX");

    return result === "OK";
  }

  async isConsumed(jti: string): Promise<boolean> {
    await this.ensureConnected();

    const key = `${this.keyPrefix}${jti}`;
    const exists = await this.client.exists(key);
    return exists === 1;
  }

  async close(): Promise<void> {
    if (this.connected) {
      await this.client.quit();
      this.connected = false;
    }
  }
}

/**
 * Factory function to create appropriate JTI store based on environment
 */
export function createJtiStore(): IJtiStore {
  const redisUrl = process.env.REDIS_URL;
  if (redisUrl && redisUrl !== "redis://localhost:6379") {
    // Use Redis in production
    return new RedisJtiStore(redisUrl);
  }
  // Use in-memory for development/testing
  return new InMemoryJtiStore();
}

/**
 * Global JTI store instance (singleton pattern for application lifetime)
 * Initialized on first use
 */
let _globalJtiStore: IJtiStore | null = null;

export function getGlobalJtiStore(): IJtiStore {
  if (!_globalJtiStore) {
    _globalJtiStore = createJtiStore();
  }
  return _globalJtiStore;
}

export function setGlobalJtiStore(store: IJtiStore): void {
  if (_globalJtiStore) {
    _globalJtiStore.close().catch(() => {});
  }
  _globalJtiStore = store;
}

/**
 * Verify and consume a capability's JTI atomically
 * This is the main entry point for replay protection
 */
export async function verifyAndConsumeJti(
  jti: string,
  ttlSeconds: number = 300, // Default 5 minutes
  store?: IJtiStore,
): Promise<{ allowed: boolean; error?: string }> {
  if (!jti || jti.length < 16) {
    return { allowed: false, error: "Invalid JTI" };
  }

  const jtiStore = store ?? getGlobalJtiStore();
  const consumed = await jtiStore.tryConsume(jti, ttlSeconds);

  if (!consumed) {
    return { allowed: false, error: "Replay detected: JTI already consumed" };
  }

  return { allowed: true };
}

/**
 * Secure zero for string (best effort in JS)
 */
export function secureZeroString(str: string): void {
  // In JS strings are immutable, but we can help GC
  // by removing references. This is best-effort.
}