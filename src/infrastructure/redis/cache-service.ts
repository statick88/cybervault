import { getRedisClient } from "./redis-client";
import { logger } from "../../shared/logger";

const DEFAULT_TTL = 300; // 5 minutes
const DEFAULT_PREFIX = "cybervault";

export class CacheService {
  private prefix: string;
  private defaultTtl: number;

  constructor(prefix = DEFAULT_PREFIX, defaultTtl = DEFAULT_TTL) {
    this.prefix = prefix;
    this.defaultTtl = defaultTtl;
  }

  private buildKey(key: string): string {
    return `${this.prefix}:${key}`;
  }

  private getClient() {
    const client = getRedisClient();
    if (!client) return null;
    return client;
  }

  async get<T>(key: string): Promise<T | null> {
    const client = this.getClient();
    if (!client) return null;

    try {
      const data = await client.get(this.buildKey(key));
      if (data === null) return null;
      return JSON.parse(data) as T;
    } catch (err) {
      logger.error(
        "Cache get error",
        "CacheService",
        { key },
        err instanceof Error ? err.message : String(err),
      );
      return null;
    }
  }

  async set<T>(key: string, value: T, ttl?: number): Promise<boolean> {
    const client = this.getClient();
    if (!client) return false;

    try {
      const serialized = JSON.stringify(value);
      if (ttl !== undefined) {
        await client.setex(this.buildKey(key), ttl, serialized);
      } else {
        await client.setex(this.buildKey(key), this.defaultTtl, serialized);
      }
      return true;
    } catch (err) {
      logger.error(
        "Cache set error",
        "CacheService",
        { key },
        err instanceof Error ? err.message : String(err),
      );
      return false;
    }
  }

  async setex(key: string, ttl: number, value: unknown): Promise<boolean> {
    const client = this.getClient();
    if (!client) return false;

    try {
      const serialized = JSON.stringify(value);
      await client.setex(this.buildKey(key), ttl, serialized);
      return true;
    } catch (err) {
      logger.error(
        "Cache setex error",
        "CacheService",
        { key },
        err instanceof Error ? err.message : String(err),
      );
      return false;
    }
  }

  async del(...keys: string[]): Promise<number> {
    const client = this.getClient();
    if (!client) return 0;

    try {
      const prefixedKeys = keys.map((k) => this.buildKey(k));
      return await client.del(...prefixedKeys);
    } catch (err) {
      logger.error(
        "Cache del error",
        "CacheService",
        { keys },
        err instanceof Error ? err.message : String(err),
      );
      return 0;
    }
  }

  async has(key: string): Promise<boolean> {
    const client = this.getClient();
    if (!client) return false;

    try {
      const exists = await client.exists(this.buildKey(key));
      return exists === 1;
    } catch (err) {
      logger.error(
        "Cache has error",
        "CacheService",
        { key },
        err instanceof Error ? err.message : String(err),
      );
      return false;
    }
  }

  async mget<T>(...keys: string[]): Promise<(T | null)[]> {
    const client = this.getClient();
    if (!client) return keys.map(() => null);

    try {
      const prefixedKeys = keys.map((k) => this.buildKey(k));
      const results = await client.mget(...prefixedKeys);
      return results.map((data) => {
        if (data === null) return null;
        try {
          return JSON.parse(data) as T;
        } catch {
          return null;
        }
      });
    } catch (err) {
      logger.error(
        "Cache mget error",
        "CacheService",
        { keys },
        err instanceof Error ? err.message : String(err),
      );
      return keys.map(() => null);
    }
  }

  async flush(): Promise<boolean> {
    const client = this.getClient();
    if (!client) return false;

    try {
      const keys = await client.keys(`${this.prefix}:*`);
      if (keys.length > 0) {
        await client.del(...keys);
      }
      return true;
    } catch (err) {
      logger.error(
        "Cache flush error",
        "CacheService",
        {},
        err instanceof Error ? err.message : String(err),
      );
      return false;
    }
  }
}

export const vaultCache = new CacheService("cybervault:vaults", 600);
export const sessionCache = new CacheService("cybervault:sessions", 1800);
