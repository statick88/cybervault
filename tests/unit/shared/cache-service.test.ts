const store = new Map<string, string>();

jest.mock("ioredis", () => {
  const MockRedis = jest.fn().mockImplementation(() => ({
    status: "ready",
    get: jest.fn(async (key: string) => store.get(key) ?? null),
    set: jest.fn(async (key: string, val: string) => {
      store.set(key, val);
      return "OK";
    }),
    setex: jest.fn(async (key: string, _ttl: number, val: string) => {
      store.set(key, val);
      return "OK";
    }),
    del: jest.fn(async (...keys: string[]) => {
      let count = 0;
      for (const k of keys) {
        if (store.delete(k)) count++;
      }
      return count;
    }),
    exists: jest.fn(async (key: string) => (store.has(key) ? 1 : 0)),
    mget: jest.fn(async (...keys: string[]) =>
      keys.map((k) => store.get(k) ?? null),
    ),
    keys: jest.fn(async (pattern: string) => {
      const prefix = pattern.replace("*", "");
      return Array.from(store.keys()).filter((k) => k.startsWith(prefix));
    }),
    connect: jest.fn().mockResolvedValue(undefined),
    quit: jest.fn().mockResolvedValue("OK"),
    disconnect: jest.fn(),
    on: jest.fn(),
  }));
  return { __esModule: true, default: MockRedis };
});

import {
  connectRedis,
  disconnectRedis,
} from "../../../src/infrastructure/redis/redis-client";
import { CacheService } from "../../../src/infrastructure/redis/cache-service";

describe("CacheService", () => {
  let cache: CacheService;

  beforeEach(async () => {
    store.clear();
    process.env.REDIS_HOST = "localhost";
    await connectRedis();
    cache = new CacheService("test", 300);
  });

  afterEach(async () => {
    await disconnectRedis();
  });

  describe("get / set", () => {
    it("returns null for missing keys", async () => {
      const result = await cache.get("nonexistent");
      expect(result).toBeNull();
    });

    it("stores and retrieves JSON values", async () => {
      const data = { name: "test", count: 42 };
      await cache.set("key1", data);
      const result = await cache.get<typeof data>("key1");
      expect(result).toEqual(data);
    });

    it("sets with custom TTL", async () => {
      await cache.set("ttl-key", "value", 60);
      const result = await cache.get<string>("ttl-key");
      expect(result).toBe("value");
    });

    it("returns false when redis unavailable", async () => {
      await disconnectRedis();
      const result = await cache.set("key", "value");
      expect(result).toBe(false);
    });

    it("returns null when redis unavailable", async () => {
      await disconnectRedis();
      const result = await cache.get("key");
      expect(result).toBeNull();
    });
  });

  describe("setex", () => {
    it("stores value with TTL", async () => {
      await cache.setex("se-key", 120, { foo: "bar" });
      const result = await cache.get<{ foo: string }>("se-key");
      expect(result).toEqual({ foo: "bar" });
    });
  });

  describe("del", () => {
    it("deletes keys", async () => {
      await cache.set("a", 1);
      await cache.set("b", 2);
      const result = await cache.del("a", "b");
      expect(result).toBe(2);
      expect(await cache.get("a")).toBeNull();
      expect(await cache.get("b")).toBeNull();
    });

    it("returns 0 when redis unavailable", async () => {
      await disconnectRedis();
      const result = await cache.del("key");
      expect(result).toBe(0);
    });
  });

  describe("has", () => {
    it("returns true for existing keys", async () => {
      await cache.set("existing", "data");
      const result = await cache.has("existing");
      expect(result).toBe(true);
    });

    it("returns false for missing keys", async () => {
      const result = await cache.has("missing");
      expect(result).toBe(false);
    });
  });

  describe("mget", () => {
    it("returns multiple values", async () => {
      await cache.set("k1", "a");
      await cache.set("k3", "c");
      const results = await cache.mget<string>("k1", "k2", "k3");
      expect(results).toEqual(["a", null, "c"]);
    });

    it("returns all null when redis unavailable", async () => {
      await disconnectRedis();
      const results = await cache.mget<string>("k1", "k2");
      expect(results).toEqual([null, null]);
    });
  });

  describe("flush", () => {
    it("deletes all prefixed keys", async () => {
      await cache.set("a", 1);
      await cache.set("b", 2);
      const result = await cache.flush();
      expect(result).toBe(true);
      expect(await cache.get("a")).toBeNull();
      expect(await cache.get("b")).toBeNull();
    });
  });

  describe("key prefix namespacing", () => {
    it("prepends prefix to all keys", async () => {
      await cache.set("mykey", "myval");
      const result = await cache.get<string>("mykey");
      expect(result).toBe("myval");
    });
  });
});
