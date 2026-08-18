jest.mock("ioredis", () => {
  const MockRedis = jest.fn().mockImplementation(() => ({
    status: "ready",
    get: jest.fn(),
    set: jest.fn(),
    setex: jest.fn(),
    del: jest.fn(),
    exists: jest.fn(),
    mget: jest.fn(),
    keys: jest.fn(),
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
  getRedisClient,
  isRedisConnected,
} from "../../../src/infrastructure/redis/redis-client";

describe("RedisClient", () => {
  afterEach(async () => {
    await disconnectRedis();
  });

  it("returns null client when REDIS_HOST is not set", async () => {
    const original = process.env.REDIS_HOST;
    delete process.env.REDIS_HOST;
    await connectRedis();
    expect(getRedisClient()).toBeNull();
    if (original) process.env.REDIS_HOST = original;
  });

  it("returns null when not connected", () => {
    expect(getRedisClient()).toBeNull();
    expect(isRedisConnected()).toBe(false);
  });

  it("connects when REDIS_HOST is set", async () => {
    process.env.REDIS_HOST = "localhost";
    await connectRedis();
    expect(getRedisClient()).not.toBeNull();
    expect(isRedisConnected()).toBe(true);
  });

  it("disconnects gracefully", async () => {
    process.env.REDIS_HOST = "localhost";
    await connectRedis();
    await disconnectRedis();
    expect(getRedisClient()).toBeNull();
  });

  it("does not throw on disconnect when no client", async () => {
    await expect(disconnectRedis()).resolves.toBeUndefined();
  });
});
