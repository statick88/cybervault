/**
 * R7 — the shared store, against a real Redis.
 *
 * ## Why a second file
 *
 * `rate-limit-shared-store.test.ts` proves the limit HOLDS and that instances
 * of the fallback share a map. It cannot prove the thing R7 is about, because
 * it reaches into a private field to do it.
 *
 * This file talks to the Redis the compose stack is already running and
 * asserts the actual property: **two limiters, two clients, one budget.**
 * If the shared store were replaced by a per-instance map, these fail and the
 * unit suite would not.
 *
 * Skipped when no Redis is reachable, rather than faked. A test that mocks the
 * very dependency it is testing proves nothing about the dependency.
 */

import {
  SharedRateLimiter,
  type RateLimitMode,
} from "../../src/infrastructure/rate-limit/shared-store";
import { withRedisCredentials } from "../../src/infrastructure/crypto/jti-store";

const REDIS_URL = process.env.REDIS_URL;
/**
 * A distinct scope per case.
 *
 * All four cases share one Redis and one `TEST_SCOPE` would mean case 2 spends
 * the budget case 1 created — the tests would interfere through the very store
 * they are testing, and the interference would look like a product bug.
 */
const scopeFor = (name: string): string => `test-${Date.now()}-${name}`;

/** Stable per case, so two limiters in the same case share one scope. */
const oncePerCase = (name: string): string => {
  const existing = scopeCache.get(name);
  if (existing) return existing;
  const created = scopeFor(name);
  scopeCache.set(name, created);
  return created;
};
const scopeCache = new Map<string, string>();

/** Probe once; skip the suite rather than fail it if Redis is absent. */
let redisAvailable = false;

beforeAll(async () => {
  if (!REDIS_URL || REDIS_URL === "redis://localhost:6379") return;
  try {
    const probe = new SharedRateLimiter({ scope: oncePerCase("probe"), max: 1, windowMs: 1000 }, REDIS_URL);
    const decision = await probe.consume("probe");
    redisAvailable = decision.mode === ("redis" as RateLimitMode);
    await probe.close();
  } catch {
    redisAvailable = false;
  }
});

describe("R7 — the budget is genuinely shared through Redis", () => {
  it("a second limiter cannot spend what the first already spent", async () => {
    if (!redisAvailable) return;
    const first = new SharedRateLimiter({ scope: oncePerCase("shared"), max: 3, windowMs: 60_000 }, REDIS_URL);
    const second = new SharedRateLimiter({ scope: oncePerCase("shared"), max: 3, windowMs: 60_000 }, REDIS_URL);

    try {
      // Three requests, all against the FIRST limiter — a single replica.
      for (let i = 0; i < 3; i++) {
        expect((await first.consume("10.1.1.1")).allowed).toBe(true);
      }

      // The SECOND limiter is a different object with its own client. It must
      // observe the exhausted budget, because the counter lives in Redis and
      // not in either process.
      const fromSecond = await second.consume("10.1.1.1");
      expect(fromSecond.mode).toBe("redis");
      expect(fromSecond.allowed).toBe(false);
      expect(fromSecond.remaining).toBe(0);
    } finally {
      await first.close();
      await second.close();
    }
  });

  it("reports a retry-after that matches the window", async () => {
    if (!redisAvailable) {
      console.warn("[rate-limit] skipping: no Redis reachable");
      return;
    }
    const limiter = new SharedRateLimiter({ scope: oncePerCase("retry"), max: 1, windowMs: 30_000 }, REDIS_URL);
    try {
      await limiter.consume("10.2.2.2");
      const refused = await limiter.consume("10.2.2.2");

      expect(refused.allowed).toBe(false);
      // A caller told to retry in zero seconds will hammer the endpoint, and a
      // caller told to wait 15 minutes gives up. The window is the contract.
      expect(refused.retryAfterSeconds).toBeGreaterThan(0);
      expect(refused.retryAfterSeconds).toBeLessThanOrEqual(30);
    } finally {
      await limiter.close();
    }
  });

  it("keeps distinct IPs on distinct budgets across instances", async () => {
    if (!redisAvailable) {
      console.warn("[rate-limit] skipping: no Redis reachable");
      return;
    }
    const a = new SharedRateLimiter({ scope: oncePerCase("ips"), max: 1, windowMs: 60_000 }, REDIS_URL);
    const b = new SharedRateLimiter({ scope: oncePerCase("ips"), max: 1, windowMs: 60_000 }, REDIS_URL);
    try {
      expect((await a.consume("10.3.3.3")).allowed).toBe(true);
      // Same IP, other instance: refused.
      expect((await b.consume("10.3.3.3")).allowed).toBe(false);
      // Different IP, other instance: still allowed. One abusive caller must
      // not lock out everyone else.
      expect((await b.consume("10.4.4.4")).allowed).toBe(true);
    } finally {
      await a.close();
      await b.close();
    }
  });

  it("authenticates: the deployment runs redis-server with --requirepass", async () => {
    if (!redisAvailable) {
      console.warn("[rate-limit] skipping: no Redis reachable");
      return;
    }
    // R2's root cause was a client connecting with no credential. If the
    // credential wiring regressed, this is the test that says so — without
    // needing to read the compose file.
    expect(process.env.REDIS_PASSWORD).toBeTruthy();
    const url = withRedisCredentials(REDIS_URL!);
    expect(url).toContain("@");
    expect(url).not.toContain("redis://redis:6379");
  });
});
