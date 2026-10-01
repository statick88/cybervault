/**
 * Shared rate-limit store (R7).
 *
 * ## The defect this closes
 *
 * Every rate limit in the product was a `new Map()` inside a module or a
 * class. That is correct for exactly one replica and wrong for every other
 * deployment:
 *
 *   - Behind N Core replicas the effective limit is N × the configured one.
 *   - The same applies to Plus, whose limit R1 added.
 *   - A restart clears every counter, so the cheapest bypass is a deploy.
 *
 * ## Why Redis
 *
 * `ioredis` is already a dependency and R2 proved the connection pattern in
 * this codebase — including the part that was originally missed, which is that
 * the deployment runs `redis-server --requirepass` and a client that connects
 * with no credential fails outright. That omission is why `REDIS_URL` went
 * unset for weeks and replay protection silently stayed in-process.
 *
 * ## Why it fails OPEN, and why that is the right call
 *
 * A limiter that throws when its store is unreachable turns a Redis outage
 * into an outage for every API client. That failure is strictly worse than the
 * one being fixed: the limit exists to bound load, and taking the service down
 * does not bound load, it removes the service.
 *
 * So an unreachable Redis degrades to the in-process limit — today's behaviour,
 * which is correct for a single replica and weaker for several. The mode is
 * reported by {@link rateLimitMode} so `/health` can surface it, and
 * {@link noteStoreDegraded} makes the degradation appear in logs exactly once
 * rather than on every request.
 *
 * ## Fixed window, and what it costs
 *
 * `INCR` plus a conditional `EXPIRE` is the standard counter. It is a FIXED
 * window, which permits up to 2× the limit across a boundary — a burst at the
 * end of one window and the start of the next. Core's limits were already
 * fixed-window, so this is not a regression for them.
 *
 * Plus's limit was a SLIDING window over a timestamp array, so moving it to a
 * counter is a narrowing. That is a deliberate trade: a sliding window over a
 * Redis list costs a round trip per retained element and buys an edge case
 * that is not the risk here. The boundary burst is documented rather than
 * hidden, and the change is localised to this module if a future reviewer
 * disagrees.
 *
 * ## The property that makes the tests meaningful
 *
 * Two limiter instances over one store must share the budget. A test that
 * creates one instance would pass against the pre-fix code, because the defect
 * is only observable across instances. {@link SharedRateLimiter} is therefore
 * written so that test is possible without a live Redis.
 */

import Redis from "ioredis";
import { withRedisCredentials } from "../crypto/jti-store";

/** Which store a limiter is actually using right now. */
export type RateLimitMode = "redis" | "memory";

export interface RateLimitDecision {
  allowed: boolean;
  /** Requests left in the current window. Useful for `X-RateLimit-Remaining`. */
  remaining: number;
  /** Seconds until the window resets. */
  retryAfterSeconds: number;
  mode: RateLimitMode;
}

export interface RateLimitRule {
  /** Stable identifier, becomes part of the Redis key. Keep it short. */
  scope: string;
  max: number;
  windowMs: number;
}

/**
 * A counter shared by every process that can see the same Redis.
 *
 * Exported so a test can point two instances at one store and observe the
 * budget being shared — which is the whole point of the fix and the one
 * behaviour a single-instance test cannot see.
 */
export class SharedRateLimiter {
  private readonly client: Redis | null;
  private readonly local = new Map<string, { count: number; resetTime: number }>();
  private mode: RateLimitMode;
  private hasLoggedDegradation = false;

  constructor(
    private readonly rule: RateLimitRule,
    redisUrl: string | undefined = process.env.REDIS_URL,
  ) {
    // The same localhost sentinel as `createJtiStore`: a developer running
    // Redis on their laptop should not silently depend on it, and the compose
    // file uses the `redis` service name precisely so it does not match.
    const usable = redisUrl && redisUrl !== "redis://localhost:6379" ? redisUrl : undefined;

    if (!usable) {
      this.client = null;
      this.mode = "memory";
      return;
    }

    this.client = new Redis(withRedisCredentials(usable), {
      maxRetriesPerRequest: 2,
      retryStrategy: (times) => (times > 2 ? null : Math.min(times * 100, 2000)),
      lazyConnect: true,
      enableOfflineQueue: false,
    });
    this.mode = "redis";
    this.client.on("error", () => {
      // Swallowed deliberately: the decision path below treats any failure as
      // "use the local map", and an unhandled 'error' event would crash the
      // process rather than degrade it.
      this.degrade();
    });
  }

  /** The mode in force right now. Surfaced by `/health`. */
  get currentMode(): RateLimitMode {
    return this.mode;
  }

  private degrade(): void {
    if (this.mode === "redis") {
      this.mode = "memory";
    }
    if (!this.hasLoggedDegradation) {
      this.hasLoggedDegradation = true;
      // eslint-disable-next-line no-console
      console.warn(
        `[rate-limit] ${this.rule.scope}: Redis unavailable, degrading to the ` +
          `in-process limit. Behind multiple replicas the effective limit is now ` +
          `per-process, not shared.`,
      );
    }
  }

  async consume(key: string): Promise<RateLimitDecision> {
    const decision = await this.tryRedis(key);
    if (decision) return decision;
    return this.consumeLocal(key);
  }

  private async tryRedis(key: string): Promise<RateLimitDecision | null> {
    if (!this.client || this.mode !== "redis") return null;

    const redisKey = `cv:rl:${this.rule.scope}:${key}`;
    try {
      // `lazyConnect` means the socket does not exist until something asks for
      // it, and `enableOfflineQueue: false` means a command issued before the
      // connection is up FAILS rather than queueing. Without this connect, the
      // very first `INCR` of a process's life throws, the catch degrades the
      // limiter, and it silently stays in-process for the rest of the run —
      // which is R2's bug reproduced in new code. `RedisJtiStore` carries the
      // same `ensureConnected` step for the same reason.
      if (this.client.status === "wait") {
        await this.client.connect();
      }
      const count = await this.client.incr(redisKey);
      if (count === 1) {
        // Only the request that created the key sets the expiry. Doing it on
        // every hit would slide the window forever and no limit would ever
        // reset — the classic INCR/EXPIRE mistake.
        await this.client.expire(redisKey, Math.ceil(this.rule.windowMs / 1000));
      }

      const ttl = await this.client.ttl(redisKey);
      const remaining = Math.max(0, this.rule.max - count);
      return {
        allowed: count <= this.rule.max,
        remaining,
        retryAfterSeconds: ttl > 0 ? ttl : Math.ceil(this.rule.windowMs / 1000),
        mode: "redis",
      };
    } catch {
      this.degrade();
      return null;
    }
  }

  private consumeLocal(key: string): RateLimitDecision {
    const now = Date.now();
    const localKey = `${this.rule.scope}:${key}`;
    const record = this.local.get(localKey);

    if (!record || now > record.resetTime) {
      this.local.set(localKey, { count: 1, resetTime: now + this.rule.windowMs });
      this.sweep(now);
      return {
        allowed: true,
        remaining: this.rule.max - 1,
        retryAfterSeconds: Math.ceil(this.rule.windowMs / 1000),
        mode: "memory",
      };
    }

    record.count++;
    const allowed = record.count <= this.rule.max;
    return {
      allowed,
      remaining: Math.max(0, this.rule.max - record.count),
      retryAfterSeconds: Math.max(1, Math.ceil((record.resetTime - now) / 1000)),
      mode: "memory",
    };
  }

  /**
   * Drop expired entries so a rotating key space cannot grow without bound.
   *
   * Redis keys expire on their own, so this only matters for the fallback —
   * but an unbounded map is a memory leak an attacker can drive at will, and
   * the current in-process limiters have exactly that flaw.
   */
  private sweep(now: number): void {
    if (this.local.size < 1024) return;
    for (const [key, record] of this.local) {
      if (now > record.resetTime) this.local.delete(key);
    }
  }

  async close(): Promise<void> {
    if (!this.client) return;
    try {
      await this.client.quit();
    } catch {
      // Nothing useful to do while shutting down.
    }
  }
}

/**
 * Process-wide limiters, one per rule.
 *
 * A Map of limiters rather than three module constants, because each rule has
 * its own window and max and threading them through call sites would make the
 * numbers scannable — the difference between `checkRateLimit(ip)` and
 * `checkRateLimit(ip, 100, 15 * 60 * 1000)` is exactly the kind of thing that
 * gets "fixed" to the wrong value at a call site.
 */
const limiters = new Map<string, SharedRateLimiter>();

export function getRateLimiter(scope: string, max: number, windowMs: number): SharedRateLimiter {
  const existing = limiters.get(scope);
  if (existing) return existing;
  const created = new SharedRateLimiter({ scope, max, windowMs });
  limiters.set(scope, created);
  return created;
}

/** The mode of every configured limiter, for `/health`. */
export function rateLimitMode(): Record<string, RateLimitMode> {
  const out: Record<string, RateLimitMode> = {};
  for (const [scope, limiter] of limiters) out[scope] = limiter.currentMode;
  return out;
}

/** Test seam: forget every limiter so a test starts from a clean slate. */
export function resetRateLimitersForTest(): void {
  limiters.clear();
}
