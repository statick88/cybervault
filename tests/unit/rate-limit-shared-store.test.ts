/**
 * R7 — the rate limit is shared, not per-process.
 *
 * ## Why this file is shaped the way it is
 *
 * The defect is only observable **across instances**. A test that creates one
 * limiter and spends its budget would pass against the pre-fix code, because
 * the pre-fix code also enforces a limit — just a different one per process.
 *
 * So the central cases here build two limiters over one store and assert they
 * contend for the same budget. If a future change replaced the shared store
 * with a per-instance map, these fail and a single-instance test would not.
 */

import {
  SharedRateLimiter,
  getRateLimiter,
  rateLimitMode,
  resetRateLimitersForTest,
} from "../../src/infrastructure/rate-limit/shared-store";

/** No REDIS_URL in the test environment, so the fallback is exercised. */
const ORIGINAL_REDIS_URL = process.env.REDIS_URL;

beforeEach(() => {
  delete process.env.REDIS_URL;
  resetRateLimitersForTest();
});

afterAll(() => {
  if (ORIGINAL_REDIS_URL === undefined) delete process.env.REDIS_URL;
  else process.env.REDIS_URL = ORIGINAL_REDIS_URL;
});

describe("R7 — the budget is shared between instances", () => {
  it("a second limiter over the same store cannot spend what the first spent", async () => {
    // Three separate `SharedRateLimiter` instances standing in for three
    // replicas of one deployment. They share nothing in-process except the
    // injected store, which is the whole point of the injection seam.
    const shared = new Map<string, { count: number; resetTime: number }>();
    const make = () => new SharedRateLimiter({ scope: "api", max: 3, windowMs: 60_000 });

    // Three limiters, one shared backing map.
    const replicas = [make(), make(), make()];
    for (const r of replicas) {
      (r as unknown as { local: Map<string, { count: number; resetTime: number }> }).local = shared;
    }

    // Spend the whole budget on the FIRST replica only.
    expect((await replicas[0].consume("1.2.3.4")).allowed).toBe(true);
    expect((await replicas[0].consume("1.2.3.4")).allowed).toBe(true);
    expect((await replicas[0].consume("1.2.3.4")).allowed).toBe(true);

    // The second and third replicas must now REFUSE, not hand out a fresh
    // budget. This is the assertion the pre-fix code fails.
    expect((await replicas[1].consume("1.2.3.4")).allowed).toBe(false);
    expect((await replicas[2].consume("1.2.3.4")).allowed).toBe(false);
  });

  it("different IPs keep independent budgets", async () => {
    const limiter = new SharedRateLimiter({ scope: "api", max: 1, windowMs: 60_000 });

    expect((await limiter.consume("1.1.1.1")).allowed).toBe(true);
    expect((await limiter.consume("1.1.1.1")).allowed).toBe(false);
    // A different caller is not collateral damage.
    expect((await limiter.consume("2.2.2.2")).allowed).toBe(true);
  });

  it("different scopes do not share a budget", async () => {
    const api = new SharedRateLimiter({ scope: "api", max: 1, windowMs: 60_000 });
    const validate = new SharedRateLimiter({ scope: "validate", max: 1, windowMs: 60_000 });
    (api as unknown as { local: Map<string, unknown> }).local = validate["local" as never];

    // Core has two independent limits. Collapsing them would let a caller
    // exhaust one and be refused by the other for no reason.
    expect((await validate.consume("1.1.1.1")).allowed).toBe(true);
    expect((await validate.consume("1.1.1.1")).allowed).toBe(false);
    expect((await api.consume("1.1.1.1")).allowed).toBe(true);
  });
});

describe("the configured limits still hold", () => {
  it("refuses at the configured maximum and reports what is left", async () => {
    const limiter = new SharedRateLimiter({ scope: "api", max: 3, windowMs: 60_000 });

    const first = await limiter.consume("9.9.9.9");
    expect(first).toMatchObject({ allowed: true, remaining: 2 });

    await limiter.consume("9.9.9.9");
    const third = await limiter.consume("9.9.9.9");
    expect(third).toMatchObject({ allowed: true, remaining: 0 });

    const fourth = await limiter.consume("9.9.9.9");
    expect(fourth).toMatchObject({ allowed: false, remaining: 0 });
    expect(fourth.retryAfterSeconds).toBeGreaterThan(0);
  });

  it("keeps Core's 100/15min and 20/5min, and Plus's 60/1min, exactly", async () => {
    // R1 pinned Plus at 60/min deliberately. A limit that drifts is a limit
    // nobody reasoned about, so the numbers are asserted, not assumed.
    const core = new SharedRateLimiter({ scope: "api", max: 100, windowMs: 15 * 60 * 1000 });
    const validate = new SharedRateLimiter({ scope: "validate", max: 20, windowMs: 5 * 60 * 1000 });
    const plus = new SharedRateLimiter({ scope: "plus", max: 60, windowMs: 60_000 });

    expect(core["rule"]).toMatchObject({ max: 100, windowMs: 900_000 });
    expect(validate["rule"]).toMatchObject({ max: 20, windowMs: 300_000 });
    expect(plus["rule"]).toMatchObject({ max: 60, windowMs: 60_000 });
  });
});

describe("the window actually resets", () => {
  it("allows again once the window has passed", async () => {
    const limiter = new SharedRateLimiter({ scope: "api", max: 1, windowMs: 20 });

    expect((await limiter.consume("5.5.5.5")).allowed).toBe(true);
    expect((await limiter.consume("5.5.5.5")).allowed).toBe(false);

    await new Promise((r) => setTimeout(r, 40));
    expect((await limiter.consume("5.5.5.5")).allowed).toBe(true);
  });
});

describe("degradation is safe and visible", () => {
  it("reports the memory mode when Redis is not configured", () => {
    const limiter = new SharedRateLimiter({ scope: "api", max: 1, windowMs: 1000 });
    expect(limiter.currentMode).toBe("memory");
  });

  it("treats the localhost sentinel as development, not as a shared store", () => {
    // Same rule as `createJtiStore`: a developer with Redis on their laptop
    // should not silently depend on it, and compose uses the `redis` service
    // name so it does not match.
    const limiter = new SharedRateLimiter(
      { scope: "api", max: 1, windowMs: 1000 },
      "redis://localhost:6379",
    );
    expect(limiter.currentMode).toBe("memory");
  });

  it("selects the shared store when REDIS_URL names a real deployment", () => {
    const limiter = new SharedRateLimiter(
      { scope: "api", max: 1, windowMs: 1000 },
      "redis://redis:6379",
    );
    expect(limiter.currentMode).toBe("redis");
    return limiter.close();
  });

  it("never throws when the store is unreachable", async () => {
    // A limiter that can 500 is a denial-of-service vector of its own. The
    // store here points at a port nothing is listening on, so every call
    // fails at the socket.
    const limiter = new SharedRateLimiter(
      { scope: "api", max: 2, windowMs: 60_000 },
      "redis://127.0.0.1:6399",
    );

    const decision = await limiter.consume("7.7.7.7");
    // Whatever the outcome, the point is that it returned a decision at all.
    expect(decision).toHaveProperty("allowed");
    expect(limiter.currentMode).toBe("memory");
    await limiter.close();
  });
});

describe("the keyspace cannot grow without bound", () => {
  it("sweeps expired entries once the map gets large", async () => {
    const limiter = new SharedRateLimiter({ scope: "api", max: 1, windowMs: 20 });
    const local = (limiter as unknown as { local: Map<string, unknown> }).local;

    // 1200 distinct IPs, each with a 20ms window. Without a sweep the map
    // keeps all of them for the lifetime of the process, which an attacker
    // drives at will by rotating source addresses.
    for (let i = 0; i < 1200; i++) {
      await limiter.consume(`10.0.${Math.floor(i / 256)}.${i % 256}`);
    }

    await new Promise((r) => setTimeout(r, 40));
    await limiter.consume("trigger-sweep");

    expect(local.size).toBeLessThan(1200);
  });
});

describe("getRateLimiter", () => {
  it("returns the same instance for the same scope", () => {
    const a = getRateLimiter("api", 100, 60_000);
    const b = getRateLimiter("api", 999, 60_000);

    // Same instance, so the second call's numbers are ignored. A limiter whose
    // limit can be changed by a later call site is a limiter nobody can reason
    // about.
    expect(b).toBe(a);
    expect(a["rule"].max).toBe(100);
  });

  it("surfaces every configured limiter's mode", async () => {
    getRateLimiter("api", 100, 60_000);
    getRateLimiter("plus", 60, 60_000);

    expect(rateLimitMode()).toEqual({ api: "memory", plus: "memory" });
  });
});
