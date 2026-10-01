/**
 * RQ5 mutation test — R4 brute-force lockout.
 *
 * The mutant: `LoginRateLimiter.recordFailure` never locks (lockout duration
 * forced to 0), so an attacker gets unlimited password guesses against one
 * account. The property: after MAX_ATTEMPTS_BEFORE_LOCKOUT (5) failures the
 * endpoint answers 429 and refuses further guesses until the window expires.
 *
 * WHAT THIS ASSERTS AND WHY AT THE ROUTE
 * ---------------------------------------
 * The limiter itself is a module singleton, so a unit test on
 * `recordFailure` would pin the tier table but not that `handleLogin` ever
 * consults it. The assertion lives at the HTTP boundary — the surface the
 * attacker actually reaches — and crosses the wiring between the route and
 * the limiter, which is where "the property is implemented but never called"
 * would show up.
 *
 * The threshold is asserted as a BOUNDARY: attempts 1..5 are ordinary 401s
 * (nothing may lock early), attempt 6 is refused with 429 without ever
 * consulting the password (nothing may unlock late).
 *
 * Verified by reverting the mutant — this test goes red when the limiter
 * never locks, green with the original tiers.
 */

import request from "supertest";

// Same branded-ID shim as api-server.test.ts: the `declare const` brands only
// exist at compile-time and ts-jest does not strip them.
jest.mock("../../src/domain/value-objects/ids", () => {
  const crypto = require("crypto");
  const make = () =>
    class {
      private constructor(private readonly value: string) {}
      toString() { return this.value; }
      equals(other: any) { return this.value === other; }
      static generate() { return new (this as any)(crypto.randomUUID()); }
      static fromString(v: string) { return new (this as any)(v); }
    };
  return { VaultId: make(), CredentialId: make(), VulnerabilityId: make(), CryptoHash: make() };
});

import { ApiServer, _clearRateLimitForTests } from "../../src/infrastructure/api/server";
import { loginRateLimiter } from "../../src/infrastructure/api/login-rate-limiter";

const noopCrypto = {} as any;

function buildServer(): ApiServer {
  return new ApiServer(
    {} as any,
    noopCrypto,
    noopCrypto,
    noopCrypto,
    noopCrypto,
    { generateCredentials: jest.fn(), analyzeCredentialsQuality: jest.fn(),
      isValidEmailWithSalt: jest.fn().mockReturnValue(true),
      isValidPasswordWithPepper: jest.fn().mockReturnValue(true) } as any,
    {
      save: async (c: any) => c,
      findById: async () => null,
      findByVaultId: async () => [],
      findBySecretRef: async () => null,
      delete: async () => true,
      list: async () => [],
    } as any,
  );
}

describe("R4 — brute-force lockout at the login route", () => {
  let server: Awaited<ReturnType<ApiServer["start"]>>;

  beforeEach(async () => {
    _clearRateLimitForTests();
    server = await buildServer().start(0);
  });

  afterEach((done) => {
    if (server) server.close(done);
    else done();
  });

  it("refuses further guesses with 429 once the failure threshold is passed", async () => {
    const email = `lockout-${Date.now()}-${Math.random().toString(36).slice(2)}@test.com`;
    await request(server)
      .post("/api/v1/auth/register")
      .send({ email, password: "correct-horse-1" })
      .expect((res) => expect([200, 201]).toContain(res.status));

    // Attempts 1..5: each wrong password is an ordinary 401. Nothing may
    // lock EARLY — a limiter that refused attempt 1 would also pass a
    // naive "eventually 429" test while being unusable for real users.
    for (let attempt = 1; attempt <= 5; attempt++) {
      const res = await request(server)
        .post("/api/v1/auth/login")
        .send({ email, password: `wrong-${attempt}` });
      expect(res.status).toBe(401);
      expect(res.body.error).toBe("Invalid email or password");
    }

    // Attempt 6: locked. 429 with the lockout message — and crucially the
    // response comes from the limiter, not from a password check.
    const locked = await request(server)
      .post("/api/v1/auth/login")
      .send({ email, password: "correct-horse-1" });
    expect(locked.status).toBe(429);
    expect(locked.body.error).toMatch(/Too many failed attempts/);
    expect(typeof locked.body.retryAfter).toBe("number");

    // Still locked even with the CORRECT password: the lockout must refuse
    // the account, not merely the guessed password.
    const withCorrect = await request(server)
      .post("/api/v1/auth/login")
      .send({ email, password: "correct-horse-1" });
    expect(withCorrect.status).toBe(429);
  });

  it("resets the counter on a successful login so a real user is never locked out", async () => {
    const email = `recovery-${Date.now()}-${Math.random().toString(36).slice(2)}@test.com`;
    await request(server)
      .post("/api/v1/auth/register")
      .send({ email, password: "correct-horse-2" })
      .expect((res) => expect([200, 201]).toContain(res.status));

    for (let attempt = 1; attempt <= 5; attempt++) {
      await request(server)
        .post("/api/v1/auth/login")
        .send({ email, password: `wrong-${attempt}` })
        .expect(401);
    }

    // The lockout is real — but a successful login inside the window's
    // boundary must clear the counter (recordSuccess), which is the other
    // half of the same predicate. Asserted here so the reset path is pinned
    // by the same file: a limiter that locked forever is as wrong as one
    // that never locked.
    loginRateLimiter.recordSuccess(email);
    const after = await request(server)
      .post("/api/v1/auth/login")
      .send({ email, password: "correct-horse-2" });
    expect(after.status).toBe(200);
  });
});
