/**
 * R2 — replay protection must survive a Core restart and be shared between
 * replicas. The threat model recorded that `createJtiStore` only selects Redis
 * when `REDIS_URL` is set, and the shipped compose file never set it, so every
 * consumed JTI died with the process.
 *
 * These cases pin the selection rule and the credential wiring. They need no
 * Redis process: the store is lazy, so constructing it never opens a socket.
 */
import { createJtiStore, withRedisCredentials, InMemoryJtiStore, RedisJtiStore } from "../../src/infrastructure/crypto/jti-store";

const ORIGINAL_REDIS_URL = process.env.REDIS_URL;
const ORIGINAL_REDIS_PASSWORD = process.env.REDIS_PASSWORD;

afterEach(() => {
  if (ORIGINAL_REDIS_URL === undefined) delete process.env.REDIS_URL;
  else process.env.REDIS_URL = ORIGINAL_REDIS_URL;

  if (ORIGINAL_REDIS_PASSWORD === undefined) delete process.env.REDIS_PASSWORD;
  else process.env.REDIS_PASSWORD = ORIGINAL_REDIS_PASSWORD;
});

describe("withRedisCredentials", () => {
  it("embeds REDIS_PASSWORD when the URL carries none", () => {
    const url = withRedisCredentials("redis://redis:6379", "s3cr3t");

    expect(url).toBe("redis://:s3cr3t@redis:6379");
  });

  it("percent-encodes a password with URL-reserved characters", () => {
    // A raw `@` or `/` in the password would otherwise terminate the
    // authority and silently connect to the wrong host.
    const url = withRedisCredentials("redis://redis:6379", "p@ss/word:1");

    expect(url).toBe(`redis://:${encodeURIComponent("p@ss/word:1")}@redis:6379`);
  });

  it("leaves credentials already embedded in the URL alone", () => {
    const url = "redis://alice:already@redis:6379";

    expect(withRedisCredentials(url, "ignored")).toBe(url);
  });

  it("preserves the rediss scheme", () => {
    const url = withRedisCredentials("rediss://redis:6380", "s3cr3t");

    expect(url).toBe("rediss://:s3cr3t@redis:6380");
  });

  it("returns the URL untouched when no password is configured", () => {
    // `redis://:@host` is read as an empty username by some clients, so this
    // has to be a true no-op rather than a decorative rewrite.
    expect(withRedisCredentials("redis://redis:6379", "")).toBe("redis://redis:6379");
  });
});

describe("createJtiStore", () => {
  it("uses Redis when REDIS_URL names a real deployment", () => {
    process.env.REDIS_URL = "redis://redis:6379";

    expect(createJtiStore()).toBeInstanceOf(RedisJtiStore);
  });

  it("uses Redis for rediss too", () => {
    process.env.REDIS_URL = "rediss://redis:6380";

    expect(createJtiStore()).toBeInstanceOf(RedisJtiStore);
  });

  it("stays in-memory with no REDIS_URL", () => {
    delete process.env.REDIS_URL;

    expect(createJtiStore()).toBeInstanceOf(InMemoryJtiStore);
  });

  it("keeps the localhost sentinel as the development case", () => {
    // The sentinel is deliberate: a developer running Redis on their laptop
    // should not silently depend on it. The compose file uses the `redis`
    // service name precisely so it does not match.
    process.env.REDIS_URL = "redis://localhost:6379";

    expect(createJtiStore()).toBeInstanceOf(InMemoryJtiStore);
  });
});

describe("the shipped compose file", () => {
  const fs = require("fs");
  const path = require("path");
  const compose = fs.readFileSync(
    path.join(__dirname, "..", "..", "docker-compose.yml"),
    "utf8",
  );

  it("sets REDIS_URL, and not to the localhost sentinel", () => {
    // This is the assertion that would have caught R2 at review time. A
    // missing or localhost REDIS_URL here is the whole bug.
    const match = compose.match(/^\s*-\s*REDIS_URL=(.*)$/m);

    expect(match).not.toBeNull();
    expect(match![1].trim()).toBe("redis://redis:6379");
    expect(match![1].trim()).not.toContain("localhost");
  });

  it("still passes REDIS_PASSWORD, which the client now actually uses", () => {
    expect(compose).toMatch(/^\s*-\s*REDIS_PASSWORD=/m);
  });
});
