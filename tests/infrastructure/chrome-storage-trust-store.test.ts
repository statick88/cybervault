/**
 * S2 — `ChromeStorageTrustStore` unit tests (mocked `chrome.storage`).
 *
 * WHY A MOCKED CLIENT
 * -------------------
 * The store talks to `chrome.storage.local` (trust decisions) and
 * `chrome.storage.session` (DOM fingerprints) through the extension global.
 * There is no extension runtime under Jest and `tests/jest.setup.js` installs
 * no global `chrome`, so this suite installs its OWN `chrome` in `beforeEach`
 * and removes it in `afterEach` — the same discipline as
 * `tests/extension/lock-semantics.test.ts` — so nothing leaks into a suite
 * that expects the global to be absent. The two storage areas are separate
 * `Map`s (as they are in the browser): a fingerprint written to `session` must
 * never become readable through `local`.
 *
 * WHAT IS PINNED HERE
 * This is a SECURITY store: its `trustLevel` is what the auditor reads before
 * deciding whether a domain may be contacted, so the read paths are pinned
 * harder than the write paths.
 * 1. Revocation is real: `revoke` removes the entry and every subsequent read
 *    (`findByDomain`, `list`) reports it as gone — a revoked domain must never
 *    come back as "trusted".
 * 2. Expiry is exact: `removeExpired` deletes precisely the entries whose
 *    `lastSeen` is at or beyond `maxAgeMs` (strict `<`), keeps the fresh ones,
 *    and returns the number it deleted.
 * 3. Storage failures PROPAGATE. If `chrome.storage` rejects, no read path
 *    resolves with `null`/`[]` that a caller could mistake for a verdict, and
 *    no write path resolves as if the decision had been persisted.
 * 4. Domain validation: control characters, `<>\"'&`, empty-after-normalize,
 *    non `[a-z0-9.-]`, leading/trailing `-`/`.`, consecutive dots, labels over
 *    63 chars and labels starting/ending with `-` are all rejected before a
 *    single byte reaches storage.
 * 5. The 10 000-entry cap is enforced on INSERT but not on UPDATE.
 *
 * NOT PINNED: the `visitCount`/`lastSeen` arithmetic is asserted, but wall
 * clock values are only bounded, never equal to a fixture, so the tests do not
 * become flaky on a slow runner.
 */

type Stored = Record<string, unknown>;

interface Area {
  get: jest.Mock;
  set: jest.Mock;
  remove: jest.Mock;
}

/** One `chrome.storage` area backed by a Map — string OR array keys. */
function createArea(store: Map<string, unknown>): Area {
  const get = jest.fn(async (keys: string | string[]) => {
    const list = Array.isArray(keys) ? keys : [keys];
    const out: Stored = {};
    for (const key of list) if (store.has(key)) out[key] = store.get(key);
    return out;
  });
  const set = jest.fn(async (items: Stored) => {
    for (const [key, value] of Object.entries(items)) store.set(key, value);
  });
  const remove = jest.fn(async (keys: string | string[]) => {
    const list = Array.isArray(keys) ? keys : [keys];
    for (const key of list) store.delete(key);
  });
  return { get, set, remove };
}

const TRUST_STORE_KEY = "cybervault_trust_store";
const FP_PREFIX = "cybervault_fp_";
const MAX_ENTRIES = 10_000;

let localStore = new Map<string, unknown>();
let sessionStore = new Map<string, unknown>();
let local: Area;
let session: Area;

import { ChromeStorageTrustStore } from "../../src/infrastructure/repositories/chrome-storage-trust-store";
import type { TrustEntry } from "../../src/domain/repositories";

function newStore(): ChromeStorageTrustStore {
  localStore = new Map();
  sessionStore = new Map();
  local = createArea(localStore);
  session = createArea(sessionStore);
  (globalThis as unknown as { chrome: unknown }).chrome = {
    storage: { local, session },
  };
  return new ChromeStorageTrustStore();
}

function teardown(): void {
  delete (globalThis as unknown as { chrome?: unknown }).chrome;
}

afterEach(() => {
  teardown();
  jest.restoreAllMocks();
});

/** Read the trust array exactly as it sits in storage. */
function storedEntries(): TrustEntry[] {
  return localStore.get(TRUST_STORE_KEY) as TrustEntry[];
}

function entry(overrides: Partial<TrustEntry> = {}): TrustEntry {
  return {
    domain: "example.com",
    trustLevel: "verified",
    firstSeen: 1_700_000_000_000,
    lastSeen: 1_700_000_000_000,
    visitCount: 1,
    ...overrides,
  };
}

/* ========================================================================== */
/* save                                                                        */
/* ========================================================================== */

describe("ChromeStorageTrustStore.save", () => {
  it("normalizes the domain and writes one visit", async () => {
    const store = newStore();
    const before = Date.now();

    await store.save(entry({ domain: "  ExAmPle.COM.  " }));

    expect(storedEntries()).toHaveLength(1);
    const saved = storedEntries()[0];
    expect(saved.domain).toBe("example.com");
    expect(saved.trustLevel).toBe("verified");
    expect(saved.visitCount).toBe(1);
    expect(saved.lastSeen).toBeGreaterThanOrEqual(before);
    expect(local.set).toHaveBeenCalledTimes(1);
    expect(local.set.mock.calls[0][0]).toHaveProperty(TRUST_STORE_KEY);
    // The session area is for fingerprints only — trust data never lands there.
    expect(session.set).not.toHaveBeenCalled();
  });

  it("defaults firstSeen when the caller supplies none", async () => {
    const store = newStore();
    const now = 1_750_000_000_000;
    jest.spyOn(Date, "now").mockReturnValue(now);

    // `firstSeen` is non-optional on the interface; the repository still has a
    // `?? now` guard for callers that hydrate an entry from elsewhere.
    await store.save({
      ...entry({ domain: "example.com" }),
      firstSeen: undefined,
    } as unknown as TrustEntry);

    expect(storedEntries()[0].firstSeen).toBe(now);
    expect(storedEntries()[0].lastSeen).toBe(now);
  });

  it("updates an existing entry instead of appending a duplicate", async () => {
    const store = newStore();
    await store.save(entry({ domain: "example.com", trustLevel: "unknown" }));

    const later = Date.now() + 5_000;
    jest.spyOn(Date, "now").mockReturnValue(later);
    await store.save(
      entry({ domain: "example.com", trustLevel: "verified", visitCount: 99 }),
    );

    expect(storedEntries()).toHaveLength(1);
    const updated = storedEntries()[0];
    expect(updated.trustLevel).toBe("verified");
    expect(updated.visitCount).toBe(2); // counted by the store, never trusted in
    expect(updated.lastSeen).toBe(later);
    // firstSeen is the ORIGINAL observation and must survive an update.
    expect(updated.firstSeen).toBe(1_700_000_000_000);
  });

  it("keeps the stored fingerprint when the update carries none", async () => {
    const store = newStore();
    await store.save(entry({ domain: "example.com", fingerprint: "sha256-old" }));

    await store.save(
      entry({ domain: "example.com", fingerprint: undefined }),
    );

    expect(storedEntries()[0].fingerprint).toBe("sha256-old");
  });

  it("replaces the fingerprint when the update carries one", async () => {
    const store = newStore();
    await store.save(entry({ domain: "example.com", fingerprint: "sha256-old" }));

    await store.save(entry({ domain: "example.com", fingerprint: "sha256-new" }));

    expect(storedEntries()[0].fingerprint).toBe("sha256-new");
  });

  it("refuses the 10 000th NEW entry but still updates an existing one", async () => {
    const store = newStore();
    localStore.set(
      TRUST_STORE_KEY,
      Array.from({ length: MAX_ENTRIES }, (_, i) => entry({ domain: `d${i}.com` })),
    );

    await expect(store.save(entry({ domain: "one-too-many.com" }))).rejects.toThrow(
      "Trust store limit exceeded",
    );
    // The cap guards INSERT only — an update of a domain already present is
    // still allowed, so a busy domain cannot be frozen out of the store.
    await expect(store.save(entry({ domain: "d0.com" }))).resolves.toBeUndefined();
    expect(storedEntries()).toHaveLength(MAX_ENTRIES);
  });

  it("rejects instead of pretending the decision was persisted", async () => {
    const store = newStore();
    local.set.mockRejectedValueOnce(new Error("storage unavailable"));

    await expect(store.save(entry())).rejects.toThrow("storage unavailable");
    expect(storedEntries()).toBeUndefined();
  });
});

/* ========================================================================== */
/* Domain validation — every rejection reason                                  */
/* ========================================================================== */

describe("ChromeStorageTrustStore — domain validation", () => {
  const cases: Array<[string, string, RegExp]> = [
    ["control character", "exa\u0000mple.com", /control characters/],
    ["DEL (127)", "exam\u007fple.com", /control characters/],
    ["dangerous character", "evil<>.example", /dangerous characters/],
    ["quotes and ampersand", "a&b.example", /dangerous characters/],
    ["empty after normalization", "   ", /empty after normalization/],
    ["underscore", "not_a_host.example", /invalid characters/],
    ["leading hyphen", "-start.example", /start or end with hyphen or dot/],
    ["trailing hyphen label", "end-.example", /label cannot start or end with hyphen/],
    ["consecutive dots", "a..example.com", /consecutive dots/],
    ["label longer than 63 chars", `${"a".repeat(64)}.example.com`, /label too long/],
  ];

  for (const [name, domain, pattern] of cases) {
    it(`rejects ${name} on save`, async () => {
      const store = newStore();
      await expect(store.save(entry({ domain }))).rejects.toThrow(pattern);
      expect(local.set).not.toHaveBeenCalled();
    });
  }

  it("rejects the same invalid domain on saveFingerprint", async () => {
    const store = newStore();
    await expect(store.saveFingerprint("bad_host.example", "fp")).rejects.toThrow(
      /invalid characters/,
    );
    expect(session.set).not.toHaveBeenCalled();
  });

  it("accepts a well-formed domain with a 63-character label", async () => {
    const store = newStore();
    const domain = `${"a".repeat(63)}.example.com`;
    await expect(store.save(entry({ domain }))).resolves.toBeUndefined();
    expect(storedEntries()[0].domain).toBe(domain);
  });
});

/* ========================================================================== */
/* findByDomain / list — the read paths a verdict is taken from                */
/* ========================================================================== */

describe("ChromeStorageTrustStore read paths", () => {
  it("findByDomain normalizes the query the same way save normalizes the key", async () => {
    const store = newStore();
    await store.save(entry({ domain: "Example.COM" }));

    await expect(store.findByDomain("EXAMPLE.com.")).resolves.toMatchObject({
      domain: "example.com",
      trustLevel: "verified",
    });
  });

  it("findByDomain returns null for an unknown domain, not a default verdict", async () => {
    const store = newStore();
    await expect(store.findByDomain("unknown.example")).resolves.toBeNull();
  });

  it("list returns every entry and [] on an empty store", async () => {
    const store = newStore();
    await expect(store.list()).resolves.toEqual([]);

    await store.save(entry({ domain: "a.example" }));
    await store.save(entry({ domain: "b.example", trustLevel: "suspicious" }));

    const all = await store.list();
    expect(all.map((e) => e.domain)).toEqual(["a.example", "b.example"]);
    expect(all[1].trustLevel).toBe("suspicious");
  });

  it("treats a non-array value under the key as an empty store", async () => {
    // Corruption in storage must degrade to "nothing known", never to a throw
    // that would leave the auditor without a verdict.
    const store = newStore();
    localStore.set(TRUST_STORE_KEY, { not: "an array" });

    await expect(store.list()).resolves.toEqual([]);
    await expect(store.findByDomain("example.com")).resolves.toBeNull();
  });
});

/* ========================================================================== */
/* revoke                                                                      */
/* ========================================================================== */

describe("ChromeStorageTrustStore.revoke", () => {
  it("removes the entry so no read path can report it as trusted again", async () => {
    const store = newStore();
    await store.save(entry({ domain: "good.example", trustLevel: "verified" }));
    await store.save(entry({ domain: "bad.example", trustLevel: "trusted" }));

    await store.revoke("BAD.example.  ");

    expect(storedEntries().map((e) => e.domain)).toEqual(["good.example"]);
    await expect(store.findByDomain("bad.example")).resolves.toBeNull();
    await expect(store.list()).resolves.toEqual([
      expect.objectContaining({ domain: "good.example" }),
    ]);
  });

  it("revoking an unknown domain is a no-op that still resolves", async () => {
    const store = newStore();
    await store.save(entry({ domain: "good.example" }));

    await expect(store.revoke("never-seen.example")).resolves.toBeUndefined();
    expect(storedEntries()).toHaveLength(1);
  });

  it("rejects rather than reporting a half-applied revocation", async () => {
    const store = newStore();
    await store.save(entry({ domain: "bad.example" }));
    local.set.mockRejectedValueOnce(new Error("storage unavailable"));

    await expect(store.revoke("bad.example")).rejects.toThrow("storage unavailable");
    // The write failed, so the in-memory Map still holds the entry — proving
    // the rejection is a real rejection and not a silent success.
    expect(storedEntries()).toHaveLength(1);
  });
});

/* ========================================================================== */
/* removeExpired                                                               */
/* ========================================================================== */

describe("ChromeStorageTrustStore.removeExpired", () => {
  const NOW = 1_750_000_000_000;

  beforeEach(() => {
    jest.spyOn(Date, "now").mockReturnValue(NOW);
  });

  it("deletes exactly the expired set and reports the count", async () => {
    const store = newStore();
    localStore.set(TRUST_STORE_KEY, [
      entry({ domain: "fresh.example", lastSeen: NOW - 1_000 }),
      entry({ domain: "stale.example", lastSeen: NOW - 10_000 }),
      // Strict `<`: an entry exactly `maxAgeMs` old is expired.
      entry({ domain: "boundary.example", lastSeen: NOW - 5_000 }),
      entry({ domain: "ancient.example", lastSeen: NOW - 99_000 }),
    ]);

    await expect(store.removeExpired(5_000)).resolves.toBe(3);

    expect(storedEntries().map((e) => e.domain)).toEqual(["fresh.example"]);
    await expect(store.findByDomain("stale.example")).resolves.toBeNull();
    await expect(store.findByDomain("boundary.example")).resolves.toBeNull();
    await expect(store.findByDomain("ancient.example")).resolves.toBeNull();
    await expect(store.findByDomain("fresh.example")).resolves.not.toBeNull();
  });

  it("returns 0 and leaves the store untouched when nothing is expired", async () => {
    const store = newStore();
    localStore.set(TRUST_STORE_KEY, [entry({ lastSeen: NOW - 10 })]);

    await expect(store.removeExpired(60_000)).resolves.toBe(0);
    expect(storedEntries()).toHaveLength(1);
  });

  it("returns 0 on an empty store", async () => {
    const store = newStore();
    await expect(store.removeExpired(1)).resolves.toBe(0);
    expect(local.set).toHaveBeenCalledTimes(1);
  });

  it("rejects rather than reporting 0 deleted when the read failed", async () => {
    const store = newStore();
    local.get.mockRejectedValueOnce(new Error("storage unavailable"));

    await expect(store.removeExpired(1)).rejects.toThrow("storage unavailable");
  });
});

/* ========================================================================== */
/* Fingerprints — session area                                                 */
/* ========================================================================== */

describe("ChromeStorageTrustStore fingerprints", () => {
  it("round-trips a fingerprint under the prefixed session key", async () => {
    const store = newStore();

    await store.saveFingerprint("Example.COM.", "sha256:abc");

    expect(sessionStore.has(`${FP_PREFIX}example.com`)).toBe(true);
    expect(sessionStore.get(`${FP_PREFIX}example.com`)).toMatchObject({
      fingerprint: "sha256:abc",
      timestamp: expect.any(Number),
    });
    // Fingerprints live in `session`, not `local`.
    expect(localStore.size).toBe(0);

    await expect(store.getFingerprint("example.com")).resolves.toBe("sha256:abc");
  });

  it("getFingerprint returns null when nothing was ever stored", async () => {
    const store = newStore();
    await expect(store.getFingerprint("example.com")).resolves.toBeNull();
  });

  it("getFingerprint returns null for a value that is not a stored record", async () => {
    const store = newStore();

    sessionStore.set(`${FP_PREFIX}example.com`, "not-an-object");
    await expect(store.getFingerprint("example.com")).resolves.toBeNull();

    sessionStore.set(`${FP_PREFIX}example.com`, { timestamp: 1 });
    await expect(store.getFingerprint("example.com")).resolves.toBeNull();
  });

  it("removeFingerprint deletes only that domain's key", async () => {
    const store = newStore();
    sessionStore.set(`${FP_PREFIX}a.example`, { fingerprint: "A", timestamp: 1 });
    sessionStore.set(`${FP_PREFIX}b.example`, { fingerprint: "B", timestamp: 1 });

    await store.removeFingerprint("A.EXAMPLE");

    expect(sessionStore.has(`${FP_PREFIX}a.example`)).toBe(false);
    expect(sessionStore.has(`${FP_PREFIX}b.example`)).toBe(true);
    expect(session.remove).toHaveBeenCalledWith(`${FP_PREFIX}a.example`);
  });

  it("propagates a session-storage failure from every fingerprint method", async () => {
    const store = newStore();

    session.set.mockRejectedValueOnce(new Error("session unavailable"));
    await expect(store.saveFingerprint("example.com", "fp")).rejects.toThrow(
      "session unavailable",
    );

    session.get.mockRejectedValueOnce(new Error("session unavailable"));
    await expect(store.getFingerprint("example.com")).rejects.toThrow(
      "session unavailable",
    );

    session.remove.mockRejectedValueOnce(new Error("session unavailable"));
    await expect(store.removeFingerprint("example.com")).rejects.toThrow(
      "session unavailable",
    );
  });
});

/* ========================================================================== */
/* Fail-closed: an outage is an outage, never a verdict                        */
/* ========================================================================== */

describe("ChromeStorageTrustStore — a storage outage never reads as 'trusted'", () => {
  it("every read path rejects when the local area cannot be read", async () => {
    const store = newStore();
    local.get.mockRejectedValue(new Error("storage unavailable"));

    const outcomes = await Promise.allSettled([
      store.findByDomain("example.com"),
      store.list(),
      store.removeExpired(1),
    ]);
    for (const outcome of outcomes) {
      expect(outcome.status).toBe("rejected");
    }
  });

  it("save and revoke reject when the local area cannot be read", async () => {
    const store = newStore();
    local.get.mockRejectedValue(new Error("storage unavailable"));

    await expect(store.save(entry())).rejects.toThrow("storage unavailable");
    await expect(store.revoke("example.com")).rejects.toThrow("storage unavailable");
  });
});
