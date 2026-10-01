/**
 * O5.10 — `PostgresReleaseShareStore` unit tests (mocked `pg`).
 *
 * WHY A MOCKED CLIENT
 * -------------------
 * The suite must run without a live PostgreSQL: `pg` is mocked at module level
 * and every assertion inspects the exact `(sql, params)` pairs the store sends.
 * A gated integration suite against a real server lives in
 * `postgres-release-share-store.integration.test.ts`.
 *
 * WHAT IS PINNED HERE
 * 1. save → find returns the same opaque blob.
 * 2. unknown `secretRef` → `null`, not a throw (legitimate refusal).
 * 3. `delete` → true when a row existed, false when it did not.
 * 4. re-saving an existing `secretRef` replaces the row (upsert, no duplicate).
 * 5. a database error PROPAGATES — an outage is never reported as "not found".
 * 6. parameterization: no secret value ever appears in a query string.
 * 7. the authoring round trip writes only `secret_ref / wrapped_share /
 *    created_at` — no plaintext username, password, TOTP seed or origin.
 * 8. the `ApiServer` selection rule (Postgres iff configured, else in-memory).
 */

const mockQuery = jest.fn();

jest.mock("pg", () => ({
  Pool: jest.fn(() => ({
    query: (text: string, values?: unknown[]) => mockQuery(text, values),
    on: jest.fn(),
    end: jest.fn(),
  })),
}));

import { PostgresReleaseShareStore } from "../../src/infrastructure/repositories/PostgresReleaseShareStore";
import { InMemoryReleaseShareStore } from "../../src/infrastructure/repositories/InMemoryReleaseShareStore";
import { createReleaseShareStore } from "../../src/infrastructure/repositories/release-share-store-factory";
import { ManagedAuthoringUseCase } from "../../src/application/use-cases/managed-authoring.use-case";
import { base32ToBytes } from "../../src/domain/services/autofill/credential-authoring";
import { base64ToBinary, binaryToBase64 } from "../../src/shared/utils";

/* -------------------------------------------------------------------------- */
/* Fixtures — same values as tests/application/managed-authoring.test.ts so the */
/* "no plaintext" assertions are the exact mirror of the in-memory suite.        */
/* -------------------------------------------------------------------------- */

const DB_URL = "postgresql://user:secret@localhost:5432/cybervault";
const SECRET_REF = "a3f1d2e4-0b7c-4d5e-9f10-111213141516";
const WRAPPED_SHARE = "Y2lwaGVydGV4dC1vcGFxdWUtaXY=";

const USERNAME = "alice@example.com";
const PASSWORD = "correct-horse-battery-staple-9!";
const TOTP_SEED = "JBSWY3DPEHPK3PXP";
const ORIGIN_INPUT = "https://github.com";
const ORIGIN_CANONICAL = "https://github.com:443";
const TITLE = "GitHub (corp)";

/**
 * Builds a store and drops the constructor's non-blocking `CREATE TABLE` call
 * from the recorded history, so assertions see only the operations under test.
 */
function newStore(): PostgresReleaseShareStore {
  const store = new PostgresReleaseShareStore(DB_URL);
  mockQuery.mockClear();
  return store;
}

beforeEach(() => {
  mockQuery.mockReset();
  mockQuery.mockResolvedValue({ rows: [], rowCount: 0 });
});

/* -------------------------------------------------------------------------- */
/* 1–3. Port semantics                                                         */
/* -------------------------------------------------------------------------- */

describe("PostgresReleaseShareStore — IReleaseShareStore semantics", () => {
  it("save then findBySecretRef returns the same opaque blob", async () => {
    const store = newStore();
    const entry = {
      secretRef: SECRET_REF,
      wrappedShare: WRAPPED_SHARE,
      createdAt: new Date("2026-09-27T12:00:00.000Z"),
    };

    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 1 });
    await store.save(entry);

    const saveCall = mockQuery.mock.calls[mockQuery.mock.calls.length - 1];
    expect(saveCall[0]).toContain("INSERT INTO release_shares");
    expect(saveCall[1]).toEqual([SECRET_REF, WRAPPED_SHARE, entry.createdAt]);

    mockQuery.mockResolvedValueOnce({
      rows: [
        { secret_ref: SECRET_REF, wrapped_share: WRAPPED_SHARE, created_at: entry.createdAt },
      ],
      rowCount: 1,
    });
    const found = await store.findBySecretRef(SECRET_REF);
    expect(found).toEqual(entry);
  });

  it("returns null (not a throw) for an unknown secretRef", async () => {
    const store = newStore();
    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 });

    await expect(store.findBySecretRef("no-such-reference")).resolves.toBeNull();
  });

  it("delete returns true when a row existed and false when it did not", async () => {
    const store = newStore();

    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 1 });
    await expect(store.delete(SECRET_REF)).resolves.toBe(true);

    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 });
    await expect(store.delete(SECRET_REF)).resolves.toBe(false);
  });
});

/* -------------------------------------------------------------------------- */
/* 4. Upsert semantics                                                         */
/* -------------------------------------------------------------------------- */

describe("PostgresReleaseShareStore — replace, not duplicate", () => {
  it("a save for an existing secretRef replaces the row instead of adding a second one", async () => {
    const store = newStore();

    // Tiny table double that honours the ON CONFLICT upsert the SQL declares.
    const rows = new Map<string, { secret_ref: string; wrapped_share: string; created_at: Date }>();
    mockQuery.mockImplementation((sql: string, values?: unknown[]) => {
      if (sql.includes("INSERT INTO release_shares")) {
        const [ref, share, createdAt] = values as [string, string, Date];
        rows.set(ref, { secret_ref: ref, wrapped_share: share, created_at: createdAt });
        return Promise.resolve({ rows: [], rowCount: 1 });
      }
      if (sql.includes("FROM release_shares")) {
        const row = rows.get(values?.[0] as string);
        return Promise.resolve({ rows: row ? [row] : [], rowCount: row ? 1 : 0 });
      }
      return Promise.resolve({ rows: [], rowCount: 0 });
    });

    await store.save({
      secretRef: SECRET_REF,
      wrappedShare: "dmVyc2lvbi1vbmU=",
      createdAt: new Date("2026-01-01T00:00:00.000Z"),
    });
    await store.save({
      secretRef: SECRET_REF,
      wrappedShare: "dmVyc2lvbi10d28=",
      createdAt: new Date("2026-02-01T00:00:00.000Z"),
    });

    expect(rows.size).toBe(1);
    expect(rows.get(SECRET_REF)?.wrapped_share).toBe("dmVyc2lvbi10d28=");

    const found = await store.findBySecretRef(SECRET_REF);
    expect(found?.wrappedShare).toBe("dmVyc2lvbi10d28=");

    // The SQL must be a real upsert (PK conflict target), not INSERT-or-fail.
    const saveSql = mockQuery.mock.calls[0][0] as string;
    expect(saveSql).toContain("ON CONFLICT (secret_ref) DO UPDATE");
    expect(saveSql).toContain("wrapped_share = EXCLUDED.wrapped_share");
  });
});

/* -------------------------------------------------------------------------- */
/* 5. Fail closed — outages are errors, not "not found"                        */
/* -------------------------------------------------------------------------- */

describe("PostgresReleaseShareStore — failure propagation", () => {
  it("propagates a database error instead of converting it into null/false", async () => {
    const store = newStore();
    mockQuery.mockReset();
    mockQuery.mockRejectedValue(new Error("simulated database failure"));

    // findBySecretRef: an outage must NOT look like an unknown reference.
    const outcome = await store
      .findBySecretRef(SECRET_REF)
      .then(() => "resolved")
      .catch((error: Error) => error.message);
    expect(outcome).toBe("simulated database failure");

    await expect(
      store.save({ secretRef: SECRET_REF, wrappedShare: WRAPPED_SHARE, createdAt: new Date() }),
    ).rejects.toThrow("simulated database failure");

    await expect(store.delete(SECRET_REF)).rejects.toThrow("simulated database failure");
  });
});

/* -------------------------------------------------------------------------- */
/* 6. Parameterized SQL — no secret in a query string                          */
/* -------------------------------------------------------------------------- */

describe("PostgresReleaseShareStore — parameterized SQL", () => {
  it("binds every value as $n and never inlines a secret into the query text", async () => {
    const store = newStore();
    const createdAt = new Date("2026-09-27T12:00:00.000Z");
    mockQuery.mockResolvedValue({
      rows: [{ secret_ref: SECRET_REF, wrapped_share: WRAPPED_SHARE, created_at: createdAt }],
      rowCount: 1,
    });

    await store.save({ secretRef: SECRET_REF, wrappedShare: WRAPPED_SHARE, createdAt });
    await store.findBySecretRef(SECRET_REF);
    await store.delete(SECRET_REF);

    expect(mockQuery.mock.calls).toHaveLength(3);

    for (const [sql, params] of mockQuery.mock.calls) {
      expect(typeof sql).toBe("string");
      // The secret material travels only in the bound parameter array.
      expect(sql).not.toContain(SECRET_REF);
      expect(sql).not.toContain(WRAPPED_SHARE);
      expect(sql).not.toContain(createdAt.toISOString());
      expect(Array.isArray(params)).toBe(true);
      // Static statement, bound placeholders — no string interpolation.
      expect(sql).toMatch(/\$\d/);
      expect(sql).not.toMatch(/'[A-Za-z0-9+/=]{8,}'/);
    }

    expect(mockQuery.mock.calls[0][1]).toEqual([SECRET_REF, WRAPPED_SHARE, createdAt]);
    expect(mockQuery.mock.calls[1][1]).toEqual([SECRET_REF]);
    expect(mockQuery.mock.calls[2][1]).toEqual([SECRET_REF]);
  });
});

/* -------------------------------------------------------------------------- */
/* 7. No plaintext at rest — the Postgres-path mirror of the O5.8 assertion    */
/* -------------------------------------------------------------------------- */

describe("PostgresReleaseShareStore — no plaintext reaches the table", () => {
  it("persists no plaintext username, password, TOTP seed or origin", async () => {
    const store = newStore();
    const serverSecret = crypto.getRandomValues(new Uint8Array(32));
    const vek = crypto.getRandomValues(new Uint8Array(32));
    const authoring = new ManagedAuthoringUseCase(store, serverSecret);
    mockQuery.mockResolvedValue({ rows: [], rowCount: 1 });

    const result = await authoring.execute({
      origin: ORIGIN_INPUT,
      username: USERNAME,
      password: PASSWORD,
      title: TITLE,
      totpSeedBase32: TOTP_SEED,
      vek,
      secretRef: SECRET_REF,
      id: crypto.randomUUID(),
    } as Parameters<ManagedAuthoringUseCase["execute"]>[0]);

    expect(result.ok).toBe(true);

    // Everything this store would hand to PostgreSQL: SQL text + bound values.
    const persisted = JSON.stringify(mockQuery.mock.calls);
    expect(persisted).not.toContain(USERNAME);
    expect(persisted).not.toContain(PASSWORD);
    expect(persisted).not.toContain(TOTP_SEED);
    expect(persisted).not.toContain(binaryToBase64(base32ToBytes(TOTP_SEED)));
    expect(persisted).not.toContain(ORIGIN_INPUT);
    expect(persisted).not.toContain(ORIGIN_CANONICAL);
    expect(persisted).not.toContain("github.com");

    // Exactly one statement: the parameterized upsert of the opaque blob.
    expect(mockQuery.mock.calls).toHaveLength(1);
    const [sql, params] = mockQuery.mock.calls[0];
    expect(sql).toContain("INSERT INTO release_shares");
    // Column list is closed: secret_ref, wrapped_share, created_at — nothing else.
    expect(sql).toContain("(secret_ref, wrapped_share, created_at)");
    expect(params).toHaveLength(3);
    expect(params[0]).toBe(SECRET_REF);
    expect(typeof params[1]).toBe("string");
    // The blob is opaque: not the plaintext share and not the reference itself.
    expect(params[1]).not.toContain(USERNAME);
    expect(params[1]).not.toBe(SECRET_REF);
    expect(base64ToBinary(params[1]).byteLength).toBeGreaterThan(32);
  });
});

/* -------------------------------------------------------------------------- */
/* 8. ApiServer selection rule                                                 */
/* -------------------------------------------------------------------------- */

describe("createReleaseShareStore — ApiServer selection rule", () => {
  it("selects the Postgres store when USE_POSTGRES=true and DATABASE_URL is set", () => {
    const store = createReleaseShareStore({
      USE_POSTGRES: "true",
      DATABASE_URL: DB_URL,
    });
    expect(store).toBeInstanceOf(PostgresReleaseShareStore);
  });

  it.each([
    ["no database configured at all", {}],
    ["flag off even with a URL", { USE_POSTGRES: "false", DATABASE_URL: DB_URL }],
    ["flag unset even with a URL", { DATABASE_URL: DB_URL }],
    ["flag on but no URL", { USE_POSTGRES: "true" }],
    ["flag on but a blank URL", { USE_POSTGRES: "true", DATABASE_URL: "   " }],
  ])("falls back to the in-memory store when %s", (_case, env) => {
    const store = createReleaseShareStore(env);
    expect(store).toBeInstanceOf(InMemoryReleaseShareStore);
  });

  it("keeps today's behaviour: with no environment it starts in-memory", () => {
    expect(createReleaseShareStore({})).toBeInstanceOf(InMemoryReleaseShareStore);
  });
});
