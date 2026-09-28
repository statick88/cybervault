/**
 * S2 — `PostgresPlusUserRepository` unit tests (mocked `pg`).
 *
 * WHY A MOCKED CLIENT
 * -------------------
 * The repository constructs `new Pool({connectionString})` internally and
 * exposes no injection seam, so `pg` is mocked at module level and every
 * assertion inspects the exact `(sql, params)` pair the repository sends.
 * No live database, no Docker, no network.
 *
 * WHAT IS PINNED HERE
 * 1. Row → domain mapping: `plus_users` rows shaped exactly as `pg` returns
 *    them (snake_case, `Date` for `timestamptz`, a real JS array for
 *    `TEXT[]`, an already-parsed object for `jsonb`) come back as fully
 *    populated camelCase `PlusUser` objects. The NULL `TEXT[]` → `[]` and
 *    NULL → `undefined` rules are asserted with a hard regression test,
 *    because a NULL `habitual_countries` is precisely what made
 *    `isCountryHabitual()` throw on `.includes()`.
 * 2. `findByEmail` LOWERCASES the argument before binding it — an
 *    identity-collision regression waiting to happen if that normalization
 *    is removed.
 * 3. Parameterization: `ILIKE` patterns, country codes and emails travel as
 *    bound parameters, never in the query text.
 * 4. Error propagation: a database error rejects, never `null` / `[]`.
 * 5. Lifecycle: constructor DDL, health probe, pool shutdown.
 */

const mockQuery = jest.fn();

jest.mock("pg", () => ({
  Pool: jest.fn(() => ({
    query: (text: string, values?: unknown[]) => mockQuery(text, values),
    on: jest.fn(),
    end: jest.fn(),
  })),
}));

import { PostgresPlusUserRepository } from "../../plus/infrastructure/repositories/PostgresPlusUserRepository";
import { PlusUser } from "../../plus/domain/entities/user";

const DB_URL = "postgresql://user:secret@localhost:5432/cybervault";

const { Pool } = jest.requireMock("pg") as { Pool: jest.Mock };

function newRepo(): PostgresPlusUserRepository {
  const repo = new PostgresPlusUserRepository(DB_URL);
  mockQuery.mockClear();
  return repo;
}

function lastPool(): { end: jest.Mock; on: jest.Mock } {
  return Pool.mock.results[Pool.mock.results.length - 1].value;
}

function lastCall(): [string, unknown[]] {
  const calls = mockQuery.mock.calls;
  const [sql, params] = calls[calls.length - 1];
  return [sql, params ?? []];
}

beforeEach(() => {
  mockQuery.mockReset();
  mockQuery.mockResolvedValue({ rows: [], rowCount: 0 });
});

/* -------------------------------------------------------------------------- */
/* Row fixture — the exact shape `pg` hands back from `SELECT *`               */
/* -------------------------------------------------------------------------- */

function plusUserRow(overrides: Record<string, unknown> = {}) {
  return {
    id: "u-1",
    email: "alice@example.com",
    name: "Alice Example",
    role: "operator",
    habitual_countries: ["EC", "US"],
    timezone: "America/Guayaquil",
    active: true,
    // jsonb arrives ALREADY PARSED (OID 3802).
    metadata: { team: "sre" },
    created_at: new Date("2026-01-01T00:00:00.000Z"),
    updated_at: new Date("2026-01-02T00:00:00.000Z"),
    last_login_at: new Date("2026-01-03T00:00:00.000Z"),
    ...overrides,
  };
}

/** Hard regression assertion: every field of the mapped domain object. */
function expectFullMapping(user: PlusUser): void {
  expect(user.id).toBe("u-1");
  expect(user.email).toBe("alice@example.com");
  expect(user.name).toBe("Alice Example");
  expect(user.role).toBe("operator");
  expect(user.habitualCountries).toEqual(["EC", "US"]);
  expect(user.timezone).toBe("America/Guayaquil");
  expect(user.active).toBe(true);
  expect(user.metadata).toEqual({ team: "sre" });
  expect(user.createdAt).toEqual(new Date("2026-01-01T00:00:00.000Z"));
  expect(user.updatedAt).toEqual(new Date("2026-01-02T00:00:00.000Z"));
  expect(user.lastLoginAt).toEqual(new Date("2026-01-03T00:00:00.000Z"));
}

function makeUser(): PlusUser {
  return PlusUser.create({
    id: "u-1",
    email: "alice@example.com",
    name: "Alice Example",
    role: "operator",
    habitualCountries: ["ec", "us"],
    timezone: "America/Guayaquil",
    metadata: { team: "sre" },
  });
}

/* ========================================================================== */
/* save                                                                        */
/* ========================================================================== */

describe("PostgresPlusUserRepository.save", () => {
  it("upserts with all 11 columns bound positionally", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [plusUserRow()], rowCount: 1 });

    await repo.save(makeUser());

    const [sql, params] = lastCall();
    expect(sql).toContain("INSERT INTO plus_users");
    expect(sql).toMatch(/ON CONFLICT \(id\) DO UPDATE SET/);
    expect(sql).toContain("RETURNING *");
    expect(params).toHaveLength(11);
    expect(sql).toContain("$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11");
  });

  it("binds the plain-object values as parameters, never in the query text", async () => {
    const repo = newRepo();
    const user = makeUser();
    mockQuery.mockResolvedValueOnce({ rows: [plusUserRow()], rowCount: 1 });

    await repo.save(user);

    const plain = user.toPlainObject();
    const [sql, params] = lastCall();
    expect(params).toEqual([
      "u-1",
      "alice@example.com",
      "Alice Example",
      "operator",
      ["EC", "US"], // `create()` upper-cases on the way in
      "America/Guayaquil",
      true,
      '{"team":"sre"}', // metadata serialized for jsonb
      plain.createdAt,
      plain.updatedAt,
      null, // no lastLoginAt → SQL NULL
    ]);
    expect(sql).not.toContain("alice@example.com");
    expect(sql).not.toContain("Alice Example");
    expect(sql).not.toContain("America/Guayaquil");
    expect(sql).not.toContain('"team":"sre"');
  });

  it("returns the mapped row from RETURNING *", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [plusUserRow()], rowCount: 1 });

    const saved = await repo.save(makeUser());

    expect(saved).toBeInstanceOf(PlusUser);
    expectFullMapping(saved);
  });

  it("propagates a database error instead of swallowing it", async () => {
    const repo = newRepo();
    mockQuery.mockRejectedValue(new Error("simulated database failure"));

    await expect(repo.save(makeUser())).rejects.toThrow(
      "simulated database failure",
    );
  });
});

/* ========================================================================== */
/* findById / findByEmail                                                      */
/* ========================================================================== */

describe("PostgresPlusUserRepository — point lookups", () => {
  it("findById maps every field of the snake_case row", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [plusUserRow()], rowCount: 1 });

    const found = await repo.findById("u-1");

    const [sql, params] = lastCall();
    expect(sql).toBe("SELECT * FROM plus_users WHERE id = $1");
    expect(sql).not.toContain("u-1");
    expect(params).toEqual(["u-1"]);
    expectFullMapping(found!);
  });

  it("findById returns null for an unknown id", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 });

    await expect(repo.findById("ghost")).resolves.toBeNull();
  });

  it("findByEmail lowercases the argument before binding it", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [plusUserRow()], rowCount: 1 });

    const found = await repo.findByEmail("Alice@Example.COM");

    const [sql, params] = lastCall();
    expect(sql).toBe("SELECT * FROM plus_users WHERE email = $1");
    // The normalization is the point: lookups are case-insensitive by
    // lower-casing the KEY, so a mixed-case login hits the same row.
    expect(params).toEqual(["alice@example.com"]);
    expect(sql).not.toContain("alice@example.com");
    expect(found!.email).toBe("alice@example.com");
  });

  it("findByEmail returns null when no row matches", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 });

    await expect(repo.findByEmail("ghost@example.com")).resolves.toBeNull();
  });

  it("a database error rejects instead of reporting 'not found'", async () => {
    const repo = newRepo();
    mockQuery.mockRejectedValue(new Error("simulated database failure"));

    const outcome = await repo
      .findById("u-1")
      .then(() => "resolved")
      .catch((error: Error) => error.message);
    expect(outcome).toBe("simulated database failure");

    mockQuery.mockRejectedValue(new Error("simulated database failure"));
    await expect(repo.findByEmail("alice@example.com")).rejects.toThrow(
      "simulated database failure",
    );
  });
});

/* ========================================================================== */
/* Collection reads                                                            */
/* ========================================================================== */

describe("PostgresPlusUserRepository — collection reads", () => {
  it("findByRole binds the role and orders newest first", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({
      rows: [plusUserRow(), plusUserRow({ id: "u-2", email: "bob@example.com" })],
      rowCount: 2,
    });

    const found = await repo.findByRole("viewer");

    const [sql, params] = lastCall();
    expect(sql).toBe(
      "SELECT * FROM plus_users WHERE role = $1 ORDER BY created_at DESC",
    );
    expect(sql).not.toContain("viewer");
    expect(params).toEqual(["viewer"]);
    expect(found).toHaveLength(2);
    expect(found[0].email).toBe("alice@example.com");
    expect(found[1].id).toBe("u-2");
  });

  it("findActive filters on `active = TRUE` with no bound values", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [plusUserRow()], rowCount: 1 });

    const found = await repo.findActive();

    const [sql, params] = mockQuery.mock.calls[mockQuery.mock.calls.length - 1];
    expect(sql).toBe(
      "SELECT * FROM plus_users WHERE active = TRUE ORDER BY created_at DESC",
    );
    // No parameter array at all — there is nothing to interpolate.
    expect(params).toBeUndefined();
    expect(found).toHaveLength(1);
    expectFullMapping(found[0]);
  });

  it("list issues a parameterless full scan", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [plusUserRow()], rowCount: 1 });

    const all = await repo.list();

    const [sql, params] = mockQuery.mock.calls[mockQuery.mock.calls.length - 1];
    expect(sql).toBe("SELECT * FROM plus_users ORDER BY created_at DESC");
    expect(params).toBeUndefined(); // full scan passes no parameter array
    expect(all).toHaveLength(1);
    expectFullMapping(all[0]);
  });

  it("an empty result set maps to an empty list, not an error", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 });

    await expect(repo.findByRole("admin")).resolves.toEqual([]);
    await expect(repo.findActive()).resolves.toEqual([]);
    await expect(repo.list()).resolves.toEqual([]);
  });

  it("a database error rejects instead of resolving to an empty list", async () => {
    const repo = newRepo();
    mockQuery.mockRejectedValue(new Error("simulated database failure"));

    await expect(repo.findByRole("admin")).rejects.toThrow(
      "simulated database failure",
    );
    mockQuery.mockRejectedValue(new Error("simulated database failure"));
    await expect(repo.list()).rejects.toThrow("simulated database failure");
  });
});

/* ========================================================================== */
/* Defaults and NULLs — the `.includes()` crash class                         */
/* ========================================================================== */

describe("PostgresPlusUserRepository — NULL columns", () => {
  it("maps a NULL TEXT[] to [] and NULL optionals to undefined", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({
      rows: [
        plusUserRow({
          habitual_countries: null,
          last_login_at: null,
          metadata: null,
          active: null,
        }),
      ],
      rowCount: 1,
    });

    const found = await repo.findById("u-1");

    // NULL TEXT[] → [] : `.includes()` on undefined is the crash this fixes.
    expect(found!.habitualCountries).toEqual([]);
    expect(() => found!.isCountryHabitual("EC")).not.toThrow();
    expect(found!.isCountryHabitual("EC")).toBe(false);
    // NULL optional columns → undefined, never null.
    expect(found!.lastLoginAt).toBeUndefined();
    expect(found!.metadata).toBeUndefined();
    // A NULL `active` flag must never read as "active".
    expect(found!.active).toBe(false);
    expect(found!.isActive()).toBe(false);
    // NOT NULL columns are still populated.
    expect(found!.email).toBe("alice@example.com");
    expect(found!.timezone).toBe("America/Guayaquil");
  });

  it("keeps a populated TEXT[] as a real JS array", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({
      rows: [plusUserRow({ habitual_countries: ["EC"] })],
      rowCount: 1,
    });

    const found = await repo.findById("u-1");
    expect(Array.isArray(found!.habitualCountries)).toBe(true);
    expect(found!.isCountryHabitual("ec")).toBe(true); // upper-cases internally
    expect(found!.isCountryHabitual("DE")).toBe(false);
  });
});

/* ========================================================================== */
/* search — dynamic WHERE, count + data                                        */
/* ========================================================================== */

describe("PostgresPlusUserRepository.search", () => {
  it("binds ILIKE patterns and equality criteria as parameters", async () => {
    const repo = newRepo();
    mockQuery.mockImplementation((sql: string) =>
      sql.includes("COUNT(*)")
        ? { rows: [{ count: "3" }], rowCount: 1 }
        : { rows: [plusUserRow()], rowCount: 1 },
    );

    const result = await repo.search({
      name: "ali",
      email: "example",
      role: "operator",
      active: true,
      habitualCountry: "ec",
      limit: 10,
      offset: 20,
    });

    const calls = mockQuery.mock.calls;
    expect(calls).toHaveLength(2);

    const [countSql] = calls[0];
    expect(countSql).toContain("SELECT COUNT(*) FROM plus_users");
    expect(countSql).toContain("name ILIKE $1");
    expect(countSql).toContain("email ILIKE $2");
    expect(countSql).toContain("role = $3");
    expect(countSql).toContain("active = $4");
    expect(countSql).toContain("$5 = ANY(habitual_countries)");
    // Wildcards and the country code live in the PARAMS, not the SQL.
    expect(countSql).not.toContain("%ali%");
    expect(countSql).not.toContain("operator");
    expect(countSql).not.toContain("'EC'"); // never inlined as a literal

    const [dataSql, dataParams] = calls[1];
    expect(dataSql).toContain("ORDER BY created_at DESC");
    expect(dataSql).toContain("LIMIT $6");
    expect(dataSql).toContain("OFFSET $7");
    // NOTE: count and data share ONE `values` array by reference, so by the
    // time both queries ran it also carries LIMIT/OFFSET.
    expect(dataParams).toEqual([
      "%ali%",
      "%example%",
      "operator",
      true,
      "EC", // upper-cased before binding
      10,
      20,
    ]);

    expect(result.total).toBe(3);
    expect(result.users).toHaveLength(1);
    expectFullMapping(result.users[0]);
  });

  it("an empty criteria object yields an unfiltered query", async () => {
    const repo = newRepo();
    mockQuery.mockImplementation((sql: string) =>
      sql.includes("COUNT(*)")
        ? { rows: [{ count: "0" }], rowCount: 1 }
        : { rows: [], rowCount: 1 },
    );

    const result = await repo.search({});

    const [countSql] = mockQuery.mock.calls[0];
    expect(countSql).not.toContain("WHERE");
    expect(result.total).toBe(0);
    expect(result.users).toEqual([]);
  });

  it("propagates a count failure instead of reporting total 0", async () => {
    const repo = newRepo();
    mockQuery.mockRejectedValue(new Error("simulated database failure"));

    await expect(repo.search({ role: "admin" })).rejects.toThrow(
      "simulated database failure",
    );
  });
});

/* ========================================================================== */
/* delete                                                                      */
/* ========================================================================== */

describe("PostgresPlusUserRepository.delete", () => {
  it("returns true on a hit and false on a miss", async () => {
    const repo = newRepo();

    mockQuery.mockResolvedValueOnce({ rows: [{ id: "u-1" }], rowCount: 1 });
    await expect(repo.delete("u-1")).resolves.toBe(true);

    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 });
    await expect(repo.delete("ghost")).resolves.toBe(false);

    const [sql, params] = lastCall();
    expect(sql).toContain("DELETE FROM plus_users WHERE id = $1 RETURNING id");
    expect(sql).not.toContain("ghost");
    expect(params).toEqual(["ghost"]);
  });

  it("treats a NULL rowCount as 'nothing deleted' rather than throwing", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: null });

    await expect(repo.delete("u-1")).resolves.toBe(false);
  });

  it("propagates a database error instead of reporting a failed delete", async () => {
    const repo = newRepo();
    mockQuery.mockRejectedValue(new Error("simulated database failure"));

    await expect(repo.delete("u-1")).rejects.toThrow(
      "simulated database failure",
    );
  });
});

/* ========================================================================== */
/* Lifecycle                                                                   */
/* ========================================================================== */

describe("PostgresPlusUserRepository — lifecycle", () => {
  it("provisions plus_users and its indexes on construction", async () => {
    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 1 });
    new PostgresPlusUserRepository(DB_URL);

    const [sql] = mockQuery.mock.calls[0];
    expect(sql).toContain("CREATE TABLE IF NOT EXISTS plus_users");
    for (const column of [
      "email VARCHAR(255) NOT NULL UNIQUE",
      "role VARCHAR(50) NOT NULL DEFAULT 'operator'",
      "habitual_countries TEXT[] DEFAULT '{}'",
      "timezone VARCHAR(100) NOT NULL DEFAULT 'UTC'",
      "active BOOLEAN DEFAULT TRUE",
      "metadata JSONB",
      "last_login_at TIMESTAMP WITH TIME ZONE",
    ]) {
      expect(sql).toContain(column);
    }
    expect(sql).toContain(
      "CREATE INDEX IF NOT EXISTS idx_plus_users_role ON plus_users(role)",
    );
    await Promise.resolve(); // settle the fire-and-forget promise
  });

  it("isHealthy reports true on a successful probe and false on failure", async () => {
    const repo = newRepo();

    mockQuery.mockResolvedValueOnce({ rows: [{ "?column?": 1 }], rowCount: 1 });
    await expect(repo.isHealthy()).resolves.toBe(true);
    expect(lastCall()[0]).toBe("SELECT 1");

    mockQuery.mockRejectedValue(new Error("ECONNREFUSED"));
    await expect(repo.isHealthy()).resolves.toBe(false);
  });

  it("close shuts the pool down", async () => {
    const repo = newRepo();
    const pool = lastPool();

    await repo.close();

    expect(pool.end).toHaveBeenCalledTimes(1);
  });
});

/* ========================================================================== */
/* Parameterization sweep                                                      */
/* ========================================================================== */

describe("PostgresPlusUserRepository — parameterized SQL", () => {
  it("no user value ever appears in any query string", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValue({ rows: [plusUserRow()], rowCount: 1 });

    await repo.findById("u-1");
    await repo.findByEmail("Alice@Example.COM");
    await repo.findByRole("viewer");
    await repo.findActive();
    await repo.list();
    await repo.delete("u-1");

    expect(mockQuery.mock.calls.length).toBeGreaterThanOrEqual(6);
    for (const [sql, rawParams] of mockQuery.mock.calls) {
      const params = rawParams ?? [];
      expect(typeof sql).toBe("string");
      expect(sql).not.toContain("u-1");
      expect(sql).not.toContain("alice@example.com");
      expect(sql).not.toContain("Alice");
      expect(sql).not.toContain("viewer");
      // Static statement, bound placeholders — a query with values uses $n,
      // a valueless one (`findActive`) has nothing to interpolate at all.
      if (params.length > 0) expect(sql).toMatch(/\$\d/);
      expect(Array.isArray(params)).toBe(true);
    }
  });
});
