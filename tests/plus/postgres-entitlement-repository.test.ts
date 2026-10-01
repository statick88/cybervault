/**
 * S2 — `PostgresEntitlementRepository` unit tests (mocked `pg`).
 *
 * WHY A MOCKED CLIENT
 * -------------------
 * The repository constructs `new Pool({connectionString})` internally and
 * exposes no injection seam, so `pg` is mocked at module level and every
 * assertion inspects the exact `(sql, params)` pair the repository sends.
 * The suite must run with no live PostgreSQL, no Docker and no network —
 * the same constraint the Postgres suites under `tests/infrastructure`
 * already follow (`postgres-release-share-store.test.ts`,
 * `optimistic-locking.test.ts`).
 *
 * WHAT IS PINNED HERE
 * 1. Row → domain mapping: rows shaped exactly as `pg` returns them
 *    (snake_case keys, `Date` for `timestamptz`, a real JS array for
 *    `TEXT[]`, an already-parsed object for `jsonb`) come back as fully
 *    populated camelCase `Entitlement` objects. That is the defect class
 *    that shipped broken across four repositories, so it gets a hard
 *    regression assertion on EVERY field.
 * 2. Defaults and NULLs: NULL `TEXT[]` → `[]`, NULL optional columns →
 *    `undefined` (never `null`) — the two behaviours whose absence crashed
 *    `.includes()`.
 * 3. Parameterization: no user value ever appears in query text.
 * 4. The id convention: `findByUserAndResource` composes
 *    `${userId}:${resourceId}` and delegates to `findById` — ONE query,
 *    `WHERE id = $1`, no JOIN. A future refactor to a JOIN would silently
 *    change it, which is why it is asserted explicitly.
 * 5. Error propagation: a database error REJECTS. An outage is never
 *    reported as `null` / `[]`.
 * 6. Lifecycle: the constructor's fire-and-forget DDL, the health probe and
 *    pool shutdown.
 */

const mockQuery = jest.fn();

jest.mock("pg", () => ({
  Pool: jest.fn(() => ({
    query: (text: string, values?: unknown[]) => mockQuery(text, values),
    on: jest.fn(),
    end: jest.fn(),
  })),
}));

import { PostgresEntitlementRepository } from "../../plus/infrastructure/repositories/PostgresEntitlementRepository";
import { Entitlement } from "../../plus/domain/entities/entitlement";

const DB_URL = "postgresql://user:secret@localhost:5432/cybervault";
const USER_ID = "user-1";
const RESOURCE_ID = "resource-1";
const COMPOSITE_ID = `${USER_ID}:${RESOURCE_ID}`;

/** The `Pool` mock, so a test can look at the pool the repo built. */
const { Pool } = jest.requireMock("pg") as { Pool: jest.Mock };

/**
 * Builds a repository and drops the constructor's non-blocking
 * `initializeTable()` call from the recorded history, so assertions see only
 * the operations under test.
 */
function newRepo(): PostgresEntitlementRepository {
  const repo = new PostgresEntitlementRepository(DB_URL);
  mockQuery.mockClear();
  return repo;
}

/** The pool instance the most recent repository constructed. */
function lastPool(): { end: jest.Mock; on: jest.Mock } {
  return Pool.mock.results[Pool.mock.results.length - 1].value;
}

/** The single query issued since the last `mockClear()` — `(sql, params)`. */
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
/* Row fixtures — the exact shape `pg` hands back from a `SELECT *`            */
/* -------------------------------------------------------------------------- */

function entitlementRow(overrides: Record<string, unknown> = {}) {
  return {
    id: COMPOSITE_ID,
    user_id: USER_ID,
    resource_id: RESOURCE_ID,
    pestillo_state: "step_up",
    allowed_operations: ["READ", "VIEW"],
    valid_from: new Date("2026-01-01T00:00:00.000Z"),
    valid_until: new Date("2026-12-31T00:00:00.000Z"),
    // jsonb arrives ALREADY PARSED (OID 3802) — never a JSON string.
    metadata: { source: "admin", priority: 1 },
    created_by: "admin-1",
    created_at: new Date("2026-02-01T10:00:00.000Z"),
    updated_at: new Date("2026-02-02T10:00:00.000Z"),
    ...overrides,
  };
}

/**
 * Asserts EVERY field of the mapped domain object — the hard regression
 * assertion for the "snake_case row handed to a camelCase factory" defect.
 */
function expectFullMapping(entitlement: Entitlement): void {
  expect(entitlement.id).toBe(COMPOSITE_ID);
  expect(entitlement.userId).toBe(USER_ID);
  expect(entitlement.resourceId).toBe(RESOURCE_ID);
  expect(entitlement.pestilloState).toBe("step_up");
  expect(entitlement.allowedOperations).toEqual(["READ", "VIEW"]);
  expect(entitlement.validFrom).toEqual(new Date("2026-01-01T00:00:00.000Z"));
  expect(entitlement.validUntil).toEqual(new Date("2026-12-31T00:00:00.000Z"));
  expect(entitlement.metadata).toEqual({ source: "admin", priority: 1 });
  expect(entitlement.createdBy).toBe("admin-1");
  expect(entitlement.createdAt).toEqual(new Date("2026-02-01T10:00:00.000Z"));
  expect(entitlement.updatedAt).toEqual(new Date("2026-02-02T10:00:00.000Z"));
}

function makeEntitlement(): Entitlement {
  return Entitlement.create({
    userId: USER_ID,
    resourceId: RESOURCE_ID,
    pestilloState: "enabled",
    allowedOperations: ["READ"],
    createdBy: "admin-1",
  });
}

/* ========================================================================== */
/* save                                                                        */
/* ========================================================================== */

describe("PostgresEntitlementRepository.save", () => {
  it("upserts by the composite id with all 11 columns bound positionally", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [entitlementRow()], rowCount: 1 });

    await repo.save(makeEntitlement());

    const [sql, params] = lastCall();
    expect(sql).toContain("INSERT INTO plus_entitlements");
    expect(sql).toMatch(/ON CONFLICT \(id\) DO UPDATE SET/);
    expect(sql).toContain("RETURNING *");
    // Exactly $1…$11 — one placeholder per column, no interpolation.
    expect(sql).toContain("$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11");
    expect(params).toHaveLength(11);
  });

  it("binds the plain-object values as parameters, never in the query text", async () => {
    const repo = newRepo();
    const entitlement = makeEntitlement();
    mockQuery.mockResolvedValueOnce({ rows: [entitlementRow()], rowCount: 1 });

    await repo.save(entitlement);

    const plain = entitlement.toPlainObject();
    const [sql, params] = lastCall();
    expect(params).toEqual([
      COMPOSITE_ID, // id — the `${userId}:${resourceId}` convention
      USER_ID,
      RESOURCE_ID,
      "enabled",
      ["READ"],
      null, // no validFrom → SQL NULL, not undefined
      null, // no validUntil → SQL NULL
      null, // no metadata → SQL NULL
      "admin-1",
      plain.createdAt, // ISO string from `toPlainObject()`
      plain.updatedAt,
    ]);
    expect(sql).not.toContain(USER_ID);
    expect(sql).not.toContain(RESOURCE_ID);
    expect(sql).not.toContain(COMPOSITE_ID);
    expect(sql).not.toContain("admin-1");
    expect(sql).not.toMatch(/'enabled'/);
  });

  it("serializes metadata to a JSON string and returns the mapped row", async () => {
    const repo = newRepo();
    const entitlement = Entitlement.create({
      userId: USER_ID,
      resourceId: RESOURCE_ID,
      pestilloState: "temporary",
      allowedOperations: ["CONNECT"],
      metadata: { ticket: "OPS-1" },
      validUntil: new Date("2026-06-30T00:00:00.000Z"),
      createdBy: "admin-1",
    });
    mockQuery.mockResolvedValueOnce({ rows: [entitlementRow()], rowCount: 1 });

    const saved = await repo.save(entitlement);

    const [, params] = lastCall();
    expect(params[6]).toBe("2026-06-30T00:00:00.000Z");
    expect(params[7]).toBe('{"ticket":"OPS-1"}');
    expect(typeof params[7]).toBe("string");
    // The RETURNING row is mapped before it is handed back.
    expect(saved).toBeInstanceOf(Entitlement);
    expectFullMapping(saved);
  });

  it("propagates a database error instead of swallowing it", async () => {
    const repo = newRepo();
    mockQuery.mockRejectedValue(new Error("simulated database failure"));

    await expect(repo.save(makeEntitlement())).rejects.toThrow(
      "simulated database failure",
    );
  });
});

/* ========================================================================== */
/* findById — mapping, miss, parameterization                                 */
/* ========================================================================== */

describe("PostgresEntitlementRepository.findById", () => {
  it("maps every field of the snake_case row onto the domain object", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [entitlementRow()], rowCount: 1 });

    const found = await repo.findById(COMPOSITE_ID);

    expect(found).toBeInstanceOf(Entitlement);
    expectFullMapping(found!);
  });

  it("returns null when the row does not exist", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 });

    await expect(repo.findById("no-such:id")).resolves.toBeNull();
  });

  it("binds the id as $1 and keeps it out of the query text", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [entitlementRow()], rowCount: 1 });

    await repo.findById(COMPOSITE_ID);

    const [sql, params] = lastCall();
    expect(sql).toContain("SELECT * FROM plus_entitlements WHERE id = $1");
    expect(sql).not.toContain(COMPOSITE_ID);
    expect(sql).not.toContain(USER_ID);
    expect(params).toEqual([COMPOSITE_ID]);
  });

  it("rejects on a database error rather than reporting 'not found'", async () => {
    const repo = newRepo();
    mockQuery.mockRejectedValue(new Error("simulated database failure"));

    const outcome = await repo
      .findById(COMPOSITE_ID)
      .then(() => "resolved")
      .catch((error: Error) => error.message);
    expect(outcome).toBe("simulated database failure");
  });
});

/* ========================================================================== */
/* findByUserAndResource — the composite-id convention                         */
/* ========================================================================== */

describe("PostgresEntitlementRepository.findByUserAndResource", () => {
  it("composes `${userId}:${resourceId}` and delegates to findById — one query", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [entitlementRow()], rowCount: 1 });

    const found = await repo.findByUserAndResource(USER_ID, RESOURCE_ID);

    // Exactly ONE statement, and it is the `findById` statement.
    expect(mockQuery.mock.calls).toHaveLength(1);
    const [sql, params] = lastCall();
    expect(sql).toBe("SELECT * FROM plus_entitlements WHERE id = $1");
    expect(sql).not.toMatch(/user_id\s*=/);
    expect(sql).not.toMatch(/resource_id\s*=/);
    expect(sql).not.toMatch(/\bJOIN\b/i);
    expect(params).toEqual([COMPOSITE_ID]);
    expectFullMapping(found!);
  });

  it("returns null when no row carries the composed id", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 });

    await expect(
      repo.findByUserAndResource("ghost", "resource"),
    ).resolves.toBeNull();
    expect(lastCall()[1]).toEqual(["ghost:resource"]);
  });

  it("propagates the error from the delegated lookup", async () => {
    const repo = newRepo();
    mockQuery.mockRejectedValue(new Error("simulated database failure"));

    await expect(
      repo.findByUserAndResource(USER_ID, RESOURCE_ID),
    ).rejects.toThrow("simulated database failure");
  });
});

/* ========================================================================== */
/* Filtered reads                                                              */
/* ========================================================================== */

describe("PostgresEntitlementRepository — filtered reads", () => {
  it("findByUserId binds the user and orders newest first", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({
      rows: [entitlementRow(), entitlementRow({ id: "user-1:resource-2" })],
      rowCount: 2,
    });

    const found = await repo.findByUserId(USER_ID);

    const [sql, params] = lastCall();
    expect(sql).toBe(
      "SELECT * FROM plus_entitlements WHERE user_id = $1 ORDER BY created_at DESC",
    );
    expect(sql).not.toContain(USER_ID);
    expect(params).toEqual([USER_ID]);
    expect(found).toHaveLength(2);
    expect(found[0].userId).toBe(USER_ID);
    expect(found[1].id).toBe("user-1:resource-2");
  });

  it("findByResourceId binds the resource", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({
      rows: [entitlementRow()],
      rowCount: 1,
    });

    await repo.findByResourceId(RESOURCE_ID);

    const [sql, params] = lastCall();
    expect(sql).toContain("WHERE resource_id = $1 ORDER BY created_at DESC");
    expect(sql).not.toContain(RESOURCE_ID);
    expect(params).toEqual([RESOURCE_ID]);
  });

  it("findByPestilloState binds the state", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({
      rows: [entitlementRow()],
      rowCount: 1,
    });

    await repo.findByPestilloState("step_up");

    const [sql, params] = lastCall();
    expect(sql).toContain("WHERE pestillo_state = $1");
    expect(sql).not.toContain("step_up");
    expect(params).toEqual(["step_up"]);
  });

  it("findExpiringSoon binds the window in milliseconds", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({
      rows: [entitlementRow()],
      rowCount: 1,
    });

    await repo.findExpiringSoon(3_600_000);

    const [sql, params] = lastCall();
    expect(sql).toContain(
      "AND valid_until <= NOW() + $1 * INTERVAL '1 millisecond'",
    );
    expect(sql).not.toContain("3600000");
    expect(params).toEqual([3_600_000]);
  });

  it("list issues a parameterless full scan", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({
      rows: [entitlementRow()],
      rowCount: 1,
    });

    const all = await repo.list();

    const [sql, params] = mockQuery.mock.calls[mockQuery.mock.calls.length - 1];
    expect(sql).toContain("SELECT * FROM plus_entitlements ORDER BY created_at DESC");
    // A full scan passes NO parameter array at all — nothing to interpolate.
    expect(params).toBeUndefined();
    expect(all).toHaveLength(1);
    expectFullMapping(all[0]);
  });

  it("an empty result set maps to an empty list, not to an error", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 });

    await expect(repo.findByUserId(USER_ID)).resolves.toEqual([]);
    await expect(repo.findByPestilloState("closed")).resolves.toEqual([]);
    await expect(repo.list()).resolves.toEqual([]);
  });

  it("a database error rejects instead of resolving to an empty list", async () => {
    const repo = newRepo();
    mockQuery.mockRejectedValue(new Error("simulated database failure"));

    await expect(repo.findByUserId(USER_ID)).rejects.toThrow(
      "simulated database failure",
    );
    mockQuery.mockRejectedValue(new Error("simulated database failure"));
    await expect(repo.list()).rejects.toThrow("simulated database failure");
  });
});

/* ========================================================================== */
/* Defaults and NULLs — the `.includes()` crash class                         */
/* ========================================================================== */

describe("PostgresEntitlementRepository — NULL columns", () => {
  it("maps a NULL TEXT[] to [] and NULL optionals to undefined", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({
      rows: [
        entitlementRow({
          allowed_operations: null,
          valid_from: null,
          valid_until: null,
          metadata: null,
        }),
      ],
      rowCount: 1,
    });

    const found = await repo.findById(COMPOSITE_ID);

    // NULL TEXT[] → [] : `.includes()` on undefined is the crash this fixes.
    expect(found!.allowedOperations).toEqual([]);
    expect(() => found!.isOperationAllowed("READ")).not.toThrow();
    expect(found!.isOperationAllowed("READ")).toBe(false);
    // NULL optional columns → undefined, never null.
    expect(found!.validFrom).toBeUndefined();
    expect(found!.validUntil).toBeUndefined();
    expect(found!.metadata).toBeUndefined();
    // NOT NULL columns are still populated.
    expect(found!.createdBy).toBe("admin-1");
    expect(found!.pestilloState).toBe("step_up");
  });

  it("an empty TEXT[] survives a round trip as []", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({
      rows: [entitlementRow({ allowed_operations: [] })],
      rowCount: 1,
    });

    const found = await repo.findById(COMPOSITE_ID);
    expect(found!.allowedOperations).toEqual([]);
    expect(Array.isArray(found!.allowedOperations)).toBe(true);
  });
});

/* ========================================================================== */
/* delete                                                                      */
/* ========================================================================== */

describe("PostgresEntitlementRepository.delete", () => {
  it("returns true when a row was deleted and false when it was not", async () => {
    const repo = newRepo();

    mockQuery.mockResolvedValueOnce({ rows: [{ id: COMPOSITE_ID }], rowCount: 1 });
    await expect(repo.delete(COMPOSITE_ID)).resolves.toBe(true);

    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 });
    await expect(repo.delete("ghost:id")).resolves.toBe(false);

    const [sql, params] = lastCall();
    expect(sql).toContain("DELETE FROM plus_entitlements WHERE id = $1 RETURNING id");
    expect(sql).not.toContain("ghost:id");
    expect(params).toEqual(["ghost:id"]);
  });

  it("treats a NULL rowCount as 'nothing deleted' rather than throwing", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: null });

    await expect(repo.delete(COMPOSITE_ID)).resolves.toBe(false);
  });

  it("propagates a database error instead of reporting a failed delete", async () => {
    const repo = newRepo();
    mockQuery.mockRejectedValue(new Error("simulated database failure"));

    await expect(repo.delete(COMPOSITE_ID)).rejects.toThrow(
      "simulated database failure",
    );
  });
});

/* ========================================================================== */
/* search — dynamic WHERE, count + data                                        */
/* ========================================================================== */

describe("PostgresEntitlementRepository.search", () => {
  it("binds criteria as parameters and returns the parsed total", async () => {
    const repo = newRepo();
    mockQuery.mockImplementation((sql: string) =>
      sql.includes("COUNT(*)")
        ? { rows: [{ count: "7" }], rowCount: 1 }
        : { rows: [entitlementRow()], rowCount: 1 },
    );

    const result = await repo.search({
      userId: USER_ID,
      pestilloState: "step_up",
      limit: 10,
      offset: 5,
    });

    const calls = mockQuery.mock.calls;
    expect(calls).toHaveLength(2);

    const [countSql] = calls[0];
    expect(countSql).toContain("SELECT COUNT(*) FROM plus_entitlements");
    expect(countSql).toContain("user_id = $1");
    expect(countSql).toContain("pestillo_state = $2");
    expect(countSql).not.toContain(USER_ID);

    const [dataSql, dataParams] = calls[1];
    expect(dataSql).toContain("ORDER BY created_at DESC");
    expect(dataSql).toContain("LIMIT $3");
    expect(dataSql).toContain("OFFSET $4");
    expect(dataSql).not.toContain(USER_ID);
    // NOTE: count and data share ONE `values` array by reference, so by the
    // time both queries have been issued it also carries LIMIT/OFFSET.
    expect(dataParams).toEqual([USER_ID, "step_up", 10, 5]);

    expect(result.total).toBe(7);
    expect(result.entitlements).toHaveLength(1);
    expectFullMapping(result.entitlements[0]);
  });

  it("adds the activeOnly predicate without binding a value", async () => {
    const repo = newRepo();
    mockQuery.mockImplementation((sql: string) =>
      sql.includes("COUNT(*)")
        ? { rows: [{ count: "1" }], rowCount: 1 }
        : { rows: [entitlementRow()], rowCount: 1 },
    );

    await repo.search({ activeOnly: true });

    const [countSql] = mockQuery.mock.calls[0];
    expect(countSql).toContain("(pestillo_state != 'closed')");
    expect(countSql).toContain("valid_until IS NULL OR valid_until > NOW()");
    expect(countSql).not.toContain("WHERE $");
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
    expect(result.entitlements).toEqual([]);
  });

  it("propagates a count failure instead of returning total 0", async () => {
    const repo = newRepo();
    mockQuery.mockRejectedValue(new Error("simulated database failure"));

    await expect(repo.search({ userId: USER_ID })).rejects.toThrow(
      "simulated database failure",
    );
  });
});

/* ========================================================================== */
/* Lifecycle — initializeTable / isHealthy / close                             */
/* ========================================================================== */

describe("PostgresEntitlementRepository — lifecycle", () => {
  it("provisions plus_entitlements and its indexes on construction", async () => {
    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 1 });
    new PostgresEntitlementRepository(DB_URL);

    const [sql] = mockQuery.mock.calls[0];
    expect(sql).toContain("CREATE TABLE IF NOT EXISTS plus_entitlements");
    for (const column of [
      "user_id VARCHAR(255) NOT NULL",
      "resource_id VARCHAR(255) NOT NULL",
      "pestillo_state VARCHAR(20) NOT NULL DEFAULT 'closed'",
      "allowed_operations TEXT[] DEFAULT '{}'",
      "valid_from TIMESTAMP WITH TIME ZONE",
      "valid_until TIMESTAMP WITH TIME ZONE",
      "metadata JSONB",
      "created_by VARCHAR(255) NOT NULL",
    ]) {
      expect(sql).toContain(column);
    }
    expect(sql).toContain(
      "CREATE INDEX IF NOT EXISTS idx_plus_entitlements_user_id ON plus_entitlements(user_id)",
    );
    expect(sql).toContain(
      "CREATE INDEX IF NOT EXISTS idx_plus_entitlements_user_resource ON plus_entitlements(user_id, resource_id)",
    );
    await Promise.resolve(); // let the fire-and-forget promise settle
  });

  it("isHealthy reports true on a successful probe", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [{ "?column?": 1 }], rowCount: 1 });

    await expect(repo.isHealthy()).resolves.toBe(true);
    const [sql, params] = mockQuery.mock.calls[mockQuery.mock.calls.length - 1];
    expect(sql).toBe("SELECT 1");
    expect(params).toBeUndefined(); // probe carries no bound values
  });

  it("isHealthy reports false when the probe fails", async () => {
    const repo = newRepo();
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

describe("PostgresEntitlementRepository — parameterized SQL", () => {
  it("no user value ever appears in any query string", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValue({ rows: [entitlementRow()], rowCount: 1 });

    await repo.findByUserId(USER_ID);
    await repo.findByResourceId(RESOURCE_ID);
    await repo.findByPestilloState("step_up");
    await repo.findExpiringSoon(60_000);
    await repo.findByUserAndResource(USER_ID, RESOURCE_ID);
    await repo.findById(COMPOSITE_ID);
    await repo.list();
    await repo.delete(COMPOSITE_ID);

    expect(mockQuery.mock.calls.length).toBeGreaterThanOrEqual(8);
    for (const [sql, rawParams] of mockQuery.mock.calls) {
      const params = rawParams ?? [];
      expect(typeof sql).toBe("string");
      expect(sql).not.toContain(USER_ID);
      expect(sql).not.toContain(RESOURCE_ID);
      expect(sql).not.toContain("step_up");
      expect(sql).not.toContain("60000");
      expect(sql).not.toContain(COMPOSITE_ID);
      // Static statement, bound placeholders — no string interpolation.
      expect(sql).not.toMatch(/'user-/);
      if (params.length > 0) expect(sql).toMatch(/\$\d/);
      expect(Array.isArray(params)).toBe(true);
    }
  });
});
