/**
 * S2 batch 3 — `PostgresResourceRepository` unit tests (mocked `pg`).
 *
 * WHY A MOCKED CLIENT
 * -------------------
 * Same constraint and same shape as the four batch-1 suites
 * (`postgres-entitlement-repository.test.ts`,
 * `postgres-plus-user-repository.test.ts`,
 * `postgres-challenge-repository.test.ts`) and the batch-2
 * `tests/infrastructure/postgres-vault-repository.test.ts`: the repository
 * builds its own `new Pool({connectionString})`, exposes no injection seam,
 * and the suite must run with no live PostgreSQL, no Docker and no network.
 *
 * WHAT IS PINNED HERE
 * 1. Instrumentation — the very first assertion is that the module loaded,
 *    because a file no test imports gets NO lcov record at all and Sonar
 *    scores an absent file as 0%.
 * 2. Row → domain mapping: rows shaped exactly as `pg` returns them
 *    (snake_case keys, `Date` for `timestamptz`, a real JS array for
 *    `TEXT[]`, an already-parsed object for `jsonb`) come back as fully
 *    populated camelCase `Resource` objects — the defect class that shipped
 *    broken across four repositories.
 * 3. NULL handling: NULL `TEXT[]` → `[]`, NULL optionals → `undefined`,
 *    NULL `active` → `false` (fail-closed).
 * 4. Parameterization: no user value ever appears in query text.
 * 5. Error propagation: a database error REJECTS; an outage is never reported
 *    as `null` / `[]` / `total 0`.
 * 6. Lifecycle: the constructor's fire-and-forget DDL, the health probe, the
 *    pool shutdown and the circuit breaker.
 */

const mockQuery = jest.fn();

jest.mock("pg", () => ({
  Pool: jest.fn(() => ({
    query: (text: string, values?: unknown[]) => mockQuery(text, values),
    on: jest.fn(),
    end: jest.fn(),
  })),
}));

import { PostgresResourceRepository } from "../../plus/infrastructure/repositories/PostgresResourceRepository";
import { Resource } from "../../plus/domain/entities/resource";

const DB_URL = "postgresql://user:secret@localhost:5432/cybervault";
const RESOURCE_ID = "db-prod-001";

/** The `Pool` mock, so a test can look at the pool the repo built. */
const { Pool } = jest.requireMock("pg") as { Pool: jest.Mock };

/**
 * Builds a repository and drops the constructor's non-blocking
 * `initializeTable()` call from the recorded history, so assertions see only
 * the operations under test.
 */
function newRepo(): PostgresResourceRepository {
  const repo = new PostgresResourceRepository(DB_URL);
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

function resourceRow(overrides: Record<string, unknown> = {}) {
  return {
    id: RESOURCE_ID,
    name: "Primary database",
    type: "database",
    endpoint: "db01.internal.example:5432",
    environment: "production",
    criticality: "critical",
    description: "Customer records",
    tags: ["pci", "tier-1"],
    owner_team: "platform",
    // jsonb arrives ALREADY PARSED (OID 3802) — never a JSON string.
    metadata: { cluster: "pg-16", replicas: 3 },
    active: true,
    created_at: new Date("2026-01-01T00:00:00.000Z"),
    updated_at: new Date("2026-02-01T00:00:00.000Z"),
    ...overrides,
  };
}

/**
 * Asserts EVERY field of the mapped domain object — the hard regression
 * assertion for the "snake_case row handed to a camelCase factory" defect.
 */
function expectFullMapping(resource: Resource): void {
  expect(resource.id).toBe(RESOURCE_ID);
  expect(resource.name).toBe("Primary database");
  expect(resource.type).toBe("database");
  expect(resource.endpoint).toBe("db01.internal.example:5432");
  expect(resource.environment).toBe("production");
  expect(resource.criticality).toBe("critical");
  expect(resource.description).toBe("Customer records");
  expect(resource.tags).toEqual(["pci", "tier-1"]);
  expect(resource.ownerTeam).toBe("platform");
  expect(resource.metadata).toEqual({ cluster: "pg-16", replicas: 3 });
  expect(resource.active).toBe(true);
  expect(resource.createdAt).toEqual(new Date("2026-01-01T00:00:00.000Z"));
  expect(resource.updatedAt).toEqual(new Date("2026-02-01T00:00:00.000Z"));
}

function makeResource(): Resource {
  return Resource.create({
    id: RESOURCE_ID,
    name: "Primary database",
    type: "database",
    endpoint: "db01.internal.example:5432",
    environment: "production",
    criticality: "critical",
    description: "Customer records",
    tags: ["pci"],
    ownerTeam: "platform",
    metadata: { cluster: "pg-16" },
  });
}

/* ========================================================================== */
/* Instrumentation — the reason this file exists                               */
/* ========================================================================== */

describe("PostgresResourceRepository — instrumentation", () => {
  it("loads and instruments the module under test", () => {
    expect(typeof PostgresResourceRepository).toBe("function");
    expect(PostgresResourceRepository.name).toBe("PostgresResourceRepository");
    expect(typeof Resource.fromPlainObject).toBe("function");
  });
});

/* ========================================================================== */
/* save                                                                        */
/* ========================================================================== */

describe("PostgresResourceRepository.save", () => {
  it("upserts by id with all 13 columns bound positionally", async () => {
    const repo = newRepo();
    const resource = makeResource();
    const plain = resource.toPlainObject();
    mockQuery.mockResolvedValueOnce({ rows: [resourceRow()], rowCount: 1 });

    await repo.save(resource);

    const [sql, params] = lastCall();
    expect(sql).toContain("INSERT INTO plus_resources");
    expect(sql).toContain("ON CONFLICT (id) DO UPDATE SET");
    expect(sql).toContain("RETURNING *");
    expect(params).toEqual([
      plain.id,
      plain.name,
      plain.type,
      plain.endpoint,
      plain.environment,
      plain.criticality,
      plain.description,
      plain.tags,
      plain.ownerTeam,
      JSON.stringify(plain.metadata),
      plain.active,
      plain.createdAt,
      plain.updatedAt,
    ]);
  });

  it("binds the plain-object values as parameters, never in the query text", async () => {
    const repo = newRepo();
    const resource = Resource.create({
      id: "res-with-quote",
      name: "O'Brien's database",
      type: "database",
      endpoint: "db01.internal.example:5432",
      environment: "production",
      criticality: "high",
      ownerTeam: "platform",
    });
    mockQuery.mockResolvedValueOnce({
      rows: [resourceRow({ id: "res-with-quote", name: "O'Brien's database" })],
      rowCount: 1,
    });

    await repo.save(resource);

    const [sql, params] = lastCall();
    expect(sql).not.toContain("res-with-quote");
    expect(sql).not.toContain("O'Brien");
    expect(params[0]).toBe("res-with-quote");
    expect(params[1]).toBe("O'Brien's database");
  });

  it("nulls the optional columns the entity left unset", async () => {
    const repo = newRepo();
    const resource = Resource.create({
      id: RESOURCE_ID,
      name: "Bare",
      type: "web",
      endpoint: "https://example.com",
      environment: "staging",
      criticality: "low",
    });
    mockQuery.mockResolvedValueOnce({ rows: [resourceRow()], rowCount: 1 });

    await repo.save(resource);

    const [, params] = lastCall();
    // description, owner_team and metadata are the nullable columns.
    expect(params[6]).toBeNull();
    expect(params[8]).toBeNull();
    expect(params[9]).toBeNull();
  });

  it("maps RETURNING * onto a fully populated entity", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [resourceRow()], rowCount: 1 });

    const saved = await repo.save(makeResource());

    expectFullMapping(saved);
    expect(saved).toBeInstanceOf(Resource);
  });

  it("propagates a database error instead of swallowing it", async () => {
    const repo = newRepo();
    mockQuery.mockRejectedValue(new Error("simulated database failure"));

    await expect(repo.save(makeResource())).rejects.toThrow(
      "simulated database failure",
    );
  });
});

/* ========================================================================== */
/* findById                                                                    */
/* ========================================================================== */

describe("PostgresResourceRepository.findById", () => {
  it("maps every field of the snake_case row onto the domain object", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [resourceRow()], rowCount: 1 });

    const found = await repo.findById(RESOURCE_ID);

    expectFullMapping(found!);
    expect(found).toBeInstanceOf(Resource);
  });

  it("returns null when the row does not exist", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 });

    await expect(repo.findById("ghost")).resolves.toBeNull();
  });

  it("binds the id as $1 and keeps it out of the query text", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 });

    await repo.findById(RESOURCE_ID);

    const [sql, params] = lastCall();
    expect(sql).toContain("SELECT * FROM plus_resources WHERE id = $1");
    expect(sql).not.toContain(RESOURCE_ID);
    expect(params).toEqual([RESOURCE_ID]);
  });

  it("rejects on a database error rather than reporting 'not found'", async () => {
    const repo = newRepo();
    mockQuery.mockRejectedValue(new Error("simulated database failure"));

    await expect(repo.findById(RESOURCE_ID)).rejects.toThrow(
      "simulated database failure",
    );
  });
});

/* ========================================================================== */
/* Filtered reads                                                              */
/* ========================================================================== */

describe("PostgresResourceRepository — filtered reads", () => {
  it("findByType binds the type and orders newest first", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [resourceRow()], rowCount: 1 });

    const rows = await repo.findByType("database");

    const [sql, params] = lastCall();
    expect(sql).toContain("WHERE type = $1 ORDER BY created_at DESC");
    expect(sql).not.toContain("database");
    expect(params).toEqual(["database"]);
    expectFullMapping(rows[0]);
  });

  it("findByEnvironment binds the environment", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [resourceRow()], rowCount: 1 });

    await repo.findByEnvironment("production");

    const [sql, params] = lastCall();
    expect(sql).toContain("WHERE environment = $1 ORDER BY created_at DESC");
    expect(sql).not.toContain("production");
    expect(params).toEqual(["production"]);
  });

  it("findByCriticality binds the criticality", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [resourceRow()], rowCount: 1 });

    await repo.findByCriticality("critical");

    const [sql, params] = lastCall();
    expect(sql).toContain("WHERE criticality = $1 ORDER BY created_at DESC");
    // The BOUND value must not be interpolated — note that the column name
    // itself contains the substring, so only the placeholder form is asserted.
    expect(sql).not.toContain("'critical'");
    expect(params).toEqual(["critical"]);
  });

  it("findActive filters on `active = TRUE` with no bound values", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [resourceRow()], rowCount: 1 });

    const rows = await repo.findActive();

    const [sql, params] = lastCall();
    expect(sql).toContain("WHERE active = TRUE");
    expect(params).toEqual([]);
    expectFullMapping(rows[0]);
  });

  it("list issues a parameterless full scan", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({
      rows: [resourceRow(), resourceRow({ id: "res-2" })],
      rowCount: 2,
    });

    const rows = await repo.list();

    const [sql, params] = lastCall();
    expect(sql).toContain("SELECT * FROM plus_resources ORDER BY created_at DESC");
    expect(params).toEqual([]);
    expect(rows).toHaveLength(2);
    expect(rows[1].id).toBe("res-2");
  });

  it("an empty result set maps to an empty list, not to an error", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 });

    await expect(repo.list()).resolves.toEqual([]);
  });

  it("a database error rejects instead of resolving to an empty list", async () => {
    const repo = newRepo();
    mockQuery.mockRejectedValue(new Error("simulated database failure"));

    await expect(repo.findByType("web")).rejects.toThrow(
      "simulated database failure",
    );
    await expect(repo.findByEnvironment("staging")).rejects.toThrow(
      "simulated database failure",
    );
    await expect(repo.findByCriticality("low")).rejects.toThrow(
      "simulated database failure",
    );
    await expect(repo.findActive()).rejects.toThrow(
      "simulated database failure",
    );
    await expect(repo.list()).rejects.toThrow("simulated database failure");
  });
});

/* ========================================================================== */
/* NULL columns                                                                */
/* ========================================================================== */

describe("PostgresResourceRepository — NULL columns", () => {
  it("maps a NULL TEXT[] to [] and NULL optionals to undefined", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({
      rows: [
        resourceRow({
          description: null,
          tags: null,
          owner_team: null,
          metadata: null,
        }),
      ],
      rowCount: 1,
    });

    const found = await repo.findById(RESOURCE_ID);

    expect(found!.tags).toEqual([]); // .includes() must not throw on undefined
    expect(found!.description).toBeUndefined();
    expect(found!.ownerTeam).toBeUndefined();
    expect(found!.metadata).toBeUndefined();
    // `null` must never leak through — `undefined` is the contract.
    expect(found!.description).not.toBeNull();
    expect(found!.ownerTeam).not.toBeNull();
    expect(found!.metadata).not.toBeNull();
  });

  it("keeps a populated TEXT[] as a real JS array", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({
      rows: [resourceRow({ tags: ["pci"] })],
      rowCount: 1,
    });

    const found = await repo.findById(RESOURCE_ID);

    expect(found!.tags).toEqual(["pci"]);
    expect(Array.isArray(found!.tags)).toBe(true);
  });

  it("maps a NULL active flag to false — fail-closed, never true", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({
      rows: [resourceRow({ active: null })],
      rowCount: 1,
    });

    const found = await repo.findById(RESOURCE_ID);

    expect(found!.active).toBe(false);
  });

  it("passes a driver string timestamp through unchanged", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({
      rows: [
        resourceRow({
          created_at: "2026-01-01T00:00:00.000Z",
          updated_at: "2026-02-01T00:00:00.000Z",
        }),
      ],
      rowCount: 1,
    });

    const found = await repo.findById(RESOURCE_ID);

    expect(found!.createdAt).toEqual(new Date("2026-01-01T00:00:00.000Z"));
    expect(found!.updatedAt).toEqual(new Date("2026-02-01T00:00:00.000Z"));
  });
});

/* ========================================================================== */
/* search — dynamic WHERE, count + data                                        */
/* ========================================================================== */

describe("PostgresResourceRepository.search", () => {
  it("binds every criterion as a parameter and returns the parsed total", async () => {
    const repo = newRepo();
    mockQuery.mockImplementation((sql: string) =>
      sql.includes("COUNT(*)")
        ? { rows: [{ count: "7" }], rowCount: 1 }
        : { rows: [resourceRow()], rowCount: 1 },
    );

    const result = await repo.search({
      name: "primary",
      type: "database",
      environment: "production",
      criticality: "critical",
      tags: ["pci"],
      active: true,
      limit: 10,
      offset: 5,
    });

    const calls = mockQuery.mock.calls;
    expect(calls).toHaveLength(2);

    const [countSql] = calls[0];
    expect(countSql).toContain("SELECT COUNT(*) FROM plus_resources");
    expect(countSql).toContain("name ILIKE $1");
    expect(countSql).toContain("type = $2");
    expect(countSql).toContain("environment = $3");
    expect(countSql).toContain("criticality = $4");
    expect(countSql).toContain("tags && $5");
    expect(countSql).toContain("active = $6");
    expect(countSql).not.toContain("primary");
    expect(countSql).not.toContain("database");

    const [dataSql, dataParams] = calls[1];
    expect(dataSql).toContain("ORDER BY created_at DESC");
    expect(dataSql).toContain("LIMIT $7");
    expect(dataSql).toContain("OFFSET $8");
    // count and data share ONE `values` array by reference.
    expect(dataParams).toEqual([
      "%primary%",
      "database",
      "production",
      "critical",
      ["pci"],
      true,
      10,
      5,
    ]);

    expect(result.total).toBe(7);
    expect(result.resources).toHaveLength(1);
    expectFullMapping(result.resources[0]);
  });

  it("adds only the criteria that were supplied", async () => {
    const repo = newRepo();
    mockQuery.mockImplementation((sql: string) =>
      sql.includes("COUNT(*)")
        ? { rows: [{ count: "1" }], rowCount: 1 }
        : { rows: [resourceRow()], rowCount: 1 },
    );

    await repo.search({ type: "web", active: false });

    const [countSql] = mockQuery.mock.calls[0];
    expect(countSql).toContain("type = $1");
    expect(countSql).toContain("active = $2");
    expect(countSql).not.toContain("name ILIKE");
    expect(countSql).not.toContain("tags &&");
    expect(countSql).not.toContain("LIMIT");
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
    expect(result.resources).toEqual([]);
  });

  it("skips an EMPTY tags array instead of binding a match-all predicate", async () => {
    const repo = newRepo();
    mockQuery.mockImplementation((sql: string) =>
      sql.includes("COUNT(*)")
        ? { rows: [{ count: "0" }], rowCount: 1 }
        : { rows: [], rowCount: 1 },
    );

    await repo.search({ tags: [] });

    const [countSql] = mockQuery.mock.calls[0];
    expect(countSql).not.toContain("tags &&");
    expect(countSql).not.toContain("WHERE");
  });

  it("propagates a count failure instead of returning total 0", async () => {
    const repo = newRepo();
    mockQuery.mockRejectedValue(new Error("simulated database failure"));

    await expect(repo.search({ type: "web" })).rejects.toThrow(
      "simulated database failure",
    );
  });

  it("propagates a data failure instead of reporting an empty page", async () => {
    const repo = newRepo();
    mockQuery.mockImplementation((sql: string) =>
      sql.includes("COUNT(*)")
        ? { rows: [{ count: "3" }], rowCount: 1 }
        : Promise.reject(new Error("simulated database failure")),
    );

    await expect(repo.search({ type: "web" })).rejects.toThrow(
      "simulated database failure",
    );
  });
});

/* ========================================================================== */
/* delete                                                                      */
/* ========================================================================== */

describe("PostgresResourceRepository.delete", () => {
  it("returns true when a row was deleted and false when it was not", async () => {
    const repo = newRepo();

    mockQuery.mockResolvedValueOnce({ rows: [{ id: RESOURCE_ID }], rowCount: 1 });
    await expect(repo.delete(RESOURCE_ID)).resolves.toBe(true);

    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 });
    await expect(repo.delete("ghost")).resolves.toBe(false);

    const [sql, params] = lastCall();
    expect(sql).toContain("DELETE FROM plus_resources WHERE id = $1 RETURNING id");
    expect(sql).not.toContain("ghost");
    expect(params).toEqual(["ghost"]);
  });

  it("treats a NULL rowCount as 'nothing deleted' rather than throwing", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: null });

    await expect(repo.delete(RESOURCE_ID)).resolves.toBe(false);
  });

  it("propagates a database error instead of reporting a failed delete", async () => {
    const repo = newRepo();
    mockQuery.mockRejectedValue(new Error("simulated database failure"));

    await expect(repo.delete(RESOURCE_ID)).rejects.toThrow(
      "simulated database failure",
    );
  });
});

/* ========================================================================== */
/* Lifecycle — initializeTable / isHealthy / close                             */
/* ========================================================================== */

describe("PostgresResourceRepository — lifecycle", () => {
  it("provisions plus_resources and its indexes on construction", async () => {
    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 1 });
    new PostgresResourceRepository(DB_URL);

    const [sql] = mockQuery.mock.calls[0];
    expect(sql).toContain("CREATE TABLE IF NOT EXISTS plus_resources");
    for (const column of [
      "id VARCHAR(255) PRIMARY KEY",
      "name VARCHAR(255) NOT NULL",
      "type VARCHAR(50) NOT NULL",
      "endpoint TEXT NOT NULL",
      "environment VARCHAR(50) NOT NULL",
      "criticality VARCHAR(20) NOT NULL",
      "tags TEXT[] DEFAULT '{}'",
      "owner_team VARCHAR(255)",
      "metadata JSONB",
      "active BOOLEAN DEFAULT TRUE",
    ]) {
      expect(sql).toContain(column);
    }
    expect(sql).toContain(
      "CREATE INDEX IF NOT EXISTS idx_plus_resources_type ON plus_resources(type)",
    );
    expect(sql).toContain(
      "CREATE INDEX IF NOT EXISTS idx_plus_resources_tags ON plus_resources USING GIN(tags)",
    );
    await Promise.resolve(); // let the fire-and-forget promise settle
  });

  it("logs rather than throws when the DDL fails", async () => {
    mockQuery.mockRejectedValue(new Error("permission denied"));

    expect(() => new PostgresResourceRepository(DB_URL)).not.toThrow();
    await Promise.resolve();
    await Promise.resolve();
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
/* Circuit breaker                                                             */
/* ========================================================================== */

describe("PostgresResourceRepository — circuit breaker", () => {
  it("rejects without touching the database once the breaker is OPEN", async () => {
    const repo = newRepo();
    // Five consecutive failures trip the breaker (failureThreshold = 5).
    mockQuery.mockRejectedValue(new Error("simulated database failure"));

    for (let i = 0; i < 5; i++) {
      await expect(repo.findById(RESOURCE_ID)).rejects.toThrow();
    }
    const callsWhenOpen = mockQuery.mock.calls.length;

    await expect(repo.findById(RESOURCE_ID)).rejects.toThrow(
      "PostgreSQL circuit breaker is OPEN — database is critical, cannot degrade",
    );
    // The guarded call must not reach the pool.
    expect(mockQuery.mock.calls.length).toBe(callsWhenOpen);
  });

  it("reports a failed health check instead of throwing when open", async () => {
    const repo = newRepo();
    mockQuery.mockRejectedValue(new Error("simulated database failure"));

    for (let i = 0; i < 5; i++) {
      await repo.isHealthy();
    }

    await expect(repo.isHealthy()).resolves.toBe(false);
  });
});

/* ========================================================================== */
/* Parameterization sweep                                                      */
/* ========================================================================== */

describe("PostgresResourceRepository — parameterized SQL", () => {
  it("no user value ever appears in any query string", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValue({ rows: [resourceRow()], rowCount: 1 });

    await repo.findById(RESOURCE_ID);
    await repo.findByType("database");
    await repo.findByEnvironment("production");
    await repo.findByCriticality("critical");
    await repo.findActive();
    await repo.list();
    await repo.search({ name: "primary", type: "database" });
    await repo.delete(RESOURCE_ID);

    expect(mockQuery.mock.calls.length).toBeGreaterThanOrEqual(8);
    for (const [sql, rawParams] of mockQuery.mock.calls) {
      const params = rawParams ?? [];
      expect(typeof sql).toBe("string");
      expect(sql).not.toContain(RESOURCE_ID);
      expect(sql).not.toContain("primary");
      expect(sql).not.toContain("production");
      // NB: the literal `critical` is a substring of the `criticality` column
      // name, so only the quoted (interpolated) form is meaningful here.
      expect(sql).not.toContain("'critical'");
      // Static statement, bound placeholders — no string interpolation.
      expect(sql).not.toMatch(/'db-prod/);
      if (params.length > 0) expect(sql).toMatch(/\$\d/);
      expect(Array.isArray(params)).toBe(true);
    }
  });
});
