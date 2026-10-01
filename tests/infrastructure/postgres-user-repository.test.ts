/**
 * S2 — `PostgresUserRepository` unit tests (mocked `pg`).
 *
 * WHY A MOCKED CLIENT
 * -------------------
 * The repository constructs `new Pool({connectionString})` internally and
 * exposes no injection seam, so `pg` is mocked at module level and every
 * assertion inspects the exact `(sql, params)` pair the repository sends.
 * No live database, no Docker, no network. This is the Core authentication
 * repository (`src/infrastructure/api/auth.ts` is its only caller), so the
 * two things that matter are that the row maps to `StoredUser` correctly and
 * that a database error is never mistaken for "no such account" — a NULL
 * result and an outage MUST be distinguishable during login.
 *
 * WHAT IS PINNED HERE
 * 1. Row → domain mapping: `users` rows shaped exactly as `pg` returns them
 *    (snake_case `user_id`, `hash`, `salt`) come back as a camelCase
 *    `StoredUser` with every field populated.
 * 2. NULL / miss: an empty result set → `null`, never a throw.
 * 3. Parameterization: the email (and every credential column) travels as a
 *    bound parameter, never in the query text.
 * 4. Error propagation: a database error REJECTS. An outage must not read as
 *    "unknown email", or every login would silently fall through to the
 *    wrong failure branch.
 * 5. Lifecycle: the constructor's fire-and-forget DDL and `close()`.
 */

const mockQuery = jest.fn();

jest.mock("pg", () => ({
  Pool: jest.fn(() => ({
    query: (text: string, values?: unknown[]) => mockQuery(text, values),
    on: jest.fn(),
    end: jest.fn(),
  })),
}));

import { PostgresUserRepository } from "../../src/infrastructure/repositories/PostgresUserRepository";
import type { StoredUser } from "../../src/infrastructure/api/auth";

const DB_URL = "postgresql://user:secret@localhost:5432/cybervault";
const EMAIL = "alice@example.com";

const { Pool } = jest.requireMock("pg") as { Pool: jest.Mock };

function newRepo(): PostgresUserRepository {
  const repo = new PostgresUserRepository(DB_URL);
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

/** A `users` row exactly as `pg` would hand it back. */
function userRow(overrides: Record<string, unknown> = {}) {
  return {
    user_id: "user-42",
    email: EMAIL,
    hash: "scrypt$deadbeef",
    salt: "c2FsdC11",
    ...overrides,
  };
}

const CREATED: StoredUser = {
  userId: "user-42",
  email: EMAIL,
  hash: "scrypt$deadbeef",
  salt: "c2FsdC11",
};

/* ========================================================================== */
/* findByEmail                                                                 */
/* ========================================================================== */

describe("PostgresUserRepository.findByEmail", () => {
  it("maps every snake_case column onto the StoredUser shape", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [userRow()], rowCount: 1 });

    const found = await repo.findByEmail(EMAIL);

    // Hard regression assertion: every field, by name.
    expect(found).toEqual({
      userId: "user-42",
      email: EMAIL,
      hash: "scrypt$deadbeef",
      salt: "c2FsdC11",
    });
    expect(found!.userId).toBe("user-42"); // NOT `row.user_id` leaking through
    expect(found).not.toHaveProperty("user_id");
  });

  it("returns null when no account carries the email", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 });

    await expect(repo.findByEmail("ghost@example.com")).resolves.toBeNull();
  });

  it("binds the email as $1 and keeps it out of the query text", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [userRow()], rowCount: 1 });

    await repo.findByEmail(EMAIL);

    const [sql, params] = lastCall();
    expect(sql).toBe(
      "SELECT user_id, email, hash, salt FROM users WHERE email = $1",
    );
    expect(sql).not.toContain(EMAIL);
    expect(sql).not.toContain("@");
    expect(params).toEqual([EMAIL]);
  });

  it("rejects on a database error instead of reporting 'no such account'", async () => {
    const repo = newRepo();
    mockQuery.mockRejectedValue(new Error("simulated database failure"));

    const outcome = await repo
      .findByEmail(EMAIL)
      .then(() => "resolved")
      .catch((error: Error) => error.message);
    expect(outcome).toBe("simulated database failure");
  });
});

/* ========================================================================== */
/* create                                                                      */
/* ========================================================================== */

describe("PostgresUserRepository.create", () => {
  it("binds the four credential columns as parameters", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 1 });

    await expect(repo.create(CREATED)).resolves.toBeUndefined();

    const [sql, params] = lastCall();
    expect(sql).toBe(
      "INSERT INTO users (user_id, email, hash, salt) VALUES ($1, $2, $3, $4)",
    );
    expect(sql).not.toContain(EMAIL);
    expect(sql).not.toContain("user-42");
    expect(sql).not.toContain("scrypt$deadbeef");
    expect(params).toEqual(["user-42", EMAIL, "scrypt$deadbeef", "c2FsdC11"]);
  });

  it("propagates a database error (a failed INSERT must not look like success)", async () => {
    const repo = newRepo();
    mockQuery.mockRejectedValue(new Error("simulated database failure"));

    await expect(repo.create(CREATED)).rejects.toThrow(
      "simulated database failure",
    );
  });
});

/* ========================================================================== */
/* Lifecycle                                                                   */
/* ========================================================================== */

describe("PostgresUserRepository — lifecycle", () => {
  it("provisions the users table on construction", async () => {
    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 1 });
    new PostgresUserRepository(DB_URL);

    const [sql] = mockQuery.mock.calls[0];
    expect(sql).toContain("CREATE TABLE IF NOT EXISTS users");
    expect(sql).toContain("user_id VARCHAR(64) PRIMARY KEY");
    expect(sql).toContain("email VARCHAR(255) UNIQUE NOT NULL");
    expect(sql).toContain("hash VARCHAR(128) NOT NULL");
    expect(sql).toContain("salt VARCHAR(64) NOT NULL");
    expect(sql).toContain(
      "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)",
    );
    await Promise.resolve(); // settle the fire-and-forget promise
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

describe("PostgresUserRepository — parameterized SQL", () => {
  it("no credential value ever appears in a query string", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValue({ rows: [userRow()], rowCount: 1 });

    await repo.findByEmail(EMAIL);
    await repo.findByEmail("bob@example.com");
    await repo.create(CREATED);

    expect(mockQuery.mock.calls).toHaveLength(3);
    for (const [sql, params] of mockQuery.mock.calls) {
      expect(typeof sql).toBe("string");
      expect(sql).not.toContain(EMAIL);
      expect(sql).not.toContain("bob@example.com");
      expect(sql).not.toContain("user-42");
      expect(sql).not.toContain("scrypt$deadbeef");
      expect(sql).not.toContain("c2FsdC11");
      expect(sql).toMatch(/\$\d/);
      expect(Array.isArray(params)).toBe(true);
    }
  });
});
