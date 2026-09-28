/**
 * S2 — `PostgresChallengeRepository` unit tests (mocked `pg`).
 *
 * WHY A MOCKED CLIENT
 * -------------------
 * The repository constructs `new Pool({connectionString})` internally and
 * exposes no injection seam, so `pg` is mocked at module level and every
 * assertion inspects the exact `(sql, params)` pair the repository sends.
 * No live database, no Docker, no network.
 *
 * WHAT IS PINNED HERE
 * 1. SECURITY — NO PLAINTEXT PIN, EVER. `ChallengeService` hands over a
 *    challenge whose `metadata.generatedPin` still holds the PIN; the
 *    repository is the boundary that strips it on EVERY write path. The
 *    INSERT/UPDATE parameters must carry `pin_hmac` ($10) and `pin_salt`
 *    ($11) and must never carry the PIN. This is a live security property,
 *    not a style choice.
 * 2. Row → domain mapping: rows shaped exactly as `pg` returns them
 *    (snake_case, `Date` for `timestamptz`, JS array for `TEXT[]`, an
 *    already-parsed object for `jsonb`) come back as fully populated
 *    camelCase `ChallengeProps`, with Unix-ms timestamps.
 * 3. Defaults and NULLs: NULL optional columns → `undefined`, not `null`
 *    (that is what broke `.includes()` in the sibling repositories).
 * 4. `findPendingByUserId` binds the status list as a `text[]` parameter —
 *    no status literal lands in the SQL text.
 * 5. `update` is deliberately NOT an upsert: a missing row throws.
 * 6. Error propagation: a database error rejects, never "not found".
 */

const mockQuery = jest.fn();

jest.mock("pg", () => ({
  Pool: jest.fn(() => ({
    query: (text: string, values?: unknown[]) => mockQuery(text, values),
    on: jest.fn(),
    end: jest.fn(),
  })),
}));

import { PostgresChallengeRepository } from "../../plus/infrastructure/repositories/PostgresChallengeRepository";
import type { ChallengeProps } from "../../plus/domain/services/challenge";

const DB_URL = "postgresql://user:secret@localhost:5432/cybervault";

const { Pool } = jest.requireMock("pg") as { Pool: jest.Mock };

/** Builds a repo and drops the constructor's fire-and-forget DDL call. */
function newRepo(): PostgresChallengeRepository {
  const repo = new PostgresChallengeRepository(DB_URL);
  mockQuery.mockClear();
  return repo;
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
/* Fixtures                                                                    */
/* -------------------------------------------------------------------------- */

const PLAINTEXT_PIN = "482913";

/** A `challenges` row exactly as `pg` would hand it back. */
function challengeRow(overrides: Record<string, unknown> = {}) {
  return {
    id: "ch-1",
    user_id: "user-1",
    resource_id: "resource-1",
    operation: "READ",
    secret_ref: "secret-ref-1",
    device_id: "device-1",
    type: "step_up",
    status: "pending",
    nonce: "bm9uY2UtYmFzZTY0",
    pin_hmac: "pin-hmac-b64",
    pin_salt: "pin-salt-b64",
    email_sent_at: new Date("2026-01-01T00:01:00.000Z"),
    accessed_at: null,
    completed_at: null,
    expires_at: new Date("2026-01-01T00:05:00.000Z"),
    attempts: 1,
    max_attempts: 3,
    risk_score: 42,
    risk_reasons: ["new_device", "impossible_travel"],
    assurance_level: 3,
    created_at: new Date("2026-01-01T00:00:00.000Z"),
    updated_at: new Date("2026-01-01T00:02:00.000Z"),
    // jsonb arrives ALREADY PARSED — never a JSON string.
    metadata: { requestId: "req-1" },
    ...overrides,
  };
}

function makeChallenge(overrides: Partial<ChallengeProps> = {}): ChallengeProps {
  return {
    id: "ch-1",
    userId: "user-1",
    resourceId: "resource-1",
    operation: "READ",
    secretRef: "secret-ref-1",
    deviceId: "device-1",
    type: "step_up",
    status: "pending",
    nonce: "bm9uY2UtYmFzZTY0",
    pinHmac: "pin-hmac-b64",
    pinSalt: "pin-salt-b64",
    emailSentAt: Date.parse("2026-01-01T00:01:00.000Z"),
    expiresAt: Date.parse("2026-01-01T00:05:00.000Z"),
    attempts: 1,
    maxAttempts: 3,
    riskScore: 42,
    riskReasons: ["new_device", "impossible_travel"],
    assuranceLevel: 3,
    createdAt: Date.parse("2026-01-01T00:00:00.000Z"),
    updatedAt: Date.parse("2026-01-01T00:02:00.000Z"),
    metadata: { requestId: "req-1" },
    ...overrides,
  };
}

/** Hard regression assertion: every field of the mapped domain object. */
function expectFullMapping(challenge: ChallengeProps): void {
  expect(challenge.id).toBe("ch-1");
  expect(challenge.userId).toBe("user-1");
  expect(challenge.resourceId).toBe("resource-1");
  expect(challenge.operation).toBe("READ");
  expect(challenge.secretRef).toBe("secret-ref-1");
  expect(challenge.deviceId).toBe("device-1");
  expect(challenge.type).toBe("step_up");
  expect(challenge.status).toBe("pending");
  expect(challenge.nonce).toBe("bm9uY2UtYmFzZTY0");
  expect(challenge.pinHmac).toBe("pin-hmac-b64");
  expect(challenge.pinSalt).toBe("pin-salt-b64");
  // TIMESTAMPTZ → Date → Unix ms.
  expect(challenge.emailSentAt).toBe(Date.parse("2026-01-01T00:01:00.000Z"));
  expect(challenge.accessedAt).toBeUndefined();
  expect(challenge.completedAt).toBeUndefined();
  expect(challenge.expiresAt).toBe(Date.parse("2026-01-01T00:05:00.000Z"));
  expect(challenge.attempts).toBe(1);
  expect(challenge.maxAttempts).toBe(3);
  expect(challenge.riskScore).toBe(42);
  expect(challenge.riskReasons).toEqual(["new_device", "impossible_travel"]);
  expect(challenge.assuranceLevel).toBe(3);
  expect(challenge.createdAt).toBe(Date.parse("2026-01-01T00:00:00.000Z"));
  expect(challenge.updatedAt).toBe(Date.parse("2026-01-01T00:02:00.000Z"));
  expect(challenge.metadata).toEqual({ requestId: "req-1" });
}

/* ========================================================================== */
/* SECURITY: no plaintext PIN ever reaches the database                        */
/* ========================================================================== */

describe("PostgresChallengeRepository — no plaintext PIN, ever", () => {
  it("save binds pin_hmac/pin_salt and strips metadata.generatedPin", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [challengeRow()], rowCount: 1 });

    await repo.save(
      makeChallenge({ metadata: { generatedPin: PLAINTEXT_PIN, requestId: "req-1" } }),
    );

    const [sql, params] = lastCall();
    expect(sql).toContain("INSERT INTO challenges");
    // Verification material — these two ARE stored.
    expect(params[9]).toBe("pin-hmac-b64"); // $10 pin_hmac
    expect(params[10]).toBe("pin-salt-b64"); // $11 pin_salt
    // $23 metadata: `generatedPin` dropped, sibling keys preserved.
    expect(params[22]).toBe(JSON.stringify({ requestId: "req-1" }));
    expect(params).toHaveLength(23);

    // The PIN itself reaches neither the SQL text nor the parameter array.
    const persisted = JSON.stringify(mockQuery.mock.calls);
    expect(persisted).not.toContain(PLAINTEXT_PIN);
    expect(persisted).not.toContain("generatedPin");
    expect(sql).not.toContain(PLAINTEXT_PIN);
    expect(params).not.toContain(PLAINTEXT_PIN);
  });

  it("save writes SQL NULL metadata when the PIN was the only key", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [challengeRow()], rowCount: 1 });

    await repo.save(
      makeChallenge({ metadata: { generatedPin: PLAINTEXT_PIN } }),
    );

    const [, params] = lastCall();
    // `JSON.stringify(null)` → "null"; a jsonb column reads that back as a
    // JSON null, and `toChallengeProps` maps NULL to `undefined`.
    expect(params[22]).toBe("null");
    const persisted = JSON.stringify(mockQuery.mock.calls);
    expect(persisted).not.toContain(PLAINTEXT_PIN);
  });

  it("update strips generatedPin on the rewrite path too", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [challengeRow()], rowCount: 1 });

    await repo.update(
      makeChallenge({ metadata: { generatedPin: PLAINTEXT_PIN, attempt: 1 } }),
    );

    const [sql, params] = lastCall();
    expect(sql).toContain("UPDATE challenges SET");
    expect(params[9]).toBe("pin-hmac-b64");
    expect(params[10]).toBe("pin-salt-b64");
    expect(params[22]).toBe(JSON.stringify({ attempt: 1 }));
    const persisted = JSON.stringify(mockQuery.mock.calls);
    expect(persisted).not.toContain(PLAINTEXT_PIN);
    expect(persisted).not.toContain("generatedPin");
  });
});

/* ========================================================================== */
/* save                                                                        */
/* ========================================================================== */

describe("PostgresChallengeRepository.save", () => {
  it("upserts with all 23 columns bound positionally", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [challengeRow()], rowCount: 1 });

    await repo.save(makeChallenge());

    const [sql, params] = lastCall();
    expect(sql).toContain("INSERT INTO challenges");
    expect(sql).toMatch(/ON CONFLICT \(id\) DO UPDATE SET/);
    expect(sql).toContain("RETURNING *");
    expect(params).toHaveLength(23);
    // id is $1 on BOTH statements — the convention `toColumnValues` pins.
    expect(params[0]).toBe("ch-1");
    expect(sql).toContain("$1, $2, $3, $4, $5, $6, $7, $8,");
  });

  it("binds Unix-ms timestamps as Date objects in the right positions", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [challengeRow()], rowCount: 1 });

    await repo.save(makeChallenge());

    const [, params] = lastCall();
    expect(params[11]).toEqual(new Date("2026-01-01T00:01:00.000Z")); // $12 email_sent_at
    expect(params[14]).toEqual(new Date("2026-01-01T00:05:00.000Z")); // $15 expires_at
    expect(params[20]).toEqual(new Date("2026-01-01T00:00:00.000Z")); // $21 created_at
    expect(params[21]).toEqual(new Date("2026-01-01T00:02:00.000Z")); // $22 updated_at
    // Absent optional timestamps become SQL NULL, not undefined.
    expect(params[12]).toBeNull(); // $13 accessed_at
    expect(params[13]).toBeNull(); // $14 completed_at
  });

  it("returns the mapped row from RETURNING *", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [challengeRow()], rowCount: 1 });

    const saved = await repo.save(makeChallenge());

    expectFullMapping(saved);
  });

  it("propagates a database error instead of swallowing it", async () => {
    const repo = newRepo();
    mockQuery.mockRejectedValue(new Error("simulated database failure"));

    await expect(repo.save(makeChallenge())).rejects.toThrow(
      "simulated database failure",
    );
  });
});

/* ========================================================================== */
/* findById / findByUserId / findPendingByUserId                               */
/* ========================================================================== */

describe("PostgresChallengeRepository — reads", () => {
  it("findById maps every field of the snake_case row", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [challengeRow()], rowCount: 1 });

    const found = await repo.findById("ch-1");

    const [sql, params] = lastCall();
    expect(sql).toBe("SELECT * FROM challenges WHERE id = $1");
    expect(sql).not.toContain("ch-1");
    expect(params).toEqual(["ch-1"]);
    expectFullMapping(found!);
  });

  it("findById returns null for an unknown id", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 });

    await expect(repo.findById("ghost")).resolves.toBeNull();
  });

  it("findByUserId orders newest first and maps every row", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({
      rows: [challengeRow(), challengeRow({ id: "ch-2", status: "completed" })],
      rowCount: 2,
    });

    const found = await repo.findByUserId("user-1");

    const [sql, params] = lastCall();
    expect(sql).toBe(
      "SELECT * FROM challenges WHERE user_id = $1 ORDER BY created_at DESC",
    );
    expect(sql).not.toContain("user-1");
    expect(params).toEqual(["user-1"]);
    expect(found).toHaveLength(2);
    expect(found[0].id).toBe("ch-1");
    expect(found[1].status).toBe("completed");
  });

  it("findPendingByUserId binds the status list as a text[] parameter", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [challengeRow()], rowCount: 1 });

    await repo.findPendingByUserId("user-1");

    const [sql, params] = lastCall();
    expect(sql).toContain("WHERE user_id = $1 AND status = ANY($2::text[])");
    expect(sql).toContain("ORDER BY created_at DESC");
    // The list travels as a bound JS array, never inlined into the SQL.
    expect(params).toEqual([
      "user-1",
      ["pending", "email_sent", "url_accessed"],
    ]);
    expect(sql).not.toContain("pending");
    expect(sql).not.toContain("email_sent");
    expect(sql).not.toContain("url_accessed");
    expect(sql).not.toContain("completed");
  });

  it("a database error rejects instead of resolving to null or []", async () => {
    const repo = newRepo();
    mockQuery.mockRejectedValue(new Error("simulated database failure"));

    const outcome = await repo
      .findById("ch-1")
      .then(() => "resolved")
      .catch((error: Error) => error.message);
    expect(outcome).toBe("simulated database failure");

    mockQuery.mockRejectedValue(new Error("simulated database failure"));
    await expect(repo.findByUserId("user-1")).rejects.toThrow(
      "simulated database failure",
    );
    mockQuery.mockRejectedValue(new Error("simulated database failure"));
    await expect(repo.findPendingByUserId("user-1")).rejects.toThrow(
      "simulated database failure",
    );
  });
});

/* ========================================================================== */
/* NULL handling on read                                                       */
/* ========================================================================== */

describe("PostgresChallengeRepository — NULL columns", () => {
  it("maps NULL optionals to undefined, never null", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({
      rows: [
        challengeRow({
          device_id: null,
          email_sent_at: null,
          accessed_at: null,
          completed_at: null,
          risk_score: null,
          risk_reasons: null,
          metadata: null,
        }),
      ],
      rowCount: 1,
    });

    const found = await repo.findById("ch-1");

    expect(found!.deviceId).toBeUndefined();
    expect(found!.emailSentAt).toBeUndefined();
    expect(found!.accessedAt).toBeUndefined();
    expect(found!.completedAt).toBeUndefined();
    expect(found!.riskScore).toBeUndefined();
    // NULL TEXT[] → undefined here (documented current behaviour); what must
    // never happen is `null`, which callers cannot distinguish from "key
    // present with a null value".
    expect(found!.riskReasons).toBeUndefined();
    expect(found!.metadata).toBeUndefined();
    // NOT NULL columns are still populated.
    expect(found!.nonce).toBe("bm9uY2UtYmFzZTY0");
    expect(found!.pinHmac).toBe("pin-hmac-b64");
  });
});

/* ========================================================================== */
/* update — deliberately not an upsert                                         */
/* ========================================================================== */

describe("PostgresChallengeRepository.update", () => {
  it("rewrites every column with `WHERE id = $1` and returns the row", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [challengeRow()], rowCount: 1 });

    const updated = await repo.update(
      makeChallenge({ status: "email_sent", attempts: 2 }),
    );

    const [sql, params] = lastCall();
    expect(sql).toContain("UPDATE challenges SET");
    expect(sql).toContain("WHERE id = $1");
    expect(sql).toContain("RETURNING *");
    expect(sql).not.toMatch(/ON CONFLICT/);
    expect(params).toHaveLength(23);
    expect(params[0]).toBe("ch-1"); // id binds $1 (the WHERE placeholder)
    expect(params[7]).toBe("email_sent"); // $8 status
    expect(params[15]).toBe(2); // $16 attempts
    expectFullMapping(updated);
    expect(updated.status).toBe("pending"); // row says pending — mapped, not guessed
  });

  it("throws when the row does not exist instead of inserting it", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 });

    await expect(repo.update(makeChallenge())).rejects.toThrow(
      "Challenge not found for update: ch-1",
    );
    // NOT an upsert: no INSERT was ever issued.
    for (const [sql] of mockQuery.mock.calls) {
      expect(sql).not.toContain("INSERT INTO challenges");
    }
  });

  it("propagates a database error", async () => {
    const repo = newRepo();
    mockQuery.mockRejectedValue(new Error("simulated database failure"));

    await expect(repo.update(makeChallenge())).rejects.toThrow(
      "simulated database failure",
    );
  });
});

/* ========================================================================== */
/* delete / cleanupExpired                                                     */
/* ========================================================================== */

describe("PostgresChallengeRepository — deletes", () => {
  it("delete returns true on a hit and false on a miss", async () => {
    const repo = newRepo();

    mockQuery.mockResolvedValueOnce({ rows: [{ id: "ch-1" }], rowCount: 1 });
    await expect(repo.delete("ch-1")).resolves.toBe(true);

    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 });
    await expect(repo.delete("ghost")).resolves.toBe(false);

    const [sql, params] = lastCall();
    expect(sql).toContain("DELETE FROM challenges WHERE id = $1 RETURNING id");
    expect(sql).not.toContain("ghost");
    expect(params).toEqual(["ghost"]);
  });

  it("cleanupExpired deletes only rows past their own expiry and returns the count", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({
      rows: [{ id: "a" }, { id: "b" }, { id: "c" }],
      rowCount: 3,
    });

    await expect(repo.cleanupExpired()).resolves.toBe(3);

    const [sql, params] = lastCall();
    expect(sql).toContain("DELETE FROM challenges WHERE expires_at <= NOW() RETURNING id");
    // No status filter: a completed challenge inside its window SURVIVES —
    // `ChallengeService.findCompletedChallenge()` depends on that.
    expect(sql).not.toContain("status");
    expect(params).toEqual([]);
  });

  it("cleanupExpired returns 0 when nothing expired", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 });

    await expect(repo.cleanupExpired()).resolves.toBe(0);
  });

  it("propagates database errors from both delete paths", async () => {
    const repo = newRepo();
    mockQuery.mockRejectedValue(new Error("simulated database failure"));
    await expect(repo.delete("ch-1")).rejects.toThrow("simulated database failure");

    mockQuery.mockRejectedValue(new Error("simulated database failure"));
    await expect(repo.cleanupExpired()).rejects.toThrow("simulated database failure");
  });
});

/* ========================================================================== */
/* Lifecycle                                                                   */
/* ========================================================================== */

describe("PostgresChallengeRepository — lifecycle", () => {
  it("provisions the challenges table with the security-relevant columns", async () => {
    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 1 });
    new PostgresChallengeRepository(DB_URL);

    const [sql] = mockQuery.mock.calls[0];
    expect(sql).toContain("CREATE TABLE IF NOT EXISTS challenges");
    for (const column of [
      "pin_hmac TEXT NOT NULL",
      "pin_salt TEXT NOT NULL",
      "nonce TEXT NOT NULL",
      "risk_reasons TEXT[] DEFAULT '{}'",
      "metadata JSONB",
      "expires_at TIMESTAMP WITH TIME ZONE NOT NULL",
      "assurance_level SMALLINT NOT NULL DEFAULT 3",
    ]) {
      expect(sql).toContain(column);
    }
    expect(sql).toContain(
      "CREATE INDEX IF NOT EXISTS idx_challenges_user_status ON challenges(user_id, status)",
    );
    await Promise.resolve(); // settle the fire-and-forget promise
  });

  it("registers an idle-client error listener so a pool error cannot crash the process", () => {
    new PostgresChallengeRepository(DB_URL);

    const pool = Pool.mock.results[Pool.mock.results.length - 1].value as {
      on: jest.Mock;
    };
    expect(pool.on).toHaveBeenCalledWith("error", expect.any(Function));
    // This repository exposes no `close()`/`isHealthy()` — its public
    // surface ends at `cleanupExpired()` (see `IChallengeRepository`).
  });
});

/* ========================================================================== */
/* Parameterization sweep                                                      */
/* ========================================================================== */

describe("PostgresChallengeRepository — parameterized SQL", () => {
  it("no user value ever appears in any query string", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValue({ rows: [challengeRow()], rowCount: 1 });

    await repo.findById("ch-1");
    await repo.findByUserId("user-1");
    await repo.findPendingByUserId("user-1");
    await repo.update(makeChallenge());
    await repo.save(makeChallenge({ metadata: { generatedPin: PLAINTEXT_PIN } }));
    await repo.delete("ch-1");

    expect(mockQuery.mock.calls.length).toBeGreaterThanOrEqual(6);
    for (const [sql, params] of mockQuery.mock.calls) {
      expect(typeof sql).toBe("string");
      expect(sql).not.toContain("user-1");
      expect(sql).not.toContain("ch-1");
      expect(sql).not.toContain("secret-ref-1");
      expect(sql).not.toContain("bm9uY2UtYmFzZTY0");
      expect(sql).not.toContain(PLAINTEXT_PIN);
      expect(sql).toMatch(/\$\d/);
      expect(Array.isArray(params)).toBe(true);
    }
  });
});
