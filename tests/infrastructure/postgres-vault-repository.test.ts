/**
 * S2 — `PostgresVaultRepository` unit tests (mocked `pg`).
 *
 * WHY A MOCKED CLIENT
 * -------------------
 * The repository constructs `new Pool({connectionString})` internally and
 * exposes no injection seam, so `pg` is mocked at module level and every
 * assertion inspects the exact `(sql, params)` pair the repository sends.
 * No live database, no Docker, no network.
 *
 * WHAT IS ALREADY PINNED ELSEWHERE — deliberately NOT repeated here
 * ------------------------------------------------------------------
 * `tests/infrastructure/optimistic-locking.test.ts` owns the H5 guarded-write
 * contract for this class: the blind upsert keeps its `ON CONFLICT` text, the
 * guarded path issues `UPDATE ... WHERE id = $1 AND lock_version = $9` and
 * never an `INSERT`, and a stale or missing row raises
 * `OptimisticLockConflictError`. `tests/infrastructure/row-mappers.test.ts`
 * owns `mapVaultRow` as a unit. This file covers everything between those two:
 * the public surface that had no repository-level test at all.
 *
 * WHAT IS PINNED HERE
 * 1. Row → domain mapping AT THE REPOSITORY BOUNDARY: a `vaults` row shaped
 *    exactly as `pg` returns it (snake_case keys, `Date` for `timestamptz`,
 *    an ALREADY-PARSED object for `jsonb`, a STRING for the `BIGINT
 *    lock_version`) comes back as a fully populated `Vault`.
 *    `encrypted_data` → `encryptedData` and `encryption_key_id` →
 *    `encryptionKeyId` are non-optional on the entity and were silently
 *    `undefined` before the row mapper existed, so both are pinned with hard
 *    equality assertions on EVERY read path, not merely `toBeDefined()`.
 * 2. NULL columns: `description`, `owner_id` and `metadata` normalise to
 *    `undefined`, never `null`, while the NOT NULL columns stay populated.
 * 3. Parameterization: ciphertext, vault names and owner ids travel only in
 *    the bound parameter array, never interpolated into SQL.
 * 4. Error propagation: a database error REJECTS on every method. An outage
 *    must never read as "no such vault" / "empty list" / "delete failed".
 * 5. `delete` reports hit/miss/NULL-rowCount distinctly.
 * 6. Lifecycle: the constructor's DDL failure is LOGGED not thrown, the idle-
 *    client error handler is registered and safe to fire, `isHealthy`,
 *    `close()`, and the circuit breaker's OPEN short-circuit.
 */

const mockQuery = jest.fn();

jest.mock("pg", () => ({
  Pool: jest.fn(() => ({
    query: (text: string, values?: unknown[]) => mockQuery(text, values),
    on: jest.fn(),
    end: jest.fn(),
  })),
}));

import { PostgresVaultRepository } from "../../src/infrastructure/repositories/PostgresVaultRepository";
import { Vault } from "../../src/domain/entities/vault";
import { VaultId } from "../../src/domain/value-objects/ids";
import { logger } from "../../src/shared/logger";

const DB_URL = "postgresql://user:secret@localhost:5432/cybervault";
const VAULT_ID = "v1";
const CIPHERTEXT = "ciphertext-blob";
const KEY_ID = "key-2026-01";
const OWNER_ID = "user-1";

const { Pool } = jest.requireMock("pg") as { Pool: jest.Mock };

function newRepo(): PostgresVaultRepository {
  const repo = new PostgresVaultRepository(DB_URL);
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
  // Silence (and make assertable) the repository's structured logging.
  jest.spyOn(logger, "info").mockImplementation(() => undefined);
  jest.spyOn(logger, "warn").mockImplementation(() => undefined);
  jest.spyOn(logger, "error").mockImplementation(() => undefined);
});

afterEach(() => {
  jest.restoreAllMocks();
});

/** Let the constructor's fire-and-forget `initializeTable()` settle. */
function flush(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve));
}

/* -------------------------------------------------------------------------- */
/* Row fixture — the exact shape `pg` hands back from a `vaults` SELECT         */
/* -------------------------------------------------------------------------- */

function vaultRow(overrides: Record<string, unknown> = {}) {
  return {
    id: VAULT_ID,
    name: "My Vault",
    description: "creds",
    encrypted_data: CIPHERTEXT,
    encryption_key_id: KEY_ID,
    owner_id: OWNER_ID,
    // JSONB arrives ALREADY PARSED by the driver's OID 3802 type parser.
    metadata: { color: "blue", tags: ["work"] },
    created_at: new Date("2026-01-01T00:00:00.000Z"),
    updated_at: new Date("2026-01-02T00:00:00.000Z"),
    // BIGINT arrives from `pg` as a STRING.
    lock_version: "7",
    ...overrides,
  };
}

/** Hard regression assertion: every field of the mapped domain object. */
function expectFullMapping(vault: Vault): void {
  expect(vault.id.toString()).toBe(VAULT_ID);
  expect(vault.name).toBe("My Vault");
  expect(vault.description).toBe("creds");
  // The two columns that used to be silently `undefined` after a spread.
  expect(vault.encryptedData).toBe(CIPHERTEXT);
  expect(vault.encryptedData).toBeDefined();
  expect(vault.encryptionKeyId).toBe(KEY_ID);
  expect(vault.encryptionKeyId).toBeDefined();
  expect(vault.ownerId).toBe(OWNER_ID);
  expect(vault.metadata).toEqual({ color: "blue", tags: ["work"] });
  expect(vault.createdAt).toEqual(new Date("2026-01-01T00:00:00.000Z"));
  expect(vault.updatedAt).toEqual(new Date("2026-01-02T00:00:00.000Z"));
  // BIGINT string → number, never "7".
  expect(vault.lockVersion).toBe(7);
  expect(typeof vault.lockVersion).toBe("number");
}

function makeVault(): Vault {
  return Vault.create({
    name: "My Vault",
    description: "creds",
    encryptedData: CIPHERTEXT,
    encryptionKeyId: KEY_ID,
    ownerId: OWNER_ID,
    metadata: { color: "blue" },
  });
}

/* ========================================================================== */
/* save (blind path — guarded H5 paths live in optimistic-locking.test.ts)     */
/* ========================================================================== */

describe("PostgresVaultRepository.save", () => {
  it("binds all nine columns positionally and never interpolates them", async () => {
    const repo = newRepo();
    const vault = makeVault();
    mockQuery.mockResolvedValueOnce({ rows: [vaultRow()], rowCount: 1 });

    await repo.save(vault);

    const [sql, params] = lastCall();
    expect(sql).toContain("INSERT INTO vaults");
    expect(params).toEqual([
      vault.id.toString(),
      "My Vault",
      "creds",
      CIPHERTEXT,
      KEY_ID,
      OWNER_ID,
      JSON.stringify({ color: "blue" }),
      vault.toPlainObject().createdAt,
      vault.toPlainObject().updatedAt,
    ]);
    expect(sql).not.toContain(CIPHERTEXT);
    expect(sql).not.toContain("My Vault");
    expect(sql).not.toContain(KEY_ID);
    expect(sql).not.toContain(OWNER_ID);
  });

  it("NULLs the optional columns the entity left unset", async () => {
    const repo = newRepo();
    const vault = Vault.create({
      name: "Bare",
      encryptedData: CIPHERTEXT,
      encryptionKeyId: KEY_ID,
    });
    mockQuery.mockResolvedValueOnce({
      rows: [vaultRow({ name: "Bare", description: null, owner_id: null, metadata: null })],
      rowCount: 1,
    });

    await repo.save(vault);

    const [, params] = lastCall();
    expect(params[2]).toBeNull(); // description
    expect(params[5]).toBeNull(); // owner_id
    expect(params[6]).toBeNull(); // metadata
  });

  it("maps RETURNING * onto a fully populated entity", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [vaultRow()], rowCount: 1 });

    const saved = await repo.save(makeVault());

    expect(saved).toBeInstanceOf(Vault);
    expectFullMapping(saved);
  });

  it("propagates a database error instead of swallowing it", async () => {
    const repo = newRepo();
    mockQuery.mockRejectedValue(new Error("simulated database failure"));

    await expect(repo.save(makeVault())).rejects.toThrow("simulated database failure");
    expect(logger.error).toHaveBeenCalled();
  });

  it("propagates a database error from a guarded save too", async () => {
    const repo = newRepo();
    mockQuery.mockRejectedValue(new Error("simulated database failure"));

    await expect(repo.save(makeVault(), 7)).rejects.toThrow("simulated database failure");
    expect(logger.error).toHaveBeenCalled();
  });

  it("still reports the conflict when the version probe itself fails", async () => {
    const repo = newRepo();
    mockQuery
      .mockResolvedValueOnce({ rows: [], rowCount: 0 }) // guarded UPDATE: no row
      .mockRejectedValueOnce(new Error("connection lost")); // SELECT lock_version

    await expect(repo.save(makeVault(), 3)).rejects.toMatchObject({
      code: "OPTIMISTIC_LOCK_CONFLICT",
      expectedVersion: 3,
      actualVersion: undefined,
    });
    // The probe failure degrades the report, it never masks the conflict.
    expect(logger.warn).toHaveBeenCalledWith(
      expect.stringContaining("Could not read lock_version"),
      expect.any(String),
    );
  });
});

/* ========================================================================== */
/* findById                                                                    */
/* ========================================================================== */

describe("PostgresVaultRepository.findById", () => {
  it("maps every column of the snake_case row onto the entity", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [vaultRow()], rowCount: 1 });

    const found = await repo.findById(VaultId.fromString(VAULT_ID));

    const [sql, params] = lastCall();
    expect(sql).toContain("FROM vaults");
    expect(sql).toContain("WHERE id = $1");
    expect(sql).toContain("encrypted_data, encryption_key_id");
    expect(sql).not.toContain(VAULT_ID);
    expect(params).toEqual([VAULT_ID]);
    expectFullMapping(found!);
  });

  it("returns null when the row does not exist", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 });

    await expect(repo.findById(VaultId.fromString("ghost"))).resolves.toBeNull();
  });

  it("normalises NULL optionals to undefined while keeping the NOT NULL columns", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({
      rows: [
        vaultRow({ description: null, owner_id: null, metadata: null }),
      ],
      rowCount: 1,
    });

    const found = await repo.findById(VaultId.fromString(VAULT_ID));

    expect(found!.description).toBeUndefined();
    expect(found!.ownerId).toBeUndefined();
    expect(found!.metadata).toBeUndefined();
    expect(found!.encryptedData).toBe(CIPHERTEXT);
    expect(found!.encryptionKeyId).toBe(KEY_ID);
    expect(found!.lockVersion).toBe(7);
  });

  it("rejects on a database error rather than reporting 'not found'", async () => {
    const repo = newRepo();
    mockQuery.mockRejectedValue(new Error("simulated database failure"));

    await expect(repo.findById(VaultId.fromString(VAULT_ID))).rejects.toThrow(
      "simulated database failure",
    );
    expect(logger.error).toHaveBeenCalled();
  });
});

/* ========================================================================== */
/* findByVaultIdAndOwnerId — the ownership boundary                            */
/* ========================================================================== */

describe("PostgresVaultRepository.findByVaultIdAndOwnerId", () => {
  it("binds BOTH the id and the owner and maps the row", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [vaultRow()], rowCount: 1 });

    const found = await repo.findByVaultIdAndOwnerId(VAULT_ID, OWNER_ID);

    const [sql, params] = lastCall();
    expect(sql).toContain("WHERE id = $1 AND owner_id = $2");
    expect(params).toEqual([VAULT_ID, OWNER_ID]);
    expect(sql).not.toContain(VAULT_ID);
    expect(sql).not.toContain(OWNER_ID);
    expectFullMapping(found!);
  });

  it("returns null when the owner does not match — the SQL must carry the predicate", async () => {
    const repo = newRepo();
    // A repository that dropped `owner_id = $2` would hand back the row here.
    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 });

    await expect(
      repo.findByVaultIdAndOwnerId(VAULT_ID, "someone-else"),
    ).resolves.toBeNull();

    expect(lastCall()[0]).toContain("WHERE id = $1 AND owner_id = $2");
    expect(lastCall()[1]).toEqual([VAULT_ID, "someone-else"]);
  });

  it("rejects on a database error instead of reporting 'not owned'", async () => {
    const repo = newRepo();
    mockQuery.mockRejectedValue(new Error("simulated database failure"));

    await expect(
      repo.findByVaultIdAndOwnerId(VAULT_ID, OWNER_ID),
    ).rejects.toThrow("simulated database failure");
    expect(logger.error).toHaveBeenCalled();
  });
});

/* ========================================================================== */
/* delete                                                                      */
/* ========================================================================== */

describe("PostgresVaultRepository.delete", () => {
  it("returns true on a hit and false on a miss", async () => {
    const repo = newRepo();

    mockQuery.mockResolvedValueOnce({ rows: [{ id: VAULT_ID }], rowCount: 1 });
    await expect(repo.delete(VaultId.fromString(VAULT_ID))).resolves.toBe(true);

    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 });
    await expect(repo.delete(VaultId.fromString("ghost"))).resolves.toBe(false);

    const [sql, params] = lastCall();
    expect(sql).toContain("DELETE FROM vaults");
    expect(sql).toContain("WHERE id = $1");
    expect(sql).toContain("RETURNING id");
    expect(sql).not.toContain("ghost");
    expect(params).toEqual(["ghost"]);
  });

  it("treats a NULL rowCount as 'nothing deleted' rather than throwing", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: null });

    await expect(repo.delete(VaultId.fromString(VAULT_ID))).resolves.toBe(false);
  });

  it("propagates a database error instead of reporting a failed delete", async () => {
    const repo = newRepo();
    mockQuery.mockRejectedValue(new Error("simulated database failure"));

    await expect(repo.delete(VaultId.fromString(VAULT_ID))).rejects.toThrow(
      "simulated database failure",
    );
    expect(logger.error).toHaveBeenCalled();
  });
});

/* ========================================================================== */
/* list / listByOwnerId                                                        */
/* ========================================================================== */

describe("PostgresVaultRepository — listings", () => {
  it("list maps every row and needs no parameters", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({
      rows: [vaultRow(), vaultRow({ id: "v2", name: "Second" })],
      rowCount: 2,
    });

    const all = await repo.list();

    // Read the raw call: `lastCall()` normalises a missing array to `[]`,
    // which would hide the difference between "no parameters" and "[]".
    const raw = mockQuery.mock.calls[mockQuery.mock.calls.length - 1];
    expect(raw[0]).toContain("FROM vaults");
    expect(raw[0]).toContain("ORDER BY created_at DESC");
    expect(raw[1]).toBeUndefined(); // full scan passes no parameter array
    expect(all).toHaveLength(2);
    expectFullMapping(all[0]);
    expect(all[1].id.toString()).toBe("v2");
    expect(all[1].name).toBe("Second");
  });

  it("listByOwnerId binds the owner and keeps it out of the query text", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [vaultRow()], rowCount: 1 });

    const mine = await repo.listByOwnerId(OWNER_ID);

    const [sql, params] = lastCall();
    expect(sql).toContain("WHERE owner_id = $1");
    expect(sql).toContain("ORDER BY created_at DESC");
    expect(sql).not.toContain(OWNER_ID);
    expect(params).toEqual([OWNER_ID]);
    expect(mine).toHaveLength(1);
    expectFullMapping(mine[0]);
  });

  it("an empty result set maps to [], never to an error", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValue({ rows: [], rowCount: 0 });

    await expect(repo.list()).resolves.toEqual([]);
    await expect(repo.listByOwnerId(OWNER_ID)).resolves.toEqual([]);
  });

  it("a database error rejects instead of resolving to an empty list", async () => {
    const repo = newRepo();
    mockQuery.mockRejectedValue(new Error("simulated database failure"));

    await expect(repo.list()).rejects.toThrow("simulated database failure");
    mockQuery.mockRejectedValue(new Error("simulated database failure"));
    await expect(repo.listByOwnerId(OWNER_ID)).rejects.toThrow(
      "simulated database failure",
    );
    expect(logger.error).toHaveBeenCalled();
  });
});

/* ========================================================================== */
/* updateMetadata                                                              */
/* ========================================================================== */

describe("PostgresVaultRepository.updateMetadata", () => {
  it("binds the JSON metadata as a parameter in the blind path", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 1 });

    await expect(repo.updateMetadata(VAULT_ID, { pinned: true })).resolves.toBeUndefined();

    const [sql, params] = lastCall();
    expect(params).toEqual([JSON.stringify({ pinned: true }), VAULT_ID]);
    expect(sql).not.toContain("pinned");
    expect(sql).not.toContain(VAULT_ID);
  });

  it("binds the expected version in the guarded path", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 1 });

    await expect(repo.updateMetadata(VAULT_ID, { pinned: true }, 5)).resolves.toBeUndefined();

    const [, params] = lastCall();
    expect(params).toEqual([JSON.stringify({ pinned: true }), VAULT_ID, 5]);
  });

  it("propagates a database error instead of reporting an update", async () => {
    const repo = newRepo();
    mockQuery.mockRejectedValue(new Error("simulated database failure"));

    await expect(repo.updateMetadata(VAULT_ID, { a: 1 })).rejects.toThrow(
      "simulated database failure",
    );
    expect(logger.error).toHaveBeenCalled();
  });
});

/* ========================================================================== */
/* Lifecycle                                                                   */
/* ========================================================================== */

describe("PostgresVaultRepository — lifecycle", () => {
  it("isHealthy reports true on a successful probe and false on failure", async () => {
    const repo = newRepo();

    mockQuery.mockResolvedValueOnce({ rows: [{ "?column?": 1 }], rowCount: 1 });
    await expect(repo.isHealthy()).resolves.toBe(true);
    expect(lastCall()[0]).toBe("SELECT 1");

    mockQuery.mockRejectedValueOnce(new Error("ECONNREFUSED"));
    await expect(repo.isHealthy()).resolves.toBe(false);
    expect(logger.error).toHaveBeenCalled();
  });

  it("close shuts the pool down", async () => {
    const repo = newRepo();
    const pool = lastPool();

    await repo.close();

    expect(pool.end).toHaveBeenCalledTimes(1);
  });

  it("registers an idle-client error handler that logs instead of throwing", async () => {
    const repo = newRepo();
    const pool = lastPool();
    expect(pool.on).toHaveBeenCalledWith("error", expect.any(Function));

    const handler = pool.on.mock.calls[0][1] as (error: Error) => void;
    expect(() => handler(new Error("terminating connection due to administrator"))).not.toThrow();
    expect(logger.error).toHaveBeenCalledWith(
      "Unexpected error on idle PostgreSQL client",
      "PostgresVaultRepository",
      undefined,
      expect.stringContaining("terminating connection due to administrator"),
    );
    // The instance survives — an idle-client error must not poison the repo.
    expect(repo).toBeInstanceOf(PostgresVaultRepository);
  });

  it("logs a schema-initialisation failure instead of throwing from the constructor", async () => {
    mockQuery.mockReset();
    mockQuery.mockRejectedValueOnce(new Error("permission denied for table vaults"));

    expect(() => new PostgresVaultRepository(DB_URL)).not.toThrow();
    await flush();

    expect(logger.warn).toHaveBeenCalledWith(
      "Schema initialization failed (may need manual migration)",
      expect.any(Error),
    );
  });

  it("opens the circuit after repeated failures and then refuses without querying", async () => {
    const repo = newRepo();
    mockQuery.mockRejectedValue(new Error("simulated database failure"));

    // failureThreshold is 5 — five failed probes open the circuit.
    for (let i = 0; i < 5; i++) {
      await expect(repo.isHealthy()).resolves.toBe(false);
    }
    const issued = mockQuery.mock.calls.length;
    expect(issued).toBe(5);

    // The OPEN branch rejects BEFORE the pool is touched.
    await expect(repo.isHealthy()).resolves.toBe(false);
    expect(mockQuery.mock.calls.length).toBe(issued);
  });
});

/* ========================================================================== */
/* Guarded writes with NULL optionals (H5 SQL shape itself: optimistic-locking) */
/* ========================================================================== */

describe("PostgresVaultRepository — guarded writes over NULL columns", () => {
  it("NULLs description, owner and metadata on a guarded save", async () => {
    const repo = newRepo();
    const bare = Vault.create({
      name: "Bare",
      encryptedData: CIPHERTEXT,
      encryptionKeyId: KEY_ID,
    });
    mockQuery.mockResolvedValueOnce({
      rows: [vaultRow({ description: null, owner_id: null, metadata: null })],
      rowCount: 1,
    });

    await repo.save(bare, 3);

    const [sql, params] = lastCall();
    expect(sql).toContain("UPDATE vaults");
    expect(sql).toContain("WHERE id = $1 AND lock_version = $9");
    expect(params[2]).toBeNull(); // description
    expect(params[5]).toBeNull(); // owner_id
    expect(params[6]).toBeNull(); // metadata
    // NOT NULL columns are still bound.
    expect(params[3]).toBe(CIPHERTEXT);
    expect(params[4]).toBe(KEY_ID);
    expect(params[8]).toBe(3); // expectedVersion
  });

  it("treats a NULL rowCount from a guarded UPDATE as a conflict, not a success", async () => {
    const repo = newRepo();
    mockQuery
      .mockResolvedValueOnce({ rows: [], rowCount: null }) // driver: count unknown
      .mockResolvedValueOnce({ rows: [{ lock_version: "4" }], rowCount: 1 });

    await expect(repo.save(makeVault(), 2)).rejects.toMatchObject({
      code: "OPTIMISTIC_LOCK_CONFLICT",
      expectedVersion: 2,
      actualVersion: 4,
    });
    expect(lastCall()[0]).toContain("SELECT lock_version FROM vaults");
  });

  it("treats a NULL rowCount from a guarded metadata UPDATE as a conflict", async () => {
    const repo = newRepo();
    mockQuery
      .mockResolvedValueOnce({ rows: [], rowCount: null })
      .mockResolvedValueOnce({ rows: [{ lock_version: "9" }], rowCount: 1 });

    await expect(repo.updateMetadata(VAULT_ID, { a: 1 }, 5)).rejects.toMatchObject({
      code: "OPTIMISTIC_LOCK_CONFLICT",
      expectedVersion: 5,
      actualVersion: 9,
    });
  });

});

/* ========================================================================== */
/* Parameterization sweep                                                      */
/* ========================================================================== */

describe("PostgresVaultRepository — parameterized SQL", () => {
  it("no vault secret or identity ever appears in a query string", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValue({ rows: [vaultRow()], rowCount: 1 });

    await repo.save(makeVault());
    await repo.findById(VaultId.fromString(VAULT_ID));
    await repo.findByVaultIdAndOwnerId(VAULT_ID, OWNER_ID);
    await repo.list();
    await repo.listByOwnerId(OWNER_ID);
    await repo.delete(VaultId.fromString(VAULT_ID));
    await repo.updateMetadata(VAULT_ID, { a: 1 });

    expect(mockQuery.mock.calls.length).toBeGreaterThanOrEqual(7);
    for (const [sql, rawParams] of mockQuery.mock.calls) {
      const params = rawParams ?? [];
      expect(typeof sql).toBe("string");
      // Ciphertext, the key id, the vault name and the owner id live in `params`.
      expect(sql).not.toContain(CIPHERTEXT);
      expect(sql).not.toContain(KEY_ID);
      expect(sql).not.toContain("My Vault");
      expect(sql).not.toContain(OWNER_ID);
      expect(sql).not.toContain(VAULT_ID);
      if (params.length > 0) expect(sql).toMatch(/\$\d/);
      expect(Array.isArray(params)).toBe(true);
    }
  });
});
