/**
 * S2 — `PostgresCredentialRepository` unit tests (mocked `pg`).
 *
 * WHY A MOCKED CLIENT
 * -------------------
 * The repository constructs `new Pool({connectionString})` internally and
 * exposes no injection seam, so `pg` is mocked at module level and every
 * assertion inspects the exact `(sql, params)` pair the repository sends.
 * No live database, no Docker, no network. The H5 guarded-save paths
 * (`save(credential, expectedVersion)` and the `OptimisticLockConflictError`
 * branch) are already pinned by `optimistic-locking.test.ts`; this file
 * covers the REST of the public surface, which had no repository-level test
 * at all: blind `save`, `findById`, `findByVaultId`, `findBySecretRef`,
 * `delete`, `list`, `isHealthy`, `close` and the constructor's DDL.
 *
 * WHAT IS PINNED HERE
 * 1. Row → domain mapping: `credentials` rows shaped exactly as `pg` returns
 *    them (snake_case, `Date` for `timestamptz`, a real JS array for
 *    `TEXT[]`, a STRING for the `BIGINT lock_version`) come back as fully
 *    populated camelCase `Credential` entities. `release_share_ref` →
 *    `releaseShareRef` is the H3 round-trip the old spread dropped — a hard
 *    assertion is made on it.
 * 2. Defaults and NULLs: NULL `TEXT[]` → `[]`, NULL optional columns →
 *    `undefined` (never `null`), NULL `mode`/`salt`/`version`/`favorite`
 *    take the column DEFAULTS the mapper documents.
 * 3. Parameterization: ciphertext, titles and secret refs travel only in the
 *    bound parameter array.
 * 4. Error propagation: a database error rejects, never `null` / `[]`.
 * 5. Lifecycle: constructor DDL (CREATE + the ALTER TABLE block migrations
 *    003/004 mirror), health probe, pool shutdown.
 */

const mockQuery = jest.fn();

jest.mock("pg", () => ({
  Pool: jest.fn(() => ({
    query: (text: string, values?: unknown[]) => mockQuery(text, values),
    on: jest.fn(),
    end: jest.fn(),
  })),
}));

import { PostgresCredentialRepository } from "../../src/infrastructure/repositories/PostgresCredentialRepository";
import { Credential } from "../../src/domain/entities/credential";
import { CredentialId, VaultId } from "../../src/domain/value-objects/ids";

const DB_URL = "postgresql://user:secret@localhost:5432/cybervault";
const VAULT_ID = "vault-1";
const CIPHERTEXT = "ciphertext-blob";
const SECRET_REF = "a3f1d2e4-0b7c-4d5e-9f10-111213141516";

const { Pool } = jest.requireMock("pg") as { Pool: jest.Mock };

function newRepo(): PostgresCredentialRepository {
  const repo = new PostgresCredentialRepository(DB_URL);
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
/* Row fixture — the exact shape `pg` hands back from a credential SELECT      */
/* -------------------------------------------------------------------------- */

function credentialRow(overrides: Record<string, unknown> = {}) {
  return {
    id: "cred-1",
    vault_id: VAULT_ID,
    title: "GitHub",
    username: "alice",
    encrypted_password: CIPHERTEXT,
    mode: "personal",
    salt: "c2FsdC12YWx1ZQ==",
    version: 2,
    release_share_ref: SECRET_REF,
    url: "https://github.com",
    notes: "work account",
    tags: ["work", "devops"], // TEXT[] arrives as a real JS array
    favorite: true,
    created_at: new Date("2026-01-01T00:00:00.000Z"),
    updated_at: new Date("2026-01-02T00:00:00.000Z"),
    last_used: new Date("2026-01-03T00:00:00.000Z"),
    // BIGINT arrives from `pg` as a STRING.
    lock_version: "7",
    ...overrides,
  };
}

/** Hard regression assertion: every field of the mapped domain object. */
function expectFullMapping(credential: Credential): void {
  expect(credential.id.toString()).toBe("cred-1");
  expect(credential.vaultId.toString()).toBe(VAULT_ID);
  expect(credential.title).toBe("GitHub");
  expect(credential.username).toBe("alice");
  expect(credential.encryptedPassword).toBe(CIPHERTEXT);
  expect(credential.mode).toBe("personal");
  expect(credential.salt).toBe("c2FsdC12YWx1ZQ==");
  expect(credential.version).toBe(2);
  // The H3 secret-ref round trip: the column exists, the value must survive.
  expect(credential.releaseShareRef).toBe(SECRET_REF);
  expect(credential.url).toBe("https://github.com");
  expect(credential.notes).toBe("work account");
  expect(credential.tags).toEqual(["work", "devops"]);
  expect(credential.favorite).toBe(true);
  expect(credential.createdAt).toEqual(new Date("2026-01-01T00:00:00.000Z"));
  expect(credential.updatedAt).toEqual(new Date("2026-01-02T00:00:00.000Z"));
  expect(credential.lastUsed).toEqual(new Date("2026-01-03T00:00:00.000Z"));
  // BIGINT string → number, never "7".
  expect(credential.lockVersion).toBe(7);
  expect(typeof credential.lockVersion).toBe("number");
}

function makeCredential(): Credential {
  return Credential.createPersonal({
    vaultId: VaultId.fromString(VAULT_ID),
    title: "GitHub",
    username: "alice",
    encryptedPassword: CIPHERTEXT,
    salt: "c2FsdC12YWx1ZQ==",
    url: "https://github.com",
    notes: "work account",
    tags: ["work", "devops"],
    favorite: true,
    version: 2,
  });
}

/* ========================================================================== */
/* save (blind path — guarded path lives in optimistic-locking.test.ts)        */
/* ========================================================================== */

describe("PostgresCredentialRepository.save", () => {
  it("upserts with all 16 columns bound positionally", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [credentialRow()], rowCount: 1 });

    await repo.save(makeCredential());

    const [sql, params] = lastCall();
    expect(sql).toContain("INSERT INTO credentials");
    expect(sql).toMatch(/ON CONFLICT \(id\) DO UPDATE SET/);
    expect(sql).toContain("RETURNING *");
    expect(params).toHaveLength(16);
    expect(sql).toContain("$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16");
    // lock_version is database-owned: never bound in the INSERT.
    expect(sql).toContain("lock_version = credentials.lock_version + 1");
  });

  it("binds domain values as parameters and NULL for absent optionals", async () => {
    const repo = newRepo();
    const credential = makeCredential();
    mockQuery.mockResolvedValueOnce({ rows: [credentialRow()], rowCount: 1 });

    await repo.save(credential);

    const plain = credential.toPlainObject();
    const [sql, params] = lastCall();
    expect(params).toEqual([
      plain.id,
      VAULT_ID,
      "GitHub",
      "alice",
      CIPHERTEXT,
      "personal",
      "c2FsdC12YWx1ZQ==",
      2,
      null, // no releaseShareRef → SQL NULL
      "https://github.com",
      "work account",
      ["work", "devops"],
      true,
      plain.createdAt,
      plain.updatedAt,
      null, // no lastUsed → SQL NULL
    ]);
    expect(sql).not.toContain(CIPHERTEXT);
    expect(sql).not.toContain("GitHub");
    expect(sql).not.toContain("c2FsdC12YWx1ZQ==");
    expect(sql).not.toContain("https://github.com");
  });

  it("binds a managed credential's release ref as a parameter", async () => {
    const repo = newRepo();
    const managed = Credential.createManaged({
      vaultId: VaultId.fromString(VAULT_ID),
      title: "Prod DB",
      username: "svc",
      encryptedPassword: CIPHERTEXT,
      salt: "c2FsdC12YWx1ZQ==",
      releaseShareRef: SECRET_REF,
    });
    mockQuery.mockResolvedValueOnce({ rows: [credentialRow()], rowCount: 1 });

    await repo.save(managed);

    const [sql, params] = lastCall();
    expect(params[8]).toBe(SECRET_REF); // $9 release_share_ref
    expect(sql).not.toContain(SECRET_REF);
  });

  it("returns the mapped row from RETURNING *", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [credentialRow()], rowCount: 1 });

    const saved = await repo.save(makeCredential());

    expect(saved).toBeInstanceOf(Credential);
    expectFullMapping(saved);
  });

  it("propagates a database error instead of swallowing it", async () => {
    const repo = newRepo();
    mockQuery.mockRejectedValue(new Error("simulated database failure"));

    await expect(repo.save(makeCredential())).rejects.toThrow(
      "simulated database failure",
    );
  });
});

/* ========================================================================== */
/* findById                                                                    */
/* ========================================================================== */

describe("PostgresCredentialRepository.findById", () => {
  it("maps every field of the snake_case row onto the entity", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [credentialRow()], rowCount: 1 });

    const found = await repo.findById(CredentialId.fromString("cred-1"));

    const [sql, params] = lastCall();
    expect(sql).toContain("FROM credentials");
    expect(sql).toContain("WHERE id = $1");
    expect(sql).not.toContain("cred-1");
    expect(params).toEqual(["cred-1"]);
    expectFullMapping(found!);
  });

  it("returns null when the row does not exist", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 });

    await expect(
      repo.findById(CredentialId.fromString("ghost")),
    ).resolves.toBeNull();
  });

  it("rejects on a database error rather than reporting 'not found'", async () => {
    const repo = newRepo();
    mockQuery.mockRejectedValue(new Error("simulated database failure"));

    const outcome = await repo
      .findById(CredentialId.fromString("cred-1"))
      .then(() => "resolved")
      .catch((error: Error) => error.message);
    expect(outcome).toBe("simulated database failure");
  });
});

/* ========================================================================== */
/* findByVaultId / findBySecretRef / list                                      */
/* ========================================================================== */

describe("PostgresCredentialRepository — collection and ref reads", () => {
  it("findByVaultId binds the vault and orders newest first", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({
      rows: [credentialRow(), credentialRow({ id: "cred-2", title: "AWS" })],
      rowCount: 2,
    });

    const found = await repo.findByVaultId(VaultId.fromString(VAULT_ID));

    const [sql, params] = lastCall();
    expect(sql).toContain("WHERE vault_id = $1");
    expect(sql).toContain("ORDER BY created_at DESC");
    expect(sql).not.toContain(VAULT_ID);
    expect(params).toEqual([VAULT_ID]);
    expect(found).toHaveLength(2);
    expect(found[0].title).toBe("GitHub");
    expect(found[1].id.toString()).toBe("cred-2");
    expectFullMapping(found[0]);
  });

  it("findBySecretRef binds the ref and keeps it out of the query text", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [credentialRow()], rowCount: 1 });

    const found = await repo.findBySecretRef(SECRET_REF);

    const [sql, params] = lastCall();
    expect(sql).toContain("WHERE release_share_ref = $1");
    expect(sql).not.toContain(SECRET_REF);
    expect(params).toEqual([SECRET_REF]);
    expect(found!.releaseShareRef).toBe(SECRET_REF);
  });

  it("findBySecretRef returns null when no credential carries the ref", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 });

    await expect(repo.findBySecretRef("no-such-ref")).resolves.toBeNull();
  });

  it("list maps every row and needs no parameters", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [credentialRow()], rowCount: 1 });

    const all = await repo.list();

    const [sql, params] = mockQuery.mock.calls[mockQuery.mock.calls.length - 1];
    expect(sql).toContain("FROM credentials");
    expect(sql).toContain("ORDER BY created_at DESC");
    expect(params).toBeUndefined(); // full scan passes no parameter array
    expect(all).toHaveLength(1);
    expectFullMapping(all[0]);
  });

  it("an empty result set maps to [] / null, never to an error", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 });

    await expect(repo.findByVaultId(VaultId.fromString(VAULT_ID))).resolves.toEqual([]);
    await expect(repo.list()).resolves.toEqual([]);
    await expect(repo.findBySecretRef("ref")).resolves.toBeNull();
  });

  it("a database error rejects instead of resolving to an empty list", async () => {
    const repo = newRepo();
    mockQuery.mockRejectedValue(new Error("simulated database failure"));

    await expect(repo.findByVaultId(VaultId.fromString(VAULT_ID))).rejects.toThrow(
      "simulated database failure",
    );
    mockQuery.mockRejectedValue(new Error("simulated database failure"));
    await expect(repo.list()).rejects.toThrow("simulated database failure");
    mockQuery.mockRejectedValue(new Error("simulated database failure"));
    await expect(repo.findBySecretRef(SECRET_REF)).rejects.toThrow(
      "simulated database failure",
    );
  });
});

/* ========================================================================== */
/* Defaults and NULLs — the `.includes()` crash class                         */
/* ========================================================================== */

describe("PostgresCredentialRepository — NULL columns", () => {
  it("maps NULL optionals to undefined and NULL TEXT[] to []", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({
      rows: [
        credentialRow({
          mode: null,
          salt: null,
          version: null,
          release_share_ref: null,
          url: null,
          notes: null,
          tags: null,
          favorite: null,
          last_used: null,
        }),
      ],
      rowCount: 1,
    });

    const found = await repo.findById(CredentialId.fromString("cred-1"));

    // NULL TEXT[] → [] : `.includes()` / `[...tags]` on undefined is the crash.
    expect(found!.tags).toEqual([]);
    expect(Array.isArray(found!.tags)).toBe(true);
    expect(() => found!.addTag("new")).not.toThrow();
    // NULL optionals → undefined, never null.
    expect(found!.releaseShareRef).toBeUndefined();
    expect(found!.url).toBeUndefined();
    expect(found!.notes).toBeUndefined();
    expect(found!.lastUsed).toBeUndefined();
    // Nullable columns with domain-wide effects take the documented DEFAULTS:
    // a credential is never "mode-less", salt-less or version-less, and a
    // NULL favorite never reads as true.
    expect(found!.mode).toBe("personal");
    expect(found!.salt).toBe("");
    expect(found!.version).toBe(1);
    expect(found!.favorite).toBe(false);
    // NOT NULL columns are still populated.
    expect(found!.encryptedPassword).toBe(CIPHERTEXT);
    expect(found!.lockVersion).toBe(7);
  });
});

/* ========================================================================== */
/* delete                                                                      */
/* ========================================================================== */

describe("PostgresCredentialRepository.delete", () => {
  it("returns true on a hit and false on a miss", async () => {
    const repo = newRepo();

    mockQuery.mockResolvedValueOnce({ rows: [{ id: "cred-1" }], rowCount: 1 });
    await expect(repo.delete(CredentialId.fromString("cred-1"))).resolves.toBe(true);

    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 0 });
    await expect(repo.delete(CredentialId.fromString("ghost"))).resolves.toBe(false);

    const [sql, params] = lastCall();
    expect(sql).toContain("DELETE FROM credentials");
    expect(sql).toContain("WHERE id = $1");
    expect(sql).toContain("RETURNING id");
    expect(sql).not.toContain("ghost");
    expect(params).toEqual(["ghost"]);
  });

  it("treats a NULL rowCount as 'nothing deleted' rather than throwing", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: null });

    await expect(repo.delete(CredentialId.fromString("cred-1"))).resolves.toBe(false);
  });

  it("propagates a database error instead of reporting a failed delete", async () => {
    const repo = newRepo();
    mockQuery.mockRejectedValue(new Error("simulated database failure"));

    await expect(
      repo.delete(CredentialId.fromString("cred-1")),
    ).rejects.toThrow("simulated database failure");
  });
});

/* ========================================================================== */
/* Lifecycle                                                                   */
/* ========================================================================== */

describe("PostgresCredentialRepository — lifecycle", () => {
  it("creates the table and applies the migration-003/004 column block", async () => {
    mockQuery.mockResolvedValueOnce({ rows: [], rowCount: 1 });
    new PostgresCredentialRepository(DB_URL);

    const [sql] = mockQuery.mock.calls[0];
    expect(sql).toContain("CREATE TABLE IF NOT EXISTS credentials");
    for (const statement of [
      "ALTER TABLE credentials ADD COLUMN IF NOT EXISTS mode VARCHAR(20) DEFAULT 'personal'",
      "ALTER TABLE credentials ADD COLUMN IF NOT EXISTS salt TEXT",
      "ALTER TABLE credentials ADD COLUMN IF NOT EXISTS version INTEGER DEFAULT 1",
      "ALTER TABLE credentials ADD COLUMN IF NOT EXISTS release_share_ref VARCHAR(255)",
      "ALTER TABLE credentials ADD COLUMN IF NOT EXISTS lock_version BIGINT NOT NULL DEFAULT 1",
      "CREATE UNIQUE INDEX IF NOT EXISTS uq_credentials_release_share_ref ON credentials(release_share_ref)",
    ]) {
      expect(sql).toContain(statement);
    }
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

describe("PostgresCredentialRepository — parameterized SQL", () => {
  it("no secret material ever appears in a query string", async () => {
    const repo = newRepo();
    mockQuery.mockResolvedValue({ rows: [credentialRow()], rowCount: 1 });

    await repo.save(makeCredential());
    await repo.findById(CredentialId.fromString("cred-1"));
    await repo.findByVaultId(VaultId.fromString(VAULT_ID));
    await repo.findBySecretRef(SECRET_REF);
    await repo.delete(CredentialId.fromString("cred-1"));

    expect(mockQuery.mock.calls.length).toBeGreaterThanOrEqual(5);
    for (const [sql, rawParams] of mockQuery.mock.calls) {
      const params = rawParams ?? [];
      expect(typeof sql).toBe("string");
      // Ciphertext, title, salt and the secret ref live only in `params`.
      expect(sql).not.toContain(CIPHERTEXT);
      expect(sql).not.toContain("c2FsdC12YWx1ZQ==");
      expect(sql).not.toContain(SECRET_REF);
      expect(sql).not.toContain("GitHub");
      expect(sql).not.toContain(VAULT_ID);
      expect(sql).not.toContain("cred-1");
      expect(sql).not.toMatch(/'work'/);
      if (params.length > 0) expect(sql).toMatch(/\$\d/);
      expect(Array.isArray(params)).toBe(true);
    }
  });
});
