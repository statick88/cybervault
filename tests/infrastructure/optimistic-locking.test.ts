/**
 * H5 — optimistic locking: the lost update that could not be detected.
 *
 * THE DEFECT
 * ----------
 * `PostgresVaultRepository.save()`, `PostgresCredentialRepository.save()` and
 * `PostgresVaultRepository.updateMetadata()` were blind writes. A caller that
 * read a row, changed it in memory and wrote it back had no way to notice that
 * somebody else had committed in between: `ON CONFLICT (id) DO UPDATE` and
 * `UPDATE ... WHERE id = $1` both apply unconditionally, so the last writer
 * silently discarded the other's changes. Two concurrent metadata merges, or a
 * credential rewritten while it was being re-encrypted, lost one side with no
 * error anywhere.
 *
 * THE FIX
 * -------
 * A database-owned `lock_version` counter (migration
 * `004_optimistic_locking.sql`). Callers that opt in pass back the version they
 * read as `expectedVersion`, and the repository issues a GUARDED write:
 *
 *     UPDATE ... SET ..., lock_version = <table>.lock_version + 1
 *      WHERE id = $1 AND lock_version = $N
 *
 * Zero affected rows raises `OptimisticLockConflictError` instead of
 * overwriting. Everything is verified against a scripted `pg` mock so the SQL
 * text and the control flow are pinned exactly — including the two things that
 * matter most for "no previously-valid request is refused":
 *
 *  * `expectedVersion` is OPTIONAL, so the blind path is byte-for-byte the old
 *    one for every caller that does not opt in.
 *  * The guarded path issues an `UPDATE` and never an `INSERT`, so it cannot
 *    resurrect a deleted row or mint a duplicate `release_share_ref`.
 *
 * The live-database half of H5 (004 applied twice, `lock_version` backfilled)
 * lives in `migration-004.integration.test.ts`.
 */

import { Vault } from "../../src/domain/entities/vault";
import { Credential } from "../../src/domain/entities/credential";
import { VaultId } from "../../src/domain/value-objects/ids";
import { OptimisticLockConflictError } from "../../src/domain/errors/optimistic-lock-conflict.error";
import { PostgresVaultRepository } from "../../src/infrastructure/repositories/PostgresVaultRepository";
import { PostgresCredentialRepository } from "../../src/infrastructure/repositories/PostgresCredentialRepository";

/* -------------------------------------------------------------------------- */
/* Scripted `pg` mock                                                          */
/* -------------------------------------------------------------------------- */

jest.mock("pg", () => {
  interface State {
    handler: (text: string, values?: unknown[]) => unknown;
    queries: Array<{ text: string; values?: unknown[] }>;
  }

  const state: State = {
    // Default: nothing to report. DDL is swallowed by the regex below before
    // this is consulted, so the constructor's fire-and-forget
    // `initializeTable()` never perturbs a test.
    handler: () => ({ rows: [], rowCount: 0 }),
    queries: [],
  };

  class MockPool {
    on(): void {
      /* idle-client error listener — no idle clients under the mock */
    }
    end(): Promise<void> {
      return Promise.resolve();
    }
    async query(text: string, values?: unknown[]) {
      state.queries.push({ text, values });
      if (/\b(CREATE TABLE|ALTER TABLE|CREATE (UNIQUE )?INDEX)\b/i.test(text)) {
        return { rows: [], rowCount: 1, command: "CREATE" };
      }
      const out = state.handler(text, values);
      if (out instanceof Error) throw out;
      return out;
    }
  }

  return { Pool: MockPool, __mockState: state };
});

const state = (require("pg") as { __mockState: { handler: unknown; queries: unknown[] } })
  .__mockState as {
  handler: (text: string, values?: unknown[]) => unknown;
  queries: Array<{ text: string; values?: unknown[] }>;
};

/** Everything issued so far, newest first. */
function queriesMatching(pattern: RegExp): Array<{ text: string; values?: unknown[] }> {
  return state.queries.filter((entry) => pattern.test(entry.text));
}
function textsMatching(pattern: RegExp): string[] {
  return queriesMatching(pattern).map((entry) => entry.text);
}

beforeEach(() => {
  state.queries.length = 0;
  state.handler = () => ({ rows: [], rowCount: 0 });
});

/* -------------------------------------------------------------------------- */
/* Fixtures                                                                    */
/* -------------------------------------------------------------------------- */

function makeVault(): Vault {
  return Vault.create({
    name: "My Vault",
    description: "creds",
    encryptedData: "ciphertext",
    encryptionKeyId: "key-1",
    ownerId: "user-1",
    metadata: { color: "blue" },
  });
}

function makeCredential(): Credential {
  return Credential.createPersonal({
    vaultId: VaultId.generate(),
    title: "Site",
    username: "alice",
    encryptedPassword: "ciphertext",
    salt: Buffer.alloc(32, 7).toString("base64"),
  });
}

/** A `RETURNING *` row exactly as PostgreSQL would hand it back. */
function vaultRow(lockVersion: number | string) {
  return {
    id: "v1",
    name: "My Vault",
    description: "creds",
    encrypted_data: "ciphertext",
    encryption_key_id: "key-1",
    owner_id: "user-1",
    // `null` rather than a parsed object: the repository's mapping runs
    // `JSON.parse(row.metadata)`, so the row is given the shape that mapping
    // expects. `metadata` is irrelevant to H5 and is kept out of the way.
    metadata: null,
    created_at: new Date("2026-01-01T00:00:00Z"),
    updated_at: new Date("2026-01-02T00:00:00Z"),
    lock_version: lockVersion,
  };
}

function credentialRow(lockVersion: number | string, vaultId: string) {
  return {
    id: "c1",
    vault_id: vaultId,
    title: "Site",
    username: "alice",
    encrypted_password: "ciphertext",
    mode: "personal",
    salt: Buffer.alloc(32, 7).toString("base64"),
    version: 1,
    release_share_ref: null,
    url: null,
    notes: null,
    tags: [],
    favorite: false,
    created_at: new Date("2026-01-01T00:00:00Z"),
    updated_at: new Date("2026-01-02T00:00:00Z"),
    last_used: null,
    lock_version: lockVersion,
  };
}

/* ========================================================================== */
/* IVaultRepository.save                                                       */
/* ========================================================================== */

describe("H5: PostgresVaultRepository.save", () => {
  it("keeps the original blind upsert when expectedVersion is omitted", async () => {
    state.handler = () => ({ rows: [vaultRow(4)], rowCount: 1 });
    const repo = new PostgresVaultRepository("postgresql://mock");

    const saved = await repo.save(makeVault());

    const inserts = queriesMatching(/^[\s\S]*INSERT INTO vaults/i);
    expect(inserts).toHaveLength(1);
    const sql = inserts[0].text;

    // Still a blind upsert — no version predicate anywhere.
    expect(sql).toMatch(/ON CONFLICT \(id\) DO UPDATE SET/);
    expect(sql).not.toMatch(/lock_version\s*=\s*\$9/);
    expect(sql).not.toMatch(/WHERE id = \$1 AND lock_version/);
    // ...but the blind writer still invalidates guarded callers' copies.
    expect(sql).toMatch(/lock_version = vaults\.lock_version \+ 1/);

    expect(saved.lockVersion).toBe(4);
  });

  it("applies a guarded UPDATE when expectedVersion matches", async () => {
    state.handler = (text) =>
      /UPDATE vaults/i.test(text)
        ? { rows: [vaultRow(8)], rowCount: 1 }
        : { rows: [], rowCount: 0 };

    const repo = new PostgresVaultRepository("postgresql://mock");
    const saved = await repo.save(makeVault(), 7);

    const guarded = queriesMatching(/WHERE id = \$1 AND lock_version = \$9/);
    expect(guarded).toHaveLength(1);
    const sql = guarded[0].text;
    expect(sql).toMatch(/UPDATE vaults/i);
    expect(sql).toMatch(/lock_version = vaults\.lock_version \+ 1/);
    // Guarded writes never INSERT — a deleted row stays deleted.
    expect(textsMatching(/INSERT INTO vaults/i)).toHaveLength(0);

    // The returned entity carries the NEW version so the caller can write again.
    expect(saved.lockVersion).toBe(8);
  });

  it("refuses a stale guarded write and reports the version actually stored", async () => {
    state.handler = (text) =>
      /SELECT lock_version FROM vaults/i.test(text)
        ? { rows: [{ lock_version: "7" }], rowCount: 1 }
        : { rows: [], rowCount: 0 };

    const repo = new PostgresVaultRepository("postgresql://mock");

    await expect(repo.save(makeVault(), 3)).rejects.toThrow(OptimisticLockConflictError);
    await expect(repo.save(makeVault(), 3)).rejects.toMatchObject({
      code: "OPTIMISTIC_LOCK_CONFLICT",
      entity: "vault",
      expectedVersion: 3,
      actualVersion: 7,
    });

    // Still no INSERT: the conflict is reported, never papered over.
    expect(textsMatching(/INSERT INTO vaults/i)).toHaveLength(0);
  });

  it("reports a missing row instead of INSERTing it", async () => {
    state.handler = (text) =>
      /SELECT lock_version FROM vaults/i.test(text)
        ? { rows: [], rowCount: 0 }
        : { rows: [], rowCount: 0 };

    const repo = new PostgresVaultRepository("postgresql://mock");

    await expect(repo.save(makeVault(), 1)).rejects.toThrow(/does not exist/);
    await expect(repo.save(makeVault(), 1)).rejects.toMatchObject({
      code: "OPTIMISTIC_LOCK_CONFLICT",
      actualVersion: undefined,
    });
    expect(textsMatching(/INSERT INTO vaults/i)).toHaveLength(0);
  });

  it("surfaces the conflict as an Error with a readable message", async () => {
    state.handler = (text) =>
      /SELECT lock_version FROM vaults/i.test(text)
        ? { rows: [{ lock_version: "9" }], rowCount: 1 }
        : { rows: [], rowCount: 0 };

    const repo = new PostgresVaultRepository("postgresql://mock");
    await expect(repo.save(makeVault(), 2)).rejects.toThrow(
      /concurrent modification/,
    );
  });
});

/* ========================================================================== */
/* IVaultRepository.updateMetadata                                             */
/* ========================================================================== */

describe("H5: PostgresVaultRepository.updateMetadata", () => {
  it("keeps the original blind WHERE when expectedVersion is omitted", async () => {
    // rowCount 0 is deliberately not an error here — matching the old behaviour.
    state.handler = () => ({ rows: [], rowCount: 0 });
    const repo = new PostgresVaultRepository("postgresql://mock");

    await expect(repo.updateMetadata("v1", { a: 1 })).resolves.toBeUndefined();

    const updates = queriesMatching(/UPDATE vaults/i);
    expect(updates).toHaveLength(1);
    const sql = updates[0].text;
    expect(sql).toMatch(/WHERE id = \$2$/m);
    expect(sql).not.toMatch(/lock_version = \$3/);
    // Metadata is still overwritten wholesale — no merge semantics added.
    expect(sql).toMatch(/SET metadata = \$1, updated_at = NOW\(\)/);
  });

  it("guards when expectedVersion is supplied and refuses a stale write", async () => {
    state.handler = (text) =>
      /SELECT lock_version FROM vaults/i.test(text)
        ? { rows: [{ lock_version: "5" }], rowCount: 1 }
        : { rows: [], rowCount: 0 };

    const repo = new PostgresVaultRepository("postgresql://mock");

    await expect(repo.updateMetadata("v1", { a: 1 }, 5)).rejects.toMatchObject({
      code: "OPTIMISTIC_LOCK_CONFLICT",
      expectedVersion: 5,
      actualVersion: 5,
    });

    const guarded = queriesMatching(/lock_version = \$3/);
    expect(guarded).toHaveLength(1);
    expect(guarded[0].text).toMatch(/lock_version = vaults\.lock_version \+ 1/);
  });

  it("writes when the guarded version matches", async () => {
    state.handler = () => ({ rows: [], rowCount: 1 });
    const repo = new PostgresVaultRepository("postgresql://mock");

    await expect(repo.updateMetadata("v1", { a: 1 }, 5)).resolves.toBeUndefined();
    expect(textsMatching(/SELECT lock_version FROM vaults/i)).toHaveLength(0);
  });
});

/* ========================================================================== */
/* ICredentialRepository.save                                                  */
/* ========================================================================== */

describe("H5: PostgresCredentialRepository.save", () => {
  it("keeps the original blind upsert when expectedVersion is omitted", async () => {
    state.handler = () => ({ rows: [credentialRow(2, "v1")], rowCount: 1 });
    const repo = new PostgresCredentialRepository("postgresql://mock");

    await repo.save(makeCredential());

    const inserts = queriesMatching(/INSERT INTO credentials/i);
    expect(inserts).toHaveLength(1);
    expect(inserts[0].text).toMatch(/ON CONFLICT \(id\) DO UPDATE SET/);
    expect(inserts[0].text).toMatch(/lock_version = credentials\.lock_version \+ 1/);
    expect(inserts[0].text).not.toMatch(/WHERE id = \$1 AND lock_version/);
  });

  it("applies a guarded UPDATE and never INSERTs", async () => {
    state.handler = (text) =>
      /UPDATE credentials/i.test(text)
        ? { rows: [credentialRow(6, "v1")], rowCount: 1 }
        : { rows: [], rowCount: 0 };

    const repo = new PostgresCredentialRepository("postgresql://mock");
    const saved = await repo.save(makeCredential(), 5);

    const guarded = queriesMatching(/WHERE id = \$1 AND lock_version = \$16/);
    expect(guarded).toHaveLength(1);
    expect(guarded[0].text).toMatch(/UPDATE credentials/i);
    expect(textsMatching(/INSERT INTO credentials/i)).toHaveLength(0);
    expect(saved.lockVersion).toBe(6);
  });

  it("refuses a stale guarded write instead of overwriting the other writer", async () => {
    state.handler = (text) =>
      /SELECT lock_version FROM credentials/i.test(text)
        ? { rows: [{ lock_version: "12" }], rowCount: 1 }
        : { rows: [], rowCount: 0 };

    const repo = new PostgresCredentialRepository("postgresql://mock");

    await expect(repo.save(makeCredential(), 11)).rejects.toMatchObject({
      name: "OptimisticLockConflictError",
      code: "OPTIMISTIC_LOCK_CONFLICT",
      entity: "credential",
      expectedVersion: 11,
      actualVersion: 12,
    });
    expect(textsMatching(/INSERT INTO credentials/i)).toHaveLength(0);
  });

  it("reports a missing credential without resurrecting it", async () => {
    state.handler = () => ({ rows: [], rowCount: 0 });
    const repo = new PostgresCredentialRepository("postgresql://mock");

    await expect(repo.save(makeCredential(), 1)).rejects.toThrow(/does not exist/);
    expect(textsMatching(/INSERT INTO credentials/i)).toHaveLength(0);
  });

  it("accepts the numeric lock_version PostgreSQL returns as a BIGINT string", async () => {
    state.handler = (text) =>
      /UPDATE credentials/i.test(text)
        ? { rows: [credentialRow("23", "v1")], rowCount: 1 }
        : { rows: [], rowCount: 0 };

    const repo = new PostgresCredentialRepository("postgresql://mock");
    const saved = await repo.save(makeCredential(), 23);

    // BIGINT arrives as a string; the entity must hold a number.
    expect(saved.lockVersion).toBe(23);
    expect(typeof saved.lockVersion).toBe("number");
  });
});

/* ========================================================================== */
/* Entities                                                                    */
/* ========================================================================== */

describe("H5: lockVersion on the entities", () => {
  it("Vault carries lockVersion through toSafeObject and toPlainObject", () => {
    const vault = Vault.fromPlainObject({
      id: "v1",
      name: "n",
      encryptedData: "e",
      encryptionKeyId: "k",
      createdAt: "2026-01-01T00:00:00Z",
      updatedAt: "2026-01-01T00:00:00Z",
      lockVersion: 3,
    });

    expect(vault.lockVersion).toBe(3);
    expect(vault.toSafeObject().lockVersion).toBe(3);
    expect(vault.toPlainObject().lockVersion).toBe(3);
  });

  it("Credential carries lockVersion and keeps `version` independent", () => {
    const credential = makeCredential().constructor === Credential ? makeCredential() : makeCredential();
    const restored = Credential.fromPlainObject({
      ...credential.toPlainObject(),
      lockVersion: "4",
    });

    expect(restored.lockVersion).toBe(4);
    // `version` is the CRYPTOGRAPHIC entry version folded into the HKDF salt —
    // it must not have been repurposed as the lock counter.
    expect(restored.version).toBe(credential.version);
    expect(restored.version).not.toBe(restored.lockVersion);
  });

  it("leaves lockVersion undefined on a fresh entity that was never read back", () => {
    expect(makeVault().lockVersion).toBeUndefined();
    expect(makeCredential().lockVersion).toBeUndefined();
    expect(makeVault().toSafeObject().lockVersion).toBeUndefined();
  });
});

/* ========================================================================== */
/* "No previously-valid request is refused"                                    */
/* ========================================================================== */

describe("H5: no previously-valid caller starts failing", () => {
  const fs = require("fs") as typeof import("fs");
  const path = require("path") as typeof import("path");
  const read = (relative: string) =>
    fs.readFileSync(path.join(__dirname, "../..", relative), "utf-8");

  it("nothing in Core passes expectedVersion — every existing call stays blind", () => {
    // If a production caller ever starts opting in, this is the assertion that
    // forces the behaviour change to be reviewed deliberately.
    const productionSources = [
      "src/infrastructure/api/server.ts",
      "src/application/use-cases/recovery.use-case.ts",
      "src/infrastructure/repositories/index.ts",
    ];
    for (const file of productionSources) {
      expect(read(file)).not.toMatch(/expectedVersion/);
    }
  });

  it("there is no vault or credential update endpoint to refuse", () => {
    const server = read("src/infrastructure/api/server.ts");
    // Core exposes no PUT/PATCH over vaults or credentials, so H5 cannot refuse
    // a request that used to succeed: nothing routes an update through it yet.
    expect(server).not.toMatch(/app\.(put|patch)\(/i);
    expect(server).not.toMatch(/\.put\(\s*[`'"]\/api\/v1\/vaults/i);
    expect(server).not.toMatch(/\.patch\(\s*[`'"]\/api\/v1\/vaults/i);
  });

  it("the repository interfaces still accept a one-argument save", () => {
    // Structural check: an implementation written against the OLD signature
    // must remain assignable to the NEW interface.
    const legacyRepository = {
      async save(credential: Credential) {
        return credential;
      },
      async findById() {
        return null;
      },
      async findByVaultId() {
        return [];
      },
      async findBySecretRef() {
        return null;
      },
      async delete() {
        return false;
      },
      async list() {
        return [];
      },
    };

    const asCredentialRepo: import("../../src/domain/repositories").ICredentialRepository =
      legacyRepository;
    expect(typeof asCredentialRepo.save).toBe("function");
  });
});
