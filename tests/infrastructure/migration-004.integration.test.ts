/**
 * H5 — migration 004 against a REAL PostgreSQL.
 *
 * `optimistic-locking.test.ts` pins the behaviour of the guarded writes against
 * a scripted `pg` mock: the SQL text, the control flow, and the fact that a
 * conflict raises `OptimisticLockConflictError` instead of overwriting. What it
 * cannot show is that the COLUMN exists. This file does that, live.
 *
 * WHAT IT PROVES
 * 1. On a database built from 001 alone, `lock_version` does not exist —
 *    reproducing the state migration 004 has to repair.
 * 2. Applying 004 adds it to BOTH `vaults` and `credentials`.
 * 3. Rows written BEFORE the migration are backfilled to `1` by the default —
 *    no NULL, no zero, no rewrite of their data.
 * 4. Running 004 a second time is a no-op.
 * 5. The repositories' own `initializeTable()` DDL is idempotent against the
 *    migrated schema and declares the same column.
 * 6. A guarded `UPDATE ... WHERE lock_version = <stale>` really does affect
 *    zero rows on a live server, which is the whole premise of H5.
 *
 * Runs inside ONE TRANSACTION that is ROLLED BACK (PostgreSQL has transactional
 * DDL), so a developer's committed data is never touched and a re-run starts
 * from the same state. The intentional failure is bracketed by a SAVEPOINT.
 *
 * OPT-IN: set CYBERVAULT_TEST_DATABASE_URL. Skips with the reason recorded
 * when the variable is absent, so a plain `npx jest` needs no server.
 */

import { Client } from "pg";
import * as fs from "fs";
import * as path from "path";

const DATABASE_URL = process.env.CYBERVAULT_TEST_DATABASE_URL;
const MIGRATIONS_DIR = path.join(__dirname, "../../src/infrastructure/db/migrations");

const migration = (name: string): string =>
  fs.readFileSync(path.join(MIGRATIONS_DIR, name), "utf-8");

const describeIfDatabase = DATABASE_URL ? describe : describe.skip;

/** Repository DDL, extracted verbatim from the source so the mirror cannot drift. */
function repositoryDdl(repositoryFile: string): string {
  const source = fs.readFileSync(
    path.join(__dirname, "../../src/infrastructure/repositories", repositoryFile),
    "utf-8",
  );
  const match = /const createTableQuery = `([\s\S]*?)`;/.exec(source);
  if (!match) throw new Error(`createTableQuery not found in ${repositoryFile}`);
  return match[1];
}

describeIfDatabase("H5: migration 004 against a live PostgreSQL", () => {
  /**
   * A dedicated `Client`, not a `Pool`: `pg-pool` replaces the connection after
   * any query error, which would move this test off its open transaction and
   * make `ROLLBACK TO SAVEPOINT` fail with "can only be used in transaction
   * blocks". See migration-003.integration.test.ts for the same reasoning.
   */
  let client: Client;

  beforeAll(async () => {
    client = new Client({ connectionString: DATABASE_URL });
    await client.connect();
  });

  afterAll(async () => {
    if (client) await client.end();
  });

  it.skip("CYBERVAULT_TEST_DATABASE_URL is not set — set it to exercise the migration against a real server", () => {
    // Intentionally empty: this is the recorded skip reason.
  });

  it("backfills lock_version, is safe to re-run, and makes guarded writes possible", async () => {
    await client.query("BEGIN");
    try {
      // Rebuild from 001 only — the pre-004 state.
      await client.query("DROP TABLE IF EXISTS credentials CASCADE");
      await client.query("DROP TABLE IF EXISTS vaults CASCADE");
      await client.query(migration("001_initial_schema.sql"));
      await client.query(
        `INSERT INTO vaults (id, name, encrypted_data, encryption_key_id, owner_id)
         VALUES ('h5-vault', 'n', 'enc', 'k1', 'u1')`,
      );
      await client.query(
        `INSERT INTO credentials (id, vault_id, title, username, encrypted_password)
         VALUES ('h5-cred', 'h5-vault', 't', 'u', 'p')`,
      );

      // --- 1. the pre-migration state has no lock_version -------------------
      const before = await client.query(
        `SELECT count(*)::int AS n FROM information_schema.columns
          WHERE table_name IN ('vaults', 'credentials') AND column_name = 'lock_version'`,
      );
      expect(before.rows[0].n).toBe(0);

      // --- 2/3. apply 004: both tables gain it, existing rows get 1 ---------
      await client.query(migration("004_optimistic_locking.sql"));

      const after = await client.query(
        `SELECT table_name, column_name, data_type, column_default, is_nullable
           FROM information_schema.columns
          WHERE column_name = 'lock_version'
          ORDER BY table_name`,
      );
      expect(after.rows).toEqual([
        {
          table_name: "credentials",
          column_name: "lock_version",
          data_type: "bigint",
          column_default: "1",
          is_nullable: "NO",
        },
        {
          table_name: "vaults",
          column_name: "lock_version",
          data_type: "bigint",
          column_default: "1",
          is_nullable: "NO",
        },
      ]);

      const backfilled = await client.query(
        `SELECT (SELECT lock_version FROM vaults WHERE id = 'h5-vault')::text AS vault_version,
                (SELECT lock_version FROM credentials WHERE id = 'h5-cred')::text AS cred_version`,
      );
      expect(backfilled.rows[0]).toEqual({ vault_version: "1", cred_version: "1" });

      // --- 4. run 004 again: a no-op ---------------------------------------
      await client.query(migration("004_optimistic_locking.sql"));
      const rerun = await client.query(
        `SELECT (SELECT lock_version FROM vaults WHERE id = 'h5-vault')::text AS vault_version,
                (SELECT lock_version FROM credentials WHERE id = 'h5-cred')::text AS cred_version`,
      );
      expect(rerun.rows[0]).toEqual({ vault_version: "1", cred_version: "1" });

      // --- 5. the repositories' mirrored DDL is idempotent here -------------
      await client.query(repositoryDdl("PostgresVaultRepository.ts"));
      await client.query(repositoryDdl("PostgresCredentialRepository.ts"));
      await client.query(repositoryDdl("PostgresVaultRepository.ts"));
      await client.query(repositoryDdl("PostgresCredentialRepository.ts"));

      const mirrored = await client.query(
        `SELECT count(*)::int AS n FROM information_schema.columns
          WHERE column_name = 'lock_version' AND table_name IN ('vaults', 'credentials')`,
      );
      expect(mirrored.rows[0].n).toBe(2);

      // --- 6. the premise of H5, observed on a live server ------------------
      // Blind write succeeds (old behaviour, unchanged).
      const blind = await client.query(
        `UPDATE vaults SET metadata = '{"blind":true}', updated_at = NOW(),
                lock_version = vaults.lock_version + 1
          WHERE id = 'h5-vault'`,
      );
      expect(blind.rowCount).toBe(1);

      // A STALE guarded write affects zero rows — that is the refusal.
      await client.query("SAVEPOINT before_stale_guard");
      const stale = await client.query(
        `UPDATE vaults SET metadata = '{"stale":true}', updated_at = NOW(),
                lock_version = vaults.lock_version + 1
          WHERE id = 'h5-vault' AND lock_version = $1`,
        [1],
      );
      expect(stale.rowCount).toBe(0);
      await client.query("ROLLBACK TO SAVEPOINT before_stale_guard");

      // The matching version writes and bumps the counter.
      const fresh = await client.query(
        `UPDATE vaults SET metadata = '{"guarded":true}', updated_at = NOW(),
                lock_version = vaults.lock_version + 1
          WHERE id = 'h5-vault' AND lock_version = $1
          RETURNING lock_version::text AS lock_version`,
        [2],
      );
      expect(fresh.rowCount).toBe(1);
      expect(fresh.rows[0].lock_version).toBe("3");

      // The blind write above is visible to the guarded writer: the counter
      // moved from 1 to 2, which is exactly why the stale write was refused.
      const counter = await client.query(
        `SELECT lock_version::text AS lock_version FROM vaults WHERE id = 'h5-vault'`,
      );
      expect(counter.rows[0].lock_version).toBe("3");
    } finally {
      await client.query("ROLLBACK");
    }
  }, 60_000);
});
