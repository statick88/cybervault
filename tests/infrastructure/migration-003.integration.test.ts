/**
 * H4 + H3 — migration 003 against a REAL PostgreSQL.
 *
 * `migration-schema.test.ts` pins the static facts (column sets, index names,
 * `IF NOT EXISTS` everywhere, no destructive statements). Those assertions run
 * on every CI run with no infrastructure. This file is the empirical half:
 * the actual bytes of `001_initial_schema.sql` and
 * `003_credentials_authoring_and_secret_ref.sql` executed against a live
 * server, so "it is idempotent" and "a duplicate ref is rejected" are observed
 * rather than argued.
 *
 * WHAT IT PROVES, IN ORDER
 * 1. (H4) On a database built from 001 alone, the repository's INSERT — all
 *    sixteen columns — fails with `column "mode" of relation "credentials"
 *    does not exist`. This is the shipped defect, reproduced.
 * 2. A `release_share_ref` column that already exists WITHOUT a unique
 *    constraint accepts two rows with the same value. This is the second
 *    shipped defect, reproduced.
 * 3. Running 003 repairs both: it adds the four columns, collapses the
 *    duplicate to a single owning row, and creates the unique index.
 * 4. Running 003 a second time changes nothing (columns skipped,
 *    `UPDATE 0`, index skipped).
 * 5. After 003, a second credential carrying an existing ref is rejected with
 *    a unique-constraint violation.
 *
 * EVERYTHING RUNS INSIDE ONE TRANSACTION THAT IS ROLLED BACK. PostgreSQL has
 * transactional DDL, so the schema is restored exactly as found and a re-run
 * starts from the same state — no test isolation guessing, no `DROP` on a
 * developer's committed data. The two intentional failures are bracketed with
 * SAVEPOINTs, because PostgreSQL aborts the whole transaction on the first
 * error otherwise.
 *
 * OPT-IN: set CYBERVAULT_TEST_DATABASE_URL to run it. The test skips (with the
 * reason recorded) when the variable is absent, so a plain `npx jest` run does
 * not require a server.
 */

import { Client } from "pg";
import * as fs from "fs";
import * as path from "path";

const DATABASE_URL = process.env.CYBERVAULT_TEST_DATABASE_URL;
const MIGRATIONS_DIR = path.join(__dirname, "../../src/infrastructure/db/migrations");

const migration = (name: string): string =>
  fs.readFileSync(path.join(MIGRATIONS_DIR, name), "utf-8");

const REPOSITORY_PATH = path.join(
  __dirname,
  "../../src/infrastructure/repositories/PostgresCredentialRepository.ts",
);

/** The repository's own `createTableQuery`, extracted verbatim from the source. */
function repositoryCredentialsDdl(): string {
  const source = fs.readFileSync(REPOSITORY_PATH, "utf-8");
  const match = /const createTableQuery = `([\s\S]*?)`;/.exec(source);
  if (!match) throw new Error("createTableQuery not found in PostgresCredentialRepository");
  return match[1];
}

/** Exactly the column list the repository's INSERT writes. */
const REPOSITORY_INSERT_COLUMNS = [
  "id",
  "vault_id",
  "title",
  "username",
  "encrypted_password",
  "mode",
  "salt",
  "version",
  "release_share_ref",
  "url",
  "notes",
  "tags",
  "favorite",
  "created_at",
  "updated_at",
  "last_used",
];

const insertFullRow = `
  INSERT INTO credentials (
    id, vault_id, title, username, encrypted_password, mode, salt, version,
    release_share_ref, url, notes, tags, favorite, created_at, updated_at, last_used
  ) VALUES (
    'h4-row', 'h4-vault', 'title', 'user', 'ciphertext', 'managed', 'salt', 1,
    'h4-ref', NULL, NULL, '{}', false, now(), now(), NULL
  )
`;

const describeIfDatabase = DATABASE_URL ? describe : describe.skip;

describeIfDatabase("H3/H4: migration 003 against a live PostgreSQL", () => {
  /**
   * A dedicated `Client`, NOT a `Pool`. `pg-pool` destroys and replaces the
   * underlying connection whenever a query errors (see `_release(client, err)`),
   * which would silently move this test onto a fresh connection with no open
   * transaction — and `ROLLBACK TO SAVEPOINT` would then fail with "can only be
   * used in transaction blocks". A `Client` keeps the same connection across a
   * statement error, so the aborted transaction stays ours to roll back.
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

  it(
    "reproduces the shipped defects, repairs them, and is safe to re-run",
    async () => {
      await client.query("BEGIN");
      try {
        // Rebuild `credentials` exactly as 001 creates it. Everything below is
        // rolled back, so this never touches committed data.
        await client.query("DROP TABLE IF EXISTS credentials CASCADE");
        await client.query(migration("001_initial_schema.sql"));

        // --- Prove the vault row for the FK exists after the rebuild. -------
        await client.query(
          `INSERT INTO vaults (id, name, encrypted_data, encryption_key_id, owner_id)
           VALUES ('h4-vault', 'n', 'enc', 'k1', 'u1')
           ON CONFLICT (id) DO NOTHING`,
        );

        // --- 1. H4: the repository's INSERT cannot run on a 001 database. ----
        await client.query("SAVEPOINT before_h4_defect");
        let h4Error: Error | undefined;
        try {
          await client.query(insertFullRow);
        } catch (error) {
          h4Error = error as Error;
        }
        expect(h4Error).toBeDefined();
        expect(h4Error?.message).toMatch(/column "mode" of relation "credentials" does not exist/);
        await client.query("ROLLBACK TO SAVEPOINT before_h4_defect");

        // --- 2. H3: an un-unique release_share_ref accepts a duplicate. ------
        await client.query(
          "ALTER TABLE credentials ADD COLUMN IF NOT EXISTS release_share_ref VARCHAR(255)",
        );
        await client.query(
          `INSERT INTO credentials (id, vault_id, title, username, encrypted_password, release_share_ref)
           VALUES ('dup-a', 'h4-vault', 't', 'u', 'p', 'shared-ref')`,
        );
        await client.query(
          `INSERT INTO credentials (id, vault_id, title, username, encrypted_password, release_share_ref)
           VALUES ('dup-b', 'h4-vault', 't', 'u', 'p', 'shared-ref')`,
        );
        const beforeFix = await client.query(
          `SELECT id FROM credentials WHERE release_share_ref = 'shared-ref' ORDER BY id`,
        );
        expect(beforeFix.rows).toHaveLength(2);

        // --- 3. Apply migration 003 for real. --------------------------------
        await client.query(migration("003_credentials_authoring_and_secret_ref.sql"));

        const columns = await client.query(
          `SELECT column_name FROM information_schema.columns
             WHERE table_name = 'credentials'
               AND column_name IN ('mode', 'salt', 'version', 'release_share_ref')
             ORDER BY column_name`,
        );
        expect(columns.rows.map((row) => row.column_name)).toEqual([
          "mode",
          "release_share_ref",
          "salt",
          "version",
        ]);

        // The duplicate collapsed to one owning row; the other was detached.
        const afterFix = await client.query(
          `SELECT id, release_share_ref FROM credentials
             WHERE id IN ('dup-a', 'dup-b') ORDER BY id`,
        );
        expect(afterFix.rows).toEqual([
          { id: "dup-a", release_share_ref: "shared-ref" },
          { id: "dup-b", release_share_ref: null },
        ]);

        const indexes = await client.query(
          `SELECT indexdef FROM pg_indexes
             WHERE tablename = 'credentials' AND indexname = 'uq_credentials_release_share_ref'`,
        );
        expect(indexes.rows).toHaveLength(1);
        expect(indexes.rows[0].indexdef).toMatch(/^CREATE UNIQUE INDEX/i);
        expect(indexes.rows[0].indexdef).toContain("release_share_ref");

        // The columns migration 003 added are the ones the repository writes.
        for (const column of REPOSITORY_INSERT_COLUMNS) {
          const found = await client.query(
            `SELECT 1 FROM information_schema.columns
               WHERE table_name = 'credentials' AND column_name = $1`,
            [column],
          );
          expect(found.rows).toHaveLength(1);
        }

        // --- 4. Run 003 a SECOND time: a no-op. ------------------------------
        await client.query(migration("003_credentials_authoring_and_secret_ref.sql"));
        const rerun = await client.query(
          `SELECT id, release_share_ref FROM credentials
             WHERE id IN ('dup-a', 'dup-b') ORDER BY id`,
        );
        expect(rerun.rows).toEqual(afterFix.rows);
        const rerunIndexes = await client.query(
          `SELECT count(*)::int AS n FROM pg_indexes
             WHERE tablename = 'credentials' AND indexname = 'uq_credentials_release_share_ref'`,
        );
        expect(rerunIndexes.rows[0].n).toBe(1);

        // --- 5. A duplicate ref is now refused by the database. --------------
        await client.query("SAVEPOINT before_duplicate");
        let duplicateError: Error | undefined;
        try {
          await client.query(
            `INSERT INTO credentials (id, vault_id, title, username, encrypted_password, release_share_ref)
             VALUES ('dup-c', 'h4-vault', 't', 'u', 'p', 'shared-ref')`,
          );
        } catch (error) {
          duplicateError = error as Error;
        }
        expect(duplicateError).toBeDefined();
        expect(duplicateError?.message).toMatch(
          /duplicate key value violates unique constraint "uq_credentials_release_share_ref"/,
        );
        await client.query("ROLLBACK TO SAVEPOINT before_duplicate");

        // --- And a distinct ref is still accepted (no over-blocking). --------
        await client.query(
          `INSERT INTO credentials (id, vault_id, title, username, encrypted_password, release_share_ref)
           VALUES ('distinct-ref', 'h4-vault', 't', 'u', 'p', 'another-ref')`,
        );

        // --- The repository's own DDL is idempotent on the migrated schema. --
        await client.query(repositoryCredentialsDdl());
        await client.query(repositoryCredentialsDdl());
      } finally {
        await client.query("ROLLBACK");
      }
    },
    60_000,
  );
});
