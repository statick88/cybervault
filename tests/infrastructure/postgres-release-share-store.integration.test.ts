/**
 * O5.10 — `PostgresReleaseShareStore` against a REAL PostgreSQL server.
 *
 * GATED: every test here is skipped unless `CYBERVAULT_TEST_DATABASE_URL` is
 * set to a throwaway database, so `npx jest` never needs a live server:
 *
 *   CYBERVAULT_TEST_DATABASE_URL=postgresql://.../cybervault_test npx jest \
 *     tests/infrastructure/postgres-release-share-store.integration.test.ts
 *
 * This suite is the empirical proof that the migration SQL executes, that the
 * primary key really makes re-saves replace instead of duplicate, and that the
 * table stores only the three opaque columns.
 */

import { Pool } from "pg";
import * as fs from "fs";
import * as path from "path";
import { PostgresReleaseShareStore } from "../../src/infrastructure/repositories/PostgresReleaseShareStore";

const describeWithPg = process.env.CYBERVAULT_TEST_DATABASE_URL
  ? describe
  : describe.skip;

describeWithPg("PostgresReleaseShareStore (real PostgreSQL)", () => {
  const url = process.env.CYBERVAULT_TEST_DATABASE_URL as string;
  const migrationPath = path.join(
    __dirname,
    "../../src/infrastructure/db/migrations/002_release_shares.sql",
  );
  const secretRef = `o510-test-${Date.now()}`;

  let pool: Pool;
  let store: PostgresReleaseShareStore;

  beforeAll(async () => {
    pool = new Pool({ connectionString: url });
    const migration = fs.readFileSync(migrationPath, "utf-8");
    // Twice: the second run proves the migration is idempotent.
    await pool.query(migration);
    await pool.query(migration);
    store = new PostgresReleaseShareStore(url);
  });

  afterAll(async () => {
    await pool.query("DELETE FROM release_shares WHERE secret_ref LIKE $1", [
      "o510-test-%",
    ]);
    await store.close();
    await pool.end();
  });

  it("creates exactly the three opaque columns behind the secret_ref primary key", async () => {
    const columns = await pool.query(
      `SELECT column_name FROM information_schema.columns
       WHERE table_name = 'release_shares' AND table_schema = current_schema()
       ORDER BY ordinal_position`,
    );
    expect(columns.rows.map((row: { column_name: string }) => row.column_name)).toEqual([
      "secret_ref",
      "wrapped_share",
      "created_at",
    ]);

    const indexes = await pool.query(
      `SELECT indexname FROM pg_indexes
       WHERE tablename = 'release_shares' AND schemaname = current_schema()`,
    );
    expect(indexes.rows.map((row: { indexname: string }) => row.indexname)).toContain(
      "release_shares_pkey",
    );
  });

  it("round-trips, replaces on re-save and deletes", async () => {
    const first = "Zmlyc3QtYmxvYg==";
    const second = "c2Vjb25kLWJsb2I=";

    await store.save({ secretRef, wrappedShare: first, createdAt: new Date() });
    const found = await store.findBySecretRef(secretRef);
    expect(found?.wrappedShare).toBe(first);

    // Re-save the same reference: replace, never duplicate.
    await store.save({ secretRef, wrappedShare: second, createdAt: new Date() });
    const count = await pool.query(
      "SELECT count(*)::int AS n FROM release_shares WHERE secret_ref = $1",
      [secretRef],
    );
    expect(count.rows[0].n).toBe(1);
    expect((await store.findBySecretRef(secretRef))?.wrappedShare).toBe(second);

    expect(await store.delete(secretRef)).toBe(true);
    expect(await store.delete(secretRef)).toBe(false);
    expect(await store.findBySecretRef(secretRef)).toBeNull();
  });

  it("stores only the opaque blob — a row exposes no plaintext secret columns", async () => {
    await store.save({
      secretRef: `${secretRef}-row`,
      wrappedShare: "b3BhcXVlLWJsb2I=",
      createdAt: new Date(),
    });

    const result = await pool.query(
      "SELECT * FROM release_shares WHERE secret_ref = $1",
      [`${secretRef}-row`],
    );
    expect(result.rows).toHaveLength(1);
    expect(Object.keys(result.rows[0]).sort()).toEqual([
      "created_at",
      "secret_ref",
      "wrapped_share",
    ]);

    await store.delete(`${secretRef}-row`);
  });
});
