/**
 * H4 (+ H3) — migration 003 is the schema authority for `credentials`.
 *
 * THE DEFECT (H4)
 * ---------------
 * `001_initial_schema.sql` created `credentials` WITHOUT `mode`, `salt`,
 * `version` and `release_share_ref`. `PostgresCredentialRepository` declares
 * those four in its own `CREATE TABLE IF NOT EXISTS credentials (...)`, which
 * is a NO-OP once 001 has run — and there was not a single `ALTER TABLE`
 * anywhere in the repository — so every INSERT targeted columns that did not
 * exist on a migrated database.
 *
 * THE DEFECT (H3, database half)
 * ------------------------------
 * `credentials.release_share_ref` was indexed but NOT unique, so a
 * caller-chosen `secretRef` could be pointed at another user's row.
 *
 * WHAT IS PINNED HERE (runs without a database)
 * 1. Every column the repository's INSERT writes exists in 001 ∪ 003.
 * 2. The repository's own CREATE TABLE column list is EXACTLY 001 ∪ 003 — the
 *    repository DDL and the migration have been reconciled, not left drifting.
 * 3. 003 adds exactly the four missing columns and nothing else.
 * 4. 003 declares a UNIQUE index over `release_share_ref` (and the repository
 *    mirrors it under the SAME name, so whichever runs first wins).
 * 5. 003 is idempotent and additive: every DDL statement carries
 *    `IF NOT EXISTS`, and the file contains no DROP / TRUNCATE / DELETE.
 *
 * The empirical half — applying it twice against a real PostgreSQL and
 * watching a duplicate `release_share_ref` raise a unique violation — lives in
 * `migration-003.integration.test.ts` (gated on CYBERVAULT_TEST_DATABASE_URL).
 */

import * as fs from "fs";
import * as path from "path";

const MIGRATIONS_DIR = path.join(__dirname, "../../src/infrastructure/db/migrations");
const REPOSITORY_PATH = path.join(
  __dirname,
  "../../src/infrastructure/repositories/PostgresCredentialRepository.ts",
);

const readMigration = (name: string): string =>
  fs.readFileSync(path.join(MIGRATIONS_DIR, name), "utf-8");

const migration001 = readMigration("001_initial_schema.sql");
const migration003 = readMigration("003_credentials_authoring_and_secret_ref.sql");
const migration004 = readMigration("004_optimistic_locking.sql");
const repositorySource = fs.readFileSync(REPOSITORY_PATH, "utf-8");

/** Column names declared in the `CREATE TABLE credentials (...)` body. */
function columnsOfCreateTable(sql: string, table: string): string[] {
  const match = new RegExp(
    `CREATE TABLE IF NOT EXISTS ${table}\\s*\\(([^]*?)\\n\\s*\\);`,
  ).exec(sql);
  if (!match) throw new Error(`CREATE TABLE ${table} not found`);

  const body = match[1];
  const columns: string[] = [];
  for (const rawLine of body.split("\n")) {
    const line = rawLine.trim().replace(/,$/, "");
    if (line === "") continue;
    if (/^(FOREIGN KEY|PRIMARY KEY|CONSTRAINT|CHECK|UNIQUE)\b/i.test(line)) continue;
    const columnMatch = /^([a-z_][a-z0-9_]*)\s+/i.exec(line);
    if (columnMatch) columns.push(columnMatch[1]);
  }
  return columns;
}

/** Column names added by `ALTER TABLE <table> ADD COLUMN IF NOT EXISTS <name>`. */
function columnsAddedByAlter(sql: string, table: string): string[] {
  const pattern = new RegExp(
    `ALTER TABLE ${table}\\s+ADD COLUMN IF NOT EXISTS\\s+([a-z_][a-z0-9_]*)`,
    "gi",
  );
  const columns: string[] = [];
  let match: RegExpExecArray | null;
  while ((match = pattern.exec(sql)) !== null) columns.push(match[1]);
  return columns;
}

/** Column names in the repository's `INSERT INTO credentials (...)` list. */
function insertColumns(source: string): string[] {
  const match = /INSERT INTO credentials\s*\(([^)]*)\)/.exec(source);
  if (!match) throw new Error("INSERT INTO credentials not found in the repository");
  return match[1]
    .split(",")
    .map((column) => column.trim())
    .filter((column) => column !== "");
}

/** Every statement in a migration file, split on `;`. */
function statements(sql: string): string[] {
  return sql
    .split(";")
    .map((statement) => statement.replace(/--[^\n]*/g, "").trim())
    .filter((statement) => statement !== "");
}

const columns001 = columnsOfCreateTable(migration001, "credentials");
const columns003Added = columnsAddedByAlter(migration003, "credentials");
const columns004Added = columnsAddedByAlter(migration004, "credentials");
/** Every column the migrated database has: 001's CREATE TABLE + every ADD COLUMN. */
const effectiveColumns = [...columns001, ...columns003Added, ...columns004Added];
const repositoryCreateColumns = columnsOfCreateTable(
  repositorySource.replace(/`/g, ""),
  "credentials",
);
const writtenColumns = insertColumns(repositorySource);

describe("H4: migration 003 is the single authority for the credentials schema", () => {
  it("001 really is missing the four columns the repository writes", () => {
    // Guards the premise of the finding: if this ever stops being true the
    // rest of the suite is measuring nothing.
    expect(columns001).not.toContain("mode");
    expect(columns001).not.toContain("salt");
    expect(columns001).not.toContain("version");
    expect(columns001).not.toContain("release_share_ref");
  });

  it("003 adds exactly the columns 001 is missing — nothing more", () => {
    expect([...columns003Added].sort()).toEqual([
      "mode",
      "release_share_ref",
      "salt",
      "version",
    ]);
  });

  it("004 adds lock_version to credentials and vaults, idempotently", () => {
    expect([...columns004Added].sort()).toEqual(["lock_version"]);
    expect(columnsAddedByAlter(migration004, "vaults")).toEqual(["lock_version"]);
    for (const statement of statements(migration004).filter((statement) =>
      /^(CREATE|ALTER|DROP|TRUNCATE)\b/i.test(statement),
    )) {
      expect(statement).toMatch(/IF NOT EXISTS/i);
    }
    expect(migration004).not.toMatch(/\bDROP\b/i);
    expect(migration004).not.toMatch(/\bTRUNCATE\b/i);
    expect(migration004).not.toMatch(/\bDELETE\s+FROM\b/i);
  });

  it("creates every column the repository's INSERT references", () => {
    expect(writtenColumns.length).toBeGreaterThan(0);
    for (const column of writtenColumns) {
      expect(effectiveColumns).toContain(column);
    }
  });

  it("the repository's CREATE TABLE matches the migration column for column", () => {
    // This is the assertion that fails while the two DDLs are still drifting:
    // the repository declares 16 columns, migration 001 + 003 define 16, and
    // they must be the SAME 16.
    expect([...repositoryCreateColumns].sort()).toEqual([...effectiveColumns].sort());
  });

  it("every column the repository INSERTs is also in its own CREATE TABLE", () => {
    for (const column of writtenColumns) {
      expect(repositoryCreateColumns).toContain(column);
    }
  });

  it("the repository mirrors migration 003's idempotent ALTERs", () => {
    for (const column of columns003Added) {
      expect(repositorySource).toMatch(
        new RegExp(`ALTER TABLE credentials ADD COLUMN IF NOT EXISTS ${column}\\b`),
      );
    }
  });

  it("migration 003 is idempotent: every DDL statement carries IF NOT EXISTS", () => {
    const ddl = statements(migration003).filter((statement) =>
      /^(CREATE|ALTER|DROP|TRUNCATE)\b/i.test(statement),
    );
    expect(ddl.length).toBeGreaterThan(0);
    for (const statement of ddl) {
      expect(statement).toMatch(/IF NOT EXISTS/i);
    }
  });

  it("migration 003 is additive: nothing is dropped, truncated or deleted", () => {
    expect(migration003).not.toMatch(/\bDROP\b/i);
    expect(migration003).not.toMatch(/\bTRUNCATE\b/i);
    expect(migration003).not.toMatch(/\bDELETE\s+FROM\b/i);
    // And it never rewrites an existing column's type or default.
    expect(migration003).not.toMatch(/ALTER COLUMN/i);
    expect(migration003).not.toMatch(/\bDROP COLUMN\b/i);
  });

  it("migrations run in lexicographic order: 001 < 003 < 004", () => {
    const files = fs
      .readdirSync(MIGRATIONS_DIR)
      .filter((file) => file.endsWith(".sql"))
      .sort();
    expect(files.indexOf("001_initial_schema.sql")).toBeLessThan(
      files.indexOf("003_credentials_authoring_and_secret_ref.sql"),
    );
    expect(files.indexOf("003_credentials_authoring_and_secret_ref.sql")).toBeLessThan(
      files.indexOf("004_optimistic_locking.sql"),
    );
  });
});

describe("H3: release_share_ref is UNIQUE at the database level", () => {
  it("migration 003 declares a unique index over credentials(release_share_ref)", () => {
    expect(migration003).toMatch(
      /CREATE UNIQUE INDEX IF NOT EXISTS \w+\s+ON credentials\(\s*release_share_ref\s*\)/,
    );
  });

  it("the repository mirrors the same unique index under the same name", () => {
    expect(repositorySource).toMatch(
      /CREATE UNIQUE INDEX IF NOT EXISTS uq_credentials_release_share_ref\s+ON credentials\(release_share_ref\)/,
    );
    // The old NON-unique index must not have been left as the repository's
    // only index on that column.
    expect(repositorySource).not.toMatch(
      /CREATE INDEX IF NOT EXISTS idx_credentials_secret_ref/,
    );
  });

  it("resolves pre-existing duplicate references before creating the index", () => {
    // The dedupe keeps exactly one row per reference and must be guarded so a
    // second run touches nothing.
    expect(migration003).toMatch(/UPDATE credentials AS c/i);
    expect(migration003).toMatch(/SET release_share_ref = NULL/i);
    expect(migration003).toMatch(/AND EXISTS\s*\(/i);
  });
});
