-- CyberVault Migration 003 — credentials schema reconciliation (H4) and a
-- unique, server-owned Release Share reference (H3).
--
-- WHY THIS MIGRATION EXISTS
-- -------------------------
-- 001_initial_schema.sql created `credentials` with only the generic columns.
-- `PostgresCredentialRepository` has always INSERTed four more —
-- `mode`, `salt`, `version`, `release_share_ref` — but it declares them in its
-- own `CREATE TABLE IF NOT EXISTS credentials (...)`, which is a NO-OP on any
-- database 001 already ran against. There was no `ALTER TABLE` anywhere in the
-- repository, so every INSERT on a migrated database targeted columns that did
-- not exist. This file is the single authority for those columns, and the
-- repository's DDL mirrors it (the same "migration is authoritative for
-- deployments, repository mirrors it for a dev instance" arrangement that
-- 002 / `PostgresReleaseShareStore` already uses).
--
-- It also makes `release_share_ref` UNIQUE. It was a plain, caller-supplied
-- value: an authenticated user could pick a `secretRef` that collided with
-- another user's and, through the release-share upsert, overwrite that
-- credential's wrapped Release Share.
--
-- SAFETY ON A DATABASE THAT ALREADY RAN 001 / 002
-- -----------------------------------------------
-- * Every DDL statement is `IF NOT EXISTS`, so re-running is a no-op.
-- * `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` is a no-op when the column is
--   already there (a database whose `credentials` table was first created by
--   the repository already has all four).
-- * Columns are only ADDED — nothing is dropped, renamed or retyped, and no
--   existing column's default changes.
-- * `ADD COLUMN ... DEFAULT` in PostgreSQL 11+ rewrites no rows for the
--   non-volatile defaults used here.
-- * The runner executes this file inside a transaction and only records the
--   id after it succeeds, so a partial application is rolled back and re-run.
--
-- PRE-EXISTING DUPLICATE REFERENCES (see the UPDATE below)
-- -------------------------------------------------------
-- The UNIQUE index cannot be created while two credential rows share one
-- `release_share_ref`. Such a row pair is ALREADY the H3 defect: both
-- credentials resolve to a single wrapped Release Share, so either one could
-- be released under one capability. The migration keeps the EARLIEST row
-- (lowest `id`, the primary key, so the choice is deterministic and stable
-- across re-runs) and detaches every later duplicate by setting its
-- `release_share_ref` to NULL.
--
-- A detached row becomes "not managed": `handleVaultManagedRelease` refuses
-- with `Credential is not managed (requires Plus authorization)` and
-- `ManagedReleaseUseCase` refuses with `Credential has no Release Share
-- reference`. That is FAILING CLOSED — the ambiguous credential stops being
-- releasable instead of silently continuing to share another credential's
-- Release Share. The credential row itself, its ciphertext and the wrapped
-- share for the surviving reference are untouched, and the operator can
-- re-author the detached credential to give it its own Release Share.

-- ---------------------------------------------------------------------------
-- 1. Columns the repository's INSERT references but 001 never created (H4).
--    Definitions are byte-for-byte the ones `PostgresCredentialRepository`
--    uses in its own CREATE TABLE, so a migrated database and a repository
--    -created database converge on the same schema.
-- ---------------------------------------------------------------------------

ALTER TABLE credentials ADD COLUMN IF NOT EXISTS mode VARCHAR(20) DEFAULT 'personal';
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS salt TEXT;
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS version INTEGER DEFAULT 1;
ALTER TABLE credentials ADD COLUMN IF NOT EXISTS release_share_ref VARCHAR(255);

-- ---------------------------------------------------------------------------
-- 2. Resolve pre-existing duplicate references before the UNIQUE index.
--    Idempotent: after the first run no row satisfies the EXISTS, so the
--    statement updates zero rows.
-- ---------------------------------------------------------------------------

UPDATE credentials AS c
SET release_share_ref = NULL
WHERE c.release_share_ref IS NOT NULL
  AND EXISTS (
    SELECT 1
    FROM credentials AS d
    WHERE d.release_share_ref = c.release_share_ref
      AND d.id < c.id
  );

-- ---------------------------------------------------------------------------
-- 3. UNIQUE constraint on the Release Share reference (H3).
--
--    The index name is deliberately NOT `idx_credentials_secret_ref`: that
--    name already exists on migrated databases as a NON-unique index, and
--    `CREATE UNIQUE INDEX IF NOT EXISTS` under the same name would silently
--    SKIP — the database would keep the old non-unique index and appear to be
--    protected while it was not. A distinct name guarantees the statement
--    either creates a unique index or (once created) is a no-op.
--
--    A UNIQUE index, not a table CONSTRAINT: `ADD CONSTRAINT ... UNIQUE` is
--    not idempotent (no `IF NOT EXISTS`), and `ADD COLUMN ... UNIQUE` cannot
--    be retried. PostgreSQL treats NULL as distinct, so any credential
--    without a Release Share is unaffected.
-- ---------------------------------------------------------------------------

CREATE UNIQUE INDEX IF NOT EXISTS uq_credentials_release_share_ref
  ON credentials(release_share_ref);
