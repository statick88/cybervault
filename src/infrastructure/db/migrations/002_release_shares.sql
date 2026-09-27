-- CyberVault Migration 002 — wrapped Release Shares for managed credentials (O5.10)
--
-- WHAT LIVES HERE
-- One row per managed credential: the `iv|ciphertext` blob produced by
-- `src/infrastructure/crypto/release-share-kek.ts`, already wrapped under the
-- Core-held Release Share KEK by the application layer BEFORE it reaches this
-- table.
--
-- WHAT NEVER LIVES HERE
-- No key material (no KEK, no unwrap logic), no plaintext Release Share, no
-- plaintext credential, no username, no password, no TOTP seed, no user
-- origin. `secret_ref` is the opaque reference Plus already sees. Reading
-- this table as a database administrator reveals nothing that can be
-- decrypted without the server-held KEK.
--
-- WHY IT IS DURABLE
-- The previous store was a per-process Map: a share written by one instance
-- was invisible to every other instance (random managed-release failures in a
-- multi-instance deploy) and was lost on restart (permanently orphaning those
-- credentials).
--
-- Idempotent: `CREATE TABLE IF NOT EXISTS`, safe to re-run. The migration
-- runner additionally skips already-applied ids by file name.

CREATE TABLE IF NOT EXISTS release_shares (
  secret_ref VARCHAR(255) NOT NULL PRIMARY KEY,
  wrapped_share TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- INDEX DECISION
-- The PRIMARY KEY on `secret_ref` IS the index for this table. Every query
-- that exists against it is an equality lookup on `secret_ref`:
--   * findBySecretRef — runs on every authorized managed release,
--   * the upsert's ON CONFLICT target — runs on every managed authoring,
--   * delete — runs on credential deletion / share rotation.
-- All three ride the PK's btree (see EXPLAIN: "Index Scan using
-- release_shares_pkey"). A secondary index on `created_at` or
-- `wrapped_share` would serve no query that exists today and would tax every
-- save, so it is deliberately not created. If a retention/cleanup query is
-- ever added, index the column that query filters on at that point.
