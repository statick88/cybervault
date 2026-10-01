-- CyberVault Migration 007 — human-presence proof for step-up approval (R11)
--
-- WHY THIS EXISTS
-- ---------------
-- `POST /api/v1/step-up/approve` signed an approval for ANY authenticated
-- caller. A compromised background worker holding only the bearer token in
-- `chrome.storage.local` could complete a release with no person present.
-- R11 closes that: approval now requires a proof the token cannot produce —
-- a WebAuthn assertion from a registered authenticator (the real control),
-- or a PBKDF2 proof derived from the user's existing `users.hash` (defence
-- in depth, honestly scoped). Both are bound to ONE approval challenge that
-- Core issues for a single `challengeId` and consumes exactly once.
--
-- WHAT LIVES HERE
-- ---------------
--   * `step_up_approval_challenges` — the one-time challenges Core issues
--     (WebAuthn challenge + per-approval PBKDF2 salt + expected rpId/origin).
--     One row per issued approval challenge; consumed atomically by
--     `handleStepUpApprove` / the authenticator registration route, so a
--     captured assertion or derived proof is not a standing credential.
--   * `user_authenticators` — the user's registered platform authenticator
--     (or security key): credential id, P-256 public key, signature counter,
--     transports. The PRIVATE key never leaves the authenticator, so this
--     table holds only what verification needs — never key material an
--     attacker could use to mint a proof.
--
-- WHAT NEVER LIVES HERE — THE PASSPHRASE
-- --------------------------------------
-- The passphrase proof is `PBKDF2(stored users.hash, salt)` compared against
-- a value the client derived from the passphrase. Neither the passphrase nor
-- `users.hash` is copied here; `salt` is a per-approval random nonce that
-- only COMBINES with knowledge of the passphrase, never reproduces one. A
-- database administrator reading this table cannot pass the third factor.
--
-- BINDING MODEL
-- -------------
-- `binding_id` is what `proof.challengeId` and the passphrase salt bind to:
--   * purpose = 'release' -> the Plus/worker release `challengeId`, so one
--     proof cannot be spent on a different release;
--   * purpose = 'enroll'  -> the row's own `id` (there is no release being
--     approved yet — this challenge gates registering a new authenticator,
--     which MUST be proof-gated too, or a token thief could enroll its own
--     key and defeat R11 in one request).
--
-- TIMESTAMP POLICY
-- ----------------
-- `TIMESTAMPTZ` like every other instant in this schema (see
-- `005_plus_schema.sql`). The store layer converts at the boundary:
-- `new Date(ms)` on the way in, `.getTime()` on the way out.
--
-- Idempotent: every statement is `CREATE TABLE IF NOT EXISTS` /
-- `CREATE INDEX IF NOT EXISTS`, so a second `cli.ts up` is a no-op.
-- Additive: nothing is dropped, renamed, retyped or deleted. The migration
-- runner additionally skips already-applied ids by file name and runs each
-- file in one transaction.

-- ---------------------------------------------------------------------------
-- step_up_approval_challenges — the one-time human-presence challenge
-- ---------------------------------------------------------------------------
-- `challenge` (WebAuthn) and `salt` (PBKDF2) are NOT NULL: a row without
-- them can never be verified against and would fail closed at request time
-- with a confusing "rejected" instead of at issuance where the bug is.
-- `rp_id` / `origin` are NULLABLE on purpose: NULL means "WebAuthn is not
-- configured" (`STEP_UP_WEBAUTHN_RP_ID` / `STEP_UP_WEBAUTHN_ORIGIN` unset),
-- and every webauthn proof against such a row must refuse — fail closed,
-- never fall back to a guessed rpId.
-- `consumed_at` NULL means "still spendable"; one-time use is the
-- `UPDATE ... WHERE consumed_at IS NULL` in the store, not a read-then-write.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS step_up_approval_challenges (
  id VARCHAR(255) PRIMARY KEY,
  binding_id VARCHAR(255) NOT NULL,
  user_id VARCHAR(255) NOT NULL,
  purpose VARCHAR(20) NOT NULL,
  challenge TEXT NOT NULL,
  salt TEXT NOT NULL,
  rp_id VARCHAR(255),
  origin TEXT,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  consumed_at TIMESTAMP WITH TIME ZONE
);

-- One index per query shape the store actually issues; the PRIMARY KEY
-- already covers `findById` and the atomic `consume` by id.
--
--   idx_step_up_approval_challenges_user  — listing a user's live challenges
--                                            (operator sweeps, expiry GC).
--   idx_step_up_approval_challenges_bind  — "which challenges were issued
--                                            for this release challengeId",
--                                            the cross-check the approval
--                                            path asserts against.
CREATE INDEX IF NOT EXISTS idx_step_up_approval_challenges_user
  ON step_up_approval_challenges(user_id);
CREATE INDEX IF NOT EXISTS idx_step_up_approval_challenges_bind
  ON step_up_approval_challenges(binding_id);

-- ---------------------------------------------------------------------------
-- user_authenticators — registered WebAuthn credentials
-- ---------------------------------------------------------------------------
-- The credential id IS the primary key: verification looks the row up by the
-- id the assertion carries, and a credential id is globally unique per
-- (rpId, user) — a second user registering the same id must be refused, not
-- silently re-owned (that would swap the public key under someone else's
-- registered authenticator).
-- `public_key` stores the NORMALIZED uncompressed P-256 point (`04||x||y`,
-- hex) exactly as verification's `importKey` wants it; the SPKI/COSE
-- translation happens once, at registration.
-- `counter` is BIGINT because the authenticator's signCount is a uint32 and
-- PostgreSQL INTEGER tops out below its maximum.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS user_authenticators (
  credential_id VARCHAR(2048) PRIMARY KEY,
  user_id VARCHAR(255) NOT NULL,
  public_key TEXT NOT NULL,
  counter BIGINT NOT NULL DEFAULT 0,
  transports TEXT[] NOT NULL DEFAULT '{}',
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_user_authenticators_user
  ON user_authenticators(user_id);
