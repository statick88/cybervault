-- CyberVault Migration 005 — Plus authorization schema (T1, plus-api-runtime)
--
-- WHAT LIVES HERE
-- The four tables the Plus authorization service (`plus/api`) reads and
-- writes. Plus compiled and passed its unit tests without ever running: none
-- of these tables existed, so every repository was one connection away from
-- failing on `relation ... does not exist`.
--
--   * `challenges`        — step-up challenges: nonce, PIN HMAC + salt, attempt
--                           counters, expiry. Only ever touched by
--                           `plus/infrastructure/repositories/PostgresChallengeRepository`.
--   * `plus_entitlements` — who may do what to which resource (pestillo state).
--   * `plus_users`        — the Plus-side user directory (role, habits, active).
--   * `plus_resources`    — the resource inventory the risk engine scores.
--
-- WHAT NEVER LIVES HERE — THE PLAINTEXT PIN
-- ------------------------------------------
-- `plus/domain/services/challenge.ts` builds a challenge with
-- `metadata: { generatedPin: pin }` and a comment stating that in production
-- the PIN would NOT be stored. That key is stripped by
-- `PostgresChallengeRepository.save()` / `.update()` before the row is written,
-- so this table never holds a plaintext step-up PIN. What it holds is
-- `pin_hmac` + `pin_salt`: material that only CONFIRMS a PIN somebody already
-- knows, never material that reproduces one. A database administrator reading
-- this table gains nothing that lets them pass the third factor.
--
-- TABLE NAMES — WHY `plus_` AND NOT THE SHORT HAND IN THE TASK LIST
-- -----------------------------------------------------------------
-- The task list called these `entitlements` and `resources`. The repositories
-- that read them already query `plus_entitlements`
-- (`PostgresEntitlementRepository`) and `plus_resources`
-- (`PostgresResourceRepository`), and each of those creates exactly that name
-- in its own `initializeTable()`. Emitting `entitlements` / `resources` here
-- would ship two tables that NOTHING reads while the real ones are still
-- auto-created at boot — a migration that documents a schema the application
-- does not use. So the names the SQL actually issues win. `plus_users` already
-- matched the task list. `challenges` had no pre-existing name and is created
-- here, mirrored verbatim by the new repository.
--
-- TIMESTAMP POLICY
-- ----------------
-- The domain models every instant as Unix milliseconds (`ChallengeProps`).
-- They are stored as `TIMESTAMPTZ` so the columns behave like every other
-- timestamp in this database and `cleanupExpired` can compare against `NOW()`
-- without a unit conversion inside the predicate. The repository converts at
-- the boundary: `new Date(ms)` on the way in, `.getTime()` on the way out.
--
-- Idempotent: every statement is `CREATE TABLE IF NOT EXISTS` /
-- `CREATE INDEX IF NOT EXISTS`, so a second `cli.ts up` is a no-op — and so is
-- this migration against a database where the repositories' own
-- `initializeTable()` already provisioned the same objects. Additive: nothing
-- is dropped, renamed, retyped or deleted. The migration runner additionally
-- skips already-applied ids by file name and runs each file in one
-- transaction.

-- ---------------------------------------------------------------------------
-- challenges — the step-up third factor
-- ---------------------------------------------------------------------------
-- `pin_hmac` / `pin_salt` are NOT NULL: a challenge without them can never be
-- verified and would silently fail at `ChallengeService.verifyPin`.
-- `expires_at` is NOT NULL because every read path filters on it and
-- `cleanupExpired` deletes on it — an unbounded expiry would be a challenge
-- that can neither expire nor be reclaimed.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS challenges (
  id VARCHAR(255) PRIMARY KEY,
  user_id VARCHAR(255) NOT NULL,
  resource_id VARCHAR(255) NOT NULL,
  operation VARCHAR(50) NOT NULL,
  secret_ref VARCHAR(255) NOT NULL,
  device_id VARCHAR(255),
  type VARCHAR(20) NOT NULL,
  status VARCHAR(20) NOT NULL,
  nonce TEXT NOT NULL,
  pin_hmac TEXT NOT NULL,
  pin_salt TEXT NOT NULL,
  email_sent_at TIMESTAMP WITH TIME ZONE,
  accessed_at TIMESTAMP WITH TIME ZONE,
  completed_at TIMESTAMP WITH TIME ZONE,
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 3,
  risk_score INTEGER,
  risk_reasons TEXT[] DEFAULT '{}',
  assurance_level SMALLINT NOT NULL DEFAULT 3,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
  metadata JSONB
);

-- INDEX DECISION (challenges)
-- ---------------------------
-- One index per query shape the repository actually issues; the PK already
-- covers `findById`, `save`, `update` and `delete`.
--
--   idx_challenges_user_id      — `findByUserId()`. The capability gate and
--                                 `ChallengeService.findOutstandingChallenge()`
--                                 both start from a user id on every request.
--   idx_challenges_user_status  — `findPendingByUserId()`, which filters on
--                                 user id AND a closed set of statuses. This is
--                                 the composite the hot path rides.
--   idx_challenges_status       — `status` is named explicitly by the task and
--                                 is the column an operator sweeps on ("show me
--                                 everything stuck pending"), which is NOT a
--                                 per-user query and therefore is not served by
--                                 the composite above.
--   idx_challenges_expires_at   — `cleanupExpired()` deletes `expires_at <=
--                                 NOW()`. Without this index that sweep is a
--                                 sequential scan over every challenge ever
--                                 written, on a timer.
CREATE INDEX IF NOT EXISTS idx_challenges_user_id ON challenges(user_id);
CREATE INDEX IF NOT EXISTS idx_challenges_user_status ON challenges(user_id, status);
CREATE INDEX IF NOT EXISTS idx_challenges_status ON challenges(status);
CREATE INDEX IF NOT EXISTS idx_challenges_expires_at ON challenges(expires_at);

-- ---------------------------------------------------------------------------
-- plus_entitlements / plus_users / plus_resources
-- ---------------------------------------------------------------------------
-- These three DDL blocks are copied column-for-column and index-for-index from
-- the `initializeTable()` of the repository that owns them
-- (`PostgresEntitlementRepository`, `PostgresPlusUserRepository`,
-- `PostgresResourceRepository`). The two must stay in sync: whichever runs
-- first provisions the objects, and the other one becomes a no-op. Divergence
-- would mean a migrated database and a bootstrapped database differ in schema
-- depending on which happened first.
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS plus_entitlements (
  id VARCHAR(512) PRIMARY KEY, -- userId:resourceId
  user_id VARCHAR(255) NOT NULL,
  resource_id VARCHAR(255) NOT NULL,
  pestillo_state VARCHAR(20) NOT NULL DEFAULT 'closed',
  allowed_operations TEXT[] DEFAULT '{}',
  valid_from TIMESTAMP WITH TIME ZONE,
  valid_until TIMESTAMP WITH TIME ZONE,
  metadata JSONB,
  created_by VARCHAR(255) NOT NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_plus_entitlements_user_id ON plus_entitlements(user_id);
CREATE INDEX IF NOT EXISTS idx_plus_entitlements_resource_id ON plus_entitlements(resource_id);
CREATE INDEX IF NOT EXISTS idx_plus_entitlements_pestillo_state ON plus_entitlements(pestillo_state);
CREATE INDEX IF NOT EXISTS idx_plus_entitlements_valid_until ON plus_entitlements(valid_until);
CREATE INDEX IF NOT EXISTS idx_plus_entitlements_user_resource ON plus_entitlements(user_id, resource_id);

CREATE TABLE IF NOT EXISTS plus_users (
  id VARCHAR(255) PRIMARY KEY,
  email VARCHAR(255) NOT NULL UNIQUE,
  name VARCHAR(255) NOT NULL,
  role VARCHAR(50) NOT NULL DEFAULT 'operator',
  habitual_countries TEXT[] DEFAULT '{}',
  timezone VARCHAR(100) NOT NULL DEFAULT 'UTC',
  active BOOLEAN DEFAULT TRUE,
  metadata JSONB,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  last_login_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_plus_users_email ON plus_users(email);
CREATE INDEX IF NOT EXISTS idx_plus_users_role ON plus_users(role);
CREATE INDEX IF NOT EXISTS idx_plus_users_active ON plus_users(active);

CREATE TABLE IF NOT EXISTS plus_resources (
  id VARCHAR(255) PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  type VARCHAR(50) NOT NULL,
  endpoint TEXT NOT NULL,
  environment VARCHAR(50) NOT NULL,
  criticality VARCHAR(20) NOT NULL,
  description TEXT,
  tags TEXT[] DEFAULT '{}',
  owner_team VARCHAR(255),
  metadata JSONB,
  active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_plus_resources_type ON plus_resources(type);
CREATE INDEX IF NOT EXISTS idx_plus_resources_environment ON plus_resources(environment);
CREATE INDEX IF NOT EXISTS idx_plus_resources_criticality ON plus_resources(criticality);
CREATE INDEX IF NOT EXISTS idx_plus_resources_active ON plus_resources(active);
CREATE INDEX IF NOT EXISTS idx_plus_resources_owner_team ON plus_resources(owner_team);
CREATE INDEX IF NOT EXISTS idx_plus_resources_tags ON plus_resources USING GIN(tags);
