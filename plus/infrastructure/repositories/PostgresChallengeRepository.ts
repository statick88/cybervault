/**
 * PostgreSQL Challenge Repository — Plus Domain
 *
 * The one implementation of `IChallengeRepository`. Challenges are the third
 * factor of the authorization flow, so this class is the only place a
 * challenge row crosses the process boundary.
 *
 * SECURITY CONTRACT — NO PLAINTEXT PIN, EVER
 * -------------------------------------------
 * R3 removed the PIN from `ChallengeService.createChallenge()`, so a challenge
 * no longer arrives here with `metadata.generatedPin` in it at all — the
 * metadata key below is kept as the boundary that would stop it if a caller
 * ever reintroduced one. It is stripped in `sanitizeMetadata()` before any
 * INSERT or UPDATE is issued, on every write path (`save` and `update` both
 * funnel through it).
 *
 * `pin_hmac` / `pin_salt` are the legacy R4 columns. Migration
 * `005_plus_schema.sql` has already run and both are `NOT NULL`, so the
 * repository keeps binding them — with an empty string when the challenge
 * carries no value, which is what every challenge created after R3 looks like.
 * An empty string is not verification material for anything, and the type
 * documents the fields as optional for exactly this reason.
 *
 * Style (pool + circuit breaker + retry + snake_case mapping) mirrors the
 * three sibling repositories in this directory.
 */

import type { QueryResult } from "pg";
import { Pool } from "pg";
import type { ChallengeProps, ChallengeStatus, ChallengeType } from "../../domain/services/challenge";
import type { IChallengeRepository } from "../../domain/repositories";
import { logger } from "@/shared/logger";
import { withRetry } from "@/shared/retry";
import { CircuitBreaker } from "@/shared/circuit-breaker";

const PG_RETRYABLE_ERRORS = ["ECONNREFUSED", "timeout", "connection terminated"];
const PG_POOL_CONFIG = {
  max: 10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 2_000,
};

const TABLE = "challenges";

/**
 * The metadata key that must never reach the database.
 *
 * `ChallengeService` no longer writes it (R3 removed the PIN); this
 * repository is the boundary that stops it if that ever regresses.
 * `pin_hmac` / `pin_salt` remain as legacy, now-empty columns.
 */
const PLAINTEXT_PIN_METADATA_KEY = "generatedPin";

/**
 * Statuses that still owe the user an action.
 *
 * Mirrors `ChallengeService.OUTSTANDING` — deliberately NOT including
 * `completed`, `failed` or `expired`, which are spent and must never be
 * resurrected by a later request.
 */
const OUTSTANDING_STATUSES: ChallengeStatus[] = ["pending", "email_sent", "url_accessed"];

/**
 * One row of `challenges`, spelled the way PostgreSQL returns it.
 *
 * A `type` alias (not an interface) so it satisfies pg's `QueryResultRow`
 * constraint through the implicit index signature.
 */
type ChallengeRow = {
  id: string;
  user_id: string;
  resource_id: string;
  operation: string;
  secret_ref: string;
  device_id: string | null;
  type: string;
  status: string;
  nonce: string;
  pin_hmac: string;
  pin_salt: string;
  email_sent_at: Date | null;
  accessed_at: Date | null;
  completed_at: Date | null;
  expires_at: Date;
  attempts: number;
  max_attempts: number;
  risk_score: number | null;
  risk_reasons: string[] | null;
  assurance_level: number;
  created_at: Date;
  updated_at: Date;
  /**
   * `pg` installs a JSON parser for `json`/`jsonb` (OID 114/3802), so this
   * arrives as an already-parsed value, never as a JSON string.
   */
  metadata: Record<string, unknown> | null;
};

/** Unix ms → the `TIMESTAMPTZ` representation used by the table. */
function toTimestamp(ms: number | undefined): Date | null {
  return ms === undefined ? null : new Date(ms);
}

/** The `TIMESTAMPTZ` representation → Unix ms, or `undefined` when NULL. */
function fromTimestamp(value: Date | null | undefined): number | undefined {
  return value ? new Date(value).getTime() : undefined;
}

/**
 * The metadata that may be written, i.e. everything EXCEPT the plaintext PIN.
 *
 * Returns `null` for an absent/now-empty object so the column stays NULL
 * rather than accumulating `'{}'` rows that read as present-but-empty.
 */
function sanitizeMetadata(metadata: Record<string, unknown> | undefined): Record<string, unknown> | null {
  if (!metadata) return null;

  const sanitized: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(metadata)) {
    if (key === PLAINTEXT_PIN_METADATA_KEY) continue;
    sanitized[key] = value;
  }

  return Object.keys(sanitized).length > 0 ? sanitized : null;
}

/** Map a stored row back onto the domain shape. */
function toChallengeProps(row: ChallengeRow): ChallengeProps {
  return {
    id: row.id,
    userId: row.user_id,
    resourceId: row.resource_id,
    operation: row.operation as ChallengeProps["operation"],
    secretRef: row.secret_ref,
    deviceId: row.device_id ?? undefined,
    type: row.type as ChallengeType,
    status: row.status as ChallengeStatus,
    nonce: row.nonce,
    pinHmac: row.pin_hmac,
    pinSalt: row.pin_salt,
    emailSentAt: fromTimestamp(row.email_sent_at),
    accessedAt: fromTimestamp(row.accessed_at),
    completedAt: fromTimestamp(row.completed_at),
    expiresAt: fromTimestamp(row.expires_at) ?? 0,
    attempts: row.attempts,
    maxAttempts: row.max_attempts,
    riskScore: row.risk_score ?? undefined,
    riskReasons: row.risk_reasons ?? undefined,
    assuranceLevel: 3,
    createdAt: fromTimestamp(row.created_at) ?? 0,
    updatedAt: fromTimestamp(row.updated_at) ?? 0,
    metadata: row.metadata ?? undefined,
  };
}

/**
 * Bind a challenge to `$1…$23`.
 *
 * `id` is `$1` in BOTH statements (INSERT's first VALUES placeholder and
 * UPDATE's `WHERE id = $1`), so one array serves `save` and `update` and the
 * two SQL texts cannot drift apart from each other.
 */
function toColumnValues(challenge: ChallengeProps): unknown[] {
  return [
    challenge.id, // $1
    challenge.userId, // $2
    challenge.resourceId, // $3
    challenge.operation, // $4
    challenge.secretRef, // $5
    challenge.deviceId ?? null, // $6
    challenge.type, // $7
    challenge.status, // $8
    challenge.nonce, // $9
    // Legacy NOT NULL columns. Post-R3 challenges carry neither value, and
    // `undefined` would be bound as NULL and violate the constraint, so an
    // empty string is written instead — a stored non-secret.
    challenge.pinHmac ?? "", // $10
    challenge.pinSalt ?? "", // $11
    toTimestamp(challenge.emailSentAt), // $12
    toTimestamp(challenge.accessedAt), // $13
    toTimestamp(challenge.completedAt), // $14
    toTimestamp(challenge.expiresAt), // $15
    challenge.attempts, // $16
    challenge.maxAttempts, // $17
    challenge.riskScore ?? null, // $18
    challenge.riskReasons ?? null, // $19
    challenge.assuranceLevel, // $20
    toTimestamp(challenge.createdAt), // $21
    toTimestamp(challenge.updatedAt), // $22
    JSON.stringify(sanitizeMetadata(challenge.metadata)), // $23 — NULL when nothing survives
  ];
}

export class PostgresChallengeRepository implements IChallengeRepository {
  private pool: Pool;
  private readonly circuitBreaker: CircuitBreaker;

  constructor(connectionString: string) {
    this.pool = new Pool({ connectionString, ...PG_POOL_CONFIG });
    this.circuitBreaker = new CircuitBreaker();

    this.pool.on("error", (err) => {
      logger.error("Unexpected error on idle PostgreSQL client", "PostgresChallengeRepository", undefined, String(err));
    });

    this.initializeTable().catch((err) => {
      logger.warn("Challenge table initialization failed (may need manual migration)", err);
    });
  }

  private executeWithCircuit<T>(fn: () => Promise<T>): Promise<T> {
    if (this.circuitBreaker.getState() === "open") {
      return Promise.reject(
        new Error("PostgreSQL circuit breaker is OPEN — database is critical, cannot degrade"),
      );
    }
    return this.circuitBreaker.execute(fn);
  }

  /**
   * Provision `challenges` on a database that never ran migration 005.
   *
   * Column-for-column and index-for-index identical to
   * `src/infrastructure/db/migrations/005_plus_schema.sql`: whichever of the
   * two runs first wins, the other is a no-op, and the resulting schema is the
   * same either way. This is the arrangement migrations 003/004 document for
   * the Core repositories.
   */
  private async initializeTable(): Promise<void> {
    const createTableQuery = `
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

      CREATE INDEX IF NOT EXISTS idx_challenges_user_id ON challenges(user_id);
      CREATE INDEX IF NOT EXISTS idx_challenges_user_status ON challenges(user_id, status);
      CREATE INDEX IF NOT EXISTS idx_challenges_status ON challenges(status);
      CREATE INDEX IF NOT EXISTS idx_challenges_expires_at ON challenges(expires_at);
    `;

    await this.executeWithCircuit(() => this.pool.query(createTableQuery));
    logger.info("Challenges table initialized");
  }

  async save(challenge: ChallengeProps): Promise<ChallengeProps> {
    // $1 is `id`; $2…$23 are the columns below in order.
    const query = `
      INSERT INTO challenges (
        id, user_id, resource_id, operation, secret_ref, device_id, type, status,
        nonce, pin_hmac, pin_salt, email_sent_at, accessed_at, completed_at,
        expires_at, attempts, max_attempts, risk_score, risk_reasons,
        assurance_level, created_at, updated_at, metadata
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8,
        $9, $10, $11, $12, $13, $14,
        $15, $16, $17, $18, $19,
        $20, $21, $22, $23
      )
      ON CONFLICT (id) DO UPDATE SET
        user_id = EXCLUDED.user_id,
        resource_id = EXCLUDED.resource_id,
        operation = EXCLUDED.operation,
        secret_ref = EXCLUDED.secret_ref,
        device_id = EXCLUDED.device_id,
        type = EXCLUDED.type,
        status = EXCLUDED.status,
        nonce = EXCLUDED.nonce,
        pin_hmac = EXCLUDED.pin_hmac,
        pin_salt = EXCLUDED.pin_salt,
        email_sent_at = EXCLUDED.email_sent_at,
        accessed_at = EXCLUDED.accessed_at,
        completed_at = EXCLUDED.completed_at,
        expires_at = EXCLUDED.expires_at,
        attempts = EXCLUDED.attempts,
        max_attempts = EXCLUDED.max_attempts,
        risk_score = EXCLUDED.risk_score,
        risk_reasons = EXCLUDED.risk_reasons,
        assurance_level = EXCLUDED.assurance_level,
        created_at = EXCLUDED.created_at,
        updated_at = EXCLUDED.updated_at,
        metadata = EXCLUDED.metadata
      RETURNING *;
    `;

    try {
      const result: QueryResult<ChallengeRow> = await this.executeWithCircuit(() =>
        withRetry(
          () => this.pool.query<ChallengeRow>(query, toColumnValues(challenge)),
          { maxAttempts: 3, retryableErrors: PG_RETRYABLE_ERRORS },
        ),
      );
      const persisted = toChallengeProps(result.rows[0]);
      logger.info(`Challenge saved: ${persisted.id}`);
      return persisted;
    } catch (error) {
      logger.error("Failed to save challenge", "PostgresChallengeRepository", undefined, String(error));
      throw error;
    }
  }

  async findById(id: string): Promise<ChallengeProps | null> {
    const query = `SELECT * FROM challenges WHERE id = $1`;
    try {
      const result: QueryResult<ChallengeRow> = await this.executeWithCircuit(() =>
        withRetry(
          () => this.pool.query<ChallengeRow>(query, [id]),
          { maxAttempts: 2, retryableErrors: PG_RETRYABLE_ERRORS },
        ),
      );
      if (result.rows.length === 0) return null;
      return toChallengeProps(result.rows[0]);
    } catch (error) {
      logger.error("Failed to find challenge by id", "PostgresChallengeRepository", undefined, String(error));
      throw error;
    }
  }

  async findByUserId(userId: string): Promise<ChallengeProps[]> {
    const query = `SELECT * FROM challenges WHERE user_id = $1 ORDER BY created_at DESC`;
    try {
      const result: QueryResult<ChallengeRow> = await this.executeWithCircuit(() =>
        withRetry(
          () => this.pool.query<ChallengeRow>(query, [userId]),
          { maxAttempts: 2, retryableErrors: PG_RETRYABLE_ERRORS },
        ),
      );
      return result.rows.map(toChallengeProps);
    } catch (error) {
      logger.error("Failed to find challenges by user id", "PostgresChallengeRepository", undefined, String(error));
      throw error;
    }
  }

  async findPendingByUserId(userId: string): Promise<ChallengeProps[]> {
    // Parameterised, not interpolated: the status list is bound as a text[]
    // so no value ever lands in the SQL text.
    const query = `
      SELECT * FROM challenges
      WHERE user_id = $1 AND status = ANY($2::text[])
      ORDER BY created_at DESC
    `;
    try {
      const result: QueryResult<ChallengeRow> = await this.executeWithCircuit(() =>
        withRetry(
          () => this.pool.query<ChallengeRow>(query, [userId, [...OUTSTANDING_STATUSES]]),
          { maxAttempts: 2, retryableErrors: PG_RETRYABLE_ERRORS },
        ),
      );
      return result.rows.map(toChallengeProps);
    } catch (error) {
      logger.error("Failed to find pending challenges by user id", "PostgresChallengeRepository", undefined, String(error));
      throw error;
    }
  }

  async update(challenge: ChallengeProps): Promise<ChallengeProps> {
    // Deliberately NOT an upsert: `ChallengeService` calls `update()` on a
    // challenge it has already read or written, so a row that is not there is
    // a bug worth surfacing rather than a hole worth papering over. Every
    // column is rewritten because the service mutates the whole entity in
    // memory before handing it back.
    const query = `
      UPDATE challenges SET
        user_id = $2,
        resource_id = $3,
        operation = $4,
        secret_ref = $5,
        device_id = $6,
        type = $7,
        status = $8,
        nonce = $9,
        pin_hmac = $10,
        pin_salt = $11,
        email_sent_at = $12,
        accessed_at = $13,
        completed_at = $14,
        expires_at = $15,
        attempts = $16,
        max_attempts = $17,
        risk_score = $18,
        risk_reasons = $19,
        assurance_level = $20,
        created_at = $21,
        updated_at = $22,
        metadata = $23
      WHERE id = $1
      RETURNING *;
    `;

    try {
      const result: QueryResult<ChallengeRow> = await this.executeWithCircuit(() =>
        withRetry(
          () => this.pool.query<ChallengeRow>(query, toColumnValues(challenge)),
          { maxAttempts: 3, retryableErrors: PG_RETRYABLE_ERRORS },
        ),
      );
      if (result.rows.length === 0) {
        throw new Error(`Challenge not found for update: ${challenge.id}`);
      }
      const persisted = toChallengeProps(result.rows[0]);
      logger.info(`Challenge updated: ${persisted.id} → ${persisted.status}`);
      return persisted;
    } catch (error) {
      logger.error("Failed to update challenge", "PostgresChallengeRepository", undefined, String(error));
      throw error;
    }
  }

  async delete(id: string): Promise<boolean> {
    const query = `DELETE FROM challenges WHERE id = $1 RETURNING id`;
    try {
      const result: QueryResult = await this.executeWithCircuit(() =>
        this.pool.query(query, [id]),
      );
      const deleted = (result.rowCount ?? 0) > 0;
      if (deleted) logger.info(`Challenge deleted: ${id}`);
      else logger.warn(`Attempted to delete non-existent challenge: ${id}`);
      return deleted;
    } catch (error) {
      logger.error("Failed to delete challenge", "PostgresChallengeRepository", undefined, String(error));
      throw error;
    }
  }

  async cleanupExpired(): Promise<number> {
    // Only rows past their own expiry. A completed challenge still inside its
    // window must SURVIVE: `ChallengeService.findCompletedChallenge()` is what
    // lets the capability route accept a proof the user already produced.
    const query = `DELETE FROM challenges WHERE expires_at <= NOW() RETURNING id`;
    try {
      const result: QueryResult = await this.executeWithCircuit(() =>
        withRetry(
          () => this.pool.query(query),
          { maxAttempts: 2, retryableErrors: PG_RETRYABLE_ERRORS },
        ),
      );
      const removed = result.rowCount ?? 0;
      if (removed > 0) logger.info(`Cleaned up ${removed} expired challenge(s)`);
      return removed;
    } catch (error) {
      logger.error("Failed to clean up expired challenges", "PostgresChallengeRepository", undefined, String(error));
      throw error;
    }
  }
}
