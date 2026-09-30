/**
 * PostgreSQL adapters for the R11 step-up proof stores.
 *
 * Same contract as the in-memory twins, so the ApiServer is unaware of which
 * adapter the factory handed it. Design rules copied from
 * `PostgresReleaseShareStore` for the same reasons:
 *
 *   - every value is a bound `$n` parameter; query text is a static
 *     constant, never string-interpolated;
 *   - failures are logged and RE-THROWN, never collapsed into null —
 *     "unknown challenge" and "database down" must stay distinguishable;
 *   - the schema here mirrors `db/migrations/007_step_up_human_proof.sql`
 *     idempotently (migration is authoritative for deployments; a dev
 *     instance that never ran `cli.ts up` still behaves).
 *
 * The security property this file exists for is in `consume()`: one-time use
 * is enforced by a single guarded UPDATE, so two racing requests cannot both
 * receive the row — a read-then-write here would let a captured assertion
 * spend twice.
 *
 * @module infrastructure/repositories/PostgresStepUpProofStores
 */

import type { QueryResult } from "pg";
import { Pool } from "pg";
import type {
  IStepUpApprovalChallengeStore,
  IStepUpAuthenticatorStore,
  StepUpApprovalChallenge,
  StepUpAuthenticator,
} from "../../domain/repositories";
import { logger } from "../../shared/logger";
import { withRetry } from "../../shared/retry";
import { CircuitBreaker } from "../../shared/circuit-breaker";

const PG_RETRYABLE_ERRORS = ["ECONNREFUSED", "timeout", "connection terminated"];

const PG_POOL_CONFIG = {
  max: 10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 2_000,
};

/* ------------------------------------------------------------------ */
/*  Approval challenges                                                 */
/* ------------------------------------------------------------------ */

const CHALLENGE_COLUMNS = `
  id, binding_id, user_id, purpose, challenge, salt, rp_id, origin,
  created_at, expires_at, consumed_at
`;

const CHALLENGE_INSERT_SQL = `
  INSERT INTO step_up_approval_challenges (
    id, binding_id, user_id, purpose, challenge, salt, rp_id, origin,
    created_at, expires_at, consumed_at
  )
  VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NULL)
`;

/**
 * One-time use in ONE statement: the row is marked spent and returned only
 * when every guard holds (owner, not yet spent, not expired). A second
 * concurrent caller's UPDATE matches zero rows and gets null — there is no
 * window where two requests both read "unconsumed".
 */
const CHALLENGE_CONSUME_SQL = `
  UPDATE step_up_approval_challenges
  SET consumed_at = $3
  WHERE id = $1
    AND user_id = $2
    AND consumed_at IS NULL
    AND expires_at > $3
  RETURNING ${CHALLENGE_COLUMNS}
`;

const CHALLENGE_FIND_SQL = `
  SELECT ${CHALLENGE_COLUMNS}
  FROM step_up_approval_challenges
  WHERE id = $1
`;

const CHALLENGE_CREATE_TABLE_SQL = `
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
  )
`;

function mapChallengeRow(row: Record<string, unknown>): StepUpApprovalChallenge {
  return {
    id: row.id as string,
    bindingId: row.binding_id as string,
    userId: row.user_id as string,
    purpose: row.purpose as StepUpApprovalChallenge["purpose"],
    challenge: row.challenge as string,
    salt: row.salt as string,
    rpId: (row.rp_id as string | null) ?? null,
    origin: (row.origin as string | null) ?? null,
    createdAt: (row.created_at as Date).getTime(),
    expiresAt: (row.expires_at as Date).getTime(),
    consumedAt: row.consumed_at ? (row.consumed_at as Date).getTime() : null,
  };
}

export class PostgresStepUpApprovalChallengeStore implements IStepUpApprovalChallengeStore {
  private readonly pool: Pool;
  private readonly circuitBreaker: CircuitBreaker;

  constructor(connectionString: string) {
    this.pool = new Pool({ connectionString, ...PG_POOL_CONFIG });
    this.circuitBreaker = new CircuitBreaker();
    this.pool.on("error", (err) => {
      logger.error(
        "Unexpected error on idle PostgreSQL client",
        "PostgresStepUpApprovalChallengeStore",
        undefined,
        String(err),
      );
    });
    this.initializeTable().catch((err) => {
      logger.warn(
        "Schema initialization failed (may need manual migration)",
        "PostgresStepUpApprovalChallengeStore",
        { error: String(err) },
      );
    });
  }

  private executeWithCircuit<T>(fn: () => Promise<T>): Promise<T> {
    if (this.circuitBreaker.getState() === "open") {
      return Promise.reject(
        new Error(
          "PostgreSQL circuit breaker is OPEN — database is critical, cannot degrade",
        ),
      );
    }
    return this.circuitBreaker.execute(fn);
  }

  private async initializeTable(): Promise<void> {
    await this.executeWithCircuit(() => this.pool.query(CHALLENGE_CREATE_TABLE_SQL));
    logger.info("Step-up approval challenges table initialized", "PostgresStepUpApprovalChallengeStore");
  }

  async save(challenge: StepUpApprovalChallenge): Promise<void> {
    await this.executeWithCircuit(() =>
      withRetry(
        () =>
          this.pool.query(CHALLENGE_INSERT_SQL, [
            challenge.id,
            challenge.bindingId,
            challenge.userId,
            challenge.purpose,
            challenge.challenge,
            challenge.salt,
            challenge.rpId,
            challenge.origin,
            new Date(challenge.createdAt),
            new Date(challenge.expiresAt),
          ]),
        { maxAttempts: 3, retryableErrors: PG_RETRYABLE_ERRORS },
      ),
    );
  }

  async consume(id: string, userId: string, now: number): Promise<StepUpApprovalChallenge | null> {
    const result: QueryResult = await this.executeWithCircuit(() =>
      withRetry(
        () => this.pool.query(CHALLENGE_CONSUME_SQL, [id, userId, new Date(now)]),
        { maxAttempts: 2, retryableErrors: PG_RETRYABLE_ERRORS },
      ),
    );
    if (result.rows.length === 0) return null;
    return mapChallengeRow(result.rows[0]);
  }

  async findById(id: string): Promise<StepUpApprovalChallenge | null> {
    const result: QueryResult = await this.executeWithCircuit(() =>
      withRetry(() => this.pool.query(CHALLENGE_FIND_SQL, [id]), {
        maxAttempts: 2,
        retryableErrors: PG_RETRYABLE_ERRORS,
      }),
    );
    if (result.rows.length === 0) return null;
    return mapChallengeRow(result.rows[0]);
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}

/* ------------------------------------------------------------------ */
/*  Registered authenticators                                           */
/* ------------------------------------------------------------------ */

const AUTHENTICATOR_COLUMNS = `
  credential_id, user_id, public_key, counter, transports, created_at
`;

/**
 * Register, or refresh the key material of the SAME owner.
 *
 * The `WHERE ... user_id = EXCLUDED.user_id` on the conflict branch is the
 * ownership guard: a different user's row is left untouched (rowCount 0 →
 * false), so registering cannot re-bind or break an authenticator someone
 * else already registered. `counter` is deliberately NOT in the update set —
 * re-registering the same credential must never rewind clone detection.
 */
const AUTHENTICATOR_SAVE_SQL = `
  INSERT INTO user_authenticators (
    credential_id, user_id, public_key, counter, transports, created_at
  )
  VALUES ($1, $2, $3, $4, $5, $6)
  ON CONFLICT (credential_id) DO UPDATE SET
    public_key = EXCLUDED.public_key,
    transports = EXCLUDED.transports
  WHERE user_authenticators.user_id = EXCLUDED.user_id
  RETURNING credential_id
`;

const AUTHENTICATOR_FIND_SQL = `
  SELECT ${AUTHENTICATOR_COLUMNS}
  FROM user_authenticators
  WHERE credential_id = $1
`;

const AUTHENTICATOR_LIST_SQL = `
  SELECT ${AUTHENTICATOR_COLUMNS}
  FROM user_authenticators
  WHERE user_id = $1
  ORDER BY created_at
`;

/** Monotonic: a counter only ever advances, so two racing writes converge. */
const AUTHENTICATOR_COUNTER_SQL = `
  UPDATE user_authenticators
  SET counter = $2
  WHERE credential_id = $1 AND counter < $2
`;

const AUTHENTICATOR_CREATE_TABLE_SQL = `
  CREATE TABLE IF NOT EXISTS user_authenticators (
    credential_id VARCHAR(2048) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    public_key TEXT NOT NULL,
    counter BIGINT NOT NULL DEFAULT 0,
    transports TEXT[] NOT NULL DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
  )
`;

function mapAuthenticatorRow(row: Record<string, unknown>): StepUpAuthenticator {
  return {
    credentialId: row.credential_id as string,
    userId: row.user_id as string,
    publicKey: row.public_key as string,
    counter: Number(row.counter),
    transports: (row.transports as string[] | null) ?? [],
    createdAt: (row.created_at as Date).getTime(),
  };
}

export class PostgresStepUpAuthenticatorStore implements IStepUpAuthenticatorStore {
  private readonly pool: Pool;
  private readonly circuitBreaker: CircuitBreaker;

  constructor(connectionString: string) {
    this.pool = new Pool({ connectionString, ...PG_POOL_CONFIG });
    this.circuitBreaker = new CircuitBreaker();
    this.pool.on("error", (err) => {
      logger.error(
        "Unexpected error on idle PostgreSQL client",
        "PostgresStepUpAuthenticatorStore",
        undefined,
        String(err),
      );
    });
    this.initializeTable().catch((err) => {
      logger.warn(
        "Schema initialization failed (may need manual migration)",
        "PostgresStepUpAuthenticatorStore",
        { error: String(err) },
      );
    });
  }

  private executeWithCircuit<T>(fn: () => Promise<T>): Promise<T> {
    if (this.circuitBreaker.getState() === "open") {
      return Promise.reject(
        new Error(
          "PostgreSQL circuit breaker is OPEN — database is critical, cannot degrade",
        ),
      );
    }
    return this.circuitBreaker.execute(fn);
  }

  private async initializeTable(): Promise<void> {
    await this.executeWithCircuit(() => this.pool.query(AUTHENTICATOR_CREATE_TABLE_SQL));
    logger.info("User authenticators table initialized", "PostgresStepUpAuthenticatorStore");
  }

  async save(authenticator: StepUpAuthenticator): Promise<boolean> {
    const result: QueryResult = await this.executeWithCircuit(() =>
      withRetry(
        () =>
          this.pool.query(AUTHENTICATOR_SAVE_SQL, [
            authenticator.credentialId,
            authenticator.userId,
            authenticator.publicKey,
            authenticator.counter,
            [...authenticator.transports],
            new Date(authenticator.createdAt),
          ]),
        { maxAttempts: 3, retryableErrors: PG_RETRYABLE_ERRORS },
      ),
    );
    return result.rows.length > 0;
  }

  async findByCredentialId(credentialId: string): Promise<StepUpAuthenticator | null> {
    const result: QueryResult = await this.executeWithCircuit(() =>
      withRetry(() => this.pool.query(AUTHENTICATOR_FIND_SQL, [credentialId]), {
        maxAttempts: 2,
        retryableErrors: PG_RETRYABLE_ERRORS,
      }),
    );
    if (result.rows.length === 0) return null;
    return mapAuthenticatorRow(result.rows[0]);
  }

  async listByUserId(userId: string): Promise<StepUpAuthenticator[]> {
    const result: QueryResult = await this.executeWithCircuit(() =>
      withRetry(() => this.pool.query(AUTHENTICATOR_LIST_SQL, [userId]), {
        maxAttempts: 2,
        retryableErrors: PG_RETRYABLE_ERRORS,
      }),
    );
    return result.rows.map(mapAuthenticatorRow);
  }

  async updateCounter(credentialId: string, counter: number): Promise<void> {
    await this.executeWithCircuit(() =>
      this.pool.query(AUTHENTICATOR_COUNTER_SQL, [credentialId, counter]),
    );
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}
