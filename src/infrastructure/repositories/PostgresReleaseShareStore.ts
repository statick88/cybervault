/**
 * PostgreSQL Release Share store — the durable implementation of
 * `IReleaseShareStore`.
 *
 * WHY THIS EXISTS
 * ---------------
 * The in-memory store keeps each wrapped Release Share inside the process that
 * wrote it, so in a multi-instance deployment an authorized managed release
 * fails depending on which instance receives the request, and every restart
 * orphans the managed credentials whose share it held.
 *
 * SECURITY BOUNDARY (deliberately dumb)
 * -------------------------------------
 * This adapter stores the opaque `wrappedShare` blob keyed by `secretRef` and
 * nothing else: no key material, no KEK, no unwrap/derive logic (wrapping
 * happens in the use cases via `infrastructure/crypto/release-share-kek.ts`),
 * no credential, no username, no password, no TOTP seed, no user origin.
 * Every value reaches PostgreSQL as a bound `$n` parameter; query text is a
 * static constant, never string-interpolated, so no secret can end up inside
 * a query string.
 *
 * FAIL CLOSED
 * -----------
 * Every failure (connection down, table missing, circuit open) is logged and
 * RE-THROWN — never converted into `null`. "Unknown secretRef" and "the
 * database is down" must stay distinguishable: the first is a legitimate
 * refusal, the second is an outage, and collapsing them would let an outage
 * masquerade as "no such reference".
 *
 * @module infrastructure/repositories/PostgresReleaseShareStore
 */

import type { QueryResult } from "pg";
import { Pool } from "pg";
import type { IReleaseShareStore, WrappedReleaseShare } from "../../domain/repositories";
import { logger } from "../../shared/logger";
import { withRetry } from "../../shared/retry";
import { CircuitBreaker } from "../../shared/circuit-breaker";

// Errores PostgreSQL que justifican reintentar la operación
const PG_RETRYABLE_ERRORS = ["ECONNREFUSED", "timeout", "connection terminated"];

// Configuración explícita del pool de conexiones (misma que los demás repos PG)
const PG_POOL_CONFIG = {
  max: 10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 2_000,
};

/*
 * SQL — static text only. Values are ALWAYS bound as parameters ($1..$3);
 * table and column names are compile-time constants. Never interpolate a
 * value (or anything derived from a value) into these strings.
 */

// Replace, never duplicate: ON CONFLICT on the secret_ref primary key.
// Both columns are overwritten, mirroring the in-memory Map.set semantics.
const SAVE_SQL = `
  INSERT INTO release_shares (secret_ref, wrapped_share, created_at)
  VALUES ($1, $2, $3)
  ON CONFLICT (secret_ref) DO UPDATE SET
    wrapped_share = EXCLUDED.wrapped_share,
    created_at = EXCLUDED.created_at
`;

// The only read shape: an equality lookup on the primary key.
const FIND_SQL = `
  SELECT secret_ref, wrapped_share, created_at
  FROM release_shares
  WHERE secret_ref = $1
`;

const DELETE_SQL = `
  DELETE FROM release_shares
  WHERE secret_ref = $1
`;

// Schema self-check (idempotent, non-blocking). The migration
// `db/migrations/002_release_shares.sql` is authoritative for deployments;
// this mirrors it so a dev instance behaves like its sibling repositories.
const CREATE_TABLE_SQL = `
  CREATE TABLE IF NOT EXISTS release_shares (
    secret_ref VARCHAR(255) NOT NULL PRIMARY KEY,
    wrapped_share TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
  )
`;

/**
 * Wrapped Release Shares persisted in PostgreSQL.
 *
 * Implements exactly the same contract as `InMemoryReleaseShareStore`
 * (save / findBySecretRef / delete with null-on-unknown), so the use cases are
 * unaware of which adapter they are given.
 */
export class PostgresReleaseShareStore implements IReleaseShareStore {
  private readonly pool: Pool;
  private readonly circuitBreaker: CircuitBreaker;

  constructor(connectionString: string) {
    this.pool = new Pool({ connectionString, ...PG_POOL_CONFIG });
    this.circuitBreaker = new CircuitBreaker();

    // Manejar errores en clientes inactivos del pool (evita crashes silenciosos)
    this.pool.on("error", (err) => {
      logger.error(
        "Unexpected error on idle PostgreSQL client",
        "PostgresReleaseShareStore",
        undefined,
        String(err),
      );
    });

    // Initialize schema on first use (non-blocking, failure is logged not thrown)
    this.initializeTable().catch((err) => {
      logger.warn(
        "Schema initialization failed (may need manual migration)",
        "PostgresReleaseShareStore",
        { error: String(err) },
      );
    });
  }

  /**
   * Ejecuta una operación protegida por el circuit breaker.
   * PostgreSQL es un componente crítico — no se puede degradar: si el circuito
   * está OPEN se lanza un error descriptivo en lugar de ejecutar la query.
   */
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
    await this.executeWithCircuit(() => this.pool.query(CREATE_TABLE_SQL));
    logger.info("Release shares table initialized", "PostgresReleaseShareStore");
  }

  /**
   * Persiste (o reemplaza) el Release Share envuelto para un secretRef.
   * Sólo se escribe el blob opaco: jamás el share en claro.
   */
  async save(entry: WrappedReleaseShare): Promise<void> {
    try {
      await this.executeWithCircuit(() =>
        withRetry(
          () =>
            this.pool.query(SAVE_SQL, [
              entry.secretRef,
              entry.wrappedShare,
              entry.createdAt,
            ]),
          { maxAttempts: 3, retryableErrors: PG_RETRYABLE_ERRORS },
        ),
      );
      logger.info(
        `Wrapped Release Share saved for secretRef: ${entry.secretRef}`,
        "PostgresReleaseShareStore",
      );
    } catch (error) {
      logger.error(
        "Failed to save wrapped Release Share",
        "PostgresReleaseShareStore",
        undefined,
        String(error),
      );
      // Fail closed: propagate. The caller reports RELEASE_SHARE_PERSIST_FAILED.
      throw error;
    }
  }

  /**
   * Devuelve el blob envuelto, o null sólo cuando la referencia es desconocida.
   * Un fallo de base de datos NUNCA se convierte en null.
   */
  async findBySecretRef(secretRef: string): Promise<WrappedReleaseShare | null> {
    try {
      const result: QueryResult = await this.executeWithCircuit(() =>
        withRetry(
          () => this.pool.query(FIND_SQL, [secretRef]),
          { maxAttempts: 2, retryableErrors: PG_RETRYABLE_ERRORS },
        ),
      );

      if (result.rows.length === 0) {
        return null;
      }

      const row = result.rows[0];
      return {
        secretRef: row.secret_ref,
        wrappedShare: row.wrapped_share,
        createdAt: row.created_at,
      };
    } catch (error) {
      logger.error(
        "Failed to find wrapped Release Share",
        "PostgresReleaseShareStore",
        undefined,
        String(error),
      );
      // Fail closed: an outage must surface as an error, not as "not found".
      throw error;
    }
  }

  /**
   * Elimina un Release Share envuelto (borrado de credencial / rotación).
   * Devuelve true sólo si existía una fila.
   */
  async delete(secretRef: string): Promise<boolean> {
    try {
      const result: QueryResult = await this.executeWithCircuit(() =>
        this.pool.query(DELETE_SQL, [secretRef]),
      );
      const deleted = (result.rowCount ?? 0) > 0;

      if (deleted) {
        logger.info(
          `Wrapped Release Share deleted for secretRef: ${secretRef}`,
          "PostgresReleaseShareStore",
        );
      }
      return deleted;
    } catch (error) {
      logger.error(
        "Failed to delete wrapped Release Share",
        "PostgresReleaseShareStore",
        undefined,
        String(error),
      );
      throw error;
    }
  }

  /** Cierra la conexión al pool de PostgreSQL. */
  async close(): Promise<void> {
    await this.pool.end();
    logger.info("PostgreSQL connection pool closed", "PostgresReleaseShareStore");
  }
}
