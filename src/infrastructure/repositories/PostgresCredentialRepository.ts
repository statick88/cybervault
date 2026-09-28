// PostgreSQL Credential Repository Implementation
// Implementa ICredentialRepository usando PostgreSQL para persistencia

import type { QueryResult } from "pg";
import { Pool } from "pg";
import { Credential } from "../../domain/entities/credential";
import type { CredentialId, VaultId } from "../../domain/value-objects/ids";
import { logger } from "../../shared/logger";
import { withRetry } from "../../shared/retry";
import { CircuitBreaker } from "../../shared/circuit-breaker";
import { OptimisticLockConflictError } from "../../domain/errors/optimistic-lock-conflict.error";

// Errores PostgreSQL que justifican reintentar la operación
const PG_RETRYABLE_ERRORS = ["ECONNREFUSED", "timeout", "connection terminated"];

// Configuración explícita del pool de conexiones
const PG_POOL_CONFIG = {
  max: 10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 2_000,
};

/**
 * Interfaz del repositorio de credenciales (debe agregarse al dominio)
 */
export interface ICredentialRepository {
  save(credential: Credential): Promise<Credential>;
  findById(id: CredentialId): Promise<Credential | null>;
  findByVaultId(vaultId: VaultId): Promise<Credential[]>;
  findBySecretRef(secretRef: string): Promise<Credential | null>;
  delete(id: CredentialId): Promise<boolean>;
  list(): Promise<Credential[]>;
}

/**
 * Repositorio de credenciales basado en PostgreSQL
 * Almacena las credenciales en una base de datos PostgreSQL
 */
export class PostgresCredentialRepository implements ICredentialRepository {
  private pool: Pool;
  private readonly circuitBreaker: CircuitBreaker;

  constructor(connectionString: string) {
    this.pool = new Pool({ connectionString, ...PG_POOL_CONFIG });
    this.circuitBreaker = new CircuitBreaker();

    // Manejar errores en clientes inactivos del pool (evita crashes silenciosos)
    this.pool.on("error", (err) => {
      logger.error("Unexpected error on idle PostgreSQL client", "PostgresCredentialRepository", undefined, String(err));
    });

    // Initialize schema on first use (non-blocking)
    this.initializeTable().catch((err) => {
      logger.warn("Schema initialization failed (may need manual migration)", err);
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

  /**
   * Inicializa la tabla de credenciales si no existe
   *
   * SCHEMA AUTHORITY
   * ----------------
   * `db/migrations/003_credentials_authoring_and_secret_ref.sql` (columns and
   * the unique reference index) and `004_optimistic_locking.sql`
   * (`lock_version`) are the single authority for deployed databases; this
   * block MIRRORS them so a dev instance
   * that never ran the migration runner behaves the same (the arrangement
   * `PostgresReleaseShareStore` already documents for 002).
   *
   * The `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` statements are the part
   * that matters: `CREATE TABLE IF NOT EXISTS` is a NO-OP on any database
   * where `db/migrations/001_initial_schema.sql` already created `credentials`
   * — which has none of `mode`, `salt`, `version`, `release_share_ref` — so
   * without them every INSERT below would target columns that do not exist.
   * The column definitions are byte-for-byte the ones in migration 003.
   *
   * `uq_credentials_release_share_ref` makes `release_share_ref` UNIQUE (H3).
   * It reuses migration 003's name deliberately: `idx_credentials_secret_ref`
   * already exists on migrated databases as a NON-unique index, so creating a
   * "unique" index under that name with IF NOT EXISTS would silently skip.
   */
  private async initializeTable(): Promise<void> {
    const createTableQuery = `
      CREATE TABLE IF NOT EXISTS credentials (
        id VARCHAR(36) PRIMARY KEY,
        vault_id VARCHAR(36) NOT NULL,
        title VARCHAR(255) NOT NULL,
        username VARCHAR(255) NOT NULL,
        encrypted_password TEXT NOT NULL,
        mode VARCHAR(20) DEFAULT 'personal',
        salt TEXT,
        version INTEGER DEFAULT 1,
        release_share_ref VARCHAR(255),
        url TEXT,
        notes TEXT,
        tags TEXT[] DEFAULT '{}',
        favorite BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        last_used TIMESTAMP WITH TIME ZONE,
        lock_version BIGINT NOT NULL DEFAULT 1,
        FOREIGN KEY (vault_id) REFERENCES vaults(id) ON DELETE CASCADE
      );

      ALTER TABLE credentials ADD COLUMN IF NOT EXISTS mode VARCHAR(20) DEFAULT 'personal';
      ALTER TABLE credentials ADD COLUMN IF NOT EXISTS salt TEXT;
      ALTER TABLE credentials ADD COLUMN IF NOT EXISTS version INTEGER DEFAULT 1;
      ALTER TABLE credentials ADD COLUMN IF NOT EXISTS release_share_ref VARCHAR(255);
      ALTER TABLE credentials ADD COLUMN IF NOT EXISTS lock_version BIGINT NOT NULL DEFAULT 1;

      CREATE INDEX IF NOT EXISTS idx_credentials_vault_id ON credentials(vault_id);
      CREATE INDEX IF NOT EXISTS idx_credentials_created_at ON credentials(created_at);
      CREATE INDEX IF NOT EXISTS idx_credentials_favorite ON credentials(favorite);
      CREATE UNIQUE INDEX IF NOT EXISTS uq_credentials_release_share_ref ON credentials(release_share_ref);
    `;

    await this.executeWithCircuit(() => this.pool.query(createTableQuery));
    logger.info("Credentials table initialized");
  }

  /**
   * Guarda una credencial en la base de datos
   *
   * H5: passing `expectedVersion` switches to a GUARDED write — see
   * `saveGuarded`. Omitting it preserves the original blind upsert, which is
   * what every existing caller does.
   */
  async save(credential: Credential, expectedVersion?: number): Promise<Credential> {
    if (expectedVersion !== undefined) {
      return this.saveGuarded(credential, expectedVersion);
    }
    const plain = credential.toPlainObject();

    // `lock_version = credentials.lock_version + 1`, NOT `EXCLUDED.lock_version`
    // — the column is database-owned and never bound in the INSERT, so a blind
    // writer still invalidates the copies held by guarded callers.
    const query = `
      INSERT INTO credentials (
        id, vault_id, title, username, encrypted_password, mode, salt, version, release_share_ref,
        url, notes, tags, favorite, 
        created_at, updated_at, last_used
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16
      )
      ON CONFLICT (id) DO UPDATE SET
        vault_id = EXCLUDED.vault_id,
        title = EXCLUDED.title,
        username = EXCLUDED.username,
        encrypted_password = EXCLUDED.encrypted_password,
        mode = EXCLUDED.mode,
        salt = EXCLUDED.salt,
        version = EXCLUDED.version,
        release_share_ref = EXCLUDED.release_share_ref,
        url = EXCLUDED.url,
        notes = EXCLUDED.notes,
        tags = EXCLUDED.tags,
        favorite = EXCLUDED.favorite,
        updated_at = EXCLUDED.updated_at,
        last_used = EXCLUDED.last_used,
        lock_version = credentials.lock_version + 1
      RETURNING *;
    `;

    const values = [
      plain.id,
      plain.vaultId,
      plain.title,
      plain.username,
      plain.encryptedPassword,
      plain.mode,
      plain.salt,
      plain.version,
      plain.releaseShareRef || null,
      plain.url || null,
      plain.notes || null,
      plain.tags,
      plain.favorite,
      plain.createdAt,
      plain.updatedAt,
      plain.lastUsed || null,
    ];

    try {
      const result: QueryResult = await this.executeWithCircuit(() =>
        withRetry(
          () => this.pool.query(query, values),
          { maxAttempts: 3, retryableErrors: PG_RETRYABLE_ERRORS },
        ),
      );
      const row = result.rows[0];

      logger.info(`Credential saved with id: ${plain.id}`);
      return Credential.fromPlainObject({
        ...row,
        tags: row.tags || [],
        vaultId: row.vault_id,
        encryptedPassword: row.encrypted_password,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
        lastUsed: row.last_used,
        lockVersion: row.lock_version,
      });
    } catch (error) {
      logger.error("Failed to save credential", "PostgresCredentialRepository", undefined, String(error));
      throw error;
    }
  }

  /**
   * H5 — guarded save. One `UPDATE ... WHERE id = $1 AND lock_version = $N`
   * and NOTHING ELSE: no `INSERT`, so a guarded write can never resurrect a
   * deleted credential, and can never mint a fresh row that collides with the
   * unique `release_share_ref`. Zero affected rows means the row is gone or
   * somebody else committed first; both surface as
   * `OptimisticLockConflictError`.
   */
  private async saveGuarded(credential: Credential, expectedVersion: number): Promise<Credential> {
    const plain = credential.toPlainObject();

    const query = `
      UPDATE credentials
      SET vault_id = $2,
          title = $3,
          username = $4,
          encrypted_password = $5,
          mode = $6,
          salt = $7,
          version = $8,
          release_share_ref = $9,
          url = $10,
          notes = $11,
          tags = $12,
          favorite = $13,
          updated_at = $14,
          last_used = $15,
          lock_version = credentials.lock_version + 1
      WHERE id = $1 AND lock_version = $16
      RETURNING *;
    `;

    const values = [
      plain.id,
      plain.vaultId,
      plain.title,
      plain.username,
      plain.encryptedPassword,
      plain.mode,
      plain.salt,
      plain.version,
      plain.releaseShareRef || null,
      plain.url || null,
      plain.notes || null,
      plain.tags,
      plain.favorite,
      plain.updatedAt,
      plain.lastUsed || null,
      expectedVersion,
    ];

    let result: QueryResult;
    try {
      result = await this.executeWithCircuit(() =>
        withRetry(
          () => this.pool.query(query, values),
          { maxAttempts: 3, retryableErrors: PG_RETRYABLE_ERRORS },
        ),
      );
    } catch (error) {
      logger.error("Failed to save credential (guarded)", "PostgresCredentialRepository", undefined, String(error));
      throw error;
    }

    if ((result.rowCount ?? 0) === 0) {
      throw await this.lockConflict(plain.id, expectedVersion);
    }

    const row = result.rows[0];
    logger.info(`Credential saved with id: ${plain.id} (lock_version ${row.lock_version})`);
    return Credential.fromPlainObject({
      ...row,
      tags: row.tags || [],
      vaultId: row.vault_id,
      encryptedPassword: row.encrypted_password,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      lastUsed: row.last_used,
      lockVersion: row.lock_version,
    });
  }

  /**
   * Reads the version actually stored so the conflict reports WHICH happened
   * — a stale version or a missing row — instead of guessing. A failure here
   * must not mask the original conflict, so it degrades to "version unknown".
   */
  private async lockConflict(
    id: string,
    expectedVersion: number,
  ): Promise<OptimisticLockConflictError> {
    let actualVersion: number | undefined;
    try {
      const result: QueryResult = await this.executeWithCircuit(() =>
        this.pool.query(`SELECT lock_version FROM credentials WHERE id = $1`, [id]),
      );
      if (result.rows.length > 0) {
        actualVersion = Number(result.rows[0].lock_version);
      }
    } catch (error) {
      logger.warn("Could not read lock_version for conflict report", String(error));
    }

    const conflict = new OptimisticLockConflictError("credential", id, expectedVersion, actualVersion);
    logger.warn(conflict.message);
    return conflict;
  }

  /**
   * Obtiene una credencial por su ID
   */
  async findById(id: CredentialId): Promise<Credential | null> {
    const query = `
      SELECT id, vault_id, title, username, encrypted_password, mode, salt, version, release_share_ref,
             url, notes, tags, favorite, 
             created_at, updated_at, last_used, lock_version
      FROM credentials
      WHERE id = $1
    `;

    try {
      const result: QueryResult = await this.executeWithCircuit(() =>
        withRetry(
          () => this.pool.query(query, [id.toString()]),
          { maxAttempts: 2, retryableErrors: PG_RETRYABLE_ERRORS },
        ),
      );

      if (result.rows.length === 0) {
        return null;
      }

      const row = result.rows[0];

      logger.info(`Credential found with id: ${id.toString()}`);
      return Credential.fromPlainObject({
        ...row,
        tags: row.tags || [],
        vaultId: row.vault_id,
        encryptedPassword: row.encrypted_password,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
        lastUsed: row.last_used,
        lockVersion: row.lock_version,
      });
    } catch (error) {
      logger.error("Failed to find credential by id", "PostgresCredentialRepository", undefined, String(error));
      throw error;
    }
  }

  /**
   * Obtiene todas las credenciales de un vault específico
   */
  async findByVaultId(vaultId: VaultId): Promise<Credential[]> {
    const query = `
      SELECT id, vault_id, title, username, encrypted_password, mode, salt, version, release_share_ref,
             url, notes, tags, favorite, 
             created_at, updated_at, last_used, lock_version
      FROM credentials
      WHERE vault_id = $1
      ORDER BY created_at DESC
    `;

    try {
      const result: QueryResult = await this.executeWithCircuit(() =>
        withRetry(
          () => this.pool.query(query, [vaultId.toString()]),
          { maxAttempts: 2, retryableErrors: PG_RETRYABLE_ERRORS },
        ),
      );

      const credentials = result.rows.map((row) =>
        Credential.fromPlainObject({
          ...row,
          tags: row.tags || [],
          vaultId: row.vault_id,
          encryptedPassword: row.encrypted_password,
          createdAt: row.created_at,
          updatedAt: row.updated_at,
          lastUsed: row.last_used,
          lockVersion: row.lock_version,
        }),
      );

      logger.info(
        `Found ${credentials.length} credentials for vault ${vaultId.toString()}`,
      );
      return credentials;
    } catch (error) {
      logger.error("Failed to find credentials by vault id", "PostgresCredentialRepository", undefined, String(error));
      throw error;
    }
  }

  /**
   * Obtiene una credencial por su secretRef (para managed release)
   */
  async findBySecretRef(secretRef: string): Promise<Credential | null> {
    const query = `
      SELECT id, vault_id, title, username, encrypted_password, mode, salt, version, release_share_ref,
             url, notes, tags, favorite, 
             created_at, updated_at, last_used, lock_version
      FROM credentials
      WHERE release_share_ref = $1
    `;

    try {
      const result: QueryResult = await this.executeWithCircuit(() =>
        withRetry(
          () => this.pool.query(query, [secretRef]),
          { maxAttempts: 2, retryableErrors: PG_RETRYABLE_ERRORS },
        ),
      );

      if (result.rows.length === 0) {
        return null;
      }

      const row = result.rows[0];

      logger.info(`Credential found with secretRef: ${secretRef}`);
      return Credential.fromPlainObject({
        ...row,
        tags: row.tags || [],
        vaultId: row.vault_id,
        encryptedPassword: row.encrypted_password,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
        lastUsed: row.last_used,
        lockVersion: row.lock_version,
      });
    } catch (error) {
      logger.error("Failed to find credential by secretRef", "PostgresCredentialRepository", undefined, String(error));
      throw error;
    }
  }

  /**
   * Elimina una credencial por su ID
   */
  async delete(id: CredentialId): Promise<boolean> {
    const query = `
      DELETE FROM credentials
      WHERE id = $1
      RETURNING id
    `;

    try {
      const result: QueryResult = await this.executeWithCircuit(() =>
        this.pool.query(query, [id.toString()]),
      );
      const deleted = (result.rowCount ?? 0) > 0;

      if (deleted) {
        logger.info(`Credential deleted with id: ${id.toString()}`);
      } else {
        logger.warn(
          `Attempted to delete non-existent credential with id: ${id.toString()}`,
        );
      }

      return deleted;
    } catch (error) {
      logger.error("Failed to delete credential", "PostgresCredentialRepository", undefined, String(error));
      throw error;
    }
  }

  /**
   * Lista todas las credenciales
   */
  async list(): Promise<Credential[]> {
    const query = `
      SELECT id, vault_id, title, username, encrypted_password, mode, salt, version, release_share_ref,
             url, notes, tags, favorite, 
             created_at, updated_at, last_used, lock_version
      FROM credentials
      ORDER BY created_at DESC
    `;

    try {
      const result: QueryResult = await this.executeWithCircuit(() =>
        withRetry(
          () => this.pool.query(query),
          { maxAttempts: 2, retryableErrors: PG_RETRYABLE_ERRORS },
        ),
      );

      const credentials = result.rows.map((row) =>
        Credential.fromPlainObject({
          ...row,
          tags: row.tags || [],
          vaultId: row.vault_id,
          encryptedPassword: row.encrypted_password,
          createdAt: row.created_at,
          updatedAt: row.updated_at,
          lastUsed: row.last_used,
          lockVersion: row.lock_version,
        }),
      );

      logger.info(`Listed ${credentials.length} credentials`);
      return credentials;
    } catch (error) {
      logger.error("Failed to list credentials", "PostgresCredentialRepository", undefined, String(error));
      throw error;
    }
  }

  /**
   * Verifica la conectividad con PostgreSQL (SELECT 1)
   */
  async isHealthy(): Promise<boolean> {
    try {
      await this.executeWithCircuit(() => this.pool.query("SELECT 1"));
      return true;
    } catch (error) {
      logger.error("PostgreSQL health check failed", "PostgresCredentialRepository", undefined, String(error));
      return false;
    }
  }

  /**
   * Cierra la conexión al pool de PostgreSQL
   */
  async close(): Promise<void> {
    await this.pool.end();
    logger.info("PostgreSQL connection pool closed");
  }
}
