// PostgreSQL Credential Repository Implementation
// Implementa ICredentialRepository usando PostgreSQL para persistencia

import type { QueryResult } from "pg";
import { Pool } from "pg";
import { Credential } from "../../domain/entities/credential";
import type { CredentialId, VaultId } from "../../domain/value-objects/ids";
import { logger } from "../../shared/logger";
import { withRetry } from "../../shared/retry";
import { CircuitBreaker } from "../../shared/circuit-breaker";

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
   */
  private async initializeTable(): Promise<void> {
    const createTableQuery = `
      CREATE TABLE IF NOT EXISTS credentials (
        id VARCHAR(36) PRIMARY KEY,
        vault_id VARCHAR(36) NOT NULL,
        title VARCHAR(255) NOT NULL,
        username VARCHAR(255) NOT NULL,
        encrypted_password TEXT NOT NULL,
        url TEXT,
        notes TEXT,
        tags TEXT[] DEFAULT '{}',
        favorite BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        last_used TIMESTAMP WITH TIME ZONE,
        FOREIGN KEY (vault_id) REFERENCES vaults(id) ON DELETE CASCADE
      );
      
      CREATE INDEX IF NOT EXISTS idx_credentials_vault_id ON credentials(vault_id);
      CREATE INDEX IF NOT EXISTS idx_credentials_created_at ON credentials(created_at);
      CREATE INDEX IF NOT EXISTS idx_credentials_favorite ON credentials(favorite);
    `;

    await this.executeWithCircuit(() => this.pool.query(createTableQuery));
    logger.info("Credentials table initialized");
  }

  /**
   * Guarda una credencial en la base de datos
   */
  async save(credential: Credential): Promise<Credential> {
    const plain = credential.toPlainObject();

    const query = `
      INSERT INTO credentials (
        id, vault_id, title, username, encrypted_password, url, notes, tags, favorite, 
        created_at, updated_at, last_used
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
      )
      ON CONFLICT (id) DO UPDATE SET
        vault_id = EXCLUDED.vault_id,
        title = EXCLUDED.title,
        username = EXCLUDED.username,
        encrypted_password = EXCLUDED.encrypted_password,
        url = EXCLUDED.url,
        notes = EXCLUDED.notes,
        tags = EXCLUDED.tags,
        favorite = EXCLUDED.favorite,
        updated_at = EXCLUDED.updated_at,
        last_used = EXCLUDED.last_used
      RETURNING *;
    `;

    const values = [
      plain.id,
      plain.vaultId,
      plain.title,
      plain.username,
      plain.encryptedPassword,
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
      });
    } catch (error) {
      logger.error("Failed to save credential", "PostgresCredentialRepository", undefined, String(error));
      throw error;
    }
  }

  /**
   * Obtiene una credencial por su ID
   */
  async findById(id: CredentialId): Promise<Credential | null> {
    const query = `
      SELECT id, vault_id, title, username, encrypted_password, url, notes, tags, favorite, 
             created_at, updated_at, last_used
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
      SELECT id, vault_id, title, username, encrypted_password, url, notes, tags, favorite, 
             created_at, updated_at, last_used
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
      SELECT id, vault_id, title, username, encrypted_password, url, notes, tags, favorite, 
             created_at, updated_at, last_used
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
