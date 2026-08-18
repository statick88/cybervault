// PostgreSQL Vault Repository Implementation
// Implementa IVaultRepository usando PostgreSQL para persistencia

import type { QueryResult } from "pg";
import { Pool } from "pg";
import { Vault } from "../../domain/entities/vault";
import type { VaultId } from "../../domain/value-objects/ids";
import type { IVaultRepository } from "../../domain/repositories";
import { Logger } from "../../shared/utils/logger";
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
 * Repositorio de bóvedas basado en PostgreSQL
 * Almacena las bóvedas en una base de datos PostgreSQL
 */
export class PostgresVaultRepository implements IVaultRepository {
  private pool: Pool;
  private readonly logger: Logger;
  private readonly circuitBreaker: CircuitBreaker;

  constructor(connectionString: string) {
    this.logger = new Logger("PostgresVaultRepository");
    this.pool = new Pool({ connectionString, ...PG_POOL_CONFIG });
    this.circuitBreaker = new CircuitBreaker();

    // Manejar errores en clientes inactivos del pool (evita crashes silenciosos)
    this.pool.on("error", (err) => {
      this.logger.error("Unexpected error on idle PostgreSQL client", err);
    });

    // Initialize schema on first use (non-blocking, failure is logged not thrown)
    this.initializeTable().catch((err) => {
      this.logger.warn("Schema initialization failed (may need manual migration)", err);
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
   * Inicializa la tabla de bóvedas si no existe
   */
  private async initializeTable(): Promise<void> {
    const createTableQuery = `
      CREATE TABLE IF NOT EXISTS vaults (
        id VARCHAR(36) PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        description TEXT,
        encrypted_data TEXT NOT NULL,
        encryption_key_id VARCHAR(255) NOT NULL,
        owner_id VARCHAR(255),
        metadata JSONB,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
      
      CREATE INDEX IF NOT EXISTS idx_vaults_name ON vaults(name);
      CREATE INDEX IF NOT EXISTS idx_vaults_created_at ON vaults(created_at);
      CREATE INDEX IF NOT EXISTS idx_vaults_owner_id ON vaults(owner_id);
    `;

    await this.executeWithCircuit(() => this.pool.query(createTableQuery));
    this.logger.info("Vaults table initialized");
  }

  /**
   * Guarda una bóveda en la base de datos
   */
  async save(vault: Vault): Promise<Vault> {
    const plain = vault.toPlainObject();

    const query = `
      INSERT INTO vaults (
        id, name, description, encrypted_data, encryption_key_id, owner_id, metadata, created_at, updated_at
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9
      )
      ON CONFLICT (id) DO UPDATE SET
        name = EXCLUDED.name,
        description = EXCLUDED.description,
        encrypted_data = EXCLUDED.encrypted_data,
        encryption_key_id = EXCLUDED.encryption_key_id,
        owner_id = EXCLUDED.owner_id,
        metadata = EXCLUDED.metadata,
        updated_at = EXCLUDED.updated_at
      RETURNING *;
    `;

    const values = [
      plain.id,
      plain.name,
      plain.description || null,
      plain.encryptedData,
      plain.encryptionKeyId,
      plain.ownerId || null,
      plain.metadata ? JSON.stringify(plain.metadata) : null,
      plain.createdAt,
      plain.updatedAt,
    ];

    try {
      const result: QueryResult = await this.executeWithCircuit(() =>
        withRetry(
          () => this.pool.query(query, values),
          { maxAttempts: 3, retryableErrors: PG_RETRYABLE_ERRORS },
        ),
      );
      const row = result.rows[0];

      this.logger.info(`Vault saved with id: ${plain.id}`);
      return Vault.fromPlainObject({
        ...row,
        ownerId: row.owner_id ?? undefined,
        metadata: row.metadata ? JSON.parse(row.metadata) : undefined,
      });
    } catch (error) {
      this.logger.error("Failed to save vault", error);
      throw error;
    }
  }

  /**
   * Obtiene una bóveda por su ID
   */
  async findById(id: VaultId): Promise<Vault | null> {
    const query = `
      SELECT id, name, description, encrypted_data, encryption_key_id, owner_id, metadata, created_at, updated_at
      FROM vaults
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

      this.logger.info(`Vault found with id: ${id.toString()}`);
      return Vault.fromPlainObject({
        ...row,
        ownerId: row.owner_id ?? undefined,
        metadata: row.metadata ? JSON.parse(row.metadata) : undefined,
      });
    } catch (error) {
      this.logger.error("Failed to find vault by id", error);
      throw error;
    }
  }

  /**
   * Obtiene una bóveda por su ID verificando que pertenezca al propietario
   */
  async findByVaultIdAndOwnerId(
    vaultId: string,
    ownerId: string,
  ): Promise<Vault | null> {
    const query = `
      SELECT id, name, description, encrypted_data, encryption_key_id, owner_id, metadata, created_at, updated_at
      FROM vaults
      WHERE id = $1 AND owner_id = $2
    `;

    try {
      const result: QueryResult = await this.executeWithCircuit(() =>
        this.pool.query(query, [vaultId, ownerId]),
      );

      if (result.rows.length === 0) {
        return null;
      }

      const row = result.rows[0];

      this.logger.info(
        `Vault found with id: ${vaultId} for owner: ${ownerId}`,
      );
      return Vault.fromPlainObject({
        ...row,
        ownerId: row.owner_id ?? undefined,
        metadata: row.metadata ? JSON.parse(row.metadata) : undefined,
      });
    } catch (error) {
      this.logger.error("Failed to find vault by id and owner id", error);
      throw error;
    }
  }

  /**
   * Elimina una bóveda por su ID
   */
  async delete(id: VaultId): Promise<boolean> {
    const query = `
      DELETE FROM vaults
      WHERE id = $1
      RETURNING id
    `;

    try {
      const result: QueryResult = await this.executeWithCircuit(() =>
        this.pool.query(query, [id.toString()]),
      );
      const deleted = (result.rowCount ?? 0) > 0;

      if (deleted) {
        this.logger.info(`Vault deleted with id: ${id.toString()}`);
      } else {
        this.logger.warn(
          `Attempted to delete non-existent vault with id: ${id.toString()}`,
        );
      }

      return deleted;
    } catch (error) {
      this.logger.error("Failed to delete vault", error);
      throw error;
    }
  }

  /**
   * Lista todas las bóvedas
   */
  async list(): Promise<Vault[]> {
    const query = `
      SELECT id, name, description, encrypted_data, encryption_key_id, owner_id, metadata, created_at, updated_at
      FROM vaults
      ORDER BY created_at DESC
    `;

    try {
      const result: QueryResult = await this.executeWithCircuit(() =>
        withRetry(
          () => this.pool.query(query),
          { maxAttempts: 2, retryableErrors: PG_RETRYABLE_ERRORS },
        ),
      );

      const vaults = result.rows.map((row) =>
        Vault.fromPlainObject({
          ...row,
          ownerId: row.owner_id ?? undefined,
          metadata: row.metadata ? JSON.parse(row.metadata) : undefined,
        }),
      );

      this.logger.info(`Listed ${vaults.length} vaults`);
      return vaults;
    } catch (error) {
      this.logger.error("Failed to list vaults", error);
      throw error;
    }
  }

  /**
   * Lista las bóvedas pertenecientes a un propietario
   */
  async listByOwnerId(ownerId: string): Promise<Vault[]> {
    const query = `
      SELECT id, name, description, encrypted_data, encryption_key_id, owner_id, metadata, created_at, updated_at
      FROM vaults
      WHERE owner_id = $1
      ORDER BY created_at DESC
    `;

    try {
      const result: QueryResult = await this.executeWithCircuit(() =>
        withRetry(
          () => this.pool.query(query, [ownerId]),
          { maxAttempts: 2, retryableErrors: PG_RETRYABLE_ERRORS },
        ),
      );

      const vaults = result.rows.map((row) =>
        Vault.fromPlainObject({
          ...row,
          ownerId: row.owner_id ?? undefined,
          metadata: row.metadata ? JSON.parse(row.metadata) : undefined,
        }),
      );

      this.logger.info(`Listed ${vaults.length} vaults for owner: ${ownerId}`);
      return vaults;
    } catch (error) {
      this.logger.error("Failed to list vaults by owner", error);
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
      this.logger.error("PostgreSQL health check failed", error);
      return false;
    }
  }

  /**
   * Cierra la conexión al pool de PostgreSQL
   */
  async close(): Promise<void> {
    await this.pool.end();
    this.logger.info("PostgreSQL connection pool closed");
  }
}
