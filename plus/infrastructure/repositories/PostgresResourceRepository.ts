/**
 * PostgreSQL Resource Repository — Plus Domain
 */

import type { QueryResult } from "pg";
import { Pool } from "pg";
import { Resource } from "../../domain/entities/resource";
import type { IResourceRepository } from "../../domain/repositories";
import { logger } from "@/shared/logger";
import { withRetry } from "@/shared/retry";
import { CircuitBreaker } from "@/shared/circuit-breaker";

const PG_RETRYABLE_ERRORS = ["ECONNREFUSED", "timeout", "connection terminated"];

const PG_POOL_CONFIG = {
  max: 10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 2_000,
};

export class PostgresResourceRepository implements IResourceRepository {
  private pool: Pool;
  private readonly circuitBreaker: CircuitBreaker;

  constructor(connectionString: string) {
    this.pool = new Pool({ connectionString, ...PG_POOL_CONFIG });
    this.circuitBreaker = new CircuitBreaker();

    this.pool.on("error", (err) => {
      logger.error("Unexpected error on idle PostgreSQL client", "PostgresResourceRepository", undefined, String(err));
    });

    this.initializeTable().catch((err) => {
      logger.warn("Resource table initialization failed (may need manual migration)", err);
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

  private async initializeTable(): Promise<void> {
    const createTableQuery = `
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
    `;

    await this.executeWithCircuit(() => this.pool.query(createTableQuery));
    logger.info("Plus resources table initialized");
  }

  async save(resource: Resource): Promise<Resource> {
    const plain = resource.toPlainObject();

    const query = `
      INSERT INTO plus_resources (
        id, name, type, endpoint, environment, criticality, description,
        tags, owner_team, metadata, active, created_at, updated_at
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13
      )
      ON CONFLICT (id) DO UPDATE SET
        name = EXCLUDED.name,
        type = EXCLUDED.type,
        endpoint = EXCLUDED.endpoint,
        environment = EXCLUDED.environment,
        criticality = EXCLUDED.criticality,
        description = EXCLUDED.description,
        tags = EXCLUDED.tags,
        owner_team = EXCLUDED.owner_team,
        metadata = EXCLUDED.metadata,
        active = EXCLUDED.active,
        updated_at = EXCLUDED.updated_at
      RETURNING *;
    `;

    const values = [
      plain.id,
      plain.name,
      plain.type,
      plain.endpoint,
      plain.environment,
      plain.criticality,
      plain.description || null,
      plain.tags,
      plain.ownerTeam || null,
      plain.metadata ? JSON.stringify(plain.metadata) : null,
      plain.active,
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
      logger.info(`Resource saved with id: ${plain.id}`);
      return Resource.fromPlainObject({
        ...row,
        tags: row.tags || [],
        ownerTeam: row.owner_team ?? undefined,
        metadata: row.metadata ? JSON.parse(row.metadata) : undefined,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
      });
    } catch (error) {
      logger.error("Failed to save resource", "PostgresResourceRepository", undefined, String(error));
      throw error;
    }
  }

  async findById(id: string): Promise<Resource | null> {
    const query = `SELECT * FROM plus_resources WHERE id = $1`;
    try {
      const result: QueryResult = await this.executeWithCircuit(() =>
        withRetry(
          () => this.pool.query(query, [id]),
          { maxAttempts: 2, retryableErrors: PG_RETRYABLE_ERRORS },
        ),
      );
      if (result.rows.length === 0) return null;
      const row = result.rows[0];
      return Resource.fromPlainObject({
        ...row,
        tags: row.tags || [],
        ownerTeam: row.owner_team ?? undefined,
        metadata: row.metadata ? JSON.parse(row.metadata) : undefined,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
      });
    } catch (error) {
      logger.error("Failed to find resource by id", "PostgresResourceRepository", undefined, String(error));
      throw error;
    }
  }

  async findByType(type: string): Promise<Resource[]> {
    const query = `SELECT * FROM plus_resources WHERE type = $1 ORDER BY created_at DESC`;
    try {
      const result: QueryResult = await this.executeWithCircuit(() =>
        withRetry(
          () => this.pool.query(query, [type]),
          { maxAttempts: 2, retryableErrors: PG_RETRYABLE_ERRORS },
        ),
      );
      return result.rows.map((row) =>
        Resource.fromPlainObject({
          ...row,
          tags: row.tags || [],
          ownerTeam: row.owner_team ?? undefined,
          metadata: row.metadata ? JSON.parse(row.metadata) : undefined,
          createdAt: row.created_at,
          updatedAt: row.updated_at,
        }),
      );
    } catch (error) {
      logger.error("Failed to find resources by type", "PostgresResourceRepository", undefined, String(error));
      throw error;
    }
  }

  async findByEnvironment(env: string): Promise<Resource[]> {
    const query = `SELECT * FROM plus_resources WHERE environment = $1 ORDER BY created_at DESC`;
    try {
      const result: QueryResult = await this.executeWithCircuit(() =>
        withRetry(
          () => this.pool.query(query, [env]),
          { maxAttempts: 2, retryableErrors: PG_RETRYABLE_ERRORS },
        ),
      );
      return result.rows.map((row) =>
        Resource.fromPlainObject({
          ...row,
          tags: row.tags || [],
          ownerTeam: row.owner_team ?? undefined,
          metadata: row.metadata ? JSON.parse(row.metadata) : undefined,
          createdAt: row.created_at,
          updatedAt: row.updated_at,
        }),
      );
    } catch (error) {
      logger.error("Failed to find resources by environment", "PostgresResourceRepository", undefined, String(error));
      throw error;
    }
  }

  async findByCriticality(criticality: string): Promise<Resource[]> {
    const query = `SELECT * FROM plus_resources WHERE criticality = $1 ORDER BY created_at DESC`;
    try {
      const result: QueryResult = await this.executeWithCircuit(() =>
        withRetry(
          () => this.pool.query(query, [criticality]),
          { maxAttempts: 2, retryableErrors: PG_RETRYABLE_ERRORS },
        ),
      );
      return result.rows.map((row) =>
        Resource.fromPlainObject({
          ...row,
          tags: row.tags || [],
          ownerTeam: row.owner_team ?? undefined,
          metadata: row.metadata ? JSON.parse(row.metadata) : undefined,
          createdAt: row.created_at,
          updatedAt: row.updated_at,
        }),
      );
    } catch (error) {
      logger.error("Failed to find resources by criticality", "PostgresResourceRepository", undefined, String(error));
      throw error;
    }
  }

  async findActive(): Promise<Resource[]> {
    const query = `SELECT * FROM plus_resources WHERE active = TRUE ORDER BY created_at DESC`;
    try {
      const result: QueryResult = await this.executeWithCircuit(() =>
        withRetry(
          () => this.pool.query(query),
          { maxAttempts: 2, retryableErrors: PG_RETRYABLE_ERRORS },
        ),
      );
      return result.rows.map((row) =>
        Resource.fromPlainObject({
          ...row,
          tags: row.tags || [],
          ownerTeam: row.owner_team ?? undefined,
          metadata: row.metadata ? JSON.parse(row.metadata) : undefined,
          createdAt: row.created_at,
          updatedAt: row.updated_at,
        }),
      );
    } catch (error) {
      logger.error("Failed to find active resources", "PostgresResourceRepository", undefined, String(error));
      throw error;
    }
  }

  async search(criteria: {
    name?: string;
    type?: string;
    environment?: string;
    criticality?: string;
    tags?: string[];
    active?: boolean;
    limit?: number;
    offset?: number;
  }): Promise<{ resources: Resource[]; total: number }> {
    const conditions: string[] = [];
    const values: any[] = [];
    let paramIndex = 1;

    if (criteria.name) {
      conditions.push(`name ILIKE $${paramIndex++}`);
      values.push(`%${criteria.name}%`);
    }
    if (criteria.type) {
      conditions.push(`type = $${paramIndex++}`);
      values.push(criteria.type);
    }
    if (criteria.environment) {
      conditions.push(`environment = $${paramIndex++}`);
      values.push(criteria.environment);
    }
    if (criteria.criticality) {
      conditions.push(`criticality = $${paramIndex++}`);
      values.push(criteria.criticality);
    }
    if (criteria.tags && criteria.tags.length > 0) {
      conditions.push(`tags && $${paramIndex++}`);
      values.push(criteria.tags);
    }
    if (criteria.active !== undefined) {
      conditions.push(`active = $${paramIndex++}`);
      values.push(criteria.active);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

    // Count query
    const countQuery = `SELECT COUNT(*) FROM plus_resources ${whereClause}`;
    const countResult: QueryResult = await this.executeWithCircuit(() =>
      withRetry(
        () => this.pool.query(countQuery, values),
        { maxAttempts: 2, retryableErrors: PG_RETRYABLE_ERRORS },
      ),
    );
    const total = parseInt(countResult.rows[0].count, 10);

    // Data query
    let dataQuery = `SELECT * FROM plus_resources ${whereClause} ORDER BY created_at DESC`;
    if (criteria.limit) {
      dataQuery += ` LIMIT $${paramIndex++}`;
      values.push(criteria.limit);
    }
    if (criteria.offset) {
      dataQuery += ` OFFSET $${paramIndex++}`;
      values.push(criteria.offset);
    }

    const result: QueryResult = await this.executeWithCircuit(() =>
      withRetry(
        () => this.pool.query(dataQuery, values),
        { maxAttempts: 2, retryableErrors: PG_RETRYABLE_ERRORS },
      ),
    );

    const resources = result.rows.map((row) =>
      Resource.fromPlainObject({
        ...row,
        tags: row.tags || [],
        ownerTeam: row.owner_team ?? undefined,
        metadata: row.metadata ? JSON.parse(row.metadata) : undefined,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
      }),
    );

    return { resources, total };
  }

  async delete(id: string): Promise<boolean> {
    const query = `DELETE FROM plus_resources WHERE id = $1 RETURNING id`;
    try {
      const result: QueryResult = await this.executeWithCircuit(() =>
        this.pool.query(query, [id]),
      );
      const deleted = (result.rowCount ?? 0) > 0;
      if (deleted) logger.info(`Resource deleted: ${id}`);
      else logger.warn(`Attempted to delete non-existent resource: ${id}`);
      return deleted;
    } catch (error) {
      logger.error("Failed to delete resource", "PostgresResourceRepository", undefined, String(error));
      throw error;
    }
  }

  async list(): Promise<Resource[]> {
    const query = `SELECT * FROM plus_resources ORDER BY created_at DESC`;
    try {
      const result: QueryResult = await this.executeWithCircuit(() =>
        withRetry(
          () => this.pool.query(query),
          { maxAttempts: 2, retryableErrors: PG_RETRYABLE_ERRORS },
        ),
      );
      return result.rows.map((row) =>
        Resource.fromPlainObject({
          ...row,
          tags: row.tags || [],
          ownerTeam: row.owner_team ?? undefined,
          metadata: row.metadata ? JSON.parse(row.metadata) : undefined,
          createdAt: row.created_at,
          updatedAt: row.updated_at,
        }),
      );
    } catch (error) {
      logger.error("Failed to list resources", "PostgresResourceRepository", undefined, String(error));
      throw error;
    }
  }

  async isHealthy(): Promise<boolean> {
    try {
      await this.executeWithCircuit(() => this.pool.query("SELECT 1"));
      return true;
    } catch (error) {
      logger.error("PostgreSQL health check failed", "PostgresResourceRepository", undefined, String(error));
      return false;
    }
  }

  async close(): Promise<void> {
    await this.pool.end();
    logger.info("PostgreSQL resource pool closed");
  }
}