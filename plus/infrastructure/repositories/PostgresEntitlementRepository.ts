/**
 * PostgreSQL Entitlement Repository — Plus Domain
 */

import type { QueryResult } from "pg";
import { Pool } from "pg";
import { Entitlement } from "../../domain/entities/entitlement";
import type { IEntitlementRepository } from "../../domain/repositories";
import { logger } from "@/shared/logger";
import { withRetry } from "@/shared/retry";
import { CircuitBreaker } from "@/shared/circuit-breaker";
import { mapEntitlementRow } from "./row-mappers";

const PG_RETRYABLE_ERRORS = ["ECONNREFUSED", "timeout", "connection terminated"];
const PG_POOL_CONFIG = {
  max: 10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 2_000,
};

export class PostgresEntitlementRepository implements IEntitlementRepository {
  private pool: Pool;
  private readonly circuitBreaker: CircuitBreaker;

  constructor(connectionString: string) {
    this.pool = new Pool({ connectionString, ...PG_POOL_CONFIG });
    this.circuitBreaker = new CircuitBreaker();

    this.pool.on("error", (err) => {
      logger.error("Unexpected error on idle PostgreSQL client", "PostgresEntitlementRepository", undefined, String(err));
    });

    this.initializeTable().catch((err) => {
      logger.warn("Entitlement table initialization failed (may need manual migration)", err);
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
    `;

    await this.executeWithCircuit(() => this.pool.query(createTableQuery));
    logger.info("Plus entitlements table initialized");
  }

  async save(entitlement: Entitlement): Promise<Entitlement> {
    const plain = entitlement.toPlainObject();

    const query = `
      INSERT INTO plus_entitlements (
        id, user_id, resource_id, pestillo_state, allowed_operations,
        valid_from, valid_until, metadata, created_by, created_at, updated_at
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
      )
      ON CONFLICT (id) DO UPDATE SET
        user_id = EXCLUDED.user_id,
        resource_id = EXCLUDED.resource_id,
        pestillo_state = EXCLUDED.pestillo_state,
        allowed_operations = EXCLUDED.allowed_operations,
        valid_from = EXCLUDED.valid_from,
        valid_until = EXCLUDED.valid_until,
        metadata = EXCLUDED.metadata,
        created_by = EXCLUDED.created_by,
        updated_at = EXCLUDED.updated_at
      RETURNING *;
    `;

    const values = [
      plain.id,
      plain.userId,
      plain.resourceId,
      plain.pestilloState,
      plain.allowedOperations,
      plain.validFrom || null,
      plain.validUntil || null,
      plain.metadata ? JSON.stringify(plain.metadata) : null,
      plain.createdBy,
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
      logger.info(`Entitlement saved: ${plain.id}`);
      return Entitlement.fromPlainObject(mapEntitlementRow(row));
    } catch (error) {
      logger.error("Failed to save entitlement", "PostgresEntitlementRepository", undefined, String(error));
      throw error;
    }
  }

  async findById(id: string): Promise<Entitlement | null> {
    const query = `SELECT * FROM plus_entitlements WHERE id = $1`;
    try {
      const result: QueryResult = await this.executeWithCircuit(() =>
        withRetry(
          () => this.pool.query(query, [id]),
          { maxAttempts: 2, retryableErrors: PG_RETRYABLE_ERRORS },
        ),
      );
      if (result.rows.length === 0) return null;
      const row = result.rows[0];
      return Entitlement.fromPlainObject(mapEntitlementRow(row));
    } catch (error) {
      logger.error("Failed to find entitlement by id", "PostgresEntitlementRepository", undefined, String(error));
      throw error;
    }
  }

  async findByUserId(userId: string): Promise<Entitlement[]> {
    const query = `SELECT * FROM plus_entitlements WHERE user_id = $1 ORDER BY created_at DESC`;
    try {
      const result: QueryResult = await this.executeWithCircuit(() =>
        withRetry(
          () => this.pool.query(query, [userId]),
          { maxAttempts: 2, retryableErrors: PG_RETRYABLE_ERRORS },
        ),
      );
      return result.rows.map((row) =>
        Entitlement.fromPlainObject(mapEntitlementRow(row)),
      );
    } catch (error) {
      logger.error("Failed to find entitlements by user id", "PostgresEntitlementRepository", undefined, String(error));
      throw error;
    }
  }

  async findByResourceId(resourceId: string): Promise<Entitlement[]> {
    const query = `SELECT * FROM plus_entitlements WHERE resource_id = $1 ORDER BY created_at DESC`;
    try {
      const result: QueryResult = await this.executeWithCircuit(() =>
        withRetry(
          () => this.pool.query(query, [resourceId]),
          { maxAttempts: 2, retryableErrors: PG_RETRYABLE_ERRORS },
        ),
      );
      return result.rows.map((row) =>
        Entitlement.fromPlainObject(mapEntitlementRow(row)),
      );
    } catch (error) {
      logger.error("Failed to find entitlements by resource id", "PostgresEntitlementRepository", undefined, String(error));
      throw error;
    }
  }

  async findByUserAndResource(userId: string, resourceId: string): Promise<Entitlement | null> {
    // The row key IS `${userId}:${resourceId}` (see `plus_entitlements.id`
    // and `Entitlement.create`), so this composes the key and delegates —
    // the intended convention, not a lookup shortcut.
    const id = `${userId}:${resourceId}`;
    return this.findById(id);
  }

  async findByPestilloState(state: string): Promise<Entitlement[]> {
    const query = `SELECT * FROM plus_entitlements WHERE pestillo_state = $1 ORDER BY created_at DESC`;
    try {
      const result: QueryResult = await this.executeWithCircuit(() =>
        withRetry(
          () => this.pool.query(query, [state]),
          { maxAttempts: 2, retryableErrors: PG_RETRYABLE_ERRORS },
        ),
      );
      return result.rows.map((row) =>
        Entitlement.fromPlainObject(mapEntitlementRow(row)),
      );
    } catch (error) {
      logger.error("Failed to find entitlements by pestillo state", "PostgresEntitlementRepository", undefined, String(error));
      throw error;
    }
  }

  async findExpiringSoon(withinMs: number): Promise<Entitlement[]> {
    const query = `
      SELECT * FROM plus_entitlements
      WHERE valid_until IS NOT NULL
      AND valid_until > NOW()
      AND valid_until <= NOW() + $1 * INTERVAL '1 millisecond'
      ORDER BY valid_until ASC
    `;
    try {
      const result: QueryResult = await this.executeWithCircuit(() =>
        withRetry(
          () => this.pool.query(query, [withinMs]),
          { maxAttempts: 2, retryableErrors: PG_RETRYABLE_ERRORS },
        ),
      );
      return result.rows.map((row) =>
        Entitlement.fromPlainObject(mapEntitlementRow(row)),
      );
    } catch (error) {
      logger.error("Failed to find expiring entitlements", "PostgresEntitlementRepository", undefined, String(error));
      throw error;
    }
  }

  async search(criteria: {
    userId?: string;
    resourceId?: string;
    pestilloState?: string;
    activeOnly?: boolean;
    limit?: number;
    offset?: number;
  }): Promise<{ entitlements: Entitlement[]; total: number }> {
    const conditions: string[] = [];
    const values: any[] = [];
    let paramIndex = 1;

    if (criteria.userId) {
      conditions.push(`user_id = $${paramIndex++}`);
      values.push(criteria.userId);
    }
    if (criteria.resourceId) {
      conditions.push(`resource_id = $${paramIndex++}`);
      values.push(criteria.resourceId);
    }
    if (criteria.pestilloState) {
      conditions.push(`pestillo_state = $${paramIndex++}`);
      values.push(criteria.pestilloState);
    }
    if (criteria.activeOnly) {
      conditions.push(`
        (pestillo_state != 'closed')
        AND (valid_until IS NULL OR valid_until > NOW())
        AND (valid_from IS NULL OR valid_from <= NOW())
      `);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

    // Count query
    const countQuery = `SELECT COUNT(*) FROM plus_entitlements ${whereClause}`;
    const countResult: QueryResult = await this.executeWithCircuit(() =>
      withRetry(
        () => this.pool.query(countQuery, values),
        { maxAttempts: 2, retryableErrors: PG_RETRYABLE_ERRORS },
      ),
    );
    const total = parseInt(countResult.rows[0].count, 10);

    // Data query
    let dataQuery = `SELECT * FROM plus_entitlements ${whereClause} ORDER BY created_at DESC`;
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

    const entitlements = result.rows.map((row) =>
      Entitlement.fromPlainObject(mapEntitlementRow(row)),
    );

    return { entitlements, total };
  }

  async delete(id: string): Promise<boolean> {
    const query = `DELETE FROM plus_entitlements WHERE id = $1 RETURNING id`;
    try {
      const result: QueryResult = await this.executeWithCircuit(() =>
        this.pool.query(query, [id]),
      );
      const deleted = (result.rowCount ?? 0) > 0;
      if (deleted) logger.info(`Entitlement deleted: ${id}`);
      else logger.warn(`Attempted to delete non-existent entitlement: ${id}`);
      return deleted;
    } catch (error) {
      logger.error("Failed to delete entitlement", "PostgresEntitlementRepository", undefined, String(error));
      throw error;
    }
  }

  async list(): Promise<Entitlement[]> {
    const query = `SELECT * FROM plus_entitlements ORDER BY created_at DESC`;
    try {
      const result: QueryResult = await this.executeWithCircuit(() =>
        withRetry(
          () => this.pool.query(query),
          { maxAttempts: 2, retryableErrors: PG_RETRYABLE_ERRORS },
        ),
      );
      return result.rows.map((row) =>
        Entitlement.fromPlainObject(mapEntitlementRow(row)),
      );
    } catch (error) {
      logger.error("Failed to list entitlements", "PostgresEntitlementRepository", undefined, String(error));
      throw error;
    }
  }

  async isHealthy(): Promise<boolean> {
    try {
      await this.executeWithCircuit(() => this.pool.query("SELECT 1"));
      return true;
    } catch (error) {
      logger.error("PostgreSQL health check failed", "PostgresEntitlementRepository", undefined, String(error));
      return false;
    }
  }

  async close(): Promise<void> {
    await this.pool.end();
    logger.info("PostgreSQL entitlement pool closed");
  }
}