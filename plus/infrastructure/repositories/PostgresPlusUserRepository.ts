/**
 * PostgreSQL Plus User Repository — Plus Domain
 */

import type { QueryResult } from "pg";
import { Pool } from "pg";
import { PlusUser } from "../../domain/entities/user";
import type { IPlusUserRepository } from "../../domain/repositories";
import { logger } from "@/shared/logger";
import { withRetry } from "@/shared/retry";
import { CircuitBreaker } from "@/shared/circuit-breaker";

const PG_RETRYABLE_ERRORS = ["ECONNREFUSED", "timeout", "connection terminated"];
const PG_POOL_CONFIG = {
  max: 10,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 2_000,
};

export class PostgresPlusUserRepository implements IPlusUserRepository {
  private pool: Pool;
  private readonly circuitBreaker: CircuitBreaker;

  constructor(connectionString: string) {
    this.pool = new Pool({ connectionString, ...PG_POOL_CONFIG });
    this.circuitBreaker = new CircuitBreaker();

    this.pool.on("error", (err) => {
      logger.error("Unexpected error on idle PostgreSQL client", "PostgresPlusUserRepository", undefined, String(err));
    });

    this.initializeTable().catch((err) => {
      logger.warn("Plus user table initialization failed (may need manual migration)", err);
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
    `;

    await this.executeWithCircuit(() => this.pool.query(createTableQuery));
    logger.info("Plus users table initialized");
  }

  async save(user: PlusUser): Promise<PlusUser> {
    const plain = user.toPlainObject();

    const query = `
      INSERT INTO plus_users (
        id, email, name, role, habitual_countries, timezone,
        active, metadata, created_at, updated_at, last_login_at
      ) VALUES (
        $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11
      )
      ON CONFLICT (id) DO UPDATE SET
        email = EXCLUDED.email,
        name = EXCLUDED.name,
        role = EXCLUDED.role,
        habitual_countries = EXCLUDED.habitual_countries,
        timezone = EXCLUDED.timezone,
        active = EXCLUDED.active,
        metadata = EXCLUDED.metadata,
        updated_at = EXCLUDED.updated_at,
        last_login_at = EXCLUDED.last_login_at
      RETURNING *;
    `;

    const values = [
      plain.id,
      plain.email,
      plain.name,
      plain.role,
      plain.habitualCountries,
      plain.timezone,
      plain.active,
      plain.metadata ? JSON.stringify(plain.metadata) : null,
      plain.createdAt,
      plain.updatedAt,
      plain.lastLoginAt || null,
    ];

    try {
      const result: QueryResult = await this.executeWithCircuit(() =>
        withRetry(
          () => this.pool.query(query, values),
          { maxAttempts: 3, retryableErrors: PG_RETRYABLE_ERRORS },
        ),
      );
      const row = result.rows[0];
      logger.info(`Plus user saved: ${plain.id}`);
      return PlusUser.fromPlainObject({
        ...row,
        habitualCountries: row.habitual_countries || [],
        timezone: row.timezone,
        active: row.active,
        metadata: row.metadata ? JSON.parse(row.metadata) : undefined,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
        lastLoginAt: row.last_login_at ?? undefined,
      });
    } catch (error) {
      logger.error("Failed to save plus user", "PostgresPlusUserRepository", undefined, String(error));
      throw error;
    }
  }

  async findById(id: string): Promise<PlusUser | null> {
    const query = `SELECT * FROM plus_users WHERE id = $1`;
    try {
      const result: QueryResult = await this.executeWithCircuit(() =>
        withRetry(
          () => this.pool.query(query, [id]),
          { maxAttempts: 2, retryableErrors: PG_RETRYABLE_ERRORS },
        ),
      );
      if (result.rows.length === 0) return null;
      const row = result.rows[0];
      return PlusUser.fromPlainObject({
        ...row,
        habitualCountries: row.habitual_countries || [],
        timezone: row.timezone,
        active: row.active,
        metadata: row.metadata ? JSON.parse(row.metadata) : undefined,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
        lastLoginAt: row.last_login_at ?? undefined,
      });
    } catch (error) {
      logger.error("Failed to find plus user by id", "PostgresPlusUserRepository", undefined, String(error));
      throw error;
    }
  }

  async findByEmail(email: string): Promise<PlusUser | null> {
    const query = `SELECT * FROM plus_users WHERE email = $1`;
    try {
      const result: QueryResult = await this.executeWithCircuit(() =>
        withRetry(
          () => this.pool.query(query, [email.toLowerCase()]),
          { maxAttempts: 2, retryableErrors: PG_RETRYABLE_ERRORS },
        ),
      );
      if (result.rows.length === 0) return null;
      const row = result.rows[0];
      return PlusUser.fromPlainObject({
        ...row,
        habitualCountries: row.habitual_countries || [],
        timezone: row.timezone,
        active: row.active,
        metadata: row.metadata ? JSON.parse(row.metadata) : undefined,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
        lastLoginAt: row.last_login_at ?? undefined,
      });
    } catch (error) {
      logger.error("Failed to find plus user by email", "PostgresPlusUserRepository", undefined, String(error));
      throw error;
    }
  }

  async findByRole(role: string): Promise<PlusUser[]> {
    const query = `SELECT * FROM plus_users WHERE role = $1 ORDER BY created_at DESC`;
    try {
      const result: QueryResult = await this.executeWithCircuit(() =>
        withRetry(
          () => this.pool.query(query, [role]),
          { maxAttempts: 2, retryableErrors: PG_RETRYABLE_ERRORS },
        ),
      );
      return result.rows.map((row) =>
        PlusUser.fromPlainObject({
          ...row,
          habitualCountries: row.habitual_countries || [],
          timezone: row.timezone,
          active: row.active,
          metadata: row.metadata ? JSON.parse(row.metadata) : undefined,
          createdAt: row.created_at,
          updatedAt: row.updated_at,
          lastLoginAt: row.last_login_at ?? undefined,
        }),
      );
    } catch (error) {
      logger.error("Failed to find plus users by role", "PostgresPlusUserRepository", undefined, String(error));
      throw error;
    }
  }

  async findActive(): Promise<PlusUser[]> {
    const query = `SELECT * FROM plus_users WHERE active = TRUE ORDER BY created_at DESC`;
    try {
      const result: QueryResult = await this.executeWithCircuit(() =>
        withRetry(
          () => this.pool.query(query),
          { maxAttempts: 2, retryableErrors: PG_RETRYABLE_ERRORS },
        ),
      );
      return result.rows.map((row) =>
        PlusUser.fromPlainObject({
          ...row,
          habitualCountries: row.habitual_countries || [],
          timezone: row.timezone,
          active: row.active,
          metadata: row.metadata ? JSON.parse(row.metadata) : undefined,
          createdAt: row.created_at,
          updatedAt: row.updated_at,
          lastLoginAt: row.last_login_at ?? undefined,
        }),
      );
    } catch (error) {
      logger.error("Failed to find active plus users", "PostgresPlusUserRepository", undefined, String(error));
      throw error;
    }
  }

  async search(criteria: {
    name?: string;
    email?: string;
    role?: string;
    active?: boolean;
    habitualCountry?: string;
    limit?: number;
    offset?: number;
  }): Promise<{ users: PlusUser[]; total: number }> {
    const conditions: string[] = [];
    const values: any[] = [];
    let paramIndex = 1;

    if (criteria.name) {
      conditions.push(`name ILIKE $${paramIndex++}`);
      values.push(`%${criteria.name}%`);
    }
    if (criteria.email) {
      conditions.push(`email ILIKE $${paramIndex++}`);
      values.push(`%${criteria.email}%`);
    }
    if (criteria.role) {
      conditions.push(`role = $${paramIndex++}`);
      values.push(criteria.role);
    }
    if (criteria.active !== undefined) {
      conditions.push(`active = $${paramIndex++}`);
      values.push(criteria.active);
    }
    if (criteria.habitualCountry) {
      conditions.push(`$${paramIndex++} = ANY(habitual_countries)`);
      values.push(criteria.habitualCountry.toUpperCase());
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(" AND ")}` : "";

    // Count query
    const countQuery = `SELECT COUNT(*) FROM plus_users ${whereClause}`;
    const countResult: QueryResult = await this.executeWithCircuit(() =>
      withRetry(
        () => this.pool.query(countQuery, values),
        { maxAttempts: 2, retryableErrors: PG_RETRYABLE_ERRORS },
      ),
    );
    const total = parseInt(countResult.rows[0].count, 10);

    // Data query
    let dataQuery = `SELECT * FROM plus_users ${whereClause} ORDER BY created_at DESC`;
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

    const users = result.rows.map((row) =>
      PlusUser.fromPlainObject({
        ...row,
        habitualCountries: row.habitual_countries || [],
        timezone: row.timezone,
        active: row.active,
        metadata: row.metadata ? JSON.parse(row.metadata) : undefined,
        createdAt: row.created_at,
        updatedAt: row.updated_at,
        lastLoginAt: row.last_login_at ?? undefined,
      }),
    );

    return { users, total };
  }

  async delete(id: string): Promise<boolean> {
    const query = `DELETE FROM plus_users WHERE id = $1 RETURNING id`;
    try {
      const result: QueryResult = await this.executeWithCircuit(() =>
        this.pool.query(query, [id]),
      );
      const deleted = (result.rowCount ?? 0) > 0;
      if (deleted) logger.info(`Plus user deleted: ${id}`);
      else logger.warn(`Attempted to delete non-existent plus user: ${id}`);
      return deleted;
    } catch (error) {
      logger.error("Failed to delete plus user", "PostgresPlusUserRepository", undefined, String(error));
      throw error;
    }
  }

  async list(): Promise<PlusUser[]> {
    const query = `SELECT * FROM plus_users ORDER BY created_at DESC`;
    try {
      const result: QueryResult = await this.executeWithCircuit(() =>
        withRetry(
          () => this.pool.query(query),
          { maxAttempts: 2, retryableErrors: PG_RETRYABLE_ERRORS },
        ),
      );
      return result.rows.map((row) =>
        PlusUser.fromPlainObject({
          ...row,
          habitualCountries: row.habitual_countries || [],
          timezone: row.timezone,
          active: row.active,
          metadata: row.metadata ? JSON.parse(row.metadata) : undefined,
          createdAt: row.created_at,
          updatedAt: row.updated_at,
          lastLoginAt: row.last_login_at ?? undefined,
        }),
      );
    } catch (error) {
      logger.error("Failed to list plus users", "PostgresPlusUserRepository", undefined, String(error));
      throw error;
    }
  }

  async isHealthy(): Promise<boolean> {
    try {
      await this.executeWithCircuit(() => this.pool.query("SELECT 1"));
      return true;
    } catch (error) {
      logger.error("PostgreSQL health check failed", "PostgresPlusUserRepository", undefined, String(error));
      return false;
    }
  }

  async close(): Promise<void> {
    await this.pool.end();
    logger.info("PostgreSQL plus user pool closed");
  }
}