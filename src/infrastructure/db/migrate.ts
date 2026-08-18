/**
 * Database migration runner for CyberVault
 * Runs SQL migrations in order, tracks applied migrations in a metadata table
 */

import { Pool } from "pg";
import * as fs from "fs";
import * as path from "path";
import { logger } from "../../shared/logger";

const MIGRATIONS_DIR = path.join(__dirname, "migrations");
const MIGRATION_TABLE = "schema_migrations";

export interface Migration {
  id: string;
  name: string;
  sql: string;
  appliedAt?: Date;
}

export class MigrationRunner {
  private pool: Pool;

  constructor(pool: Pool) {
    this.pool = pool;
  }

  async ensureMigrationTable(): Promise<void> {
    await this.pool.query(`
      CREATE TABLE IF NOT EXISTS ${MIGRATION_TABLE} (
        id VARCHAR(255) PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        applied_at TIMESTAMPTZ DEFAULT NOW()
      )
    `);
  }

  async getAppliedMigrations(): Promise<string[]> {
    const result = await this.pool.query(
      `SELECT id FROM ${MIGRATION_TABLE} ORDER BY applied_at`
    );
    return result.rows.map((r) => r.id);
  }

  async loadMigrations(): Promise<Migration[]> {
    if (!fs.existsSync(MIGRATIONS_DIR)) {
      return [];
    }

    const files = fs.readdirSync(MIGRATIONS_DIR)
      .filter((f) => f.endsWith(".sql"))
      .sort();

    return files.map((file) => {
      const id = file.replace(".sql", "");
      const sql = fs.readFileSync(path.join(MIGRATIONS_DIR, file), "utf-8");
      return { id, name: file, sql };
    });
  }

  async run(): Promise<{ applied: number; skipped: number }> {
    await this.ensureMigrationTable();
    const applied = await this.getAppliedMigrations();
    const migrations = await this.loadMigrations();

    let appliedCount = 0;
    let skippedCount = 0;

    for (const migration of migrations) {
      if (applied.includes(migration.id)) {
        skippedCount++;
        continue;
      }

      logger.info(`Applying migration: ${migration.name}`, "MigrationRunner");
      await this.pool.query("BEGIN");
      try {
        await this.pool.query(migration.sql);
        await this.pool.query(
          `INSERT INTO ${MIGRATION_TABLE} (id, name) VALUES ($1, $2)`,
          [migration.id, migration.name]
        );
        await this.pool.query("COMMIT");
        appliedCount++;
        logger.info(`✓ Applied: ${migration.name}`, "MigrationRunner");
      } catch (error) {
        await this.pool.query("ROLLBACK");
        logger.error(`✗ Failed: ${migration.name}`, "MigrationRunner", undefined, String(error));
        throw error;
      }
    }

    return { applied: appliedCount, skipped: skippedCount };
  }
}
