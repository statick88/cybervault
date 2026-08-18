#!/usr/bin/env node
/**
 * Database migration CLI
 * Usage: npx tsx src/infrastructure/db/cli.ts [command]
 * Commands: up, down, status
 */

import { Pool } from "pg";
import { MigrationRunner } from "./migrate";
import { logger } from "../../shared/logger";

const DATABASE_URL = process.env.DATABASE_URL || "postgresql://localhost:5432/cybervault";

async function main() {
  const command = process.argv[2] || "status";
  const pool = new Pool({ connectionString: DATABASE_URL });
  const runner = new MigrationRunner(pool);

  try {
    switch (command) {
      case "up":
        const result = await runner.run();
        logger.info(`Migrations applied: ${result.applied}, skipped: ${result.skipped}`, "DbCli");
        break;
      case "status":
        await runner.ensureMigrationTable();
        const applied = await runner.getAppliedMigrations();
        const migrations = await runner.loadMigrations();
        logger.info(`Applied: ${applied.length}/${migrations.length}`, "DbCli");
        for (const m of migrations) {
          const status = applied.includes(m.id) ? "✓" : "○";
          logger.info(`  ${status} ${m.name}`, "DbCli");
        }
        break;
      default:
        logger.info("Usage: migrate [up|status]", "DbCli");
    }
  } finally {
    await pool.end();
  }
}

main().catch((err) => {
  logger.error("Migration failed", "DbCli", undefined, String(err));
  process.exit(1);
});
