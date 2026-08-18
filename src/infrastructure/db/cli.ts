#!/usr/bin/env node
/**
 * Database migration CLI
 * Usage: npx tsx src/infrastructure/db/cli.ts [command]
 * Commands: up, down, status
 */

import { Pool } from "pg";
import { MigrationRunner } from "./migrate";

const DATABASE_URL = process.env.DATABASE_URL || "postgresql://localhost:5432/cybervault";

async function main() {
  const command = process.argv[2] || "status";
  const pool = new Pool({ connectionString: DATABASE_URL });
  const runner = new MigrationRunner(pool);

  try {
    switch (command) {
      case "up":
        const result = await runner.run();
        console.log(`Migrations applied: ${result.applied}, skipped: ${result.skipped}`);
        break;
      case "status":
        await runner.ensureMigrationTable();
        const applied = await runner.getAppliedMigrations();
        const migrations = await runner.loadMigrations();
        console.log(`Applied: ${applied.length}/${migrations.length}`);
        for (const m of migrations) {
          const status = applied.includes(m.id) ? "✓" : "○";
          console.log(`  ${status} ${m.name}`);
        }
        break;
      default:
        console.log("Usage: migrate [up|status]");
    }
  } finally {
    await pool.end();
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
