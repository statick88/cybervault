/**
 * PostgreSQL User Repository — persistent user storage
 *
 * Replaces the in-memory Map with Postgres for user registration and lookup.
 * Follows the same pattern as PostgresVaultRepository.
 */

import { Pool } from "pg";
import type { StoredUser } from "../api/auth";

export class PostgresUserRepository {
  private pool: Pool;

  constructor(connectionString: string) {
    this.pool = new Pool({ connectionString });
    // Initialize schema on first use (non-blocking)
    this.initializeTable().catch(() => {});
  }

  private async initializeTable(): Promise<void> {
    const query = `
      CREATE TABLE IF NOT EXISTS users (
        user_id VARCHAR(64) PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        hash VARCHAR(128) NOT NULL,
        salt VARCHAR(64) NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
      CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
    `;
    await this.pool.query(query);
  }

  async findByEmail(email: string): Promise<StoredUser | null> {
    const result = await this.pool.query(
      "SELECT user_id, email, hash, salt FROM users WHERE email = $1",
      [email],
    );
    if (result.rows.length === 0) return null;
    const row = result.rows[0];
    return { userId: row.user_id, email: row.email, hash: row.hash, salt: row.salt };
  }

  async create(user: StoredUser): Promise<void> {
    await this.pool.query(
      "INSERT INTO users (user_id, email, hash, salt) VALUES ($1, $2, $3, $4)",
      [user.userId, user.email, user.hash, user.salt],
    );
  }

  async close(): Promise<void> {
    await this.pool.end();
  }
}
