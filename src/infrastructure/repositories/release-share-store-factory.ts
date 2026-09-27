/**
 * Selection rule for the Release Share store.
 *
 * The port (`IReleaseShareStore`) has two adapters and exactly one rule picks
 * between them, so the ApiServer never has to know about connection strings:
 *
 *   PostgreSQL  iff  USE_POSTGRES === "true"  AND  DATABASE_URL is non-blank
 *   in-memory   otherwise  (today's behaviour: server starts with no database)
 *
 * WHY BOTH CONDITIONS
 * - `USE_POSTGRES` is the switch the rest of the server already uses for the
 *   vault/credential repositories, so all persistence moves together — shares
 *   must not go to Postgres while the credentials that reference them go
 *   somewhere else (split-brain across the same process).
 * - A non-blank `DATABASE_URL` is what "a configured database" means. Handing
 *   pg an empty connection string makes it silently fall back to `PG*` env
 *   vars / localhost, i.e. possibly the wrong database; an explicit refusal to
 *   use Postgres (documented in-memory fallback) is the safer failure.
 *   `USE_POSTGRES=true` without a URL logs a warning: the deployment is
 *   half-configured and shares will not survive a restart.
 *
 * The adapter itself is key-free either way — it only stores opaque blobs.
 *
 * @module infrastructure/repositories/release-share-store-factory
 */

import type { IReleaseShareStore } from "../../domain/repositories";
import { logger } from "../../shared/logger";
import { InMemoryReleaseShareStore } from "./InMemoryReleaseShareStore";
import { PostgresReleaseShareStore } from "./PostgresReleaseShareStore";

/** The two environment entries the rule reads (injectable for tests). */
export interface ReleaseShareStoreEnv {
  USE_POSTGRES?: string;
  DATABASE_URL?: string;
}

export function createReleaseShareStore(
  env: ReleaseShareStoreEnv = process.env,
): IReleaseShareStore {
  if (env.USE_POSTGRES !== "true") {
    logger.info(
      "Release Share store: in-memory (single instance; set USE_POSTGRES=true and DATABASE_URL to persist)",
      "ReleaseShareStore",
    );
    return new InMemoryReleaseShareStore();
  }

  const connectionString = env.DATABASE_URL?.trim() ?? "";
  if (!connectionString) {
    logger.warn(
      "USE_POSTGRES=true but DATABASE_URL is empty — Release Shares fall back to the in-memory store (lost on restart)",
      "ReleaseShareStore",
    );
    return new InMemoryReleaseShareStore();
  }

  logger.info(
    "Release Share store: PostgreSQL (durable, shared across instances)",
    "ReleaseShareStore",
  );
  return new PostgresReleaseShareStore(connectionString);
}
