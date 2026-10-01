/**
 * Plus API — process entrypoint (T3, plus-api-runtime).
 *
 * `plus/api/server.ts` exported `startPlusServer()` and nothing ever called
 * it: the authorization service had no way to be started. This file is that
 * way — for `node dist/plus/api/main.js` in the container, or
 * `npx tsx plus/api/main.ts` on a checkout.
 *
 * It wires the three repositories `PlusApiServer` takes:
 *
 *   * `PostgresChallengeRepository`      — step-up challenges (new in this task)
 *   * `PostgresEntitlementRepository`   — who may do what
 *   * `PostgresPlusUserRepository`      — the Plus-side user directory
 *
 * `IResourceRepository` / `PostgresResourceRepository` is deliberately NOT
 * constructed: `PlusApiServer` does not accept one, and the capability route
 * documents why (`neutralResource()` — the risk engine is handed a NEUTRAL
 * stand-in rather than a guessed resource). Building a fourth pool that
 * nothing would read would be a connection opened for show, so this
 * entrypoint wires exactly what the server consumes.
 *
 * Import order matters and is not cosmetic: `./module-aliases` must load
 * BEFORE `./server`, because the compiled server requires `@/…` specifiers
 * that plain Node cannot resolve on its own. TypeScript preserves import
 * order in the emitted CommonJS, so the emitted file requires the resolver
 * first.
 */

import "./module-aliases";

import { logger } from "@/shared/logger";
import { startPlusServer } from "./server";
import { PostgresChallengeRepository } from "../infrastructure/repositories/PostgresChallengeRepository";
import { PostgresEntitlementRepository } from "../infrastructure/repositories/PostgresEntitlementRepository";
import { PostgresPlusUserRepository } from "../infrastructure/repositories/PostgresPlusUserRepository";

/** Same default `startPlusServer()` and `PLUS_BASE_URL` already assume. */
const DEFAULT_PORT = 3001;

async function main(): Promise<void> {
  // Same shape as Core's entrypoint: one connection string, three pools.
  // Every repository also provisions its own table on construction, so a
  // Plus instance pointed at a database that has not run migration 005 still
  // boots instead of failing its first query.
  const connectionString = process.env.DATABASE_URL || "";
  const challengeRepo = new PostgresChallengeRepository(connectionString);
  const entitlementRepo = new PostgresEntitlementRepository(connectionString);
  const userRepo = new PostgresPlusUserRepository(connectionString);

  const port = parseInt(process.env.PORT || String(DEFAULT_PORT), 10);

  await startPlusServer({ port, challengeRepo, entitlementRepo, userRepo });
}

if (require.main === module) {
  main().catch((error) => {
    // H6 reasoning, same as Core: a refusal to start (TLS guard, missing
    // PLUS_JWT_SECRET, an unreachable database the caller did ask for) must
    // not leave a half-alive process. Log and exit non-zero.
    logger.error(
      "Plus server startup failed",
      "PlusApiServer",
      undefined,
      error instanceof Error ? error.message : String(error),
    );
    process.exit(1);
  });
}
