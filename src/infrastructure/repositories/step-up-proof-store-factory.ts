/**
 * Selection rule for the R11 step-up proof stores.
 *
 * Mirrors `release-share-store-factory.ts` deliberately — same conditions,
 * same reasoning, same "the ApiServer never sees a connection string"
 * boundary:
 *
 *   PostgreSQL  iff  USE_POSTGRES === "true"  AND  DATABASE_URL is non-blank
 *   in-memory   otherwise  (tests and single-instance development)
 *
 * WHY BOTH CONDITIONS: `USE_POSTGRES` is the switch the vault/credential
 * repositories already use, so all persistence moves together — approval
 * challenges must not live in a different place than the users and
 * credentials they reference. A non-blank `DATABASE_URL` is what "a
 * configured database" means; handing pg an empty string silently falls back
 * to whatever `PG*` env vars say, i.e. possibly the wrong database.
 *
 * A multi-instance deployment with the in-memory adapter degrades exactly
 * like Release Shares do: the challenge minted on one instance cannot be
 * consumed on another, so approval fails closed rather than succeeds
 * unsafely.
 *
 * @module infrastructure/repositories/step-up-proof-store-factory
 */

import type {
  IStepUpApprovalChallengeStore,
  IStepUpAuthenticatorStore,
} from "../../domain/repositories";
import { logger } from "../../shared/logger";
import {
  InMemoryStepUpApprovalChallengeStore,
  InMemoryStepUpAuthenticatorStore,
} from "./InMemoryStepUpProofStores";
import {
  PostgresStepUpApprovalChallengeStore,
  PostgresStepUpAuthenticatorStore,
} from "./PostgresStepUpProofStores";

/** The two environment entries the rule reads (injectable for tests). */
export interface StepUpProofStoreEnv {
  USE_POSTGRES?: string;
  DATABASE_URL?: string;
}

export interface StepUpProofStores {
  readonly challenges: IStepUpApprovalChallengeStore;
  readonly authenticators: IStepUpAuthenticatorStore;
}

export function createStepUpProofStores(
  env: StepUpProofStoreEnv = process.env,
): StepUpProofStores {
  if (env.USE_POSTGRES !== "true") {
    logger.info(
      "Step-up proof stores: in-memory (set USE_POSTGRES=true and DATABASE_URL to persist)",
      "StepUpProofStore",
    );
    return {
      challenges: new InMemoryStepUpApprovalChallengeStore(),
      authenticators: new InMemoryStepUpAuthenticatorStore(),
    };
  }

  const connectionString = env.DATABASE_URL?.trim() ?? "";
  if (!connectionString) {
    logger.warn(
      "USE_POSTGRES=true but DATABASE_URL is empty — step-up proof challenges fall back to memory (lost on restart, single instance only)",
      "StepUpProofStore",
    );
    return {
      challenges: new InMemoryStepUpApprovalChallengeStore(),
      authenticators: new InMemoryStepUpAuthenticatorStore(),
    };
  }

  logger.info(
    "Step-up proof stores: PostgreSQL (durable, shared across instances)",
    "StepUpProofStore",
  );
  return {
    challenges: new PostgresStepUpApprovalChallengeStore(connectionString),
    authenticators: new PostgresStepUpAuthenticatorStore(connectionString),
  };
}
