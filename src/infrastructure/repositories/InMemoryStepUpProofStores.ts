/**
 * In-memory adapters for the R11 step-up proof stores.
 *
 * Same role as `InMemoryReleaseShareStore`: tests, single-instance
 * development and the dev API server. The factory picks Postgres instead
 * when `USE_POSTGRES=true` and `DATABASE_URL` is set — the process runs one
 * or the other, never a split view of the same challenge.
 *
 * One-time use stays honest here: JavaScript is single-threaded and
 * `consume` checks and writes with no `await` in between, so the check-and-
 * the-write are one indivisible step — the in-memory equivalent of the
 * Postgres store's guarded `UPDATE ... WHERE consumed_at IS NULL`.
 *
 * @module infrastructure/repositories/InMemoryStepUpProofStores
 */

import type {
  IStepUpApprovalChallengeStore,
  IStepUpAuthenticatorStore,
  StepUpApprovalChallenge,
  StepUpAuthenticator,
} from "../../domain/repositories";

export class InMemoryStepUpApprovalChallengeStore implements IStepUpApprovalChallengeStore {
  private readonly rows = new Map<string, StepUpApprovalChallenge>();

  async save(challenge: StepUpApprovalChallenge): Promise<void> {
    this.rows.set(challenge.id, challenge);
  }

  async consume(id: string, userId: string, now: number): Promise<StepUpApprovalChallenge | null> {
    const row = this.rows.get(id);
    if (!row) return null;
    if (row.userId !== userId) return null;
    if (row.consumedAt !== null) return null;
    if (row.expiresAt <= now) return null;
    // No await between read and write: atomic by single-threaded execution.
    const consumed: StepUpApprovalChallenge = { ...row, consumedAt: now };
    this.rows.set(id, consumed);
    return consumed;
  }

  async findById(id: string): Promise<StepUpApprovalChallenge | null> {
    return this.rows.get(id) ?? null;
  }
}

export class InMemoryStepUpAuthenticatorStore implements IStepUpAuthenticatorStore {
  private readonly rows = new Map<string, StepUpAuthenticator>();

  async save(authenticator: StepUpAuthenticator): Promise<boolean> {
    const existing = this.rows.get(authenticator.credentialId);
    if (existing && existing.userId !== authenticator.userId) return false;
    this.rows.set(authenticator.credentialId, authenticator);
    return true;
  }

  async findByCredentialId(credentialId: string): Promise<StepUpAuthenticator | null> {
    return this.rows.get(credentialId) ?? null;
  }

  async listByUserId(userId: string): Promise<StepUpAuthenticator[]> {
    return [...this.rows.values()].filter((row) => row.userId === userId);
  }

  async updateCounter(credentialId: string, counter: number): Promise<void> {
    const row = this.rows.get(credentialId);
    if (!row) return;
    // Mirror the Postgres adapter's `WHERE counter < $2`: counters only move
    // forward, so a stale or replayed update can never rewind clone detection.
    if (counter <= row.counter) return;
    this.rows.set(credentialId, { ...row, counter });
  }
}
