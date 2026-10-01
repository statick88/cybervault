/**
 * OptimisticLockConflictError — raised when a repository write that carries an
 * `expectedVersion` cannot be applied because the stored row no longer has the
 * version the caller read.
 *
 * H5 (lost update) — `PostgresVaultRepository` and `PostgresCredentialRepository`
 * used to blind-`UPSERT`: whoever wrote last won, with no check against what
 * the caller had read. Two concurrent writes therefore silently discarded one
 * of them. The repositories now accept an OPTIONAL `expectedVersion` and, when
 * it is supplied, perform a guarded UPDATE
 * (`WHERE id = $1 AND lock_version = $2`). Zero affected rows means somebody
 * else committed first, and this error is thrown instead of overwriting.
 *
 * WHY OPTIONAL. `expectedVersion` is deliberately opt-in: every caller that
 * does not pass it keeps the original blind-write behaviour, so no existing
 * write path can start failing. `RecoveryUseCase.updateMetadata` — the one
 * production call that reaches `updateMetadata` — does not pass it and is
 * therefore unaffected.
 *
 * The `code` property follows the shape `server.ts` already reads when it maps
 * an error to a response (`"code" in error`), so a route can surface it without
 * importing the class.
 */
export type LockableEntity = "vault" | "credential";

export class OptimisticLockConflictError extends Error {
  readonly code = "OPTIMISTIC_LOCK_CONFLICT" as const;
  readonly entity: LockableEntity;
  readonly id: string;
  readonly expectedVersion: number;
  /** Version actually stored, when the row was found. Undefined when it was not. */
  readonly actualVersion?: number;

  constructor(
    entity: LockableEntity,
    id: string,
    expectedVersion: number,
    actualVersion?: number,
  ) {
    super(
      actualVersion === undefined
        ? `${entity} ${id} does not exist (expected lock_version ${expectedVersion}, guarded write refused without INSERT)`
        : `${entity} ${id} is at lock_version ${actualVersion} but the caller expected ${expectedVersion} — concurrent modification`,
    );
    this.name = "OptimisticLockConflictError";
    this.entity = entity;
    this.id = id;
    this.expectedVersion = expectedVersion;
    this.actualVersion = actualVersion;

    // Keeps `instanceof` working after compilation down to ES5.
    Object.setPrototypeOf(this, OptimisticLockConflictError.prototype);
  }
}
