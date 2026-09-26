/**
 * In-memory Release Share store.
 *
 * Holds wrapped Release Shares only — no key material, no unwrap logic (see
 * `infrastructure/crypto/release-share-kek.ts`). Suitable for tests, single
 * instance development and the dev API server; a multi-instance deployment
 * needs a durable implementation of the same `IReleaseShareStore` port.
 *
 * @module infrastructure/repositories/InMemoryReleaseShareStore
 */

import type { IReleaseShareStore, WrappedReleaseShare } from "../../domain/repositories";

export class InMemoryReleaseShareStore implements IReleaseShareStore {
  private readonly entries = new Map<string, WrappedReleaseShare>();

  async save(entry: WrappedReleaseShare): Promise<void> {
    this.entries.set(entry.secretRef, {
      secretRef: entry.secretRef,
      wrappedShare: entry.wrappedShare,
      createdAt: entry.createdAt,
    });
  }

  async findBySecretRef(secretRef: string): Promise<WrappedReleaseShare | null> {
    return this.entries.get(secretRef) ?? null;
  }

  async delete(secretRef: string): Promise<boolean> {
    return this.entries.delete(secretRef);
  }

  /**
   * Read-only view of what is actually persisted.
   *
   * Exposed so tests can assert that no plaintext secret ever reaches the
   * store. Returns copies; the stored blobs are never handed out for mutation.
   */
  snapshot(): WrappedReleaseShare[] {
    return [...this.entries.values()].map((entry) => ({ ...entry }));
  }
}
