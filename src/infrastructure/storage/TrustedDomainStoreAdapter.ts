import type { ITrustedDomainStore } from '../../domain/ports/ITrustedDomainStore';
import type { IDomainNormalizer } from '../../domain/ports/IDomainNormalizer';

export class TrustedDomainStoreAdapter implements ITrustedDomainStore {
  private readonly store = new Set<string>();

  constructor(
    private readonly normalizer: IDomainNormalizer,
    private readonly storageKey = 'cybervault:trusted-domains'
  ) {
    this.loadFromStorage();
  }

  isTrusted(normalizedDomain: string): boolean {
    return this.store.has(normalizedDomain.toLowerCase());
  }

  add(domain: string): void {
    const { hostname } = this.normalizer.normalize(domain);
    this.store.add(hostname);
    this.persist();
  }

  remove(domain: string): void {
    const { hostname } = this.normalizer.normalize(domain);
    this.store.delete(hostname);
    this.persist();
  }

  getAll(): ReadonlyArray<string> {
    return [...this.store];
  }

  clear(): void {
    this.store.clear();
    this.persist();
  }

  private loadFromStorage(): void {
    try {
      const stored = localStorage.getItem(this.storageKey);
      if (stored) {
        const parsed = JSON.parse(stored);
        if (Array.isArray(parsed)) {
          for (const d of parsed) this.store.add(d.toLowerCase());
        }
      }
    } catch {
      // Ignore corrupted storage
    }
  }

  private persist(): void {
    try {
      localStorage.setItem(this.storageKey, JSON.stringify([...this.store]));
    } catch {
      // Storage full/private mode
    }
  }
}