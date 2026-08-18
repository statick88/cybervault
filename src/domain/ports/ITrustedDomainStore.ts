export interface ITrustedDomainStore {
  isTrusted(normalizedDomain: string): boolean;
  add(domain: string): void;
  remove(domain: string): void;
  getAll(): ReadonlyArray<string>;
  clear(): void;
}