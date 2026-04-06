/**
 * In-Memory Vault Repository para testing
 * Implementa IVaultRepository usando memoria volátil
 */

import { IVaultRepository } from "../../../../../src/domain/repositories";
import { Vault } from "../../../../../src/domain/entities/vault";
import { VaultId } from "../../../../../src/domain/value-objects/ids";

export class InMemoryVaultRepository implements IVaultRepository {
  private vaults: Map<string, Vault> = new Map();

  async save(vault: Vault): Promise<Vault> {
    this.vaults.set(vault.id.toString(), vault);
    return vault;
  }

  async findById(id: VaultId): Promise<Vault | null> {
    return this.vaults.get(id.toString()) || null;
  }

  async delete(id: VaultId): Promise<boolean> {
    return this.vaults.delete(id.toString());
  }

  async list(): Promise<Vault[]> {
    return Array.from(this.vaults.values());
  }

  /**
   * Helper para limpiar estado entre tests
   */
  clear(): void {
    this.vaults.clear();
  }

  /**
   * Helper para obtener count (útil para asserts)
   */
  getCount(): number {
    return this.vaults.size;
  }
}
