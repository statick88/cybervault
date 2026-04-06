import { IVaultRepository } from "../../domain/repositories";
import { Vault } from "../../domain/entities/vault";
import { VaultId } from "../../domain/value-objects/ids";

export class ChromeStorageVaultRepository implements IVaultRepository {
  private readonly STORAGE_KEY = "vault_data";

  async save(vault: Vault): Promise<Vault> {
    const plain = vault.toPlainObject();
    await chrome.storage.local.set({ [this.STORAGE_KEY]: plain });
    return vault;
  }

  async findById(id: VaultId): Promise<Vault | null> {
    const result = await chrome.storage.local.get([this.STORAGE_KEY]);
    const data = (result as any)[this.STORAGE_KEY] as
      | ReturnType<Vault["toPlainObject"]>
      | undefined;
    if (!data) return null;
    const vault = Vault.fromPlainObject(data);
    return vault.id.equals(id) ? vault : null;
  }

  async delete(id: VaultId): Promise<boolean> {
    // Deleter el vault si matches ID
    const result = await chrome.storage.local.get([this.STORAGE_KEY]);
    const data = (result as any)[this.STORAGE_KEY] as
      | ReturnType<Vault["toPlainObject"]>
      | undefined;
    if (!data) return false;
    const vault = Vault.fromPlainObject(data);
    if (!vault.id.equals(id)) return false;
    await chrome.storage.local.remove(this.STORAGE_KEY);
    return true;
  }

  async list(): Promise<Vault[]> {
    const result = await chrome.storage.local.get([this.STORAGE_KEY]);
    const data = (result as any)[this.STORAGE_KEY] as
      | ReturnType<Vault["toPlainObject"]>
      | undefined;
    if (!data) return [];
    const vault = Vault.fromPlainObject(data);
    return [vault]; // solo uno
  }
}
