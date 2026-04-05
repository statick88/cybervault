import { Credential } from "../../../domain/entities/credential";
import { CredentialId } from "../../../domain/value-objects/ids";
import { PopupStorageService } from "./PopupStorageService";
import { VaultStatusService } from "./VaultStatusService";

/**
 * Event types para el servicio de credenciales
 */
export type CredentialsEvent =
  | "credentials:changed"
  | "credentials:loaded"
  | "credentials:search:updated";

/**
 * CredentialsService - Gestor de estado de credenciales en memoria
 *
 * RESPONSABILIDADES:
 * - Gestionar estado de credenciales en caché (memoria)
 * - CRUD operations usando PopupStorageService
 * - Filtrado y búsqueda
 * - Ordenamiento (favorites first, alphabetical)
 * - Notificar cambios via eventos
 *
 * USO:
 *   const service = new CredentialsService(storageService, vaultStatusService);
 *   await service.loadAll();
 *   service.onChange(() => updateUI());
 */
export class CredentialsService {
  private credentials: Credential[] = [];
  private filteredCredentials: Credential[] = [];
  private listeners: Map<CredentialsEvent, Set<() => void>> = new Map();

  constructor(
    private storageService: PopupStorageService,
    private vaultStatusService: VaultStatusService,
  ) {}

  /**
   * Carga todas las credenciales desde storage
   * REQUISITO: Vault debe estar unlocked
   */
  async loadAll(): Promise<Credential[]> {
    this.ensureVaultUnlocked();

    const credentials = await this.storageService.loadCredentials();
    this.credentials = credentials;
    this.filteredCredentials = [...credentials];
    this.applySorting(this.filteredCredentials);

    this.emit("credentials:loaded");
    this.emit("credentials:changed");

    return credentials;
  }

  /**
   * Retorna copia de todas las credenciales
   */
  getAll(): Credential[] {
    return [...this.credentials];
  }

  /**
   * Retorna copia de credenciales filtradas
   */
  getFiltered(): Credential[] {
    return [...this.filteredCredentials];
  }

  /**
   * Crea una nueva credencial
   * REQUISITO: Vault debe estar unlocked
   */
  async add(
    credential: Omit<Credential, "id" | "createdAt" | "updatedAt">,
  ): Promise<Credential> {
    this.ensureVaultUnlocked();

    // Crear credencial usando factory method
    const newCredential = Credential.create({
      vaultId: credential.vaultId,
      title: credential.title,
      username: credential.username,
      encryptedPassword: credential.encryptedPassword,
      url: credential.url,
      notes: credential.notes,
      tags: credential.tags,
      favorite: credential.favorite,
    });

    // Agregar al estado local
    this.credentials.push(newCredential);

    // Actualizar filtered si coincide con filtro actual
    if (this.matchesCurrentFilter(newCredential)) {
      this.filteredCredentials.push(newCredential);
      this.applySorting(this.filteredCredentials);
    }

    // Persistir
    await this.storageService.saveCredentials(this.credentials);

    // Notificar cambios
    this.emit("credentials:changed");

    return newCredential;
  }

  /**
   * Actualiza una credencial existente
   * REQUISITO: Vault debe estar unlocked
   */
  async update(
    id: string,
    updates: Partial<Omit<Credential, "id" | "createdAt">>,
  ): Promise<boolean> {
    this.ensureVaultUnlocked();

    const credentialId = CredentialId.fromString(id);
    const index = this.credentials.findIndex((cred) =>
      cred.id.equals(credentialId),
    );

    if (index === -1) {
      return false;
    }

    const credential = this.credentials[index];

    // Aplicar actualizaciones usando métodos de dominio
    if (updates.title !== undefined) {
      credential.updateTitle(updates.title);
    }
    if (updates.username !== undefined) {
      credential.updateUsername(updates.username);
    }
    if (updates.encryptedPassword !== undefined) {
      credential.updatePassword(updates.encryptedPassword);
    }
    if (updates.url !== undefined || updates.url === null) {
      // Necesitamos un setter URL o reconstruir el objeto
      // Por ahora, asumimos que no se actualiza URL directamente
    }
    if (updates.notes !== undefined || updates.notes === null) {
      // Similar a URL
    }
    if (updates.tags !== undefined) {
      // Reemplazar tags completamente
      credential["props"].tags = [...updates.tags];
      credential["props"].updatedAt = new Date();
    }
    if (updates.favorite !== undefined) {
      if (updates.favorite !== credential.favorite) {
        credential.toggleFavorite();
      }
    }
    // lastUsed se maneja via incrementUsage

    // Reemplazar en array
    this.credentials[index] = credential;

    // Actualizar filtered si existe
    const filteredIndex = this.filteredCredentials.findIndex((cred) =>
      cred.id.equals(credentialId),
    );
    if (filteredIndex !== -1) {
      this.filteredCredentials[filteredIndex] = credential;
      this.applySorting(this.filteredCredentials);
    }

    // Persistir
    await this.storageService.saveCredentials(this.credentials);

    // Notificar cambios
    this.emit("credentials:changed");

    return true;
  }

  /**
   * Elimina una credencial
   * REQUISITO: Vault debe estar unlocked
   */
  async delete(id: string): Promise<boolean> {
    this.ensureVaultUnlocked();

    const credentialId = CredentialId.fromString(id);
    const initialLength = this.credentials.length;

    // Remover de credentials
    this.credentials = this.credentials.filter(
      (cred) => !cred.id.equals(credentialId),
    );

    // Remover de filtered
    this.filteredCredentials = this.filteredCredentials.filter(
      (cred) => !cred.id.equals(credentialId),
    );

    const deleted = this.credentials.length < initialLength;

    if (deleted) {
      // Persistir
      await this.storageService.saveCredentials(this.credentials);

      // Notificar cambios
      this.emit("credentials:changed");
    }

    return deleted;
  }

  /**
   * Filtra credenciales por búsqueda (title, username, url, tags)
   * La búsqueda es case-insensitive y busca matches parciales
   */
  search(query: string): void {
    if (!query.trim()) {
      this.clearSearch();
      return;
    }

    const lowerQuery = query.toLowerCase().trim();

    this.filteredCredentials = this.credentials.filter((cred) => {
      // Buscar en title
      if (cred.title.toLowerCase().includes(lowerQuery)) {
        return true;
      }
      // Buscar en username
      if (cred.username.toLowerCase().includes(lowerQuery)) {
        return true;
      }
      // Buscar en url
      if (cred.url && cred.url.toLowerCase().includes(lowerQuery)) {
        return true;
      }
      // Buscar en tags
      if (cred.tags.some((tag) => tag.toLowerCase().includes(lowerQuery))) {
        return true;
      }
      return false;
    });

    this.applySorting(this.filteredCredentials);
    this.emit("credentials:search:updated");
    this.emit("credentials:changed");
  }

  /**
   * Resetea el filtro, mostrando todas las credenciales
   */
  clearSearch(): void {
    this.filteredCredentials = [...this.credentials];
    this.applySorting(this.filteredCredentials);
    this.emit("credentials:search:updated");
    this.emit("credentials:changed");
  }

  /**
   * Marca/desmarca una credencial como favorita
   * REQUISITO: Vault debe estar unlocked
   */
  async toggleFavorite(id: string): Promise<void> {
    this.ensureVaultUnlocked();

    const credentialId = CredentialId.fromString(id);
    const index = this.credentials.findIndex((cred) =>
      cred.id.equals(credentialId),
    );

    if (index === -1) {
      throw new Error(`Credential with id ${id} not found`);
    }

    const credential = this.credentials[index];
    credential.toggleFavorite();

    // Actualizar en filtered también
    const filteredIndex = this.filteredCredentials.findIndex((cred) =>
      cred.id.equals(credentialId),
    );
    if (filteredIndex !== -1) {
      this.filteredCredentials[filteredIndex] = credential;
    }

    this.applySorting(this.filteredCredentials);

    // Persistir
    await this.storageService.saveCredentials(this.credentials);

    // Notificar cambios
    this.emit("credentials:changed");
  }

  /**
   * Incrementa el contador de uso (lastUsed) de una credencial
   * REQUISITO: Vault debe estar unlocked
   */
  async incrementUsage(id: string): Promise<void> {
    this.ensureVaultUnlocked();

    const credentialId = CredentialId.fromString(id);
    const index = this.credentials.findIndex((cred) =>
      cred.id.equals(credentialId),
    );

    if (index === -1) {
      throw new Error(`Credential with id ${id} not found`);
    }

    const credential = this.credentials[index];
    credential.markAsUsed();

    // Actualizar en filtered también
    const filteredIndex = this.filteredCredentials.findIndex((cred) =>
      cred.id.equals(credentialId),
    );
    if (filteredIndex !== -1) {
      this.filteredCredentials[filteredIndex] = credential;
    }

    // Persistir
    await this.storageService.saveCredentials(this.credentials);

    // Notificar cambios
    this.emit("credentials:changed");
  }

  /**
   * Registra callback para eventos
   */
  on(event: CredentialsEvent, callback: () => void): void {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event)!.add(callback);
  }

  /**
   * Remueve callback de eventos
   */
  off(event: CredentialsEvent, callback: () => void): void {
    const callbacks = this.listeners.get(event);
    if (callbacks) {
      callbacks.delete(callback);
    }
  }

  /**
   * Emite un evento
   */
  private emit(event: CredentialsEvent): void {
    const callbacks = this.listeners.get(event);
    if (callbacks) {
      callbacks.forEach((cb) => cb());
    }
  }

  /**
   * Aplica ordenamiento: favorites first, luego alfabético por title
   */
  private applySorting(credentials: Credential[]): void {
    credentials.sort((a, b) => {
      // Favorites primero
      if (a.favorite && !b.favorite) return -1;
      if (!a.favorite && b.favorite) return 1;

      // Orden alfabético por título
      return a.title.localeCompare(b.title);
    });
  }

  /**
   * Verifica si una credencial coincide con el filtro actual de búsqueda
   */
  private matchesCurrentFilter(credential: Credential): boolean {
    // Si no hay filtro activo (filtered === credentials), todos coinciden
    if (this.filteredCredentials.length === this.credentials.length) {
      return true;
    }

    // Verificar si está en filtered
    return this.filteredCredentials.some((c) => c.id.equals(credential.id));
  }

  /**
   * Verifica que el vault esté desbloqueado antes de operaciones de escritura
   */
  private ensureVaultUnlocked(): void {
    const status = this.vaultStatusService.getStatus();
    if (!status.unlocked) {
      throw new Error("Vault is locked. Unlock the vault first.");
    }
  }
}
