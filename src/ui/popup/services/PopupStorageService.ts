import { Credential } from "../../../domain/entities/credential";
import { CredentialId } from "../../../domain/value-objects/ids";

/**
 * Servicio de almacenamiento para el popup.
 * Maneja la persistencia de credenciales y estado del vault usando chrome.storage.local.
 */
export class PopupStorageService {
  /**
   * Carga todas las credenciales desde storage.
   * @returns Promise con array de credenciales
   */
  async loadCredentials(): Promise<Credential[]> {
    try {
      const result = await chrome.storage.local.get(["credentials"]);

      if (!result.credentials || !Array.isArray(result.credentials)) {
        return [];
      }

      // Deserializar cada credencial desde objeto plano
      const credentials = result.credentials.map(
        (cred: {
          id: string;
          vaultId: string;
          title: string;
          username: string;
          encryptedPassword: string;
          url?: string;
          notes?: string;
          tags: string[];
          favorite: boolean;
          createdAt: string;
          updatedAt: string;
          lastUsed?: string;
        }) => Credential.fromPlainObject(cred),
      );

      // Devolver copia del array (no referencia interna)
      return [...credentials];
    } catch (error) {
      console.error("[PopupStorageService] Error loading credentials:", error);
      throw error;
    }
  }

  /**
   * Guarda todas las credenciales en storage (reemplaza completo).
   * @param credentials Array de credenciales a guardar
   */
  async saveCredentials(credentials: Credential[]): Promise<void> {
    try {
      // Serializar credenciales a objetos planos
      const plainCredentials = credentials.map((cred) => cred.toPlainObject());

      // Guardar en storage
      await chrome.storage.local.set({ credentials: plainCredentials });
    } catch (error) {
      console.error("[PopupStorageService] Error saving credentials:", error);
      throw error;
    }
  }

  /**
   * Obtiene el estado actual del vault.
   * @returns Promise con estado de inicialización y desbloqueo
   */
  async getVaultStatus(): Promise<{ initialized: boolean; unlocked: boolean }> {
    try {
      const result = await chrome.storage.local.get([
        "vault_initialized",
        "vault_unlocked",
      ]);

      return {
        initialized: result.vault_initialized === true,
        unlocked: result.vault_unlocked === true,
      };
    } catch (error) {
      console.error("[PopupStorageService] Error getting vault status:", error);
      throw error;
    }
  }

  /**
   * Añade una nueva credencial al storage.
   * @param credential Credencial a añadir
   */
  async addCredential(credential: Credential): Promise<void> {
    try {
      const credentials = await this.loadCredentials();
      credentials.push(credential);
      await this.saveCredentials(credentials);
    } catch (error) {
      console.error("[PopupStorageService] Error adding credential:", error);
      throw error;
    }
  }

  /**
   * Actualiza una credencial existente por ID.
   * @param id ID de la credencial a actualizar
   * @param updates Campos a actualizar (parciales)
   */
  async updateCredential(
    id: string,
    updates: Partial<Credential>,
  ): Promise<void> {
    try {
      // Validar formato UUID
      const credentialId = CredentialId.fromString(id);

      const credentials = await this.loadCredentials();
      const index = credentials.findIndex((cred) =>
        cred.id.equals(credentialId),
      );

      if (index === -1) {
        throw new Error(`Credential with id ${id} not found`);
      }

      const credential = credentials[index];

      // Aplicar actualizaciones manteniendo consistencia
      if (updates.title !== undefined) {
        credential.updateTitle(updates.title);
      }
      if (updates.username !== undefined) {
        credential.updateUsername(updates.username);
      }
      if (updates.encryptedPassword !== undefined) {
        credential.updatePassword(updates.encryptedPassword);
      }

      credentials[index] = credential;
      await this.saveCredentials(credentials);
    } catch (error) {
      console.error("[PopupStorageService] Error updating credential:", error);
      throw error;
    }
  }

  /**
   * Elimina una credencial por ID.
   * @param id ID de la credencial a eliminar
   */
  async deleteCredential(id: string): Promise<void> {
    try {
      const credentials = await this.loadCredentials();
      const filtered = credentials.filter((cred) => cred.id.toString() !== id);

      // Verificar que se eliminó exactamente una
      if (filtered.length === credentials.length) {
        throw new Error(`Credential with id ${id} not found`);
      }

      await this.saveCredentials(filtered);
    } catch (error) {
      console.error("[PopupStorageService] Error deleting credential:", error);
      throw error;
    }
  }
}
