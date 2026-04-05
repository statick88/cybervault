/**
 * PopupOrchestrator - Central point for all popup logic
 *
 * PURPOSE: Replace the 1033-line monolithic popup.ts with a clean, testable API
 */

import { Credential } from "../../domain/entities/credential";
import { VaultId } from "../../domain/value-objects/ids";
import { PopupStorageService } from "./services/PopupStorageService";
import { VaultStatusService } from "./services/VaultStatusService";
import { CredentialsService } from "./services/CredentialsService";
import { ValidationService } from "./services/ValidationService";
import { NotificationService } from "./services/NotificationService";
import { PopupUIService } from "./services/PopupUIService";
import {
  initializeVault,
  lockVault,
  encryptWithSessionKey,
  decryptWithSessionKey,
} from "../../infrastructure/crypto/master-key-manager";

/**
 * Operation result type
 */
export interface OperationResult<T = void> {
  success: boolean;
  data?: T;
  error?: string;
}

/**
 * Credential input data (for add/edit - includes both plain and encrypted)
 */
export interface CredentialInput {
  title?: string;
  username?: string;
  password?: string;
  encryptedPassword?: string;
  url?: string;
  notes?: string;
  tags?: string[];
  favorite?: boolean;
}

/**
 * Event types emitted by the orchestrator
 */
export type OrchestratorEvent =
  | "status:changed"
  | "credentials:changed"
  | "notification:show"
  | "loading"
  | "error";

/**
 * PopupOrchestrator - Centralizes all popup logic and services
 */
export class PopupOrchestrator {
  private storageService: PopupStorageService;
  private vaultStatusService: VaultStatusService;
  private credentialsService: CredentialsService;
  private validationService: ValidationService;
  private notificationService: NotificationService;
  private uiService: PopupUIService;

  private eventListeners: Map<OrchestratorEvent, Set<(payload?: any) => void>>;
  private currentVaultId: VaultId | null = null;

  // Password tokens for temporary password viewing (in-memory only)
  private passwordTokens: Map<string, string> = new Map();

  constructor() {
    this.storageService = new PopupStorageService();
    this.vaultStatusService = new VaultStatusService();
    this.credentialsService = new CredentialsService(
      this.storageService,
      this.vaultStatusService,
    );
    this.validationService = new ValidationService();
    this.notificationService = new NotificationService();
    this.uiService = new PopupUIService();

    this.eventListeners = new Map();

    // Subscribe to underlying service events
    this.setupServiceSubscriptions();
  }

  /**
   * Subscribe to orchestrator events
   */
  public on(event: OrchestratorEvent, callback: (payload?: any) => void): void {
    if (!this.eventListeners.has(event)) {
      this.eventListeners.set(event, new Set());
    }
    this.eventListeners.get(event)!.add(callback);
  }

  /**
   * Unsubscribe from orchestrator events
   */
  public off(
    event: OrchestratorEvent,
    callback: (payload?: any) => void,
  ): void {
    const callbacks = this.eventListeners.get(event);
    if (callbacks) {
      callbacks.delete(callback);
    }
  }

  /**
   * Emit an event to all listeners
   */
  private emit(event: OrchestratorEvent, payload?: any): void {
    const callbacks = this.eventListeners.get(event);
    if (callbacks) {
      callbacks.forEach((cb) => cb(payload));
    }
  }

  /**
   * Subscribe to events from underlying services
   */
  private setupServiceSubscriptions(): void {
    // Vault status changes
    this.vaultStatusService.onStatusChange("status_change", () => {
      this.emit("status:changed", this.getVaultStatus());
    });

    this.vaultStatusService.onStatusChange("unlocked", () => {
      this.notification("🔓 Bóveda desbloqueada", "success");
    });

    this.vaultStatusService.onStatusChange("locked", () => {
      this.notification("🔒 Bóveda bloqueada", "info");
    });

    this.vaultStatusService.onStatusChange("session_expired", () => {
      this.notification("Sesión expirada", "warning");
    });

    // Credentials changes
    this.credentialsService.on("credentials:changed", () => {
      this.emit("credentials:changed");
    });
  }

  // ============================================================================
  // Initialization
  // ============================================================================

  /**
   * Initialize the orchestrator and check vault status
   */
  public async initialize(): Promise<void> {
    this.emit("loading", { isLoading: true, message: "Inicializando..." });

    try {
      await this.vaultStatusService.checkStatus();
      await this.ensureVaultId();
      this.emit("loading", { isLoading: false });
    } catch (error) {
      this.emit("error", {
        error: error as Error,
        context: "initialize",
      });
      this.emit("loading", { isLoading: false });
      throw error;
    }
  }

  /**
   * Ensure we have a vault ID
   */
  private async ensureVaultId(): Promise<void> {
    if (this.currentVaultId) return;

    const credentials = await this.storageService.loadCredentials();
    if (credentials.length > 0 && credentials[0].vaultId) {
      this.currentVaultId = credentials[0].vaultId;
    } else {
      this.currentVaultId = VaultId.generate();
    }
  }

  // ============================================================================
  // Master Key Operations
  // ============================================================================

  /**
   * Setup master key for the first time
   */
  public async setupMasterKey(
    masterKey: string,
    confirmKey?: string,
    understood?: boolean,
  ): Promise<OperationResult> {
    this.emit("loading", { isLoading: true, message: "Creando bóveda..." });

    try {
      if (!masterKey) {
        this.notification("La clave maestra es requerida", "error");
        this.emit("loading", { isLoading: false });
        return { success: false, error: "La clave maestra es requerida" };
      }

      if (confirmKey && masterKey !== confirmKey) {
        this.notification("Las claves no coinciden", "error");
        this.emit("loading", { isLoading: false });
        return { success: false, error: "Las claves no coinciden" };
      }

      if (masterKey.length < 12) {
        this.notification(
          "La clave debe tener al menos 12 caracteres",
          "error",
        );
        this.emit("loading", { isLoading: false });
        return {
          success: false,
          error: "La clave debe tener al menos 12 caracteres",
        };
      }

      if (understood !== true) {
        this.notification("Debes confirmar que entiendes el riesgo", "error");
        this.emit("loading", { isLoading: false });
        return {
          success: false,
          error: "Debes confirmar que entiendes el riesgo",
        };
      }

      const result = await initializeVault(masterKey);

      if (result.success) {
        await this.vaultStatusService.checkStatus();
        this.currentVaultId = VaultId.generate();
        this.notification("🎉 Bóveda creada correctamente", "success");
      }

      this.emit("loading", { isLoading: false });
      return result;
    } catch (error) {
      this.emit("error", {
        error: error as Error,
        context: "setupMasterKey",
      });
      this.emit("loading", { isLoading: false });
      return {
        success: false,
        error: error instanceof Error ? error.message : "Error desconocido",
      };
    }
  }

  /**
   * Unlock the vault with master key
   */
  public async unlockVault(masterKey: string): Promise<OperationResult> {
    this.emit("loading", { isLoading: true, message: "Desbloqueando..." });

    try {
      if (!masterKey) {
        this.notification("La clave maestra es requerida", "error");
        this.emit("loading", { isLoading: false });
        return { success: false, error: "La clave maestra es requerida" };
      }

      const result = await this.vaultStatusService.unlockVault(masterKey);

      if (result.success) {
        await this.credentialsService.loadAll();
        await this.ensureVaultId();
        this.notification("🔓 Bóveda desbloqueada", "success");
      }

      this.emit("loading", { isLoading: false });
      return { success: result.success, error: result.error };
    } catch (error) {
      this.emit("error", {
        error: error as Error,
        context: "unlockVault",
      });
      this.emit("loading", { isLoading: false });
      return {
        success: false,
        error: error instanceof Error ? error.message : "Error desconocido",
      };
    }
  }

  /**
   * Lock the vault
   */
  public lockVault(): void {
    lockVault();
    this.vaultStatusService.lockVault();
    this.notification("🔒 Bóveda bloqueada", "info");
  }

  // ============================================================================
  // Credentials Operations
  // ============================================================================

  /**
   * Get all credentials
   */
  public getCredentials(): Credential[] {
    return this.credentialsService.getFiltered();
  }

  /**
   * Search credentials by query
   */
  public searchCredentials(query: string): Credential[] {
    this.credentialsService.search(query);
    return this.credentialsService.getFiltered();
  }

  /**
   * Add a new credential
   */
  public async addCredential(
    credData: CredentialInput,
  ): Promise<OperationResult<Credential>> {
    this.emit("loading", {
      isLoading: true,
      message: "Guardando credencial...",
    });

    try {
      const status = this.vaultStatusService.getStatus();
      if (!status.unlocked) {
        this.notification("Bóveda bloqueada. Desbloquea primero.", "error");
        this.emit("loading", { isLoading: false });
        return {
          success: false,
          error: "Bóveda bloqueada. Desbloquea primero.",
        };
      }

      await this.ensureVaultId();
      if (!this.currentVaultId) {
        throw new Error("Vault ID not available");
      }

      // Sanitize
      const title = credData.title
        ? this.validationService.sanitizeString(credData.title, 100)
        : undefined;
      const username = credData.username
        ? this.validationService.sanitizeString(credData.username, 254)
        : undefined;
      const url = credData.url
        ? this.validationService.sanitizeString(credData.url, 2048)
        : undefined;
      const notes = credData.notes
        ? this.validationService.sanitizeString(credData.notes, 10000)
        : undefined;
      const tags = credData.tags
        ? this.validationService.validateTags(credData.tags)
        : [];

      if (!title || !username) {
        this.notification(
          "Título, usuario y contraseña son requeridos",
          "error",
        );
        this.emit("loading", { isLoading: false });
        return {
          success: false,
          error: "Título, usuario y contraseña son requeridos",
        };
      }

      if (url && !this.validationService.isValidUrl(url)) {
        this.notification("URL inválida", "error");
        this.emit("loading", { isLoading: false });
        return { success: false, error: "URL inválida" };
      }

      const password = credData.password || credData.encryptedPassword;
      if (!password) {
        this.notification("La contraseña es requerida", "error");
        this.emit("loading", { isLoading: false });
        return { success: false, error: "La contraseña es requerida" };
      }

      const encryptedPassword = await encryptWithSessionKey(password);
      if (!encryptedPassword) {
        this.notification("No se pudo encriptar la contraseña", "error");
        this.emit("loading", { isLoading: false });
        return {
          success: false,
          error: "No se pudo encriptar la contraseña",
        };
      }

      const newCredential = Credential.create({
        vaultId: this.currentVaultId,
        title,
        username,
        encryptedPassword,
        url,
        notes,
        tags,
        favorite: credData.favorite || false,
      });

      await this.credentialsService.add(newCredential);

      this.emit("loading", { isLoading: false });
      this.notification("Credencial guardada correctamente", "success");
      return { success: true, data: newCredential };
    } catch (error) {
      this.emit("error", {
        error: error as Error,
        context: "addCredential",
      });
      this.emit("loading", { isLoading: false });
      return {
        success: false,
        error: error instanceof Error ? error.message : "Error desconocido",
      };
    }
  }

  /**
   * Edit an existing credential
   */
  public async editCredential(
    id: string,
    updates: CredentialInput,
  ): Promise<OperationResult> {
    this.emit("loading", {
      isLoading: true,
      message: "Actualizando credencial...",
    });

    try {
      const status = this.vaultStatusService.getStatus();
      if (!status.unlocked) {
        this.notification("Bóveda bloqueada. Desbloquea primero.", "error");
        this.emit("loading", { isLoading: false });
        return {
          success: false,
          error: "Bóveda bloqueada. Desbloquea primero.",
        };
      }

      // Build updates object (use 'any' to bypass readonly restrictions)
      const serviceUpdates: any = {};

      if (updates.title !== undefined) {
        serviceUpdates.title = this.validationService.sanitizeString(
          updates.title,
          100,
        );
      }

      if (updates.username !== undefined) {
        serviceUpdates.username = this.validationService.sanitizeString(
          updates.username,
          254,
        );
      }

      if (updates.url !== undefined) {
        const sanitized = this.validationService.sanitizeString(
          updates.url,
          2048,
        );
        if (sanitized && this.validationService.isValidUrl(sanitized)) {
          serviceUpdates.url = sanitized;
        } else if (updates.url === null || updates.url === "") {
          serviceUpdates.url = undefined;
        }
      }

      if (updates.notes !== undefined) {
        serviceUpdates.notes = this.validationService.sanitizeString(
          updates.notes,
          10000,
        );
      }

      if (updates.tags !== undefined) {
        serviceUpdates.tags = this.validationService.validateTags(updates.tags);
      }

      if (updates.favorite !== undefined) {
        serviceUpdates.favorite = updates.favorite;
      }

      if (updates.password || updates.encryptedPassword) {
        const password = updates.password || updates.encryptedPassword;
        const encrypted = await encryptWithSessionKey(password as string);
        if (!encrypted) {
          this.notification("No se pudo encriptar la contraseña", "error");
          this.emit("loading", { isLoading: false });
          return {
            success: false,
            error: "No se pudo encriptar la contraseña",
          };
        }
        serviceUpdates.encryptedPassword = encrypted;
      }

      const success = await this.credentialsService.update(id, serviceUpdates);

      this.emit("loading", { isLoading: false });
      if (success) {
        this.notification("Credencial actualizada correctamente", "success");
        return { success: true };
      } else {
        this.notification("Credencial no encontrada", "error");
        return { success: false, error: "Credencial no encontrada" };
      }
    } catch (error) {
      this.emit("error", {
        error: error as Error,
        context: "editCredential",
      });
      this.emit("loading", { isLoading: false });
      return {
        success: false,
        error: error instanceof Error ? error.message : "Error desconocido",
      };
    }
  }

  /**
   * Delete a credential
   */
  public async deleteCredential(id: string): Promise<OperationResult> {
    this.emit("loading", {
      isLoading: true,
      message: "Eliminando credencial...",
    });

    try {
      const status = this.vaultStatusService.getStatus();
      if (!status.unlocked) {
        this.notification("Bóveda bloqueada. Desbloquea primero.", "error");
        this.emit("loading", { isLoading: false });
        return {
          success: false,
          error: "Bóveda bloqueada. Desbloquea primero.",
        };
      }

      const success = await this.credentialsService.delete(id);

      this.emit("loading", { isLoading: false });
      if (success) {
        this.notification("Credencial eliminada", "success");
        return { success: true };
      } else {
        this.notification("Credencial no encontrada", "error");
        return { success: false, error: "Credencial no encontrada" };
      }
    } catch (error) {
      this.emit("error", {
        error: error as Error,
        context: "deleteCredential",
      });
      this.emit("loading", { isLoading: false });
      return {
        success: false,
        error: error instanceof Error ? error.message : "Error desconocido",
      };
    }
  }

  /**
   * View credential details and get temporary password token
   */
  public async viewCredential(
    id: string,
  ): Promise<
    OperationResult<{ credential: Credential; passwordToken: string }>
  > {
    this.emit("loading", {
      isLoading: true,
      message: "Cargando credencial...",
    });

    try {
      const status = this.vaultStatusService.getStatus();
      if (!status.unlocked) {
        this.notification("Bóveda bloqueada. Desbloquea primero.", "error");
        this.emit("loading", { isLoading: false });
        return {
          success: false,
          error: "Bóveda bloqueada. Desbloquea primero.",
        };
      }

      const credentials = this.credentialsService.getAll();
      const credential = credentials.find((c) => c.id.toString() === id);

      if (!credential) {
        this.notification("Credencial no encontrada", "error");
        this.emit("loading", { isLoading: false });
        return {
          success: false,
          error: "Credencial no encontrada",
        };
      }

      const passwordToken = crypto.randomUUID();
      this.passwordTokens.set(passwordToken, credential.encryptedPassword);

      setTimeout(
        () => {
          this.passwordTokens.delete(passwordToken);
        },
        5 * 60 * 1000,
      );

      this.emit("loading", { isLoading: false });
      return {
        success: true,
        data: {
          credential,
          passwordToken,
        },
      };
    } catch (error) {
      this.emit("error", {
        error: error as Error,
        context: "viewCredential",
      });
      this.emit("loading", { isLoading: false });
      return {
        success: false,
        error: error instanceof Error ? error.message : "Error desconocido",
      };
    }
  }

  /**
   * Copy password using a one-time token
   */
  public async copyPassword(token: string): Promise<OperationResult<boolean>> {
    try {
      const status = this.vaultStatusService.getStatus();
      if (!status.unlocked) {
        this.notification("Bóveda bloqueada.", "error");
        return { success: false, error: "Bóveda bloqueada." };
      }

      const encryptedPassword = this.passwordTokens.get(token);
      if (!encryptedPassword) {
        this.notification("Token inválido o expirado", "error");
        return { success: false, error: "Token inválido o expirado" };
      }

      const decryptedPassword = await decryptWithSessionKey(encryptedPassword);
      if (!decryptedPassword) {
        this.notification("No se pudo desencriptar la contraseña", "error");
        return {
          success: false,
          error: "No se pudo desencriptar la contraseña",
        };
      }

      await navigator.clipboard.writeText(decryptedPassword);
      this.passwordTokens.delete(token);
      this.notification("Contraseña copiada", "success");
      return { success: true, data: true };
    } catch (error) {
      this.emit("error", {
        error: error as Error,
        context: "copyPassword",
      });
      return {
        success: false,
        error: error instanceof Error ? error.message : "Error desconocido",
      };
    }
  }

  // ============================================================================
  // Status Queries
  // ============================================================================

  /**
   * Get current vault status
   */
  public getVaultStatus(): {
    initialized: boolean;
    unlocked: boolean;
    sessionValid: boolean;
  } {
    const vaultStatus = this.vaultStatusService.getStatus();
    return {
      initialized: vaultStatus.initialized,
      unlocked: vaultStatus.unlocked,
      sessionValid: vaultStatus.sessionValid,
    };
  }

  /**
   * Check if vault is ready for operations
   */
  public isVaultReady(): boolean {
    const status = this.getVaultStatus();
    return status.initialized && status.unlocked && status.sessionValid;
  }

  // ============================================================================
  // Utility Methods
  // ============================================================================

  /**
   * Generate unique ID
   */
  public generateId(): string {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return Array.from(array, (b) => b.toString(16).padStart(2, "0")).join("");
  }

  /**
   * Show notification
   */
  public notification(
    message: string,
    type?: "success" | "error" | "warning" | "info",
    duration?: number,
  ): void {
    this.notificationService.showNotification(message, type, duration);
  }

  /**
   * Show modal
   */
  public showModal(modalId: string): void {
    this.uiService.showModal(modalId);
  }

  /**
   * Hide modal
   */
  public hideModal(modalId: string): void {
    this.uiService.hideModal(modalId);
  }
}

/**
 * Create and export a singleton instance for the popup
 */
export const popupOrchestrator = new PopupOrchestrator();
