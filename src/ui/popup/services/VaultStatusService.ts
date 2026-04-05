/**
 * VaultStatusService - Gestor de estado de la bóveda
 *
 * SECURITY: Zero Trust Architecture
 * - Centraliza el estado del vault para consistencia
 * - Notifica cambios via eventos para actualización de UI
 * - NO almacena datos sensibles, solo metadatos de estado
 *
 * Uso:
 *   const service = new VaultStatusService();
 *   service.onStatusChange(() => updateUI());
 *   await service.initialize();
 */

import {
  isVaultInitialized,
  unlockVault,
  lockVault,
  isVaultUnlocked,
  isSessionValid,
  refreshSession,
} from "@/infrastructure/crypto/master-key-manager";

// Duración de sesión (15 minutos) - debe coincidir con master-key-manager
const SESSION_DURATION_MS = 15 * 60 * 1000;

/**
 * Estado de la bóveda
 */
export interface VaultStatus {
  initialized: boolean;
  unlocked: boolean;
  sessionValid: boolean;
  unlockTime: number | null;
}

/**
 * Event types para listeners
 */
export type VaultStatusEvent =
  | "status_change"
  | "unlocked"
  | "locked"
  | "session_expired"
  | "initialized";

/**
 * Servicio de gestión de estado de la bóveda
 * Mantiene estado en memoria y notifica cambios via eventos
 */
export class VaultStatusService {
  private status: VaultStatus;
  private listeners: Map<VaultStatusEvent, Set<() => void>>;

  constructor() {
    this.status = {
      initialized: false,
      unlocked: false,
      sessionValid: false,
      unlockTime: null,
    };
    this.listeners = new Map();
  }

  /**
   * Obtener copia del estado actual
   */
  public getStatus(): Readonly<VaultStatus> {
    return { ...this.status };
  }

  /**
   * Verificar si el vault está inicializado
   */
  public async checkStatus(): Promise<void> {
    const initialized = await isVaultInitialized();
    this.updateStatus({ initialized });

    // Si está inicializado, también verificar unlock/session
    if (initialized) {
      const unlocked = isVaultUnlocked();
      const unlockTime = this.getUnlockTimeFromMemory();
      const sessionValid = unlockTime
        ? Date.now() - unlockTime < SESSION_DURATION_MS
        : false;

      this.updateStatus({
        unlocked,
        sessionValid,
        unlockTime: unlocked ? unlockTime : null,
      });
    } else {
      // No inicializado => no desbloqueado
      this.updateStatus({
        unlocked: false,
        sessionValid: false,
        unlockTime: null,
      });
    }
  }

  /**
   * Desbloquear vault con clave maestra
   */
  public async unlockVault(masterKey: string): Promise<{
    success: boolean;
    error?: string;
  }> {
    const result = await unlockVault(masterKey);

    if (result.success) {
      // Actualizar estado local basado en master-key-manager state
      const unlocked = isVaultUnlocked();
      const unlockTime = this.getUnlockTimeFromMemory();
      const sessionValid = isSessionValid();

      this.updateStatus({
        unlocked,
        sessionValid,
        unlockTime: unlocked ? unlockTime : null,
      });
    }

    return result;
  }

  /**
   * Bloquear vault
   */
  public lockVault(): void {
    lockVault();
    this.updateStatus({
      unlocked: false,
      sessionValid: false,
      unlockTime: null,
    });
  }

  /**
   * Refrescar timer de sesión
   */
  public refreshSession(): void {
    refreshSession();

    // Recalcular estado de sesión
    const sessionValid = isSessionValid();
    const unlockTime = this.getUnlockTimeFromMemory();

    this.updateStatus({
      sessionValid,
      unlockTime: sessionValid ? unlockTime : null,
    });
  }

  /**
   * Verificar si la sesión actual es válida
   */
  public isSessionValid(): boolean {
    return isSessionValid();
  }

  /**
   * Registrar callback para cambios de estado
   */
  public onStatusChange(event: VaultStatusEvent, callback: () => void): void {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event)!.add(callback);
  }

  /**
   * Remover callback de cambios de estado
   */
  public offStatusChange(event: VaultStatusEvent, callback: () => void): void {
    const callbacks = this.listeners.get(event);
    if (callbacks) {
      callbacks.delete(callback);
    }
  }

  /**
   * Emitir evento de cambio de estado
   */
  private emit(event: VaultStatusEvent): void {
    const callbacks = this.listeners.get(event);
    if (callbacks) {
      callbacks.forEach((cb) => cb());
    }
  }

  /**
   * Actualizar estado interno y emitir eventos apropiados
   */
  private updateStatus(updates: Partial<VaultStatus>): void {
    const previous = { ...this.status };
    this.status = { ...this.status, ...updates };

    // Emitir eventos específicos basados en cambios
    if (
      updates.initialized !== undefined &&
      updates.initialized !== previous.initialized
    ) {
      this.emit("initialized");
    }

    if (
      updates.unlocked !== undefined &&
      updates.unlocked !== previous.unlocked
    ) {
      if (updates.unlocked) {
        this.emit("unlocked");
      } else {
        this.emit("locked");
      }
    }

    if (
      updates.sessionValid !== undefined &&
      updates.sessionValid !== previous.sessionValid
    ) {
      if (!updates.sessionValid && previous.sessionValid) {
        this.emit("session_expired");
      }
    }

    // Siempre emitir cambio general
    this.emit("status_change");
  }

  /**
   * Obtener unlockTime del estado de master-key-manager
   * (Acceso interno al estado del módulo)
   */
  private getUnlockTimeFromMemory(): number | null {
    // Acceder al estado interno de master-key-manager via getSessionKey
    // o mantenerlo sincronizado. Por ahora, guardar unlockTime localmente en sync.
    // En una implementación futura, master-key-manager podría exponerlo.
    return this.status.unlockTime;
  }
}

/**
 * Instancia singleton para uso global
 */
export const vaultStatusService = new VaultStatusService();
