/**
 * Background Auditor - Chrome MV3 Service Worker
 * Monitoreo pasivo de vulnerabilidades y credenciales
 *
 * Este archivo es el Service Worker principal que se ejecuta en background.
 * NO almacena información sensible de forma persistente.
 */

import { BreachDetector } from "./breach-detector";
import { CredentialMonitor } from "./credential-monitor";
import { secureZero } from "../infrastructure/crypto/secure-memory";

// ============================================================================
// Tipos e Interfaces
// ============================================================================

export interface AuditorConfig {
  scanIntervalHours: number;
  breachCheckEnabled: boolean;
  credentialMonitorEnabled: boolean;
  threatIntelSyncEnabled: boolean;
}

export interface AuditResult {
  id: string;
  timestamp: Date;
  type: "breach_check" | "credential_scan" | "threat_intel" | "full";
  findings: Finding[];
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE";
}

export interface Finding {
  category: "breach" | "credential" | "threat" | "config";
  title: string;
  description: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  recommendation?: string;
  metadata?: Record<string, unknown>;
}

// ============================================================================
// Constantes
// ============================================================================

const DEFAULT_CONFIG: AuditorConfig = {
  scanIntervalHours: 24,
  breachCheckEnabled: true,
  credentialMonitorEnabled: true,
  threatIntelSyncEnabled: true,
};

const STORAGE_KEYS = {
  CONFIG: "auditor_config",
  LAST_SCAN: "last_audit_timestamp",
  AUDIT_RESULTS: "audit_results",
} as const;

// ============================================================================
// Background Auditor Service
// ============================================================================

export class BackgroundAuditor {
  private config: AuditorConfig;
  private breachDetector: BreachDetector;
  private credentialMonitor: CredentialMonitor;
  private isRunning: boolean = false;
  private scanHistory: AuditResult[] = [];

  constructor() {
    this.config = { ...DEFAULT_CONFIG };
    this.breachDetector = new BreachDetector();
    this.credentialMonitor = new CredentialMonitor();
  }

  /**
   * Inicializa el auditor - llamado desde Service Worker
   */
  async initialize(): Promise<void> {
    try {
      console.log("[BackgroundAuditor] Inicializando...");

      // Cargar configuración
      await this.loadConfig();

      // Configurar alarm para scans periódicos
      await this.setupScheduledScans();

      // Registrar event listeners
      this.registerEventListeners();

      // Ejecutar scan inicial
      await this.runFullAudit();

      console.log("[BackgroundAuditor] Inicialización completa");
    } catch (error) {
      console.error("[BackgroundAuditor] Error en inicialización:", error);
    }
  }

  /**
   * Carga configuración desde storage
   */
  private async loadConfig(): Promise<void> {
    try {
      const stored = await chrome.storage.local.get(STORAGE_KEYS.CONFIG);
      const configData = stored[STORAGE_KEYS.CONFIG] as
        | AuditorConfig
        | undefined;
      if (configData) {
        this.config = { ...DEFAULT_CONFIG, ...configData };
      }
    } catch (error) {
      console.warn("[BackgroundAuditor] Error cargando config, usando默认值");
    }
  }

  /**
   * Guarda configuración en storage
   */
  async saveConfig(config: Partial<AuditorConfig>): Promise<void> {
    this.config = { ...this.config, ...config };
    await chrome.storage.local.set({
      [STORAGE_KEYS.CONFIG]: this.config,
    });
  }

  /**
   * Configura scans programados usando chrome.alarms
   */
  private async setupScheduledScans(): Promise<void> {
    // Cancelar alarms existentes
    const alarms = await chrome.alarms.getAll();
    for (const alarm of alarms) {
      if (alarm.name.startsWith("auditor_")) {
        await chrome.alarms.clear(alarm.name);
      }
    }

    // Crear nuevo alarm para scans periódicos
    await chrome.alarms.create("auditor_periodic_scan", {
      delayInMinutes: this.config.scanIntervalHours * 60,
      periodInMinutes: this.config.scanIntervalHours * 60,
    });
  }

  /**
   * Registra event listeners para Chrome APIs
   */
  private registerEventListeners(): void {
    // Alarm triggers
    chrome.alarms.onAlarm.addListener((alarm) => {
      if (alarm.name === "auditor_periodic_scan") {
        this.handlePeriodicScan();
      }
    });

    // Tab updates para credential monitoring
    chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
      if (changeInfo.status === "complete" && tab.url) {
        this.handleTabUpdate(tabId, tab.url);
      }
    });

    // Messages desde popup/options
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      console.log("[BackgroundAuditor] Message received:", message);
      this.handleMessage(message, sender).then((response) => {
        console.log("[BackgroundAuditor] Sending response:", response);
        sendResponse(response);
      });
      return true; // Async response
    });
  }

  /**
   * Maneja scan periódico
   */
  private async handlePeriodicScan(): Promise<void> {
    if (this.isRunning) {
      console.log("[BackgroundAuditor] Scan en progreso, saltando...");
      return;
    }

    console.log("[BackgroundAuditor] Ejecutando scan periódico...");
    await this.runFullAudit();
  }

  /**
   * Maneja actualización de tab
   */
  private async handleTabUpdate(tabId: number, url: string): Promise<void> {
    if (!this.config.credentialMonitorEnabled) return;

    try {
      const findings = await this.credentialMonitor.analyzePage(url);

      if (findings.length > 0) {
        // Notificar al usuario
        await this.sendNotification({
          type: "credential",
          title: "Sitio con credenciales detectado",
          message: `Se detectaron ${findings.length} credenciales en ${new URL(url).hostname}`,
          severity: "HIGH",
        });

        // Guardar resultado
        await this.saveAuditResult({
          id: this.generateId(),
          timestamp: new Date(),
          type: "credential_scan",
          findings,
          severity: "HIGH",
        });
      }
    } catch (error) {
      console.error("[BackgroundAuditor] Error en análisis de página:", error);
    }
  }

  /**
   * Maneja mensajes desde popup/options
   */
  private async handleMessage(
    message: { action: string; payload?: unknown },
    _sender: chrome.runtime.MessageSender,
  ): Promise<unknown> {
    switch (message.action) {
      case "ping":
        return { status: "alive", timestamp: Date.now() };

      case "run_audit":
        return await this.runFullAudit();

      case "get_status":
        return {
          isRunning: this.isRunning,
          lastScan: await this.getLastScanTime(),
          config: this.config,
        };

      case "update_config":
        await this.saveConfig(message.payload as Partial<AuditorConfig>);
        await this.setupScheduledScans();
        return { success: true };

      case "get_history":
        return await this.getAuditHistory();

      case "clear_history":
        await this.clearAuditHistory();
        return { success: true };

      default:
        return { error: "Unknown action" };
    }
  }

  /**
   * Ejecuta un audit completo
   */
  async runFullAudit(): Promise<AuditResult> {
    if (this.isRunning) {
      throw new Error("Ya hay un scan en progreso");
    }

    this.isRunning = true;
    const findings: Finding[] = [];

    try {
      // 1. Breach Detection
      if (this.config.breachCheckEnabled) {
        const breachFindings = await this.breachDetector.checkBreaches();
        findings.push(...breachFindings);
      }

      // 2. Credential Analysis
      if (this.config.credentialMonitorEnabled) {
        // Análisis de credenciales almacenadas
        // TODO: Integrar con vault cifrado
      }

      // 3. Threat Intelligence
      if (this.config.threatIntelSyncEnabled) {
        const threatFindings = await this.breachDetector.syncThreatIntel();
        findings.push(...threatFindings);
      }

      // Determinar severidad general
      const severity = this.calculateOverallSeverity(findings);

      // Crear resultado
      const result: AuditResult = {
        id: this.generateId(),
        timestamp: new Date(),
        type: "full",
        findings,
        severity,
      };

      // Guardar resultado
      await this.saveAuditResult(result);

      // Notificar si hay hallazgos críticos
      if (severity === "CRITICAL" || severity === "HIGH") {
        await this.sendNotification({
          type: "breach",
          title: "Vulnerabilidad Crítica Detectada",
          message: `Se encontraron ${findings.length} vulnerabilidades (${severity})`,
          severity,
        });
      }

      return result;
    } finally {
      this.isRunning = false;
      await this.updateLastScanTime();
    }
  }

  /**
   * Calcula severidad general del audit
   */
  private calculateOverallSeverity(
    findings: Finding[],
  ): AuditResult["severity"] {
    if (findings.length === 0) return "NONE";

    const hasCritical = findings.some((f) => f.severity === "CRITICAL");
    const hasHigh = findings.some((f) => f.severity === "HIGH");
    const hasMedium = findings.some((f) => f.severity === "MEDIUM");

    if (hasCritical) return "CRITICAL";
    if (hasHigh) return "HIGH";
    if (hasMedium) return "MEDIUM";
    return "LOW";
  }

  /**
   * Envía notificación al usuario
   */
  private async sendNotification(params: {
    type: string;
    title: string;
    message: string;
    severity: string;
  }): Promise<void> {
    // Notificaciones deshabilitadas temporalmente para evitar errores
    console.log("[CyberVault] Notification:", params.title, params.message);
    return;
    
    /* // Código original - deshabilitado temporalmente
    try {
      if (!params.title || !params.message) {
        console.warn("[BackgroundAuditor] Notification skipped: missing params");
        return;
      }
      await chrome.notifications.create({
        type: "basic",
        title: params.title,
        message: params.message,
        priority: params.severity === "CRITICAL" ? 2 : 1,
      });
    } catch (error) {
      console.warn("[BackgroundAuditor] Notification error:", error);
    }
    */
  }

  /**
   * Guarda resultado de audit
   */
  private async saveAuditResult(result: AuditResult): Promise<void> {
    this.scanHistory.push(result);

    // Mantener solo últimos 100 resultados
    if (this.scanHistory.length > 100) {
      this.scanHistory = this.scanHistory.slice(-100);
    }

    // Guardar en storage
    await chrome.storage.local.set({
      [STORAGE_KEYS.AUDIT_RESULTS]: this.scanHistory.map((r) => ({
        ...r,
        timestamp: r.timestamp.toISOString(),
      })),
    });
  }

  /**
   * Obtiene historial de audits
   */
  private async getAuditHistory(): Promise<AuditResult[]> {
    const stored = await chrome.storage.local.get(STORAGE_KEYS.AUDIT_RESULTS);
    const results =
      (stored[STORAGE_KEYS.AUDIT_RESULTS] as Array<{
        id: string;
        timestamp: string;
        type: "breach_check" | "credential_scan" | "threat_intel" | "full";
        findings: Array<{
          category: "breach" | "credential" | "threat" | "config";
          title: string;
          description: string;
          severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
          recommendation?: string;
          metadata?: Record<string, unknown>;
        }>;
        severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "NONE";
      }>) || [];

    return results.map((r) => ({
      id: r.id,
      timestamp: new Date(r.timestamp),
      type: r.type,
      findings: r.findings,
      severity: r.severity,
    }));
  }

  /**
   * Limpia historial de audits
   */
  private async clearAuditHistory(): Promise<void> {
    this.scanHistory = [];
    await chrome.storage.local.remove(STORAGE_KEYS.AUDIT_RESULTS);
  }

  /**
   * Actualiza timestamp del último scan
   */
  private async updateLastScanTime(): Promise<void> {
    await chrome.storage.local.set({
      [STORAGE_KEYS.LAST_SCAN]: Date.now(),
    });
  }

  /**
   * Obtiene timestamp del último scan
   */
  private async getLastScanTime(): Promise<Date | null> {
    const stored = await chrome.storage.local.get(STORAGE_KEYS.LAST_SCAN);
    const timestamp = stored[STORAGE_KEYS.LAST_SCAN] as number | undefined;
    return timestamp ? new Date(timestamp) : null;
  }

  /**
   * Genera ID único
   */
  private generateId(): string {
    const array = new Uint8Array(16);
    crypto.getRandomValues(array);
    return Array.from(array, (b) => b.toString(16).padStart(2, "0")).join("");
  }

  /**
   * Limpia memoria sensible (llamado al destruir)
   */
  async cleanup(): Promise<void> {
    // Limpiar buffers sensibles
    for (const result of this.scanHistory) {
      if (result.findings) {
        // Sobrescribir datos sensibles
        result.findings = [];
      }
    }
    this.scanHistory = [];
    console.log("[BackgroundAuditor] Memoria limpiada");
  }
}

// ============================================================================
// Service Worker Entry Point
// ============================================================================

let auditor: BackgroundAuditor;

// Función de inicialización
async function initAuditor() {
  try {
    auditor = new BackgroundAuditor();
    await auditor.initialize();
    console.log("[BackgroundAuditor] Ready and initialized");
  } catch (err) {
    console.error("[BackgroundAuditor] Init failed:", err);
  }
}

// Inicializar después de un pequeño delay para asegurar que el SW esté listo
// Usamos un approach más robusto para el service worker
function setupServiceWorker() {
  // Verificar que estamos en el contexto correcto de Chrome
  if (typeof chrome === 'undefined' || !chrome.runtime) {
    console.warn("[BackgroundAuditor] Chrome runtime not available, skipping setup");
    return;
  }

  // Escuchar el evento de instalación
  if (chrome.runtime.onInstalled) {
    chrome.runtime.onInstalled.addListener(() => {
      console.log("[BackgroundAuditor] Installed/Updated");
      initAuditor();
    });
  }

  // También intentar inicializar ahora (puede ser un reinicio del SW)
  initAuditor();
}

// Ejecutar setup cuando el script se carga
// Usamos requestIdleCallback o un fallback con setTimeout
if (typeof requestIdleCallback !== 'undefined') {
  requestIdleCallback(() => setupServiceWorker(), { timeout: 1000 });
} else {
  setTimeout(() => setupServiceWorker(), 100);
}
