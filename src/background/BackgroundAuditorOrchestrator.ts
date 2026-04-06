/**
 * BackgroundAuditorOrchestrator
 * Centraliza orquestación de auditorías de seguridad en background
 */

import { AuditorConfig, AuditResult, Finding, SeverityLevel } from "./models";
import { StorageService } from "./services/StorageService";
import { NotificationService } from "./services/NotificationService";
import { ScanScheduler } from "./services/ScanScheduler";
import { BreachScanner } from "./scanners/BreachScanner";
import { CredentialScanner } from "./scanners/CredentialScanner";
import { ThreatIntelScanner } from "./scanners/ThreatIntelScanner";

export class BackgroundAuditorOrchestrator {
  private isRunning = false;
  private config: AuditorConfig;
  private lastScanTime: Date | null = null;
  private scanHistory: AuditResult[] = [];
  private scanScheduler?: ScanScheduler;

  // Dependencias inyectadas
  private readonly storageService: StorageService;
  private readonly notificationService: NotificationService;
  private readonly breachScanner: BreachScanner;
  private readonly credentialScanner: CredentialScanner;
  private readonly threatIntelScanner: ThreatIntelScanner;

  constructor(
    storageService: StorageService,
    notificationService: NotificationService,
    breachScanner: BreachScanner,
    credentialScanner: CredentialScanner,
    threatIntelScanner: ThreatIntelScanner,
    config: AuditorConfig,
  ) {
    this.storageService = storageService;
    this.notificationService = notificationService;
    this.breachScanner = breachScanner;
    this.credentialScanner = credentialScanner;
    this.threatIntelScanner = threatIntelScanner;
    this.config = config;
  }

  setScanScheduler(scheduler: ScanScheduler): void {
    this.scanScheduler = scheduler;
  }

  /**
   * Inicializa el orchestrator
   */
  async initialize(): Promise<void> {
    console.log("[BackgroundAuditorOrchestrator] Inicializando...");

    // Cargar configuración desde storage
    this.config = await this.storageService.loadConfig();

    // Programar scans periódicos
    if (!this.scanScheduler) {
      throw new Error("ScanScheduler no ha sido inyectado");
    }
    await this.scanScheduler.schedule(this.config.scanIntervalHours);

    // Cargar historial persistente
    this.scanHistory = await this.storageService.getAuditHistory();

    console.log("[BackgroundAuditorOrchestrator] Inicialización completa");
  }

  /**
   * Ejecuta un audit completo
   */
  async runFullAudit(): Promise<AuditResult> {
    if (this.isRunning) {
      return Promise.reject(new Error("Ya hay un scan en progreso"));
    }

    this.isRunning = true;

    try {
      const result = await this.performAudit();
      return result;
    } finally {
      this.isRunning = false;
    }
  }

  /**
   * Ejecuta la auditoría interna
   */
  private async performAudit(): Promise<AuditResult> {
    const allFindings: Finding[] = [];

    // 1. Breach Scanner
    if (this.config.breachCheckEnabled) {
      const breachFindings = await this.breachScanner.scan();
      allFindings.push(...breachFindings);
    }

    // 2. Credential Scanner (monitoreo de dominios)
    if (this.config.credentialMonitorEnabled) {
      const credentialFindings =
        await this.credentialScanner.scanMonitoredDomains();
      allFindings.push(...credentialFindings);
    }

    // 3. Threat Intelligence Scanner
    if (this.config.threatIntelSyncEnabled) {
      const threatFindings = await this.threatIntelScanner.scan();
      allFindings.push(...threatFindings);
    }

    // Calcular severidad global
    const severity = this.calculateOverallSeverity(allFindings);

    // Crear resultado
    const auditResult: AuditResult = {
      id: crypto.randomUUID(),
      timestamp: new Date(),
      type: "full",
      findings: allFindings,
      severity,
    };

    // Guardar en storage
    await this.storageService.saveAuditResult(auditResult);
    this.scanHistory.push(auditResult);

    // Mantener límite de historial
    if (this.scanHistory.length > 100) {
      this.scanHistory = this.scanHistory.slice(-100);
    }

    // Actualizar último scan
    this.lastScanTime = new Date();
    await this.storageService.setLastScanTime(this.lastScanTime.getTime());

    // Notificar si severidad es crítica o alta
    if (severity === "CRITICAL" || severity === "HIGH") {
      await this.notificationService.send({
        type: "breach",
        title: "Vulnerabilidad Crítica Detectada",
        message: `Se encontraron ${allFindings.length} vulnerabilidades (${severity})`,
        severity,
      });
    }

    return auditResult;
  }

  /**
   * Calcula severidad global basada en hallazgos
   */
  private calculateOverallSeverity(
    findings: Finding[],
  ): SeverityLevel | "NONE" {
    if (findings.length === 0) return "NONE";

    if (findings.some((f) => f.severity === "CRITICAL")) return "CRITICAL";
    if (findings.some((f) => f.severity === "HIGH")) return "HIGH";
    if (findings.some((f) => f.severity === "MEDIUM")) return "MEDIUM";
    if (findings.some((f) => f.severity === "LOW")) return "LOW";

    return "NONE";
  }

  /**
   * Obtiene estado actual del auditor
   */
  async getStatus(): Promise<{
    isRunning: boolean;
    lastScan: Date | null;
    nextScan: Date | null;
  }> {
    const nextScan = this.scanScheduler
      ? await this.scanScheduler.getNextScan()
      : null;
    return {
      isRunning: this.isRunning,
      lastScan: this.lastScanTime,
      nextScan,
    };
  }

  /**
   * Obtiene historial de auditorías
   */
  async getHistory(): Promise<AuditResult[]> {
    return [...this.scanHistory];
  }

  /**
   * Limpia historial de auditorías
   */
  async clearHistory(): Promise<void> {
    this.scanHistory = [];
    await this.storageService.clearAuditHistory();
  }

  /**
   * Actualiza configuración del auditor
   */
  async updateConfig(newConfig: Partial<AuditorConfig>): Promise<void> {
    const oldConfig = { ...this.config };
    this.config = { ...this.config, ...newConfig };

    await this.storageService.saveConfig(this.config);

    // Rescheduling si cambió intervalo
    if (newConfig.scanIntervalHours !== undefined) {
      if (!this.scanScheduler) {
        throw new Error("ScanScheduler no inyectado");
      }
      await this.scanScheduler.rescheduleAfterConfigChange(
        this.config.scanIntervalHours,
        oldConfig.scanIntervalHours,
      );
    }
  }

  /**
   * Maneja hallazgos desde TabService
   */
  async handleTabFindings(findings: Finding[]): Promise<void> {
    const severity = this.calculateOverallSeverity(findings);

    // Notificar si severidad >= HIGH
    if (severity === "CRITICAL" || severity === "HIGH") {
      await this.notificationService.send({
        type: "credential",
        title: "Sitio con credenciales detectado",
        message: `Se detectaron ${findings.length} hallazgos en la pestaña actual`,
        severity,
      });
    }

    // Guardar en historial como tipo credential_scan
    const result: AuditResult = {
      id: crypto.randomUUID(),
      timestamp: new Date(),
      type: "credential_scan",
      findings,
      severity,
    };

    await this.storageService.saveAuditResult(result);
    this.scanHistory.push(result);

    if (this.scanHistory.length > 100) {
      this.scanHistory = this.scanHistory.slice(-100);
    }
  }
}
