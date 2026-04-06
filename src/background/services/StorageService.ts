import {
  AuditorConfig,
  AuditResult,
  Finding,
  AuditType,
  SeverityLevel,
} from "../models";

/**
 * Servicio de almacenamiento para el Background Auditor
 * Encapsula todo acceso a chrome.storage.local
 */
export class StorageService {
  // KEYS privadas
  private readonly KEYS = {
    CONFIG: "auditor_config",
    LAST_SCAN: "last_audit_timestamp",
    AUDIT_RESULTS: "audit_results",
  } as const;

  // Config por defecto
  private readonly DEFAULT_CONFIG: AuditorConfig = {
    scanIntervalHours: 24,
    breachCheckEnabled: true,
    credentialMonitorEnabled: true,
    threatIntelSyncEnabled: false,
  };

  // Config
  async loadConfig(): Promise<AuditorConfig> {
    const result = await chrome.storage.local.get([this.KEYS.CONFIG]);
    const config = result[this.KEYS.CONFIG] as AuditorConfig | undefined;
    return config || { ...this.DEFAULT_CONFIG };
  }

  async saveConfig(config: AuditorConfig): Promise<void> {
    await chrome.storage.local.set({ [this.KEYS.CONFIG]: config });
  }

  // Audit results
  async saveAuditResult(result: {
    id: string;
    timestamp: Date;
    type: AuditType;
    findings: Finding[];
    severity: SeverityLevel | "NONE";
  }): Promise<void> {
    const serialized = this.serializeAuditResult(result);

    const current = await this.getAuditHistoryRaw();
    const updated = [serialized, ...current].slice(0, 100);

    await chrome.storage.local.set({ [this.KEYS.AUDIT_RESULTS]: updated });
  }

  async getAuditHistory(): Promise<AuditResult[]> {
    const raw = await this.getAuditHistoryRaw();
    return raw
      .map((item) => this.deserializeAuditResult(item))
      .filter((item): item is AuditResult => item !== null)
      .sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
  }

  async clearAuditHistory(): Promise<void> {
    await chrome.storage.local.set({ [this.KEYS.AUDIT_RESULTS]: [] });
  }

  // Timestamps
  async setLastScanTime(timestamp: number): Promise<void> {
    await chrome.storage.local.set({ [this.KEYS.LAST_SCAN]: timestamp });
  }

  async getLastScanTime(): Promise<Date | null> {
    const result = await chrome.storage.local.get([this.KEYS.LAST_SCAN]);
    const time = result[this.KEYS.LAST_SCAN] as number | undefined;
    return time ? new Date(time) : null;
  }

  private async getAuditHistoryRaw(): Promise<unknown[]> {
    const result = await chrome.storage.local.get([this.KEYS.AUDIT_RESULTS]);
    const data = result[this.KEYS.AUDIT_RESULTS] as unknown[] | undefined;
    return data || [];
  }

  private serializeAuditResult(result: {
    id: string;
    timestamp: Date;
    type: AuditType;
    findings: Finding[];
    severity: SeverityLevel | "NONE";
  }): object {
    return {
      id: result.id,
      timestamp: result.timestamp.toISOString(),
      type: result.type,
      findings: result.findings,
      severity: result.severity,
    };
  }

  private deserializeAuditResult(data: unknown): AuditResult | null {
    try {
      const { id, timestamp, type, findings, severity } = data as {
        id: string;
        timestamp: string;
        type: AuditType;
        findings: Finding[];
        severity: SeverityLevel | "NONE";
      };

      const date = new Date(timestamp);
      if (isNaN(date.getTime())) {
        return null;
      }

      return {
        id,
        timestamp: date,
        type,
        findings,
        severity,
      };
    } catch {
      return null;
    }
  }
}
