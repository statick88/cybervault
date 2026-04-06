/**
 * Modelos de datos para el sistema de auditoría
 * Contiene las interfaces y tipos utilizados por el Background Auditor
 */

/**
 * Configuración del Background Auditor
 */
export interface AuditorConfig {
  scanIntervalHours: number;
  breachCheckEnabled: boolean;
  credentialMonitorEnabled: boolean;
  threatIntelSyncEnabled: boolean;
}

/**
 * Categorías de hallazgos de auditoría
 */
export type FindingCategory = "breach" | "credential" | "threat" | "config";

/**
 * Niveles de severidad
 */
export type SeverityLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

/**
 * Tipo de scan de auditoría
 */
export type AuditType =
  | "breach_check"
  | "credential_scan"
  | "threat_intel"
  | "full";

/**
 * Hallazgo individual en una auditoría
 */
export interface Finding {
  category: FindingCategory;
  title: string;
  description: string;
  severity: SeverityLevel;
  recommendation?: string;
  metadata?: Record<string, unknown>;
}

/**
 * Resultado completo de una auditoría
 */
export interface AuditResult {
  id: string;
  timestamp: Date;
  type: AuditType;
  findings: Finding[];
  severity: SeverityLevel | "NONE";
}
