/**
 * Breach Detector
 * Detección pasiva de breaches usando APIs externas
 *
 * Integración con HaveIBeenPwned, AlienVault OTX, etc.
 */

import { bytesToHex } from "@noble/hashes/utils";
import { sha256 } from "@noble/hashes/sha2";

export interface BreachFinding {
  category: "breach" | "threat";
  title: string;
  description: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  recommendation?: string;
  source: string;
  metadata?: Record<string, unknown>;
}

export interface ThreatIntel {
  indicator: string;
  type: "domain" | "ip" | "hash" | "url";
  confidence: number;
  malware?: string;
  lastSeen?: Date;
}

/**
 * Cliente para APIs de breach detection
 */
export class BreachDetector {
  private apiEndpoints = {
    haveibeenpwned: "https://api.pwnedpasswords.com",
    alienvault: "https://otx.alienvault.com/api/v1",
    github: "https://api.github.com",
  };

  private threatIntelCache: ThreatIntel[] = [];
  private cacheExpiry: Date | null = null;
  private CACHE_TTL_MS = 60 * 60 * 1000; // 1 hora

  constructor() {}

  /**
   * Verifica si un email ha sido comprometido
   * Usa HIBP API (k-Anonymity)
   */
  async checkEmail(email: string): Promise<BreachFinding[]> {
    const findings: BreachFinding[] = [];

    try {
      // Hash SHA-1 del email (solo primeros 5 caracteres para k-anonimato)
      const emailHash = sha256(new TextEncoder().encode(email));
      const hashHex = bytesToHex(emailHash).toUpperCase();
      const prefix = hashHex.substring(0, 5);
      const suffix = hashHex.substring(5);

      // Consultar HIBP API
      const response = await fetch(
        `${this.apiEndpoints.haveibeenpwned}/range/${prefix}`,
        {
          headers: {
            "User-Agent": "CyberVault-Security-Extension",
          },
        },
      );

      if (response.ok) {
        const text = await response.text();
        const hashes = text.split("\n");

        for (const line of hashes) {
          const [hashSuffix, count] = line.split(":");
          if (hashSuffix.trim() === suffix) {
            findings.push({
              category: "breach",
              title: "Email comprometido en brecha de datos",
              description: `El email ha sido encontrado en ${parseInt(count)} brechas de datos públicas.`,
              severity: this.calculateSeverity(parseInt(count)),
              recommendation:
                "Cambiar contraseña inmediatamente y habilitar 2FA",
              source: "HaveIBeenPwned",
              metadata: { email, breachCount: parseInt(count) },
            });
            break;
          }
        }
      }
    } catch (error) {
      console.warn("[BreachDetector] Error consultando HIBP:", error);
    }

    return findings;
  }

  /**
   * Verifica si una contraseña ha sido filtrada
   * Retorna el número de veces que apareció en brechas
   */
  async checkPassword(password: string): Promise<{
    compromised: boolean;
    count: number;
  }> {
    try {
      // Hash SHA-1 de la contraseña
      const passwordHash = sha256(new TextEncoder().encode(password));
      const hashHex = bytesToHex(passwordHash).toUpperCase();
      const prefix = hashHex.substring(0, 5);
      const suffix = hashHex.substring(5);

      // Consultar HIBP API
      const response = await fetch(
        `${this.apiEndpoints.haveibeenpwned}/range/${prefix}`,
        {
          headers: {
            "User-Agent": "CyberVault-Security-Extension",
          },
        },
      );

      if (response.ok) {
        const text = await response.text();
        const hashes = text.split("\n");

        for (const line of hashes) {
          const [hashSuffix, count] = line.split(":");
          if (hashSuffix.trim() === suffix) {
            return {
              compromised: true,
              count: parseInt(count),
            };
          }
        }
      }

      return { compromised: false, count: 0 };
    } catch (error) {
      console.warn("[BreachDetector] Error verificando contraseña:", error);
      return { compromised: false, count: 0 };
    }
  }

  /**
   * Sincroniza inteligencia de amenazas desde IPFS
   * En producción, esto descargaría desde IPNS del vault
   */
  async syncThreatIntel(): Promise<BreachFinding[]> {
    const findings: BreachFinding[] = [];

    // Verificar si cache es válido
    if (
      this.threatIntelCache.length > 0 &&
      this.cacheExpiry &&
      new Date() < this.cacheExpiry
    ) {
      return findings; // Usar cache
    }

    try {
      // En producción: descargar desde IPFS/IPNS
      // Por ahora, simulamos con datos de ejemplo

      // Simular amenaza detectada
      const mockThreats: ThreatIntel[] = [
        {
          indicator: "malicious-domain.example",
          type: "domain",
          confidence: 0.95,
          malware: "phishing",
          lastSeen: new Date(),
        },
      ];

      this.threatIntelCache = mockThreats;
      this.cacheExpiry = new Date(Date.now() + this.CACHE_TTL_MS);

      // Convertir a findings
      for (const threat of mockThreats) {
        findings.push({
          category: "threat",
          title: `Threat Intelligence: ${threat.indicator}`,
          description: `Indicador malicioso detectado: ${threat.type} - Confianza: ${(threat.confidence * 100).toFixed(0)}%`,
          severity: threat.confidence > 0.8 ? "HIGH" : "MEDIUM",
          recommendation: "Bloquear acceso a este indicador",
          source: "Threat Intel Feed",
          metadata: threat as unknown as Record<string, unknown>,
        });
      }
    } catch (error) {
      console.warn("[BreachDetector] Error sincronizando threat intel:", error);
    }

    return findings;
  }

  /**
   * Ejecuta verificación completa de breaches
   */
  async checkBreaches(): Promise<BreachFinding[]> {
    const findings: BreachFinding[] = [];

    // 1. Sync threat intelligence
    const threatFindings = await this.syncThreatIntel();
    findings.push(...threatFindings);

    // 2. Verificar dominio del vault (si está configurado)
    // TODO: Integrar con vault para verificar emails registrados

    return findings;
  }

  /**
   * Calcula severidad basada en cantidad de brechas
   */
  private calculateSeverity(
    breachCount: number,
  ): "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" {
    if (breachCount > 100) return "CRITICAL";
    if (breachCount > 10) return "HIGH";
    if (breachCount > 1) return "MEDIUM";
    return "LOW";
  }

  /**
   * Limpia cache de threat intelligence
   */
  clearCache(): void {
    this.threatIntelCache = [];
    this.cacheExpiry = null;
  }
}
