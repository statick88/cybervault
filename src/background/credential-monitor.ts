/**
 * Credential Monitor
 * Monitoreo de credenciales en páginas web visitadas
 *
 * Detecta cuando el usuario visita sitios donde tiene credenciales almacenadas
 * y analiza la seguridad de las credenciales.
 */

import { bytesToHex } from "@noble/hashes/utils";
import { sha256 } from "@noble/hashes/sha2";

export interface CredentialFinding {
  category: "credential";
  title: string;
  description: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  recommendation?: string;
  metadata?: Record<string, unknown>;
}

export interface CredentialMatch {
  domain: string;
  username: string;
  hasPassword: boolean;
  lastUsed?: Date;
}

/**
 * Monitorea credenciales en sitios web
 */
export class CredentialMonitor {
  private monitoredDomains: Map<string, string> = new Map(); // domain -> encrypted credential ref

  constructor() {}

  /**
   * Añade un dominio al monitoreo
   */
  async addMonitoredDomain(
    domain: string,
    credentialRef: string,
  ): Promise<void> {
    this.monitoredDomains.set(domain.toLowerCase(), credentialRef);
  }

  /**
   * Remueve un dominio del monitoreo
   */
  async removeMonitoredDomain(domain: string): Promise<void> {
    this.monitoredDomains.delete(domain.toLowerCase());
  }

  /**
   * Analiza una página web para detectar credenciales
   */
  async analyzePage(url: string): Promise<CredentialFinding[]> {
    const findings: CredentialFinding[] = [];

    try {
      const urlObj = new URL(url);
      const domain = urlObj.hostname.toLowerCase();

      // Verificar si es un dominio monitoreado
      if (this.monitoredDomains.has(domain)) {
        findings.push({
          category: "credential",
          title: "Sitio con credenciales guardadas",
          description: `El dominio ${domain} tiene credenciales almacenadas en el vault.`,
          severity: "MEDIUM",
          recommendation:
            "Verificar que la sesión sea segura antes de autofill",
          metadata: {
            domain,
            credentialRef: this.monitoredDomains.get(domain),
          },
        });
      }

      // Análisis de seguridad del sitio
      const securityFindings = await this.analyzePageSecurity(urlObj);
      findings.push(...securityFindings);
    } catch (error) {
      console.warn("[CredentialMonitor] Error analizando página:", error);
    }

    return findings;
  }

  /**
   * Analiza la seguridad de una página
   */
  private async analyzePageSecurity(url: URL): Promise<CredentialFinding[]> {
    const findings: CredentialFinding[] = [];

    // 1. Verificar HTTPS
    if (url.protocol !== "https:") {
      findings.push({
        category: "credential",
        title: "Conexión no segura",
        description: `El sitio ${url.hostname} no usa HTTPS. Las credenciales podrían ser interceptadas.`,
        severity: "HIGH",
        recommendation: "No introducir credenciales en sitios sin HTTPS",
        metadata: { domain: url.hostname, protocol: url.protocol },
      });
    }

    // 2. Verificar elementos sensibles en la página (mediante content script)
    // Esto se ejecutaría en el contexto de la página, no aquí
    // El background solo coordina

    // 3. Verificar login forms conocidos
    // Similar al punto anterior

    return findings;
  }

  /**
   * Escanea todas las credenciales almacenadas
   */
  async scanAllCredentials(
    credentials: Array<{ domain: string; username: string }>,
  ): Promise<CredentialFinding[]> {
    const findings: CredentialFinding[] = [];

    for (const cred of credentials) {
      // Verificar si el sitio sigue siendo seguro
      try {
        await fetch(`https://${cred.domain}`, {
          method: "HEAD",
          mode: "no-cors",
        });

        // Si no podemos verificar, advertimos
        findings.push({
          category: "credential",
          title: `Credencial para ${cred.domain}`,
          description: `Sitio ${cred.domain} - última verificación: ${new Date().toISOString()}`,
          severity: "LOW",
          recommendation:
            "Verificar manualmente que el sitio siga siendo legítimo",
          metadata: { domain: cred.domain, username: cred.username },
        });
      } catch (error) {
        findings.push({
          category: "credential",
          title: `Error verificando ${cred.domain}`,
          description: `No se pudo verificar el estado de seguridad de ${cred.domain}`,
          severity: "MEDIUM",
          recommendation: "Verificar manualmente el sitio",
          metadata: { domain: cred.domain, error: String(error) },
        });
      }
    }

    return findings;
  }

  /**
   * Genera hash de credencial para matching
   */
  hashCredential(domain: string, username: string): string {
    const input = `${domain.toLowerCase()}:${username.toLowerCase()}`;
    const hash = sha256(new TextEncoder().encode(input));
    return bytesToHex(hash);
  }

  /**
   * Obtiene lista de dominios monitoreados
   */
  getMonitoredDomains(): string[] {
    return Array.from(this.monitoredDomains.keys());
  }
}
