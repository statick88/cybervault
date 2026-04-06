/**
 * Credential Scanner
 * Escanea credenciales usando CredentialMonitor
 */

import { CredentialMonitor } from "../credential-monitor";
import { CredentialFinding } from "../credential-monitor";

export class CredentialScanner {
  constructor(private credentialMonitor: CredentialMonitor) {}

  async analyzeUrl(url: string): Promise<CredentialFinding[]> {
    return await this.credentialMonitor.analyzePage(url);
  }

  async scanMonitoredDomains(): Promise<CredentialFinding[]> {
    const domains = this.credentialMonitor.getMonitoredDomains();
    const allFindings: CredentialFinding[] = [];

    for (const domain of domains) {
      const findings = await this.credentialMonitor.analyzePage(
        `https://${domain}`,
      );
      allFindings.push(...findings);
    }

    return allFindings;
  }

  addMonitoredDomain(domain: string, credentialRef: string): Promise<void> {
    return this.credentialMonitor.addMonitoredDomain(domain, credentialRef);
  }

  removeMonitoredDomain(domain: string): Promise<void> {
    return this.credentialMonitor.removeMonitoredDomain(domain);
  }
}
