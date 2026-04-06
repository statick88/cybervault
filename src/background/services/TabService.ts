/**
 * Tab Service
 * Monitorea cambios en pestañas y delega análisis de credenciales
 */

import type { Finding } from "../models";
import { CredentialScanner } from "../scanners/CredentialScanner";

export class TabService {
  private listener!: (
    tabId: number,
    changeInfo: any,
    tab: chrome.tabs.Tab,
  ) => void;

  constructor(
    private onTabFindings: (findings: Finding[]) => Promise<void>,
    private credentialScanner: CredentialScanner,
  ) {
    this.setupListener();
  }

  private setupListener(): void {
    this.listener = async (
      _tabId: number,
      changeInfo: any,
      tab: chrome.tabs.Tab,
    ) => {
      if (changeInfo.status === "complete" && tab.url && tab.id) {
        await this.handleTabUpdate(tab.url);
      }
    };

    chrome.tabs.onUpdated.addListener(this.listener);
  }

  private async handleTabUpdate(url: string): Promise<void> {
    try {
      const findings = await this.credentialScanner.analyzeUrl(url);
      if (findings.length > 0) {
        await this.onTabFindings(findings as Finding[]);
      }
    } catch (error) {
      console.error("[TabService] Error analyzing tab:", error);
    }
  }

  destroy(): void {
    if (this.listener) {
      chrome.tabs.onUpdated.removeListener(this.listener);
    }
  }
}
