/**
 * Threat Intelligence Scanner
 * Escanea threat intelligence using BreachDetector
 */

import { BreachDetector } from "../breach-detector";
import { BreachFinding } from "../breach-detector";

export class ThreatIntelScanner {
  constructor(private breachDetector: BreachDetector) {}

  async scan(): Promise<BreachFinding[]> {
    return await this.breachDetector.syncThreatIntel();
  }
}
