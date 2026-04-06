/**
 * Breach Scanner
 * Escanea breaches de datos using BreachDetector
 */

import { BreachDetector } from "../breach-detector";
import { BreachFinding } from "../breach-detector";

export class BreachScanner {
  constructor(private breachDetector: BreachDetector) {}

  async scan(): Promise<BreachFinding[]> {
    return await this.breachDetector.checkBreaches();
  }

  async syncThreatIntel(): Promise<BreachFinding[]> {
    return await this.breachDetector.syncThreatIntel();
  }
}
