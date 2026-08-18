/**
 * Confusable Detection Step — Unicode TR39 Homograph Detection
 *
 * Detects internationalized domain name (IDN) homograph attacks by scanning
 * for characters from non-Latin scripts that visually resemble Latin characters.
 * Implements Unicode TR39 confusable detection with support for Cyrillic,
 * Arabic, Greek, Latin Extended, and Fullwidth scripts.
 *
 * @module domain/services/aitm/steps/confusable-detection-step
 */

import {
  detectConfusables,
  stripZeroWidth,
} from "../../../utils/unicode-confusables";
import type {
  IDomainValidationStep,
  DomainValidationResult,
} from "../domain-validation-pipeline";

export class ConfusableDetectionStep implements IDomainValidationStep {
  readonly name = "ConfusableDetection";

  async execute(
    hostname: string,
    _expectedDomain: string,
  ): Promise<DomainValidationResult> {
    const cleanHost = stripZeroWidth(hostname);
    const evidence = detectConfusables(cleanHost);

    if (evidence.length === 0) {
      return {
        isValid: true,
        strategy: this.name,
        riskLevel: "low",
        confidence: 1.0,
        reason: `No confusable characters detected in "${cleanHost}"`,
        evidence: [],
      };
    }

    // Determine the highest-risk script detected
    const scripts = [...new Set(evidence.map((e) => e.script))];
    const isHighRisk =
      scripts.includes("Cyrillic") ||
      scripts.includes("Arabic") ||
      scripts.includes("Fullwidth");

    const riskLevel: "low" | "medium" | "high" = isHighRisk ? "high" : "medium";

    return {
      isValid: false,
      strategy: this.name,
      riskLevel,
      confidence: 0.95,
      reason: `Detected ${evidence.length} confusable character(s) from scripts: ${scripts.join(", ")}`,
      evidence: evidence as unknown[],
    };
  }
}
