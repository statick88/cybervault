/**
 * Exact Match Step — Absolute Origin Validation
 *
 * Delegates the actual "is this the same origin?" decision to the single
 * canonical authority in `domain/services/autofill/origin.ts`.
 *
 * WHY DELEGATION MATTERS HERE
 * ---------------------------
 * This step and the autofill guard both decide whether a credential may be
 * shown to a page. If they each carried their own notion of origin equality
 * they would eventually disagree, and the disagreement would be a security bug
 * in whichever copy was more permissive. There is now exactly one definition.
 *
 * This step's remaining job is to express the verdict in AiTM pipeline terms
 * (risk level, confidence, human-readable reason) and to keep the similarity
 * signals separate — confusable and typosquatting detection are WARNING-ONLY
 * and can never authorize a release.
 *
 * @module domain/services/aitm/steps/exact-match-step
 */

import { compareAbsoluteOrigins } from "../../autofill/origin";
import type {
  IDomainValidationStep,
  DomainValidationResult,
} from "../domain-validation-pipeline";

export class ExactMatchStep implements IDomainValidationStep {
  readonly name = "ExactMatch";

  async execute(
    currentOrigin: string,
    expectedOrigin: string,
  ): Promise<DomainValidationResult> {
    const comparison = compareAbsoluteOrigins(expectedOrigin, currentOrigin);

    if (comparison.equal) {
      return {
        isValid: true,
        strategy: this.name,
        riskLevel: "low",
        confidence: 1.0,
        reason: `Origin "${currentOrigin}" exactly matches expected origin "${expectedOrigin}"`,
      };
    }

    return {
      isValid: false,
      strategy: this.name,
      riskLevel: "high",
      confidence: 1.0,
      reason: `Origin "${currentOrigin}" does NOT exactly match expected "${expectedOrigin}" — ${comparison.reason}`,
      metadata: {
        expected: comparison.expected?.serialized ?? null,
        actual: comparison.actual?.serialized ?? null,
      },
    };
  }
}
