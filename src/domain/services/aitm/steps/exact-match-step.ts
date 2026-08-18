/**
 * Exact Match Step — RFC 1035 Domain Validation
 *
 * Validates whether the current hostname is an exact match or a valid
 * subdomain of the expected domain. Uses dnsNormalize() for RFC 1035
 * compliance (case folding, trailing dot removal).
 *
 * @module domain/services/aitm/steps/exact-match-step
 */

import { dnsNormalize } from "../../../utils/dns-normalize";
import type {
  IDomainValidationStep,
  DomainValidationResult,
} from "../domain-validation-pipeline";

export class ExactMatchStep implements IDomainValidationStep {
  readonly name = "ExactMatch";

  async execute(
    hostname: string,
    expectedDomain: string,
  ): Promise<DomainValidationResult> {
    const normalizedHost = dnsNormalize(hostname);
    const normalizedExpected = dnsNormalize(expectedDomain);

    // Exact match after normalization
    if (normalizedHost === normalizedExpected) {
      return {
        isValid: true,
        strategy: this.name,
        riskLevel: "low",
        confidence: 1.0,
        reason: `Hostname "${normalizedHost}" exactly matches expected domain "${normalizedExpected}"`,
      };
    }

    // Subdomain check: hostname ends with .expectedDomain
    const subdomainSuffix = `.${normalizedExpected}`;
    if (normalizedHost.endsWith(subdomainSuffix)) {
      return {
        isValid: true,
        strategy: this.name,
        riskLevel: "low",
        confidence: 1.0,
        reason: `Hostname "${normalizedHost}" is a valid subdomain of "${normalizedExpected}"`,
      };
    }

    // No match
    return {
      isValid: false,
      strategy: this.name,
      riskLevel: "high",
      confidence: 1.0,
      reason: `Hostname "${normalizedHost}" does not match expected domain "${normalizedExpected}" and is not a valid subdomain`,
    };
  }
}
