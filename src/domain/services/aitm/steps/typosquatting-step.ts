/**
 * Typosquatting Detection Step — Optimized Levenshtein
 *
 * Detects typosquatting by computing Levenshtein similarity between the
 * registrable domain portions of the current and expected hostnames.
 * Common TLDs are stripped before comparison so that different TLDs
 * (e.g., .com vs .org) do not inflate the distance.
 *
 * @module domain/services/aitm/steps/typosquatting-step
 */

import { levenshteinSimilarity } from "../../../utils/levenshtein";
import { dnsNormalize } from "../../../utils/dns-normalize";
import type {
  IDomainValidationStep,
  DomainValidationResult,
} from "../domain-validation-pipeline";

/** Common TLDs stripped before comparison */
const COMMON_TLDS = [
  ".com",
  ".org",
  ".net",
  ".edu",
  ".gov",
  ".co",
  ".io",
  ".info",
  ".biz",
  ".xyz",
];

/**
 * Strip common TLDs from a hostname to extract the registrable domain.
 */
function stripTld(hostname: string): string {
  let normalized = dnsNormalize(hostname);
  for (const tld of COMMON_TLDS) {
    if (normalized.endsWith(tld)) {
      normalized = normalized.slice(0, -tld.length);
      break;
    }
  }
  return normalized;
}

/**
 * Extract the registrable domain (last two labels before the TLD).
 * For "mail.google.com" → "google"
 * For "google.com" → "google"
 * For "a.b.c.google.com" → "google"
 */
function extractRegistrableDomain(hostname: string): string {
  const normalized = dnsNormalize(hostname);

  // Strip TLD from the full hostname
  const withoutTld = stripTld(hostname);
  const registrableLabels = withoutTld.split(".");

  // Return the last label (the domain name proper)
  return registrableLabels[registrableLabels.length - 1] || normalized;
}

export class TyposquattingStep implements IDomainValidationStep {
  readonly name = "LevenshteinTypoSquatting";
  private readonly threshold: number;

  constructor(threshold: number = 0.85) {
    this.threshold = threshold;
  }

  async execute(
    hostname: string,
    expectedDomain: string,
  ): Promise<DomainValidationResult> {
    const currentRegistrable = extractRegistrableDomain(hostname);
    const expectedRegistrable = extractRegistrableDomain(expectedDomain);

    // Exact match on registrable domain
    if (currentRegistrable === expectedRegistrable) {
      return {
        isValid: true,
        strategy: this.name,
        riskLevel: "low",
        confidence: 1.0,
        reason: `Registrable domain "${currentRegistrable}" exactly matches "${expectedRegistrable}"`,
        distance: 0,
      };
    }

    const similarity = levenshteinSimilarity(
      currentRegistrable,
      expectedRegistrable,
    );
    const distance =
      currentRegistrable.length > 0 && expectedRegistrable.length > 0
        ? Math.round((1 - similarity) * Math.max(currentRegistrable.length, expectedRegistrable.length))
        : 0;

    if (similarity >= this.threshold) {
      return {
        isValid: false,
        strategy: this.name,
        riskLevel: "high",
        confidence: similarity,
        reason: `Registrable domain "${currentRegistrable}" is similar to "${expectedRegistrable}" (similarity: ${similarity.toFixed(3)}, threshold: ${this.threshold})`,
        distance,
      };
    }

    return {
      isValid: true,
      strategy: this.name,
      riskLevel: "low",
      confidence: similarity,
      reason: `Registrable domain "${currentRegistrable}" is sufficiently different from "${expectedRegistrable}" (similarity: ${similarity.toFixed(3)})`,
      distance,
    };
  }
}
