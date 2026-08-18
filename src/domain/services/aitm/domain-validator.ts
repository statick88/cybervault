/**
 * Domain Validator — Validación avanzada de dominios
 *
 * Extiende la validación básica de dominios con:
 * - Detección de typosquatting (Levenshtein)
 * - Detección de homograph attacks (Unicode confusables)
 * - Normalización IDNA/Punycode
 * - Validación de subdominios
 */

import { levenshteinSimilarity } from "../../utils/levenshtein";

const CONFUSABLE_PATTERN = new RegExp(
  `[${String.fromCharCode(0x0400)}-${String.fromCharCode(0x04ff)}\u0261\u0280\u1D07\u1D04\u1D05\u1D1C]`
);

export class DomainValidator {
  /**
   * Valida si un hostname corresponde a un dominio esperado
   */
  validate(hostname: string, expectedDomain: string): {
    isValid: boolean;
    riskLevel: 'low' | 'medium' | 'high';
    reason: string;
  } {
    const normalizedHost = hostname.toLowerCase().trim();
    const normalizedExpected = expectedDomain.toLowerCase().trim();

    // Exact match
    if (normalizedHost === normalizedExpected) {
      return { isValid: true, riskLevel: 'low', reason: 'Exact match' };
    }

    // Subdomain match
    if (normalizedHost.endsWith(`.${normalizedExpected}`)) {
      return { isValid: true, riskLevel: 'low', reason: 'Valid subdomain' };
    }

    // Confusable detection
    if (this.hasConfusableCharacters(normalizedHost)) {
      return {
        isValid: false,
        riskLevel: 'high',
        reason: 'Confusable characters detected',
      };
    }

    // Typosquatting check
    const similarity = this.calculateSimilarity(
      normalizedHost,
      normalizedExpected
    );
    if (similarity >= 0.85) {
      return {
        isValid: false,
        riskLevel: 'high',
        reason: `Possible typosquatting (similarity: ${(similarity * 100).toFixed(1)}%)`,
      };
    }

    return {
      isValid: false,
      riskLevel: 'high',
      reason: 'Domain mismatch',
    };
  }

  /**
   * Detecta caracteres confusables (homograph attacks)
   */
  hasConfusableCharacters(hostname: string): boolean {
    return CONFUSABLE_PATTERN.test(hostname);
  }

  /**
   * Calcula similitud entre dominios (Levenshtein normalized)
   */
  calculateSimilarity(a: string, b: string): number {
    return levenshteinSimilarity(a, b);
  }

  /**
   * Normaliza hostname (IDNA/Punycode si es necesario)
   */
  normalize(hostname: string): string {
    try {
      // Intentar convertir IDN a ASCII (Punycode)
      return new URL(`https://${hostname}`).hostname.toLowerCase();
    } catch {
      return hostname.toLowerCase().trim();
    }
  }
}
