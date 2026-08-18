/**
 * FingerprintAnomaly — immutable value object for a detected browser fingerprint anomaly.
 *
 * Represents a single discrepancy between baseline and current page fingerprints.
 * Used by IBrowserIntegrityEvaluator and AiTM detection to surface anomalies.
 *
 * @module domain/value-objects/fingerprint-anomaly
 */

export type FingerprintAnomalyType =
  | 'content-hash-mismatch'
  | 'form-structure-modified'
  | 'script-count-anomaly'
  | 'unexpected-external-resource'
  | 'missing-expected-resource'
  | 'timestamp-skew';

export type FingerprintAnomalySeverity = 'info' | 'warning' | 'critical';

export interface FingerprintAnomalyPlain {
  readonly type: FingerprintAnomalyType;
  readonly severity: FingerprintAnomalySeverity;
  readonly expected: string;
  readonly actual: string;
  readonly description: string;
  readonly detectedAt: number;
}

export class FingerprintAnomaly {
  readonly type: FingerprintAnomalyType;
  readonly severity: FingerprintAnomalySeverity;
  readonly expected: string;
  readonly actual: string;
  readonly description: string;
  readonly detectedAt: number;

  private constructor(
    type: FingerprintAnomalyType,
    severity: FingerprintAnomalySeverity,
    expected: string,
    actual: string,
    description: string,
    detectedAt: number,
  ) {
    this.type = type;
    this.severity = severity;
    this.expected = expected;
    this.actual = actual;
    this.description = description;
    this.detectedAt = detectedAt;
    Object.freeze(this);
  }

  static create(
    type: FingerprintAnomalyType,
    severity: FingerprintAnomalySeverity,
    expected: string,
    actual: string,
    description: string,
    detectedAt: number,
  ): FingerprintAnomaly {
    if (!type) {
      throw new Error('FingerprintAnomaly: type is required');
    }
    if (!severity) {
      throw new Error('FingerprintAnomaly: severity is required');
    }
    if (detectedAt <= 0) {
      throw new Error('FingerprintAnomaly: detectedAt must be positive');
    }

    return new FingerprintAnomaly(type, severity, expected, actual, description, detectedAt);
  }

  toPlainObject(): FingerprintAnomalyPlain {
    return {
      type: this.type,
      severity: this.severity,
      expected: this.expected,
      actual: this.actual,
      description: this.description,
      detectedAt: this.detectedAt,
    };
  }
}
