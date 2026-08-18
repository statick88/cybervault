/**
 * Centralized AITM Detection Types
 * Consolidates types from content-fingerprinter.ts, dom-integrity-checker.ts, and aitm-detector.ts
 * Pure domain types — no external API dependencies
 */

import type { IntegrityScore } from '../../value-objects/integrity-score';
import type { FingerprintAnomaly, FingerprintAnomalyType, FingerprintAnomalySeverity } from '../../value-objects/fingerprint-anomaly';

/**
 * Page fingerprint captured for integrity evaluation
 */
export interface PageFingerprint {
  readonly url: string;
  readonly contentHash: string;
  readonly formStructure: string;
  readonly scriptCount: number;
  readonly externalResources: readonly string[];
  readonly timestamp: number;
  readonly integrityScore?: IntegrityScore;
  readonly anomalies?: readonly FingerprintAnomaly[];
}

/**
 * Types of DOM anomalies detected during integrity checks
 * Extended to include FingerprintAnomalyType for unified anomaly tracking
 */
export type DOMAnomalyType =
  | 'unexpected-script'
  | 'modified-form'
  | 'hidden-field'
  | 'event-listener'
  | 'iframe-injection'
  | 'style-injection'
  | FingerprintAnomalyType;

/**
 * Severity levels for DOM anomalies
 * Aligned with FingerprintAnomalySeverity
 */
export type DOMAnomalySeverity = FingerprintAnomalySeverity;

/**
 * Individual DOM anomaly finding
 * Can be converted to/from FingerprintAnomaly for unified handling
 */
export interface DOMAnomaly {
  readonly type: DOMAnomalyType;
  readonly severity: DOMAnomalySeverity;
  readonly description: string;
  readonly element?: string;
  readonly expected?: string;
  readonly actual?: string;
}

/**
 * Result of DOM integrity check
 * Now includes IntegrityScore for unified scoring
 */
export interface DOMIntegrityResult {
  readonly anomalies: readonly DOMAnomaly[];
  readonly fingerprintAnomalies: readonly FingerprintAnomaly[];
  readonly integrityScore?: IntegrityScore;
  readonly score: number; // 0-100, higher = more integrity
  readonly checkedAt: number;
}

/**
 * Types of detection signals used in AiTM evaluation
 * Extended to include integrity-score and fingerprint-anomaly signal types
 */
export type DetectionSignalType =
  | 'hostname'
  | 'content-hash'
  | 'timing'
  | 'dom-integrity'
  | 'cookie-security'
  | 'integrity-score'
  | 'fingerprint-anomaly';

/**
 * Status of individual detection signals
 */
export type DetectionSignalStatus = 'pass' | 'warn' | 'fail';

/**
 * Individual detection signal result
 * Now includes confidence and weight for computeRiskScore() integration
 */
export interface DetectionSignal {
  readonly type: DetectionSignalType;
  readonly status: DetectionSignalStatus;
  readonly score: number; // 0-100 (risk score, higher = more risk)
  readonly confidence: number; // 0-1
  readonly weight: number; // 0-1, used by computeRiskScore
  readonly details: string;
  readonly integrityScore?: IntegrityScore;
  readonly anomalies?: readonly FingerprintAnomaly[];
}

/**
 * Overall AiTM detection result
 * Now includes aggregated IntegrityScore and FingerprintAnomaly[]
 */
export interface AiTMDetectionResult {
  readonly riskScore: number; // 0-100, higher = more risk
  readonly signals: readonly DetectionSignal[];
  readonly recommendation: 'allow' | 'warn' | 'block';
  readonly evaluatedAt: number;
  readonly integrityScore?: IntegrityScore;
  readonly anomalies?: readonly FingerprintAnomaly[];
}

/**
 * Signal weight constants for risk score calculation
 * Must sum to 1.0
 * Extended to include integrity and fingerprint anomaly signals
 */
export const WEIGHTS: Record<DetectionSignalType, number> = {
  hostname: 0.25,
  'content-hash': 0.30,
  timing: 0.15,
  'dom-integrity': 0.20,
  'cookie-security': 0.10,
  'integrity-score': 0.25,
  'fingerprint-anomaly': 0.15,
} as const;

/**
 * Risk threshold constants
 */
export const THRESHOLDS = {
  block: 70,
  warn: 40,
} as const;

/**
 * Timing analysis thresholds (milliseconds)
 */
export const TIMING_THRESHOLDS = {
  warning: 200,
  critical: 500,
} as const;

/**
 * Compute risk score from signals using WEIGHTS
 */
export function computeRiskScore(signals: readonly DetectionSignal[]): number {
  let weightedSum = 0;
  let totalWeight = 0;

  for (const signal of signals) {
    const weight = WEIGHTS[signal.type] ?? 0;
    weightedSum += signal.score * weight;
    totalWeight += weight;
  }

  return totalWeight > 0 ? Math.round(weightedSum / totalWeight) : 0;
}

/**
 * Determine recommendation from risk score using THRESHOLDS
 */
export function getRecommendation(riskScore: number): 'allow' | 'warn' | 'block' {
  if (riskScore >= THRESHOLDS.block) {
    return 'block';
  }
  if (riskScore >= THRESHOLDS.warn) {
    return 'warn';
  }
  return 'allow';
}

/**
 * Validate that WEIGHTS sum to 1.0 (within floating point tolerance)
 */
export function validateWeights(): boolean {
  const sum = Object.values(WEIGHTS).reduce((acc, w) => acc + w, 0);
  return Math.abs(sum - 1.0) < 0.001;
}