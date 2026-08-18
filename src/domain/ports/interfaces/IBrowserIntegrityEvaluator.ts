/**
 * IBrowserIntegrityEvaluator Port Interface
 * Pure domain contract for browser integrity evaluation
 * Implementations belong in infrastructure layer
 */

import type { PageFingerprint } from '../../services/aitm/types.js';
import type { AiTMDetectionResult } from '../../services/aitm/types.js';
import type { IntegrityScore } from '../../value-objects/integrity-score.js';
import type { FingerprintAnomaly } from '../../value-objects/fingerprint-anomaly.js';

/**
 * Evaluation context containing fingerprint and optional baseline
 */
export interface IntegrityEvaluationContext {
  readonly currentFingerprint: PageFingerprint;
  readonly baselineFingerprint?: PageFingerprint;
  readonly url: string;
  readonly timestamp: number;
}

/**
 * Detailed evaluation result extending the base detection result
 */
export interface BrowserIntegrityEvaluationResult extends AiTMDetectionResult {
  readonly integrityScore: IntegrityScore;
  readonly fingerprintAnomalies: readonly FingerprintAnomaly[];
  readonly evaluationContext: IntegrityEvaluationContext;
}

/**
 * Port interface for browser integrity evaluation
 * Pure domain contract — no infrastructure dependencies
 */
export interface IBrowserIntegrityEvaluator {
  /**
   * Evaluate browser integrity against a baseline
   * @param context Evaluation context with current and optional baseline fingerprints
   * @returns Detailed integrity evaluation result
   */
  evaluate(context: IntegrityEvaluationContext): Promise<BrowserIntegrityEvaluationResult>;

  /**
   * Quick integrity check using only current fingerprint (no baseline comparison)
   * @param fingerprint Current page fingerprint
   * @returns Simplified evaluation result
   */
  quickEvaluate(fingerprint: PageFingerprint): Promise<AiTMDetectionResult>;

  /**
   * Get the evaluator's unique identifier
   */
  readonly evaluatorId: string;

  /**
   * Get the evaluator version
   */
  readonly version: string;
}