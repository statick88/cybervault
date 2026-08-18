/**
 * Pipeline Orchestrator — 3-Phase Domain Validation + Integrity Signal Aggregation
 *
 * Orchestrates ExactMatch → ConfusableDetection → Typosquatting
 * with short-circuit logic:
 * - Phase 1 (ExactMatch) success → skip remaining phases
 * - Phase 2 (ConfusableDetection) high-risk → skip Phase 3
 * - Phase 1 failure → progressive (Phase 2 still executes)
 *
 * Extended with Integrity Signal Aggregation:
 * - Injects BrowserIntegrityEvaluatorAdapter results into evaluation flow
 * - Aggregates risk score via computeRiskScore() alongside existing signals
 * - Processes all signals through WEIGHTS and THRESHOLDS
 *
 * @module domain/services/aitm/pipeline-orchestrator
 */

import type {
  IDomainValidationStep,
  IDomainValidationPipeline,
  DomainValidationResult,
  PipelineResult,
} from "./domain-validation-pipeline";
import type { DetectionSignal, AiTMDetectionResult } from "./types";
import { computeRiskScore, getRecommendation, THRESHOLDS, WEIGHTS } from "./types";
import type { IBrowserIntegrityEvaluator, IntegrityEvaluationContext } from "../../ports/interfaces/IBrowserIntegrityEvaluator";

/** Default timeouts in ms */
const DEFAULT_PHASE_TIMEOUT_MS = 50;
const DEFAULT_TOTAL_TIMEOUT_MS = 200;

export interface PipelineOrchestratorConfig {
  /** Maximum time per phase in ms (default: 50) */
  phaseTimeoutMs?: number;
  /** Maximum total pipeline time in ms (default: 200) */
  totalTimeoutMs?: number;
  /** Optional browser integrity evaluator for multi-vector signal aggregation */
  integrityEvaluator?: IBrowserIntegrityEvaluator;
  /** Current page fingerprint for integrity evaluation */
  currentFingerprint?: {
    readonly url: string;
    readonly contentHash: string;
    readonly formStructure: string;
    readonly scriptCount: number;
    readonly externalResources: readonly string[];
    readonly timestamp: number;
  };
  /** Baseline fingerprint for comparison */
  baselineFingerprint?: {
    readonly url: string;
    readonly contentHash: string;
    readonly formStructure: string;
    readonly scriptCount: number;
    readonly externalResources: readonly string[];
    readonly timestamp: number;
  };
}

/**
 * Execute a single phase with a timeout.
 */
async function executeWithTimeout(
  step: IDomainValidationStep,
  hostname: string,
  expectedDomain: string,
  timeoutMs: number,
): Promise<{ result: DomainValidationResult; timedOut: boolean }> {
  let timeoutHandle: NodeJS.Timeout | undefined;
  const timeoutPromise = new Promise<{ result: DomainValidationResult; timedOut: true }>((resolve) => {
    timeoutHandle = setTimeout(() => {
      resolve({
        result: {
          isValid: false,
          strategy: step.name,
          riskLevel: "medium",
          confidence: 0,
          reason: `Phase "${step.name}" timed out after ${timeoutMs}ms`,
        },
        timedOut: true,
      });
    }, timeoutMs);
  });

  const executePromise = step.execute(hostname, expectedDomain).then((result) => ({
    result,
    timedOut: false as const,
  }));

  // Clear the timer once the step settles so the handle never leaks
  executePromise.finally(() => {
    if (timeoutHandle) clearTimeout(timeoutHandle);
  });

  return Promise.race([executePromise, timeoutPromise]);
}

export class PipelineOrchestrator implements IDomainValidationPipeline {
  private readonly steps: IDomainValidationStep[] = [];
  private readonly phaseTimeoutMs: number;
  private readonly totalTimeoutMs: number;
  private readonly integrityEvaluator?: IBrowserIntegrityEvaluator;
  private readonly currentFingerprint?: IntegrityEvaluationContext['currentFingerprint'];
  private readonly baselineFingerprint?: IntegrityEvaluationContext['baselineFingerprint'];

  constructor(config?: PipelineOrchestratorConfig) {
    this.phaseTimeoutMs = config?.phaseTimeoutMs ?? DEFAULT_PHASE_TIMEOUT_MS;
    this.totalTimeoutMs = config?.totalTimeoutMs ?? DEFAULT_TOTAL_TIMEOUT_MS;
    this.integrityEvaluator = config?.integrityEvaluator;
    this.currentFingerprint = config?.currentFingerprint;
    this.baselineFingerprint = config?.baselineFingerprint;
  }

  addStep(step: IDomainValidationStep): void {
    this.steps.push(step);
  }

  async validate(
    hostname: string,
    expectedDomain: string,
  ): Promise<PipelineResult & { integrityResult?: AiTMDetectionResult }> {
    const startTime = performance.now();
    const stepResults: DomainValidationResult[] = [];
    const phaseErrors: Array<{ phase: number; error: string }> = [];

    // Global timeout
    const globalTimeout = new Promise<{ timedOut: true }>((resolve) => {
      setTimeout(() => resolve({ timedOut: true }), this.totalTimeoutMs);
    });

    const execution = (async () => {
      for (let i = 0; i < this.steps.length; i++) {
        const step = this.steps[i];

        try {
          const { result, timedOut } = await executeWithTimeout(
            step,
            hostname,
            expectedDomain,
            this.phaseTimeoutMs,
          );

          stepResults.push(result);

          if (timedOut) {
            phaseErrors.push({ phase: i + 1, error: `Timeout after ${this.phaseTimeoutMs}ms` });
            continue;
          }

          // Short-circuit on exact match (Phase 1 success)
          if (result.strategy === "ExactMatch" && result.isValid) {
            break;
          }

          // Security short-circuit on high-risk confusable (Phase 2)
          if (result.strategy === "ConfusableDetection" && result.riskLevel === "high") {
            break;
          }
        } catch (err) {
          const errorMsg = err instanceof Error ? err.message : String(err);
          phaseErrors.push({ phase: i + 1, error: errorMsg });

          stepResults.push({
            isValid: false,
            strategy: step.name,
            riskLevel: "medium",
            confidence: 0,
            reason: `Phase "${step.name}" failed: ${errorMsg}`,
          });
        }
      }
    })();

    await Promise.race([execution, globalTimeout]);

    // Phase 3.1: Integrity Signal Aggregation
    // If integrity evaluator is available, run it and aggregate signals
    let integrityResult: AiTMDetectionResult | undefined;
    let combinedRiskScore = 0;
    let combinedRecommendation: 'allow' | 'warn' | 'block' = 'allow';

    if (this.integrityEvaluator && this.currentFingerprint) {
      const context: IntegrityEvaluationContext = {
        currentFingerprint: this.currentFingerprint,
        baselineFingerprint: this.baselineFingerprint,
        url: this.currentFingerprint.url,
        timestamp: Date.now(),
      };

      try {
        integrityResult = await this.integrityEvaluator.evaluate(context);
        
        // Convert domain validation results to DetectionSignal format for aggregation
        const domainSignals: DetectionSignal[] = stepResults.map(step => {
          const signalType = this.mapStrategyToSignalType(step.strategy);
          return {
            type: signalType,
            status: step.isValid ? 'pass' : step.riskLevel === 'high' ? 'fail' : 'warn',
            score: step.isValid ? 0 : step.riskLevel === 'high' ? 100 : 50,
            confidence: step.confidence,
            weight: WEIGHTS[signalType],
            details: step.reason,
          };
        });

        // Combine all signals: domain validation + integrity evaluation
        const allSignals: DetectionSignal[] = [
          ...domainSignals,
          ...integrityResult.signals,
        ];

        // Aggregate using centralized computeRiskScore
        combinedRiskScore = computeRiskScore(allSignals);
        combinedRecommendation = getRecommendation(combinedRiskScore);
      } catch (err) {
        // Integrity evaluation failed, log but continue with domain-only result
        console.warn('[PipelineOrchestrator] Integrity evaluation failed:', err);
      }
    }

    const totalTimeMs = performance.now() - startTime;
    
    // Determine overall risk from both domain and integrity
    const domainRisk = stepResults.some((r) => r.riskLevel === "high")
      ? "high"
      : stepResults.some((r) => r.riskLevel === "medium")
        ? "medium"
        : "low";
    
    const integrityRisk = integrityResult?.riskScore ?? 0;
    const integrityRiskLevel = integrityRisk >= THRESHOLDS.block ? "high" : integrityRisk >= THRESHOLDS.warn ? "medium" : "low";
    
    // Combined overall risk takes the higher of the two
    const overallRisk = (domainRisk === "high" || integrityRiskLevel === "high") ? "high"
      : (domainRisk === "medium" || integrityRiskLevel === "medium") ? "medium"
      : "low";

    const isValid = stepResults.length > 0
      ? stepResults[stepResults.length - 1].isValid
      : true;

    // Final validity considers both domain and integrity
    const finalIsValid = isValid && (combinedRiskScore < THRESHOLDS.block);

    return {
      steps: stepResults,
      overallRisk,
      isValid: finalIsValid,
      totalTimeMs,
      integrityResult,
    };
  }

  /**
   * Map domain validation strategy to DetectionSignal type
   */
  private mapStrategyToSignalType(strategy: string): DetectionSignal['type'] {
    switch (strategy) {
      case 'ExactMatch':
        return 'hostname';
      case 'ConfusableDetection':
        return 'content-hash';
      case 'LevenshteinTypoSquatting':
        return 'timing';
      default:
        return 'cookie-security';
    }
  }
}
