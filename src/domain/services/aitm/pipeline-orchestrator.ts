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
import { computeRiskScore, THRESHOLDS, WEIGHTS } from "./types";
import type { IBrowserIntegrityEvaluator, IntegrityEvaluationContext } from "../../ports/interfaces/IBrowserIntegrityEvaluator";

/** Risk level type alias */
type RiskLevel = 'high' | 'medium' | 'low';

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
  currentOrigin: string,
  expectedOrigin: string,
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

  const executePromise = step.execute(currentOrigin, expectedOrigin).then((result) => ({
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
    currentOrigin: string,
    expectedOrigin: string,
  ): Promise<PipelineResult & { integrityResult?: AiTMDetectionResult }> {
    const startTime = performance.now();
    const stepResults = await this.executePipelineSteps(currentOrigin, expectedOrigin);
    const integrityResult = await this.runIntegrityEvaluation(stepResults);
    const totalTimeMs = performance.now() - startTime;

    const overallRisk = this.computeOverallRisk(stepResults, integrityResult);
    const combinedRiskScore = integrityResult ? computeRiskScore(
      this.buildDomainSignals(stepResults).concat(integrityResult.signals)
    ) : 0;
    
    // SECURITY: If ANY step fails (isValid=false), overall is invalid.
    // ExactMatch failure is absolute - no fallback to other steps.
    const isValid = stepResults.length > 0 && stepResults.every(r => r.isValid);
    const finalIsValid = isValid && (combinedRiskScore < THRESHOLDS.block);

    return {
      steps: stepResults,
      overallRisk,
      isValid: finalIsValid,
      totalTimeMs,
      integrityResult,
    };
  }

  private async executePipelineSteps(
    currentOrigin: string,
    expectedOrigin: string,
  ): Promise<DomainValidationResult[]> {
    const stepResults: DomainValidationResult[] = [];

    const execution = this.runStepsWithTimeout(currentOrigin, expectedOrigin, stepResults);

    const globalTimeout = new Promise<{ timedOut: true }>((resolve) => {
      setTimeout(() => resolve({ timedOut: true }), this.totalTimeoutMs);
    });

    await Promise.race([execution, globalTimeout]);
    return stepResults;
  }

  private async runStepsWithTimeout(
    currentOrigin: string,
    expectedOrigin: string,
    stepResults: DomainValidationResult[],
  ): Promise<void> {
    for (const step of this.steps) {

      try {
        const { result, timedOut } = await executeWithTimeout(
          step,
          currentOrigin,
          expectedOrigin,
          this.phaseTimeoutMs,
        );

        stepResults.push(result);

        if (timedOut) continue;
        if (this.shouldShortCircuit(result)) break;
      } catch (err) {
        const errorMsg = err instanceof Error ? err.message : String(err);
        stepResults.push(this.createErrorResult(step.name, errorMsg));
      }
    }
  }

  private shouldShortCircuit(result: DomainValidationResult): boolean {
    return (result.strategy === "ExactMatch" && result.isValid) ||
           (result.strategy === "ExactMatch" && !result.isValid) || // Absolute failure
           (result.strategy === "ConfusableDetection" && result.riskLevel === "high");
  }

  private createErrorResult(stepName: string, errorMsg: string): DomainValidationResult {
    return {
      isValid: false,
      strategy: stepName,
      riskLevel: "medium",
      confidence: 0,
      reason: `Phase "${stepName}" failed: ${errorMsg}`,
    };
  }

  private async runIntegrityEvaluation(
    stepResults: DomainValidationResult[],
  ): Promise<AiTMDetectionResult | undefined> {
    if (!this.integrityEvaluator || !this.currentFingerprint) return undefined;

    const context: IntegrityEvaluationContext = {
      currentFingerprint: this.currentFingerprint,
      baselineFingerprint: this.baselineFingerprint,
      url: this.currentFingerprint.url,
      timestamp: Date.now(),
    };

    try {
      return await this.integrityEvaluator.evaluate(context);
    } catch (err) {
      console.warn('[PipelineOrchestrator] Integrity evaluation failed:', err);
      return undefined;
    }
  }

  private buildDomainSignals(stepResults: DomainValidationResult[]): DetectionSignal[] {
    return stepResults.map(step => {
      const signalType = this.mapStrategyToSignalType(step.strategy);
      return {
        type: signalType,
        status: this.computeSignalStatus(step),
        score: this.computeSignalScore(step),
        confidence: step.confidence,
        weight: WEIGHTS[signalType],
        details: step.reason,
      };
    });
  }

  private computeSignalStatus(step: DomainValidationResult): 'pass' | 'fail' | 'warn' {
    if (step.isValid) return 'pass';
    return step.riskLevel === 'high' ? 'fail' : 'warn';
  }

  private computeSignalScore(step: DomainValidationResult): number {
    if (step.isValid) return 0;
    return step.riskLevel === 'high' ? 100 : 50;
  }

  private computeOverallRisk(
    stepResults: DomainValidationResult[],
    integrityResult: AiTMDetectionResult | undefined,
  ): RiskLevel {
    const domainRisk = this.computeDomainRisk(stepResults);
    const integrityRiskLevel = this.computeIntegrityRiskLevel(integrityResult);

    if (domainRisk === 'high' || integrityRiskLevel === 'high') return 'high';
    if (domainRisk === 'medium' || integrityRiskLevel === 'medium') return 'medium';
    return 'low';
  }

  private computeDomainRisk(stepResults: DomainValidationResult[]): RiskLevel {
    if (stepResults.some(r => r.riskLevel === 'high')) return 'high';
    if (stepResults.some(r => r.riskLevel === 'medium')) return 'medium';
    return 'low';
  }

  private computeIntegrityRiskLevel(integrityResult: AiTMDetectionResult | undefined): RiskLevel {
    const integrityRisk = integrityResult?.riskScore ?? 0;
    if (integrityRisk >= THRESHOLDS.block) return 'high';
    if (integrityRisk >= THRESHOLDS.warn) return 'medium';
    return 'low';
  }

  private mapStrategyToSignalType(strategy: string): DetectionSignal['type'] {
    switch (strategy) {
      case 'ExactMatch': return 'hostname';
      case 'ConfusableDetection': return 'content-hash';
      case 'LevenshteinTypoSquatting': return 'timing';
      default: return 'cookie-security';
    }
  }
}
