/**
 * Domain Validation Pipeline — Interfaces and types
 *
 * Defines the contract for a composable, step-based domain validation pipeline.
 * Each step validates the hostname against one criterion (e.g., exact match,
 * DNS normalization, typosquatting, homograph detection) and returns an
 * individual result. The pipeline aggregates all step results into a final
 * verdict.
 *
 * @module domain/services/aitm/domain-validation-pipeline
 */

/**
 * Risk levels for domain validation results.
 */
export type RiskLevel = "low" | "medium" | "high";

/**
 * Result produced by a single validation step.
 */
export interface DomainValidationResult {
  /** Whether the hostname passed this validation step */
  isValid: boolean;
  /** Name of the strategy that produced this result */
  strategy: string;
  /** Assessed risk level */
  riskLevel: RiskLevel;
  /** Confidence in the result, `[0, 1]` */
  confidence: number;
  /** Human-readable explanation of the result */
  reason: string;
  /** Optional evidence supporting the result (e.g., intermediate values) */
  evidence?: unknown[];
  /** Optional edit distance if the step computed one */
  distance?: number;
}

/**
 * Aggregated result produced by running all pipeline steps.
 */
export interface PipelineResult {
  /** Individual results from each step in execution order */
  steps: DomainValidationResult[];
  /** Highest risk level observed across all steps */
  overallRisk: RiskLevel;
  /** Whether the hostname is considered valid overall */
  isValid: boolean;
  /** Wall-clock time in milliseconds for the entire pipeline run */
  totalTimeMs: number;
}

/**
 * A single validation step in the pipeline.
 */
export interface IDomainValidationStep {
  /** Human-readable name for this step (used in logs and diagnostics) */
  name: string;

  /**
   * Execute this validation step against the given hostname.
   *
   * @param hostname - The hostname to validate (already normalized)
   * @param expectedDomain - The expected/legitimate domain
   * @returns The validation result for this step
   */
  execute(hostname: string, expectedDomain: string): Promise<DomainValidationResult>;
}

/**
 * Pipeline that chains multiple validation steps and aggregates results.
 */
export interface IDomainValidationPipeline {
  /**
   * Register a validation step. Steps execute in registration order.
   *
   * @param step - The validation step to add
   */
  addStep(step: IDomainValidationStep): void;

  /**
   * Run all registered steps and return the aggregated result.
   *
   * @param hostname - The hostname to validate
   * @param expectedDomain - The expected/legitimate domain
   * @returns The aggregated pipeline result
   */
  validate(hostname: string, expectedDomain: string): Promise<PipelineResult>;
}
