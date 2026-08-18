/**
 * Pre-Submission Gate — Credential Form Protection
 *
 * Intercepts form submissions with password fields and evaluates
 * the domain context before allowing credential autofill.
 *
 * Security model:
 * - ALL credential fill operations MUST pass through this gate
 * - Block before DOM/network touch if domain is malicious
 * - Warn on unknown domains (TOFU protocol)
 * - Rate limit to prevent DoS
 *
 * @module domain/services/aitm/pre-submission-gate
 */

import type {
  IDomainValidationPipeline,
  DomainValidationResult,
} from "./domain-validation-pipeline";
import type { ITrustStoreRepository, TrustEntry } from "../../repositories";

/**
 * Context extracted from a form submission event.
 */
export interface FormContext {
  /** Full URL of the current page */
  url: string;
  /** Hostname being validated */
  hostname: string;
  /** Form action URL */
  formAction: string;
  /** Form method (GET/POST) */
  formMethod: string;
  /** Whether the form contains a password field */
  hasPasswordField: boolean;
  /** Form field metadata */
  fields: Array<{ name: string; type: string; value?: string }>;
  /** Expected/registered domain for this site */
  expectedDomain?: string;
}

/**
 * Decision produced by the pre-submission gate.
 */
export interface GateDecision {
  /** Action to take: allow fill, block submission, or warn user */
  action: "allow" | "block" | "warn";
  /** Human-readable reason for the decision */
  reason: string;
  /** Confidence score [0, 1] */
  confidence: number;
  /** Numeric risk score [0, 100] */
  riskScore: number;
  /** Validation evidence from pipeline steps */
  evidence: DomainValidationResult[];
  /** Unique request ID for audit trail */
  requestId: string;
  /** Unix timestamp of the decision */
  timestamp: number;
}

/**
 * Configuration for the pre-submission gate.
 */
export interface PreSubmissionGateConfig {
  /** Whether the gate is active */
  enabled: boolean;
  /** Similarity threshold for typosquatting [0, 1] */
  threshold: number;
  /** Domains that bypass all checks */
  whitelist: string[];
  /** Domains that are always blocked */
  blacklist: string[];
  /** Max submissions per minute per domain */
  maxSubmissionsPerMinute: number;
}

/**
 * Interface for the pre-submission gate.
 */
export interface IPreSubmissionGate {
  evaluate(ctx: FormContext): Promise<GateDecision>;
}

/**
 * Generate a unique request ID.
 */
function generateRequestId(): string {
  return `req_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
}

/**
 * Detect suspicious hidden fields (honeypot detection).
 */
function hasSuspiciousHiddenFields(fields: FormContext["fields"]): boolean {
  return fields.some(
    (f) =>
      f.type === "hidden" &&
      f.value !== undefined &&
      f.value.length > 0 &&
      !["csrf_token", "csrfmiddlewaretoken", "_token", "__token"].includes(
        f.name.toLowerCase(),
      ),
  );
}

/**
 * Pre-Submission Gate implementation.
 *
 * Evaluates form submissions and decides whether to allow,
 * block, or warn before credentials are sent to the DOM.
 */
export class PreSubmissionGate implements IPreSubmissionGate {
  private readonly config: PreSubmissionGateConfig;
  private readonly domainPipeline: IDomainValidationPipeline;
  private readonly trustStore: ITrustStoreRepository;

  // Rate limiting state: domain -> timestamps of recent submissions
  private readonly submissionTimestamps = new Map<string, number[]>();

  constructor(
    config: PreSubmissionGateConfig,
    domainPipeline?: IDomainValidationPipeline,
    trustStore?: ITrustStoreRepository,
  ) {
    this.config = config;
    this.domainPipeline = domainPipeline ?? ({
      validate: async () => ({ steps: [], overallRisk: "low", isValid: true, totalTimeMs: 0 }),
    } as unknown as IDomainValidationPipeline);
    this.trustStore = trustStore ?? ({
      findByDomain: async () => null,
    } as unknown as ITrustStoreRepository);
  }

  async evaluate(ctx: FormContext): Promise<GateDecision> {
    const requestId = generateRequestId();
    const timestamp = Date.now();

    // Gate disabled → allow everything
    if (!this.config.enabled) {
      return {
        action: "allow",
        reason: "gate_disabled",
        confidence: 1.0,
        riskScore: 0,
        evidence: [],
        requestId,
        timestamp,
      };
    }

    // No password field → no gate needed
    if (!ctx.hasPasswordField) {
      return {
        action: "allow",
        reason: "no_password_field",
        confidence: 1.0,
        riskScore: 0,
        evidence: [],
        requestId,
        timestamp,
      };
    }

    const normalizedHostname = ctx.hostname.toLowerCase().trim();

    // 1. Blacklist check (absolute block)
    if (this.config.blacklist.some((bl) => normalizedHostname === bl || normalizedHostname.endsWith(`.${bl}`))) {
      return {
        action: "block",
        reason: "blacklist_match",
        confidence: 1.0,
        riskScore: 100,
        evidence: [],
        requestId,
        timestamp,
      };
    }

    // 2. Whitelist check (absolute allow)
    if (this.config.whitelist.some((wl) => normalizedHostname === wl || normalizedHostname.endsWith(`.${wl}`))) {
      return {
        action: "allow",
        reason: "whitelist_match",
        confidence: 1.0,
        riskScore: 0,
        evidence: [],
        requestId,
        timestamp,
      };
    }

    // 3. Rate limiting
    const rateLimitResult = this.checkRateLimit(normalizedHostname);
    if (!rateLimitResult.allowed) {
      return {
        action: "block",
        reason: "rate_limit_exceeded",
        confidence: 1.0,
        riskScore: 80,
        evidence: [],
        requestId,
        timestamp,
      };
    }

    // 4. Hidden field detection (honeypot)
    if (hasSuspiciousHiddenFields(ctx.fields)) {
      return {
        action: "warn",
        reason: "suspicious_hidden_fields",
        confidence: 0.7,
        riskScore: 60,
        evidence: [],
        requestId,
        timestamp,
      };
    }

    // 5. Domain validation pipeline
    const expectedDomain = ctx.expectedDomain || normalizedHostname;
    const pipelineResult = await this.domainPipeline.validate(
      normalizedHostname,
      expectedDomain,
    );

    // 6. Trust store lookup
    let trustEntry: TrustEntry | null = null;
    try {
      trustEntry = await this.trustStore.findByDomain(normalizedHostname);
    } catch {
      // Trust store unavailable — continue without trust info
    }

    // 7. Decision logic based on pipeline result + trust
    const { action, reason, riskScore, confidence } = this.makeDecision(
      pipelineResult,
      trustEntry,
    );

    // Record submission for rate limiting
    this.recordSubmission(normalizedHostname);

    return {
      action,
      reason,
      confidence,
      riskScore,
      evidence: pipelineResult.steps,
      requestId,
      timestamp,
    };
  }

  private makeDecision(
    pipelineResult: Awaited<ReturnType<IDomainValidationPipeline["validate"]>>,
    trustEntry: TrustEntry | null,
  ): {
    action: GateDecision["action"];
    reason: string;
    riskScore: number;
    confidence: number;
  } {
    // Trusted domain → allow
    if (trustEntry?.trustLevel === "verified") {
      return {
        action: "allow",
        reason: "trusted_domain",
        riskScore: 0,
        confidence: 1.0,
      };
    }

    // Pipeline says block (high risk) → block regardless
    if (!pipelineResult.isValid && pipelineResult.overallRisk === "high") {
      const highRiskStep = pipelineResult.steps.find((s) => s.riskLevel === "high");
      return {
        action: "block",
        reason: highRiskStep?.reason || "domain_validation_failed",
        riskScore: 90,
        confidence: highRiskStep?.confidence ?? 0.8,
      };
    }

    // Pipeline says medium risk → warn
    if (pipelineResult.overallRisk === "medium") {
      return {
        action: "warn",
        reason: "domain_validation_uncertain",
        riskScore: 50,
        confidence: 0.5,
      };
    }

    // TOFU: unknown domain → warn
    if (!trustEntry) {
      return {
        action: "warn",
        reason: "domain_not_in_trust_store",
        riskScore: 40,
        confidence: 0.5,
      };
    }

    // Distrusted domain → block
    if (trustEntry.trustLevel === "distrusted") {
      return {
        action: "block",
        reason: "distrusted_domain",
        riskScore: 90,
        confidence: 1.0,
      };
    }

    // Low risk, known but not verified → allow
    return {
      action: "allow",
      reason: "low_risk_domain",
      riskScore: 10,
      confidence: 0.8,
    };
  }

  private checkRateLimit(hostname: string): { allowed: boolean } {
    const now = Date.now();
    const windowMs = 60_000; // 1 minute
    const timestamps = this.submissionTimestamps.get(hostname) ?? [];

    // Clean old entries
    const recent = timestamps.filter((t) => now - t < windowMs);

    if (recent.length >= this.config.maxSubmissionsPerMinute) {
      this.submissionTimestamps.set(hostname, recent);
      return { allowed: false };
    }

    return { allowed: true };
  }

  private recordSubmission(hostname: string): void {
    const now = Date.now();
    const timestamps = this.submissionTimestamps.get(hostname) ?? [];
    const recent = timestamps.filter((t) => now - t < 60_000);
    recent.push(now);
    this.submissionTimestamps.set(hostname, recent);
  }
}
