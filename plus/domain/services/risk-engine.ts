/**
 * Adaptive Risk Engine — Deterministic Context Scoring for CyberVault Plus
 *
 * Evaluates authentication/authorization context and produces a risk score (0-100)
 * that drives pestillo state transitions and capability issuance decisions.
 *
 * Design principles:
 * - Deterministic: Same inputs → same score (no ML, no randomness)
 * - Explainable: Every score component has a named reason
 * - Configurable: Weights and thresholds via policy
 * - Context ≠ pestillo substitute: Pestillo is the gate, risk modulates within gate
 */

import type { CapabilityOperation } from "../operations";
import type { PestilloState } from "../entities/entitlement";
import type { PlusUser } from "../entities/user";
import type { Resource } from "../entities/resource";

/** Risk evaluation context */
export interface RiskContext {
  /** User attempting the operation */
  user: PlusUser;
  /** Target resource */
  resource: Resource;
  /** Operation being requested */
  operation: CapabilityOperation;
  /** Current pestillo state for this user×resource */
  pestilloState: PestilloState;
  /** Client-provided context (may be enriched by trusted edge) */
  clientContext: {
    country?: string; // ISO 3166-1 alpha-2
    ip?: string;
    deviceId?: string;
    userAgent?: string;
    timestamp: number; // Unix ms
  };
  /** Historical behavior (from audit log) */
  history?: {
    recentFailedAttempts: number; // Last 1 hour
    recentSuccessfulOps: number; // Last 24 hours
    avgRiskScore: number; // Last 30 days
    knownDevices: string[]; // Previously seen device IDs
    knownCountries: string[]; // Previously seen countries
  };
  /** Policy configuration (from policy engine) */
  policy: RiskPolicy;
}

/** Individual risk factor contribution */
export interface RiskFactor {
  name: string;
  score: number; // 0-100 contribution
  weight: number; // Policy weight (0-1)
  reason: string; // Human-readable explanation
  details?: Record<string, any>;
}

/** Complete risk evaluation result */
export interface RiskEvaluation {
  totalScore: number; // 0-100
  factors: RiskFactor[];
  decision: RiskDecision;
  timestamp: number;
}

/** Risk-based decision */
export type RiskDecision = "allow" | "challenge" | "deny";

/** Risk policy configuration */
export interface RiskPolicy {
  // Weights for each factor (sum should be ~1.0)
  weights: {
    countryDeviation: number;
    ipReputation: number;
    deviceTrust: number;
    timeAnomaly: number;
    operationCriticality: number;
    resourceCriticality: number;
    pestilloState: number;
    historyDeviation: number;
    velocity: number; // Impossible travel, rapid requests
  };

  // Thresholds
  thresholds: {
    allow: number; // Score ≤ allow → allow
    challenge: number; // allow < score ≤ challenge → challenge/step-up
    deny: number; // Score > deny → deny
  };

  // Country risk mapping
  countryRisk: Record<string, number>; // ISO code → base risk (0-100)

  // Operation risk multipliers
  operationRiskMultiplier: Record<string, number>;

  // Resource criticality risk multipliers
  criticalityRiskMultiplier: Record<string, number>;

  // Pestillo state modifiers
  pestilloModifiers: {
    closed: number;
    enabled: number;
    step_up: number;
    temporary: number;
  };

  // Velocity limits
  velocity: {
    maxRequestsPerMinute: number;
    maxNewCountriesPerHour: number;
    maxNewDevicesPerDay: number;
    impossibleTravelKmPerHour: number; // Max realistic travel speed
  };
}

/** Default risk policy */
export const DEFAULT_RISK_POLICY: RiskPolicy = {
  weights: {
    countryDeviation: 0.20,
    ipReputation: 0.10,
    deviceTrust: 0.15,
    timeAnomaly: 0.10,
    operationCriticality: 0.15,
    resourceCriticality: 0.10,
    pestilloState: 0.10,
    historyDeviation: 0.05,
    velocity: 0.05,
  },
  thresholds: {
    allow: 30,
    challenge: 70,
    deny: 100,
  },
  countryRisk: {
    // Default: unknown countries = 50
    // Low risk: 10-20
    // Medium risk: 30-50
    // High risk: 60-80
    // Critical: 90-100
    "US": 10, "CA": 10, "GB": 10, "DE": 10, "FR": 10, "JP": 10, "AU": 10,
    "EC": 10, "CO": 15, "PE": 15, "CL": 15, "AR": 15, "MX": 20, "BR": 25,
    "CN": 60, "RU": 60, "KP": 90, "IR": 80,
  },
  operationRiskMultiplier: {
    "AUTOFILL": 1.0,
    "VIEW": 0.8,
    "TOTP": 0.8,
    "CONNECT": 1.2,
    "READ": 0.8,
    "ADMIN": 2.0,
    "BACKUP": 1.5,
    "RESTORE": 2.0,
    "ROTATE_SECRET": 1.8,
    "EDIT_SECRET": 1.5,
    "DELETE_SECRET": 2.0,
    "EXPORT_SECRET": 2.0,
  },
  criticalityRiskMultiplier: {
    "low": 0.5,
    "medium": 1.0,
    "high": 1.5,
    "critical": 2.0,
  },
  pestilloModifiers: {
    closed: 0, // Not evaluated (gate closed)
    enabled: 1.0,
    step_up: 0.5, // Already requires step-up, risk modulates within
    temporary: 1.2, // Time-bounded, slightly higher scrutiny
  },
  velocity: {
    maxRequestsPerMinute: 30,
    maxNewCountriesPerHour: 2,
    maxNewDevicesPerDay: 3,
    impossibleTravelKmPerHour: 1000, // Commercial flight speed
  },
};

/**
 * Adaptive Risk Engine — Main class
 */
export class AdaptiveRiskEngine {
  private policy: RiskPolicy;
  private lastKnownLocation: Map<string, { country: string; timestamp: number }> = new Map();

  constructor(policy: Partial<RiskPolicy> = {}) {
    this.policy = this.mergePolicy(DEFAULT_RISK_POLICY, policy);
  }

  private mergePolicy(base: RiskPolicy, override: Partial<RiskPolicy>): RiskPolicy {
    return {
      weights: { ...base.weights, ...override.weights },
      thresholds: { ...base.thresholds, ...override.thresholds },
      countryRisk: { ...base.countryRisk, ...override.countryRisk },
      operationRiskMultiplier: { ...base.operationRiskMultiplier, ...override.operationRiskMultiplier },
      criticalityRiskMultiplier: { ...base.criticalityRiskMultiplier, ...override.criticalityRiskMultiplier },
      pestilloModifiers: { ...base.pestilloModifiers, ...override.pestilloModifiers },
      velocity: { ...base.velocity, ...override.velocity },
    };
  }

  /**
   * Evaluate risk for a capability request
   */
  evaluate(context: RiskContext): RiskEvaluation {
    const factors: RiskFactor[] = [];

    // 1. Country deviation from habitual
    factors.push(this.evaluateCountryDeviation(context));

    // 2. IP reputation (placeholder - would integrate with threat intel)
    factors.push(this.evaluateIpReputation(context));

    // 3. Device trust
    factors.push(this.evaluateDeviceTrust(context));

    // 4. Time anomaly (outside business hours)
    factors.push(this.evaluateTimeAnomaly(context));

    // 5. Operation criticality
    factors.push(this.evaluateOperationCriticality(context));

    // 6. Resource criticality
    factors.push(this.evaluateResourceCriticality(context));

    // 7. Pestillo state modifier
    factors.push(this.evaluatePestilloState(context));

    // 8. History deviation
    factors.push(this.evaluateHistoryDeviation(context));

    // 9. Velocity checks
    factors.push(this.evaluateVelocity(context));

    // Calculate weighted total
    const totalScore = this.calculateWeightedScore(factors);

    // Determine decision based on thresholds and pestillo state
    const decision = this.makeDecision(totalScore, context.pestilloState);

    // Update last known location for velocity tracking
    if (context.clientContext.country) {
      this.lastKnownLocation.set(context.user.id, {
        country: context.clientContext.country,
        timestamp: context.clientContext.timestamp,
      });
    }

    return {
      totalScore: Math.round(totalScore),
      factors,
      decision,
      timestamp: Date.now(),
    };
  }

  private evaluateCountryDeviation(context: RiskContext): RiskFactor {
    const { user, clientContext, policy } = context;
    const currentCountry = clientContext.country?.toUpperCase();
    const habitualCountries = user.habitualCountries.map((c) => c.toUpperCase());

    let score = 0;
    let reason = "";

    if (!currentCountry) {
      score = 50; // Unknown country
      reason = "Country not provided in request";
    } else if (habitualCountries.length === 0) {
      score = 30; // No habitual countries established
      reason = "No habitual countries established for user";
    } else if (habitualCountries.includes(currentCountry)) {
      // Habitual country: score stays at its initial value of 0
      reason = `Country ${currentCountry} is habitual for user`;
    } else {
      // New country - check policy country risk
      const countryRisk = policy.countryRisk[currentCountry] ?? 50;
      score = Math.min(countryRisk, 80); // Cap at 80
      reason = `New country ${currentCountry} (base risk: ${countryRisk})`;
    }

    return {
      name: "countryDeviation",
      score,
      weight: policy.weights.countryDeviation,
      reason,
      details: { currentCountry, habitualCountries },
    };
  }

  private evaluateIpReputation(context: RiskContext): RiskFactor {
    // Placeholder - would integrate with threat intel feeds (AbuseIPDB, etc.)
    const score = 0; // Default: unknown IP = neutral
    return {
      name: "ipReputation",
      score,
      weight: this.policy.weights.ipReputation,
      reason: "IP reputation check not implemented (placeholder)",
      details: { ip: context.clientContext.ip },
    };
  }

  private evaluateDeviceTrust(context: RiskContext): RiskFactor {
    const { clientContext, history, policy } = context;
    const deviceId = clientContext.deviceId;

    let score = 0;
    let reason = "";

    if (!deviceId) {
      score = 40;
      reason = "No device ID provided";
    } else if (history?.knownDevices?.includes(deviceId)) {
      // Known device: score stays at its initial value of 0
      reason = `Device ${deviceId} is known/trusted`;
    } else {
      score = 50;
      reason = `New device ${deviceId} not previously seen`;
    }

    return {
      name: "deviceTrust",
      score,
      weight: policy.weights.deviceTrust,
      reason,
      details: { deviceId, knownDevices: history?.knownDevices },
    };
  }

  private evaluateTimeAnomaly(context: RiskContext): RiskFactor {
    const { clientContext, user, policy } = context;
    const timestamp = clientContext.timestamp || Date.now();
    const date = new Date(timestamp);
    const hour = date.getUTCHours();
    const day = date.getUTCDay(); // 0 = Sunday

    // Business hours: 8-18 UTC, Monday-Friday
    const isBusinessHours = hour >= 8 && hour <= 18 && day >= 1 && day <= 5;
    const userTimezone = user.timezone || "UTC";

    let score = 0;
    let reason = "";

    if (!isBusinessHours) {
      score = 25;
      reason = `Request outside business hours (UTC hour: ${hour}, day: ${day})`;
    } else {
      // Within business hours: score stays at its initial value of 0
      reason = "Request within business hours";
    }

    return {
      name: "timeAnomaly",
      score,
      weight: policy.weights.timeAnomaly,
      reason,
      details: { hour, day, isBusinessHours, userTimezone },
    };
  }

  private evaluateOperationCriticality(context: RiskContext): RiskFactor {
    const { operation, policy } = context;
    const multiplier = policy.operationRiskMultiplier[operation] ?? 1.0;

    // Only positive deviation from baseline (1.0) contributes to risk
    const score = Math.max(0, Math.min((multiplier - 1.0) * 50, 50));
    const reason = `Operation ${operation} has risk multiplier ${multiplier}`;

    return {
      name: "operationCriticality",
      score,
      weight: policy.weights.operationCriticality,
      reason,
      details: { operation, multiplier },
    };
  }

  private evaluateResourceCriticality(context: RiskContext): RiskFactor {
    const { resource, policy } = context;
    const multiplier = policy.criticalityRiskMultiplier[resource.criticality] ?? 1.0;

    // Only positive deviation from baseline (1.0) contributes to risk
    const score = Math.max(0, Math.min((multiplier - 1.0) * 50, 50));
    const reason = `Resource ${resource.id} criticality: ${resource.criticality} (multiplier: ${multiplier})`;

    return {
      name: "resourceCriticality",
      score,
      weight: policy.weights.resourceCriticality,
      reason,
      details: { resourceId: resource.id, criticality: resource.criticality, multiplier },
    };
  }

  private evaluatePestilloState(context: RiskContext): RiskFactor {
    const { pestilloState, policy } = context;
    const modifier = policy.pestilloModifiers[pestilloState] ?? 1.0;

    let score = 0;
    let reason = "";

    switch (pestilloState) {
      case "closed":
        score = 100; // Gate closed - max risk, no modifier
        reason = "Pestillo is CLOSED - access denied by policy";
        break;
      case "enabled":
        // Base score of 0; the modifier is applied below
        reason = "Pestillo is ENABLED - adaptive risk applies";
        break;
      case "step_up":
        score = 30; // Already requires step-up, no modifier
        reason = "Pestillo is STEP_UP - third factor mandatory";
        break;
      case "temporary":
        score = 20; // Base score, modifier will be applied
        reason = "Pestillo is TEMPORARY - time-bounded authorization";
        break;
    }

    // Apply modifier only for states where adaptive risk applies
    if (pestilloState === "enabled" || pestilloState === "temporary") {
      score = Math.round(score * modifier);
    }

    return {
      name: "pestilloState",
      score,
      weight: policy.weights.pestilloState,
      reason,
      details: { pestilloState, modifier },
    };
  }

  private evaluateHistoryDeviation(context: RiskContext): RiskFactor {
    const { history, policy } = context;

    if (!history) {
      return {
        name: "historyDeviation",
        score: 20,
        weight: policy.weights.historyDeviation,
        reason: "No historical data available",
        details: {},
      };
    }

    let score = 0;
    const reasons: string[] = [];

    if (history.recentFailedAttempts > 3) {
      score += 30;
      reasons.push(`${history.recentFailedAttempts} failed attempts in last hour`);
    }
    if (history.avgRiskScore > 50) {
      score += 20;
      reasons.push(`High average risk score (${history.avgRiskScore})`);
    }

    return {
      name: "historyDeviation",
      score: Math.min(score, 80),
      weight: policy.weights.historyDeviation,
      reason: reasons.join("; ") || "History within normal bounds",
      details: history,
    };
  }

  private evaluateVelocity(context: RiskContext): RiskFactor {
    const { clientContext, history, policy } = context;
    const velocity = policy.velocity;

    let score = 0;
    const reasons: string[] = [];

    // Check request rate (would need rate limiter integration)
    // This is a simplified check
    if (history?.recentSuccessfulOps && history.recentSuccessfulOps > velocity.maxRequestsPerMinute) {
      score += 25;
      reasons.push(`High request rate: ${history.recentSuccessfulOps}/min`);
    }

    // Check impossible travel
    if (clientContext.country && history?.knownCountries) {
      const lastLocation = this.lastKnownLocation.get(context.user.id);
      if (lastLocation && lastLocation.country !== clientContext.country) {
        // In a real implementation, calculate distance between countries
        // and compare with max travel speed
        score += 40;
        reasons.push(`Country change detected: ${lastLocation.country} → ${clientContext.country}`);
      }
    }

    return {
      name: "velocity",
      score: Math.min(score, 80),
      weight: policy.weights.velocity,
      reason: reasons.join("; ") || "Velocity within normal bounds",
      details: { velocityConfig: velocity },
    };
  }

  private calculateWeightedScore(factors: RiskFactor[]): number {
    let totalWeight = 0;
    let weightedSum = 0;

    for (const factor of factors) {
      weightedSum += factor.score * factor.weight;
      totalWeight += factor.weight;
    }

    return totalWeight > 0 ? weightedSum / totalWeight : 0;
  }

  private makeDecision(score: number, pestilloState: PestilloState): RiskDecision {
    const { thresholds } = this.policy;

    // Pestillo CLOSED always denies (except for auditing)
    if (pestilloState === "closed") {
      return "deny";
    }

    // Pestillo STEP_UP always requires challenge
    if (pestilloState === "step_up") {
      return "challenge";
    }

    // Score-based decision
    if (score <= thresholds.allow) {
      return "allow";
    } else if (score <= thresholds.challenge) {
      return "challenge";
    } else {
      return "deny";
    }
  }

  /**
   * Update policy at runtime
   */
  updatePolicy(partial: Partial<RiskPolicy>): void {
    this.policy = this.mergePolicy(this.policy, partial);
  }

  /**
   * Get current policy
   */
  getPolicy(): RiskPolicy {
    return { ...this.policy };
  }
}

/**
 * Singleton instance getter
 */
let _riskEngine: AdaptiveRiskEngine | null = null;

export function getRiskEngine(policy?: Partial<RiskPolicy>): AdaptiveRiskEngine {
  if (!_riskEngine) {
    _riskEngine = new AdaptiveRiskEngine(policy);
  }
  return _riskEngine;
}

export function setRiskEngine(engine: AdaptiveRiskEngine | null | undefined): void {
  _riskEngine = engine ?? null;
}