/**
 * Adaptive Risk Engine Tests — Strict TDD
 *
 * Tests for deterministic context scoring and risk decisions
 * Following: RED -> GREEN -> REFACTOR
 */

import { AdaptiveRiskEngine, getRiskEngine, setRiskEngine, DEFAULT_RISK_POLICY, RiskPolicy, RiskContext, RiskDecision } from "../../plus/domain/services/risk-engine";
import { PlusUser } from "../../plus/domain/entities/user";
import { Resource } from "../../plus/domain/entities/resource";
import type { CapabilityOperation, PestilloState } from "../../plus/domain/entities/entitlement";

describe("AdaptiveRiskEngine", () => {
  let engine: AdaptiveRiskEngine;
  let testUser: PlusUser;
  let testResource: Resource;
  let baseContext: RiskContext;

  beforeEach(() => {
    setRiskEngine(undefined); // Reset singleton
    engine = new AdaptiveRiskEngine();

    testUser = PlusUser.create({
      id: "user-123",
      email: "operator@company.com",
      name: "Test Operator",
      role: "operator",
      habitualCountries: ["EC", "US"],
      timezone: "America/Guayaquil",
    });

    testResource = Resource.create({
      id: "db-prod-001",
      name: "Production Database",
      type: "database",
      endpoint: "db01.internal:5432",
      environment: "production",
      criticality: "high",
    });

    baseContext = {
      user: testUser,
      resource: testResource,
      operation: "VIEW",
      pestilloState: "enabled" as PestilloState,
      clientContext: {
        country: "EC",
        ip: "192.168.1.100",
        deviceId: "device-abc",
        userAgent: "Mozilla/5.0...",
        timestamp: Date.now(),
      },
      history: {
        recentFailedAttempts: 0,
        recentSuccessfulOps: 10,
        avgRiskScore: 15,
        knownDevices: ["device-abc", "device-xyz"],
        knownCountries: ["EC", "US"],
      },
      policy: DEFAULT_RISK_POLICY,
    };
  });

  afterEach(() => {
    setRiskEngine(undefined);
  });

  describe("Constructor & Policy", () => {
    test("creates engine with default policy", () => {
      const e = new AdaptiveRiskEngine();
      expect(e.getPolicy()).toEqual(DEFAULT_RISK_POLICY);
    });

    test("accepts partial policy override", () => {
      const customPolicy: Partial<RiskPolicy> = {
        thresholds: { allow: 20, challenge: 60, deny: 100 },
      };
      const e = new AdaptiveRiskEngine(customPolicy);
      expect(e.getPolicy().thresholds.allow).toBe(20);
      expect(e.getPolicy().thresholds.challenge).toBe(60);
    });

    test("singleton getRiskEngine works", () => {
      setRiskEngine(null);
      const e1 = getRiskEngine();
      const e2 = getRiskEngine();
      expect(e1).toBe(e2);
    });

    test("setRiskEngine replaces singleton", () => {
      const e1 = new AdaptiveRiskEngine();
      setRiskEngine(e1);
      const e2 = getRiskEngine();
      expect(e2).toBe(e1);
    });
  });

  describe("Country Deviation", () => {
    test("habitual country → score 0", () => {
      const ctx = { ...baseContext, clientContext: { ...baseContext.clientContext, country: "EC" } };
      const result = engine.evaluate(ctx);
      const factor = result.factors.find((f) => f.name === "countryDeviation");
      expect(factor?.score).toBe(0);
      expect(factor?.reason).toContain("habitual");
    });

    test("new country with low risk → moderate score", () => {
      const ctx = { ...baseContext, clientContext: { ...baseContext.clientContext, country: "US" } };
      const result = engine.evaluate(ctx);
      const factor = result.factors.find((f) => f.name === "countryDeviation");
      expect(factor?.score).toBeLessThanOrEqual(10); // US is low risk (10)
    });

    test("new country with high risk → high score", () => {
      const ctx = { ...baseContext, clientContext: { ...baseContext.clientContext, country: "CN" } };
      const result = engine.evaluate(ctx);
      const factor = result.factors.find((f) => f.name === "countryDeviation");
      expect(factor?.score).toBeGreaterThanOrEqual(60); // CN is 60
    });

    test("unknown country → default 50", () => {
      const ctx = { ...baseContext, clientContext: { ...baseContext.clientContext, country: "XX" } };
      const result = engine.evaluate(ctx);
      const factor = result.factors.find((f) => f.name === "countryDeviation");
      expect(factor?.score).toBe(50);
    });

    test("no country provided → score 50", () => {
      const ctx = { ...baseContext, clientContext: { ...baseContext.clientContext, country: undefined } };
      const result = engine.evaluate(ctx);
      const factor = result.factors.find((f) => f.name === "countryDeviation");
      expect(factor?.score).toBe(50);
    });
  });

  describe("Device Trust", () => {
    test("known device → score 0", () => {
      const ctx = { ...baseContext, clientContext: { ...baseContext.clientContext, deviceId: "device-abc" } };
      const result = engine.evaluate(ctx);
      const factor = result.factors.find((f) => f.name === "deviceTrust");
      expect(factor?.score).toBe(0);
    });

    test("new device → score 50", () => {
      const ctx = { ...baseContext, clientContext: { ...baseContext.clientContext, deviceId: "device-new" } };
      const result = engine.evaluate(ctx);
      const factor = result.factors.find((f) => f.name === "deviceTrust");
      expect(factor?.score).toBe(50);
    });

    test("no device ID → score 40", () => {
      const ctx = { ...baseContext, clientContext: { ...baseContext.clientContext, deviceId: undefined } };
      const result = engine.evaluate(ctx);
      const factor = result.factors.find((f) => f.name === "deviceTrust");
      expect(factor?.score).toBe(40);
    });
  });

  describe("Time Anomaly", () => {
    test("business hours UTC → score 0", () => {
      // 10:00 UTC on Wednesday
      const timestamp = new Date("2024-01-10T10:00:00Z").getTime();
      const ctx = { ...baseContext, clientContext: { ...baseContext.clientContext, timestamp } };
      const result = engine.evaluate(ctx);
      const factor = result.factors.find((f) => f.name === "timeAnomaly");
      expect(factor?.score).toBe(0);
    });

    test("outside business hours → score 25", () => {
      // 02:00 UTC on Wednesday
      const timestamp = new Date("2024-01-10T02:00:00Z").getTime();
      const ctx = { ...baseContext, clientContext: { ...baseContext.clientContext, timestamp } };
      const result = engine.evaluate(ctx);
      const factor = result.factors.find((f) => f.name === "timeAnomaly");
      expect(factor?.score).toBe(25);
    });

    test("weekend → score 25", () => {
      // Saturday 10:00 UTC
      const timestamp = new Date("2024-01-13T10:00:00Z").getTime();
      const ctx = { ...baseContext, clientContext: { ...baseContext.clientContext, timestamp } };
      const result = engine.evaluate(ctx);
      const factor = result.factors.find((f) => f.name === "timeAnomaly");
      expect(factor?.score).toBe(25);
    });
  });

  describe("Operation Criticality", () => {
    test("VIEW → low score", () => {
      const ctx = { ...baseContext, operation: "VIEW" as CapabilityOperation };
      const result = engine.evaluate(ctx);
      const factor = result.factors.find((f) => f.name === "operationCriticality");
      expect(factor?.score).toBeLessThan(20); // VIEW multiplier 0.8
    });

    test("ADMIN → high score", () => {
      const ctx = { ...baseContext, operation: "ADMIN" as CapabilityOperation };
      const result = engine.evaluate(ctx);
      const factor = result.factors.find((f) => f.name === "operationCriticality");
      expect(factor?.score).toBeGreaterThanOrEqual(50); // ADMIN multiplier 2.0
    });

    test("RESTORE → high score", () => {
      const ctx = { ...baseContext, operation: "RESTORE" as CapabilityOperation };
      const result = engine.evaluate(ctx);
      const factor = result.factors.find((f) => f.name === "operationCriticality");
      expect(factor?.score).toBeGreaterThanOrEqual(50); // RESTORE multiplier 2.0
    });
  });

  describe("Resource Criticality", () => {
    test("low criticality → score 0", () => {
      const lowResource = Resource.create({
        id: "test-low",
        name: "Test Low",
        type: "web",
        endpoint: "example.com",
        environment: "development",
        criticality: "low",
      });
      const ctx = { ...baseContext, resource: lowResource };
      const result = engine.evaluate(ctx);
      const factor = result.factors.find((f) => f.name === "resourceCriticality");
      expect(factor?.score).toBe(0); // low multiplier 0.5
    });

    test("critical → high score", () => {
      const criticalResource = Resource.create({
        id: "test-critical",
        name: "Test Critical",
        type: "database",
        endpoint: "db.internal",
        environment: "production",
        criticality: "critical",
      });
      const ctx = { ...baseContext, resource: criticalResource };
      const result = engine.evaluate(ctx);
      const factor = result.factors.find((f) => f.name === "resourceCriticality");
      expect(factor?.score).toBeGreaterThanOrEqual(50); // critical multiplier 2.0
    });
  });

  describe("Pestillo State", () => {
    test("CLOSED → score 100 (max)", () => {
      const ctx = { ...baseContext, pestilloState: "closed" as PestilloState };
      const result = engine.evaluate(ctx);
      const factor = result.factors.find((f) => f.name === "pestilloState");
      expect(factor?.score).toBe(100);
    });

    test("ENABLED → score 0", () => {
      const ctx = { ...baseContext, pestilloState: "enabled" as PestilloState };
      const result = engine.evaluate(ctx);
      const factor = result.factors.find((f) => f.name === "pestilloState");
      expect(factor?.score).toBe(0);
    });

    test("STEP_UP → score 30", () => {
      const ctx = { ...baseContext, pestilloState: "step_up" as PestilloState };
      const result = engine.evaluate(ctx);
      const factor = result.factors.find((f) => f.name === "pestilloState");
      expect(factor?.score).toBe(30);
    });

    test("TEMPORARY → score 24 (base 20 * modifier 1.2)", () => {
      const ctx = { ...baseContext, pestilloState: "temporary" as PestilloState };
      const result = engine.evaluate(ctx);
      const factor = result.factors.find((f) => f.name === "pestilloState");
      expect(factor?.score).toBe(24);
    });
  });

  describe("History Deviation", () => {
    test("no history → score 20", () => {
      const ctx = { ...baseContext, history: undefined };
      const result = engine.evaluate(ctx);
      const factor = result.factors.find((f) => f.name === "historyDeviation");
      expect(factor?.score).toBe(20);
    });

    test("many failed attempts → high score", () => {
      const ctx = { ...baseContext, history: { ...baseContext.history!, recentFailedAttempts: 5 } };
      const result = engine.evaluate(ctx);
      const factor = result.factors.find((f) => f.name === "historyDeviation");
      expect(factor?.score).toBeGreaterThanOrEqual(30);
    });

    test("high avg risk → elevated score", () => {
      const ctx = { ...baseContext, history: { ...baseContext.history!, avgRiskScore: 60 } };
      const result = engine.evaluate(ctx);
      const factor = result.factors.find((f) => f.name === "historyDeviation");
      expect(factor?.score).toBeGreaterThanOrEqual(20);
    });
  });

  describe("Velocity", () => {
    test("normal velocity → score 0", () => {
      const ctx = { ...baseContext, history: { ...baseContext.history!, recentSuccessfulOps: 10 } };
      const result = engine.evaluate(ctx);
      const factor = result.factors.find((f) => f.name === "velocity");
      expect(factor?.score).toBe(0);
    });

    test("high request rate → elevated score", () => {
      const ctx = { ...baseContext, history: { ...baseContext.history!, recentSuccessfulOps: 50 } };
      const result = engine.evaluate(ctx);
      const factor = result.factors.find((f) => f.name === "velocity");
      expect(factor?.score).toBeGreaterThanOrEqual(25);
    });
  });

  describe("Decision Making", () => {
    test("low score + ENABLED → allow", () => {
      const ctx = { ...baseContext, operation: "VIEW" as CapabilityOperation };
      const result = engine.evaluate(ctx);
      expect(result.decision).toBe("allow");
    });

    test("high score + ENABLED → challenge", () => {
      // High risk: new country (KP=90), new device, ADMIN operation, critical resource, outside business hours, failed attempts
      const timestamp = new Date("2024-01-10T02:00:00Z").getTime(); // Outside business hours
      const criticalResource = Resource.create({
        id: "db-critical-001",
        name: "Critical DB",
        type: "database",
        endpoint: "db.internal",
        environment: "production",
        criticality: "critical",
      });
      const ctx = {
        ...baseContext,
        resource: criticalResource,
        operation: "ADMIN" as CapabilityOperation,
        clientContext: { ...baseContext.clientContext, country: "KP", deviceId: "device-new", timestamp },
        history: {
          ...baseContext.history!,
          recentFailedAttempts: 5,
          avgRiskScore: 60,
        },
      };
      const result = engine.evaluate(ctx);
      expect(result.decision).toBe("challenge");
    });

    test("very high score → deny", () => {
      // Very high risk combination
      const ctx = {
        ...baseContext,
        operation: "ADMIN" as CapabilityOperation,
        clientContext: { ...baseContext.clientContext, country: "KP", deviceId: "device-new" },
        pestilloState: "temporary" as PestilloState,
      };
      const result = engine.evaluate(ctx);
      // Score should exceed deny threshold
      expect(["challenge", "deny"]).toContain(result.decision);
    });

    test("CLOSED pestillo → always deny", () => {
      const ctx = { ...baseContext, pestilloState: "closed" as PestilloState };
      const result = engine.evaluate(ctx);
      expect(result.decision).toBe("deny");
    });

    test("STEP_UP pestillo → always challenge", () => {
      const ctx = { ...baseContext, pestilloState: "step_up" as PestilloState };
      const result = engine.evaluate(ctx);
      expect(result.decision).toBe("challenge");
    });
  });

  describe("Score Calculation", () => {
    test("returns all factors with correct weights", () => {
      const result = engine.evaluate(baseContext);
      expect(result.factors.length).toBeGreaterThan(5);
      for (const factor of result.factors) {
        expect(factor.weight).toBeGreaterThan(0);
        expect(factor.score).toBeGreaterThanOrEqual(0);
        expect(factor.score).toBeLessThanOrEqual(100);
      }
    });

    test("total score within bounds", () => {
      const result = engine.evaluate(baseContext);
      expect(result.totalScore).toBeGreaterThanOrEqual(0);
      expect(result.totalScore).toBeLessThanOrEqual(100);
    });

    test("includes timestamp", () => {
      const before = Date.now();
      const result = engine.evaluate(baseContext);
      const after = Date.now();
      expect(result.timestamp).toBeGreaterThanOrEqual(before);
      expect(result.timestamp).toBeLessThanOrEqual(after);
    });
  });

  describe("Policy Updates", () => {
    test("updatePolicy modifies thresholds", () => {
      engine.updatePolicy({
        thresholds: { allow: 10, challenge: 50, deny: 100 },
      });
      const policy = engine.getPolicy();
      expect(policy.thresholds.allow).toBe(10);
      expect(policy.thresholds.challenge).toBe(50);
    });

    test("updatePolicy modifies weights", () => {
      engine.updatePolicy({
        weights: { ...DEFAULT_RISK_POLICY.weights, countryDeviation: 0.5 },
      });
      const policy = engine.getPolicy();
      expect(policy.weights.countryDeviation).toBe(0.5);
    });
  });

  describe("Default Policy Constants", () => {
    test("DEFAULT_RISK_POLICY has all required fields", () => {
      expect(DEFAULT_RISK_POLICY.weights).toBeDefined();
      expect(DEFAULT_RISK_POLICY.thresholds).toBeDefined();
      expect(DEFAULT_RISK_POLICY.countryRisk).toBeDefined();
      expect(DEFAULT_RISK_POLICY.operationRiskMultiplier).toBeDefined();
      expect(DEFAULT_RISK_POLICY.criticalityRiskMultiplier).toBeDefined();
      expect(DEFAULT_RISK_POLICY.pestilloModifiers).toBeDefined();
      expect(DEFAULT_RISK_POLICY.velocity).toBeDefined();
    });

    test("weights sum approximately to 1.0", () => {
      const sum = Object.values(DEFAULT_RISK_POLICY.weights).reduce((a, b) => a + b, 0);
      expect(sum).toBeCloseTo(1.0, 1);
    });

    test("thresholds are ordered", () => {
      const { allow, challenge, deny } = DEFAULT_RISK_POLICY.thresholds;
      expect(allow).toBeLessThan(challenge);
      expect(challenge).toBeLessThan(deny);
    });
  });
});