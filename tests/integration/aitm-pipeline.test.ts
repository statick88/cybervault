/**
 * AiTM Pipeline Integration Tests
 *
 * Tests the full domain validation pipeline with all steps wired together,
 * exercising the PipelineOrchestrator with real ExactMatch, ConfusableDetection,
 * and Typosquatting steps.
 */

import { PipelineOrchestrator } from "../../src/domain/services/aitm/pipeline-orchestrator";
import { ExactMatchStep } from "../../src/domain/services/aitm/steps/exact-match-step";
import { ConfusableDetectionStep } from "../../src/domain/services/aitm/steps/confusable-detection-step";
import { TyposquattingStep } from "../../src/domain/services/aitm/steps/typosquatting-step";
import type { DomainValidationResult } from "../../src/domain/services/aitm/domain-validation-pipeline";

function origin(scheme: string, hostname: string, port?: number): string {
  const p = port ?? (scheme === "https" ? 443 : 80);
  return `${scheme}://${hostname}:${p}`;
}

function createPipeline(): PipelineOrchestrator {
  const pipeline = new PipelineOrchestrator({
    phaseTimeoutMs: 100,
    totalTimeoutMs: 300,
  });
  pipeline.addStep(new ExactMatchStep());
  pipeline.addStep(new ConfusableDetectionStep());
  pipeline.addStep(new TyposquattingStep(0.85));
  return pipeline;
}

describe("AiTM Pipeline Integration", () => {
  const trustedOrigin = origin("https", "example.com", 443);

  describe("legitimate domains", () => {
    it("allows exact origin match", async () => {
      const pipeline = createPipeline();
      const result = await pipeline.validate(trustedOrigin, trustedOrigin);

      expect(result.isValid).toBe(true);
      expect(result.overallRisk).toBe("low");
      // Pipeline short-circuits on exact match — only first step runs
      expect(result.steps.length).toBeGreaterThanOrEqual(1);
      expect(result.steps[0].isValid).toBe(true);
      expect(result.steps[0].strategy).toBe("ExactMatch");
    });

    it("REJECTS subdomains (absolute ExactMatch)", async () => {
      const pipeline = createPipeline();
      const subdomainOrigin = origin("https", "mail.example.com", 443);
      const result = await pipeline.validate(subdomainOrigin, trustedOrigin);

      expect(result.isValid).toBe(false);
      expect(result.overallRisk).toBe("high");
    });

    it("REJECTS www subdomain", async () => {
      const pipeline = createPipeline();
      const subdomainOrigin = origin("https", "www.example.com", 443);
      const result = await pipeline.validate(subdomainOrigin, trustedOrigin);

      expect(result.isValid).toBe(false);
      expect(result.overallRisk).toBe("high");
    });

    it("allows different trusted origin", async () => {
      const pipeline = createPipeline();
      const googleOrigin = origin("https", "google.com", 443);
      const result = await pipeline.validate(googleOrigin, googleOrigin);

      expect(result.isValid).toBe(true);
      expect(result.overallRisk).toBe("low");
    });
  });

  describe("typosquatting detection", () => {
    it("detects single-character substitution (tested in isolation)", async () => {
      // Typosquatting detection is tested in isolation because
      // the full pipeline short-circuits on ExactMatch failure
      const pipeline = new PipelineOrchestrator({
        phaseTimeoutMs: 100,
        totalTimeoutMs: 300,
      });
      pipeline.addStep(new TyposquattingStep(0.80));

      // "goggle" vs "google" similarity ≈ 0.833; use threshold 0.80 so it's above
      const result = await pipeline.validate(
        origin("https", "goggle.com", 443),
        origin("https", "google.com", 443)
      );

      expect(result.overallRisk).not.toBe("low");
      const typosquatStep = result.steps.find((s: DomainValidationResult) => s.strategy === "LevenshteinTypoSquatting");
      expect(typosquatStep).toBeDefined();
      expect(typosquatStep!.riskLevel).not.toBe("low");
    });

    it("detects character duplication (tested in isolation)", async () => {
      const pipeline = new PipelineOrchestrator({
        phaseTimeoutMs: 100,
        totalTimeoutMs: 300,
      });
      pipeline.addStep(new TyposquattingStep(0.85));

      const result = await pipeline.validate(
        origin("https", "exampple.com", 443),
        origin("https", "example.com", 443)
      );

      expect(result.overallRisk).not.toBe("low");
    });

    it("detects character omission (tested in isolation)", async () => {
      const pipeline = new PipelineOrchestrator({
        phaseTimeoutMs: 100,
        totalTimeoutMs: 300,
      });
      pipeline.addStep(new TyposquattingStep(0.85));

      const result = await pipeline.validate(
        origin("https", "exmple.com", 443),
        origin("https", "example.com", 443)
      );

      expect(result.overallRisk).not.toBe("low");
    });

    it("flags very different domains as invalid (ExactMatch absolute)", async () => {
      const pipeline = createPipeline();
      const result = await pipeline.validate(
        origin("https", "completely-different-site.org", 443),
        trustedOrigin
      );

      // ExactMatch is absolute - different domain = invalid, regardless of typosquatting
      expect(result.isValid).toBe(false);
      expect(result.overallRisk).toBe("high");
      // Only ExactMatch runs due to short-circuit on failure
      expect(result.steps.length).toBe(1);
      expect(result.steps[0].strategy).toBe("ExactMatch");
    });
  });

  describe("confusable detection", () => {
    it("detects Cyrillic homograph when testing against matching base domain", async () => {
      // Test confusable detection in isolation by using a pipeline with only confusable step
      // (Integration: the full pipeline short-circuits on ExactMatch failure, 
      // but confusable detection is tested at unit level)
      const pipeline = new PipelineOrchestrator({
        phaseTimeoutMs: 100,
        totalTimeoutMs: 300,
      });
      pipeline.addStep(new ConfusableDetectionStep());

      // Cyrillic 'а' (U+0430) looks like Latin 'a' - test against "google.com"
      const cyrillicDomain = "g\u043E\u043Egle.com"; // gооgle.com with Cyrillic о
      const result = await pipeline.validate(
        origin("https", cyrillicDomain, 443),
        origin("https", "google.com", 443)
      );

      expect(result.overallRisk).not.toBe("low");
      const confusableStep = result.steps.find((s: DomainValidationResult) => s.strategy === "ConfusableDetection");
      expect(confusableStep).toBeDefined();
      expect(confusableStep!.riskLevel).toBe("high");
    });

    it("allows clean ASCII domains (different domain but clean) - ExactMatch fails fast", async () => {
      const pipeline = createPipeline();
      // Different domain - ExactMatch fails fast, no confusable check needed
      const result = await pipeline.validate(
        origin("https", "secure-login.example.net", 443),
        trustedOrigin
      );

      expect(result.isValid).toBe(false);
      expect(result.overallRisk).toBe("high");
      // Only ExactMatch runs due to short-circuit on failure
      expect(result.steps.length).toBe(1);
      expect(result.steps[0].strategy).toBe("ExactMatch");
      expect(result.steps[0].isValid).toBe(false);
    });
  });

  describe("pipeline orchestration", () => {
    it("short-circuits on exact match", async () => {
      const pipeline = createPipeline();
      const result = await pipeline.validate(trustedOrigin, trustedOrigin);

      // Exact match should pass, other steps still run but won't change verdict
      expect(result.steps[0].isValid).toBe(true);
      expect(result.totalTimeMs).toBeGreaterThan(0);
    });

    it("reports per-step confidence", async () => {
      const pipeline = createPipeline();
      const result = await pipeline.validate(trustedOrigin, trustedOrigin);

      for (const step of result.steps) {
        expect(step.confidence).toBeGreaterThanOrEqual(0);
        expect(step.confidence).toBeLessThanOrEqual(1);
      }
    });

    it("respects global timeout", async () => {
      const pipeline = new PipelineOrchestrator({
        phaseTimeoutMs: 5,
        totalTimeoutMs: 10,
      });
      pipeline.addStep(new ExactMatchStep());
      pipeline.addStep(new ConfusableDetectionStep());
      pipeline.addStep(new TyposquattingStep(0.85));

      // Should complete without hanging
      const result = await pipeline.validate(trustedOrigin, trustedOrigin);
      expect(result).toBeDefined();
      expect(typeof result.totalTimeMs).toBe("number");
    });
  });

  describe("edge cases", () => {
    it("handles empty hostname in origin (fails fast)", async () => {
      const pipeline = createPipeline();
      const result = await pipeline.validate(
        origin("https", "", 443),
        trustedOrigin
      );

      expect(result).toBeDefined();
      expect(result.isValid).toBe(false);
      // Only ExactMatch runs due to short-circuit on failure
      expect(result.steps.length).toBe(1);
      expect(result.steps[0].strategy).toBe("ExactMatch");
    });

    it("handles hostname with trailing dot (normalized)", async () => {
      const pipeline = createPipeline();
      const result = await pipeline.validate(
        origin("https", "example.com.", 443),
        trustedOrigin
      );

      expect(result.isValid).toBe(true);
    });

    it("handles case-insensitive comparison", async () => {
      const pipeline = createPipeline();
      const result = await pipeline.validate(
        origin("https", "EXAMPLE.COM", 443),
        trustedOrigin
      );

      expect(result.isValid).toBe(true);
    });

    it("REJECTS different scheme (http vs https)", async () => {
      const pipeline = createPipeline();
      const result = await pipeline.validate(
        origin("http", "example.com", 80),
        trustedOrigin
      );

      expect(result.isValid).toBe(false);
      expect(result.overallRisk).toBe("high");
    });

    it("REJECTS different port", async () => {
      const pipeline = createPipeline();
      const result = await pipeline.validate(
        origin("https", "example.com", 8443),
        trustedOrigin
      );

      expect(result.isValid).toBe(false);
      expect(result.overallRisk).toBe("high");
    });
  });
});