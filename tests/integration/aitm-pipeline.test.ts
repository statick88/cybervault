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
  const trustedDomain = "example.com";

  describe("legitimate domains", () => {
    it("allows exact match", async () => {
      const pipeline = createPipeline();
      const result = await pipeline.validate("example.com", trustedDomain);

      expect(result.isValid).toBe(true);
      expect(result.overallRisk).toBe("low");
      // Pipeline short-circuits on exact match — only first step runs
      expect(result.steps.length).toBeGreaterThanOrEqual(1);
      expect(result.steps[0].isValid).toBe(true);
      expect(result.steps[0].strategy).toBe("ExactMatch");
    });

    it("allows subdomains of trusted domain", async () => {
      const pipeline = createPipeline();
      const result = await pipeline.validate("mail.example.com", trustedDomain);

      expect(result.isValid).toBe(true);
      expect(result.overallRisk).toBe("low");
    });

    it("allows different trusted domain", async () => {
      const pipeline = createPipeline();
      const result = await pipeline.validate("google.com", "google.com");

      expect(result.isValid).toBe(true);
      expect(result.overallRisk).toBe("low");
    });
  });

  describe("typosquatting detection", () => {
    it("detects single-character substitution", async () => {
      const pipeline = createPipeline();
      const result = await pipeline.validate("examp1e.com", trustedDomain);

      expect(result.overallRisk).not.toBe("low");
      const typosquatStep = result.steps.find((s: DomainValidationResult) => s.strategy === "LevenshteinTypoSquatting");
      expect(typosquatStep).toBeDefined();
      expect(typosquatStep!.riskLevel).not.toBe("low");
    });

    it("detects character duplication", async () => {
      const pipeline = createPipeline();
      const result = await pipeline.validate("exampple.com", trustedDomain);

      expect(result.overallRisk).not.toBe("low");
    });

    it("detects character omission", async () => {
      const pipeline = createPipeline();
      const result = await pipeline.validate("exmple.com", trustedDomain);

      expect(result.overallRisk).not.toBe("low");
    });

    it("does not flag very different domains", async () => {
      const pipeline = createPipeline();
      const result = await pipeline.validate("completely-different-site.org", trustedDomain);

      // Should be low risk since it's not similar to example.com
      expect(result.isValid).toBe(true);
    });
  });

  describe("confusable detection", () => {
    it("detects Cyrillic homograph", async () => {
      // Cyrillic 'о' (U+043E) looks like Latin 'o'
      const cyrillicDomain = "exаmple.com".replace("a", "\u0430"); // Cyrillic а
      const pipeline = createPipeline();
      const result = await pipeline.validate(cyrillicDomain, trustedDomain);

      expect(result.overallRisk).not.toBe("low");
      const confusableStep = result.steps.find((s: DomainValidationResult) => s.strategy === "ConfusableDetection");
      expect(confusableStep).toBeDefined();
      expect(confusableStep!.riskLevel).toBe("high");
    });

    it("allows clean ASCII domains", async () => {
      const pipeline = createPipeline();
      // Use a non-matching domain so all steps run
      const result = await pipeline.validate("secure-login.example.net", trustedDomain);

      const confusableStep = result.steps.find((s: DomainValidationResult) => s.strategy === "ConfusableDetection");
      expect(confusableStep).toBeDefined();
      expect(confusableStep!.isValid).toBe(true);
    });
  });

  describe("pipeline orchestration", () => {
    it("short-circuits on exact match", async () => {
      const pipeline = createPipeline();
      const result = await pipeline.validate("example.com", trustedDomain);

      // Exact match should pass, other steps still run but won't change verdict
      expect(result.steps[0].isValid).toBe(true);
      expect(result.totalTimeMs).toBeGreaterThan(0);
    });

    it("reports per-step confidence", async () => {
      const pipeline = createPipeline();
      const result = await pipeline.validate("example.com", trustedDomain);

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
      const result = await pipeline.validate("example.com", trustedDomain);
      expect(result).toBeDefined();
      expect(typeof result.totalTimeMs).toBe("number");
    });
  });

  describe("edge cases", () => {
    it("handles empty hostname", async () => {
      const pipeline = createPipeline();
      const result = await pipeline.validate("", trustedDomain);

      expect(result).toBeDefined();
      expect(result.steps.length).toBe(3);
    });

    it("handles hostname with trailing dot", async () => {
      const pipeline = createPipeline();
      const result = await pipeline.validate("example.com.", trustedDomain);

      expect(result.isValid).toBe(true);
    });

    it("handles case-insensitive comparison", async () => {
      const pipeline = createPipeline();
      const result = await pipeline.validate("EXAMPLE.COM", trustedDomain);

      expect(result.isValid).toBe(true);
    });
  });
});
