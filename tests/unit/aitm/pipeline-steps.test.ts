import { ExactMatchStep } from "../../../src/domain/services/aitm/steps/exact-match-step";
import { ConfusableDetectionStep } from "../../../src/domain/services/aitm/steps/confusable-detection-step";
import { TyposquattingStep } from "../../../src/domain/services/aitm/steps/typosquatting-step";

function origin(scheme: string, hostname: string, port?: number): string {
  const p = port ?? (scheme === "https" ? 443 : 80);
  return `${scheme}://${hostname}:${p}`;
}

describe("AITM Pipeline Steps", () => {
  describe("ExactMatchStep", () => {
    const step = new ExactMatchStep();

    it("has correct name", () => {
      expect(step.name).toBe("ExactMatch");
    });

    it("returns valid for exact origin match", async () => {
      const result = await step.execute(
        origin("https", "example.com", 443),
        origin("https", "example.com", 443)
      );
      expect(result.isValid).toBe(true);
      expect(result.riskLevel).toBe("low");
      expect(result.confidence).toBe(1.0);
      expect(result.strategy).toBe("ExactMatch");
    });

    it("normalizes case before matching", async () => {
      const result = await step.execute(
        origin("https", "EXAMPLE.COM", 443),
        origin("https", "example.com", 443)
      );
      expect(result.isValid).toBe(true);
    });

    it("handles trailing dot in hostname", async () => {
      const result = await step.execute(
        origin("https", "example.com.", 443),
        origin("https", "example.com", 443)
      );
      expect(result.isValid).toBe(true);
    });

    it("returns INVALID for subdomain (no subdomain matching)", async () => {
      const result = await step.execute(
        origin("https", "mail.example.com", 443),
        origin("https", "example.com", 443)
      );
      expect(result.isValid).toBe(false);
      expect(result.riskLevel).toBe("high");
      expect(result.confidence).toBe(1.0);
    });

    it("returns INVALID for www subdomain", async () => {
      const result = await step.execute(
        origin("https", "www.example.com", 443),
        origin("https", "example.com", 443)
      );
      expect(result.isValid).toBe(false);
      expect(result.riskLevel).toBe("high");
    });

    it("returns INVALID for different scheme (http vs https)", async () => {
      const result = await step.execute(
        origin("http", "example.com", 80),
        origin("https", "example.com", 443)
      );
      expect(result.isValid).toBe(false);
      expect(result.riskLevel).toBe("high");
    });

    it("returns INVALID for different port", async () => {
      const result = await step.execute(
        origin("https", "example.com", 8443),
        origin("https", "example.com", 443)
      );
      expect(result.isValid).toBe(false);
      expect(result.riskLevel).toBe("high");
    });

    it("returns invalid for non-matching domain", async () => {
      const result = await step.execute(
        origin("https", "evil.com", 443),
        origin("https", "example.com", 443)
      );
      expect(result.isValid).toBe(false);
      expect(result.riskLevel).toBe("high");
      expect(result.confidence).toBe(1.0);
    });

    it("returns invalid for similar but wrong domain", async () => {
      const result = await step.execute(
        origin("https", "examp1e.com", 443),
        origin("https", "example.com", 443)
      );
      expect(result.isValid).toBe(false);
      expect(result.riskLevel).toBe("high");
    });
  });

  describe("ConfusableDetectionStep", () => {
    const step = new ConfusableDetectionStep();

    it("has correct name", () => {
      expect(step.name).toBe("ConfusableDetection");
    });

    it("returns valid for clean domain", async () => {
      const result = await step.execute(
        origin("https", "google.com", 443),
        origin("https", "google.com", 443)
      );
      expect(result.isValid).toBe(true);
      expect(result.riskLevel).toBe("low");
      expect(result.evidence).toEqual([]);
    });

    it("returns invalid for Cyrillic attack domain", async () => {
      // gооgle.com with Cyrillic 'о' (U+043E)
      const result = await step.execute(
        origin("https", "g\u043E\u043Egle.com", 443),
        origin("https", "google.com", 443)
      );
      expect(result.isValid).toBe(false);
      expect(result.riskLevel).toBe("high");
      expect(result.evidence!.length).toBeGreaterThan(0);
    });

    it("returns invalid for Greek characters", async () => {
      // gοοgle.com with Greek omicron (U+03BF)
      const result = await step.execute(
        origin("https", "g\u03BF\u03BFgle.com", 443),
        origin("https", "google.com", 443)
      );
      expect(result.isValid).toBe(false);
      expect(result.riskLevel).toBe("medium");
    });

    it("strips zero-width characters before detection", async () => {
      const result = await step.execute(
        origin("https", "g\u200Boogle.com", 443),
        origin("https", "google.com", 443)
      );
      expect(result.isValid).toBe(true);
    });

    it("returns high risk for mixed Cyrillic/Latin", async () => {
      const result = await step.execute(
        origin("https", "g\u043E\u043Egle.com", 443),
        origin("https", "google.com", 443)
      );
      expect(result.riskLevel).toBe("high");
      expect(result.confidence).toBe(0.95);
    });
  });

  describe("TyposquattingStep", () => {
    it("has correct name", () => {
      const step = new TyposquattingStep();
      expect(step.name).toBe("LevenshteinTypoSquatting");
    });

    it("returns valid for exact registrable domain match", async () => {
      const step = new TyposquattingStep();
      const result = await step.execute(
        origin("https", "google.com", 443),
        origin("https", "google.com", 443)
      );
      expect(result.isValid).toBe(true);
      expect(result.distance).toBe(0);
      expect(result.riskLevel).toBe("low");
    });

    it("returns invalid for very similar domain above threshold", async () => {
      // "goggle" vs "google" similarity ≈ 0.833; use threshold 0.80 so it's above
      const step = new TyposquattingStep(0.80);
      const result = await step.execute(
        origin("https", "goggle.com", 443),
        origin("https", "google.com", 443)
      );
      expect(result.isValid).toBe(false);
      expect(result.riskLevel).toBe("high");
      expect(result.distance).toBeGreaterThan(0);
    });

    it("returns valid for very different domain below threshold", async () => {
      const step = new TyposquattingStep(0.85);
      const result = await step.execute(
        origin("https", "amazon.com", 443),
        origin("https", "google.com", 443)
      );
      expect(result.isValid).toBe(true);
      expect(result.riskLevel).toBe("low");
    });

    it("strips common TLDs before comparison", async () => {
      const step = new TyposquattingStep(0.85);
      // Both resolve to registrable "google"
      const result = await step.execute(
        origin("https", "google.com", 443),
        origin("https", "google.org", 443)
      );
      expect(result.isValid).toBe(true);
      expect(result.distance).toBe(0);
    });

    it("respects custom threshold", async () => {
      const strictStep = new TyposquattingStep(0.95);
      const looseStep = new TyposquattingStep(0.5);

      // "goggle" vs "google" ~ 0.83 similarity
      const strict = await strictStep.execute(
        origin("https", "goggle.com", 443),
        origin("https", "google.com", 443)
      );
      expect(strict.isValid).toBe(true); // below strict threshold

      const loose = await looseStep.execute(
        origin("https", "goggle.com", 443),
        origin("https", "google.com", 443)
      );
      expect(loose.isValid).toBe(false); // above loose threshold
    });

    it("handles subdomains extracting registrable domain", async () => {
      const step = new TyposquattingStep(0.85);
      const result = await step.execute(
        origin("https", "mail.google.com", 443),
        origin("https", "google.com", 443)
      );
      expect(result.isValid).toBe(true);
      expect(result.distance).toBe(0);
    });
  });
});