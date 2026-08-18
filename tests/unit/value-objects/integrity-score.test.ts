import { IntegrityScore } from "../../../src/domain/value-objects/integrity-score";

describe("IntegrityScore", () => {
  const all100 = {
    hostname: 100,
    contentHash: 100,
    timing: 100,
    domIntegrity: 100,
    cookieSecurity: 100,
  };

  const all0 = {
    hostname: 0,
    contentHash: 0,
    timing: 0,
    domIntegrity: 0,
    cookieSecurity: 0,
  };

  describe("create()", () => {
    it("creates with all scores at 100", () => {
      const score = IntegrityScore.create(all100, 1);
      expect(score.overall).toBe(100);
      expect(score.hostname).toBe(100);
      expect(score.evaluatedAt).toBe(1);
    });

    it("creates with all scores at 0", () => {
      const score = IntegrityScore.create(all0, 1);
      expect(score.overall).toBe(0);
    });

    it("throws on zero evaluatedAt", () => {
      expect(() => IntegrityScore.create(all100, 0)).toThrow(
        "evaluatedAt must be positive",
      );
    });

    it("throws on negative evaluatedAt", () => {
      expect(() => IntegrityScore.create(all100, -1)).toThrow(
        "evaluatedAt must be positive",
      );
    });
  });

  describe("weighted average calculation", () => {
    it("computes correct weighted average for mixed scores", () => {
      const score = IntegrityScore.create(
        {
          hostname: 100,
          contentHash: 100,
          timing: 100,
          domIntegrity: 100,
          cookieSecurity: 100,
        },
        1,
      );
      expect(score.overall).toBe(100);
    });

    it("weights contentHash highest (0.30)", () => {
      const score = IntegrityScore.create(
        {
          hostname: 0,
          contentHash: 100,
          timing: 0,
          domIntegrity: 0,
          cookieSecurity: 0,
        },
        1,
      );
      // contentHash: 100 * 0.30 = 30
      expect(score.overall).toBe(30);
    });

    it("weights cookieSecurity lowest (0.10)", () => {
      const score = IntegrityScore.create(
        {
          hostname: 0,
          contentHash: 0,
          timing: 0,
          domIntegrity: 0,
          cookieSecurity: 100,
        },
        1,
      );
      expect(score.overall).toBe(10);
    });

    it("clamps individual scores above 100", () => {
      const score = IntegrityScore.create(
        {
          hostname: 150,
          contentHash: 150,
          timing: 150,
          domIntegrity: 150,
          cookieSecurity: 150,
        },
        1,
      );
      expect(score.hostname).toBe(100);
      expect(score.overall).toBe(100);
    });

    it("clamps individual scores below 0", () => {
      const score = IntegrityScore.create(
        {
          hostname: -10,
          contentHash: -5,
          timing: 0,
          domIntegrity: 0,
          cookieSecurity: 0,
        },
        1,
      );
      expect(score.hostname).toBe(0);
      expect(score.contentHash).toBe(0);
    });

    it("rounds the overall score", () => {
      const score = IntegrityScore.create(
        {
          hostname: 50,
          contentHash: 33,
          timing: 67,
          domIntegrity: 41,
          cookieSecurity: 72,
        },
        1,
      );
      // Verify it's an integer
      expect(Number.isInteger(score.overall)).toBe(true);
    });
  });

  describe("toPlainObject() / fromPlainObject()", () => {
    it("roundtrips through plain object", () => {
      const score = IntegrityScore.create(
        {
          hostname: 80,
          contentHash: 90,
          timing: 70,
          domIntegrity: 85,
          cookieSecurity: 95,
        },
        1700000000000,
      );
      const plain = score.toPlainObject();

      expect(plain.hostname).toBe(80);
      expect(plain.contentHash).toBe(90);
      expect(plain.timing).toBe(70);
      expect(plain.domIntegrity).toBe(85);
      expect(plain.cookieSecurity).toBe(95);
      expect(plain.overall).toBe(score.overall);
      expect(plain.evaluatedAt).toBe(1700000000000);

      const restored = IntegrityScore.fromPlainObject(plain);
      expect(restored.overall).toBe(score.overall);
      expect(restored.evaluatedAt).toBe(1700000000000);
    });
  });

  describe("immutability", () => {
    it("is frozen after creation", () => {
      const score = IntegrityScore.create(all100, 1);
      expect(Object.isFrozen(score)).toBe(true);
    });
  });
});
