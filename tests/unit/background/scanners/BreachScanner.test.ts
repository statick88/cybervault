/**
 * BreachScanner Unit Tests
 * ~20 tests covering delegation, error handling, and state isolation
 */

import { describe, it, expect, beforeEach, jest } from "@jest/globals";
import { BreachScanner } from "@/background/scanners/BreachScanner";

describe("BreachScanner", () => {
  let scanner: BreachScanner;
  let mockDetector: any;

  const createMockDetector = (): any => ({
    checkBreaches: jest.fn(),
    syncThreatIntel: jest.fn(),
  });

  beforeEach(() => {
    mockDetector = createMockDetector();
    scanner = new BreachScanner(mockDetector);
  });

  describe("scan()", () => {
    it("delegates to checkBreaches()", async () => {
      const findings = [
        {
          category: "breach",
          title: "Test",
          severity: "HIGH",
          source: "test",
          description: "test",
        },
      ];
      mockDetector.checkBreaches.mockResolvedValue(findings);
      const result = await scanner.scan();
      expect(mockDetector.checkBreaches).toHaveBeenCalledTimes(1);
      expect(result).toBe(findings);
    });

    it("returns empty array when no breaches", async () => {
      mockDetector.checkBreaches.mockResolvedValue([]);
      expect(await scanner.scan()).toEqual([]);
    });

    it("returns multiple findings with mixed categories", async () => {
      const findings = [
        {
          category: "breach",
          title: "B1",
          severity: "HIGH",
          source: "HIBP",
          description: "d",
        },
        {
          category: "threat",
          title: "T1",
          severity: "CRITICAL",
          source: "Feed",
          description: "d",
        },
      ];
      mockDetector.checkBreaches.mockResolvedValue(findings);
      const result = await scanner.scan();
      expect(result[0].category).toBe("breach");
      expect(result[1].category).toBe("threat");
    });

    it("handles checkBreaches rejection", async () => {
      mockDetector.checkBreaches.mockRejectedValue(new Error("API down"));
      await expect(scanner.scan()).rejects.toThrow("API down");
    });

    it("propagates exact error", async () => {
      const err = new Error("Timeout");
      mockDetector.checkBreaches.mockRejectedValue(err);
      await expect(scanner.scan()).rejects.toBe(err);
    });

    it("calls detector on each invocation", async () => {
      mockDetector.checkBreaches.mockResolvedValue([]);
      await scanner.scan();
      await scanner.scan();
      await scanner.scan();
      expect(mockDetector.checkBreaches).toHaveBeenCalledTimes(3);
    });

    it("works after a previous error", async () => {
      mockDetector.checkBreaches
        .mockRejectedValueOnce(new Error("fail"))
        .mockResolvedValueOnce([
          {
            category: "breach",
            title: "T",
            severity: "HIGH",
            source: "S",
            description: "d",
          },
        ]);
      await expect(scanner.scan()).rejects.toThrow("fail");
      const result = await scanner.scan();
      expect(result).toHaveLength(1);
    });

    it("returns whatever detector returns", async () => {
      const weird = "not an array" as any;
      mockDetector.checkBreaches.mockResolvedValue(weird);
      expect(await scanner.scan()).toBe(weird);
    });
  });

  describe("syncThreatIntel()", () => {
    it("delegates to syncThreatIntel()", async () => {
      const findings = [
        {
          category: "threat",
          title: "Intel",
          severity: "HIGH",
          source: "Feed",
          description: "d",
        },
      ];
      mockDetector.syncThreatIntel.mockResolvedValue(findings);
      const result = await scanner.syncThreatIntel();
      expect(mockDetector.syncThreatIntel).toHaveBeenCalledTimes(1);
      expect(result).toBe(findings);
    });

    it("returns empty array when no intel", async () => {
      mockDetector.syncThreatIntel.mockResolvedValue([]);
      expect(await scanner.syncThreatIntel()).toEqual([]);
    });

    it("handles rejection", async () => {
      mockDetector.syncThreatIntel.mockRejectedValue(
        new Error("Network error"),
      );
      await expect(scanner.syncThreatIntel()).rejects.toThrow("Network error");
    });

    it("includes metadata when present", async () => {
      const findings = [
        {
          category: "threat",
          title: "T",
          severity: "HIGH",
          source: "S",
          description: "d",
          metadata: { indicator: "evil.com" },
        },
      ];
      mockDetector.syncThreatIntel.mockResolvedValue(findings);
      const result = await scanner.syncThreatIntel();
      expect(result[0].metadata?.indicator).toBe("evil.com");
    });

    it("calls detector on each invocation", async () => {
      mockDetector.syncThreatIntel.mockResolvedValue([]);
      await scanner.syncThreatIntel();
      await scanner.syncThreatIntel();
      expect(mockDetector.syncThreatIntel).toHaveBeenCalledTimes(2);
    });

    it("works after a previous error", async () => {
      mockDetector.syncThreatIntel
        .mockRejectedValueOnce(new Error("fail"))
        .mockResolvedValueOnce([
          {
            category: "threat",
            title: "T",
            severity: "HIGH",
            source: "S",
            description: "d",
          },
        ]);
      await expect(scanner.syncThreatIntel()).rejects.toThrow("fail");
      const result = await scanner.syncThreatIntel();
      expect(result).toHaveLength(1);
    });
  });

  describe("Finding structure", () => {
    it("validates required fields", async () => {
      const findings = [
        {
          category: "breach",
          title: "T",
          severity: "HIGH",
          source: "S",
          description: "d",
        },
      ];
      mockDetector.checkBreaches.mockResolvedValue(findings);
      const result = await scanner.scan();
      expect(result[0]).toMatchObject({
        category: expect.any(String),
        title: expect.any(String),
        description: expect.any(String),
        severity: expect.any(String),
        source: expect.any(String),
      });
    });

    it("supports all severities", async () => {
      const severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
      for (const sev of severities) {
        mockDetector.checkBreaches.mockResolvedValue([
          {
            category: "breach",
            title: "T",
            severity: sev,
            source: "S",
            description: "d",
          },
        ]);
        const result = await scanner.scan();
        expect(result[0].severity).toBe(sev);
        mockDetector.checkBreaches.mockClear();
      }
    });

    it("supports both breach and threat categories", async () => {
      const breachFinding = {
        category: "breach",
        title: "B",
        severity: "HIGH",
        source: "S",
        description: "d",
      };
      const threatFinding = {
        category: "threat",
        title: "T",
        severity: "HIGH",
        source: "S",
        description: "d",
      };
      mockDetector.checkBreaches.mockResolvedValue([breachFinding]);
      let result = await scanner.scan();
      expect(result[0].category).toBe("breach");
      mockDetector.checkBreaches.mockResolvedValue([threatFinding]);
      result = await scanner.scan();
      expect(result[0].category).toBe("threat");
    });

    it("recommendation is optional", async () => {
      const finding = {
        category: "breach",
        title: "T",
        severity: "HIGH",
        source: "S",
        description: "d",
      };
      mockDetector.checkBreaches.mockResolvedValue([finding]);
      const result = await scanner.scan();
      expect(result[0].recommendation).toBeUndefined();
    });
  });

  describe("State isolation", () => {
    it("separate instances use separate detectors", async () => {
      const detector2 = createMockDetector();
      const scanner2 = new BreachScanner(detector2 as any);
      const findings = [
        {
          category: "breach",
          title: "T",
          severity: "HIGH",
          source: "S",
          description: "d",
        },
      ];
      mockDetector.checkBreaches.mockResolvedValue(findings);
      detector2.checkBreaches.mockResolvedValue(findings);
      const r1 = await scanner.scan();
      const r2 = await scanner2.scan();
      expect(mockDetector.checkBreaches).toHaveBeenCalledTimes(1);
      expect(detector2.checkBreaches).toHaveBeenCalledTimes(1);
    });
  });

  describe("Constructor", () => {
    it("creates instance with detector", () => {
      const detector = createMockDetector();
      const s = new BreachScanner(detector);
      expect(s).toBeInstanceOf(BreachScanner);
    });
  });
});
