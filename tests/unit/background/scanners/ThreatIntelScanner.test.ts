/**
 * ThreatIntelScanner Unit Tests
 * ~12 tests covering delegation and error handling
 */

import { describe, it, expect, beforeEach, jest } from "@jest/globals";
import { ThreatIntelScanner } from "@/background/scanners/ThreatIntelScanner";

describe("ThreatIntelScanner", () => {
  let scanner: ThreatIntelScanner;
  let mockDetector: any;

  beforeEach(() => {
    mockDetector = {
      checkBreaches: jest.fn(),
      syncThreatIntel: jest.fn(),
    };
    scanner = new ThreatIntelScanner(mockDetector);
  });

  describe("scan()", () => {
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
      const result = await scanner.scan();
      expect(mockDetector.syncThreatIntel).toHaveBeenCalledTimes(1);
      expect(result).toBe(findings);
    });

    it("returns empty array when no intel", async () => {
      mockDetector.syncThreatIntel.mockResolvedValue([]);
      expect(await scanner.scan()).toEqual([]);
    });

    it("does NOT call checkBreaches", async () => {
      mockDetector.syncThreatIntel.mockResolvedValue([]);
      await scanner.scan();
      expect(mockDetector.checkBreaches).not.toHaveBeenCalled();
    });

    it("handles syncThreatIntel rejection", async () => {
      mockDetector.syncThreatIntel.mockRejectedValue(new Error("Feed down"));
      await expect(scanner.scan()).rejects.toThrow("Feed down");
    });

    it("includes metadata when present", async () => {
      const findings = [
        {
          category: "threat",
          title: "T",
          severity: "HIGH",
          source: "S",
          description: "d",
          metadata: { indicator: "1.2.3.4", confidence: 0.9 },
        },
      ];
      mockDetector.syncThreatIntel.mockResolvedValue(findings);
      const result = await scanner.scan();
      expect(result[0].metadata?.indicator).toBe("1.2.3.4");
    });

    it("returns threat category", async () => {
      const findings = [
        {
          category: "threat",
          title: "T",
          severity: "MEDIUM",
          source: "S",
          description: "d",
        },
      ];
      mockDetector.syncThreatIntel.mockResolvedValue(findings);
      expect((await scanner.scan())[0].category).toBe("threat");
    });

    it("supports all severity levels", async () => {
      const severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
      for (const sev of severities) {
        mockDetector.syncThreatIntel.mockResolvedValue([
          {
            category: "threat",
            title: "T",
            severity: sev,
            source: "S",
            description: "d",
          },
        ]);
        const result = await scanner.scan();
        expect(result[0].severity).toBe(sev);
        mockDetector.syncThreatIntel.mockClear();
      }
    });

    it("recommendation is optional", async () => {
      const findings = [
        {
          category: "threat",
          title: "T",
          severity: "LOW",
          source: "S",
          description: "d",
        },
      ];
      mockDetector.syncThreatIntel.mockResolvedValue(findings);
      const result = await scanner.scan();
      expect(result[0].recommendation).toBeUndefined();
    });

    it("works after error", async () => {
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
      await expect(scanner.scan()).rejects.toThrow("fail");
      const result = await scanner.scan();
      expect(result).toHaveLength(1);
    });
  });

  describe("Multiple scan() calls", () => {
    it("calls syncThreatIntel each time", async () => {
      mockDetector.syncThreatIntel.mockResolvedValue([]);
      await scanner.scan();
      await scanner.scan();
      await scanner.scan();
      expect(mockDetector.syncThreatIntel).toHaveBeenCalledTimes(3);
      expect(mockDetector.checkBreaches).not.toHaveBeenCalled();
    });

    it("returns fresh data each call", async () => {
      const f1 = [
        {
          category: "threat",
          title: "First",
          severity: "HIGH",
          source: "S",
          description: "d",
        },
      ];
      const f2 = [
        {
          category: "threat",
          title: "Second",
          severity: "LOW",
          source: "S",
          description: "d",
        },
      ];
      mockDetector.syncThreatIntel
        .mockResolvedValueOnce(f1)
        .mockResolvedValueOnce(f2);
      expect(await scanner.scan()).toBe(f1);
      expect(await scanner.scan()).toBe(f2);
    });
  });

  describe("Constructor", () => {
    it("creates instance with detector", () => {
      const detector = { checkBreaches: jest.fn(), syncThreatIntel: jest.fn() };
      const s = new ThreatIntelScanner(detector as any);
      expect(s).toBeInstanceOf(ThreatIntelScanner);
    });
  });
});
