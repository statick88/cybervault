/**
 * CredentialScanner Unit Tests
 * Tests delegation, error handling, edge cases (~25 tests)
 */

import { describe, it, expect, beforeEach, jest } from "@jest/globals";
import { CredentialScanner } from "@/background/scanners/CredentialScanner";

describe("CredentialScanner", () => {
  let scanner: CredentialScanner;
  let mockMonitor: any;

  const createMockMonitor = (): any => ({
    analyzePage: jest.fn(),
    getMonitoredDomains: jest.fn(),
    addMonitoredDomain: jest.fn(),
    removeMonitoredDomain: jest.fn(),
  });

  beforeEach(() => {
    mockMonitor = createMockMonitor();
    scanner = new CredentialScanner(mockMonitor);
  });

  // ==================== analyzeUrl() ====================
  describe("analyzeUrl()", () => {
    it("delegates to analyzePage() with exact URL", async () => {
      const findings = [
        {
          category: "credential",
          title: "Test",
          severity: "LOW",
          description: "d",
        },
      ];
      mockMonitor.analyzePage.mockResolvedValue(findings);
      const url = "https://example.com/login";
      expect(await scanner.analyzeUrl(url)).toEqual(findings);
      expect(mockMonitor.analyzePage).toHaveBeenCalledWith(url);
    });

    it("returns empty array", async () => {
      mockMonitor.analyzePage.mockResolvedValue([]);
      expect(await scanner.analyzeUrl("https://test.com")).toEqual([]);
    });

    it("handles various URL formats", async () => {
      const findings = [{ category: "credential" }];
      mockMonitor.analyzePage.mockResolvedValue(findings);
      const urls = [
        "https://example.com",
        "https://example.com/path",
        "https://example.com?q=1",
        "https://example.com:8443",
        "https://user:pass@example.com",
        "https://example.com#frag",
      ];
      for (const url of urls) {
        await scanner.analyzeUrl(url);
        expect(mockMonitor.analyzePage).toHaveBeenLastCalledWith(url);
        mockMonitor.analyzePage.mockClear();
      }
    });

    it("propagates errors", async () => {
      mockMonitor.analyzePage.mockRejectedValue(new Error("Invalid"));
      await expect(scanner.analyzeUrl("bad")).rejects.toThrow("Invalid");
    });
  });

  // ==================== scanMonitoredDomains() ====================
  describe("scanMonitoredDomains()", () => {
    it("gets domains and adds https:// prefix", async () => {
      const domains = ["example.com", "test.org"];
      mockMonitor.getMonitoredDomains.mockReturnValue(domains);
      mockMonitor.analyzePage
        .mockResolvedValueOnce([{ category: "credential" }])
        .mockResolvedValueOnce([{ category: "credential" }]);

      await scanner.scanMonitoredDomains();

      expect(mockMonitor.getMonitoredDomains).toHaveBeenCalledTimes(1);
      expect(mockMonitor.analyzePage).toHaveBeenNthCalledWith(
        1,
        "https://example.com",
      );
      expect(mockMonitor.analyzePage).toHaveBeenNthCalledWith(
        2,
        "https://test.org",
      );
    });

    it("concatenates findings", async () => {
      const domains = ["a.com", "b.com"];
      mockMonitor.getMonitoredDomains.mockReturnValue(domains);
      mockMonitor.analyzePage
        .mockResolvedValueOnce([{ title: "A1" }, { title: "A2" }])
        .mockResolvedValueOnce([{ title: "B1" }]);

      const result = await scanner.scanMonitoredDomains();

      expect(result).toHaveLength(3);
      expect(result[0].title).toBe("A1");
      expect(result[1].title).toBe("A2");
      expect(result[2].title).toBe("B1");
    });

    it("empty domains returns empty array", async () => {
      mockMonitor.getMonitoredDomains.mockReturnValue([]);
      expect(await scanner.scanMonitoredDomains()).toEqual([]);
      expect(mockMonitor.analyzePage).not.toHaveBeenCalled();
    });

    it("stops on first analysis error", async () => {
      const domains = ["good.com", "bad.com"];
      mockMonitor.getMonitoredDomains.mockReturnValue(domains);
      mockMonitor.analyzePage
        .mockResolvedValueOnce([{ category: "credential" }])
        .mockRejectedValueOnce(new Error("fail"));

      await expect(scanner.scanMonitoredDomains()).rejects.toThrow("fail");
    });

    it("maintains domain order", async () => {
      const domains = ["zebra.com", "apple.com", "mango.com"];
      mockMonitor.getMonitoredDomains.mockReturnValue(domains);
      mockMonitor.analyzePage.mockResolvedValue([{}]);

      await scanner.scanMonitoredDomains();

      for (let i = 0; i < domains.length; i++) {
        expect(mockMonitor.analyzePage).toHaveBeenNthCalledWith(
          i + 1,
          `https://${domains[i]}`,
        );
      }
    });

    it("single domain works", async () => {
      mockMonitor.getMonitoredDomains.mockReturnValue(["single.com"]);
      mockMonitor.analyzePage.mockResolvedValue([{ title: "Single" }]);

      const result = await scanner.scanMonitoredDomains();

      expect(result).toHaveLength(1);
      expect(mockMonitor.analyzePage).toHaveBeenCalledWith(
        "https://single.com",
      );
    });
  });

  // ==================== addMonitoredDomain() ====================
  describe("addMonitoredDomain()", () => {
    it("delegates with correct params", async () => {
      mockMonitor.addMonitoredDomain.mockResolvedValue(undefined);
      await scanner.addMonitoredDomain("example.com", "cred-ref-123");
      expect(mockMonitor.addMonitoredDomain).toHaveBeenCalledWith(
        "example.com",
        "cred-ref-123",
      );
    });

    it("handles various domains", async () => {
      const cases = [
        ["example.com", "ref1"],
        ["test.org", "ref2"],
        ["sub.domain.com", "ref3"],
        ["UPPERCASE.COM", "ref4"],
      ];
      for (const [domain, ref] of cases) {
        mockMonitor.addMonitoredDomain.mockResolvedValue(undefined);
        await scanner.addMonitoredDomain(domain, ref);
        expect(mockMonitor.addMonitoredDomain).toHaveBeenLastCalledWith(
          domain,
          ref,
        );
      }
    });

    it("propagates add errors", async () => {
      mockMonitor.addMonitoredDomain.mockRejectedValue(new Error("Exists"));
      await expect(scanner.addMonitoredDomain("x.com", "r")).rejects.toThrow(
        "Exists",
      );
    });

    it("handles empty domain", async () => {
      mockMonitor.addMonitoredDomain.mockResolvedValue(undefined);
      await scanner.addMonitoredDomain("", "ref");
      expect(mockMonitor.addMonitoredDomain).toHaveBeenCalledWith("", "ref");
    });

    it("handles empty credentialRef", async () => {
      mockMonitor.addMonitoredDomain.mockResolvedValue(undefined);
      await scanner.addMonitoredDomain("example.com", "");
      expect(mockMonitor.addMonitoredDomain).toHaveBeenCalledWith(
        "example.com",
        "",
      );
    });
  });

  // ==================== removeMonitoredDomain() ====================
  describe("removeMonitoredDomain()", () => {
    it("delegates with correct domain", async () => {
      mockMonitor.removeMonitoredDomain.mockResolvedValue(undefined);
      await scanner.removeMonitoredDomain("example.com");
      expect(mockMonitor.removeMonitoredDomain).toHaveBeenCalledWith(
        "example.com",
      );
    });

    it("does not throw for non-existent domain", async () => {
      mockMonitor.removeMonitoredDomain.mockResolvedValue(undefined);
      await expect(
        scanner.removeMonitoredDomain("nonexistent.com"),
      ).resolves.toBeUndefined();
    });

    it("propagates remove errors", async () => {
      mockMonitor.removeMonitoredDomain.mockRejectedValue(
        new Error("DB error"),
      );
      await expect(scanner.removeMonitoredDomain("x.com")).rejects.toThrow(
        "DB error",
      );
    });
  });

  // ==================== Edge cases ====================
  describe("Edge cases", () => {
    it("scanMonitoredDomains calls getMonitoredDomains each time", async () => {
      mockMonitor.getMonitoredDomains.mockReturnValue(["a.com"]);
      mockMonitor.analyzePage.mockResolvedValue([]);
      await scanner.scanMonitoredDomains();
      await scanner.scanMonitoredDomains();
      expect(mockMonitor.getMonitoredDomains).toHaveBeenCalledTimes(2);
    });

    it("handles undefined URL gracefully", async () => {
      mockMonitor.analyzePage.mockResolvedValue([]);
      // @ts-expect-error
      await expect(scanner.analyzeUrl(undefined)).resolves.toEqual([]);
      expect(mockMonitor.analyzePage).toHaveBeenCalledWith(undefined);
    });
  });

  // ==================== Constructor ====================
  describe("Constructor", () => {
    it("creates instance with monitor", () => {
      const monitor = createMockMonitor();
      const s = new CredentialScanner(monitor);
      expect(s).toBeInstanceOf(CredentialScanner);
    });
  });
});
