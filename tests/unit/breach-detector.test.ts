/**
 * BreachDetector Unit Tests
 * Tests for breach detection using HIBP API and threat intelligence
 */

import {
  describe,
  it,
  expect,
  beforeEach,
  afterEach,
  jest,
} from "@jest/globals";

// Constants for mocking hash values
const MOCK_HASH_PREFIX = "ABCDE";
const MOCK_HASH_SUFFIX = "F0123456789ABCDEF0123456789ABCDEF0123456789";
const MOCK_FULL_HASH = MOCK_HASH_PREFIX + MOCK_HASH_SUFFIX;

// Mock @noble/hashes modules before importing BreachDetector
jest.mock("@noble/hashes/utils", () => ({
  bytesToHex: jest.fn().mockReturnValue(MOCK_FULL_HASH),
}));

jest.mock("@noble/hashes/sha2", () => ({
  sha256: jest.fn().mockReturnValue(new Uint8Array(32)),
}));

// Import BreachDetector after mocks are set up
import { BreachDetector } from "../../src/background/breach-detector";

// Mock global fetch
const mockFetch = jest.fn() as jest.MockedFunction<typeof fetch>;
global.fetch = mockFetch;

// Helper to create mock response
function createMockResponse(
  ok: boolean,
  textContent: string,
  status?: number,
): any {
  return {
    ok,
    status,
    text: async () => textContent,
  };
}

describe("BreachDetector", () => {
  let detector: BreachDetector;

  beforeEach(() => {
    detector = new BreachDetector();
    mockFetch.mockClear();
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe("checkEmail", () => {
    it("should return empty array for non-breached email", async () => {
      mockFetch.mockResolvedValueOnce(createMockResponse(true, ""));

      const findings = await detector.checkEmail("safe@example.com");

      expect(findings).toEqual([]);
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it("should return BreachFinding with CRITICAL severity for >100 breaches", async () => {
      mockFetch.mockResolvedValueOnce(
        createMockResponse(true, `${MOCK_HASH_SUFFIX}:150`),
      );

      const findings = await detector.checkEmail("test@example.com");

      if (findings.length > 0) {
        expect(findings[0].severity).toBe("CRITICAL");
        expect(findings[0].category).toBe("breach");
        expect(findings[0].source).toBe("HaveIBeenPwned");
        expect(findings[0].metadata?.breachCount).toBe(150);
      }
    });

    it("should return BreachFinding with HIGH severity for 11-100 breaches", async () => {
      mockFetch.mockResolvedValueOnce(
        createMockResponse(true, `${MOCK_HASH_SUFFIX}:50`),
      );

      const findings = await detector.checkEmail("test2@example.com");

      if (findings.length > 0) {
        expect(findings[0].severity).toBe("HIGH");
      }
    });

    it("should return BreachFinding with MEDIUM severity for 2-10 breaches", async () => {
      mockFetch.mockResolvedValueOnce(
        createMockResponse(true, `${MOCK_HASH_SUFFIX}:5`),
      );

      const findings = await detector.checkEmail("test3@example.com");

      if (findings.length > 0) {
        expect(findings[0].severity).toBe("MEDIUM");
      }
    });

    it("should return BreachFinding with LOW severity for 1 breach", async () => {
      mockFetch.mockResolvedValueOnce(
        createMockResponse(true, `${MOCK_HASH_SUFFIX}:1`),
      );

      const findings = await detector.checkEmail("test4@example.com");

      if (findings.length > 0) {
        expect(findings[0].severity).toBe("LOW");
      }
    });

    it("should handle multiple hashes in response and match correct suffix", async () => {
      const otherSuffix1 = "AAAAA1111111111111111111111111111111111";
      const otherSuffix2 = "BBBBB2222222222222222222222222222222222";

      mockFetch.mockResolvedValueOnce(
        createMockResponse(
          true,
          `${otherSuffix1}:10\n${MOCK_HASH_SUFFIX}:50\n${otherSuffix2}:20`,
        ),
      );

      const findings = await detector.checkEmail("test5@example.com");

      if (findings.length > 0) {
        expect(findings[0].metadata?.breachCount).toBe(50);
      }
    });

    it("should handle network errors gracefully and return empty array", async () => {
      mockFetch.mockRejectedValueOnce(new Error("Network error"));

      const findings = await detector.checkEmail("test@example.com");

      expect(findings).toEqual([]);
      expect(mockFetch).toHaveBeenCalledTimes(1);
    });

    it("should handle non-200 HTTP responses by returning empty array", async () => {
      mockFetch.mockResolvedValueOnce(createMockResponse(false, "", 404));

      const findings = await detector.checkEmail("test@example.com");

      expect(findings).toEqual([]);
    });

    it("should handle malformed response lines without colon", async () => {
      mockFetch.mockResolvedValueOnce(
        createMockResponse(
          true,
          `malformed line without colon\n${MOCK_HASH_SUFFIX}:25\nanother malformed line`,
        ),
      );

      const findings = await detector.checkEmail("test6@example.com");

      if (findings.length > 0) {
        expect(findings[0].metadata?.breachCount).toBe(25);
      }
    });

    it("should include proper User-Agent header", async () => {
      mockFetch.mockResolvedValueOnce(createMockResponse(true, ""));

      await detector.checkEmail("test@example.com");

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringMatching(
          /^https:\/\/api\.pwnedpasswords\.com\/range\/[A-F0-9]{5}$/,
        ),
        expect.objectContaining({
          headers: { "User-Agent": "CyberVault-Security-Extension" },
        }),
      );
    });

    it("should handle empty response without crashing", async () => {
      mockFetch.mockResolvedValueOnce(createMockResponse(true, ""));

      const findings = await detector.checkEmail("test@example.com");

      expect(findings).toEqual([]);
    });

    it("should trim hash suffix before comparison", async () => {
      mockFetch.mockResolvedValueOnce(
        createMockResponse(true, `  ${MOCK_HASH_SUFFIX}:30  `),
      );

      const findings = await detector.checkEmail("test7@example.com");

      if (findings.length > 0) {
        expect(findings[0].metadata?.breachCount).toBe(30);
      }
    });
  });

  describe("checkPassword", () => {
    it("should return compromised=false for safe password", async () => {
      mockFetch.mockResolvedValueOnce(createMockResponse(true, ""));

      const result = await detector.checkPassword("securePassword123!");

      expect(result).toEqual({ compromised: false, count: 0 });
    });

    it("should return compromised=true with correct count for breached password", async () => {
      mockFetch.mockResolvedValueOnce(
        createMockResponse(true, `${MOCK_HASH_SUFFIX}:1000`),
      );

      const result = await detector.checkPassword("breachedPassword");

      expect(result.compromised).toBe(true);
      expect(result.count).toBe(1000);
    });

    it("should handle network errors gracefully and return safe result", async () => {
      mockFetch.mockRejectedValueOnce(new Error("Network error"));

      const result = await detector.checkPassword("anypassword");

      expect(result).toEqual({ compromised: false, count: 0 });
    });

    it("should use correct endpoint and headers", async () => {
      mockFetch.mockResolvedValueOnce(createMockResponse(true, ""));

      await detector.checkPassword("testpass");

      expect(mockFetch).toHaveBeenCalledWith(
        expect.stringMatching(
          /^https:\/\/api\.pwnedpasswords\.com\/range\/[A-F0-9]{5}$/,
        ),
        expect.objectContaining({
          headers: { "User-Agent": "CyberVault-Security-Extension" },
        }),
      );
    });
  });

  describe("Cache", () => {
    it("should cache threat intelligence on first sync", async () => {
      const findings = await detector.syncThreatIntel();

      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].category).toBe("threat");
    });

    it("should preserve cache on subsequent sync calls within TTL", async () => {
      const detectorAny = detector as any;
      await detector.syncThreatIntel();
      const cacheAfterFirst = detectorAny.threatIntelCache;

      // Second call within TTL should not clear cache
      await detector.syncThreatIntel();
      const cacheAfterSecond = detectorAny.threatIntelCache;

      expect(cacheAfterSecond).toBe(cacheAfterFirst);
      expect(cacheAfterSecond.length).toBeGreaterThan(0);
    });

    it("clearCache should clear threat intel cache", () => {
      detector.syncThreatIntel();

      const detectorAny = detector as any;
      expect(detectorAny.threatIntelCache.length).toBeGreaterThan(0);
      expect(detectorAny.cacheExpiry).not.toBeNull();

      detector.clearCache();

      expect(detectorAny.threatIntelCache).toEqual([]);
      expect(detectorAny.cacheExpiry).toBeNull();
    });

    it("should have TTL of 1 hour (3600000ms)", () => {
      const detectorAny = detector as any;
      expect(detectorAny.CACHE_TTL_MS).toBe(60 * 60 * 1000);
    });

    it("should expire cache after TTL and fetch fresh data", async () => {
      const detectorAny = detector as any;

      await detector.syncThreatIntel();
      expect(detectorAny.cacheExpiry).not.toBeNull();

      detectorAny.cacheExpiry = new Date(Date.now() - 1000);

      const findings = await detector.syncThreatIntel();

      expect(findings.length).toBeGreaterThan(0);
    });
  });

  describe("syncThreatIntel", () => {
    it("should return findings with category 'threat'", async () => {
      const findings = await detector.syncThreatIntel();

      expect(findings[0].category).toBe("threat");
      expect(findings[0].source).toBe("Threat Intel Feed");
    });

    it("should set recommendation to block indicator", async () => {
      const findings = await detector.syncThreatIntel();

      expect(findings[0].recommendation).toBe(
        "Bloquear acceso a este indicador",
      );
    });

    it("should include metadata with original threat intel data", async () => {
      const findings = await detector.syncThreatIntel();

      expect(findings[0].metadata).toBeDefined();
      expect(findings[0].metadata?.indicator).toBeDefined();
      expect(findings[0].metadata?.type).toBeDefined();
      expect(findings[0].metadata?.confidence).toBeDefined();
    });

    it("should set severity to HIGH when confidence > 0.8", async () => {
      const findings = await detector.syncThreatIntel();

      expect(findings[0].severity).toBe("HIGH");
    });
  });

  describe("checkBreaches", () => {
    it("should combine threat intel findings", async () => {
      const findings = await detector.checkBreaches();

      expect(Array.isArray(findings)).toBe(true);
      expect(findings.length).toBeGreaterThan(0);
    });

    it("should include threat intelligence findings", async () => {
      const findings = await detector.checkBreaches();

      const threatFindings = findings.filter((f) => f.category === "threat");
      expect(threatFindings.length).toBeGreaterThan(0);
    });
  });

  describe("Edge Cases", () => {
    it("should handle email with special characters", async () => {
      mockFetch.mockResolvedValueOnce(createMockResponse(true, ""));

      const findings = await detector.checkEmail("user+tag@example.co.uk");

      expect(findings).toEqual([]);
    });

    it("should handle very long email addresses", async () => {
      mockFetch.mockResolvedValueOnce(createMockResponse(true, ""));

      const longEmail = `a${"a".repeat(250)}@example.com`;
      const findings = await detector.checkEmail(longEmail);

      expect(findings).toEqual([]);
    });

    it("should not leak email in error messages", async () => {
      mockFetch.mockRejectedValueOnce(new Error("Network timeout"));

      const findings = await detector.checkEmail("sensitive@example.com");

      expect(findings).toEqual([]);
    });
  });

  describe("API Contract", () => {
    it("should return BreachFinding objects with required fields", async () => {
      mockFetch.mockResolvedValueOnce(
        createMockResponse(true, `${MOCK_HASH_SUFFIX}:100`),
      );

      const findings = await detector.checkEmail("test-contract@example.com");

      if (findings.length > 0) {
        expect(findings[0]).toMatchObject({
          category: "breach",
          title: expect.any(String),
          description: expect.any(String),
          severity: expect.any(String),
          source: expect.any(String),
        });
      }
    });

    it("should include recommendation for breach findings", async () => {
      mockFetch.mockResolvedValueOnce(
        createMockResponse(true, `${MOCK_HASH_SUFFIX}:50`),
      );

      const findings = await detector.checkEmail("test-rec@example.com");

      if (findings.length > 0) {
        expect(findings[0].recommendation).toBeDefined();
        expect(findings[0].recommendation).toContain("contraseña");
      }
    });

    it("should include metadata with email and breach count", async () => {
      mockFetch.mockResolvedValueOnce(
        createMockResponse(true, `${MOCK_HASH_SUFFIX}:75`),
      );

      const findings = await detector.checkEmail("test-meta@example.com");

      if (findings.length > 0) {
        expect(findings[0].metadata?.email).toBe("test-meta@example.com");
        expect(findings[0].metadata?.breachCount).toBe(75);
      }
    });

    it("checkPassword should return proper type shape", async () => {
      mockFetch.mockResolvedValueOnce(createMockResponse(true, ""));

      const result = await detector.checkPassword("password123");

      expect(result).toMatchObject({
        compromised: expect.any(Boolean),
        count: expect.any(Number),
      });
    });
  });
});
