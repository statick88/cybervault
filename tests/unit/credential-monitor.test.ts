/**
 * CredentialMonitor Unit Tests
 * Tests for credential monitoring and security analysis
 */

import { describe, it, expect, beforeEach, jest } from "@jest/globals";

// Mock global fetch
global.fetch = jest.fn() as any;

// Mock @noble/hashes to avoid ESM issues in node_modules
jest.mock("@noble/hashes/utils", () => ({
  bytesToHex: jest.fn().mockImplementation((bytes: any) =>
    Array.from(bytes)
      .map((b: any) => b.toString(16).padStart(2, "0"))
      .join(""),
  ),
}));

jest.mock("@noble/hashes/sha2", () => ({
  sha256: jest.fn().mockImplementation((data: any) => {
    // Create a deterministic but different hash based on input content
    const base = new Uint8Array(32);
    if (data && data.length) {
      // Compute a simple checksum of all bytes to differentiate inputs
      let sum = 0;
      for (let i = 0; i < data.length; i++) {
        sum = (sum + data[i]) % 256;
      }
      base[0] = sum;
      base[31] = data.length % 256;
    }
    return base;
  }),
}));

// Import after mocking
import { CredentialMonitor } from "../../src/background/credential-monitor";

describe("CredentialMonitor", () => {
  let monitor: CredentialMonitor;

  beforeEach(() => {
    monitor = new CredentialMonitor();
    jest.clearAllMocks();
  });

  describe("addMonitoredDomain / removeMonitoredDomain", () => {
    it("should store domain in lowercase", async () => {
      await monitor.addMonitoredDomain("EXAMPLE.COM", "cred-ref-1");
      expect(monitor.getMonitoredDomains()).toContain("example.com");
      expect(monitor.getMonitoredDomains()).not.toContain("EXAMPLE.COM");
    });

    it("should treat same domain with different cases as same key", async () => {
      await monitor.addMonitoredDomain("Example.com", "cred-ref-1");
      await monitor.addMonitoredDomain("EXAMPLE.COM", "cred-ref-2");

      const domains = monitor.getMonitoredDomains();
      expect(domains).toHaveLength(1);
      expect(domains[0]).toBe("example.com");
    });

    it("should remove domain successfully", async () => {
      await monitor.addMonitoredDomain("example.com", "cred-ref-1");
      await monitor.removeMonitoredDomain("example.com");

      expect(monitor.getMonitoredDomains()).not.toContain("example.com");
    });

    it("should not throw error when removing non-existent domain", async () => {
      await monitor.addMonitoredDomain("example.com", "cred-ref-1");

      // Removing a domain that doesn't exist should not throw
      expect(async () => {
        await monitor.removeMonitoredDomain("nonexistent.com");
      }).not.toThrow();

      expect(monitor.getMonitoredDomains()).toContain("example.com");
    });

    it("should monitor multiple domains simultaneously", async () => {
      const domains = ["example.com", "test.com", "demo.org"];
      const credRefs = ["cred-1", "cred-2", "cred-3"];

      for (let i = 0; i < domains.length; i++) {
        await monitor.addMonitoredDomain(domains[i], credRefs[i]);
      }

      expect(monitor.getMonitoredDomains()).toHaveLength(3);
      domains.forEach((domain) => {
        expect(monitor.getMonitoredDomains()).toContain(domain.toLowerCase());
      });
    });
  });

  describe("analyzePage", () => {
    it("should return empty array for invalid URL", async () => {
      const findings = await monitor.analyzePage("not-a-valid-url");
      expect(findings).toEqual([]);
    });

    it("should return only security findings for non-monitored domain with HTTPS", async () => {
      const url = "https://unmonitored.com";
      const findings = await monitor.analyzePage(url);

      // No credential finding since domain is not monitored
      const credentialFindings = findings.filter(
        (f) => f.category === "credential" && f.title.includes("credenciales"),
      );
      expect(credentialFindings).toHaveLength(0);

      // No security issue (HTTPS is secure)
      const httpsFindings = findings.filter(
        (f) => f.title === "Conexión no segura",
      );
      expect(httpsFindings).toHaveLength(0);
    });

    it("should return credential finding for monitored domain", async () => {
      await monitor.addMonitoredDomain("example.com", "cred-ref-123");

      const findings = await monitor.analyzePage("https://example.com/login");

      const credentialFindings = findings.filter(
        (f) =>
          f.category === "credential" &&
          f.title === "Sitio con credenciales guardadas",
      );

      expect(credentialFindings).toHaveLength(1);
      expect(credentialFindings[0].severity).toBe("MEDIUM");
      expect(credentialFindings[0].description).toContain("example.com");
      expect(credentialFindings[0].recommendation).toBeDefined();
    });

    it("should include domain and credentialRef in metadata for monitored domain", async () => {
      await monitor.addMonitoredDomain("example.com", "cred-ref-123");

      const findings = await monitor.analyzePage("https://example.com");

      const credFinding = findings.find(
        (f) => f.title === "Sitio con credenciales guardadas",
      );
      expect(credFinding).toBeDefined();
      expect(credFinding?.metadata).toEqual({
        domain: "example.com",
        credentialRef: "cred-ref-123",
      });
    });

    it("should combine credential finding with security findings", async () => {
      await monitor.addMonitoredDomain("example.com", "cred-ref-123");

      // HTTP URL will trigger security finding
      const findings = await monitor.analyzePage("http://example.com");

      const credentialFindings = findings.filter(
        (f) => f.title === "Sitio con credenciales guardadas",
      );
      const securityFindings = findings.filter(
        (f) => f.title === "Conexión no segura",
      );

      expect(credentialFindings).toHaveLength(1);
      expect(securityFindings).toHaveLength(1);
      expect(findings).toHaveLength(2);
    });

    it("should handle subdomains as separate domains", async () => {
      await monitor.addMonitoredDomain("example.com", "cred-ref-1");

      // Subdomain should not match parent domain
      const findings = await monitor.analyzePage("https://sub.example.com");

      const credentialFindings = findings.filter(
        (f) => f.title === "Sitio con credenciales guardadas",
      );
      expect(credentialFindings).toHaveLength(0);
    });

    it("should handle URLs with ports", async () => {
      await monitor.addMonitoredDomain("example.com", "cred-ref-1");

      // Port in URL should still match domain
      const findings = await monitor.analyzePage(
        "https://example.com:8443/login",
      );

      const credentialFindings = findings.filter(
        (f) => f.title === "Sitio con credenciales guardadas",
      );
      expect(credentialFindings).toHaveLength(1);
    });
  });

  describe("analyzePageSecurity", () => {
    it("should detect HTTP as critical security finding", async () => {
      const findings = await monitor.analyzePage("http://example.com");

      const httpFindings = findings.filter(
        (f) => f.title === "Conexión no segura",
      );
      expect(httpFindings).toHaveLength(1);
      expect(httpFindings[0].severity).toBe("HIGH");
      expect(httpFindings[0].description).toContain("no usa HTTPS");
      expect(httpFindings[0].metadata).toEqual({
        domain: "example.com",
        protocol: "http:",
      });
    });

    it("should not add HTTPS finding for secure connection", async () => {
      const findings = await monitor.analyzePage("https://example.com");

      const httpsFindings = findings.filter(
        (f) => f.title === "Conexión no segura",
      );
      expect(httpsFindings).toHaveLength(0);
    });

    it("should handle file URLs without throwing", async () => {
      const findings = await monitor.analyzePage("file:///path/to/file.html");

      // File protocol is not http/https, should still not throw
      expect(Array.isArray(findings)).toBe(true);
    });

    it("should handle non-standard ports", async () => {
      // La implementación actual no extrae el puerto en metadata
      // pero debería procesarse sin errores
      const findings = await monitor.analyzePage("http://example.com:8080");

      const httpFindings = findings.filter(
        (f) => f.title === "Conexión no segura",
      );
      expect(httpFindings).toHaveLength(1);
    });

    it("should handle IP addresses as hostnames", async () => {
      const findings = await monitor.analyzePage("https://192.168.1.1");

      // Should not throw and should not detect credential (IP not monitored)
      expect(Array.isArray(findings)).toBe(true);
    });

    it("should handle URLs with credentials in hostname", async () => {
      const findings = await monitor.analyzePage(
        "https://user:pass@example.com",
      );

      // Should parse correctly and extract hostname
      expect(Array.isArray(findings)).toBe(true);
      const httpFindings = findings.filter(
        (f) => f.title === "Conexión no segura",
      );
      expect(httpFindings).toHaveLength(0); // HTTPS is used
    });
  });

  describe("scanAllCredentials", () => {
    it("should create finding for each credential", async () => {
      const credentials = [
        { domain: "example.com", username: "user1" },
        { domain: "test.com", username: "user2" },
      ];

      (global.fetch as any).mockResolvedValue({ ok: true });

      const findings = await monitor.scanAllCredentials(credentials);

      expect(findings).toHaveLength(2);
      findings.forEach((finding, index) => {
        expect(finding.category).toBe("credential");
        expect(finding.title).toContain(credentials[index].domain);
        expect(finding.severity).toBe("LOW");
        expect(finding.metadata?.domain).toBe(credentials[index].domain);
        expect(finding.metadata?.username).toBe(credentials[index].username);
      });
    });

    it("should handle fetch errors gracefully", async () => {
      const credentials = [{ domain: "example.com", username: "user1" }];

      (global.fetch as any).mockRejectedValue(new Error("Network error"));

      const findings = await monitor.scanAllCredentials(credentials);

      expect(findings).toHaveLength(1);
      expect(findings[0].severity).toBe("MEDIUM");
      expect(findings[0].title).toContain("Error verificando");
      expect(findings[0].metadata?.error).toBeDefined();
    });

    it("should use HEAD method for verification", async () => {
      const credentials = [{ domain: "example.com", username: "user1" }];

      (global.fetch as any).mockResolvedValue({ ok: true });

      await monitor.scanAllCredentials(credentials);

      expect(global.fetch).toHaveBeenCalledWith(
        "https://example.com",
        expect.objectContaining({
          method: "HEAD",
          mode: "no-cors",
        }),
      );
    });

    it("should handle empty credentials array", async () => {
      const findings = await monitor.scanAllCredentials([]);
      expect(findings).toEqual([]);
    });
  });

  describe("hashCredential", () => {
    it("should generate consistent hash for same inputs", () => {
      const hash1 = monitor.hashCredential("example.com", "user1");
      const hash2 = monitor.hashCredential("example.com", "user1");

      expect(hash1).toBe(hash2);
      expect(hash1).toMatch(/^[a-f0-9]{64}$/); // SHA-256 = 64 hex chars
    });

    it("should generate different hashes for different domains", () => {
      const hash1 = monitor.hashCredential("example.com", "user1");
      const hash2 = monitor.hashCredential("test.com", "user1");

      expect(hash1).not.toBe(hash2);
    });

    it("should generate different hashes for different usernames", () => {
      const hash1 = monitor.hashCredential("example.com", "user1");
      const hash2 = monitor.hashCredential("example.com", "user2");

      expect(hash1).not.toBe(hash2);
    });

    it("should be case-insensitive for domain and username", () => {
      const hash1 = monitor.hashCredential("EXAMPLE.COM", "USER1");
      const hash2 = monitor.hashCredential("example.com", "user1");

      expect(hash1).toBe(hash2);
    });
  });

  describe("getMonitoredDomains", () => {
    it("should return empty array when no domains monitored", () => {
      const domains = monitor.getMonitoredDomains();
      expect(domains).toEqual([]);
    });

    it("should return all monitored domains", () => {
      monitor.addMonitoredDomain("example.com", "cred-1");
      monitor.addMonitoredDomain("test.com", "cred-2");
      monitor.addMonitoredDomain("demo.org", "cred-3");

      const domains = monitor.getMonitoredDomains();
      expect(domains).toHaveLength(3);
      expect(domains).toContain("example.com");
      expect(domains).toContain("test.com");
      expect(domains).toContain("demo.org");
    });

    it("should return domains in insertion order", () => {
      monitor.addMonitoredDomain("zebra.com", "cred-1");
      monitor.addMonitoredDomain("apple.com", "cred-2");
      monitor.addMonitoredDomain("mango.com", "cred-3");

      const domains = monitor.getMonitoredDomains();
      expect(domains[0]).toBe("zebra.com");
      expect(domains[1]).toBe("apple.com");
      expect(domains[2]).toBe("mango.com");
    });
  });

  describe("Edge cases", () => {
    it("should handle empty domain in addMonitoredDomain", async () => {
      await monitor.addMonitoredDomain("", "cred-ref");
      expect(monitor.getMonitoredDomains()).toContain("");
    });

    it("should handle empty credentialRef in addMonitoredDomain", async () => {
      await monitor.addMonitoredDomain("example.com", "");
      const findings = await monitor.analyzePage("https://example.com");

      const credFinding = findings.find(
        (f) => f.title === "Sitio con credenciales guardadas",
      );
      expect(credFinding?.metadata?.credentialRef).toBe("");
    });

    it("should maintain state between method calls", async () => {
      await monitor.addMonitoredDomain("example.com", "cred-1");

      // First call
      const findings1 = await monitor.analyzePage("https://example.com");
      expect(
        findings1.some((f) => f.title === "Sitio con credenciales guardadas"),
      ).toBe(true);

      // Second call should maintain state
      const findings2 = await monitor.analyzePage("https://example.com/page2");
      expect(
        findings2.some((f) => f.title === "Sitio con credenciales guardadas"),
      ).toBe(true);

      // Remove and verify state changes
      await monitor.removeMonitoredDomain("example.com");
      const findings3 = await monitor.analyzePage("https://example.com");
      expect(
        findings3.some((f) => f.title === "Sitio con credenciales guardadas"),
      ).toBe(false);
    });

    it("should handle URLs with query parameters", async () => {
      monitor.addMonitoredDomain("example.com", "cred-1");

      const findings = await monitor.analyzePage(
        "https://example.com/search?q=test&page=1",
      );

      const credFinding = findings.find(
        (f) => f.title === "Sitio con credenciales guardadas",
      );
      expect(credFinding).toBeDefined();
      expect(credFinding?.metadata?.domain).toBe("example.com");
    });

    it("should handle URLs with fragments", async () => {
      monitor.addMonitoredDomain("example.com", "cred-1");

      const findings = await monitor.analyzePage(
        "https://example.com/page#section",
      );

      const credFinding = findings.find(
        (f) => f.title === "Sitio con credenciales guardadas",
      );
      expect(credFinding).toBeDefined();
    });

    it("should handle special characters in domain", async () => {
      // Internationalized domain names
      monitor.addMonitoredDomain("xn--exmple-cua.com", "cred-1");

      const findings = await monitor.analyzePage("https://xn--exmple-cua.com");

      const credFinding = findings.find(
        (f) => f.title === "Sitio con credenciales guardadas",
      );
      expect(credFinding).toBeDefined();
    });
  });

  describe("CredentialFinding structure", () => {
    it("should have correct structure for credential finding", async () => {
      monitor.addMonitoredDomain("example.com", "cred-ref-123");
      const findings = await monitor.analyzePage("https://example.com");

      const finding = findings.find(
        (f) => f.title === "Sitio con credenciales guardadas",
      );

      expect(finding).toMatchObject({
        category: "credential",
        title: "Sitio con credenciales guardadas",
        severity: "MEDIUM",
      });
      expect(typeof finding?.description).toBe("string");
      expect(typeof finding?.recommendation).toBe("string");
      expect(typeof finding?.metadata).toBe("object");
    });

    it("should have correct structure for security finding", async () => {
      const findings = await monitor.analyzePage("http://example.com");

      const finding = findings.find((f) => f.title === "Conexión no segura");

      expect(finding).toMatchObject({
        category: "credential",
        title: "Conexión no segura",
        severity: "HIGH",
      });
      expect(finding?.description).toContain("example.com");
      expect(finding?.recommendation).toBe(
        "No introducir credenciales en sitios sin HTTPS",
      );
      expect(finding?.metadata).toEqual({
        domain: "example.com",
        protocol: "http:",
      });
    });
  });
});
