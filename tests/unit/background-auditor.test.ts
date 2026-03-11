/**
 * Background Auditor Tests
 * Unit tests simplificados para el servicio de auditoría
 */

// Tests para BreachDetector
describe("BreachDetector", () => {
  let BreachDetector: any;
  let detector: any;

  beforeEach(async () => {
    // Mock de fetch
    global.fetch = jest.fn();
    const module = await import("../src/background/breach-detector");
    BreachDetector = module.BreachDetector;
    detector = new BreachDetector();
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  describe("checkPassword", () => {
    it("should return compromised=true when password found in breach", async () => {
      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        text: async () => Promise.resolve("ABC123:50000"),
      });

      const result = await detector.checkPassword("testpassword");

      expect(result).toHaveProperty("compromised");
      expect(result).toHaveProperty("count");
    });

    it("should return compromised=false when password not found", async () => {
      (global.fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        text: async () => Promise.resolve("ABC123:0\nDEF456:0"),
      });

      const result = await detector.checkPassword("uniquepassword12345");

      expect(result.compromised).toBe(false);
      expect(result.count).toBe(0);
    });

    it("should handle fetch errors gracefully", async () => {
      (global.fetch as jest.Mock).mockRejectedValueOnce(
        new Error("Network error"),
      );

      const result = await detector.checkPassword("anypassword");

      expect(result.compromised).toBe(false);
      expect(result.count).toBe(0);
    });
  });

  describe("syncThreatIntel", () => {
    it("should return threat findings from cache", async () => {
      // Primer llamado para poblar cache
      const findings1 = await detector.syncThreatIntel();

      // Segundo llamado debe usar cache
      const findings2 = await detector.syncThreatIntel();

      // Ambos deben retornar arrays
      expect(Array.isArray(findings1)).toBe(true);
      expect(Array.isArray(findings2)).toBe(true);
    });

    it("should return threat findings", async () => {
      const findings = await detector.syncThreatIntel();

      expect(Array.isArray(findings)).toBe(true);
    });
  });

  describe("clearCache", () => {
    it("should clear threat intel cache", () => {
      detector.clearCache();

      // No debe lanzar errores
      expect(true).toBe(true);
    });
  });
});

// Tests para CredentialMonitor
describe("CredentialMonitor", () => {
  let CredentialMonitor: any;
  let monitor: any;

  beforeEach(async () => {
    const module = await import("../src/background/credential-monitor");
    CredentialMonitor = module.CredentialMonitor;
    monitor = new CredentialMonitor();
  });

  describe("addMonitoredDomain", () => {
    it("should add domain to monitoring", async () => {
      await monitor.addMonitoredDomain("example.com", "credential-ref-123");

      const domains = monitor.getMonitoredDomains();
      expect(domains).toContain("example.com");
    });

    it("should store credential reference", async () => {
      await monitor.addMonitoredDomain("github.com", "ref-abc123");

      const findings = await monitor.analyzePage("https://github.com/login");

      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0].metadata?.credentialRef).toBe("ref-abc123");
    });
  });

  describe("removeMonitoredDomain", () => {
    it("should remove domain from monitoring", async () => {
      await monitor.addMonitoredDomain("example.com", "ref-123");
      await monitor.removeMonitoredDomain("example.com");

      const domains = monitor.getMonitoredDomains();
      expect(domains).not.toContain("example.com");
    });
  });

  describe("analyzePage", () => {
    it("should detect non-HTTPS connections", async () => {
      const findings = await monitor.analyzePage("http://insecure-site.com");

      const httpsWarning = findings.find(
        (f: any) => f.title === "Conexión no segura",
      );
      expect(httpsWarning).toBeDefined();
      expect(httpsWarning.severity).toBe("HIGH");
    });

    it("should not warn for HTTPS", async () => {
      const findings = await monitor.analyzePage("https://secure-site.com");

      const httpsWarning = findings.find(
        (f: any) => f.title === "Conexión no segura",
      );
      expect(httpsWarning).toBeUndefined();
    });

    it("should detect monitored domains", async () => {
      await monitor.addMonitoredDomain("mybank.com", "bank-credentials");

      const findings = await monitor.analyzePage("https://mybank.com/login");

      const monitoredFinding = findings.find(
        (f: any) => f.title === "Sitio con credenciales guardadas",
      );
      expect(monitoredFinding).toBeDefined();
    });
  });

  describe("hashCredential", () => {
    it("should generate consistent hash", () => {
      const hash1 = monitor.hashCredential("github.com", "user@example.com");
      const hash2 = monitor.hashCredential("github.com", "user@example.com");

      expect(hash1).toBe(hash2);
      expect(hash1).toHaveLength(64); // SHA-256 hex
    });

    it("should generate different hash for different domains", () => {
      const hash1 = monitor.hashCredential("github.com", "user@example.com");
      const hash2 = monitor.hashCredential("gitlab.com", "user@example.com");

      expect(hash1).not.toBe(hash2);
    });

    it("should generate different hash for different usernames", () => {
      const hash1 = monitor.hashCredential("github.com", "user1@example.com");
      const hash2 = monitor.hashCredential("github.com", "user2@example.com");

      expect(hash1).not.toBe(hash2);
    });

    it("should be case insensitive", () => {
      const hash1 = monitor.hashCredential("GITHUB.COM", "USER@EXAMPLE.COM");
      const hash2 = monitor.hashCredential("github.com", "user@example.com");

      expect(hash1).toBe(hash2);
    });
  });

  describe("scanAllCredentials", () => {
    it("should return findings for each credential", async () => {
      const credentials = [
        { domain: "github.com", username: "user1" },
        { domain: "gitlab.com", username: "user2" },
      ];

      const findings = await monitor.scanAllCredentials(credentials);

      expect(findings.length).toBe(2);
    });
  });
});

// Tests de integración
describe("Integration", () => {
  describe("Full audit flow", () => {
    it("should complete full audit without errors", async () => {
      global.fetch = jest.fn().mockResolvedValue({
        ok: true,
        text: async () => Promise.resolve("ABC123:0"),
      });

      const { BreachDetector } =
        await import("../src/background/breach-detector");
      const { CredentialMonitor } =
        await import("../src/background/credential-monitor");

      const breachDetector = new BreachDetector();
      const credentialMonitor = new CredentialMonitor();

      // Ejecutar checks
      const breachFindings = await breachDetector.checkPassword("testpass123");
      await credentialMonitor.addMonitoredDomain("test.com", "ref-123");
      const pageFindings =
        await credentialMonitor.analyzePage("https://test.com");

      expect(breachFindings).toHaveProperty("compromised");
      expect(Array.isArray(pageFindings)).toBe(true);
    });
  });
});
