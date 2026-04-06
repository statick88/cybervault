import { StorageService } from "@/background/services/StorageService";
import {
  AuditorConfig,
  AuditResult,
  Finding,
  AuditType,
  SeverityLevel,
} from "@/background/models";

// Mock de chrome.storage.local
const mockStorage: Record<string, unknown> = {};

const mockChromeStorage = {
  get: jest.fn((keys: string | string[]) => {
    if (Array.isArray(keys)) {
      const result: Record<string, unknown> = {};
      keys.forEach((key) => {
        if (mockStorage[key] !== undefined) {
          result[key] = mockStorage[key];
        }
      });
      return Promise.resolve(result);
    }
    return Promise.resolve({ [keys]: mockStorage[keys] });
  }),
  set: jest.fn((items: Record<string, unknown>) => {
    Object.assign(mockStorage, items);
    return Promise.resolve();
  }),
  remove: jest.fn((keys: string | string[]) => {
    if (Array.isArray(keys)) {
      keys.forEach((key) => delete mockStorage[key]);
    } else {
      delete mockStorage[keys];
    }
    return Promise.resolve();
  }),
  clear: jest.fn(() => {
    Object.keys(mockStorage).forEach((key) => delete mockStorage[key]);
    return Promise.resolve();
  }),
};

// Mock de chrome API
const mockChrome = {
  storage: {
    local: mockChromeStorage,
  },
};

// Asignar mock global
(global as any).chrome = mockChrome;

// Helper para crear resultados de auditoría mock
const createMockAuditResult = (
  overrides: Partial<AuditResult> = {},
): AuditResult => ({
  id: `test-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
  timestamp: new Date(),
  type: "full" as AuditType,
  findings: [],
  severity: "NONE",
  ...overrides,
});

describe("StorageService", () => {
  let storageService: StorageService;

  beforeEach(() => {
    // Limpiar storage antes de cada test
    Object.keys(mockStorage).forEach((key) => delete mockStorage[key]);
    jest.clearAllMocks();

    storageService = new StorageService();
  });

  describe("Config", () => {
    test("1. loadConfig() cuando no hay config → retorna defaults", async () => {
      const config = await storageService.loadConfig();

      expect(config).toEqual({
        scanIntervalHours: 24,
        breachCheckEnabled: true,
        credentialMonitorEnabled: true,
        threatIntelSyncEnabled: false,
      });
    });

    test("2. loadConfig() cuando hay config guardada → retorna esa config", async () => {
      const savedConfig: AuditorConfig = {
        scanIntervalHours: 12,
        breachCheckEnabled: false,
        credentialMonitorEnabled: true,
        threatIntelSyncEnabled: true,
      };

      await storageService.saveConfig(savedConfig);
      const loadedConfig = await storageService.loadConfig();

      expect(loadedConfig).toEqual(savedConfig);
      expect(mockChromeStorage.get).toHaveBeenCalledWith(["auditor_config"]);
    });

    test("3. saveConfig() guarda correctamente en storage", async () => {
      const config: AuditorConfig = {
        scanIntervalHours: 8,
        breachCheckEnabled: true,
        credentialMonitorEnabled: false,
        threatIntelSyncEnabled: true,
      };

      await storageService.saveConfig(config);

      expect(mockChromeStorage.set).toHaveBeenCalledWith({
        auditor_config: config,
      });
      expect(mockStorage["auditor_config"]).toEqual(config);
    });

    test("4. saveConfig() sobrescribe configuración anterior", async () => {
      const config1: AuditorConfig = {
        scanIntervalHours: 24,
        breachCheckEnabled: true,
        credentialMonitorEnabled: true,
        threatIntelSyncEnabled: false,
      };

      const config2: AuditorConfig = {
        scanIntervalHours: 6,
        breachCheckEnabled: false,
        credentialMonitorEnabled: false,
        threatIntelSyncEnabled: true,
      };

      await storageService.saveConfig(config1);
      await storageService.saveConfig(config2);

      expect(mockStorage["auditor_config"]).toEqual(config2);
    });
  });

  describe("Audit Results", () => {
    test("5. saveAuditResult() agrega nuevo resultado al array", async () => {
      const result1 = createMockAuditResult({ id: "result-1" });
      const result2 = createMockAuditResult({ id: "result-2" });

      await storageService.saveAuditResult(result1);
      await storageService.saveAuditResult(result2);

      const history = await storageService.getAuditHistory();

      expect(history).toHaveLength(2);
      expect(history[0].id).toBe("result-2"); // Más reciente primero
      expect(history[1].id).toBe("result-1");
    });

    test("6. saveAuditResult() mantiene solo últimos 100 (truncate)", async () => {
      const baseTime = Date.now();
      // Crear 110 resultados (result-0 es MÁS RECIENTE, result-109 es MÁS ANTIGUO)
      const results: AuditResult[] = [];
      for (let i = 0; i < 110; i++) {
        results.push(
          createMockAuditResult({
            id: `result-${i}`,
            timestamp: new Date(baseTime - i * 1000),
          }),
        );
      }

      // Guardar en orden CRONOLÓGICO (más antiguo primero) para que cada nuevo sea más reciente
      for (let i = results.length - 1; i >= 0; i--) {
        await storageService.saveAuditResult(results[i]);
      }

      const history = await storageService.getAuditHistory();

      expect(history).toHaveLength(100);
      // Los 100 más recientes son result-0 a result-99
      expect(history[0].id).toBe("result-0");
      expect(history[99].id).toBe("result-99");
      // Los más antiguos (result-100 a result-109) no deberían estar
      expect(history.find((r) => r.id === "result-109")).toBeUndefined();
      expect(history.find((r) => r.id === "result-100")).toBeUndefined();
    });

    test("7. saveAuditResult() ordena por timestamp descendente", async () => {
      const now = Date.now();
      const result1 = createMockAuditResult({
        id: "old",
        timestamp: new Date(now - 10000),
      });
      const result2 = createMockAuditResult({
        id: "new",
        timestamp: new Date(now),
      });
      const result3 = createMockAuditResult({
        id: "mid",
        timestamp: new Date(now - 5000),
      });

      await storageService.saveAuditResult(result1);
      await storageService.saveAuditResult(result2);
      await storageService.saveAuditResult(result3);

      const history = await storageService.getAuditHistory();

      expect(history[0].id).toBe("new");
      expect(history[1].id).toBe("mid");
      expect(history[2].id).toBe("old");
    });

    test("8. getAuditHistory() retorna array ordenado (más reciente primero)", async () => {
      const now = Date.now();
      const results = [
        createMockAuditResult({ id: "a", timestamp: new Date(now - 30000) }),
        createMockAuditResult({ id: "b", timestamp: new Date(now - 10000) }),
        createMockAuditResult({ id: "c", timestamp: new Date(now - 20000) }),
      ];

      // Guardar en orden no ordenado
      for (const result of results) {
        await storageService.saveAuditResult(result);
      }

      const history = await storageService.getAuditHistory();

      expect(history).toHaveLength(3);
      expect(history[0].timestamp.getTime()).toBeGreaterThan(
        history[1].timestamp.getTime(),
      );
      expect(history[1].timestamp.getTime()).toBeGreaterThan(
        history[2].timestamp.getTime(),
      );
    });

    test("9. getAuditHistory() cuando no hay resultados → []", async () => {
      const history = await storageService.getAuditHistory();

      expect(history).toEqual([]);
    });

    test("10. clearAuditHistory() elimina todos los resultados", async () => {
      // Guardar algunos resultados primero
      for (let i = 0; i < 5; i++) {
        await storageService.saveAuditResult(
          createMockAuditResult({ id: `result-${i}` }),
        );
      }

      expect(await storageService.getAuditHistory()).toHaveLength(5);

      await storageService.clearAuditHistory();

      const history = await storageService.getAuditHistory();
      expect(history).toEqual([]);
      expect(mockChromeStorage.set).toHaveBeenCalledWith({
        audit_results: [],
      });
    });

    test("11. Serialización: Date → ISO string, deserialización correcta", async () => {
      const now = new Date("2024-01-15T10:30:00.000Z");
      const result: AuditResult = {
        id: "serialization-test",
        timestamp: now,
        type: "breach_check",
        findings: [
          {
            category: "breach",
            title: "Test Finding",
            description: "Test description",
            severity: "CRITICAL",
          },
        ],
        severity: "CRITICAL",
      };

      await storageService.saveAuditResult(result);

      const storageValue = mockStorage["audit_results"] as Array<{
        timestamp: string;
      }>;
      expect(storageValue[0].timestamp).toBe("2024-01-15T10:30:00.000Z");

      const history = await storageService.getAuditHistory();
      expect(history[0].timestamp).toEqual(now);
      expect(history[0].timestamp instanceof Date).toBe(true);
    });
  });

  describe("Timestamps", () => {
    test("12. setLastScanTime() guarda número", async () => {
      const timestamp = 1705312800000; // 2024-01-15T10:00:00.000Z en ms

      await storageService.setLastScanTime(timestamp);

      expect(mockChromeStorage.set).toHaveBeenCalledWith({
        last_audit_timestamp: timestamp,
      });
      expect(mockStorage["last_audit_timestamp"]).toBe(timestamp);
    });

    test("13. getLastScanTime() retorna Date o null", async () => {
      // Sin timestamp
      let result = await storageService.getLastScanTime();
      expect(result).toBeNull();

      // Con timestamp válido
      const timestamp = 1705312800000;
      await storageService.setLastScanTime(timestamp);
      result = await storageService.getLastScanTime();

      expect(result).toBeInstanceOf(Date);
      expect(result?.getTime()).toBe(timestamp);
    });

    test("14. getLastScanTime() convierte timestamp a Date correctamente", async () => {
      const timestamp = 1705312800000;
      const expectedDate = new Date(timestamp);

      await storageService.setLastScanTime(timestamp);
      const result = await storageService.getLastScanTime();

      expect(result?.getFullYear()).toBe(expectedDate.getFullYear());
      expect(result?.getMonth()).toBe(expectedDate.getMonth());
      expect(result?.getDate()).toBe(expectedDate.getDate());
      expect(result?.getHours()).toBe(expectedDate.getHours());
      expect(result?.getMinutes()).toBe(expectedDate.getMinutes());
      expect(result?.getSeconds()).toBe(expectedDate.getSeconds());
    });

    test("14b. getLastScanTime() con timestamp inválido en storage → retorna Date inválida", async () => {
      // Simular corrupt data en storage
      mockStorage["last_audit_timestamp"] = "invalid-timestamp";

      const result = await storageService.getLastScanTime();

      expect(result).toBeInstanceOf(Date);
      expect(result?.getTime()).toBeNaN();
    });
  });

  describe("Edge Cases", () => {
    test("15. Guardar resultado con 100+ items → truncar a 100", async () => {
      const baseTime = Date.now();
      const totalResults = 115;
      // Crear 115 resultados (result-0 es MÁS RECIENTE, result-114 es MÁS ANTIGUO)
      const results: AuditResult[] = [];
      for (let i = 0; i < totalResults; i++) {
        results.push(
          createMockAuditResult({
            id: `result-${i}`,
            timestamp: new Date(baseTime - i * 1000),
          }),
        );
      }

      // Guardar en orden CRONOLÓGICO (más antiguo primero)
      for (let i = results.length - 1; i >= 0; i--) {
        await storageService.saveAuditResult(results[i]);
      }

      const history = await storageService.getAuditHistory();

      expect(history).toHaveLength(100);
      // Los 100 más recientes son result-0 a result-99
      expect(history[99].id).toBe("result-99");
      expect(history.find((r) => r.id === "result-100")).toBeUndefined();
    });

    test("16. Múltiples saves secuenciales mantienen todos los resultados y orden correcto", async () => {
      const baseTime = Date.now();
      const numResults = 20;

      // Guardar resultados secuencialmente (simulando uso normal)
      for (let i = 0; i < numResults; i++) {
        await storageService.saveAuditResult(
          createMockAuditResult({
            id: `seq-${i}`,
            timestamp: new Date(baseTime + i * 10), // Cada 10ms más reciente
          }),
        );
      }

      const history = await storageService.getAuditHistory();

      expect(history).toHaveLength(numResults);
      // Verificar orden descendente por timestamp
      for (let i = 0; i < history.length - 1; i++) {
        expect(history[i].timestamp.getTime()).toBeGreaterThan(
          history[i + 1].timestamp.getTime(),
        );
      }
      // Verificar que todos los IDs están presentes
      for (let i = 0; i < numResults; i++) {
        expect(history.find((r) => r.id === `seq-${i}`)).toBeDefined();
      }
    });

    test("17. saveAuditResult() con finding vacío funciona correctamente", async () => {
      const result: AuditResult = {
        id: "empty-findings",
        timestamp: new Date(),
        type: "full",
        findings: [],
        severity: "NONE",
      };

      await storageService.saveAuditResult(result);

      const history = await storageService.getAuditHistory();
      expect(history[0].findings).toEqual([]);
    });

    test("18. saveAuditResult() con many findings funciona correctamente", async () => {
      const manyFindings: Finding[] = Array.from({ length: 50 }, (_, i) => ({
        category: "credential" as const,
        title: `Finding ${i}`,
        description: `Description ${i}`,
        severity: "MEDIUM" as SeverityLevel,
        metadata: { index: i },
      }));

      const result: AuditResult = {
        id: "many-findings",
        timestamp: new Date(),
        type: "credential_scan",
        findings: manyFindings,
        severity: "HIGH",
      };

      await storageService.saveAuditResult(result);

      const history = await storageService.getAuditHistory();
      expect(history[0].findings).toHaveLength(50);
      expect(history[0].severity).toBe("HIGH");
    });

    test("19. getAuditHistory() filtra resultados corruptos (null)", async () => {
      // Guardar resultado válido
      const validResult = createMockAuditResult({ id: "valid" });
      await storageService.saveAuditResult(validResult);

      // Corrupt data directamente en storage
      const rawData = mockStorage["audit_results"] as unknown[];
      rawData.push({
        id: "corrupt",
        timestamp: "invalid-date",
        type: "full",
        findings: [],
        severity: "NONE",
      });

      const history = await storageService.getAuditHistory();

      expect(history).toHaveLength(1);
      expect(history[0].id).toBe("valid");
    });

    test("20. saveAuditResult() preserva orden cuando no alcanza límite de 100", async () => {
      const now = Date.now();

      // Guardar 10 resultados con timestamps decrecientes (más viejo primero)
      for (let i = 9; i >= 0; i--) {
        await storageService.saveAuditResult(
          createMockAuditResult({
            id: `order-test-${i}`,
            timestamp: new Date(now - (9 - i) * 1000),
          }),
        );
      }

      const history = await storageService.getAuditHistory();

      expect(history).toHaveLength(10);
      // Verificar que están en orden descendente por timestamp
      for (let i = 0; i < history.length - 1; i++) {
        expect(history[i].timestamp.getTime()).toBeGreaterThan(
          history[i + 1].timestamp.getTime(),
        );
      }
    });
  });

  describe("Chrome Storage Integration", () => {
    test("21. chrome.storage.local.get es llamado con las keys correctas", async () => {
      await storageService.loadConfig();
      expect(mockChromeStorage.get).toHaveBeenCalledWith(["auditor_config"]);

      await storageService.getAuditHistory();
      expect(mockChromeStorage.get).toHaveBeenCalledWith(["audit_results"]);

      await storageService.getLastScanTime();
      expect(mockChromeStorage.get).toHaveBeenCalledWith([
        "last_audit_timestamp",
      ]);
    });

    test("22. chrome.storage.local.set es llamado con las keys correctas", async () => {
      const config: AuditorConfig = {
        scanIntervalHours: 12,
        breachCheckEnabled: false,
        credentialMonitorEnabled: true,
        threatIntelSyncEnabled: false,
      };

      await storageService.saveConfig(config);
      expect(mockChromeStorage.set).toHaveBeenCalledWith({
        auditor_config: config,
      });

      const result: AuditResult = {
        id: "test",
        timestamp: new Date(),
        type: "full",
        findings: [],
        severity: "NONE",
      };
      await storageService.saveAuditResult(result);
      expect(mockChromeStorage.set).toHaveBeenCalledWith({
        audit_results: expect.any(Array),
      });

      await storageService.setLastScanTime(1705312800000);
      expect(mockChromeStorage.set).toHaveBeenCalledWith({
        last_audit_timestamp: 1705312800000,
      });

      await storageService.clearAuditHistory();
      expect(mockChromeStorage.set).toHaveBeenCalledWith({
        audit_results: [],
      });
    });

    test("23. loadConfig() devuelve copia del default (no referencia)", async () => {
      const config1 = await storageService.loadConfig();
      config1.scanIntervalHours = 100;

      const config2 = await storageService.loadConfig();

      expect(config2.scanIntervalHours).toBe(24);
      expect(config1).not.toBe(config2);
    });

    test("24. saveAuditResult() mantiene limite incluso con saves grandes", async () => {
      // Simular storage con >100 items previos
      const existingData = Array.from({ length: 100 }, (_, i) => ({
        id: `existing-${i}`,
        timestamp: new Date(Date.now() - i * 1000).toISOString(),
        type: "full" as AuditType,
        findings: [] as Finding[],
        severity: "NONE" as SeverityLevel | "NONE",
      }));
      mockStorage["audit_results"] = existingData;

      // Guardar nuevo resultado
      const newResult = createMockAuditResult({ id: "new-result" });
      await storageService.saveAuditResult(newResult);

      const history = await storageService.getAuditHistory();
      expect(history).toHaveLength(100);
      expect(history[0].id).toBe("new-result");
    });

    test("25. getAuditHistory() returns empty array cuando storage tiene null", async () => {
      mockStorage["audit_results"] = null;

      const history = await storageService.getAuditHistory();

      expect(history).toEqual([]);
    });
  });
});
