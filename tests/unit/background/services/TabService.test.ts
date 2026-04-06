import { TabService } from "@/background/services/TabService";
import type { Finding } from "@/background/models";

// Mock de chrome.tabs

// Helper para limpiar mocks
const clearMocks = () => {
  jest.clearAllMocks();
  mockOnUpdatedAddListener.mockClear();
  mockOnUpdatedRemoveListener.mockClear();
};

describe("TabService", () => {
  let mockOrchestrator: ReturnType<typeof createMockOrchestrator>;
  let mockCredentialScanner: ReturnType<typeof createMockCredentialScanner>;

  beforeEach(() => {
    clearMocks();
    mockOrchestrator = createMockOrchestrator();
    mockCredentialScanner = createMockCredentialScanner([]);
  });

  describe("1. Constructor y registro de listener", () => {
    test("1.1 Constructor registra listener en chrome.tabs.onUpdated.addListener", () => {
      new TabService(
        mockOrchestrator.handleTabFindings.bind(mockOrchestrator),
        mockCredentialScanner,
      );

      expect(mockOnUpdatedAddListener).toHaveBeenCalledTimes(1);
    });

    test("1.2 Constructor llama a addListener con función async", () => {
      new TabService(
        mockOrchestrator.handleTabFindings.bind(mockOrchestrator),
        mockCredentialScanner,
      );

      const listenerArg = mockOnUpdatedAddListener.mock.calls[0][0];
      expect(typeof listenerArg).toBe("function");
    });

    test("1.3 Listener puede ser invocado múltiples veces", () => {
      const service = new TabService(
        mockOrchestrator.handleTabFindings.bind(mockOrchestrator),
        mockCredentialScanner,
      );

      const listener = mockOnUpdatedAddListener.mock.calls[0][0] as (
        tabId: number,
        changeInfo: any,
        tab: chrome.tabs.Tab,
      ) => void;

      expect(() =>
        listener(1, {}, { url: "https://example.com", id: 1 } as any),
      ).not.toThrow();
    });
  });

  describe("2. setupListener", () => {
    test("2.1 setupListener configura listener correctamente", () => {
      expect(mockOnUpdatedAddListener).toHaveBeenCalledTimes(1);
    });

    test("2.2 Listener se registra solo una vez por instancia", () => {
      new TabService(
        mockOrchestrator.handleTabFindings.bind(mockOrchestrator),
        mockCredentialScanner,
      );

      expect(mockOnUpdatedAddListener).toHaveBeenCalledTimes(1);
    });
  });

  describe("3. handleTabUpdate", () => {
    test("3.1 Cuando analysis retorna findings → llama a orchestrator.handleTabFindings()", async () => {
      const findings: Finding[] = [
        {
          category: "credential",
          title: "Test finding",
          description: "Test description",
          severity: "HIGH",
        },
      ];
      const scanner = createMockCredentialScanner(findings);

      const service = new TabService(
        mockOrchestrator.handleTabFindings.bind(mockOrchestrator),
        scanner,
      );

      // Obtener el listener registrado
      const listener = mockOnUpdatedAddListener.mock.calls[0][0] as (
        tabId: number,
        changeInfo: any,
        tab: chrome.tabs.Tab,
      ) => void;

      // Simular tab update
      await listener(1, { status: "complete" }, {
        url: "https://example.com",
        id: 1,
      } as any);

      expect(scanner.analyzeUrl).toHaveBeenCalledWith("https://example.com");
      expect(mockOrchestrator.handleTabFindings).toHaveBeenCalledWith(findings);
    });

    test("3.2 Cuando analysis retorna vacío → NO llama a orchestrator", async () => {
      const scanner = createMockCredentialScanner([]);

      const service = new TabService(
        mockOrchestrator.handleTabFindings.bind(mockOrchestrator),
        scanner,
      );

      const listener = mockOnUpdatedAddListener.mock.calls[0][0] as (
        tabId: number,
        changeInfo: any,
        tab: chrome.tabs.Tab,
      ) => void;

      await listener(1, { status: "complete" }, {
        url: "https://example.com",
        id: 1,
      } as any);

      expect(mockOrchestrator.handleTabFindings).not.toHaveBeenCalled();
    });

    test("3.3 Solo procesa cuando status es 'complete'", async () => {
      const scanner = createMockCredentialScanner([
        {
          category: "credential",
          title: "Test",
          description: "Test",
          severity: "HIGH",
        },
      ]);

      new TabService(
        mockOrchestrator.handleTabFindings.bind(mockOrchestrator),
        scanner,
      );

      const listener = mockOnUpdatedAddListener.mock.calls[0][0] as (
        tabId: number,
        changeInfo: any,
        tab: chrome.tabs.Tab,
      ) => void;

      // Status no complete
      await listener(1, { status: "loading" }, {
        url: "https://example.com",
        id: 1,
      } as any);

      expect(scanner.analyzeUrl).not.toHaveBeenCalled();
    });

    test("3.4 Solo procesa cuando tab.url existe", async () => {
      const scanner = createMockCredentialScanner([]);

      new TabService(
        mockOrchestrator.handleTabFindings.bind(mockOrchestrator),
        scanner,
      );

      const listener = mockOnUpdatedAddListener.mock.calls[0][0] as (
        tabId: number,
        changeInfo: any,
        tab: chrome.tabs.Tab,
      ) => void;

      // tab.url es undefined
      await listener(1, { status: "complete" }, { id: 1 } as any);

      expect(scanner.analyzeUrl).not.toHaveBeenCalled();
    });

    test("3.5 Solo procesa cuando tab.id existe", async () => {
      const scanner = createMockCredentialScanner([]);

      new TabService(
        mockOrchestrator.handleTabFindings.bind(mockOrchestrator),
        scanner,
      );

      const listener = mockOnUpdatedAddListener.mock.calls[0][0] as (
        tabId: number,
        changeInfo: any,
        tab: chrome.tabs.Tab,
      ) => void;

      // tab.id es undefined
      await listener(1, { status: "complete" }, {
        url: "https://example.com",
      } as any);

      expect(scanner.analyzeUrl).not.toHaveBeenCalled();
    });

    test("3.6 Captura errores de credentialScanner.analyzeUrl", async () => {
      const consoleSpy = jest
        .spyOn(console, "error")
        .mockImplementation(() => {});
      const scanner = {
        analyzeUrl: jest.fn().mockRejectedValue(new Error("Scanner failed")),
      };

      new TabService(
        mockOrchestrator.handleTabFindings.bind(mockOrchestrator),
        scanner as any,
      );

      const listener = mockOnUpdatedAddListener.mock.calls[0][0] as (
        tabId: number,
        changeInfo: any,
        tab: chrome.tabs.Tab,
      ) => void;

      await listener(1, { status: "complete" }, {
        url: "https://example.com",
        id: 1,
      } as any);

      expect(consoleSpy).toHaveBeenCalled();
      expect(mockOrchestrator.handleTabFindings).not.toHaveBeenCalled();
      consoleSpy.mockRestore();
    });

    test("3.7 Captura errores de orchestrator.handleTabFindings", async () => {
      const consoleSpy = jest
        .spyOn(console, "error")
        .mockImplementation(() => {});
      const errorOrchestrator = {
        handleTabFindings: jest
          .fn()
          .mockRejectedValue(new Error("Orchestrator failed")),
      };

      const scanner = createMockCredentialScanner([
        {
          category: "credential",
          title: "Test",
          description: "Test",
          severity: "HIGH",
        },
      ]);

      new TabService(
        errorOrchestrator.handleTabFindings.bind(errorOrchestrator),
        scanner,
      );

      const listener = mockOnUpdatedAddListener.mock.calls[0][0] as (
        tabId: number,
        changeInfo: any,
        tab: chrome.tabs.Tab,
      ) => void;

      await listener(1, { status: "complete" }, {
        url: "https://example.com",
        id: 1,
      } as any);

      expect(consoleSpy).toHaveBeenCalled();
      consoleSpy.mockRestore();
    });

    test("3.8 handleTabUpdate maneja múltiples findings", async () => {
      const findings: Finding[] = [
        {
          category: "credential",
          title: "Finding 1",
          description: "Desc 1",
          severity: "HIGH",
        },
        {
          category: "credential",
          title: "Finding 2",
          description: "Desc 2",
          severity: "MEDIUM",
        },
      ];
      const scanner = createMockCredentialScanner(findings);

      new TabService(
        mockOrchestrator.handleTabFindings.bind(mockOrchestrator),
        scanner,
      );

      const listener = mockOnUpdatedAddListener.mock.calls[0][0] as (
        tabId: number,
        changeInfo: any,
        tab: chrome.tabs.Tab,
      ) => void;

      await listener(1, { status: "complete" }, {
        url: "https://example.com",
        id: 1,
      } as any);

      expect(mockOrchestrator.handleTabFindings).toHaveBeenCalledWith(findings);
    });

    test("3.9 handleTabUpdate no procesa URLs con protocolo no HTTP/HTTPS", async () => {
      const scanner = createMockCredentialScanner([]);

      new TabService(
        mockOrchestrator.handleTabFindings.bind(mockOrchestrator),
        scanner,
      );

      const listener = mockOnUpdatedAddListener.mock.calls[0][0] as (
        tabId: number,
        changeInfo: any,
        tab: chrome.tabs.Tab,
      ) => void;

      await listener(1, { status: "complete" }, {
        url: "file:///path/to/file",
        id: 1,
      } as any);

      expect(scanner.analyzeUrl).toHaveBeenCalledWith("file:///path/to/file");
    });

    test("3.10 handleTabUpdate pasa la URL exacta recibida", async () => {
      const testUrl = "https://test.example.com/path?query=123";
      const scanner = createMockCredentialScanner([]);

      new TabService(
        mockOrchestrator.handleTabFindings.bind(mockOrchestrator),
        scanner,
      );

      const listener = mockOnUpdatedAddListener.mock.calls[0][0] as (
        tabId: number,
        changeInfo: any,
        tab: chrome.tabs.Tab,
      ) => void;

      await listener(1, { status: "complete" }, { url: testUrl, id: 1 } as any);

      expect(scanner.analyzeUrl).toHaveBeenCalledWith(testUrl);
    });
  });

  describe("4. destroy", () => {
    test("4.1 destroy remueve el listener de chrome.tabs.onUpdated", () => {
      const service = new TabService(
        mockOrchestrator.handleTabFindings.bind(mockOrchestrator),
        mockCredentialScanner,
      );

      expect(mockOnUpdatedRemoveListener).not.toHaveBeenCalled();

      service.destroy();

      expect(mockOnUpdatedRemoveListener).toHaveBeenCalledTimes(1);
    });

    test("4.2 destroy remueve el listener correcto", () => {
      const service = new TabService(
        mockOrchestrator.handleTabFindings.bind(mockOrchestrator),
        mockCredentialScanner,
      );

      service.destroy();

      expect(mockOnUpdatedRemoveListener).toHaveBeenCalledWith(
        mockOnUpdatedAddListener.mock.calls[0][0],
      );
    });

    test("4.3 destroy se puede llamar múltiples veces sin error", () => {
      const service = new TabService(
        mockOrchestrator.handleTabFindings.bind(mockOrchestrator),
        mockCredentialScanner,
      );

      service.destroy();
      service.destroy();
      service.destroy();

      expect(mockOnUpdatedRemoveListener).toHaveBeenCalledTimes(3);
    });

    test("4.4 Después de destroy, no se procesan nuevos updates", async () => {
      const scanner = createMockCredentialScanner([
        {
          category: "credential",
          title: "Test",
          description: "Test",
          severity: "HIGH",
        },
      ]);

      const service = new TabService(
        mockOrchestrator.handleTabFindings.bind(mockOrchestrator),
        scanner,
      );

      service.destroy();

      const listener = mockOnUpdatedAddListener.mock.calls[0][0] as (
        tabId: number,
        changeInfo: any,
        tab: chrome.tabs.Tab,
      ) => void;

      await listener(1, { status: "complete" }, {
        url: "https://example.com",
        id: 1,
      } as any);

      expect(mockOrchestrator.handleTabFindings).not.toHaveBeenCalled();
    });
  });

  describe("5. Integración y flujo completo", () => {
    test("5.1 Flujo completo: tab update → scan → findings → orchestrator", async () => {
      const findings: Finding[] = [
        {
          category: "breach",
          title: "Breach detected",
          description: "Credential found in breach",
          severity: "CRITICAL",
        },
      ];
      const scanner = createMockCredentialScanner(findings);

      new TabService(
        mockOrchestrator.handleTabFindings.bind(mockOrchestrator),
        scanner,
      );

      const listener = mockOnUpdatedAddListener.mock.calls[0][0] as (
        tabId: number,
        changeInfo: any,
        tab: chrome.tabs.Tab,
      ) => void;

      await listener(42, { status: "complete" }, {
        url: "https://bank.com",
        id: 42,
      } as any);

      expect(scanner.analyzeUrl).toHaveBeenCalledWith("https://bank.com");
      expect(mockOrchestrator.handleTabFindings).toHaveBeenCalledWith(findings);
    });

    test("5.2 Flujo: tab update → scan → sin findings → NO orchestrator", async () => {
      const scanner = createMockCredentialScanner([]);

      new TabService(
        mockOrchestrator.handleTabFindings.bind(mockOrchestrator),
        scanner,
      );

      const listener = mockOnUpdatedAddListener.mock.calls[0][0] as (
        tabId: number,
        changeInfo: any,
        tab: chrome.tabs.Tab,
      ) => void;

      await listener(1, { status: "complete" }, {
        url: "https://safe.com",
        id: 1,
      } as any);

      expect(mockOrchestrator.handleTabFindings).not.toHaveBeenCalled();
    });
  });

  describe("6. Manejo de diferentes categorías de findings", () => {
    test("6.1 Maneja findings de categoría credential", async () => {
      const findings: Finding[] = [
        {
          category: "credential",
          title: "Credencial expuesta",
          description: "Desc",
          severity: "HIGH",
        },
      ];
      const scanner = createMockCredentialScanner(findings);

      new TabService(
        mockOrchestrator.handleTabFindings.bind(mockOrchestrator),
        scanner,
      );

      const listener = mockOnUpdatedAddListener.mock.calls[0][0] as (
        tabId: number,
        changeInfo: any,
        tab: chrome.tabs.Tab,
      ) => void;

      await listener(1, { status: "complete" }, {
        url: "https://test.com",
        id: 1,
      } as any);

      expect(mockOrchestrator.handleTabFindings).toHaveBeenCalledWith(
        expect.arrayContaining([
          expect.objectContaining({ category: "credential" }),
        ]),
      );
    });

    test("6.2 Maneja findings de categoría breach", async () => {
      const findings: Finding[] = [
        {
          category: "breach",
          title: "Breach",
          description: "Desc",
          severity: "CRITICAL",
        },
      ];
      const scanner = createMockCredentialScanner(findings);

      new TabService(
        mockOrchestrator.handleTabFindings.bind(mockOrchestrator),
        scanner,
      );

      const listener = mockOnUpdatedAddListener.mock.calls[0][0] as (
        tabId: number,
        changeInfo: any,
        tab: chrome.tabs.Tab,
      ) => void;

      await listener(1, { status: "complete" }, {
        url: "https://test.com",
        id: 1,
      } as any);

      expect(mockOrchestrator.handleTabFindings).toHaveBeenCalledWith(
        expect.arrayContaining([
          expect.objectContaining({ category: "breach" }),
        ]),
      );
    });
  });

  describe("7. Edge cases y Robustez", () => {
    test("7.1 handleTabUpdate con findings vacíos no destaque", async () => {
      const scanner = createMockCredentialScanner([]);

      new TabService(
        mockOrchestrator.handleTabFindings.bind(mockOrchestrator),
        scanner,
      );

      const listener = mockOnUpdatedAddListener.mock.calls[0][0] as (
        tabId: number,
        changeInfo: any,
        tab: chrome.tabs.Tab,
      ) => void;

      await listener(1, { status: "complete" }, {
        url: "https://test.com",
        id: 1,
      } as any);

      expect(mockOrchestrator.handleTabFindings).not.toHaveBeenCalled();
    });

    test("7.2 Listener maneja changeInfo con otras propiedades", async () => {
      const scanner = createMockCredentialScanner([]);

      new TabService(
        mockOrchestrator.handleTabFindings.bind(mockOrchestrator),
        scanner,
      );

      const listener = mockOnUpdatedAddListener.mock.calls[0][0] as (
        tabId: number,
        changeInfo: any,
        tab: chrome.tabs.Tab,
      ) => void;

      // changeInfo con múltiples propiedades
      await listener(
        1,
        { status: "complete", url: "changed", title: "New Title" },
        { url: "https://test.com", id: 1 } as any,
      );

      expect(scanner.analyzeUrl).toHaveBeenCalledWith("https://test.com");
    });

    test("7.3 Service mantiene estado interno correcto", () => {
      const service = new TabService(
        mockOrchestrator.handleTabFindings.bind(mockOrchestrator),
        mockCredentialScanner,
      );

      expect(service).toBeDefined();
    });

    test("7.4 Múltiples instancias registran listeners independientes", () => {
      const service1 = new TabService(
        mockOrchestrator.handleTabFindings.bind(mockOrchestrator),
        mockCredentialScanner,
      );
      const service2 = new TabService(
        mockOrchestrator.handleTabFindings.bind(mockOrchestrator),
        mockCredentialScanner,
      );

      expect(mockOnUpdatedAddListener).toHaveBeenCalledTimes(2);
    });

    test("7.5 destroy individual elimina solo su listener", () => {
      const service1 = new TabService(
        mockOrchestrator.handleTabFindings.bind(mockOrchestrator),
        mockCredentialScanner,
      );
      const service2 = new TabService(
        mockOrchestrator.handleTabFindings.bind(mockOrchestrator),
        mockCredentialScanner,
      );

      expect(mockOnUpdatedAddListener).toHaveBeenCalledTimes(2);

      service1.destroy();

      expect(mockOnUpdatedRemoveListener).toHaveBeenCalledTimes(1);

      service2.destroy();

      expect(mockOnUpdatedRemoveListener).toHaveBeenCalledTimes(2);
    });
  });
});
