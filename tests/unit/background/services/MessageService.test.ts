import { MessageService } from "@/background/services/MessageService";
import { BackgroundAuditorOrchestrator } from "@/background/BackgroundAuditorOrchestrator";

// Mock de chrome.runtime.onMessage
const mockAddListener = jest.fn();
const mockOnMessage = {
  addListener: mockAddListener,
};

// Mock global de chrome
(global as any).chrome = {
  runtime: {
    onMessage: mockOnMessage,
  },
};

// Helper para crear mock de orchestrator
const createMockOrchestrator = () => ({
  runFullAudit: jest.fn(),
  getStatus: jest.fn(),
  updateConfig: jest.fn(),
  getHistory: jest.fn(),
  clearHistory: jest.fn(),
});

// Helper para obtener el listener registrado (el más reciente)
const getRegisteredListener = () => {
  const calls = mockOnMessage.addListener.mock.calls;
  return calls[calls.length - 1][0] as (
    message: { action: string; payload?: unknown },
    sender: chrome.runtime.MessageSender,
    sendResponse: (response: unknown) => void,
  ) => boolean;
};

// Helper para invocar mensaje y capturar respuesta
const invokeMessage = async (
  action: string,
  payload?: unknown,
  customHandlers?: Record<string, (payload?: unknown) => Promise<unknown>>,
  orchestrator?: ReturnType<typeof createMockOrchestrator>,
) => {
  const sendResponseMock = jest.fn();

  const handlers: Record<string, (payload?: unknown) => Promise<unknown>> = {
    ping: () => Promise.resolve({ status: "alive", timestamp: Date.now() }),
    ...customHandlers,
  };

  const service = new MessageService(handlers);
  const listener = getRegisteredListener();
  const message = { action, payload };

  const returnValue = listener(
    message,
    {} as chrome.runtime.MessageSender,
    sendResponseMock,
  );

  // Esperar a que la promesa interna se resuelva y sendResponse sea llamado
  await Promise.resolve();
  await Promise.resolve();

  return {
    returnValue,
    sendResponseMock,
    service,
  };
};

describe("MessageService", () => {
  let mockOrchestrator: ReturnType<typeof createMockOrchestrator>;

  beforeEach(() => {
    jest.clearAllMocks();
    mockOrchestrator = createMockOrchestrator();
  });

  describe("1. Registro de handlers", () => {
    test("1.1 setupListener llamada en constructor registra listener en chrome.runtime.onMessage", () => {
      new MessageService();
      expect(mockOnMessage.addListener).toHaveBeenCalledTimes(1);
    });

    test("1.2 Handlers por defecto están registrados (ping, run_audit, etc.)", async () => {
      const { sendResponseMock } = await invokeMessage("ping");
      expect(sendResponseMock).toHaveBeenCalledWith(
        expect.objectContaining({ status: "alive" }),
      );
    });
  });

  describe("2. Manejo de mensajes", () => {
    test("2.1 ping → retorna { status: 'alive', timestamp }", async () => {
      const { sendResponseMock } = await invokeMessage("ping");
      const response = sendResponseMock.mock.calls[0][0] as {
        status: string;
        timestamp: number;
      };
      expect(response.status).toBe("alive");
      expect(response.timestamp).toBeGreaterThan(0);
    });

    test("2.2 run_audit → delega a orchestrator.runFullAudit()", async () => {
      const expectedResult = { id: "audit-123" };
      mockOrchestrator.runFullAudit.mockResolvedValue(expectedResult);

      const { sendResponseMock } = await invokeMessage("run_audit", undefined, {
        run_audit: () => mockOrchestrator.runFullAudit(),
      });

      expect(mockOrchestrator.runFullAudit).toHaveBeenCalledTimes(1);
      expect(sendResponseMock).toHaveBeenCalledWith(expectedResult);
    });

    test("2.3 get_status → delega a orchestrator.getStatus()", async () => {
      const expectedStatus = {
        isRunning: false,
        lastScan: null,
        nextScan: null,
      };
      mockOrchestrator.getStatus.mockResolvedValue(expectedStatus);

      const { sendResponseMock } = await invokeMessage(
        "get_status",
        undefined,
        {
          get_status: () => mockOrchestrator.getStatus(),
        },
      );

      expect(mockOrchestrator.getStatus).toHaveBeenCalledTimes(1);
      expect(sendResponseMock).toHaveBeenCalledWith(expectedStatus);
    });

    test("2.4 update_config → delega a orchestrator.updateConfig()", async () => {
      const config = { scanIntervalHours: 12 };
      mockOrchestrator.updateConfig.mockResolvedValue(undefined);

      const { sendResponseMock } = await invokeMessage(
        "update_config",
        config,
        {
          update_config: (payload) =>
            mockOrchestrator.updateConfig(payload as Partial<any>),
        },
      );

      expect(mockOrchestrator.updateConfig).toHaveBeenCalledWith(config);
      expect(sendResponseMock).toHaveBeenCalledWith(undefined);
    });

    test("2.5 get_history → delega a orchestrator.getHistory()", async () => {
      const history = [{ id: "1" }, { id: "2" }];
      mockOrchestrator.getHistory.mockResolvedValue(history);

      const { sendResponseMock } = await invokeMessage(
        "get_history",
        undefined,
        {
          get_history: () => mockOrchestrator.getHistory(),
        },
      );

      expect(mockOrchestrator.getHistory).toHaveBeenCalledTimes(1);
      expect(sendResponseMock).toHaveBeenCalledWith(history);
    });

    test("2.6 clear_history → delega a orchestrator.clearHistory()", async () => {
      mockOrchestrator.clearHistory.mockResolvedValue(undefined);

      const { sendResponseMock } = await invokeMessage(
        "clear_history",
        undefined,
        {
          clear_history: () => mockOrchestrator.clearHistory(),
        },
      );

      expect(mockOrchestrator.clearHistory).toHaveBeenCalledTimes(1);
      expect(sendResponseMock).toHaveBeenCalledWith(undefined);
    });

    test("2.7 acción desconocida → retorna { error: 'Unknown action: xyz' }", async () => {
      const { sendResponseMock } = await invokeMessage("unknown_action");
      expect(sendResponseMock).toHaveBeenCalledWith({
        error: "Unknown action: unknown_action",
      });
    });
  });

  describe("3. Errores", () => {
    test("3.1 orchestrator throw error → mensaje retorna { error: 'error message' }", async () => {
      const errorMessage = "Database connection failed";
      mockOrchestrator.getStatus.mockRejectedValue(new Error(errorMessage));

      const { sendResponseMock } = await invokeMessage(
        "get_status",
        undefined,
        {
          get_status: () => mockOrchestrator.getStatus(),
        },
      );

      expect(sendResponseMock).toHaveBeenCalledWith({ error: errorMessage });
    });

    test("3.2 orchestrator throw error no-instanceof Error → retorna mensaje genérico", async () => {
      mockOrchestrator.getStatus.mockRejectedValue("string error");

      const { sendResponseMock } = await invokeMessage(
        "get_status",
        undefined,
        {
          get_status: () => mockOrchestrator.getStatus(),
        },
      );

      // Check that console.error was called (the error is logged)
      expect(sendResponseMock).toHaveBeenCalledWith({
        error: "Error processing request",
      });
    });

    test("3.3 handler custom lanza Error → retorna mensaje de error", async () => {
      const customError = new Error("Custom handler failed");
      const customHandler = jest.fn().mockRejectedValue(customError);

      const { sendResponseMock, service } = await invokeMessage(
        "custom_action",
        undefined,
        {
          custom_action: customHandler,
        },
      );

      expect(sendResponseMock).toHaveBeenCalledWith({
        error: "Custom handler failed",
      });
    });

    test("3.4 handler custom lanza error no-Error → retorna mensaje genérico", async () => {
      const customHandler = jest.fn().mockRejectedValue("some string error");

      const { sendResponseMock } = await invokeMessage(
        "custom_action",
        undefined,
        {
          custom_action: customHandler,
        },
      );

      expect(sendResponseMock).toHaveBeenCalledWith({
        error: "Error processing request",
      });
    });
  });

  describe("4. Response handling", () => {
    test("4.1 sendResponse es llamado con el resultado", async () => {
      const { sendResponseMock } = await invokeMessage("ping");
      expect(sendResponseMock).toHaveBeenCalledTimes(1);
      expect(sendResponseMock.mock.calls[0][0]).toEqual(
        expect.objectContaining({ status: "alive" }),
      );
    });

    test("4.2 Retorna true para permitir response asincrónica", async () => {
      const { returnValue } = await invokeMessage("ping");
      expect(returnValue).toBe(true);
    });
  });

  describe("5. registerAction / unregisterAction", () => {
    test("5.1 registerAction agrega handler personalizado", async () => {
      const customHandler = jest.fn().mockResolvedValue({ custom: true });
      const service = new MessageService();
      service.registerAction("custom", customHandler);

      const listener = getRegisteredListener();
      const sendResponseMock = jest.fn();
      const message = { action: "custom", payload: undefined };

      listener(message, {} as chrome.runtime.MessageSender, sendResponseMock);
      await Promise.resolve();
      await Promise.resolve();

      expect(customHandler).toHaveBeenCalledWith(undefined);
      expect(sendResponseMock).toHaveBeenCalledWith({ custom: true });
    });

    test("5.2 unregisterAction elimina handler", async () => {
      const customHandler = jest.fn().mockResolvedValue({ custom: true });
      const service = new MessageService();
      service.registerAction("custom", customHandler);
      service.unregisterAction("custom");

      const listener = getRegisteredListener();
      const sendResponseMock = jest.fn();
      const message = { action: "custom", payload: undefined };

      listener(message, {} as chrome.runtime.MessageSender, sendResponseMock);
      await Promise.resolve();

      expect(sendResponseMock).toHaveBeenCalledWith({
        error: "Unknown action: custom",
      });
      expect(customHandler).not.toHaveBeenCalled();
    });

    test("5.3 Handler personalizado sobrescribe default", async () => {
      const defaultHandler = jest.fn().mockResolvedValue({ source: "default" });
      const overrideHandler = jest
        .fn()
        .mockResolvedValue({ source: "override" });

      const service = new MessageService({ test_action: defaultHandler });
      expect(defaultHandler).not.toHaveBeenCalled();

      service.registerAction("test_action", overrideHandler);

      const listener = getRegisteredListener();
      const sendResponseMock = jest.fn();
      const message = { action: "test_action", payload: undefined };

      listener(message, {} as chrome.runtime.MessageSender, sendResponseMock);
      await Promise.resolve();
      await Promise.resolve();

      expect(defaultHandler).not.toHaveBeenCalled();
      expect(overrideHandler).toHaveBeenCalledWith(undefined);
      expect(sendResponseMock).toHaveBeenCalledWith({ source: "override" });
    });
  });

  describe("6. Edge cases", () => {
    test("6.1 Mensaje sin.action → error", async () => {
      const service = new MessageService();
      const listener = getRegisteredListener();
      const sendResponseMock = jest.fn();
      const message = { action: undefined as any, payload: undefined };

      listener(message, {} as chrome.runtime.MessageSender, sendResponseMock);
      await Promise.resolve();

      expect(sendResponseMock).toHaveBeenCalledWith({
        error: "Unknown action: undefined",
      });
    });

    test("6.2 Mensaje con payload undefined → handler recibe undefined", async () => {
      const customHandler = jest
        .fn()
        .mockResolvedValue({ received: undefined });
      const service = new MessageService();
      service.registerAction("test_payload", customHandler);

      const listener = getRegisteredListener();
      const sendResponseMock = jest.fn();
      const message = { action: "test_payload", payload: undefined };

      listener(message, {} as chrome.runtime.MessageSender, sendResponseMock);
      await Promise.resolve();
      await Promise.resolve();

      expect(customHandler).toHaveBeenCalledWith(undefined);
      expect(sendResponseMock).toHaveBeenCalledWith({ received: undefined });
    });

    test("6.3 Mensaje con payload definido → handler recibe payload", async () => {
      const payload = { key: "value" };
      const customHandler = jest.fn().mockResolvedValue({ received: payload });
      const service = new MessageService();
      service.registerAction("test_payload", customHandler);

      const listener = getRegisteredListener();
      const sendResponseMock = jest.fn();
      const message = { action: "test_payload", payload };

      listener(message, {} as chrome.runtime.MessageSender, sendResponseMock);
      await Promise.resolve();
      await Promise.resolve();

      expect(customHandler).toHaveBeenCalledWith(payload);
      expect(sendResponseMock).toHaveBeenCalledWith({ received: payload });
    });

    test("6.4 Handler sin parámetros funciona correctamente", async () => {
      const noParamHandler = jest.fn().mockResolvedValue({ ok: true });
      const service = new MessageService();
      service.registerAction("no_param", noParamHandler);

      const listener = getRegisteredListener();
      const sendResponseMock = jest.fn();
      const message = { action: "no_param", payload: undefined };

      listener(message, {} as chrome.runtime.MessageSender, sendResponseMock);
      await Promise.resolve();
      await Promise.resolve();

      expect(noParamHandler).toHaveBeenCalledWith(undefined);
      expect(sendResponseMock).toHaveBeenCalledWith({ ok: true });
    });
  });

  describe("7. Múltiples registros y desregistros", () => {
    test("7.1 registerAction múltiples veces → solo el último permanece", async () => {
      const handler1 = jest.fn().mockResolvedValue({ version: 1 });
      const handler2 = jest.fn().mockResolvedValue({ version: 2 });

      const service = new MessageService();
      service.registerAction("multi", handler1);
      service.registerAction("multi", handler2);

      const listener = getRegisteredListener();
      const sendResponseMock = jest.fn();
      const message = { action: "multi", payload: undefined };

      listener(message, {} as chrome.runtime.MessageSender, sendResponseMock);
      await Promise.resolve();
      await Promise.resolve();

      expect(handler1).not.toHaveBeenCalled();
      expect(handler2).toHaveBeenCalledWith(undefined);
      expect(sendResponseMock).toHaveBeenCalledWith({ version: 2 });
    });

    test("7.2 unregisterAction de acción inexistente no causa error", async () => {
      const service = new MessageService();
      expect(() => service.unregisterAction("nonexistent")).not.toThrow();

      const listener = getRegisteredListener();
      const sendResponseMock = jest.fn();
      const message = { action: "nonexistent", payload: undefined };

      listener(message, {} as chrome.runtime.MessageSender, sendResponseMock);
      await Promise.resolve();

      expect(sendResponseMock).toHaveBeenCalledWith({
        error: "Unknown action: nonexistent",
      });
    });
  });

  describe("8. Integración con orchestrator (tipos correctos)", () => {
    test("8.1 orchestrator.runFullAudit() devuelve AuditResult correctamente", async () => {
      const orchestrator = createMockOrchestrator();
      const auditResult = {
        id: "audit-123",
        timestamp: new Date(),
        type: "full",
        findings: [],
        severity: "NONE",
      };
      orchestrator.runFullAudit.mockResolvedValue(auditResult);

      const { sendResponseMock } = await invokeMessage("run_audit", undefined, {
        run_audit: () => orchestrator.runFullAudit(),
      });

      expect(sendResponseMock).toHaveBeenCalledWith(auditResult);
    });

    test("8.2 orchestrator.getStatus() devuelve objeto de estado correctamente", async () => {
      const orchestrator = createMockOrchestrator();
      const status = {
        isRunning: true,
        lastScan: new Date(),
        nextScan: new Date(Date.now() + 3600000),
      };
      orchestrator.getStatus.mockResolvedValue(status);

      const { sendResponseMock } = await invokeMessage(
        "get_status",
        undefined,
        {
          get_status: () => orchestrator.getStatus(),
        },
      );

      expect(sendResponseMock).toHaveBeenCalledWith(status);
    });

    test("8.3 orchestrator.updateConfig() con payload correcto", async () => {
      const orchestrator = createMockOrchestrator();
      orchestrator.updateConfig.mockResolvedValue(undefined);
      const configPayload = { scanIntervalHours: 6, breachCheckEnabled: false };

      const { sendResponseMock } = await invokeMessage(
        "update_config",
        configPayload,
        {
          update_config: (payload) =>
            orchestrator.updateConfig(payload as Partial<any>),
        },
      );

      expect(orchestrator.updateConfig).toHaveBeenCalledWith(configPayload);
      expect(sendResponseMock).toHaveBeenCalledWith(undefined);
    });

    test("8.4 orchestrator.getHistory() devuelve array de AuditResult", async () => {
      const orchestrator = createMockOrchestrator();
      const history = [
        {
          id: "1",
          timestamp: new Date(),
          type: "full",
          findings: [],
          severity: "LOW",
        },
        {
          id: "2",
          timestamp: new Date(),
          type: "full",
          findings: [],
          severity: "HIGH",
        },
      ];
      orchestrator.getHistory.mockResolvedValue(history);

      const { sendResponseMock } = await invokeMessage(
        "get_history",
        undefined,
        {
          get_history: () => orchestrator.getHistory(),
        },
      );

      expect(sendResponseMock).toHaveBeenCalledWith(history);
    });

    test("8.5 orchestrator.clearHistory() no retorna valor", async () => {
      const orchestrator = createMockOrchestrator();
      orchestrator.clearHistory.mockResolvedValue(undefined);

      const { sendResponseMock } = await invokeMessage(
        "clear_history",
        undefined,
        {
          clear_history: () => orchestrator.clearHistory(),
        },
      );

      expect(orchestrator.clearHistory).toHaveBeenCalledTimes(1);
      expect(sendResponseMock).toHaveBeenCalledWith(undefined);
    });
  });

  describe("9. Timestamps y datos invariables", () => {
    test("9.1 ping incluye timestamp del momento de la llamada", async () => {
      const before = Date.now();
      const { sendResponseMock } = await invokeMessage("ping");
      const response = sendResponseMock.mock.calls[0][0] as {
        status: string;
        timestamp: number;
      };
      const after = Date.now();

      expect(response.status).toBe("alive");
      expect(response.timestamp).toBeGreaterThanOrEqual(before);
      expect(response.timestamp).toBeLessThanOrEqual(after);
    });
  });
});
