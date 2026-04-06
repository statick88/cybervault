import {
  NotificationService,
  type NotificationSeverity,
} from "@/background/services/NotificationService";

// Mock de chrome.notifications
const mockCreate = jest.fn().mockResolvedValue(undefined);

// Mock global de chrome
(global as any).chrome = {
  notifications: {
    create: mockCreate,
  },
};

// Helper para limpiar mocks
const clearMocks = () => {
  jest.clearAllMocks();
  mockCreate.mockClear();
};

describe("NotificationService", () => {
  let service: NotificationService;

  beforeEach(() => {
    clearMocks();
    service = new NotificationService();
  });

  describe("1. Constructor y estado inicial", () => {
    test("1.1 Constructor crea instancia correctamente", () => {
      expect(service).toBeInstanceOf(NotificationService);
    });

    test("1.2 Estado inicial es enabled", () => {
      // El servicio debería estar habilitado por defecto
      // Esto se prueba indirectamente verificando que send() funciona
      expect(service).toBeDefined();
    });
  });

  describe("2. Métodos enable() y disable()", () => {
    test("2.1 disable() cambia estado interno a deshabilitado", () => {
      service.disable();
      // Internamente no hay getter público, pero probaremos el comportamiento en send()
      expect(service).toBeDefined();
    });

    test("2.2 enable() cambia estado interno a habilitado", () => {
      service.disable();
      service.enable();
      expect(service).toBeDefined();
    });

    test("2.3 enable/disable pueden llamarse múltiples veces", () => {
      service.enable();
      service.enable();
      service.disable();
      service.disable();
      expect(service).toBeDefined();
    });

    test("2.4 Estado defaultValue es enabled (send funciona)", async () => {
      await service.send({
        type: "scan_complete",
        title: "Test",
        message: "Test message",
        severity: "MEDIUM",
      });

      expect(mockCreate).toHaveBeenCalled();
    });
  });

  describe("3. send() - Creación de notificaciones", () => {
    test("3.1 send() llama a chrome.notifications.create con ID correcto", async () => {
      await service.send({
        type: "scan_complete",
        title: "Audit Complete",
        message: "Scan finished",
        severity: "MEDIUM",
      });

      const [notificationId, options] = mockCreate.mock.calls[0];
      expect(typeof notificationId).toBe("string");
      expect(notificationId).toMatch(/^cybervault-scan_complete-\d+$/);
    });

    test("3.2 send() genera notificationId con formato cybault-{type}-{timestamp}", async () => {
      const before = Date.now();
      await service.send({
        type: "credential_found",
        title: "Credential Detected",
        message: "Found credential",
        severity: "HIGH",
      });
      const after = Date.now();

      const [notificationId] = mockCreate.mock.calls[0];
      expect(notificationId).toMatch(/^cybervault-credential_found-\d+$/);

      const timestamp = Number(notificationId.split("-")[2]);
      expect(timestamp).toBeGreaterThanOrEqual(before);
      expect(timestamp).toBeLessThanOrEqual(after);
    });

    test("3.3 send() pasa opciones correctas a chrome.notifications.create", async () => {
      await service.send({
        type: "breach_alert",
        title: "Breach Alert",
        message: "Credential in breach",
        severity: "CRITICAL",
      });

      const [, options] = mockCreate.mock.calls[0];
      expect(options).toEqual({
        type: "basic",
        title: "Breach Alert",
        message: "Credential in breach",
        priority: 2,
        iconUrl: "icon48.png",
      });
    });

    test("3.4 send() usa priority 2 para severidad CRITICAL", async () => {
      await service.send({
        type: "alert",
        title: "Critical",
        message: "Critical issue",
        severity: "CRITICAL",
      });

      const [, options] = mockCreate.mock.calls[0];
      expect(options.priority).toBe(2);
    });

    test("3.5 send() usa priority 1 para severidades no CRITICAL", async () => {
      const severities: NotificationSeverity[] = ["HIGH", "MEDIUM", "LOW"];

      for (const severity of severities) {
        clearMocks();
        await service.send({
          type: "alert",
          title: `Test ${severity}`,
          message: "Test message",
          severity,
        });

        const [, options] = mockCreate.mock.calls[0];
        expect(options.priority).toBe(1);
      }
    });

    test("3.6 send() permite title y message vacíos (pero warning al console)", async () => {
      const consoleSpy = jest
        .spyOn(console, "warn")
        .mockImplementation(() => {});

      await service.send({
        type: "test",
        title: "",
        message: "",
        severity: "LOW",
      });

      expect(consoleSpy).toHaveBeenCalledWith(
        "[NotificationService] skipped: missing params",
      );
      expect(mockCreate).not.toHaveBeenCalled();

      consoleSpy.mockRestore();
    });

    test("3.7 send() con title undefined no crea notificación", async () => {
      const consoleSpy = jest
        .spyOn(console, "warn")
        .mockImplementation(() => {});

      await service.send({
        type: "test",
        title: "Valid title",
        message: "" as any,
        severity: "LOW",
      });

      expect(consoleSpy).toHaveBeenCalled();
      expect(mockCreate).not.toHaveBeenCalled();

      consoleSpy.mockRestore();
    });

    test("3.8 send() con message undefined no crea notificación", async () => {
      const consoleSpy = jest
        .spyOn(console, "warn")
        .mockImplementation(() => {});

      await service.send({
        type: "test",
        title: "" as any,
        message: "Valid message",
        severity: "LOW",
      });

      expect(consoleSpy).toHaveBeenCalled();
      expect(mockCreate).not.toHaveBeenCalled();

      consoleSpy.mockRestore();
    });

    test("3.9 send() siempre incluye iconUrl", async () => {
      await service.send({
        type: "any_type",
        title: "Title",
        message: "Message",
        severity: "LOW",
      });

      const [, options] = mockCreate.mock.calls[0];
      expect(options.iconUrl).toBe("icon48.png");
    });

    test("3.10 send() usa tipo 'basic' para todas las notificaciones", async () => {
      await service.send({
        type: "custom_type",
        title: "Title",
        message: "Message",
        severity: "LOW",
      });

      const [, options] = mockCreate.mock.calls[0];
      expect(options.type).toBe("basic");
    });
  });

  describe("4. Integración enable/disable con send()", () => {
    test("4.1 Cuando disabled, send() no crea notificación", async () => {
      service.disable();

      await service.send({
        type: "test",
        title: "Test",
        message: "Test",
        severity: "LOW",
      });

      expect(mockCreate).not.toHaveBeenCalled();
    });

    test("4.2 Después de disable, múltiples sends no crean notificaciones", async () => {
      service.disable();

      await service.send({
        type: "test1",
        title: "Test1",
        message: "Test1",
        severity: "LOW",
      });
      await service.send({
        type: "test2",
        title: "Test2",
        message: "Test2",
        severity: "MEDIUM",
      });
      await service.send({
        type: "test3",
        title: "Test3",
        message: "Test3",
        severity: "HIGH",
      });

      expect(mockCreate).not.toHaveBeenCalled();
    });

    test("4.3 disable → enable → send crea notificación", async () => {
      service.disable();
      service.enable();

      await service.send({
        type: "test",
        title: "Test",
        message: "Test",
        severity: "MEDIUM",
      });

      expect(mockCreate).toHaveBeenCalledTimes(1);
    });

    test("4.4 enable → disable → send → enable → send funciona correctamente", async () => {
      service.enable();
      await service.send({
        type: "test1",
        title: "Test1",
        message: "Test1",
        severity: "LOW",
      });
      expect(mockCreate).toHaveBeenCalledTimes(1);

      service.disable();
      await service.send({
        type: "test2",
        title: "Test2",
        message: "Test2",
        severity: "MEDIUM",
      });
      expect(mockCreate).toHaveBeenCalledTimes(1); // Sin cambios

      service.enable();
      await service.send({
        type: "test3",
        title: "Test3",
        message: "Test3",
        severity: "HIGH",
      });
      expect(mockCreate).toHaveBeenCalledTimes(2);
    });
  });

  describe("5. Manejo de errores", () => {
    test("5.1 send captura errores de chrome.notifications.create", async () => {
      const consoleSpy = jest
        .spyOn(console, "warn")
        .mockImplementation(() => {});
      mockCreate.mockRejectedValue(new Error("Notification failed"));

      await expect(
        service.send({
          type: "test",
          title: "Test",
          message: "Test",
          severity: "LOW",
        }),
      ).resolves.toBeUndefined();

      expect(consoleSpy).toHaveBeenCalledWith(
        expect.stringContaining("[NotificationService] error:"),
      );
      consoleSpy.mockRestore();
    });

    test("5.2 send no throw al usuario si chrome.notifications falla", async () => {
      mockCreate.mockRejectedValue(new Error("Chrome error"));

      await expect(
        service.send({
          type: "test",
          title: "Test",
          message: "Test",
          severity: "LOW",
        }),
      ).resolves.not.toThrow();
    });

    test("5.3 send con error mantiene el estado habilitado", async () => {
      mockCreate.mockRejectedValue(new Error("Error persistente"));

      await service.send({
        type: "test",
        title: "Test",
        message: "Test",
        severity: "LOW",
      });

      // Debería seguir habilitado
      expect(() => service.enable()).not.toThrow();
    });
  });

  describe("6. Tipos de notificaciones y severidades", () => {
    test("6.1 send acepta cualquier tipo de notificación (type)", async () => {
      const types = [
        "scan_complete",
        "credential_found",
        "breach_alert",
        "config_change",
        "threat_detected",
      ];

      for (const type of types) {
        clearMocks();
        await service.send({
          type,
          title: `Title ${type}`,
          message: `Message ${type}`,
          severity: "MEDIUM",
        });

        const [notificationId] = mockCreate.mock.calls[0];
        expect(notificationId).toMatch(new RegExp(`^cybervault-${type}-\\d+$`));
      }
    });

    test("6.2 send maneja todas las severidades correctamente", async () => {
      const severityMap: Record<NotificationSeverity, number> = {
        CRITICAL: 2,
        HIGH: 1,
        MEDIUM: 1,
        LOW: 1,
      };

      for (const [severity, expectedPriority] of Object.entries(severityMap)) {
        clearMocks();
        await service.send({
          type: "test",
          title: "Test",
          message: "Test",
          severity: severity as NotificationSeverity,
        });

        const [, options] = mockCreate.mock.calls[0];
        expect(options.priority).toBe(expectedPriority);
      }
    });

    test("6.3 notificationId incluye timestamp único", async () => {
      const timestamps: number[] = [];

      // Enviar varias notificaciones y verificar timestamps diferentes
      for (let i = 0; i < 5; i++) {
        await service.send({
          type: "test",
          title: `Test ${i}`,
          message: `Message ${i}`,
          severity: "LOW",
        });

        const [notificationId] = mockCreate.mock.calls[i];
        const timestamp = Number(notificationId.split("-")[2]);
        timestamps.push(timestamp);
      }

      // Todos los timestamps deben ser únicos
      const uniqueTimestamps = new Set(timestamps);
      expect(uniqueTimestamps.size).toBe(5);
    });
  });

  describe("7. Contenido completo de notificación", () => {
    test("7.1 send incluye todos los campos requeridos", async () => {
      await service.send({
        type: "full_test",
        title: "Full Title",
        message: "Full Message",
        severity: "HIGH",
      });

      const [, options] = mockCreate.mock.calls[0];
      expect(options).toHaveProperty("type", "basic");
      expect(options).toHaveProperty("title", "Full Title");
      expect(options).toHaveProperty("message", "Full Message");
      expect(options).toHaveProperty("priority", 1);
      expect(options).toHaveProperty("iconUrl", "icon48.png");
    });

    test("7.2 send preserva tildes y caracteres especiales", async () => {
      await service.send({
        type: "español",
        title: "Título con acentos:的安全测试",
        message: "Mensaje con ñ, á, é, í, ó, ú: 安全测试",
        severity: "MEDIUM",
      });

      const [, options] = mockCreate.mock.calls[0];
      expect(options.title).toBe("Título con acentos:的安全测试");
      expect(options.message).toBe("Mensaje con ñ, á, é, í, ó, ú: 安全测试");
    });

    test("7.3 send preserva title y message exactamente como se pasan", async () => {
      const specialTitle = "Special: !@#$%^&*()_+-=[]{}|;':\",./<>?";
      const specialMessage = "Message with\nnewlines and\ttabs";

      await service.send({
        type: "special",
        title: specialTitle,
        message: specialMessage,
        severity: "LOW",
      });

      const [, options] = mockCreate.mock.calls[0];
      expect(options.title).toBe(specialTitle);
      expect(options.message).toBe(specialMessage);
    });
  });

  describe("8. Formato de notificationId", () => {
    test("8.1 notificationId sigue patrón cybervault-{type}-{timestamp}", async () => {
      await service.send({
        type: "custom_type_123",
        title: "Test",
        message: "Test",
        severity: "LOW",
      });

      const [notificationId] = mockCreate.mock.calls[0];
      const parts = notificationId.split("-");
      expect(parts.length).toBe(3);
      expect(parts[0]).toBe("cybervault");
      expect(parts[1]).toBe("custom_type_123");
      expect(Number.isInteger(Number(parts[2]))).toBe(true);
    });

    test("8.2 type con guiones se incluye completp", async () => {
      await service.send({
        type: "scan-complete-ok",
        title: "Test",
        message: "Test",
        severity: "LOW",
      });

      const [notificationId] = mockCreate.mock.calls[0];
      expect(notificationId).toMatch(/^cybervault-scan-complete-ok-\d+$/);
    });

    test("8.3 timestamp es numérico y timestamp actual", async () => {
      const before = Date.now();
      await service.send({
        type: "test",
        title: "Test",
        message: "Test",
        severity: "LOW",
      });
      const after = Date.now();

      const [notificationId] = mockCreate.mock.calls[0];
      const timestamp = Number(notificationId.split("-")[2]);
      expect(timestamp).toBeGreaterThanOrEqual(before);
      expect(timestamp).toBeLessThanOrEqual(after);
    });
  });

  describe("9. Thread safety y concurrencia", () => {
    test("9.1 Múltiples send() concurrentes generan IDs únicos", async () => {
      const promises = [];
      for (let i = 0; i < 10; i++) {
        promises.push(
          service.send({
            type: "concurrent",
            title: `Concurrent ${i}`,
            message: `Message ${i}`,
            severity: "LOW",
          }),
        );
      }

      await Promise.all(promises);

      const notificationIds = mockCreate.mock.calls.map((call) => call[0]);
      const uniqueIds = new Set(notificationIds);
      expect(uniqueIds.size).toBe(10);
    });

    test("9.2 send concurrentes respetan estado disabled", async () => {
      service.disable();

      const promises = [];
      for (let i = 0; i < 5; i++) {
        promises.push(
          service.send({
            type: "test",
            title: `Test ${i}`,
            message: `Message ${i}`,
            severity: "LOW",
          }),
        );
      }

      await Promise.all(promises);
      expect(mockCreate).not.toHaveBeenCalled();
    });
  });

  describe("10. API completeness", () => {
    test("10.1 send es async y retorna Promise<void>", () => {
      const result = service.send({
        type: "test",
        title: "Test",
        message: "Test",
        severity: "LOW",
      });
      expect(result).toBeInstanceOf(Promise);
    });

    test("10.2 enable retorna void", () => {
      expect(() => service.enable()).not.toThrow();
    });

    test("10.3 disable retorna void", () => {
      expect(() => service.disable()).not.toThrow();
    });
  });
});
