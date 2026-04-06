import { AlarmService } from "@/background/services/AlarmService";

// Mock de chrome.alarms
const mockCreate = jest.fn();
const mockClear = jest.fn();
const mockGetAll = jest.fn();
const mockGet = jest.fn();
const mockOnAlarm = {
  addListener: jest.fn(),
};

// Mock global de chrome
(global as any).chrome = {
  alarms: {
    create: mockCreate,
    clear: mockClear,
    getAll: mockGetAll,
    get: mockGet,
    onAlarm: mockOnAlarm,
  },
};

// Helper para crear mock de orchestrator
const createMockOrchestrator = () => ({
  runFullAudit: jest.fn().mockResolvedValue(undefined),
});

// Helper para limpiar mocks
const clearMocks = () => {
  jest.clearAllMocks();
  mockGetAll.mockResolvedValue([]);
  mockGet.mockResolvedValue(null);
  mockCreate.mockResolvedValue(undefined);
  mockClear.mockResolvedValue(true);
};

// Helper para obtener el listener registrado
const getRegisteredListener = () => {
  const calls = mockOnAlarm.addListener.mock.calls;
  return calls[calls.length - 1][0] as (
    alarm: chrome.alarms.Alarm,
  ) => Promise<void> | void;
};

describe("AlarmService", () => {
  let mockOrchestrator: ReturnType<typeof createMockOrchestrator>;

  beforeEach(() => {
    clearMocks();
    mockOrchestrator = createMockOrchestrator();
  });

  describe("1. setupPeriodicScan", () => {
    test("1.1 Crea alarm con nombre 'auditor_periodic_scan'", async () => {
      const service = new AlarmService(
        mockOrchestrator.runFullAudit.bind(mockOrchestrator),
      );
      await service.setupPeriodicScan(1);

      expect(mockCreate).toHaveBeenCalledWith("auditor_periodic_scan", {
        periodInMinutes: 60,
      });
    });

    test("1.2 Periodo correcto en minutos (intervalHours * 60)", async () => {
      const service = new AlarmService(
        mockOrchestrator.runFullAudit.bind(mockOrchestrator),
      );
      await service.setupPeriodicScan(2);

      expect(mockCreate).toHaveBeenCalledWith("auditor_periodic_scan", {
        periodInMinutes: 120,
      });
    });

    test("1.3 Periodo con decimales se redondea correctamente", async () => {
      const service = new AlarmService(
        mockOrchestrator.runFullAudit.bind(mockOrchestrator),
      );
      await service.setupPeriodicScan(1.5);

      expect(mockCreate).toHaveBeenCalledWith("auditor_periodic_scan", {
        periodInMinutes: 90,
      });
    });

    test("1.4 setupPeriodicScan puede llamarse múltiples veces", async () => {
      const service = new AlarmService(
        mockOrchestrator.runFullAudit.bind(mockOrchestrator),
      );
      await service.setupPeriodicScan(1);
      await service.setupPeriodicScan(2);

      expect(mockCreate).toHaveBeenCalledTimes(2);
    });
  });

  describe("2. clearAll", () => {
    test("2.1 Limpia todas las alarms que empiezan con 'auditor_'", async () => {
      const alarms = [
        { name: "auditor_periodic_scan", scheduledTime: Date.now() },
        { name: "auditor_other", scheduledTime: Date.now() },
        { name: "auditor_cleanup", scheduledTime: Date.now() },
      ];
      mockGetAll.mockResolvedValue(alarms);

      const service = new AlarmService(
        mockOrchestrator.runFullAudit.bind(mockOrchestrator),
      );
      await service.clearAll();

      expect(mockClear).toHaveBeenCalledTimes(3);
      expect(mockClear).toHaveBeenCalledWith("auditor_periodic_scan");
      expect(mockClear).toHaveBeenCalledWith("auditor_other");
      expect(mockClear).toHaveBeenCalledWith("auditor_cleanup");
    });

    test("2.2 No elimina alarms con otros prefijos", async () => {
      const alarms = [
        { name: "auditor_periodic_scan", scheduledTime: Date.now() },
        { name: "other_alarm", scheduledTime: Date.now() },
        { name: "different_thing", scheduledTime: Date.now() },
      ];
      mockGetAll.mockResolvedValue(alarms);

      const service = new AlarmService(
        mockOrchestrator.runFullAudit.bind(mockOrchestrator),
      );
      await service.clearAll();

      expect(mockClear).toHaveBeenCalledTimes(1);
      expect(mockClear).toHaveBeenCalledWith("auditor_periodic_scan");
    });

    test("2.3 clearAll con no alarms → sin error", async () => {
      mockGetAll.mockResolvedValue([]);

      const service = new AlarmService(
        mockOrchestrator.runFullAudit.bind(mockOrchestrator),
      );
      await expect(service.clearAll()).resolves.not.toThrow();

      expect(mockClear).not.toHaveBeenCalled();
    });

    test("2.4 clearAll maneja error en chrome.alarms.clear", async () => {
      const alarms = [
        { name: "auditor_periodic_scan", scheduledTime: Date.now() },
      ];
      mockGetAll.mockResolvedValue(alarms);
      mockClear.mockRejectedValue(new Error("Chrome error"));

      const service = new AlarmService(
        mockOrchestrator.runFullAudit.bind(mockOrchestrator),
      );
      await expect(service.clearAll()).rejects.toThrow("Chrome error");

      expect(mockClear).toHaveBeenCalledWith("auditor_periodic_scan");
    });
  });

  describe("3. onAlarm", () => {
    test("3.1 Si alarm name es PERIODIC_SCAN → llama a orchestrator.runFullAudit()", async () => {
      const service = new AlarmService(
        mockOrchestrator.runFullAudit.bind(mockOrchestrator),
      );
      const alarm = { name: "auditor_periodic_scan" } as chrome.alarms.Alarm;

      await service.onAlarm(alarm);

      expect(mockOrchestrator.runFullAudit).toHaveBeenCalledTimes(1);
    });

    test("3.2 Si alarm name es otro → no hace nada", async () => {
      const service = new AlarmService(
        mockOrchestrator.runFullAudit.bind(mockOrchestrator),
      );
      const alarm = { name: "other_alarm" } as chrome.alarms.Alarm;

      await service.onAlarm(alarm);

      expect(mockOrchestrator.runFullAudit).not.toHaveBeenCalled();
    });

    test("3.3 onAlarm captura errores del orchestrator y no crash", async () => {
      const consoleSpy = jest
        .spyOn(console, "error")
        .mockImplementation(() => {});
      const mockOrchestratorWithError = {
        runFullAudit: jest.fn().mockRejectedValue(new Error("Audit failed")),
      };

      const service = new AlarmService(
        mockOrchestratorWithError.runFullAudit.bind(mockOrchestratorWithError),
      );
      const alarm = { name: "auditor_periodic_scan" } as chrome.alarms.Alarm;

      // Should NOT throw, should handle gracefully
      await expect(service.onAlarm(alarm)).resolves.not.toThrow();

      expect(consoleSpy).toHaveBeenCalled();
      consoleSpy.mockRestore();
    });

    test("3.4 onAlarm con alarm sin name → no hace nada", async () => {
      const service = new AlarmService(
        mockOrchestrator.runFullAudit.bind(mockOrchestrator),
      );
      const alarm = { name: "" } as chrome.alarms.Alarm;

      await service.onAlarm(alarm);

      expect(mockOrchestrator.runFullAudit).not.toHaveBeenCalled();
    });
  });

  describe("4. isPeriodicScanAlarm", () => {
    test("4.1 Retorna true para nombre PERIODIC_SCAN", () => {
      const service = new AlarmService(
        mockOrchestrator.runFullAudit.bind(mockOrchestrator),
      );
      const alarm = { name: "auditor_periodic_scan" } as chrome.alarms.Alarm;

      expect(service.isPeriodicScanAlarm(alarm)).toBe(true);
    });

    test("4.2 Retorna false para otros nombres", () => {
      const service = new AlarmService(
        mockOrchestrator.runFullAudit.bind(mockOrchestrator),
      );
      const alarm = { name: "other_alarm" } as chrome.alarms.Alarm;

      expect(service.isPeriodicScanAlarm(alarm)).toBe(false);
    });

    test("4.3 Retorna false para alarm sin nombre", () => {
      const service = new AlarmService(
        mockOrchestrator.runFullAudit.bind(mockOrchestrator),
      );
      const alarm = { name: "" } as chrome.alarms.Alarm;

      expect(service.isPeriodicScanAlarm(alarm)).toBe(false);
    });

    test("4.4 isPeriodicScanAlarm distingue mayúsculas/minúsculas", () => {
      const service = new AlarmService(
        mockOrchestrator.runFullAudit.bind(mockOrchestrator),
      );
      const alarm = { name: "AUDITOR_PERIODIC_SCAN" } as chrome.alarms.Alarm;

      expect(service.isPeriodicScanAlarm(alarm)).toBe(false);
    });
  });

  describe("5. getNextScheduledTime", () => {
    test("5.1 Retorna Date si alarm existe con scheduledTime", async () => {
      const scheduledTime = Date.now() + 3600000;
      mockGet.mockResolvedValue({ scheduledTime });

      const service = new AlarmService(
        mockOrchestrator.runFullAudit.bind(mockOrchestrator),
      );
      const result = await service.getNextScheduledTime();

      expect(result).toBeInstanceOf(Date);
      expect(result?.getTime()).toBe(scheduledTime);
    });

    test("5.2 Retorna null si alarm no existe", async () => {
      mockGet.mockResolvedValue(null);

      const service = new AlarmService(
        mockOrchestrator.runFullAudit.bind(mockOrchestrator),
      );
      const result = await service.getNextScheduledTime();

      expect(result).toBeNull();
    });

    test("5.3 Retorna null si alarm existe pero sin scheduledTime", async () => {
      mockGet.mockResolvedValue({ name: "auditor_periodic_scan" });

      const service = new AlarmService(
        mockOrchestrator.runFullAudit.bind(mockOrchestrator),
      );
      const result = await service.getNextScheduledTime();

      expect(result).toBeNull();
    });

    test("5.4 getNextScheduledTime llama a chrome.alarms.get con nombre correcto", async () => {
      mockGet.mockResolvedValue({ scheduledTime: Date.now() });

      const service = new AlarmService(
        mockOrchestrator.runFullAudit.bind(mockOrchestrator),
      );
      await service.getNextScheduledTime();

      expect(mockGet).toHaveBeenCalledWith("auditor_periodic_scan");
    });
  });

  describe("6. Constructor y registro de listener", () => {
    test("6.1 Constructor registra listener en chrome.alarms.onAlarm", () => {
      new AlarmService(mockOrchestrator.runFullAudit.bind(mockOrchestrator));
      expect(mockOnAlarm.addListener).toHaveBeenCalledTimes(1);
    });

    test("6.2 Constructor llama a addListener con función bound", () => {
      const runFullAudit = jest.fn().mockResolvedValue(undefined);
      const service = new AlarmService(runFullAudit);

      const listenerArg = mockOnAlarm.addListener.mock.calls[0][0];
      expect(typeof listenerArg).toBe("function");
    });
  });

  describe("7. Integración y tipo de alarmas", () => {
    test("7.1 onAlarm es llamado con alarm object correcto", async () => {
      const service = new AlarmService(
        mockOrchestrator.runFullAudit.bind(mockOrchestrator),
      );
      const listener = getRegisteredListener();

      const mockAlarm = {
        name: "auditor_periodic_scan",
        scheduledTime: Date.now(),
      };
      await listener(mockAlarm);

      expect(mockOrchestrator.runFullAudit).toHaveBeenCalled();
    });

    test("7.2 isPeriodicScanAlarm y onAlarm trabajan en conjunto", async () => {
      const service = new AlarmService(
        mockOrchestrator.runFullAudit.bind(mockOrchestrator),
      );

      const periodicAlarm = {
        name: "auditor_periodic_scan",
      } as chrome.alarms.Alarm;
      const otherAlarm = { name: "random_alarm" } as chrome.alarms.Alarm;

      expect(service.isPeriodicScanAlarm(periodicAlarm)).toBe(true);
      expect(service.isPeriodicScanAlarm(otherAlarm)).toBe(false);

      await service.onAlarm(periodicAlarm);
      expect(mockOrchestrator.runFullAudit).toHaveBeenCalledTimes(1);

      await service.onAlarm(otherAlarm);
      expect(mockOrchestrator.runFullAudit).toHaveBeenCalledTimes(1);
    });
  });

  describe("8. Tipos y edge cases adicionales", () => {
    test("8.1 Alarm con scheduledTime como string numérico", async () => {
      const scheduledTime = "1234567890000";
      mockGet.mockResolvedValue({ scheduledTime: Number(scheduledTime) });

      const service = new AlarmService(
        mockOrchestrator.runFullAudit.bind(mockOrchestrator),
      );
      const result = await service.getNextScheduledTime();

      expect(result).toBeInstanceOf(Date);
      expect(result?.getTime()).toBe(Number(scheduledTime));
    });

    test("8.2 Alarm con scheduledTime negativo (edge)", async () => {
      mockGet.mockResolvedValue({ scheduledTime: -1 });

      const service = new AlarmService(
        mockOrchestrator.runFullAudit.bind(mockOrchestrator),
      );
      const result = await service.getNextScheduledTime();

      expect(result).toBeInstanceOf(Date);
    });

    test("8.3 clearAll mantiene alarms que empiezan con 'auditor' pero no exactamente 'auditor_'", async () => {
      const alarms = [
        { name: "auditorperiodic_scan", scheduledTime: Date.now() },
        { name: "auditor_periodic_scan", scheduledTime: Date.now() },
        { name: "not_auditor", scheduledTime: Date.now() },
      ];
      mockGetAll.mockResolvedValue(alarms);

      const service = new AlarmService(
        mockOrchestrator.runFullAudit.bind(mockOrchestrator),
      );
      await service.clearAll();

      expect(mockClear).toHaveBeenCalledTimes(1);
      expect(mockClear).toHaveBeenCalledWith("auditor_periodic_scan");
    });

    test("8.4 onAlarm maneja undefined como alarm sin crash", async () => {
      const consoleSpy = jest
        .spyOn(console, "error")
        .mockImplementation(() => {});
      const service = new AlarmService(
        mockOrchestrator.runFullAudit.bind(mockOrchestrator),
      );

      // Should NOT throw even with undefined alarm
      await expect(service.onAlarm(undefined as any)).resolves.not.toThrow();

      expect(mockOrchestrator.runFullAudit).not.toHaveBeenCalled();
      consoleSpy.mockRestore();
    });
  });
});
