import { ScanScheduler } from "@/background/services/ScanScheduler";

// Mock de AlarmService
const createMockAlarmService = (
  config: {
    setupPeriodicScan?: jest.Mock;
    clearAll?: jest.Mock;
    getNextScheduledTime?: jest.Mock;
  } = {},
) => ({
  setupPeriodicScan:
    config.setupPeriodicScan ?? jest.fn().mockResolvedValue(undefined),
  clearAll: config.clearAll ?? jest.fn().mockResolvedValue(undefined),
  getNextScheduledTime:
    config.getNextScheduledTime ?? jest.fn().mockResolvedValue(null),
});

// Helper para limpiar mocks
const clearMocks = (
  mockAlarmService: ReturnType<typeof createMockAlarmService>,
) => {
  jest.clearAllMocks();
  mockAlarmService.setupPeriodicScan.mockClear();
  mockAlarmService.clearAll.mockClear();
  mockAlarmService.getNextScheduledTime.mockClear();
};

describe("ScanScheduler", () => {
  let mockAlarmService: ReturnType<typeof createMockAlarmService>;

  beforeEach(() => {
    mockAlarmService = createMockAlarmService();
  });

  describe("1. Constructor y dependencias", () => {
    test("1.1 Constructor recibe AlarmService correctamente", () => {
      const scheduler = new ScanScheduler(mockAlarmService);
      expect(scheduler).toBeInstanceOf(ScanScheduler);
    });

    test("1.2 Constructor no llama métodos automáticamente", () => {
      new ScanScheduler(mockAlarmService);

      expect(mockAlarmService.setupPeriodicScan).not.toHaveBeenCalled();
      expect(mockAlarmService.clearAll).not.toHaveBeenCalled();
    });
  });

  describe("2. schedule", () => {
    test("2.1 schedule llama a clearAll() primero", async () => {
      const scheduler = new ScanScheduler(mockAlarmService);
      await scheduler.schedule(1);

      expect(mockAlarmService.clearAll).toHaveBeenCalledTimes(1);
    });

    test("2.2 schedule llama a setupPeriodicScan con intervalHours", async () => {
      const scheduler = new ScanScheduler(mockAlarmService);
      await scheduler.schedule(2);

      expect(mockAlarmService.setupPeriodicScan).toHaveBeenCalledWith(2);
    });

    test("2.3 schedule con 1 hora llama correctamente", async () => {
      const scheduler = new ScanScheduler(mockAlarmService);
      await scheduler.schedule(1);

      expect(mockAlarmService.clearAll).toHaveBeenCalled();
      expect(mockAlarmService.setupPeriodicScan).toHaveBeenCalledWith(1);
    });

    test("2.4 schedule con decimales pasa el valor exacto", async () => {
      const scheduler = new ScanScheduler(mockAlarmService);
      await scheduler.schedule(1.5);

      expect(mockAlarmService.setupPeriodicScan).toHaveBeenCalledWith(1.5);
    });

    test("2.5chedule puede llamarse múltiples veces", async () => {
      const scheduler = new ScanScheduler(mockAlarmService);
      await scheduler.schedule(1);
      await scheduler.schedule(2);

      expect(mockAlarmService.clearAll).toHaveBeenCalledTimes(2);
      expect(mockAlarmService.setupPeriodicScan).toHaveBeenCalledTimes(2);
      expect(mockAlarmService.setupPeriodicScan).toHaveBeenNthCalledWith(1, 1);
      expect(mockAlarmService.setupPeriodicScan).toHaveBeenNthCalledWith(2, 2);
    });

    test("2.6 schedule maneja errores de AlarmService", async () => {
      const consoleSpy = jest
        .spyOn(console, "error")
        .mockImplementation(() => {});
      const errorService = createMockAlarmService({
        clearAll: jest.fn().mockRejectedValue(new Error("Clear failed")),
      });

      const scheduler = new ScanScheduler(errorService);

      await expect(scheduler.schedule(1)).rejects.toThrow("Clear failed");
      consoleSpy.mockRestore();
    });

    test("2.7 schedule llama a clearAll ANTES de setupPeriodicScan", async () => {
      const scheduler = new ScanScheduler(mockAlarmService);

      const clearPromise = mockAlarmService.clearAll.mockImplementation(() => {
        return new Promise((resolve) => setTimeout(resolve, 10));
      });
      const setupPromise =
        mockAlarmService.setupPeriodicScan.mockResolvedValue(undefined);

      await scheduler.schedule(1);

      expect(mockAlarmService.clearAll).toHaveBeenCalledBefore(
        mockAlarmService.setupPeriodicScan,
      );
    });
  });

  describe("3. rescheduleAfterConfigChange", () => {
    test("3.1 Si newInterval !== oldInterval → llama a schedule", async () => {
      const scheduler = new ScanScheduler(mockAlarmService);

      await scheduler.rescheduleAfterConfigChange(2, 1);

      expect(mockAlarmService.clearAll).toHaveBeenCalled();
      expect(mockAlarmService.setupPeriodicScan).toHaveBeenCalledWith(2);
    });

    test("3.2 Si newInterval === oldInterval → NO llama a schedule", async () => {
      const scheduler = new ScanScheduler(mockAlarmService);

      await scheduler.rescheduleAfterConfigChange(2, 2);

      expect(mockAlarmService.clearAll).not.toHaveBeenCalled();
      expect(mockAlarmService.setupPeriodicScan).not.toHaveBeenCalled();
    });

    test("3.3 Reschedule con misma纵但 diferentes tipos (numérico)", async () => {
      const scheduler = new ScanScheduler(mockAlarmService);

      await scheduler.rescheduleAfterConfigChange(2.0, 2);

      // 2.0 === 2 en JavaScript, entonces NO debe llamar
      expect(mockAlarmService.clearAll).not.toHaveBeenCalled();
    });

    test("3.4 Reschedule con interval 0 y 0.0 → iguales", async () => {
      const scheduler = new ScanScheduler(mockAlarmService);

      await scheduler.rescheduleAfterConfigChange(0, 0.0);

      expect(mockAlarmService.clearAll).not.toHaveBeenCalled();
    });

    test("3.5 Reschedule de null/undefined → se reschedulea", async () => {
      const scheduler = new ScanScheduler(mockAlarmService);

      await scheduler.rescheduleAfterConfigChange(1, undefined as any);

      expect(mockAlarmService.clearAll).toHaveBeenCalled();
    });

    test("3.6 Reschedule múltiple con diferentes cambios", async () => {
      const scheduler = new ScanScheduler(mockAlarmService);

      await scheduler.rescheduleAfterConfigChange(2, 1); // diff → schedule
      await scheduler.rescheduleAfterConfigChange(3, 2); // diff → schedule
      await scheduler.rescheduleAfterConfigChange(3, 3); // equal → no schedule

      expect(mockAlarmService.setupPeriodicScan).toHaveBeenCalledTimes(2);
      expect(mockAlarmService.setupPeriodicScan).toHaveBeenNthCalledWith(1, 2);
      expect(mockAlarmService.setupPeriodicScan).toHaveBeenNthCalledWith(2, 3);
    });

    test("3.7 Reschedule no afecta getNextScheduledTime", async () => {
      const scheduler = new ScanScheduler(mockAlarmService);

      await scheduler.rescheduleAfterConfigChange(2, 1);

      expect(mockAlarmService.getNextScheduledTime).not.toHaveBeenCalled();
    });
  });

  describe("4. getNextScan", () => {
    test("4.1 getNextScan delega a alarmService.getNextScheduledTime()", async () => {
      mockAlarmService.getNextScheduledTime.mockResolvedValue(new Date());

      const scheduler = new ScanScheduler(mockAlarmService);
      const result = await scheduler.getNextScan();

      expect(mockAlarmService.getNextScheduledTime).toHaveBeenCalledTimes(1);
    });

    test("4.2 getNextScan retorna Date cuando alarmService retorna Date", async () => {
      const now = new Date();
      mockAlarmService.getNextScheduledTime.mockResolvedValue(now);

      const scheduler = new ScanScheduler(mockAlarmService);
      const result = await scheduler.getNextScan();

      expect(result).toBeInstanceOf(Date);
      expect(result).toBe(now);
    });

    test("4.3 getNextScan retorna null cuando alarmService retorna null", async () => {
      mockAlarmService.getNextScheduledTime.mockResolvedValue(null);

      const scheduler = new ScanScheduler(mockAlarmService);
      const result = await scheduler.getNextScan();

      expect(result).toBeNull();
    });

    test("4.4 getNextScan no modifica otros métodos", async () => {
      mockAlarmService.getNextScheduledTime.mockResolvedValue(new Date());

      const scheduler = new ScanScheduler(mockAlarmService);
      await scheduler.getNextScan();

      expect(mockAlarmService.clearAll).not.toHaveBeenCalled();
      expect(mockAlarmService.setupPeriodicScan).not.toHaveBeenCalled();
    });

    test("4.5 getNextScan puede llamarse múltiples veces", async () => {
      mockAlarmService.getNextScheduledTime.mockResolvedValue(new Date());

      const scheduler = new ScanScheduler(mockAlarmService);
      await scheduler.getNextScan();
      await scheduler.getNextScan();
      await scheduler.getNextScan();

      expect(mockAlarmService.getNextScheduledTime).toHaveBeenCalledTimes(3);
    });

    test("4.6 getNextScan propaga errores de alarmService", async () => {
      mockAlarmService.getNextScheduledTime.mockRejectedValue(
        new Error("Alarm service error"),
      );

      const scheduler = new ScanScheduler(mockAlarmService);

      await expect(scheduler.getNextScan()).rejects.toThrow(
        "Alarm service error",
      );
    });

    test("4.7 getNextScan retorna Date con tiempo futuro", async () => {
      const futureTime = Date.now() + 3600000; // 1 hora en el futuro
      mockAlarmService.getNextScheduledTime.mockResolvedValue(
        new Date(futureTime),
      );

      const scheduler = new ScanScheduler(mockAlarmService);
      const result = await scheduler.getNextScan();

      expect(result?.getTime()).toBeGreaterThanOrEqual(Date.now());
    });
  });

  describe("5. Integración de múltiples métodos", () => {
    test("5.1 Ciclo completo: schedule → getNextScan", async () => {
      const futureDate = new Date(Date.now() + 7200000);
      mockAlarmService.getNextScheduledTime.mockResolvedValue(futureDate);

      const scheduler = new ScanScheduler(mockAlarmService);

      await scheduler.schedule(2);
      const nextScan = await scheduler.getNextScan();

      expect(nextScan).toBe(futureDate);
      expect(mockAlarmService.clearAll).toHaveBeenCalled();
      expect(mockAlarmService.setupPeriodicScan).toHaveBeenCalledWith(2);
    });

    test("5.2 Flujo: schedule → reschedule → getNextScan", async () => {
      const futureDate = new Date(Date.now() + 10800000);
      mockAlarmService.getNextScheduledTime.mockResolvedValue(futureDate);

      const scheduler = new ScanScheduler(mockAlarmService);

      await scheduler.schedule(1);
      clearMocks(mockAlarmService);

      await scheduler.rescheduleAfterConfigChange(3, 1);
      const nextScan = await scheduler.getNextScan();

      expect(nextScan).toBe(futureDate);
      expect(mockAlarmService.setupPeriodicScan).toHaveBeenCalledWith(3);
    });

    test("5.3 schedule después de reschedule mantiene nuevo intervalo", async () => {
      const scheduler = new ScanScheduler(mockAlarmService);

      // Schedule inicial
      await scheduler.schedule(1);
      expect(mockAlarmService.setupPeriodicScan).toHaveBeenCalledWith(1);

      // Reschedule
      clearMocks(mockAlarmService);
      await scheduler.rescheduleAfterConfigChange(2, 1);
      expect(mockAlarmService.setupPeriodicScan).toHaveBeenCalledWith(2);

      // Schedule explícito después del reschedule
      clearMocks(mockAlarmService);
      await scheduler.schedule(3);
      expect(mockAlarmService.setupPeriodicScan).toHaveBeenCalledWith(3);
    });
  });

  describe("6. Manejo de errores y validación", () => {
    test("6.1 schedule con alarmService setupPeriodicScan fallando", async () => {
      mockAlarmService.setupPeriodicScan.mockRejectedValue(
        new Error("Setup failed"),
      );

      const scheduler = new ScanScheduler(mockAlarmService);

      await expect(scheduler.schedule(1)).rejects.toThrow("Setup failed");
      expect(mockAlarmService.clearAll).toHaveBeenCalled();
    });

    test("6.2 schedule con clearAll fallando", async () => {
      mockAlarmService.clearAll.mockRejectedValue(new Error("Clear failed"));

      const scheduler = new ScanScheduler(mockAlarmService);

      await expect(scheduler.schedule(1)).rejects.toThrow("Clear failed");
      expect(mockAlarmService.setupPeriodicScan).not.toHaveBeenCalled();
    });

    test("6.3 getNextScan con alarmService fallando", async () => {
      mockAlarmService.getNextScheduledTime.mockRejectedValue(
        new Error("Get failed"),
      );

      const scheduler = new ScanScheduler(mockAlarmService);

      await expect(scheduler.getNextScan()).rejects.toThrow("Get failed");
    });
  });

  describe("7. Orden de operaciones", () => {
    test("7.1 schedule ejecuta clearAll antes que setupPeriodicScan (garantizado)", async () => {
      const scheduler = new ScanScheduler(mockAlarmService);

      const clearMock = mockAlarmService.clearAll.mockImplementation(() => {
        // Verificar que setupPeriodicScan aun no fue llamado
        expect(mockAlarmService.setupPeriodicScan).not.toHaveBeenCalled();
        return Promise.resolve();
      });

      await scheduler.schedule(2);

      expect(clearMock).toHaveBeenCalled();
      expect(mockAlarmService.setupPeriodicScan).toHaveBeenCalled();
    });

    test("7.2 rescheduleAfterConfigChange usa schedule cuando intervals difieren", async () => {
      const scheduler = new ScanScheduler(mockAlarmService);

      await scheduler.rescheduleAfterConfigChange(3, 1);

      expect(mockAlarmService.clearAll).toHaveBeenCalled();
      expect(mockAlarmService.setupPeriodicScan).toHaveBeenCalledWith(3);
    });
  });

  describe("8. Tipos de retorno y contratos", () => {
    test("8.1 schedule retorna Promise<void>", async () => {
      const scheduler = new ScanScheduler(mockAlarmService);
      const result = scheduler.schedule(1);

      expect(result).toBeInstanceOf(Promise);
      await expect(result).resolves.toBeUndefined();
    });

    test("8.2 rescheduleAfterConfigChange retorna Promise<void>", async () => {
      const scheduler = new ScanScheduler(mockAlarmService);
      const result = scheduler.rescheduleAfterConfigChange(2, 1);

      expect(result).toBeInstanceOf(Promise);
      await expect(result).resolves.toBeUndefined();
    });

    test("8.3 getNextScan retorna Promise<Date | null>", async () => {
      const scheduler = new ScanScheduler(mockAlarmService);
      const result = scheduler.getNextScan();

      expect(result).toBeInstanceOf(Promise);
      const resolved = await result;
      expect(typeof resolved === "object" || resolved === null).toBe(true);
    });
  });

  describe("9. Isolation entre instancias", () => {
    test("9.1 Diferentes instancias usan diferentes mocks", async () => {
      const mockAlarmService2 = createMockAlarmService();

      const scheduler1 = new ScanScheduler(mockAlarmService);
      const scheduler2 = new ScanScheduler(mockAlarmService2);

      await scheduler1.schedule(1);
      await scheduler2.schedule(2);

      expect(mockAlarmService.setupPeriodicScan).toHaveBeenCalledWith(1);
      expect(mockAlarmService2.setupPeriodicScan).toHaveBeenCalledWith(2);
    });

    test("9.2 getNextScan de diferentes instancias no se mezclan", async () => {
      const date1 = new Date();
      const date2 = new Date(Date.now() + 10000);
      mockAlarmService.getNextScheduledTime
        .mockResolvedValueOnce(date1)
        .mockResolvedValueOnce(date2);

      const scheduler1 = new ScanScheduler(mockAlarmService);
      const scheduler2 = new ScanScheduler(mockAlarmService);

      const result1 = await scheduler1.getNextScan();
      const result2 = await scheduler2.getNextScan();

      expect(result1).toBe(date1);
      expect(result2).toBe(date2);
    });
  });

  describe("10. Validación de parámetros", () => {
    test("10.1 schedule acepta interval 0", async () => {
      const scheduler = new ScanScheduler(mockAlarmService);

      await expect(scheduler.schedule(0)).resolves.not.toThrow();

      expect(mockAlarmService.setupPeriodicScan).toHaveBeenCalledWith(0);
    });

    test("10.2 schedule con números negativos", async () => {
      const scheduler = new ScanScheduler(mockAlarmService);

      await scheduler.schedule(-1);

      expect(mockAlarmService.setupPeriodicScan).toHaveBeenCalledWith(-1);
    });

    test("10.3 rescheduleAfterConfigChange con oldInterval null y newInterval 0", async () => {
      const scheduler = new ScanScheduler(mockAlarmService);

      await scheduler.rescheduleAfterConfigChange(0, null as any);

      expect(mockAlarmService.clearAll).toHaveBeenCalled();
    });
  });
});
