import {
  CircuitBreaker,
  CircuitState,
} from "../../../src/shared/circuit-breaker";

describe("CircuitBreaker", () => {
  it("starts in CLOSED state", () => {
    const cb = new CircuitBreaker();
    expect(cb.getState()).toBe("closed");
  });

  it("opens after reaching failure threshold", async () => {
    const cb = new CircuitBreaker({ failureThreshold: 3 });
    const failingFn = jest.fn().mockRejectedValue(new Error("fail"));

    for (let i = 0; i < 3; i++) {
      await cb.execute(failingFn).catch(() => {});
    }

    expect(cb.getState()).toBe("open");
  });

  it("transitions to HALF_OPEN after resetTimeout elapses", async () => {
    const cb = new CircuitBreaker({
      failureThreshold: 2,
      resetTimeoutMs: 50,
    });
    const failingFn = jest.fn().mockRejectedValue(new Error("fail"));

    // Open the circuit
    await cb.execute(failingFn).catch(() => {});
    await cb.execute(failingFn).catch(() => {});
    expect(cb.getState()).toBe("open");

    // Wait for reset timeout
    await new Promise((resolve) => setTimeout(resolve, 60));

    expect(cb.getState()).toBe("half_open");
  });

  it("closes again after success in HALF_OPEN", async () => {
    const cb = new CircuitBreaker({
      failureThreshold: 2,
      successThreshold: 1,
      resetTimeoutMs: 50,
    });
    const failingFn = jest.fn().mockRejectedValue(new Error("fail"));
    const successFn = jest.fn().mockResolvedValue("ok");

    // Open the circuit
    await cb.execute(failingFn).catch(() => {});
    await cb.execute(failingFn).catch(() => {});

    // Wait for half_open
    await new Promise((resolve) => setTimeout(resolve, 60));
    expect(cb.getState()).toBe("half_open");

    // Succeed in half_open
    await cb.execute(successFn);
    expect(cb.getState()).toBe("closed");
  });

  it("execute() passes through result on success", async () => {
    const cb = new CircuitBreaker();
    const fn = jest.fn().mockResolvedValue(42);

    const result = await cb.execute(fn);

    expect(result).toBe(42);
  });

  it("execute() throws when circuit is OPEN", async () => {
    const cb = new CircuitBreaker({ failureThreshold: 2 });
    const failingFn = jest.fn().mockRejectedValue(new Error("fail"));

    // Open the circuit
    await cb.execute(failingFn).catch(() => {});
    await cb.execute(failingFn).catch(() => {});

    await expect(cb.execute(jest.fn())).rejects.toThrow(
      "Circuit breaker is OPEN",
    );
  });

  it("success in HALF_OPEN resets failure count", async () => {
    const cb = new CircuitBreaker({
      failureThreshold: 2,
      successThreshold: 2,
      resetTimeoutMs: 50,
    });
    const failingFn = jest.fn().mockRejectedValue(new Error("fail"));
    const successFn = jest.fn().mockResolvedValue("ok");

    // Open the circuit
    await cb.execute(failingFn).catch(() => {});
    await cb.execute(failingFn).catch(() => {});

    // Wait for half_open
    await new Promise((resolve) => setTimeout(resolve, 60));

    // One success in HALF_OPEN: resets failureCount to 0, increments successCount to 1
    await cb.execute(successFn);
    expect(cb.getState()).toBe("half_open");

    // One failure now: failureCount goes from 0→1, but threshold is 2
    // So circuit stays half_open — proving the success reset the count
    await cb.execute(failingFn).catch(() => {});
    expect(cb.getState()).toBe("half_open");

    // Need a second consecutive failure to re-open
    await cb.execute(failingFn).catch(() => {});
    expect(cb.getState()).toBe("open");
  });

  it("reset() returns circuit to CLOSED state", async () => {
    const cb = new CircuitBreaker({ failureThreshold: 2 });
    const failingFn = jest.fn().mockRejectedValue(new Error("fail"));

    await cb.execute(failingFn).catch(() => {});
    await cb.execute(failingFn).catch(() => {});
    expect(cb.getState()).toBe("open");

    cb.reset();
    expect(cb.getState()).toBe("closed");
  });
});
