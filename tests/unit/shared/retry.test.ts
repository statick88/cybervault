import { withRetry, RetryOptions } from "../../../src/shared/retry";

describe("withRetry", () => {
  it("succeeds on first attempt without retrying", async () => {
    const fn = jest.fn().mockResolvedValue("ok");

    const result = await withRetry(fn);

    expect(result).toBe("ok");
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it("retries on failure and eventually succeeds", async () => {
    const fn = jest
      .fn()
      .mockRejectedValueOnce(new Error("fail 1"))
      .mockRejectedValueOnce(new Error("fail 2"))
      .mockResolvedValue("success");

    const result = await withRetry(fn, { baseDelayMs: 1, maxAttempts: 3 });

    expect(result).toBe("success");
    expect(fn).toHaveBeenCalledTimes(3);
  });

  it("exhausts maxAttempts and throws the last error", async () => {
    const fn = jest.fn().mockRejectedValue(new Error("persistent failure"));

    await expect(
      withRetry(fn, { maxAttempts: 3, baseDelayMs: 1 }),
    ).rejects.toThrow("persistent failure");

    expect(fn).toHaveBeenCalledTimes(3);
  });

  it("respects custom delay by using exponential backoff", async () => {
    const delays: number[] = [];
    const originalSetTimeout = global.setTimeout;

    // Mock setTimeout to capture delays without actually waiting
    jest
      .spyOn(global, "setTimeout")
      .mockImplementation(((cb: (...args: unknown[]) => void, ms?: number) => {
        delays.push(ms ?? 0);
        cb();
        return 0 as unknown as ReturnType<typeof originalSetTimeout>;
      }) as typeof setTimeout);

    const fn = jest
      .fn()
      .mockRejectedValueOnce(new Error("fail"))
      .mockResolvedValue("ok");

    try {
      await withRetry(fn, {
        maxAttempts: 2,
        baseDelayMs: 100,
        backoffMultiplier: 2,
      });
    } finally {
      jest.restoreAllMocks();
    }

    // The first retry should use baseDelayMs * multiplier^(attempt-1) = 100 * 2^0 = 100
    // plus jitter (0.5x-1x), so delay should be in [50, 100]
    expect(delays.length).toBe(1);
    expect(delays[0]).toBeGreaterThanOrEqual(50);
    expect(delays[0]).toBeLessThanOrEqual(100);
  });

  it("breaks early on non-retryable error when retryableErrors is set", async () => {
    const fn = jest.fn().mockRejectedValue(new Error("auth error"));

    await expect(
      withRetry(fn, {
        maxAttempts: 3,
        baseDelayMs: 1,
        retryableErrors: ["timeout", "connection"],
      }),
    ).rejects.toThrow("auth error");

    // Should not retry since "auth error" doesn't match any retryable pattern
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it("retries when error matches retryableErrors pattern", async () => {
    const fn = jest
      .fn()
      .mockRejectedValueOnce(new Error("timeout exceeded"))
      .mockResolvedValue("ok");

    const result = await withRetry(fn, {
      maxAttempts: 3,
      baseDelayMs: 1,
      retryableErrors: ["timeout"],
    });

    expect(result).toBe("ok");
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it("wraps non-Error throws into Error objects", async () => {
    const fn = jest.fn().mockRejectedValue("string error");

    await expect(
      withRetry(fn, { maxAttempts: 1, baseDelayMs: 1 }),
    ).rejects.toThrow("string error");
  });
});
