/**
 * Retry with exponential backoff utility
 */

export interface RetryOptions {
  maxAttempts: number;
  baseDelayMs: number;
  maxDelayMs: number;
  backoffMultiplier: number;
  retryableErrors?: string[];
}

const DEFAULT_RETRY_OPTIONS: RetryOptions = {
  maxAttempts: 3,
  baseDelayMs: 100,
  maxDelayMs: 5000,
  backoffMultiplier: 2,
};

function isErrorRetryable(error: Error, retryableErrors?: string[]): boolean {
  if (!retryableErrors || retryableErrors.length === 0) return true;
  return retryableErrors.some((pattern) => error.message.includes(pattern));
}

function calculateDelay(attempt: number, opts: RetryOptions): number {
  const delay = Math.min(
    opts.baseDelayMs * Math.pow(opts.backoffMultiplier, attempt - 1),
    opts.maxDelayMs,
  );
  return delay * (0.5 + Math.random() * 0.5);
}

export async function withRetry<T>(
  fn: () => Promise<T>,
  options?: Partial<RetryOptions>,
): Promise<T> {
  const opts = { ...DEFAULT_RETRY_OPTIONS, ...options };
  let lastError: Error | undefined;

  for (let attempt = 1; attempt <= opts.maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error instanceof Error ? error : new Error(String(error));

      if (attempt === opts.maxAttempts) break;

      if (!isErrorRetryable(lastError, opts.retryableErrors)) break;

      await new Promise((resolve) => setTimeout(resolve, calculateDelay(attempt, opts)));
    }
  }

  throw lastError;
}