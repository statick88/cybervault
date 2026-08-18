const requestCounts = new Map<string, { count: number; resetTime: number }>();
const RATE_LIMIT_MAX = 100;
const RATE_LIMIT_WINDOW = 15 * 60 * 1000;

const validateRequestCounts = new Map<
  string,
  { count: number; resetTime: number }
>();
const VALIDATE_RATE_LIMIT_MAX = 20;
const VALIDATE_RATE_LIMIT_WINDOW = 5 * 60 * 1000;

export { RATE_LIMIT_MAX, RATE_LIMIT_WINDOW };

export function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const record = requestCounts.get(ip);

  if (!record) {
    requestCounts.set(ip, { count: 1, resetTime: now + RATE_LIMIT_WINDOW });
    return true;
  }

  if (now > record.resetTime) {
    requestCounts.set(ip, { count: 1, resetTime: now + RATE_LIMIT_WINDOW });
    return true;
  }

  record.count++;

  if (record.count > RATE_LIMIT_MAX) {
    return false;
  }

  return true;
}

export function checkValidateRateLimit(ip: string): boolean {
  const now = Date.now();
  const record = validateRequestCounts.get(ip);

  if (!record) {
    validateRequestCounts.set(ip, {
      count: 1,
      resetTime: now + VALIDATE_RATE_LIMIT_WINDOW,
    });
    return true;
  }

  if (now > record.resetTime) {
    validateRequestCounts.set(ip, {
      count: 1,
      resetTime: now + VALIDATE_RATE_LIMIT_WINDOW,
    });
    return true;
  }

  record.count++;

  if (record.count > VALIDATE_RATE_LIMIT_MAX) {
    return false;
  }

  return true;
}

function cleanupRateLimits(): void {
  const now = Date.now();
  requestCounts.forEach((record, ip) => {
    if (now > record.resetTime) {
      requestCounts.delete(ip);
    }
  });
  validateRequestCounts.forEach((record, ip) => {
    if (now > record.resetTime) {
      validateRequestCounts.delete(ip);
    }
  });
}

export function _clearRateLimitForTests(): void {
  requestCounts.clear();
}

const _rateLimitCleanupInterval = setInterval(
  cleanupRateLimits,
  5 * 60 * 1000,
);
if (_rateLimitCleanupInterval.unref) _rateLimitCleanupInterval.unref();
