/**
 * Core's rate limits, now backed by a store every replica can see (R7).
 *
 * The exported names and the numbers are unchanged — `checkRateLimit(ip)` is
 * still 100 per 15 minutes and `checkValidateRateLimit(ip)` is still 20 per 5
 * — so nothing at a call site needs to know that the backing store moved from
 * a module-level `Map` to Redis.
 *
 * The one visible change is that both are now `async`. A call site that
 * `await`s them is correct either way, and the compile error at a site that
 * does not is the point: silently ignoring a rate-limit decision is exactly
 * the failure mode a limiter should never have.
 */

import { getRateLimiter, resetRateLimitersForTest } from "../../rate-limit/shared-store";

const RATE_LIMIT_MAX = 100;
const RATE_LIMIT_WINDOW = 15 * 60 * 1000;

const VALIDATE_RATE_LIMIT_MAX = 20;
const VALIDATE_RATE_LIMIT_WINDOW = 5 * 60 * 1000;

export { RATE_LIMIT_MAX, RATE_LIMIT_WINDOW };

export async function checkRateLimit(ip: string): Promise<boolean> {
  const decision = await getRateLimiter("core-api", RATE_LIMIT_MAX, RATE_LIMIT_WINDOW).consume(ip);
  return decision.allowed;
}

export async function checkValidateRateLimit(ip: string): Promise<boolean> {
  const decision = await getRateLimiter(
    "core-validate",
    VALIDATE_RATE_LIMIT_MAX,
    VALIDATE_RATE_LIMIT_WINDOW,
  ).consume(ip);
  return decision.allowed;
}

/**
 * Drop every limiter's counters.
 *
 * Kept under its historical name because `tests/integration/swagger.test.ts`
 * imports it through `ApiServer` and a suite that sweeps a server across many
 * cases would otherwise inherit a spent budget and fail for the wrong reason.
 *
 * With Redis configured this resets the local map only — the shared counters
 * live in Redis and are namespaced per deployment. That is correct: a test
 * that needs a clean shared store must also clear it there.
 */
export function _clearRateLimitForTests(): void {
  resetRateLimitersForTest();
}
