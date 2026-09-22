/**
 * Login Rate Limiter — Brute-force protection
 * Tracks failed login attempts per email with progressive lockout
 *
 * Pattern: 5 failures → 1 min lockout, 10 failures → 5 min lockout, 15+ → 15 min lockout
 * Resets on successful login or after lockout window expires
 */

import { logger } from "../../shared/logger";

interface AttemptRecord {
  count: number;
  firstFailureAt: number;
  lockedUntil: number | null;
}

const MAX_ATTEMPTS_BEFORE_LOCKOUT = 5;
const LOCKOUT_TIERS = [
  { threshold: 5, durationMs: 60_000 },      // 5 failures → 1 min
  { threshold: 10, durationMs: 300_000 },    // 10 failures → 5 min
  { threshold: 15, durationMs: 900_000 },    // 15 failures → 15 min
];
const CLEANUP_INTERVAL_MS = 60_000; // Cleanup stale entries every minute
const STALE_THRESHOLD_MS = 30 * 60_000; // 30 min — purge records with no activity

class LoginRateLimiter {
  private attempts = new Map<string, AttemptRecord>();
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;

  constructor() {
    // Periodic cleanup to prevent memory leak from abandoned entries
    this.cleanupTimer = setInterval(() => this.cleanup(), CLEANUP_INTERVAL_MS);
  }

  /**
   * Returns the lockout duration for a given failure count
   */
  private getLockoutDuration(failureCount: number): number {
    let duration = 0;
    for (const tier of LOCKOUT_TIERS) {
      if (failureCount >= tier.threshold) {
        duration = tier.durationMs;
      }
    }
    return duration;
  }

  /**
   * Check if an email is currently locked out
   */
  isLocked(email: string): { locked: boolean; retryAfterMs?: number } {
    const record = this.attempts.get(email);
    if (!record) return { locked: false };

    if (record.lockedUntil && Date.now() < record.lockedUntil) {
      return {
        locked: true,
        retryAfterMs: record.lockedUntil - Date.now(),
      };
    }

    // Lockout expired — clear it
    if (record.lockedUntil && Date.now() >= record.lockedUntil) {
      record.count = 0;
      record.lockedUntil = null;
      record.firstFailureAt = Date.now();
    }

    return { locked: false };
  }

  /**
   * Record a failed login attempt. Returns lockout info.
   */
  recordFailure(email: string): { locked: boolean; retryAfterMs?: number } {
    const now = Date.now();
    let record = this.attempts.get(email);

    if (!record) {
      record = { count: 0, firstFailureAt: now, lockedUntil: null };
      this.attempts.set(email, record);
    }

    record.count++;
    const lockoutDuration = this.getLockoutDuration(record.count);

    if (lockoutDuration > 0) {
      record.lockedUntil = now + lockoutDuration;
      logger.warn(
        `Login lockout triggered for ${email}: ${record.count} failures, locked for ${lockoutDuration / 1000}s`,
        "LoginRateLimiter",
      );
      return { locked: true, retryAfterMs: lockoutDuration };
    }

    return { locked: false };
  }

  /**
   * Clear failed attempts on successful login
   */
  recordSuccess(email: string): void {
    this.attempts.delete(email);
  }

  /**
   * Purge stale entries to prevent memory leak
   */
  private cleanup(): void {
    const now = Date.now();
    for (const [email, record] of this.attempts) {
      const lastActivity = record.lockedUntil
        ? Math.max(record.lockedUntil, record.firstFailureAt)
        : record.firstFailureAt;
      if (now - lastActivity > STALE_THRESHOLD_MS) {
        this.attempts.delete(email);
      }
    }
  }

  /**
   * Shutdown the cleanup timer (for graceful shutdown)
   */
  destroy(): void {
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
  }
}

// Singleton — one limiter per process
export const loginRateLimiter = new LoginRateLimiter();
