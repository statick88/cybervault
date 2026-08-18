/**
 * HIBP Breach Monitoring Service
 *
 * Checks passwords against the Have I Been Pwned API using k-anonymity.
 * The password is SHA-1 hashed, only the first 5 chars of the hash are sent to the API.
 * This preserves privacy — the full password never leaves the client.
 */

import * as crypto from 'crypto';

const HIBP_API_BASE = 'https://api.pwnedpasswords.com/range';

export interface BreachCheckResult {
  isBreached: boolean;
  breachCount: number;
  checkedAt: number;
}

/**
 * Check if a password has been exposed in known data breaches.
 * Uses k-anonymity: only first 5 chars of SHA-1 hash are sent.
 */
export async function checkPasswordBreach(password: string): Promise<BreachCheckResult> {
  const sha1 = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
  const prefix = sha1.slice(0, 5);
  const suffix = sha1.slice(5);

  try {
    const response = await fetch(`${HIBP_API_BASE}/${prefix}`, {
      headers: { 'User-Agent': 'CyberVault-PasswordManager' },
    });

    if (!response.ok) {
      throw new Error(`HIBP API error: ${response.status}`);
    }

    const text = await response.text();
    const lines = text.split('\n');

    for (const line of lines) {
      const [hashSuffix, count] = line.split(':');
      if (hashSuffix.trim() === suffix) {
        return {
          isBreached: true,
          breachCount: parseInt(count.trim(), 10),
          checkedAt: Date.now(),
        };
      }
    }

    return { isBreached: false, breachCount: 0, checkedAt: Date.now() };
  } catch {
    // Fail open — don't block user if HIBP is unreachable
    return { isBreached: false, breachCount: 0, checkedAt: Date.now() };
  }
}
