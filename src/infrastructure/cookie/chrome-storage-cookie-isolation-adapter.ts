import type { ICookieIsolationPolicy } from "../../domain/ports/i-cookie-isolation-policy";
import type { IsolatedCookieMetadata } from "../../domain/value-objects/isolated-cookie-metadata";
import { COOKIE_TTL_MS } from "../../domain/constants/cookie-isolation";
import { SecureBuffer } from "../crypto/secure-memory";

interface IsolatedEntry {
  buffer: SecureBuffer;
  expiresAt: number;
}

/**
 * Chrome-storage adapter for cookie isolation.
 * Uses an in-memory Map for synchronous critical-path operations
 * and fire-and-forget Chrome API calls for native cookie removal.
 */
export class ChromeStorageCookieIsolationAdapter implements ICookieIsolationPolicy {
  private readonly store = new Map<string, IsolatedEntry>();

  isolateSessionCookies(
    domain: string,
    cookieData: IsolatedCookieMetadata[],
    cookieValue: string,
  ): void {
    if (!cookieValue) {
      throw new Error("Cookie value required");
    }

    const encoder = new TextEncoder();
    const encoded = encoder.encode(cookieValue);

    for (const cookie of cookieData) {
      const key = `${domain}:${cookie.name}`;

      // Free existing entry if key collision (latest cookie wins)
      const existing = this.store.get(key);
      if (existing) {
        existing.buffer.free();
      }

      // Allocate SecureBuffer and copy encoded value
      const buffer = new SecureBuffer(encoded.length);
      buffer.copyFrom(encoded);

      // Store with TTL timestamp
      this.store.set(key, {
        buffer,
        expiresAt: Date.now() + COOKIE_TTL_MS,
      });

      // Fire-and-forget: remove native cookie (no await)
      this.removeNativeCookie(cookie.domain, cookie.name).catch(() => {
        // Cookie is already encrypted in memory; native removal is defense-in-depth
      });
    }
  }

  retrieveIsolatedSession(domain: string): SecureBuffer | null {
    const results: SecureBuffer[] = [];

    // Collect all valid entries for this domain
    for (const [key, entry] of this.store) {
      if (!key.startsWith(`${domain}:`)) continue;

      // Lazy TTL check
      if (Date.now() > entry.expiresAt) {
        entry.buffer.free();
        this.store.delete(key);
        continue;
      }

      results.push(entry.buffer);
    }

    if (results.length === 0) return null;

    // Merge all cookie buffers for this domain into one
    const totalLength = results.reduce((sum, b) => sum + b.length, 0);
    const merged = new SecureBuffer(totalLength);
    let offset = 0;
    for (const buf of results) {
      const chunk = new Uint8Array(buf.length);
      buf.copyTo(chunk);
      merged.view.set(chunk, offset);
      offset += buf.length;
    }

    return merged;
  }

  freeAll(): void {
    for (const [, entry] of this.store) {
      entry.buffer.free();
    }
    this.store.clear();
  }

  /**
   * Fire-and-forget removal of native Chrome cookie.
   * Failures are logged but never block the critical path.
   */
  private async removeNativeCookie(domain: string, name: string): Promise<void> {
    try {
      await chrome.cookies.remove({ url: `https://${domain}`, name });
    } catch {
      // Defense-in-depth — cookie is already encrypted in memory
    }
  }
}
