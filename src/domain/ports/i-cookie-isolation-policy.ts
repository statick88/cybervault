import type { IsolatedCookieMetadata } from "../value-objects/isolated-cookie-metadata";

export interface ICookieIsolationPolicy {
  isolateSessionCookies(
    domain: string,
    cookieData: IsolatedCookieMetadata[],
    cookieValue: string,
  ): void;
  retrieveIsolatedSession(domain: string): import("../../infrastructure/crypto/secure-memory").SecureBuffer | null;
  freeAll(): void;
}
