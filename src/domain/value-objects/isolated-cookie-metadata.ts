/**
 * Metadata for a cookie being isolated in secure memory.
 *
 * @module domain/value-objects/isolated-cookie-metadata
 */

export interface IsolatedCookieMetadata {
  readonly name: string;
  readonly domain: string;
  readonly path?: string;
  readonly expires?: number;
  readonly secure?: boolean;
  readonly sameSite?: 'Strict' | 'Lax' | 'None';
}
