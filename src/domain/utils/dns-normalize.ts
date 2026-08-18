/**
 * DNS Normalize — RFC 1035 hostname normalization
 *
 * Performs deterministic normalization: lowercase, trim, trailing dot removal.
 * No Punycode/IDNA conversion — pure string operations.
 *
 * @module domain/utils/dns-normalize
 */

/**
 * Normalize a hostname per RFC 1035 conventions.
 *
 * - Lowercases
 * - Trims whitespace
 * - Removes trailing dot (if present)
 */
export function dnsNormalize(hostname: string): string {
  return hostname.toLowerCase().trim().replace(/\.$/, "");
}
