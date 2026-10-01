import type { ServerResponse } from "http";

/**
 * Content-Security-Policy directives.
 *
 * KEYS ARE THE WIRE FORMAT. `Object.entries(CSP).map(([key, values]) => ...)`
 * emits the key VERBATIM, so these must be the lowercase, hyphenated directive
 * names the CSP specification defines (`default-src`, not `defaultSrc`).
 * A camelCase token is not a valid directive: a browser drops the directive it
 * cannot parse, and with every directive here being camelCase the WHOLE policy
 * was ignored — the header was emitted, looked correct in a naive `grep` for
 * `Content-Security-Policy`, and enforced nothing.
 *
 * `CSP_DIRECTIVES` and `buildContentSecurityPolicy` are exported so a test can
 * assert the emitted directive names are valid CSP tokens.
 */
export const CSP_DIRECTIVES = {
  "default-src": ["'self'"],
  "script-src": ["'self'"],
  "style-src": ["'self'", "'unsafe-inline'"],
  "img-src": ["'self'", "data:", "blob:"],
  "connect-src": ["'self'"],
  "font-src": ["'self'"],
  "object-src": ["'none'"],
  "media-src": ["'self'"],
  "frame-src": ["'none'"],
} as const;

/**
 * Build the `Content-Security-Policy` header value.
 *
 * Exported (rather than inlined in `applySecurityHeaders`) so a test can parse
 * the exact string that reaches `res.setHeader` without standing up a server.
 */
export function buildContentSecurityPolicy(
  directives: Readonly<Record<string, readonly string[]>> = CSP_DIRECTIVES,
): string {
  return Object.entries(directives)
    .map(([name, values]) => `${name} ${values.join(" ")}`)
    .join("; ");
}

export function applySecurityHeaders(res: ServerResponse): void {
  res.setHeader("Content-Security-Policy", buildContentSecurityPolicy());
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader(
    "Strict-Transport-Security",
    "max-age=31536000; includeSubDomains",
  );
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
}
