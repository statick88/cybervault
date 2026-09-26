/**
 * Canonical Absolute Origin — the single authority for "is this the same origin?"
 *
 * WHY THIS MODULE EXISTS
 * ----------------------
 * "Same origin" is the load-bearing decision for every credential release in
 * CyberVault. If two places in the codebase each implement it, they will
 * eventually disagree, and the disagreement will be a security bug in whichever
 * copy is more permissive. So there is exactly one implementation, here, and
 * both the AITM ExactMatch step and the autofill guard delegate to it.
 *
 * THE RULE (RFC 6454 §4.1, plus an explicit port)
 * -----------------------------------------------
 * Two origins are equal only when scheme, hostname and port are all equal.
 *
 *   - Scheme mismatch  -> different origin. http://github.com is NOT github.com.
 *   - Hostname mismatch-> different origin. www.github.com is NOT github.com.
 *   - Port mismatch    -> different origin. :8443 is NOT :443.
 *
 * There is deliberately NO wildcard, suffix, base-domain or "similar enough"
 * matching. Subdomains are a different origin, full stop. This is the single
 * most important property in the product: it is what stops
 * `github.com.evil.example` and `github-login.example` from being treated as
 * github.com.
 *
 * A missing port is NOT an error: it defaults to the scheme's default port, so
 * `https://github.com` and `https://github.com:443` are the same origin. An
 * explicit `:443` and an omitted `:443` mean the same thing per the URL spec.
 */

/** Default ports per scheme, used when the URL omits an explicit port. */
const DEFAULT_PORTS: Readonly<Record<string, number>> = {
  http: 80,
  https: 443,
  ws: 80,
  wss: 443,
  ftp: 21,
};

/**
 * Schemes that may legitimately carry credentials.
 *
 * Anything else (data:, blob:, file:, javascript:, chrome-extension:) is
 * rejected outright. A `javascript:` or `data:` "origin" matching a credential
 * would be a complete bypass, so we refuse to parse rather than guess.
 */
const SUPPORTED_SCHEMES = new Set(["http", "https"]);

export interface CanonicalOrigin {
  /** Lowercased scheme, without the trailing colon. */
  readonly scheme: string;
  /** RFC 1035 normalized, lowercased hostname. */
  readonly hostname: string;
  /** Resolved port: explicit, or the scheme default. */
  readonly port: number;
  /** Canonical serialization: `scheme://hostname:port`. */
  readonly serialized: string;
}

export type OriginParseFailure =
  /** Input was empty or whitespace. */
  | "EMPTY"
  /** Input was not parseable as a URL. */
  | "UNPARSEABLE"
  /** Scheme is absent or not http/https. */
  | "UNSUPPORTED_SCHEME"
  /** Hostname is absent. */
  | "MISSING_HOSTNAME";

export type OriginParseResult =
  | { readonly ok: true; readonly origin: CanonicalOrigin }
  | { readonly ok: false; readonly reason: OriginParseFailure };

/**
 * Normalize a hostname per RFC 1035: lowercase, drop a single trailing dot.
 *
 * The trailing dot denotes an explicitly-rooted name and is equivalent to the
 * bare name, so `example.com.` and `example.com` MUST compare equal. Getting
 * this wrong would lock users out of their own credentials; getting it wrong in
 * the other direction would let an attacker append a dot to impersonate.
 */
export function normalizeHostname(hostname: string): string {
  let host = hostname.trim().toLowerCase();
  if (host.endsWith(".") && host.length > 1) {
    host = host.slice(0, -1);
  }
  return host;
}

/**
 * Parse an absolute origin, with no silent fallbacks.
 *
 * A parse failure is a first-class result, never a coerced value. Callers that
 * swallow a failure and continue with `undefined` are how fail-open bugs start.
 */
export function parseAbsoluteOrigin(input: string): OriginParseResult {
  if (typeof input !== "string") return { ok: false, reason: "EMPTY" };

  const trimmed = input.trim();
  if (trimmed.length === 0) return { ok: false, reason: "EMPTY" };

  let url: URL;
  try {
    url = new URL(trimmed);
  } catch {
    return { ok: false, reason: "UNPARSEABLE" };
  }

  const scheme = url.protocol.replace(":", "").toLowerCase();
  if (!SUPPORTED_SCHEMES.has(scheme)) {
    return { ok: false, reason: "UNSUPPORTED_SCHEME" };
  }

  // URL parsing of a Unicode hostname yields Punycode. We intentionally keep the
  // Punycode form here: it is the canonical, unambiguous wire form, and it is
  // what the credential was bound to. Confusable/homograph detection is a
  // separate, warning-only concern handled by the AITM pipeline.
  const hostname = normalizeHostname(url.hostname);
  if (hostname.length === 0) return { ok: false, reason: "MISSING_HOSTNAME" };

  const port = url.port !== "" ? Number.parseInt(url.port, 10) : DEFAULT_PORTS[scheme];
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    return { ok: false, reason: "UNPARSEABLE" };
  }

  return {
    ok: true,
    origin: { scheme, hostname, port, serialized: `${scheme}://${hostname}:${port}` },
  };
}

/**
 * Strict absolute-origin equality. The only authority in the codebase.
 *
 * Returns a discriminated result rather than a bare boolean so callers can
 * record WHY a fill was refused — an unexplained denial is unauditable.
 */
export type OriginComparison =
  | { readonly equal: true; readonly origin: CanonicalOrigin }
  | {
      readonly equal: false;
      readonly expected: CanonicalOrigin | null;
      readonly actual: CanonicalOrigin | null;
      /** Human-readable audit reason. Never contains secret material. */
      readonly reason: string;
    };

export function compareAbsoluteOrigins(
  expectedInput: string,
  actualInput: string,
): OriginComparison {
  const expected = parseAbsoluteOrigin(expectedInput);
  const actual = parseAbsoluteOrigin(actualInput);

  if (!expected.ok) {
    return {
      equal: false,
      expected: null,
      actual: actual.ok ? actual.origin : null,
      reason: `expected origin is unusable (${expected.reason})`,
    };
  }
  if (!actual.ok) {
    return {
      equal: false,
      expected: expected.origin,
      actual: null,
      reason: `actual origin is unusable (${actual.reason})`,
    };
  }

  const e = expected.origin;
  const a = actual.origin;

  if (e.scheme !== a.scheme) {
    return {
      equal: false,
      expected: e,
      actual: a,
      reason: `scheme differs (${a.scheme} != ${e.scheme})`,
    };
  }
  if (e.hostname !== a.hostname) {
    return {
      equal: false,
      expected: e,
      actual: a,
      reason: `hostname differs (${a.hostname} != ${e.hostname})`,
    };
  }
  if (e.port !== a.port) {
    return {
      equal: false,
      expected: e,
      actual: a,
      reason: `port differs (${a.port} != ${e.port})`,
    };
  }

  return { equal: true, origin: e };
}

/**
 * Resolve a possibly-relative URL against a base origin.
 *
 * A `<form>` with no `action` attribute, or `action=""`, submits to the current
 * document — that is a SELF-submit and is legitimate. Callers therefore must
 * resolve rather than treat a missing action as "unrestricted".
 */
export function resolveAgainstOrigin(
  candidate: string | null | undefined,
  baseOrigin: string,
): OriginParseResult {
  if (candidate === null || candidate === undefined) {
    return parseAbsoluteOrigin(baseOrigin);
  }
  const trimmed = candidate.trim();
  if (trimmed === "") {
    // Empty action attribute => submit to self.
    return parseAbsoluteOrigin(baseOrigin);
  }
  try {
    return parseAbsoluteOrigin(new URL(trimmed, baseOrigin).toString());
  } catch {
    return { ok: false, reason: "UNPARSEABLE" };
  }
}

/**
 * Build an origin string from a live browser location.
 *
 * `window.location.origin` is unavailable for opaque origins, so this falls back
 * to explicit assembly and lets the caller surface the failure.
 */
export function originFromLocation(location: {
  protocol: string;
  hostname: string;
  port: string;
}): string {
  return `${location.protocol}//${location.hostname}${location.port ? `:${location.port}` : ""}`;
}
