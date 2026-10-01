/**
 * Domain Index — opaque origin lookup tokens.
 *
 * THE PROBLEM
 * -----------
 * To offer a credential on `https://github.com`, the extension must find the
 * credentials bound to that origin. The naive approach is to send the list of
 * origins a user has credentials for. That is a catastrophic disclosure: the
 * backend would learn every service the user has an account with, which is a
 * map of their infrastructure. It is also a stable identifier that survives
 * password rotation and is trivially correlatable.
 *
 * THE FIX
 * -------
 * Never store or transmit the origin. Store a *token* derived from the origin
 * with a key only the client holds, so the backend sees opaque blobs that are
 * useless without the VEK:
 *
 *     lookupToken(origin) = HMAC-SHA256(DomainIndexKey, canonicalOrigin)
 *
 * Properties this buys:
 *   - The backend cannot enumerate a user's origins from the index.
 *   - Tokens are deterministic, so lookup is a single indexed read.
 *   - Tokens are unforgeable without the key, so a hostile backend cannot
 *     inject a token for an origin the user never stored.
 *   - The DomainIndexKey is derived from the VEK with its own info string, so it
 *     is cryptographically distinct from every per-entry key. Reusing the VEK
 *     directly as an HMAC key would leak cross-protocol structure.
 *
 * WHAT THIS DOES NOT DO
 * ---------------------
 * It does not hide *which* origin is being looked up at the moment of use — the
 * client must present the token, and a hostile backend can observe the timing
 * and volume of lookups. That is a deliberate, documented trade-off: it stops
 * mass disclosure of the user's service map, not traffic analysis.
 */

import { parseAbsoluteOrigin, type CanonicalOrigin } from "./origin";

/** Distinct info string so this key is never confused with a per-entry key. */
const DOMAIN_INDEX_INFO = "cybervault|domain-index|v1";

const TOKEN_BYTES = 32; // Full 256-bit HMAC output.

function toArrayBuffer(data: Uint8Array): ArrayBuffer {
  const buf = new ArrayBuffer(data.byteLength);
  new Uint8Array(buf).set(data);
  return buf;
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

/** Import raw bytes as a non-extractable HMAC key. */
async function importHmacKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    toArrayBuffer(raw),
    { name: "HMAC", hash: "SHA-256" },
    /* extractable */ false,
    ["sign"],
  );
}

/**
 * Derive the DomainIndexKey from the VEK.
 *
 * Uses HKDF-Expand over the VEK with a dedicated info string. Deriving rather
 * than using the VEK directly means a compromise of the index key does not
 * yield the VEK, and the two keys are non-interchangeable.
 */
export async function deriveDomainIndexKey(vek: Uint8Array): Promise<CryptoKey> {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    toArrayBuffer(vek),
    { name: "HKDF" },
    false,
    ["deriveBits"],
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt: new Uint8Array(32),
      info: new TextEncoder().encode(DOMAIN_INDEX_INFO),
    },
    baseKey,
    TOKEN_BYTES * 8,
  );

  return importHmacKey(new Uint8Array(bits));
}

export type LookupTokenResult =
  | { readonly ok: true; readonly token: string; readonly origin: CanonicalOrigin }
  | { readonly ok: false; readonly reason: "ORIGIN_UNUSABLE" | "INDEX_KEY_MISSING" };

function toHex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/**
 * Compute the opaque lookup token for an origin.
 *
 * The origin is canonicalized first, so `https://GitHub.com` and
 * `https://github.com:443/` produce the same token. Without that, a user could
 * silently create duplicate entries that all resolve to the same site.
 */
export async function computeLookupToken(
  origin: string,
  indexKey: CryptoKey | null,
): Promise<LookupTokenResult> {
  if (!indexKey) return { ok: false, reason: "INDEX_KEY_MISSING" };

  const parsed = parseAbsoluteOrigin(origin);
  if (!parsed.ok) return { ok: false, reason: "ORIGIN_UNUSABLE" };

  const canonical = parsed.origin.serialized;
  const mac = await crypto.subtle.sign(
    "HMAC",
    indexKey,
    toArrayBuffer(new TextEncoder().encode(canonical)),
  );

  return { ok: true, token: toHex(new Uint8Array(mac)), origin: parsed.origin };
}

/**
 * Build the client-side index: token -> credential ids.
 *
 * This is the only structure persisted for lookup. It contains no origins and
 * no secret material — just opaque tokens and internal credential ids.
 */
export interface OpaqueIndex {
  readonly version: 1;
  /** lookupToken (hex) -> credential ids bound to that origin. */
  readonly byToken: Readonly<Record<string, readonly string[]>>;
}

export function emptyIndex(): OpaqueIndex {
  return { version: 1, byToken: {} };
}

export function addToIndex(
  index: OpaqueIndex,
  token: string,
  credentialId: string,
): OpaqueIndex {
  const existing = index.byToken[token] ?? [];
  if (existing.includes(credentialId)) return index;
  return {
    version: 1,
    byToken: { ...index.byToken, [token]: [...existing, credentialId] },
  };
}

export function removeFromIndex(
  index: OpaqueIndex,
  token: string,
  credentialId: string,
): OpaqueIndex {
  const existing = index.byToken[token];
  if (!existing) return index;
  const next = existing.filter((id) => id !== credentialId);
  const byToken = { ...index.byToken };
  if (next.length === 0) delete byToken[token];
  else byToken[token] = next;
  return { version: 1, byToken };
}

export function lookupIndex(
  index: OpaqueIndex,
  token: string,
): readonly string[] {
  return index.byToken[token] ?? [];
}

/**
 * Verify that a token presented by the backend really corresponds to an origin
 * we hold the key for.
 *
 * This is the anti-injection check: a compromised backend must not be able to
 * hand us a token for an arbitrary origin and have us fill a field for it.
 */
export async function verifyTokenForOrigin(
  origin: string,
  indexKey: CryptoKey | null,
  presentedToken: string,
): Promise<boolean> {
  const result = await computeLookupToken(origin, indexKey);
  if (!result.ok) return false;

  // Constant-time-ish comparison. Token length is fixed at 64 hex chars, so an
  // early length check leaks nothing meaningful.
  if (presentedToken.length !== result.token.length) return false;

  let diff = 0;
  for (let i = 0; i < result.token.length; i++) {
    diff |= result.token.charCodeAt(i) ^ presentedToken.charCodeAt(i);
  }
  return diff === 0;
}

/**
 * Defence in depth: confirm an index entry is reachable only from its own origin.
 *
 * Used by the content script before it will act on an id, so a corrupted or
 * tampered local index cannot cause a fill on the wrong origin.
 */
export function indexEntryMatchesOrigin(
  index: OpaqueIndex,
  token: string,
  credentialId: string,
  canonicalOrigin: string,
  indexKey: CryptoKey | null,
): Promise<boolean> {
  return verifyTokenForOrigin(canonicalOrigin, indexKey, token).then((ok) => {
    if (!ok) return false;
    return lookupIndex(index, token).includes(credentialId);
  });
}

export { concat as _concatForTests };
