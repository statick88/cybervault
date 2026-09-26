/**
 * Credential authoring — creating a release-ready credential record.
 *
 * This is the write side that O5.5 deliberately left out. Without it the
 * release path can read an encrypted record and an opaque index, but nothing
 * ever populates them, so a real browser session lists zero candidates and the
 * whole guarded pipeline is dormant.
 *
 * TWO INVARIANTS THIS MODULE ENFORCES
 * ------------------------------------
 * 1. EXACTMATCH AT AUTHORING TIME. An origin that cannot be canonicalized into
 *    an absolute http/https origin is rejected outright. This is the last point
 *    at which a typo like `github.com` (no scheme) or `https//github.com` can be
 *    caught. Storing a credential under a malformed origin would make it
 *    permanently unreachable, and would be indistinguishable from "locked".
 *
 * 2. NO PLAINTEXT IN THE RECORD. The stored record contains ciphertext, a
 *    per-entry salt, a version, a mode, an opaque Release Share reference and a
 *    redacted display hint. The username is encrypted alongside the password
 *    rather than kept in the clear: at this boundary the username is pushed
 *    into a web page, which is the same disclosure channel as the password, so
 *    treating it as public metadata would be inconsistent with where it is
 *    actually used.
 *
 * This module is pure: it takes a VEK and returns a record. It performs no I/O.
 *
 * @module domain/services/autofill/credential-authoring
 */

import {
  computeLookupToken,
  deriveDomainIndexKey,
  addToIndex,
  type OpaqueIndex,
} from "./domain-index";
import { parseAbsoluteOrigin } from "./origin";
import { derivePersonalEntryKey } from "../../../infrastructure/crypto/hkdf-derivation";
import { binaryToBase64, base64ToBinary } from "../../../shared/utils";
import { secureZero } from "../../../infrastructure/crypto/secure-memory";

const SALT_LEN = 32;
const IV_LEN = 12;

function toArrayBuffer(data: Uint8Array): ArrayBuffer {
  const buf = new ArrayBuffer(data.byteLength);
  new Uint8Array(buf).set(data);
  return buf;
}

/**
 * The encrypted envelope for a credential's user-facing secret.
 *
 * `u` and `p` are deliberately terse: this string is persisted, and a
 * self-describing field name would invite someone to log it.
 */
export interface SecretEnvelope {
  /** Username. */
  u: string;
  /** Password. */
  p: string;
}

/** A credential record ready to be persisted. Contains no plaintext secret. */
export interface AuthoredCredentialRecord {
  id: string;
  mode: "personal" | "managed";
  /** Base64 `salt|iv|ciphertext` of the SecretEnvelope. */
  encryptedSecret: string;
  /** Base64 `salt|iv|ciphertext` of the TOTP seed, when supplied. */
  encryptedTotpSecret?: string;
  /** Base64 32-byte HKDF salt for this entry. */
  salt: string;
  version: number;
  /** Opaque Release Share reference; managed entries only. */
  releaseShareRef?: string;
  /** Redacted, non-reversible label for the candidate list. */
  usernameHint: string;
  title: string;
  /** Canonical origin this credential is bound to. Never a raw user string. */
  origin: string;
}

export type AuthoringRejection =
  | "ORIGIN_MISSING"
  | "ORIGIN_NOT_ABSOLUTE"
  | "ORIGIN_SCHEME_NOT_ALLOWED"
  | "USERNAME_REQUIRED"
  | "PASSWORD_REQUIRED"
  | "TITLE_REQUIRED"
  | "MANAGED_REQUIRES_RELEASE_SHARE_REF"
  | "VAULT_LOCKED";

export type AuthoringResult =
  | {
      readonly ok: true;
      readonly record: AuthoredCredentialRecord;
      readonly index: OpaqueIndex;
      /** Opaque token registered for the bound origin. */
      readonly lookupToken: string;
    }
  | { readonly ok: false; readonly reason: AuthoringRejection; readonly detail: string };

export interface AuthorCredentialInput {
  /** Raw user-supplied origin. Validated, never trusted verbatim. */
  origin: string;
  username: string;
  password: string;
  title: string;
  /** Base32 or Base64 TOTP seed; encoded to bytes here. */
  totpSeedBase32?: string;
  mode?: "personal" | "managed";
  releaseShareRef?: string;
  /** Explicit id; generated when omitted. */
  id?: string;
}

/**
 * Build a redacted hint.
 *
 * Deliberately lossy: it must be enough for a human to recognise the right
 * account in a list, and useless for reconstructing it. Everything after the
 * first character is replaced, so length is not leaked either.
 */
export function redactUsername(username: string): string {
  const trimmed = username.trim();
  if (trimmed.length === 0) return "";
  if (trimmed.length === 1) return "*";
  return `${trimmed[0]}${"*".repeat(Math.min(trimmed.length - 1, 8))}`;
}

/** Encode a Base32 TOTP seed to raw bytes. */
export function base32ToBytes(base32: string): Uint8Array {
  const clean = base32.replace(/[\s=]/g, "").toUpperCase();
  let bits = 0;
  let value = 0;
  const out: number[] = [];

  for (const char of clean) {
    let v: number;
    if (char >= "A" && char <= "Z") v = char.charCodeAt(0) - 65;
    else if (char >= "2" && char <= "7") v = char.charCodeAt(0) - 24;
    else continue;
    value = (value << 5) | v;
    bits += 5;
    if (bits >= 8) {
      out.push((value >> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(out);
}

/** Encrypt plaintext into the `salt|iv|ciphertext` layout the reader expects. */
async function seal(
  plaintext: string,
  keyBytes: Uint8Array,
  salt: Uint8Array,
): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_LEN));
  const key = await crypto.subtle.importKey(
    "raw",
    toArrayBuffer(keyBytes),
    "AES-GCM",
    false,
    ["encrypt"],
  );
  const enc = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: toArrayBuffer(iv), tagLength: 128 },
    key,
    toArrayBuffer(new TextEncoder().encode(plaintext)),
  );
  const out = new Uint8Array(salt.length + iv.length + enc.byteLength);
  out.set(salt, 0);
  out.set(iv, salt.length);
  out.set(new Uint8Array(enc), salt.length + iv.length);
  return binaryToBase64(out);
}

function reject(reason: AuthoringRejection, detail: string): AuthoringResult {
  return { ok: false, reason, detail };
}

function randomId(): string {
  return crypto.randomUUID();
}

/* ------------------------------------------------------------------ */
/*  Input validation (extracted from authorCredential, order intact)   */
/* ------------------------------------------------------------------ */

type OriginValidation =
  | { readonly ok: true; readonly canonical: string }
  | { readonly ok: false; readonly reason: AuthoringRejection; readonly detail: string };

type FieldValidation =
  | { readonly ok: true; readonly title: string }
  | { readonly ok: false; readonly reason: AuthoringRejection; readonly detail: string };

/**
 * Validate the origin BEFORE anything else.
 *
 * EXTRACTED VERBATIM from `authorCredential` step 1: same checks, same
 * order, same rejection codes and detail strings.
 */
function validateAuthoringOrigin(origin: string | null | undefined): OriginValidation {
  if (origin === null || origin === undefined || origin.trim() === "") {
    return { ok: false, reason: "ORIGIN_MISSING", detail: "an origin is required" };
  }

  const trimmedOrigin = origin.trim();
  // A bare host such as "github.com" is not an origin. Refusing it here is
  // better than guessing a scheme, because guessing http for an https site
  // would produce a permanently unfillable credential.
  if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmedOrigin)) {
    return {
      ok: false,
      reason: "ORIGIN_NOT_ABSOLUTE",
      detail: `origin must be absolute (scheme://host[:port]); got "${trimmedOrigin}"`,
    };
  }

  const parsed = parseAbsoluteOrigin(trimmedOrigin);
  if (!parsed.ok) {
    return {
      ok: false,
      reason:
        parsed.reason === "UNSUPPORTED_SCHEME" ? "ORIGIN_SCHEME_NOT_ALLOWED" : "ORIGIN_NOT_ABSOLUTE",
      detail: `origin rejected (${parsed.reason})`,
    };
  }
  return { ok: true, canonical: parsed.origin.serialized };
}

/**
 * Validate username, password and title.
 *
 * EXTRACTED VERBATIM from `authorCredential` step 2: same checks, same order,
 * same rejection codes. Returns the effective title (which defaults to the
 * username) so the caller stores exactly what was validated.
 */
function validateAuthoringFields(
  input: AuthorCredentialInput,
  username: string,
): FieldValidation {
  if (username === "") {
    return { ok: false, reason: "USERNAME_REQUIRED", detail: "a username is required" };
  }
  if (!input.password) {
    return { ok: false, reason: "PASSWORD_REQUIRED", detail: "a password is required" };
  }
  const title = input.title?.trim() || username;
  if (title === "") {
    return { ok: false, reason: "TITLE_REQUIRED", detail: "a title is required" };
  }
  return { ok: true, title };
}

/* ------------------------------------------------------------------ */
/*  Sealing + opaque index registration                               */
/* ------------------------------------------------------------------ */

interface SealContext {
  /** Session VEK. Zeroized on every failure path, exactly as before. */
  vek: Uint8Array;
  input: AuthorCredentialInput;
  username: string;
  title: string;
  canonicalOrigin: string;
  credentialId: string;
  salt: Uint8Array;
  existingIndex: OpaqueIndex | null;
}

/**
 * Derive the per-entry key, seal the envelope and register the lookup token.
 *
 * EXTRACTED from `authorCredential` step 3–4 together with its try/catch/
 * finally: the failure messages, the `secureZero` calls and their timing are
 * unchanged. Returns the full success shape or the same rejection the inline
 * code produced.
 */
async function sealAndRegisterCredential(ctx: SealContext): Promise<AuthoringResult> {
  const { vek, input, username, title, canonicalOrigin, credentialId, salt, existingIndex } = ctx;
  let keyBytes: Uint8Array | null = null;

  try {
    const derived = await derivePersonalEntryKey(vek, salt, credentialId, 1);
    keyBytes = base64ToBinary(derived.keyBase64);

    const envelope: SecretEnvelope = { u: username, p: input.password };
    const encryptedSecret = await seal(JSON.stringify(envelope), keyBytes, salt);

    let encryptedTotpSecret: string | undefined;
    if (input.totpSeedBase32) {
      const seedBytes = base32ToBytes(input.totpSeedBase32);
      if (seedBytes.length === 0) {
        secureZero(vek);
        if (keyBytes) secureZero(keyBytes);
        return reject("PASSWORD_REQUIRED", "TOTP seed contained no usable characters");
      }
      encryptedTotpSecret = await seal(binaryToBase64(seedBytes), keyBytes, salt);
      secureZero(seedBytes);
    }

    /* Register the opaque lookup token. */
    const indexKey = await deriveDomainIndexKey(vek);
    const token = await computeLookupToken(canonicalOrigin, indexKey);
    if (!token.ok) {
      secureZero(vek);
      if (keyBytes) secureZero(keyBytes);
      return reject("ORIGIN_NOT_ABSOLUTE", "could not derive a lookup token");
    }

    const nextIndex = addToIndex(
      existingIndex ?? { version: 1, byToken: {} },
      token.token,
      credentialId,
    );

    const record: AuthoredCredentialRecord = {
      id: credentialId,
      mode: "personal",
      encryptedSecret,
      encryptedTotpSecret,
      salt: binaryToBase64(salt),
      version: 1,
      usernameHint: redactUsername(username),
      title,
      origin: canonicalOrigin,
    };

    return { ok: true, record, index: nextIndex, lookupToken: token.token };
  } catch {
    secureZero(vek);
    return reject("ORIGIN_NOT_ABSOLUTE", "unexpected failure while authoring");
  } finally {
    if (keyBytes) secureZero(keyBytes);
  }
}

/**
 * Author a credential and register it in the opaque index.
 *
 * @param vek Session vault encryption key. Zeroized internally.
 * @param existingIndex Current index, or null when none exists yet.
 */
export async function authorCredential(
  input: AuthorCredentialInput,
  vek: Uint8Array | null,
  existingIndex: OpaqueIndex | null,
): Promise<AuthoringResult> {
  if (!vek) return reject("VAULT_LOCKED", "vault is locked");

  /* ---- 1. Validate the origin BEFORE anything else. ---- */
  const origin = validateAuthoringOrigin(input.origin);
  if (!origin.ok) {
    secureZero(vek);
    return reject(origin.reason, origin.detail);
  }

  /* ---- 2. Validate the rest of the input. ---- */
  const username = input.username?.trim() ?? "";
  const fields = validateAuthoringFields(input, username);
  if (!fields.ok) {
    secureZero(vek);
    return reject(fields.reason, fields.detail);
  }
  const title = fields.title;

  const mode = input.mode ?? "personal";
  if (mode === "managed" && !input.releaseShareRef) {
    secureZero(vek);
    return reject(
      "MANAGED_REQUIRES_RELEASE_SHARE_REF",
      "a managed credential requires an opaque Release Share reference",
    );
  }

  /* ------------------------------------------------------------------
   * MANAGED AUTHORING IS DELIBERATELY REFUSED HERE — THIS IS DESIGN, NOT
   * A GAP.
   *
   * A managed entry key is HKDF(VEK || ReleaseShare, ...). At authoring time
   * the client does not hold the Release Share — that is the entire point of
   * split trust, since Core keeps it wrapped and releases it only after Plus
   * authorizes an operation. So the final entry key is not derivable here.
   *
   * The tempting shortcut is to seal to a VEK-only key and mix the Release
   * Share in at release time, but that yields a ciphertext no release path can
   * ever open, which would look like a working managed credential while failing
   * silently at use.
   *
   * DECISION (odd/tasks/cybervault-final-security-architecture.md,
   * "Decisions Already Made", 2026-09-26): managed authoring happens
   * SERVER-SIDE, in Core — see `src/application/use-cases/
   * managed-authoring.use-case.ts`, which is the only place that ever holds
   * both the VEK-derived material and the Release Share at once. Two-layer
   * wrapping (Option A) and a client-held stable share (Option B) were both
   * rejected because they add a second holder of share material.
   *
   * Keeping this refusal is therefore a design invariant: it is what stops the
   * extension from creating a credential that lists correctly and then fails
   * silently at use (defect D1). Do not "fix" this branch by allowing managed
   * mode here.
   * ------------------------------------------------------------------ */
  if (mode === "managed") {
    secureZero(vek);
    return reject(
      "MANAGED_REQUIRES_RELEASE_SHARE_REF",
      "managed authoring is server-side by design: the entry key is " +
        "HKDF(VEK || ReleaseShare) and only Core holds the Release Share at " +
        "authoring time (see application/use-cases/managed-authoring.use-case.ts)",
    );
  }

  /* ---- 3 + 4. Derive the per-entry key, encrypt, register the token.
   *             (extracted verbatim into sealAndRegisterCredential) ---- */
  return sealAndRegisterCredential({
    vek,
    input,
    username,
    title,
    canonicalOrigin: origin.canonical,
    credentialId: input.id ?? randomId(),
    salt: crypto.getRandomValues(new Uint8Array(SALT_LEN)),
    existingIndex,
  });
}
