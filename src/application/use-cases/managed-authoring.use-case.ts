/**
 * Use Case: Server-side MANAGED credential authoring (ODD "Option C").
 *
 * WHY THIS LIVES IN CORE
 * ----------------------
 * A managed entry key is `HKDF(VEK || ReleaseShare, salt, context{credentialId,
 * version, managed})`. At authoring time the CLIENT cannot compute it: split
 * trust puts the Release Share exclusively in Core, released only after Plus
 * authorizes a single operation. `domain/services/autofill/credential-authoring.ts`
 * therefore refuses managed mode, and that refusal is a design invariant — this
 * file is the sanctioned counterpart, not a relaxation of it.
 *
 * Only Core holds both halves at once, so Core mints the share, derives the
 * entry key, seals the envelope, wraps the share under the Release Share KEK
 * and hands back a record that contains NO plaintext secret:
 *
 *   1. Validate/canonicalize the origin (identical rejection semantics to the
 *      client path — this is the last point a malformed origin can be caught).
 *   2. Mint a fresh 32-byte Release Share.
 *   3. EntryKey = deriveManagedEntryKey(VEK, ReleaseShare, salt, id, version).
 *   4. Seal `{u, p}` (and the optional TOTP seed) with AES-256-GCM in the exact
 *      `salt|iv|ciphertext` base64 layout the extension's `decryptAESGCM`
 *      expects.
 *   5. Wrap the Release Share under the Release Share KEK and persist it
 *      against `secretRef`.
 *   6. Register the opaque HMAC lookup token so the entry is discoverable by
 *      origin WITHOUT persisting the origin anywhere.
 *
 * The Release Share is never part of the return value: at authoring time the
 * client has no business holding it.
 *
 * This use case owns the buffers it creates (VEK copy, Release Share, entry
 * key, seed bytes, KEK) and zeroizes them in `finally`. The caller's VEK is
 * copied, not consumed — the session that supplied it still owns it.
 *
 * @module application/use-cases/managed-authoring.use-case
 */

import type { IReleaseShareStore } from "../../domain/repositories";
import type { OpaqueIndex } from "../../domain/services/autofill/domain-index";
import {
  computeLookupToken,
  deriveDomainIndexKey,
  addToIndex,
} from "../../domain/services/autofill/domain-index";
import { parseAbsoluteOrigin } from "../../domain/services/autofill/origin";
import {
  type AuthoredCredentialRecord,
  redactUsername,
  base32ToBytes,
} from "../../domain/services/autofill/credential-authoring";
import { deriveManagedEntryKey } from "../../infrastructure/crypto/hkdf-derivation";
import {
  deriveReleaseShareKek,
  wrapReleaseShare,
  ReleaseShareKekError,
} from "../../infrastructure/crypto/release-share-kek";
import { secureZero } from "../../infrastructure/crypto/secure-memory";
import { binaryToBase64, base64ToBinary } from "../../shared/utils";

const SALT_LEN = 32;
const IV_LEN = 12;
const RELEASE_SHARE_LEN = 32;
const ENTRY_VERSION = 1;

function toArrayBuffer(data: Uint8Array): ArrayBuffer {
  const buf = new ArrayBuffer(data.byteLength);
  new Uint8Array(buf).set(data);
  return buf;
}

/**
 * Rejection reasons. The four ORIGIN_* codes are byte-for-byte the same
 * vocabulary the client path uses, so a caller can handle both identically.
 */
export type ManagedAuthoringRejection =
  | "ORIGIN_MISSING"
  | "ORIGIN_NOT_ABSOLUTE"
  | "ORIGIN_SCHEME_NOT_ALLOWED"
  | "USERNAME_REQUIRED"
  | "PASSWORD_REQUIRED"
  | "TITLE_REQUIRED"
  | "SECRET_REF_REQUIRED"
  | "VEK_MISSING"
  | "TOTP_SEED_INVALID"
  | "RELEASE_SHARE_KEK_INVALID"
  | "RELEASE_SHARE_PERSIST_FAILED"
  | "INTERNAL_ERROR";

export type ManagedAuthoringResult =
  | {
      readonly ok: true;
      readonly record: AuthoredCredentialRecord;
      readonly index: OpaqueIndex;
      /** Opaque token registered for the bound origin. Never the origin itself. */
      readonly lookupToken: string;
    }
  | { readonly ok: false; readonly reason: ManagedAuthoringRejection; readonly detail: string };

/**
 * Session VEK as the caller hands it over: absent while the vault is locked.
 * Named so the union is not repeated inline across the file (S4323).
 */
type SessionVek = Uint8Array | null | undefined;

export interface ManagedAuthoringInput {
  /** Raw user-supplied origin. Validated, never trusted verbatim. */
  origin: string;
  username: string;
  password: string;
  title: string;
  /** Base32 or Base64 TOTP seed; encoded to bytes here. */
  totpSeedBase32?: string;
  /** Session VEK. Copied internally; the caller keeps ownership of this buffer. */
  vek: SessionVek;
  /** Fresh opaque reference this credential will be released under. */
  secretRef: string;
  /** Existing index to append to, when the caller already has one. */
  existingIndex?: OpaqueIndex | null;
  /** Explicit id; generated when omitted. */
  id?: string;
}

function reject(reason: ManagedAuthoringRejection, detail: string): ManagedAuthoringResult {
  return { ok: false, reason, detail };
}

/* ------------------------------------------------------------------ */
/*  Input validation (extracted from execute, order and codes intact)  */
/* ------------------------------------------------------------------ */

type ManagedOriginValidation =
  | { readonly ok: true; readonly canonical: string }
  | { readonly ok: false; readonly reason: ManagedAuthoringRejection; readonly detail: string };

type ManagedFieldValidation =
  | { readonly ok: true; readonly username: string; readonly title: string; readonly secretRef: string; readonly vek: Uint8Array }
  | { readonly ok: false; readonly reason: ManagedAuthoringRejection; readonly detail: string };

/**
 * Validate the origin BEFORE anything else (client semantics, byte-for-byte).
 */
function validateManagedOrigin(origin: string | null | undefined): ManagedOriginValidation {
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
 * Validate username, password, title, secretRef and VEK — same checks, same
 * order, same codes as the inline code was. Returns the validated values so
 * the caller stores exactly what was checked.
 */
function validateManagedFields(input: ManagedAuthoringInput): ManagedFieldValidation {
  const username = input.username?.trim() ?? "";
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
  const secretRef = input.secretRef?.trim() ?? "";
  if (secretRef === "") {
    return {
      ok: false,
      reason: "SECRET_REF_REQUIRED",
      detail: "a fresh opaque Release Share reference is required",
    };
  }
  if (!input.vek || input.vek.byteLength === 0) {
    return { ok: false, reason: "VEK_MISSING", detail: "vault is locked: no VEK supplied" };
  }
  return { ok: true, username, title, secretRef, vek: input.vek };
}

/**
 * Derive the Release Share KEK. Fail closed, no default: a missing or short
 * server secret is a typed rejection naming the real blocker.
 */
async function deriveReleaseShareKekOrReject(
  secret: SessionVek,
): Promise<
  { readonly ok: true; readonly kek: Uint8Array } | { readonly ok: false; readonly rejection: ManagedAuthoringResult }
> {
  try {
    const kek = await deriveReleaseShareKek(secret);
    return { ok: true, kek };
  } catch (error) {
    const detail =
      error instanceof ReleaseShareKekError ? error.message : "Release Share KEK unavailable";
    return { ok: false, rejection: reject("RELEASE_SHARE_KEK_INVALID", detail) };
  }
}

/* ------------------------------------------------------------------ */
/*  Secret material produced during a single execute()                 */
/* ------------------------------------------------------------------ */

/** Key buffers owned by the caller's `finally`; zeroized there, as before. */
interface ManagedSealBuffers {
  keyBytes: Uint8Array | null;
  seedBytes: Uint8Array | null;
}

type ManagedSealResult =
  | {
      readonly ok: true;
      readonly encryptedSecret: string;
      readonly encryptedTotpSecret?: string;
      readonly index: OpaqueIndex;
      readonly lookupToken: string;
    }
  | { readonly ok: false; readonly reason: ManagedAuthoringRejection; readonly detail: string };

type ManagedPersistResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly reason: ManagedAuthoringRejection; readonly detail: string };

/**
 * Steps 4–6 — derive the entry key, seal the envelopes, register the token.
 *
 * EXTRACTED VERBATIM from `execute`: same derivation inputs, same rejection
 * codes, same index mutation. No try here on purpose — a throw must reach
 * `execute`'s catch so it becomes the same INTERNAL_ERROR as before. The
 * key/seed buffers are handed back through `buffers` for the caller's
 * `finally` to zeroize, exactly where the inline code did it.
 */
async function sealManagedSecrets(args: {
  vek: Uint8Array;
  releaseShare: Uint8Array;
  input: ManagedAuthoringInput;
  username: string;
  canonicalOrigin: string;
  credentialId: string;
  salt: Uint8Array;
  existingIndex: OpaqueIndex | null | undefined;
  buffers: ManagedSealBuffers;
}): Promise<ManagedSealResult> {
  const { vek, releaseShare, input, username, canonicalOrigin, credentialId, salt, buffers } =
    args;

  /* Step 4: EntryKey = HKDF(VEK || ReleaseShare, salt, context). */
  const derived = await deriveManagedEntryKey(vek, releaseShare, salt, credentialId, ENTRY_VERSION);
  const keyBytes = base64ToBinary(derived.keyBase64);
  buffers.keyBytes = keyBytes;

  /* Step 5: seal the {u, p} envelope (username travels with the password). */
  const envelope = { u: username, p: input.password };
  const encryptedSecret = await seal(JSON.stringify(envelope), keyBytes, salt);

  let encryptedTotpSecret: string | undefined;
  if (input.totpSeedBase32) {
    const seedBytes = base32ToBytes(input.totpSeedBase32);
    buffers.seedBytes = seedBytes;
    if (seedBytes.length === 0) {
      return { ok: false, reason: "TOTP_SEED_INVALID", detail: "TOTP seed contained no usable characters" };
    }
    encryptedTotpSecret = await seal(binaryToBase64(seedBytes), keyBytes, salt);
  }

  /* Step 6: opaque lookup token — origin is derived into, never stored. */
  const indexKey = await deriveDomainIndexKey(vek);
  const token = await computeLookupToken(canonicalOrigin, indexKey);
  if (!token.ok) {
    return { ok: false, reason: "ORIGIN_NOT_ABSOLUTE", detail: "could not derive a lookup token" };
  }

  const nextIndex = addToIndex(
    args.existingIndex ?? { version: 1, byToken: {} },
    token.token,
    credentialId,
  );

  return { ok: true, encryptedSecret, encryptedTotpSecret, index: nextIndex, lookupToken: token.token };
}

/**
 * Step 7 — wrap the Release Share and persist the opaque blob.
 *
 * EXTRACTED VERBATIM including its catch: a KEK failure still surfaces as
 * RELEASE_SHARE_KEK_INVALID, anything else as RELEASE_SHARE_PERSIST_FAILED.
 */
async function wrapAndPersistShare(
  kek: Uint8Array,
  releaseShare: Uint8Array,
  secretRef: string,
  store: IReleaseShareStore,
): Promise<ManagedPersistResult> {
  try {
    const wrappedShare = await wrapReleaseShare(kek, releaseShare, secretRef);
    await store.save({ secretRef, wrappedShare, createdAt: new Date() });
    return { ok: true };
  } catch (error) {
    const cause = error instanceof Error ? error.message : "unknown failure";
    const detail =
      error instanceof ReleaseShareKekError
        ? error.message
        : `could not persist the wrapped Release Share: ${cause}`;
    const reason: ManagedAuthoringRejection =
      error instanceof ReleaseShareKekError ? "RELEASE_SHARE_KEK_INVALID" : "RELEASE_SHARE_PERSIST_FAILED";
    return { ok: false, reason, detail };
  }
}

/**
 * Zeroize every buffer one execute() created — same set, same order as the
 * inline `finally` (key and seed buffers first through their holders).
 */
function zeroizeManagedSecrets(parts: {
  vekCopy: Uint8Array;
  releaseShare: Uint8Array;
  salt: Uint8Array;
  buffers: ManagedSealBuffers;
  kek: Uint8Array;
}): void {
  secureZero(parts.vekCopy);
  secureZero(parts.releaseShare);
  secureZero(parts.salt);
  if (parts.buffers.keyBytes) secureZero(parts.buffers.keyBytes);
  if (parts.buffers.seedBytes) secureZero(parts.buffers.seedBytes);
  secureZero(parts.kek);
}

/**
 * Encrypt plaintext into the `salt|iv|ciphertext` layout the extension's
 * `decryptAESGCM` reads back (32-byte salt, 12-byte IV, ciphertext+tag).
 */
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

export class ManagedAuthoringUseCase {
  constructor(
    private releaseShareStore: IReleaseShareStore,
    /**
     * Raw 32-byte server secret backing the Release Share KEK. Never defaulted:
     * a missing/short value is a typed, fail-closed rejection.
     */
    private releaseShareKekSecret: SessionVek,
  ) {}

  async execute(input: ManagedAuthoringInput): Promise<ManagedAuthoringResult> {
    /* ---- 1. Validate the origin BEFORE anything else (client semantics). ---- */
    const origin = validateManagedOrigin(input.origin);
    if (!origin.ok) return reject(origin.reason, origin.detail);

    /* ---- 2. Validate the rest of the input. ---- */
    const fields = validateManagedFields(input);
    if (!fields.ok) return reject(fields.reason, fields.detail);
    const { username, title, secretRef } = fields;

    /* ---- 3. Release Share KEK: fail closed, no default. ---- */
    const kekResult = await deriveReleaseShareKekOrReject(this.releaseShareKekSecret);
    if (!kekResult.ok) return kekResult.rejection;
    const kek = kekResult.kek;

    /* ------------------------------------------------------------------
     * Everything below creates secret material. It is all zeroized in the
     * `finally`, including the KEK and a private copy of the VEK.
     * ------------------------------------------------------------------ */
    const vekCopy = new Uint8Array(fields.vek);
    const releaseShare = crypto.getRandomValues(new Uint8Array(RELEASE_SHARE_LEN));
    const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
    const buffers: ManagedSealBuffers = { keyBytes: null, seedBytes: null };

    try {
      const credentialId = input.id ?? crypto.randomUUID();

      /* Steps 4–6 — entry key, envelope sealing, opaque lookup token. */
      const sealed = await sealManagedSecrets({
        vek: vekCopy,
        releaseShare,
        input,
        username,
        canonicalOrigin: origin.canonical,
        credentialId,
        salt,
        existingIndex: input.existingIndex,
        buffers,
      });
      if (!sealed.ok) return reject(sealed.reason, sealed.detail);

      /* Step 7 — wrap the Release Share and persist the opaque blob. */
      const persisted = await wrapAndPersistShare(kek, releaseShare, secretRef, this.releaseShareStore);
      if (!persisted.ok) return reject(persisted.reason, persisted.detail);

      const record: AuthoredCredentialRecord = {
        id: credentialId,
        mode: "managed",
        encryptedSecret: sealed.encryptedSecret,
        encryptedTotpSecret: sealed.encryptedTotpSecret,
        salt: binaryToBase64(salt),
        version: ENTRY_VERSION,
        releaseShareRef: secretRef,
        usernameHint: redactUsername(username),
        title,
        origin: origin.canonical,
      };

      return { ok: true, record, index: sealed.index, lookupToken: sealed.lookupToken };
    } catch (error) {
      const detail = error instanceof Error ? error.message : "unknown failure";
      return reject("INTERNAL_ERROR", `unexpected failure while authoring: ${detail}`);
    } finally {
      zeroizeManagedSecrets({ vekCopy, releaseShare, salt, buffers, kek });
    }
  }
}
