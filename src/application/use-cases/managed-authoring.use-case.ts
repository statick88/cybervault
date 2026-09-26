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

export interface ManagedAuthoringInput {
  /** Raw user-supplied origin. Validated, never trusted verbatim. */
  origin: string;
  username: string;
  password: string;
  title: string;
  /** Base32 or Base64 TOTP seed; encoded to bytes here. */
  totpSeedBase32?: string;
  /** Session VEK. Copied internally; the caller keeps ownership of this buffer. */
  vek: Uint8Array | null | undefined;
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
    private releaseShareKekSecret: Uint8Array | null | undefined,
  ) {}

  async execute(input: ManagedAuthoringInput): Promise<ManagedAuthoringResult> {
    /* ---- 1. Validate the origin BEFORE anything else (client semantics). ---- */
    if (input.origin === null || input.origin === undefined || input.origin.trim() === "") {
      return reject("ORIGIN_MISSING", "an origin is required");
    }

    const trimmedOrigin = input.origin.trim();
    // A bare host such as "github.com" is not an origin. Refusing it here is
    // better than guessing a scheme, because guessing http for an https site
    // would produce a permanently unfillable credential.
    if (!/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmedOrigin)) {
      return reject(
        "ORIGIN_NOT_ABSOLUTE",
        `origin must be absolute (scheme://host[:port]); got "${trimmedOrigin}"`,
      );
    }

    const parsed = parseAbsoluteOrigin(trimmedOrigin);
    if (!parsed.ok) {
      return reject(
        parsed.reason === "UNSUPPORTED_SCHEME" ? "ORIGIN_SCHEME_NOT_ALLOWED" : "ORIGIN_NOT_ABSOLUTE",
        `origin rejected (${parsed.reason})`,
      );
    }
    const canonicalOrigin = parsed.origin.serialized;

    /* ---- 2. Validate the rest of the input. ---- */
    const username = input.username?.trim() ?? "";
    if (username === "") {
      return reject("USERNAME_REQUIRED", "a username is required");
    }
    if (!input.password) {
      return reject("PASSWORD_REQUIRED", "a password is required");
    }
    const title = input.title?.trim() || username;
    if (title === "") {
      return reject("TITLE_REQUIRED", "a title is required");
    }
    const secretRef = input.secretRef?.trim() ?? "";
    if (secretRef === "") {
      return reject(
        "SECRET_REF_REQUIRED",
        "a fresh opaque Release Share reference is required",
      );
    }
    if (!input.vek || input.vek.byteLength === 0) {
      return reject("VEK_MISSING", "vault is locked: no VEK supplied");
    }

    /* ---- 3. Release Share KEK: fail closed, no default. ---- */
    let kek: Uint8Array | null = null;
    try {
      kek = await deriveReleaseShareKek(this.releaseShareKekSecret);
    } catch (error) {
      const detail =
        error instanceof ReleaseShareKekError ? error.message : "Release Share KEK unavailable";
      return reject("RELEASE_SHARE_KEK_INVALID", detail);
    }

    /* ------------------------------------------------------------------
     * Everything below creates secret material. It is all zeroized in the
     * `finally`, including the KEK and a private copy of the VEK.
     * ------------------------------------------------------------------ */
    const vekCopy = new Uint8Array(input.vek);
    const releaseShare = crypto.getRandomValues(new Uint8Array(RELEASE_SHARE_LEN));
    const salt = crypto.getRandomValues(new Uint8Array(SALT_LEN));
    let keyBytes: Uint8Array | null = null;
    let seedBytes: Uint8Array | null = null;

    try {
      const credentialId = input.id ?? crypto.randomUUID();

      /* ---- 4. EntryKey = HKDF(VEK || ReleaseShare, salt, context). ---- */
      const derived = await deriveManagedEntryKey(
        vekCopy,
        releaseShare,
        salt,
        credentialId,
        ENTRY_VERSION,
      );
      keyBytes = base64ToBinary(derived.keyBase64);

      /* ---- 5. Seal the {u, p} envelope (username travels with the password). ---- */
      const envelope = { u: username, p: input.password };
      const encryptedSecret = await seal(JSON.stringify(envelope), keyBytes, salt);

      let encryptedTotpSecret: string | undefined;
      if (input.totpSeedBase32) {
        seedBytes = base32ToBytes(input.totpSeedBase32);
        if (seedBytes.length === 0) {
          return reject("TOTP_SEED_INVALID", "TOTP seed contained no usable characters");
        }
        encryptedTotpSecret = await seal(binaryToBase64(seedBytes), keyBytes, salt);
      }

      /* ---- 6. Opaque lookup token: origin is derived into, never stored. ---- */
      const indexKey = await deriveDomainIndexKey(vekCopy);
      const token = await computeLookupToken(canonicalOrigin, indexKey);
      if (!token.ok) {
        return reject("ORIGIN_NOT_ABSOLUTE", "could not derive a lookup token");
      }

      const nextIndex = addToIndex(
        input.existingIndex ?? { version: 1, byToken: {} },
        token.token,
        credentialId,
      );

      /* ---- 7. Wrap the Release Share and persist the opaque blob. ---- */
      try {
        const wrappedShare = await wrapReleaseShare(kek, releaseShare, secretRef);
        await this.releaseShareStore.save({
          secretRef,
          wrappedShare,
          createdAt: new Date(),
        });
      } catch (error) {
        const detail =
          error instanceof ReleaseShareKekError
            ? error.message
            : `could not persist the wrapped Release Share: ${error instanceof Error ? error.message : "unknown failure"}`;
        const reason: ManagedAuthoringRejection =
          error instanceof ReleaseShareKekError ? "RELEASE_SHARE_KEK_INVALID" : "RELEASE_SHARE_PERSIST_FAILED";
        return reject(reason, detail);
      }

      const record: AuthoredCredentialRecord = {
        id: credentialId,
        mode: "managed",
        encryptedSecret,
        encryptedTotpSecret,
        salt: binaryToBase64(salt),
        version: ENTRY_VERSION,
        releaseShareRef: secretRef,
        usernameHint: redactUsername(username),
        title,
        origin: canonicalOrigin,
      };

      return { ok: true, record, index: nextIndex, lookupToken: token.token };
    } catch (error) {
      const detail = error instanceof Error ? error.message : "unknown failure";
      return reject("INTERNAL_ERROR", `unexpected failure while authoring: ${detail}`);
    } finally {
      secureZero(vekCopy);
      secureZero(releaseShare);
      secureZero(salt);
      if (keyBytes) secureZero(keyBytes);
      if (seedBytes) secureZero(seedBytes);
      if (kek) secureZero(kek);
    }
  }
}
