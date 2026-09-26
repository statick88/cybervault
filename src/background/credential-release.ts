/**
 * Credential release — service-worker side.
 *
 * WHY THE ORIGIN IS NEVER STORED
 * ------------------------------
 * The opaque index maps `lookupToken -> credentialId[]`. Tokens are one-way, so
 * the service worker cannot recover an origin from the index. That is the point
 * (§6.6: the backend must not learn the user's service map), but it creates a
 * question: how does the worker know which origin a credential is bound to when
 * it has to run the guard?
 *
 * The answer is that it never needs to know. The token IS the binding proof:
 *
 *     token = HMAC(indexKey, canonicalOrigin)
 *
 * If `credentialId` is in the bucket for `token(requestedOrigin)`, then that
 * credential was registered against exactly that origin. Recomputing the token
 * and finding the id in the bucket proves the binding without ever storing,
 * transmitting or recovering the origin string. A compromised index cannot
 * launder a credential onto a different origin, because it cannot produce the
 * token for an origin it was never granted.
 *
 * ORDER OF OPERATIONS (this ordering is the security property)
 * ------------------------------------------------------------
 *   1. Prove origin binding via the token/bucket lookup.
 *   2. Run the guard. Nothing is decrypted before it passes.
 *   3. Only then request a capability, obtain a Release Share, derive the
 *      per-entry key and decrypt.
 *
 * Decrypting before the guard would mean holding a plaintext secret while
 * deciding whether to release it — a bug in a later step would then leak it.
 *
 * @module background/credential-release
 */

import { evaluateAutofill } from "../domain/services/autofill/autofill-guard";
import {
  computeLookupToken,
  indexEntryMatchesOrigin,
  type OpaqueIndex,
} from "../domain/services/autofill/domain-index";
import { deriveManagedEntryKey, derivePersonalEntryKey } from "../infrastructure/crypto/hkdf-derivation";
import { base64ToBinary } from "../shared/utils";
import { secureZero } from "../infrastructure/crypto/secure-memory";

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

/**
 * The encrypted envelope holding the user-facing secret.
 *
 * Username and password travel together because at the extension boundary the
 * username is written into a web page — the same disclosure channel as the
 * password. Treating it as public metadata here would be inconsistent with how
 * it is actually used. The keys are terse because the ciphertext is persisted
 * and self-describing names invite logging.
 */
export interface SecretEnvelope {
  /** Username. */
  u: string;
  /** Password. */
  p: string;
}

/** An encrypted credential record as persisted. Never contains plaintext. */
export interface EncryptedCredentialRecord {
  id: string;
  mode: "personal" | "managed";
  /** Base64 `salt|iv|ciphertext` of the SecretEnvelope. */
  encryptedSecret: string;
  /** Base64 `salt|iv|ciphertext` of the TOTP seed, when present. */
  encryptedTotpSecret?: string;
  /** Base64 32-byte per-entry salt for HKDF. */
  salt: string;
  version: number;
  /** Opaque reference, managed entries only. */
  releaseShareRef?: string;
  /** Redacted display metadata, safe to return to the page. */
  title?: string;
  usernameHint?: string;
}

export interface CandidateSummary {
  credentialId: string;
  origin: string;
  hasTotp: boolean;
  /**
   * User-authored display label.
   *
   * This is the field that lets the user tell two accounts apart. The redacted
   * username hint cannot: "octocat" and "ostrich" both redact to "o******", so
   * relying on it would make the candidate list ambiguous exactly when the user
   * has several credentials for one origin.
   */
  title?: string;
  /** Redacted, non-reversible username for context. Never the real value. */
  usernameHint?: string;
}

export interface ReleasedCredential {
  id: string;
  username: string;
  password: string;
  totpSecret?: string;
}

export type ReleaseOutcome =
  | { readonly ok: true; readonly credential: ReleasedCredential }
  | { readonly ok: false; readonly code: ReleaseDenialCode; readonly detail: string };

export type ReleaseDenialCode =
  | "VAULT_LOCKED"
  | "ORIGIN_UNUSABLE"
  | "ORIGIN_NOT_BOUND"
  | "CREDENTIAL_NOT_FOUND"
  | "GUARD_BLOCKED"
  | "CAPABILITY_DENIED"
  | "CHALLENGE_REQUIRED"
  | "RELEASE_SHARE_DENIED"
  | "DECRYPT_FAILED"
  | "MANAGED_REQUIRED"
  | "TOTP_DECRYPT_FAILED";

/* ------------------------------------------------------------------ */
/*  Collaborators (injected so this module is testable without chrome)  */
/* ------------------------------------------------------------------ */

export interface ReleaseDeps {
  /** Session VEK, or null when the vault is locked. */
  getVek(): Promise<Uint8Array | null>;
  getIndex(): Promise<OpaqueIndex>;
  getRecord(credentialId: string): Promise<EncryptedCredentialRecord | null>;
  /**
   * Obtain an Ed25519 capability from Plus for a managed credential.
   * Resolves to null when Plus requires a step-up challenge instead.
   */
  requestCapability(input: {
    credentialId: string;
    secretRef: string;
    operation: "AUTOFILL" | "VIEW" | "TOTP";
  }): Promise<{ ok: true; releaseShare: string } | { ok: false; challengeRequired: true } | { ok: false; challengeRequired?: false; detail: string }>;
}

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

function toArrayBuffer(data: Uint8Array): ArrayBuffer {
  const buf = new ArrayBuffer(data.byteLength);
  new Uint8Array(buf).set(data);
  return buf;
}

interface ParsedCiphertext {
  salt: Uint8Array;
  iv: Uint8Array;
  body: Uint8Array;
}

const SALT_LEN = 32;
const IV_LEN = 12;

function parseCiphertext(blob: string): ParsedCiphertext | null {
  try {
    const bytes = base64ToBinary(blob);
    if (bytes.length <= SALT_LEN + IV_LEN) return null;
    return {
      salt: bytes.slice(0, SALT_LEN),
      iv: bytes.slice(SALT_LEN, SALT_LEN + IV_LEN),
      body: bytes.slice(SALT_LEN + IV_LEN),
    };
  } catch {
    return null;
  }
}

/**
 * Decrypt a `salt|iv|ciphertext` blob with a raw AES-256-GCM key.
 *
 * The salt travels with the ciphertext, but the KEY is always derived from the
 * record's own `salt` field via HKDF. The embedded salt is what the writer used;
 * they must agree, and a mismatch surfaces as a decryption failure rather than
 * silently producing garbage.
 */
async function decryptBlob(blob: string, keyBytes: Uint8Array): Promise<string | null> {
  const parsed = parseCiphertext(blob);
  if (!parsed) return null;

  try {
    const key = await crypto.subtle.importKey(
      "raw",
      toArrayBuffer(keyBytes),
      "AES-GCM",
      false,
      ["decrypt"],
    );
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: toArrayBuffer(parsed.iv), tagLength: 128 },
      key,
      toArrayBuffer(parsed.body),
    );
    return new TextDecoder().decode(plain);
  } catch {
    return null;
  }
}

function deny(code: ReleaseDenialCode, detail: string): ReleaseOutcome {
  return { ok: false, code, detail };
}

/* ------------------------------------------------------------------ */
/*  Candidate listing                                                  */
/* ------------------------------------------------------------------ */

/**
 * List the credentials bound to an origin, WITHOUT releasing any secret.
 *
 * Only non-secret metadata crosses this boundary: an id, the origin it is bound
 * to, and whether a TOTP seed exists. No username, no password, no TOTP seed.
 */
export async function listCandidatesForOrigin(
  origin: string,
  deps: ReleaseDeps,
): Promise<CandidateSummary[]> {
  const provided = await deps.getVek();
  if (!provided) return [];

  // Work on a private copy. The first draft zeroed the caller's buffer in the
  // `finally` block, which silently corrupted any caller that cached the VEK:
  // the second call derived the index key from all-zero bytes and every lookup
  // failed with ORIGIN_NOT_BOUND. Functions here now promise never to mutate
  // memory they were handed.
  const vek = provided.slice();

  try {
    const { deriveDomainIndexKey } = await import("../domain/services/autofill/domain-index");
    const indexKey = await deriveDomainIndexKey(vek);

    const token = await computeLookupToken(origin, indexKey);
    if (!token.ok) return [];

    const index = await deps.getIndex();
    const { lookupIndex } = await import("../domain/services/autofill/domain-index");
    const ids = lookupIndex(index, token.token);

    const canonical = token.origin.serialized;
    const summaries: CandidateSummary[] = [];

    for (const credentialId of ids) {
      const record = await deps.getRecord(credentialId);
      if (!record) continue; // index drifted from storage; skip rather than fail
      summaries.push({
        credentialId,
        origin: canonical,
        hasTotp: Boolean(record.encryptedTotpSecret),
        title: record.title,
        usernameHint: record.usernameHint,
      });
    }
    return summaries;
  } catch {
    // Fail closed: an unreadable index means no candidates, not "all".
    return [];
  } finally {
    secureZero(vek);
  }
}

/* ------------------------------------------------------------------ */
/*  Release                                                            */
/* ------------------------------------------------------------------ */

export interface ReleaseRequest {
  credentialId: string;
  /** Origin the page claims to be. Proven against the index, not trusted. */
  origin: string;
  operation: "AUTOFILL" | "TOTP";
  documentOrigin: string;
  topLevelOrigin: string;
  isFramed: boolean;
}

/**
 * Release a credential to a page, or refuse with a reason.
 */
export async function releaseCredential(
  request: ReleaseRequest,
  deps: ReleaseDeps,
): Promise<ReleaseOutcome> {
  const provided = await deps.getVek();
  if (!provided) return deny("VAULT_LOCKED", "vault is locked");

  // Private copy — see the note in listCandidatesForOrigin. Zeroing the
  // caller's buffer here corrupted cached VEKs across calls.
  const vek = provided.slice();

  let entryKeyBytes: Uint8Array | null = null;

  try {
    const { deriveDomainIndexKey } = await import("../domain/services/autofill/domain-index");
    const indexKey = await deriveDomainIndexKey(vek);

    /* Step 1 — prove the origin binding. */
    const token = await computeLookupToken(request.origin, indexKey);
    if (!token.ok) return deny("ORIGIN_UNUSABLE", "requested origin is unusable");

    const index = await deps.getIndex();
    const bound = await indexEntryMatchesOrigin(
      index,
      token.token,
      request.credentialId,
      token.origin.serialized,
      indexKey,
    );
    if (!bound) {
      return deny(
        "ORIGIN_NOT_BOUND",
        "credential is not bound to the requested origin",
      );
    }

    /* Step 2 — the record must exist and match the mode we expect. */
    const record = await deps.getRecord(request.credentialId);
    if (!record) return deny("CREDENTIAL_NOT_FOUND", "no such credential");

    if (record.mode === "managed" && !record.releaseShareRef) {
      return deny("MANAGED_REQUIRED", "managed credential has no Release Share reference");
    }

    /* Step 3 — the guard, before any decryption. */
    const decision = evaluateAutofill({
      operation: "AUTOFILL",
      credentialOrigin: token.origin.serialized,
      documentOrigin: request.documentOrigin,
      topLevelOrigin: request.isFramed ? request.topLevelOrigin : null,
      frameOrigin: request.isFramed ? request.documentOrigin : null,
    });
    if (!decision.allowed) {
      return deny("GUARD_BLOCKED", `${decision.reason}: ${decision.detail}`);
    }

    /* Step 4 — derive the per-entry key. */
    const salt = base64ToBinary(record.salt);
    let entryKeyBase64: string;

    if (record.mode === "personal") {
      const derived = await derivePersonalEntryKey(
        vek,
        salt,
        record.id,
        record.version,
      );
      entryKeyBase64 = derived.keyBase64;
    } else {
      const capability = await deps.requestCapability({
        credentialId: record.id,
        secretRef: record.releaseShareRef as string,
        operation: "AUTOFILL",
      });

      if ("challengeRequired" in capability && capability.challengeRequired) {
        // A step-up is required. That is a legitimate outcome, not an error,
        // and it must NOT be reported to the page as a generic failure.
        return deny(
          "CHALLENGE_REQUIRED",
          "policy requires a step-up challenge before release",
        );
      }
      if (!capability.ok) {
        return deny("CAPABILITY_DENIED", capability.detail);
      }

      const releaseShare = base64ToBinary(capability.releaseShare);
      const derived = await deriveManagedEntryKey(
        vek,
        releaseShare,
        salt,
        record.id,
        record.version,
      );
      secureZero(releaseShare);
      entryKeyBase64 = derived.keyBase64;
    }

    entryKeyBytes = base64ToBinary(entryKeyBase64);

    /* Step 5 — decrypt the envelope. */
    const envelopeRaw = await decryptBlob(record.encryptedSecret, entryKeyBytes);
    if (envelopeRaw === null) {
      return deny("DECRYPT_FAILED", "secret blob could not be decrypted");
    }

    let envelope: SecretEnvelope;
    try {
      const parsed = JSON.parse(envelopeRaw) as Partial<SecretEnvelope>;
      if (typeof parsed?.u !== "string" || typeof parsed?.p !== "string") {
        return deny("DECRYPT_FAILED", "secret envelope is malformed");
      }
      envelope = { u: parsed.u, p: parsed.p };
    } catch {
      return deny("DECRYPT_FAILED", "secret envelope is not valid JSON");
    }

    let totpSecret: string | undefined;
    if (record.encryptedTotpSecret) {
      const seed = await decryptBlob(record.encryptedTotpSecret, entryKeyBytes);
      if (seed === null) {
        // A broken TOTP seed must not block the password release; the seed is
        // simply unavailable for this fill.
        secureZero(entryKeyBytes);
        return {
          ok: true,
          credential: { id: record.id, username: envelope.u, password: envelope.p },
        };
      }
      totpSecret = seed;
    }

    return {
      ok: true,
      credential: {
        id: record.id,
        username: envelope.u,
        password: envelope.p,
        ...(totpSecret ? { totpSecret } : {}),
      },
    };
  } catch {
    return deny("DECRYPT_FAILED", "unexpected failure during release");
  } finally {
    secureZero(vek);
    if (entryKeyBytes) secureZero(entryKeyBytes);
  }
}
