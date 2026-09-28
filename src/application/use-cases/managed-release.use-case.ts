/**
 * Use Case: Managed Credential Release
 *
 * Verifies a capability token from Plus and returns the ReleaseShare
 * for a managed credential. This is the Core↔Plus bridge endpoint.
 *
 * Flow:
 * 1. Fail closed when `PLUS_PUBLIC_KEY` is not pinned (never a request key)
 * 2. Verify capability signature (Ed25519) with the PINNED Plus public key,
 *    plus expiry, issuer, audience, operation, and every declared binding
 *    (userId, resourceId, secretRef, deviceId) against the expected context
 * 3. Atomically consume JTI (replay protection)
 * 4. Find credential by secretRef
 * 5. Verify credential is MANAGED mode
 * 6. Verify the credential's Release Share reference matches the capability
 *    AND that the credential lives in the vault named in the URL
 * 7. Unwrap the stored Release Share with the Release Share KEK and return it
 *    (base64). Fails closed — never falls back to the opaque reference.
 *
 * DEFECT D1 (odd/tasks/cybervault-final-security-architecture.md): step 7 used
 * to return `credential.releaseShareRef`, so the client derived
 * `HKDF(VEK || base64(reference))` and every AES-GCM open failed. The share is
 * now minted and wrapped server-side by `ManagedAuthoringUseCase` and only ever
 * leaves Core here, after all six checks above.
 */

import type { ICredentialRepository, IReleaseShareStore } from "../../domain/repositories";
import type { Credential } from "../../domain/entities/credential";
import {
  verifyCapability,
  CapabilityPayload,
  CapabilityOperation,
  CapabilityBindingContext,
} from "../../infrastructure/crypto/ed25519-capability";
import { verifyAndConsumeJti } from "../../infrastructure/crypto/jti-store";
import {
  deriveReleaseShareKek,
  unwrapReleaseShare,
  ReleaseShareKekError,
} from "../../infrastructure/crypto/release-share-kek";
import { secureZero } from "../../infrastructure/crypto/secure-memory";
import { binaryToBase64 } from "../../shared/utils";

export interface ManagedReleaseInput {
  capabilityToken: {
    payload: CapabilityPayload;
    signature: string;
    protectedHeader: string;
  };
  /**
   * Bindings the capability must satisfy: authenticated user, requested
   * resource, requested secret and bound device. Built by the route from the
   * session, the URL vault and Core's own credential store — never from the
   * capability and never from the request. Required: a missing context is a
   * refusal, not a skipped check.
   */
  expected: CapabilityBindingContext;
  /** Vault named in the URL. The released credential must live in it. */
  vaultId: string;
}

export interface ManagedReleaseOutput {
  success: boolean;
  /** Base64 Release Share — the actual 32-byte share, not its reference. */
  releaseShare?: string;
  error?: string;
  credentialId?: string;
}

/**
 * Capability validity window, in seconds, for JTI consumption.
 *
 * `iat` and `exp` are Unix SECONDS (`createCapabilityPayload`, and
 * `verifyCapability` compares `exp` against `Math.floor(Date.now()/1000)`), so
 * the window is `exp - iat`. This file used to pass
 * `Math.floor((exp - iat) / 1000)`, which collapsed a 5-minute capability to a
 * 0-second JTI window — `InMemoryJtiStore` then treats the entry as already
 * expired and every replay is accepted. A non-positive window is refused
 * rather than consumed, so a malformed capability cannot disable replay
 * protection.
 */
function capabilityTtlSeconds(
  capability: CapabilityPayload,
): { ok: true; ttlSeconds: number } | { ok: false; error: string } {
  const ttlSeconds = Math.floor(capability.exp) - Math.floor(capability.iat);
  if (!Number.isFinite(ttlSeconds) || ttlSeconds <= 0) {
    return { ok: false, error: "Capability has an invalid validity window" };
  }
  return { ok: true, ttlSeconds };
}

/**
 * Outcome of a fail-closed configuration gate. The `plusPublicKey` branch is
 * not decoration: it is how `execute` keeps the PINNED key narrowed to
 * `Uint8Array` after the "is it configured at all" check has passed.
 */
type PinnedKeyGate = { ok: false; error: string } | { ok: true; plusPublicKey: Uint8Array };

/** Outcome of resolving the credential a capability is allowed to release. */
type ResolvedReleaseCredential =
  | { ok: true; credential: Credential }
  | { ok: false; error: string };

export class ManagedReleaseUseCase {
  constructor(
    private credentialRepository: ICredentialRepository,
    private jtiStore?: any, // Optional custom JTI store
    /**
     * Core-side store of wrapped Release Shares. When absent, release fails
     * closed: there is no path that could hand back the opaque reference.
     */
    private releaseShareStore?: IReleaseShareStore | null,
    /** Raw 32-byte server secret backing the Release Share KEK. No default. */
    private releaseShareKekSecret?: Uint8Array | null,
    /**
     * PINNED Ed25519 verification key (from `PLUS_PUBLIC_KEY` via
     * `loadPlusPublicKey`). No default, never taken from the request: null
     * means every managed release refuses with the missing variable named.
     */
    private plusPublicKey?: Uint8Array | null,
  ) {}

  async execute(input: ManagedReleaseInput): Promise<ManagedReleaseOutput> {
    try {
      // 0. Fail closed on configuration BEFORE anything else: without the
      //    pinned key there is nothing trustworthy to verify against, and the
      //    refusal must name the real blocker for the operator. The checks
      //    live in `configurationRefusal`, in their original order.
      const key = this.configurationRefusal(input);
      if (!key.ok) {
        return { success: false, error: key.error };
      }

      // 1. Verify capability signature, structure AND every declared binding
      //    (userId, resourceId, secretRef, deviceId) against `input.expected`.
      const verifyResult = await verifyCapability(
        input.capabilityToken,
        key.plusPublicKey,
        input.expected,
      );
      if (!verifyResult.valid) {
        return { success: false, error: verifyResult.error };
      }

      const capability = input.capabilityToken.payload;

      // 2. Verify operation is allowed for release
      if (capability.operation !== "VIEW" && capability.operation !== "AUTOFILL" && capability.operation !== "TOTP") {
        return { success: false, error: `Operation ${capability.operation} not allowed for managed release` };
      }

      // 3. Atomically consume JTI (replay protection)
      const ttl = capabilityTtlSeconds(capability);
      if (!ttl.ok) {
        return { success: false, error: ttl.error };
      }
      const jtiResult = await verifyAndConsumeJti(
        capability.jti,
        ttl.ttlSeconds, // TTL in seconds
        this.jtiStore,
      );
      if (!jtiResult.allowed) {
        return { success: false, error: jtiResult.error };
      }

      // 4–6b. Resolve the credential THROUGH the capability and check it
      //        against the capability's secretRef and the vault named in the
      //        URL, in that order.
      const resolved = await this.resolveCredentialForRelease(capability, input.vaultId);
      if (!resolved.ok) {
        return { success: false, error: resolved.error };
      }
      const credential = resolved.credential;

      // 7. Unwrap the Release Share with the Core-held Release Share KEK and
      //    return the share itself. Fail closed on every path: a missing store,
      //    a missing secret, an unknown reference or an authentication failure
      //    all produce an error, never a fallback to the opaque reference.
      const unwrapped = await this.unwrapStoredReleaseShare(credential.releaseShareRef);
      if (!unwrapped.ok) {
        return { success: false, error: unwrapped.error };
      }

      const releaseShare = binaryToBase64(unwrapped.share);
      secureZero(unwrapped.share);

      return {
        success: true,
        releaseShare,
        credentialId: credential.id.toString(),
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown error";
      return { success: false, error: `Managed release failed: ${message}` };
    }
  }

  /**
   * The configuration refusals of the release flow (steps 0, 0b and the vault
   * binding), verbatim and in their original order. A refusal here always
   * precedes signature verification: without a pinned key there is nothing
   * trustworthy to verify against, and a missing binding context must never
   * reach `verifyCapability` as `undefined`, because the optional third
   * argument is only tolerated for Plus's own self-verification.
   */
  private configurationRefusal(input: ManagedReleaseInput): PinnedKeyGate {
    if (!this.plusPublicKey || this.plusPublicKey.byteLength === 0) {
      return {
        ok: false,
        error:
          "Managed release refused: PLUS_PUBLIC_KEY is not configured — the Ed25519 capability " +
          "verification key must be pinned in server configuration (base64 of the Plus signer's " +
          "32-byte public key)",
      };
    }
    if (!input.expected || typeof input.expected !== "object") {
      return {
        ok: false,
        error: "Managed release refused: capability binding context missing",
      };
    }
    if (typeof input.vaultId !== "string" || input.vaultId === "") {
      return {
        ok: false,
        error: "Managed release refused: vault binding missing",
      };
    }
    return { ok: true, plusPublicKey: this.plusPublicKey };
  }

  /**
   * Steps 4–6b of the release flow: find, then check. The order of the four
   * refusals is part of the security contract — it decides WHICH reason a
   * refused release reports — so each condition and its message is unchanged.
   */
  private async resolveCredentialForRelease(
    capability: CapabilityPayload,
    vaultId: string,
  ): Promise<ResolvedReleaseCredential> {
    // 4. Find credential by secretRef (opaque reference)
    const credential = await this.credentialRepository.findBySecretRef(capability.secretRef);
    if (!credential) {
      return { ok: false, error: "Credential not found for secretRef" };
    }

    // 5. Verify credential is MANAGED mode
    if (!credential.isManaged()) {
      return { ok: false, error: "Credential is not managed (requires Plus authorization)" };
    }

    // 6. Verify the secretRef matches
    if (credential.releaseShareRef !== capability.secretRef) {
      return { ok: false, error: "Secret reference mismatch" };
    }

    // 6b. THE CREDENTIAL MUST LIVE IN THE VAULT NAMED IN THE URL. Without
    //     this, a capability (or a colliding `releaseShareRef` — H5) could
    //     release a credential from another user's vault: the route already
    //     proved the caller owns `vaultId`, so this binds the released
    //     row to that same vault instead of trusting the lookup alone.
    if (credential.vaultId.toString() !== vaultId) {
      return { ok: false, error: "Credential does not belong to the requested vault" };
    }

    return { ok: true, credential };
  }

  /**
   * Unwrap the stored Release Share for `secretRef`.
   *
   * The returned buffer is secret material: the caller must `secureZero` it
   * once it has been encoded. Every failure mode is reported as a refusal
   * rather than a partial result.
   */
  private async unwrapStoredReleaseShare(
    secretRef: string | undefined,
  ): Promise<{ ok: true; share: Uint8Array } | { ok: false; error: string }> {
    if (!secretRef) {
      return { ok: false, error: "Credential has no Release Share reference" };
    }
    if (!this.releaseShareStore) {
      return {
        ok: false,
        error: "Managed release is not configured: Release Share store unavailable",
      };
    }

    let kek: Uint8Array | null = null;
    try {
      kek = await deriveReleaseShareKek(this.releaseShareKekSecret);
    } catch (error) {
      const detail =
        error instanceof ReleaseShareKekError ? error.message : "Release Share KEK unavailable";
      return { ok: false, error: `Managed release refused: ${detail}` };
    }

    try {
      const wrapped = await this.releaseShareStore.findBySecretRef(secretRef);
      if (!wrapped) {
        return { ok: false, error: "Release Share not found for secretRef" };
      }
      const share = await unwrapReleaseShare(kek, wrapped.wrappedShare, wrapped.secretRef);
      return { ok: true, share };
    } catch (error) {
      // Fail closed. Never return the reference as a stand-in for the share.
      const detail = error instanceof Error ? error.message : "unknown failure";
      return {
        ok: false,
        error: `Release Share unwrapping failed: ${detail}`,
      };
    } finally {
      if (kek) secureZero(kek);
    }
  }
}

// Additional use case for retrieving credential with capability verification
export interface GetCredentialWithCapabilityInput {
  capabilityToken: {
    payload: CapabilityPayload;
    signature: string;
    protectedHeader: string;
  };
  /**
   * Bindings the capability must satisfy (authenticated user, requested
   * resource, requested secret, bound device). Required — never derived from
   * the capability itself.
   */
  expected: CapabilityBindingContext;
  credentialId: string;
}

export interface GetCredentialWithCapabilityOutput {
  success: boolean;
  credential?: {
    id: string;
    title: string;
    username: string;
    encryptedPassword: string;
    mode: string;
    salt: string;
    version: number;
    releaseShareRef?: string;
  };
  error?: string;
}

/** Operations a capability may carry that can result in a credential read. */
const RELEASABLE_OPERATIONS: ReadonlySet<string> = new Set<CapabilityOperation>([
  "VIEW",
  "AUTOFILL",
  "TOTP",
]);

function isReleasableOperation(operation: CapabilityOperation): boolean {
  return RELEASABLE_OPERATIONS.has(operation);
}

export class GetCredentialWithCapabilityUseCase {
  constructor(
    private credentialRepository: ICredentialRepository,
    private jtiStore?: any,
    /** PINNED Ed25519 verification key. No default: null refuses. */
    private plusPublicKey?: Uint8Array | null,
  ) {}

  async execute(input: GetCredentialWithCapabilityInput): Promise<GetCredentialWithCapabilityOutput> {
    try {
      // Fail closed: no pinned key, no verification — never a request key.
      const key = this.configurationRefusal(input);
      if (!key.ok) {
        return { success: false, error: key.error };
      }

      // Verify capability: signature, structure and every declared binding.
      const verifyResult = await verifyCapability(
        input.capabilityToken,
        key.plusPublicKey,
        input.expected,
      );
      if (!verifyResult.valid) {
        return { success: false, error: verifyResult.error };
      }

      const capability = input.capabilityToken.payload;

      // Consume JTI
      const ttl = capabilityTtlSeconds(capability);
      if (!ttl.ok) {
        return { success: false, error: ttl.error };
      }
      const jtiResult = await verifyAndConsumeJti(
        capability.jti,
        ttl.ttlSeconds,
        this.jtiStore,
      );
      if (!jtiResult.allowed) {
        return { success: false, error: jtiResult.error };
      }

      // Resolve and check the credential THROUGH the capability, then make
      // sure the operation fits the credential's mode.
      const resolved = await this.resolveCredentialForCapability(capability, input.credentialId);
      if (!resolved.ok) {
        return { success: false, error: resolved.error };
      }
      const credential = resolved.credential;

      return {
        success: true,
        credential: {
          id: credential.id.toString(),
          title: credential.title,
          username: credential.username,
          encryptedPassword: credential.encryptedPassword,
          mode: credential.mode,
          salt: credential.salt,
          version: credential.version,
          releaseShareRef: credential.releaseShareRef,
        },
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown error";
      return { success: false, error: `Get credential failed: ${message}` };
    }
  }

  /**
   * The configuration refusals of this use case, verbatim and in their
   * original order: a pinned key first (never a request key), then the
   * binding context.
   */
  private configurationRefusal(
    input: GetCredentialWithCapabilityInput,
  ): PinnedKeyGate {
    if (!this.plusPublicKey || this.plusPublicKey.byteLength === 0) {
      return {
        ok: false,
        error:
          "Get credential refused: PLUS_PUBLIC_KEY is not configured — the Ed25519 capability " +
          "verification key must be pinned in server configuration",
      };
    }
    if (!input.expected || typeof input.expected !== "object") {
      return {
        ok: false,
        error: "Get credential refused: capability binding context missing",
      };
    }
    return { ok: true, plusPublicKey: this.plusPublicKey };
  }

  /**
   * Resolve the credential the capability authorizes, then check the caller's
   * credential id and the credential's mode against the capability's
   * operation — in that order, with the original messages.
   */
  private async resolveCredentialForCapability(
    capability: CapabilityPayload,
    credentialId: string,
  ): Promise<ResolvedReleaseCredential> {
    // Resolve the credential THROUGH the capability, never from the
    // request. A capability authorizes one secretRef, so looking the
    // credential up by a caller-supplied id would let any validly signed
    // capability retrieve any credential in the store: the capability's
    // userId, resourceId, operation and secretRef are all ignored once the
    // signature checks out. That is an IDOR, and the previous version of
    // this method did exactly that — the ownership check below was an empty
    // branch whose comment claimed the check existed.
    const credential = await this.credentialRepository.findBySecretRef(
      capability.secretRef,
    );
    if (!credential) {
      return { ok: false, error: "Credential not found for secretRef" };
    }

    // If the caller named a credential, it must be the one the capability
    // authorizes. Never the other way round.
    if (credentialId && credential.id.toString() !== credentialId) {
      return { ok: false, error: "Credential does not match the capability" };
    }

    // Operation must be consistent with the credential's mode. A VIEW of a
    // managed credential is exactly what a capability is for; an operation
    // the mode does not support is refused rather than served.
    if (credential.isManaged() && !isReleasableOperation(capability.operation)) {
      return { ok: false, error: "Operation is not permitted for this credential" };
    }
    if (credential.isPersonal() && capability.operation !== "VIEW") {
      return { ok: false, error: "Operation is not permitted for a personal credential" };
    }

    return { ok: true, credential };
  }
}