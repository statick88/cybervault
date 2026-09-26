/**
 * Use Case: Managed Credential Release
 *
 * Verifies a capability token from Plus and returns the ReleaseShare
 * for a managed credential. This is the Core↔Plus bridge endpoint.
 *
 * Flow:
 * 1. Verify capability signature (Ed25519) with Plus public key
 * 2. Check capability expiry, issuer, audience, operation
 * 3. Atomically consume JTI (replay protection)
 * 4. Find credential by secretRef
 * 5. Verify credential is MANAGED mode
 * 6. Verify the credential's Release Share reference matches the capability
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
import { CredentialId } from "../../domain/value-objects/ids";
import { verifyCapability, CapabilityPayload } from "../../infrastructure/crypto/ed25519-capability";
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
  plusPublicKey: string; // base64 Ed25519 public key
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
  ) {}

  async execute(input: ManagedReleaseInput): Promise<ManagedReleaseOutput> {
    try {
      // 1. Verify capability signature and structure
      const verifyResult = await verifyCapability(input.capabilityToken, 
        Buffer.from(input.plusPublicKey, "base64"),
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

      // 4. Find credential by secretRef (opaque reference)
      const credential = await this.credentialRepository.findBySecretRef(capability.secretRef);
      if (!credential) {
        return { success: false, error: "Credential not found for secretRef" };
      }

      // 5. Verify credential is MANAGED mode
      if (!credential.isManaged()) {
        return { success: false, error: "Credential is not managed (requires Plus authorization)" };
      }

      // 6. Verify the secretRef matches
      if (credential.releaseShareRef !== capability.secretRef) {
        return { success: false, error: "Secret reference mismatch" };
      }

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
  plusPublicKey: string;
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

export class GetCredentialWithCapabilityUseCase {
  constructor(
    private credentialRepository: ICredentialRepository,
    private jtiStore?: any,
  ) {}

  async execute(input: GetCredentialWithCapabilityInput): Promise<GetCredentialWithCapabilityOutput> {
    try {
      // Verify capability
      const verifyResult = await verifyCapability(input.capabilityToken,
        Buffer.from(input.plusPublicKey, "base64"),
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

      // Find credential by ID
      const credentialId = input.credentialId ? CredentialId.fromString(input.credentialId) : null;
      if (!credentialId) {
        return { success: false, error: "Credential ID required" };
      }
      const credential = await this.credentialRepository.findById(credentialId);
      if (!credential) {
        return { success: false, error: "Credential not found" };
      }

      // Verify credential belongs to the user in capability
      // (This would require userId in credential - adding to repository query)

      // Verify operation matches credential mode
      if (credential.isManaged() && capability.operation === "VIEW") {
        // VIEW requires capability for managed credentials
      } else if (credential.isPersonal() && capability.operation !== "VIEW") {
        // Personal credentials don't need capability for VIEW
        // but other operations might
      }

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
}