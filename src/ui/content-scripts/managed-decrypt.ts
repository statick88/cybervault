/**
 * Managed Credential Decrypt — Extension Side
 *
 * Handles decryption of managed credentials using split-trust architecture:
 * 1. Detects managed credential (has releaseShareRef)
 * 2. Requests capability from Plus via background script
 * 3. Uses capability to request ReleaseShare from Core
 * 4. Derives EntryKey = HKDF(VEK || ReleaseShare, salt, context)
 * 5. Decrypts credential payload with AES-256-GCM
 */

import { deriveManagedEntryKey } from "../../infrastructure/crypto/hkdf-derivation";
import { base64ToBinary } from "../../shared/utils";
import { secureZero } from "../../infrastructure/crypto/secure-memory";

/** Convert Uint8Array to ArrayBuffer for Web Crypto API */
function toArrayBuffer(data: Uint8Array): ArrayBuffer {
  const buf = new ArrayBuffer(data.byteLength);
  new Uint8Array(buf).set(data);
  return buf;
}

/** AES-GCM Decryption */
async function decryptAESGCM(
  ciphertextBase64: string,
  keyBase64: string,
): Promise<string | null> {
  try {
    const combined = base64ToBinary(ciphertextBase64);
    const saltLength = 32; // HKDF_CONFIG.SALT_LENGTH
    const ivLength = 12; // AES-GCM IV

    // For managed credentials, the encrypted data format is:
    // salt(32) | iv(12) | ciphertext+tag
    const iv = combined.slice(saltLength, saltLength + ivLength);
    const ciphertextWithTag = combined.slice(saltLength + ivLength);

    const key = base64ToBinary(keyBase64);
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      toArrayBuffer(key),
      "AES-GCM",
      false,
      ["decrypt"],
    );

    const decryptedBuffer = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: toArrayBuffer(iv),
        tagLength: 128,
      },
      cryptoKey,
      toArrayBuffer(ciphertextWithTag),
    );

    return new TextDecoder().decode(decryptedBuffer);
  } catch {
    return null;
  }
}

/** Capability request payload for Plus API */
export interface CapabilityRequest {
  userId: string;
  resourceId: string;
  operation: "AUTOFILL" | "VIEW" | "TOTP";
  secretRef: string;
  deviceId?: string;
  assurance: 1 | 2 | 3;
  context?: {
    country?: string;
    ip?: string;
    userAgent?: string;
    timestamp?: number;
  };
}

/** Capability response from Plus */
export interface CapabilityResponse {
  success: boolean;
  capabilityToken?: {
    payload: any;
    signature: string;
    protectedHeader: string;
  };
  error?: string;
  challengeRequired?: boolean;
  challengeId?: string;
  challengeExpiresAt?: number;
}

/** Managed Release response from Core */
export interface ManagedReleaseResponse {
  success: boolean;
  releaseShare?: string; // base64 encoded ReleaseShare
  error?: string;
}

/**
 * Request capability from Plus for managed credential access
 */
export async function requestManagedCapability(
  request: CapabilityRequest,
): Promise<CapabilityResponse> {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(
      {
        type: "REQUEST_MANAGED_CAPABILITY",
        payload: request,
      },
      (response) => {
        if (chrome.runtime.lastError) {
          resolve({ success: false, error: chrome.runtime.lastError.message });
          return;
        }
        // The worker replies with the service-worker envelope
        // `{ ok, data, error }`; the capability itself is in `data`.
        if (!response?.ok) {
          resolve({ success: false, error: response?.error });
          return;
        }
        const data = (response.data ?? {}) as CapabilityResponse;
        resolve({ ...data, success: Boolean(data.capabilityToken) });
      },
    );
  });
}

/**
 * Request ReleaseShare from Core using capability
 *
 * The payload is exactly what `POST /api/v1/vaults/{vaultId}/managed-release`
 * takes: the capability and the credential it is for. No public key travels
 * with it — Core has pinned Plus's key itself since WU-1, and a key the caller
 * supplies would be a key the caller chooses.
 */
export async function requestReleaseShare(
  capabilityToken: CapabilityResponse["capabilityToken"],
  credentialId: string,
): Promise<ManagedReleaseResponse> {
  return new Promise((resolve) => {
    chrome.runtime.sendMessage(
      {
        type: "REQUEST_RELEASE_SHARE",
        payload: {
          capabilityToken,
          credentialId,
        },
      },
      (response) => {
        if (chrome.runtime.lastError) {
          resolve({ success: false, error: chrome.runtime.lastError.message });
        } else if (!response?.ok) {
          resolve({ success: false, error: response?.error });
        } else if (!response.data?.releaseShare) {
          // An OK response carrying no share is not a success. Reporting
          // success:true with an undefined share hands the caller a "you have
          // the key" answer with no key behind it, and this envelope is the
          // root of trust for decrypting a managed credential.
          resolve({ success: false, error: "Release response contained no share" });
        } else {
          resolve({ success: true, releaseShare: response.data.releaseShare });
        }
      },
    );
  });
}

/**
 * Decrypt a managed credential
 *
 * @param credential - The credential object with mode="managed"
 * @param vekBase64 - Base64 encoded VEK from session
 * @returns Decrypted password string or null on failure
 */
export async function decryptManagedCredential(
  credential: {
    encryptedPassword: string;
    salt: string;
    version: number;
    releaseShareRef: string;
    id: string;
  },
  vekBase64: string,
): Promise<string | null> {
  try {
    // 1. Request capability from Plus
    const capabilityRequest: CapabilityRequest = {
      userId: "", // Will be filled by background from session
      resourceId: credential.releaseShareRef, // Use releaseShareRef as resource ID
      operation: "AUTOFILL",
      secretRef: credential.releaseShareRef,
      assurance: 2,
      context: {
        userAgent: navigator.userAgent,
        timestamp: Date.now(),
      },
    };

    const capabilityResponse = await requestManagedCapability(capabilityRequest);
    if (!capabilityResponse.success || !capabilityResponse.capabilityToken) {
      console.error("Failed to get capability:", capabilityResponse.error);
      return null;
    }

    // 2. Request the ReleaseShare from Core. Core pins Plus's verification key
    //    itself, so no key is fetched here to travel with the request.
    const releaseResponse = await requestReleaseShare(
      capabilityResponse.capabilityToken,
      credential.id,
    );

    if (!releaseResponse.success || !releaseResponse.releaseShare) {
      console.error("Failed to get ReleaseShare:", releaseResponse.error);
      return null;
    }

    // 4. Derive EntryKey = HKDF(VEK || ReleaseShare, salt, context)
    const vek = base64ToBinary(vekBase64);
    const releaseShare = base64ToBinary(releaseResponse.releaseShare);
    const salt = base64ToBinary(credential.salt);

    const derived = await deriveManagedEntryKey(
      vek,
      releaseShare,
      salt,
      credential.id,
      credential.version,
    );

    // 5. Decrypt the credential
    const decrypted = await decryptAESGCM(
      credential.encryptedPassword,
      derived.keyBase64,
    );

    // Secure cleanup
    secureZero(vek);
    secureZero(releaseShare);
    secureZero(salt);

    return decrypted;
  } catch (err) {
    console.error("Managed decrypt failed:", err);
    return null;
  }
}

/**
 * Decrypt a personal credential (for comparison/completeness)
 */
export async function decryptPersonalCredential(
  credential: {
    encryptedPassword: string;
    salt: string;
    version: number;
    id: string;
  },
  vekBase64: string,
): Promise<string | null> {
  try {
    const { derivePersonalEntryKey } = await import(
      "../../infrastructure/crypto/hkdf-derivation"
    );

    const vek = base64ToBinary(vekBase64);
    const salt = base64ToBinary(credential.salt);

    const derived = await derivePersonalEntryKey(
      vek,
      salt,
      credential.id,
      credential.version,
    );

    const decrypted = await decryptAESGCM(
      credential.encryptedPassword,
      derived.keyBase64,
    );

    secureZero(vek);
    secureZero(salt);

    return decrypted;
  } catch (err) {
    console.error("Personal decrypt failed:", err);
    return null;
  }
}

/**
 * Unified decrypt function that handles both personal and managed credentials
 */
export interface CredentialLike {
  id: string;
  encryptedPassword: string;
  salt: string;
  version: number;
  mode: "personal" | "managed";
  releaseShareRef?: string;
}

export async function decryptCredential(
  credential: CredentialLike,
  vekBase64: string,
): Promise<string | null> {
  if (credential.mode === "managed" && credential.releaseShareRef) {
    return decryptManagedCredential(
      {
        ...credential,
        releaseShareRef: credential.releaseShareRef,
      },
      vekBase64,
    );
  } else {
    return decryptPersonalCredential(credential, vekBase64);
  }
}