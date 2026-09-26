/**
 * CyberVault Background Service Worker — Auditor
 *
 * Chrome Extension Manifest V3 service worker that acts as the central
 * message router and background orchestrator. Handles domain validation
 * via the PipelineOrchestrator, trust status queries via the
 * ChromeStorageTrustStore, anomaly reporting, and vault unlock requests.
 *
 * @module background/auditor
 */

import { PipelineOrchestrator } from "../domain/services/aitm/pipeline-orchestrator";
import { ExactMatchStep } from "../domain/services/aitm/steps/exact-match-step";
import { ConfusableDetectionStep } from "../domain/services/aitm/steps/confusable-detection-step";
import { TyposquattingStep } from "../domain/services/aitm/steps/typosquatting-step";
import { ChromeStorageTrustStore } from "../infrastructure/repositories/chrome-storage-trust-store";
import {
  listCandidatesForOrigin,
  releaseCredential,
  type ReleaseDeps,
  type EncryptedCredentialRecord,
} from "./credential-release";
import type { OpaqueIndex } from "../domain/services/autofill/domain-index";
import type { StepUpBinding } from "../domain/services/autofill/step-up-flow";
import {
  MESSAGE_TYPES,
  type BackgroundMessage,
  type BackgroundResponse,
  type ValidateDomainMessage,
  type GetTrustStatusMessage,
  type ReportAnomalyMessage,
  type UnlockVaultMessage,
  type LockVaultMessage,
  type CheckVaultStatusMessage,
  type EncryptDataMessage,
  type DecryptDataMessage,
  type RequestManagedCapabilityMessage,
  type RequestReleaseShareMessage,
  type GetPlusPublicKeyMessage,
  type ListCredentialsForOriginMessage,
  type ReleaseCredentialMessage,
  type StartStepUpMessage,
  type SubmitStepUpPinMessage,
} from "./message-types";
import { metrics } from "../shared/metrics";
import { logger } from "../shared/logger";
import type { TrustEntry } from "../domain/repositories";

/* ------------------------------------------------------------------ */
/*  Message contract                                                   */
/*                                                                     */
/*  Re-exported from ./message-types so the content scripts and the    */
/*  worker cannot drift apart. That module is side-effect free, which  */
/*  is why it can be imported by tests without standing up a listener.  */
/* ------------------------------------------------------------------ */

export * from "./message-types";

/* ------------------------------------------------------------------ */
/*  Singleton instances                                                */
/* ------------------------------------------------------------------ */

const trustStore = new ChromeStorageTrustStore();

function createPipeline(): PipelineOrchestrator {
  const pipeline = new PipelineOrchestrator();
  pipeline.addStep(new ExactMatchStep());
  pipeline.addStep(new ConfusableDetectionStep());
  pipeline.addStep(new TyposquattingStep());
  return pipeline;
}

/* ------------------------------------------------------------------ */
/*  Message Handlers                                                   */
/* ------------------------------------------------------------------ */

async function handleValidateDomain(
  msg: ValidateDomainMessage,
): Promise<BackgroundResponse> {
  try {
    const pipeline = createPipeline();
    const result = await pipeline.validate(msg.hostname, msg.expectedDomain);

    // Métrica de detección AiTM con el nivel de riesgo resultante
    metrics.counter(
      "cybervault_aitm_detections_total",
      "Total AiTM detections",
      { risk_level: result.overallRisk },
    );

    // Persist trust assessment so future lookups are fast
    const trustLevel: TrustEntry["trustLevel"] =
      result.overallRisk === "high"
        ? "suspicious"
        : "trusted";

    await trustStore.save({
      domain: msg.hostname,
      trustLevel,
      firstSeen: Date.now(),
      lastSeen: Date.now(),
      visitCount: 1,
    });

    // Store last validation result in session for popup/options access
    await chrome.storage.local.set({
      [`cybervault_last_validation_${msg.hostname}`]: {
        result,
        timestamp: Date.now(),
      },
    });

    return { ok: true, data: result };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, error: message };
  }
}

async function handleGetTrustStatus(
  msg: GetTrustStatusMessage,
): Promise<BackgroundResponse<TrustEntry | null>> {
  try {
    const entry = await trustStore.findByDomain(msg.domain);
    return { ok: true, data: entry };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, error: message };
  }
}

async function handleReportAnomaly(
  msg: ReportAnomalyMessage,
): Promise<BackgroundResponse> {
  try {
    // Persist the anomaly report to chrome.storage.local
    const key = "cybervault_anomaly_log";
    const stored = await chrome.storage.local.get(key);
    const log: Array<{
      domain: string;
      anomalyType: string;
      severity: string;
      details: string;
      timestamp: number;
    }> = Array.isArray(stored[key]) ? stored[key] : [];

    log.push({
      domain: msg.domain,
      anomalyType: msg.anomalyType,
      severity: msg.severity,
      details: msg.details,
      timestamp: Date.now(),
    });

    // Cap log at 500 entries to avoid storage bloat
    if (log.length > 500) {
      log.splice(0, log.length - 500);
    }

    await chrome.storage.local.set({ [key]: log });

    // If severity is high, mark domain as suspicious in trust store
    if (msg.severity === "high") {
      await trustStore.save({
        domain: msg.domain,
        trustLevel: "suspicious",
        firstSeen: Date.now(),
        lastSeen: Date.now(),
        visitCount: 1,
      });
    }

    return { ok: true };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, error: message };
  }
}

async function handleUnlockVault(
  msg: UnlockVaultMessage,
): Promise<BackgroundResponse> {
  try {
    // Store unlock state in session storage (cleared when browser closes)
    await chrome.storage.session.set({
      cybervault_unlock_state: {
        vaultId: msg.vaultId,
        unlockedAt: Date.now(),
        expiresAt: Date.now() + 30 * 60 * 1000, // 30 min session
      },
    });

    return { ok: true, data: { unlocked: true } };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, error: message };
  }
}

async function handleLockVault(
  _msg: LockVaultMessage,
): Promise<BackgroundResponse> {
  try {
    // The VEK MUST be cleared here, not just the derived session key.
    //
    // The release path reads `cybervault_vek` to derive the domain-index key and
    // the per-entry keys. An earlier version of this handler removed only the
    // session key and unlock timestamps, which left the VEK resident: the vault
    // appeared locked in the UI while every credential remained releasable from
    // the service worker. Locking has to remove the key material that
    // authorization actually depends on, or "locked" is a lie.
    await chrome.storage.session.remove([
      STORE_KEYS.SESSION_VEK,
      "cybervault_session_key",
      "cybervault_unlock_time",
      "cybervault_unlock_state",
    ]);

    // Confirm the VEK is actually gone rather than assuming the removal worked.
    const remaining = await chrome.storage.session.get([STORE_KEYS.SESSION_VEK]);
    const stillPresent = typeof remaining[STORE_KEYS.SESSION_VEK] === "string";

    if (stillPresent) {
      logger.error(
        "Lock did not clear the session VEK; vault may remain releasable",
        "Auditor",
      );
      return { ok: false, error: "lock failed to clear session VEK" };
    }

    return { ok: true, data: { locked: true, vekCleared: true } };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, error: message };
  }
}

async function handleCheckVaultStatus(
  _msg: CheckVaultStatusMessage,
): Promise<BackgroundResponse> {
  try {
    const session = await chrome.storage.session.get([
      "cybervault_session_key",
      "cybervault_unlock_time",
    ]);
    const sessionKey = session["cybervault_session_key"] as string | undefined;
    const unlockTime = session["cybervault_unlock_time"] as number | undefined;
    const isValid = !!(sessionKey && unlockTime && Date.now() - unlockTime < 30 * 60 * 1000);
    return { ok: true, data: { unlocked: isValid } };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, error: message };
  }
}

async function handleEncryptData(
  msg: EncryptDataMessage,
): Promise<BackgroundResponse> {
  try {
    const session = await chrome.storage.session.get(["cybervault_session_key"]);
    const sessionKey = session["cybervault_session_key"] as string | undefined;
    if (!sessionKey) {
      return { ok: false, error: "Vault not unlocked" };
    }
    // Use the encryption service with session key
    const { encryptWithKey } = await import("../infrastructure/crypto/EncryptionService");
    const encrypted = await encryptWithKey(msg.payload, sessionKey);
    return { ok: true, data: encrypted };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, error: message };
  }
}

async function handleDecryptData(
  msg: DecryptDataMessage,
): Promise<BackgroundResponse> {
  try {
    const session = await chrome.storage.session.get(["cybervault_session_key"]);
    const sessionKey = session["cybervault_session_key"] as string | undefined;
    if (!sessionKey) {
      return { ok: false, error: "Vault not unlocked" };
    }
    // Use the encryption service with session key
    const { decryptWithKey } = await import("../infrastructure/crypto/EncryptionService");
    const decrypted = await decryptWithKey(msg.payload, sessionKey);
    return { ok: true, data: decrypted };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, error: message };
  }
}

async function handleRequestManagedCapability(
  msg: RequestManagedCapabilityMessage,
): Promise<BackgroundResponse> {
  try {
    // Get auth token and user ID from storage
    const authData = await chrome.storage.local.get([
      "cybervault_token",
      "cybervault_userId",
    ]);
    const authToken = authData["cybervault_token"];
    const userId = authData["cybervault_userId"];

    if (!authToken || !userId) {
      return { ok: false, error: "Not authenticated" };
    }

    // Get Plus config from storage or use defaults
    const plusConfig = await chrome.storage.local.get([
      "plus_base_url",
      "plus_service_secret",
    ]);
    const baseUrl = (plusConfig["plus_base_url"] as string) || "http://localhost:3011";
    const serviceSecret = (plusConfig["plus_service_secret"] as string) || "";

    // Build capability request
    const capabilityRequest = {
      userId,
      resourceId: msg.payload.resourceId,
      operation: msg.payload.operation,
      secretRef: msg.payload.secretRef,
      deviceId: msg.payload.deviceId,
      assurance: msg.payload.assurance,
      context: msg.payload.context,
    };

    // Call Plus API for capability
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);

    try {
      const response = await fetch(`${baseUrl}/api/v1/capabilities/request`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Core-Service": "cybervault-core",
          "X-Service-Secret": serviceSecret,
          "Authorization": `Bearer ${authToken}`,
        },
        body: JSON.stringify(capabilityRequest),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const errorText = await response.text();
        return { ok: false, error: `Plus API ${response.status}: ${errorText}` };
      }

      const data = await response.json();
      return { ok: true, data };
    } catch (fetchErr) {
      clearTimeout(timeoutId);
      const message = fetchErr instanceof Error ? fetchErr.message : String(fetchErr);
      if (message.includes("aborted") || message.includes("timeout")) {
        return { ok: false, error: "Plus API timeout" };
      }
      return { ok: false, error: `Plus API error: ${message}` };
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, error: message };
  }
}

async function handleRequestReleaseShare(
  msg: RequestReleaseShareMessage,
): Promise<BackgroundResponse> {
  try {
    // Get auth token
    const authData = await chrome.storage.local.get(["cybervault_token"]);
    const authToken = authData["cybervault_token"];

    if (!authToken) {
      return { ok: false, error: "Not authenticated" };
    }

    // Get Core API base URL
    const coreConfig = await chrome.storage.local.get(["core_base_url"]);
    const baseUrl = coreConfig["core_base_url"] || "http://localhost:3010";

    // Call Core API for managed release
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);

    try {
      const response = await fetch(`${baseUrl}/api/v1/managed/release`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${authToken}`,
        },
        body: JSON.stringify({
          capabilityToken: msg.payload.capabilityToken,
          plusPublicKey: msg.payload.plusPublicKey,
        }),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const errorText = await response.text();
        return { ok: false, error: `Core API ${response.status}: ${errorText}` };
      }

      const data = await response.json();
      return { ok: true, data };
    } catch (fetchErr) {
      clearTimeout(timeoutId);
      const message = fetchErr instanceof Error ? fetchErr.message : String(fetchErr);
      if (message.includes("aborted") || message.includes("timeout")) {
        return { ok: false, error: "Core API timeout" };
      }
      return { ok: false, error: `Core API error: ${message}` };
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, error: message };
  }
}

async function handleGetPlusPublicKey(
  _msg: GetPlusPublicKeyMessage,
): Promise<BackgroundResponse> {
  try {
    const plusConfig = await chrome.storage.local.get(["plus_base_url"]);
    const baseUrl = plusConfig["plus_base_url"] || "http://localhost:3011";

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);

    try {
      const response = await fetch(`${baseUrl}/api/v1/crypto/public-key`, {
        method: "GET",
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        const errorText = await response.text();
        return { ok: false, error: `Plus API ${response.status}: ${errorText}` };
      }

      const data = await response.json();
      return { ok: true, data };
    } catch (fetchErr) {
      clearTimeout(timeoutId);
      const message = fetchErr instanceof Error ? fetchErr.message : String(fetchErr);
      return { ok: false, error: `Plus public key error: ${message}` };
    }
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, error: message };
  }
}

/* ------------------------------------------------------------------ */
/*  Credential release adapters                                        */
/* ------------------------------------------------------------------ */

/**
 * Storage keys owned by the credential store.
 *
 * Both hold ENCRYPTED material only. The index holds opaque tokens and internal
 * ids; the record store holds ciphertext, salts and non-secret metadata. Neither
 * contains an origin, a username, a password or a TOTP seed in the clear.
 */
const STORE_KEYS = {
  INDEX: "cybervault_cred_index",
  RECORDS: "cybervault_cred_records",
  /** Session-scoped VEK, written by master-key-manager on unlock. */
  SESSION_VEK: "cybervault_vek",
} as const;

/**
 * Read the session VEK.
 *
 * Absent or unparseable means "locked", never "empty VEK" — a zero-filled VEK
 * would derive predictable keys, so this fails closed instead.
 */
async function readSessionVek(): Promise<Uint8Array | null> {
  try {
    const stored = await chrome.storage.session.get([STORE_KEYS.SESSION_VEK]);
    const raw = stored[STORE_KEYS.SESSION_VEK];
    if (typeof raw !== "string" || raw === "") return null;

    const binary = atob(raw);
    if (binary.length !== 32) return null;

    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  } catch {
    return null;
  }
}

function buildReleaseDeps(): ReleaseDeps {
  return {
    getVek: readSessionVek,

    getIndex: async () => {
      const stored = await chrome.storage.local.get([STORE_KEYS.INDEX]);
      const raw = stored[STORE_KEYS.INDEX] as { version?: number; byToken?: unknown } | undefined;
      // A malformed index is treated as empty, so lookups fail closed instead of
      // throwing and being mistaken for "allow".
      if (!raw || raw.version !== 1 || typeof raw.byToken !== "object" || raw.byToken === null) {
        return { version: 1, byToken: {} };
      }
      return raw as OpaqueIndex;
    },

    getRecord: async (credentialId) => {
      const stored = await chrome.storage.local.get([STORE_KEYS.RECORDS]);
      const all = stored[STORE_KEYS.RECORDS] as Record<string, EncryptedCredentialRecord> | undefined;
      if (!all || typeof all !== "object") return null;
      const record = all[credentialId];
      return record ?? null;
    },

    requestCapability: async ({ credentialId, secretRef, operation }) => {
      // Delegate to the existing Plus/Core round trip. The service worker
      // cannot message itself, so the HTTP calls are inlined here rather than
      // reusing the message handlers.
      const auth = await chrome.storage.local.get([
        "cybervault_token",
        "cybervault_userId",
      ]);
      const token = auth["cybervault_token"] as string | undefined;
      const userId = auth["cybervault_userId"] as string | undefined;
      if (!token || !userId) {
        return { ok: false, detail: "not authenticated" };
      }

      const config = await chrome.storage.local.get([
        "plus_base_url",
        "plus_service_secret",
      ]);
      const plusBase = (config["plus_base_url"] as string) || "http://localhost:3011";
      const serviceSecret = (config["plus_service_secret"] as string) || "";
      const coreBase = "http://localhost:3010";

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 10_000);

      try {
        const capRes = await fetch(`${plusBase}/api/v1/capabilities/request`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Core-Service": "cybervault-core",
            "X-Service-Secret": serviceSecret,
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({
            userId,
            resourceId: secretRef,
            operation,
            secretRef,
            assurance: 2,
            context: { userAgent: "cybervault-extension", timestamp: Date.now() },
          }),
          signal: controller.signal,
        });

        if (!capRes.ok) {
          return { ok: false, detail: `capability request failed (${capRes.status})` };
        }
        const cap = (await capRes.json()) as {
          success?: boolean;
          challengeRequired?: boolean;
          error?: string;
        };
        if (cap.challengeRequired) {
          return { ok: false, challengeRequired: true };
        }
        if (cap.success === false) {
          return { ok: false, detail: cap.error ?? "capability denied" };
        }

        const pubRes = await fetch(`${plusBase}/api/v1/crypto/public-key`, {
          method: "GET",
          signal: controller.signal,
        });
        if (!pubRes.ok) {
          return { ok: false, detail: `public key unavailable (${pubRes.status})` };
        }
        const pub = (await pubRes.json()) as { publicKey?: string };
        if (!pub.publicKey) {
          return { ok: false, detail: "public key missing" };
        }

        const relRes = await fetch(`${coreBase}/api/v1/managed/release`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
          },
          body: JSON.stringify({
            credentialId,
            capabilityToken: cap,
            plusPublicKey: pub.publicKey,
          }),
          signal: controller.signal,
        });

        if (!relRes.ok) {
          return { ok: false, detail: `managed release failed (${relRes.status})` };
        }
        const rel = (await relRes.json()) as { success?: boolean; releaseShare?: string; error?: string };
        if (rel.success === false || !rel.releaseShare) {
          return { ok: false, detail: rel.error ?? "release share denied" };
        }

        return { ok: true, releaseShare: rel.releaseShare };
      } catch (err) {
        return {
          ok: false,
          detail: err instanceof Error ? err.message : "capability request failed",
        };
      } finally {
        clearTimeout(timer);
      }
    },
  };
}

async function handleListCredentialsForOrigin(
  msg: ListCredentialsForOriginMessage,
): Promise<BackgroundResponse> {
  try {
    const candidates = await listCandidatesForOrigin(msg.origin, buildReleaseDeps());
    return { ok: true, data: candidates };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, error: message };
  }
}

async function handleReleaseCredential(
  msg: ReleaseCredentialMessage,
): Promise<BackgroundResponse> {
  try {
    const outcome = await releaseCredential(
      {
        credentialId: msg.credentialId,
        origin: msg.origin,
        operation: msg.operation,
        documentOrigin: msg.documentOrigin,
        topLevelOrigin: msg.topLevelOrigin,
        isFramed: msg.isFramed,
      },
      buildReleaseDeps(),
    );

    if (outcome.ok) return { ok: true, data: outcome.credential };
    // Denials are a normal, expected outcome. The page receives the code so it
    // can distinguish "locked" from "blocked by policy" from "needs step-up",
    // but never a partial credential.
    return { ok: false, error: outcome.code, data: { code: outcome.code } };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, error: message };
  }
}

/* ------------------------------------------------------------------ */
/*  Step-up (third factor)                                             */
/* ------------------------------------------------------------------ */

/**
 * In-memory challenge registry for the current browser session.
 *
 * Deliberately in memory, not chrome.storage.session: a challenge is a live
 * authorization in progress, and writing it to storage would give any code with
 * storage access a handle on an in-flight third factor. A service-worker
 * restart drops the registry, which forces a new challenge — the safe direction
 * to fail.
 */
const stepUpChallenges = new Map<string, { binding: StepUpBinding; expiresAt: number }>();

const STEP_UP_PLUS_URL = "http://localhost:3011";

async function handleStartStepUp(msg: StartStepUpMessage): Promise<BackgroundResponse> {
  try {
    const binding: StepUpBinding = {
      credentialId: msg.binding?.credentialId ?? "",
      origin: msg.binding?.origin ?? "",
      operation: msg.binding?.operation ?? "AUTOFILL",
    };
    if (!binding.credentialId || !binding.origin) {
      return { ok: false, error: "BINDING_MISSING" };
    }

    const auth = await chrome.storage.local.get([
      "cybervault_token",
      "cybervault_userId",
    ]);
    const token = auth["cybervault_token"] as string | undefined;
    const userId = auth["cybervault_userId"] as string | undefined;
    if (!token || !userId) return { ok: false, error: "not authenticated" };

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10_000);
    try {
      const res = await fetch(`${STEP_UP_PLUS_URL}/api/v1/challenges/trigger`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Core-Service": "cybervault-core",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          userId,
          // Plus binds the challenge to resourceId/operation/secretRef. The
          // credential id doubles as the resource reference for the step-up.
          resourceId: binding.credentialId,
          operation: binding.operation,
          secretRef: binding.credentialId,
          context: { userAgent: "cybervault-extension", timestamp: Date.now() },
        }),
        signal: controller.signal,
      });

      if (!res.ok) {
        const text = await res.text();
        return { ok: false, error: `challenge trigger failed (${res.status})`, data: { text } };
      }
      const body = (await res.json()) as {
        success?: boolean;
        challengeId?: string;
        expiresAt?: number;
        error?: string;
      };
      if (body.success === false || !body.challengeId) {
        return { ok: false, error: body.error ?? "challenge refused" };
      }

      const expiresAt = body.expiresAt ?? Date.now() + 120_000;
      stepUpChallenges.set(body.challengeId, { binding, expiresAt });

      return {
        ok: true,
        data: {
          challengeId: body.challengeId,
          expiresAt,
          attemptsRemaining: 3,
          binding,
        },
      };
    } finally {
      clearTimeout(timer);
    }
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

async function handleSubmitStepUpPin(msg: SubmitStepUpPinMessage): Promise<BackgroundResponse> {
  try {
    const entry = stepUpChallenges.get(msg.challengeId);
    if (!entry) {
      // Unknown challenge: refuse without contacting Plus, so the response time
      // does not distinguish "never existed" from "already consumed".
      return { ok: false, error: "the PIN was not accepted" };
    }
    if (Date.now() >= entry.expiresAt) {
      stepUpChallenges.delete(msg.challengeId);
      return { ok: false, error: "the PIN was not accepted" };
    }

    const auth = await chrome.storage.local.get(["cybervault_token"]);
    const token = auth["cybervault_token"] as string | undefined;
    if (!token) return { ok: false, error: "not authenticated" };

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10_000);
    try {
      const res = await fetch(`${STEP_UP_PLUS_URL}/api/v1/challenges/verify`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Core-Service": "cybervault-core",
          Authorization: `Bearer ${token}`,
        },
        // msg.pin is forwarded and never stored, logged or attached to the
        // challenge registry entry above.
        body: JSON.stringify({ challengeId: msg.challengeId, pin: msg.pin }),
        signal: controller.signal,
      });

      if (!res.ok) {
        return { ok: false, error: "the PIN was not accepted" };
      }
      const body = (await res.json()) as {
        success?: boolean;
        attemptsRemaining?: number;
      };

      if (body.success) {
        // One-shot: a completed challenge cannot be replayed.
        stepUpChallenges.delete(msg.challengeId);
        return { ok: true, data: { verified: true } };
      }

      const remaining = body.attemptsRemaining ?? 0;
      if (remaining <= 0) stepUpChallenges.delete(msg.challengeId);
      return { ok: false, error: "the PIN was not accepted", data: { attemptsRemaining: remaining } };
    } finally {
      clearTimeout(timer);
    }
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

/* ------------------------------------------------------------------ */
/*  Message Router                                                     */
/* ------------------------------------------------------------------ */

chrome.runtime.onMessage.addListener(
  (
    message: BackgroundMessage,
    _sender: chrome.runtime.MessageSender,
    sendResponse: (response: BackgroundResponse) => void,
  ): boolean => {
    let handlerPromise: Promise<BackgroundResponse>;

    switch (message.type) {
      case MESSAGE_TYPES.VALIDATE_DOMAIN:
        handlerPromise = handleValidateDomain(message);
        break;

      case MESSAGE_TYPES.GET_TRUST_STATUS:
        handlerPromise = handleGetTrustStatus(message);
        break;

      case MESSAGE_TYPES.REPORT_ANOMALY:
        handlerPromise = handleReportAnomaly(message);
        break;

      case MESSAGE_TYPES.UNLOCK_VAULT:
        handlerPromise = handleUnlockVault(message);
        break;

      case MESSAGE_TYPES.LOCK_VAULT:
        handlerPromise = handleLockVault(message);
        break;

      case MESSAGE_TYPES.CHECK_VAULT_STATUS:
        handlerPromise = handleCheckVaultStatus(message);
        break;

      case MESSAGE_TYPES.ENCRYPT_DATA:
        handlerPromise = handleEncryptData(message);
        break;

      case MESSAGE_TYPES.DECRYPT_DATA:
        handlerPromise = handleDecryptData(message);
        break;

      case MESSAGE_TYPES.REQUEST_MANAGED_CAPABILITY:
        handlerPromise = handleRequestManagedCapability(message);
        break;

      case MESSAGE_TYPES.REQUEST_RELEASE_SHARE:
        handlerPromise = handleRequestReleaseShare(message);
        break;

      case MESSAGE_TYPES.GET_PLUS_PUBLIC_KEY:
        handlerPromise = handleGetPlusPublicKey(message);
        break;

      case MESSAGE_TYPES.LIST_CREDENTIALS_FOR_ORIGIN:
        handlerPromise = handleListCredentialsForOrigin(message);
        break;

      case MESSAGE_TYPES.RELEASE_CREDENTIAL:
        handlerPromise = handleReleaseCredential(message);
        break;

      case MESSAGE_TYPES.START_STEP_UP:
        handlerPromise = handleStartStepUp(message);
        break;

      case MESSAGE_TYPES.SUBMIT_STEP_UP_PIN:
        handlerPromise = handleSubmitStepUpPin(message);
        break;

      default:
        sendResponse({
          ok: false,
          error: `Unknown message type: ${(message as { type: string }).type}`,
        });
        return false;
    }

    handlerPromise
      .then((response) => sendResponse(response))
      .catch((err) => {
        const errorMsg = err instanceof Error ? err.message : String(err);
        sendResponse({ ok: false, error: errorMsg });
      });

    // Return true to indicate we will send sendResponse asynchronously
    return true;
  },
);

/* ------------------------------------------------------------------ */
/*  Extension Lifecycle                                                */
/* ------------------------------------------------------------------ */

chrome.runtime.onInstalled.addListener(
  async (details: chrome.runtime.InstalledDetails) => {
    const { reason } = details;

    if (reason === "install") {
      // First install — seed default settings
      await chrome.storage.local.set({
        cybervault_settings: {
          autoValidate: true,
          blockHighRisk: true,
          showNotifications: true,
          sessionTimeoutMinutes: 30,
        },
        cybervault_anomaly_log: [],
      });

      logger.info("Extension installed — default settings seeded", "Auditor");
    }

    if (reason === "update") {
      // Migration logic — check for stale trust store entries
      const trustEntries = await trustStore.list();
      const expiredCount = await trustStore.removeExpired(
        90 * 24 * 60 * 60 * 1000, // 90 days
      );

      if (expiredCount > 0) {
        logger.info(
          `Cleaned ${expiredCount} expired trust entries (${trustEntries.length} remaining)`,
          "Auditor",
        );
      }
    }
  },
);
