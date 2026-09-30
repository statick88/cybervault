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
import { authorCredential } from "../domain/services/autofill/credential-authoring";
import {
  canRetryRelease,
  type StepUpBinding,
  type StepUpSession,
} from "../domain/services/autofill/step-up-flow";
import { initializeVault, unlockVault } from "../infrastructure/crypto/master-key-manager";
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
  type ApproveStepUpMessage,
  type AuthorCredentialMessage,
  type GetPendingStepUpMessage,
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
    const passphrase = msg.passphrase;
    if (typeof passphrase !== "string" || passphrase === "") {
      return { ok: false, error: "a passphrase is required" };
    }

    // Verify first. Only a vault that does not exist yet is created here:
    // nothing else in `src/` ever calls `initializeVault`, so without this the
    // very first unlock would fail with "not initialized" and no extension
    // session could ever start. A wrong passphrase on an existing vault never
    // reaches this branch, so it cannot re-initialize over live data.
    let result = await unlockVault(passphrase);
    if (!result.success && result.code === "VAULT_NOT_INITIALIZED") {
      const created = await initializeVault(passphrase);
      if (!created.success) {
        return {
          ok: false,
          error: created.error ?? "vault initialization failed",
          data: { success: false },
        };
      }
      result = await unlockVault(passphrase);
    }
    if (!result.success) {
      return {
        ok: false,
        error: result.error ?? "unlock failed",
        data: { success: false },
      };
    }

    // Persist the session VEK. This is the writer the release path was missing:
    // `readSessionVek` returns null until `cybervault_vek` exists, so
    // `listCandidatesForOrigin` returned [] and `releaseCredential` refused
    // with VAULT_LOCKED for every credential.
    //
    // The extension derives exactly one 256-bit secret at unlock (HKDF label
    // `cybervault|session_key|v2`, see key-derivation-service) and that value
    // IS this vault's VEK — the header of master-key-manager.ts documents the
    // two names for the same session-scoped key. `cybervault_vek` is the
    // authorization-scoped handle the release path reads; both entries live in
    // session storage and are removed together by `handleLockVault`.
    const session = await chrome.storage.session.get(["cybervault_session_key"]);
    const sessionKey = session["cybervault_session_key"] as string | undefined;
    if (!sessionKey) {
      return { ok: false, error: "unlock produced no session key" };
    }

    const now = Date.now();
    await chrome.storage.session.set({
      [STORE_KEYS.SESSION_VEK]: sessionKey,
      cybervault_unlock_state: {
        vaultId: msg.vaultId,
        unlockedAt: now,
        expiresAt: now + SESSION_WINDOW_MS, // 30 min session
      },
    });

    return {
      ok: true,
      data: { success: true, unlocked: true, vaultId: msg.vaultId },
    };
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
      // The gate goes with the session that recorded it: a completion is an
      // authorisation to spend key material, and this code already promises
      // (below) that none of it outlives the lock.
      STEP_UP_GATE_KEY,
    ]);

    // Confirm the VEK is actually gone rather than assuming the removal worked.
    const remaining = await chrome.storage.session.get([STORE_KEYS.SESSION_VEK, STEP_UP_GATE_KEY]);
    const stillPresent = typeof remaining[STORE_KEYS.SESSION_VEK] === "string";

    if (stillPresent) {
      logger.error(
        "Lock did not clear the session VEK; vault may remain releasable",
        "Auditor",
      );
      return { ok: false, error: "lock failed to clear session VEK" };
    }

    // Same verification for the gate: a removal that did not remove would
    // leave a step-up completion spendable by whoever unlocks next, which is
    // exactly what the line below refuses to promise.
    if (STEP_UP_GATE_KEY in remaining) {
      logger.error("Lock did not clear the step-up gate; a completion may survive the next unlock", "Auditor");
      return { ok: false, error: "lock failed to clear step-up gate" };
    }

    // Key material is gone, so every in-flight third factor with it: a
    // challenge or a completion recorded against a session that no longer
    // exists must not be spendable after the next unlock.
    stepUpChallenges.clear();
    challengedBindings.clear();
    completedStepUps.clear();

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
    const unlocked = await isSessionUnlocked();
    return { ok: true, data: { unlocked } };
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

/**
 * POST one managed release to Core.
 *
 * ONE implementation for both call sites (the message handler and the release
 * path's `requestCapability`), because two hand-written copies of a security
 * request is how they drift apart — and they had: both posted to
 * `/api/v1/managed/release`, which does not exist, and both sent a
 * `plusPublicKey` the route has not accepted since WU-1, while omitting the
 * `credentialId` it verifies.
 *
 * `vaultId` is read from the worker's own unlock state rather than taken from
 * the caller: the caller does not get to choose which vault to release from.
 */
async function fetchManagedRelease(args: {
  token: string;
  credentialId: string;
  capabilityToken: RequestReleaseShareMessage["payload"]["capabilityToken"];
  signal: AbortSignal;
}): Promise<
  | { readonly ok: true; readonly releaseShare: string }
  | {
      readonly ok: false;
      readonly kind: "unlocked" | "http" | "network" | "denied";
      readonly status?: number;
      readonly detail: string;
    }
> {
  const config = await chrome.storage.local.get(["core_base_url"]);
  const baseUrl = (config["core_base_url"] as string) || "http://localhost:3010";

  const session = await chrome.storage.session.get(["cybervault_unlock_state"]);
  const state = session["cybervault_unlock_state"] as { vaultId?: string } | undefined;
  const vaultId = state?.vaultId;
  if (typeof vaultId !== "string" || vaultId === "") {
    return { ok: false, kind: "unlocked", detail: "vault not unlocked" };
  }

  let response: Response;
  try {
    response = await fetch(
      `${baseUrl}/api/v1/vaults/${encodeURIComponent(vaultId)}/managed-release`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${args.token}`,
        },
        body: JSON.stringify({
          capabilityToken: args.capabilityToken,
          credentialId: args.credentialId,
        }),
        signal: args.signal,
      },
    );
  } catch (err) {
    return {
      ok: false,
      kind: "network",
      detail: err instanceof Error ? err.message : String(err),
    };
  }

  if (!response.ok) {
    const text = await response.text();
    return { ok: false, kind: "http", status: response.status, detail: text };
  }

  const body = (await response.json()) as {
    success?: boolean;
    releaseShare?: string;
    error?: string;
  };
  if (body.success === false || !body.releaseShare) {
    return { ok: false, kind: "denied", detail: body.error ?? "release share denied" };
  }
  return { ok: true, releaseShare: body.releaseShare };
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

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);

    try {
      const release = await fetchManagedRelease({
        token: authToken as string,
        credentialId: msg.payload.credentialId,
        capabilityToken: msg.payload.capabilityToken,
        signal: controller.signal,
      });
      if (!release.ok) {
        if (release.kind === "http") {
          return { ok: false, error: `Core API ${release.status}: ${release.detail}` };
        }
        if (release.kind === "network") {
          const message = release.detail;
          if (message.includes("aborted") || message.includes("timeout")) {
            return { ok: false, error: "Core API timeout" };
          }
          return { ok: false, error: `Core API error: ${message}` };
        }
        return { ok: false, error: release.detail };
      }

      return {
        ok: true,
        data: { success: true, releaseShare: release.releaseShare },
      };
    } finally {
      clearTimeout(timeoutId);
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
    const plusConfig = await chrome.storage.local.get([
      "plus_base_url",
      "plus_service_secret",
    ]);
    const baseUrl = plusConfig["plus_base_url"] || "http://localhost:3011";
    // D1: R1 put the signing-key route behind the secret too, and this call
    // sent nothing, so fetching Plus's public key has been failing with 401
    // since. Found by checking every call site rather than the two I expected.
    const serviceSecret = (plusConfig["plus_service_secret"] as string) || "";

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);

    try {
      const response = await fetch(`${baseUrl}/api/v1/crypto/public-key`, {
        method: "GET",
        headers: { "X-Service-Secret": serviceSecret },
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
  /** Session-scoped VEK, written by `handleUnlockVault` on a successful unlock. */
  SESSION_VEK: "cybervault_vek",
} as const;

/**
 * How long an unlock stays usable.
 *
 * One window for the whole worker. `unlock_state.expiresAt`, the status reply
 * and the VEK liveness gate all read this constant, so they cannot drift apart.
 *
 * NOTE (reported, not silently unified): `master-key-manager.ts` separately
 * keeps its own `SESSION_DURATION_MS` of 15 minutes, which governs
 * `isSessionValid()` and therefore `getSessionKey()`. Between minute 15 and 30
 * those two views disagree — the worker reports unlocked while the key manager
 * would report expired. The worker's own paths all go through the gate below,
 * so they are internally consistent; closing the 15-vs-30 gap is a separate
 * decision about which timeout the product actually wants.
 */
const SESSION_WINDOW_MS = 30 * 60 * 1000;

/**
 * Is the vault usable right now?
 *
 * Shared by the status reply and by `readSessionVek`, so "the popup says
 * unlocked" and "the release path may derive a key" can never disagree.
 */
async function isSessionUnlocked(): Promise<boolean> {
  try {
    const session = await chrome.storage.session.get([
      "cybervault_session_key",
      "cybervault_unlock_time",
      "cybervault_unlock_state",
    ]);
    const sessionKey = session["cybervault_session_key"] as string | undefined;
    const unlockTime = session["cybervault_unlock_time"] as number | undefined;
    const state = session["cybervault_unlock_state"] as
      | { expiresAt?: number }
      | undefined;
    if (!sessionKey || !unlockTime) return false;
    if (typeof state?.expiresAt === "number" && Date.now() >= state.expiresAt) {
      return false;
    }
    return Date.now() - unlockTime < SESSION_WINDOW_MS;
  } catch {
    // Fail closed: storage unavailable means "locked".
    return false;
  }
}

/**
 * Drop every piece of session key material the moment the window lapses.
 *
 * The release path is the only thing that reads the VEK, so expiry is enforced
 * where it is read rather than by a timer the service worker could be asleep
 * for. Leaving the material in place until someone asks would make "locked" a
 * statement about the UI rather than about the key.
 *
 * The step-up gate goes with it: it was recorded against THIS unlock session,
 * so a completion must not be spendable by whoever unlocks next — the same
 * promise `handleLockVault` makes, kept for the expiry path too. Forgetting an
 * "owed" entry here is safe because it is re-derived from Plus on the next
 * release rather than carried forward as still true.
 */
async function expireSessionKeyMaterial(): Promise<void> {
  challengedBindings.clear();
  completedStepUps.clear();
  await chrome.storage.session.remove([
    STORE_KEYS.SESSION_VEK,
    "cybervault_session_key",
    "cybervault_unlock_time",
    "cybervault_unlock_state",
    STEP_UP_GATE_KEY,
  ]);
}

/**
 * Read the session VEK.
 *
 * Absent or unparseable means "locked", never "empty VEK" — a zero-filled VEK
 * would derive predictable keys, so this fails closed instead.
 */
async function readSessionVek(): Promise<Uint8Array | null> {
  try {
    // Liveness first: a VEK left behind by a lapsed session must not be usable
    // just because nobody removed it. On expiry the material is dropped here,
    // so the refusal is "locked" rather than "cleared after the fact".
    if (!(await isSessionUnlocked())) {
      await expireSessionKeyMaterial();
      return null;
    }

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

/** The Ed25519 capability Plus issues, in the shape it returns it. */
interface PlusCapabilityToken {
  readonly payload: unknown;
  readonly signature: string;
  readonly protectedHeader: string;
}

/** Success shape of the Plus capability round trip. */
interface PlusMaterialSuccess {
  readonly ok: true;
  readonly capabilityToken: PlusCapabilityToken;
}

/**
 * Failure shapes: a plain detail, or a step-up challenge. Matches the
 * `ReleaseDeps['requestCapability']` contract so callers can pass them on.
 */
type PlusMaterialResult =
  | PlusMaterialSuccess
  | { readonly ok: false; readonly detail: string }
  | { readonly ok: false; readonly challengeRequired: true };

/**
 * Plus round trip for a managed release: ask for the capability.
 *
 * EXTRACTED VERBATIM from `buildReleaseDeps().requestCapability` — same
 * endpoint, headers, request body, status handling and failure detail strings.
 *
 * CONTRACT (read from `plus/api/server.ts`, not assumed): the route responds
 * with `{ capabilityToken, expiresAt }` — the token is a top-level field, not a
 * wrapper object. The previous shape read `success` / `challengeRequired` off
 * the whole body and then handed that whole body to Core as `capabilityToken`,
 * so a release could never have succeeded even with the URL corrected.
 *
 * Not fetched here: the Plus public key. Core pins that key itself since WU-1,
 * so transporting it would only invite the caller-chosen-key bypass again.
 */
async function fetchPlusMaterial(args: {
  plusBase: string;
  serviceSecret: string;
  token: string;
  userId: string;
  secretRef: string;
  operation: "AUTOFILL" | "VIEW" | "TOTP";
  signal: AbortSignal;
}): Promise<PlusMaterialResult> {
  const capRes = await fetch(`${args.plusBase}/api/v1/capabilities/request`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Core-Service": "cybervault-core",
      "X-Service-Secret": args.serviceSecret,
      Authorization: `Bearer ${args.token}`,
    },
    body: JSON.stringify({
      userId: args.userId,
      resourceId: args.secretRef,
      operation: args.operation,
      secretRef: args.secretRef,
      assurance: 2,
      context: { userAgent: "cybervault-extension", timestamp: Date.now() },
    }),
    signal: args.signal,
  });

  if (!capRes.ok) {
    return { ok: false, detail: `capability request failed (${capRes.status})` };
  }
  const cap = (await capRes.json()) as {
    success?: boolean;
    challengeRequired?: boolean;
    error?: string;
    capabilityToken?: PlusCapabilityToken;
  };
  // Checked first and kept, even though the current Plus issues a 400 instead:
  // `ReleaseDeps` promises this outcome, and a policy that demands a third
  // factor must surface as a challenge rather than as a generic denial.
  if (cap.challengeRequired) {
    return { ok: false, challengeRequired: true };
  }
  if (cap.success === false) {
    return { ok: false, detail: cap.error ?? "capability denied" };
  }
  if (
    !cap.capabilityToken ||
    typeof cap.capabilityToken.signature !== "string" ||
    typeof cap.capabilityToken.protectedHeader !== "string"
  ) {
    return { ok: false, detail: "capability token missing" };
  }

  return { ok: true, capabilityToken: cap.capabilityToken };
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

      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), 10_000);

      try {
        const plus = await fetchPlusMaterial({
          plusBase,
          serviceSecret,
          token,
          userId,
          secretRef,
          operation,
          signal: controller.signal,
        });
        if (!plus.ok) return plus;

        const released = await fetchManagedRelease({
          token,
          credentialId,
          capabilityToken: plus.capabilityToken,
          signal: controller.signal,
        });
        if (!released.ok) {
          if (released.kind === "http") {
            return { ok: false, detail: `managed release failed (${released.status})` };
          }
          // network / denied / not-unlocked: the helper already carries a
          // message that is safe to show, and it never contains key material.
          return { ok: false, detail: released.detail };
        }

        return { ok: true, releaseShare: released.releaseShare };
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

/**
 * Author one credential into the release store.
 *
 * This is the writer for `cybervault_cred_records` and `cybervault_cred_index`.
 * Neither store ever had one, so the index was empty for every user: listing
 * found no candidates and every release returned CREDENTIAL_NOT_FOUND. The
 * guard, the crypto and the binding logic were all present — and unreachable.
 *
 * The call is delegated to `authorCredential`, which validates the origin
 * before anything else, seals the envelope and registers the lookup token.
 * This handler owns only the persistence, and it persists the record WITHOUT
 * its origin: the store must hold ciphertext, salts and non-secret metadata
 * only (see STORE_KEYS), and the opaque index is what proves the binding.
 */
async function handleAuthorCredential(
  msg: AuthorCredentialMessage,
): Promise<BackgroundResponse> {
  try {
    const vek = await readSessionVek();
    if (!vek) {
      return { ok: false, error: "VAULT_LOCKED", data: { code: "VAULT_LOCKED" } };
    }

    const existingIndex = await buildReleaseDeps().getIndex();
    const result = await authorCredential(
      {
        origin: msg.payload?.origin ?? "",
        username: msg.payload?.username ?? "",
        password: msg.payload?.password ?? "",
        title: msg.payload?.title ?? "",
        totpSeedBase32: msg.payload?.totpSeedBase32,
      },
      vek,
      existingIndex,
    );

    if (!result.ok) {
      return {
        ok: false,
        error: result.reason,
        data: { reason: result.reason, detail: result.detail },
      };
    }

    const { origin: _boundOrigin, ...persisted } = result.record;

    const stored = await chrome.storage.local.get([STORE_KEYS.RECORDS]);
    const all =
      (stored[STORE_KEYS.RECORDS] as Record<string, EncryptedCredentialRecord> | undefined) ?? {};

    await chrome.storage.local.set({
      [STORE_KEYS.RECORDS]: { ...all, [result.record.id]: persisted },
      [STORE_KEYS.INDEX]: result.index,
    });

    return {
      ok: true,
      data: {
        id: result.record.id,
        title: result.record.title,
        usernameHint: result.record.usernameHint,
        origin: result.record.origin,
      },
    };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, error: message };
  }
}

async function handleReleaseCredential(
  msg: ReleaseCredentialMessage,
): Promise<BackgroundResponse> {
  try {
    const binding: StepUpBinding = {
      credentialId: msg.credentialId,
      origin: msg.origin,
      operation: msg.operation,
    };
    const key = bindingKey(binding);

    /* FAST PATH — a refusal this worker already knows how to give, without
     * spending a round trip. Deny only: it may STOP a release, never START
     * one, so forgetting it after an eviction can cost a question to Plus but
     * can never authorise anything. That asymmetry is the whole point — while
     * this `if` was the only gate, eviction emptied `challengedBindings`, the
     * block was skipped, and the release went out with no step-up behind it
     * (measured, not theorised: tests/extension/worker-eviction.test.ts).
     *
     * `canRetryRelease` is the check the domain module exists to enforce: a
     * step-up satisfied for one credential, origin or operation never
     * authorises a different one, and a step-up that has not been completed
     * authorises nothing at all. */
    if (challengedBindings.has(key)) {
      const retry = canRetryRelease(completedStepUps.get(key) ?? null, binding);
      if (!retry.ok) {
        return { ok: false, error: "CHALLENGE_REQUIRED", data: { code: "CHALLENGE_REQUIRED" } };
      }
    }

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

    if (outcome.ok) {
      /* AUTHORITATIVE CHECK — Plus's grant is necessary, not sufficient.
       *
       * Asked after the round trip, not before it. In front of the trip a
       * restarted worker cannot tell "this binding owes a step-up" from "this
       * worker has never heard of this binding" — both look like an empty map
       * — so refusing from persisted state before asking would turn every
       * post-eviction release into a refusal nobody questioned, and Plus's own
       * answer (the other half of the two-service defence) would never be
       * heard. Deny early, allow late: the cheap check may stop a release
       * early, only the full path may start one. */
      if (await sessionOwesStepUp(key, binding)) {
        // Record it HERE too, so the next retry is refused by the fast path
        // instead of buying another round trip to relearn the same answer.
        await rememberChallenged(key, binding);
        return { ok: false, error: "CHALLENGE_REQUIRED", data: { code: "CHALLENGE_REQUIRED" } };
      }

      // The step-up, when there was one, is spent by exactly this release —
      // in memory and in the record an eviction would otherwise hand back.
      await spendStepUp(key);
      return { ok: true, data: outcome.credential };
    }

    if (outcome.code === "CHALLENGE_REQUIRED") {
      await rememberChallenged(key, binding);
    }

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
 *
 * Note what is NOT covered by that argument: the GATE below (what is owed and
 * what has been paid). Dropping an in-flight ceremony fails closed; dropping
 * the gate fails open, which is the whole of R9.
 */
const stepUpChallenges = new Map<string, { binding: StepUpBinding; expiresAt: number }>();

/**
 * Bindings a release was refused for, keyed by `bindingKey`.
 *
 * A challenge exists to authorize ONE release. Recording which releases are
 * waiting on one is what lets `handleReleaseCredential` refuse a retry that has
 * no completed step-up behind it, instead of spending a round trip to learn
 * what Plus would have said again.
 *
 * This map is the FAST PATH — what this worker remembers, consulted to refuse
 * early. It is no longer the authority: eviction erases it, and R9 measured
 * what that costs. The authority is `STEP_UP_GATE_KEY` in session storage.
 */
const challengedBindings = new Map<string, StepUpBinding>();

/** Completed step-ups, keyed by the binding they were completed for. Same split: fast path, not authority. */
const completedStepUps = new Map<string, StepUpSession>();

/**
 * A release is identified by all three fields — credential, origin and
 * operation — because a challenge for any two of them must never authorize
 * the third. The triple is serialized rather than concatenated: an origin may
 * contain a separator-looking run of characters (IPv6 hosts such as `[::1]`),
 * and a key that could be assembled two ways is a key that can be collided.
 */
function bindingKey(binding: StepUpBinding): string {
  return JSON.stringify([binding.credentialId, binding.origin, binding.operation]);
}

/* ------------------------------------------------------------------ */
/*  The gate that survives an eviction (R9)                            */
/* ------------------------------------------------------------------ */

/**
 * Session storage key holding the gate: `challenged` and `completed`, keyed by
 * `bindingKey`.
 *
 * WHY IT IS NOT ONLY IN MEMORY
 * ----------------------------
 * `challengedBindings` answers "does this release owe a step-up?". A gate held
 * solely in worker memory is erased by the very lifecycle event the threat
 * model claimed it survived: MV3 evicts the worker after ~30s idle, the map
 * comes back empty, `has(key)` is false, and the block that refused the release
 * never runs. The extension then has no gate at all — the denial a user still
 * sees comes from Plus, i.e. one service instead of two.
 *
 * WHY `storage.session` AND NOT `storage.local`
 * ---------------------------------------------
 * 1. Content scripts cannot write it. `storage.session` is TRUSTED_CONTEXTS
 *    unless someone widens it explicitly (see `keepStepUpGatePrivate`), while
 *    `storage.local` is open to content scripts by default — and a compromised
 *    page can drive its own content script, so `.local` would let a page
 *    pre-mark a binding as completed and turn this fix into a bypass.
 * 2. It is memory-only and cleared when the browser closes, so a completion
 *    cannot outlive the session it was granted in.
 * 3. The VEK lives in the same area: "the gate is unreadable" and "the vault
 *    is locked" therefore cannot disagree about a release.
 *
 * NOT persisted: `stepUpChallenges`. An in-flight ceremony is not a gate
 * decision; dropping it on eviction forces a new challenge, which is the safe
 * direction for something that must never be replayed.
 */
const STEP_UP_GATE_KEY = "cybervault_stepup_gate";

interface PersistedStepUpGate {
  challenged: Record<string, StepUpBinding>;
  completed: Record<string, StepUpSession>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Re-assert that nothing outside the trusted contexts can reach the gate.
 *
 * The default already is TRUSTED_CONTEXTS — that default is load-bearing, not
 * incidental: it is what makes "the content script cannot write the gate" a
 * property of the platform instead of a convention this codebase follows. This
 * pins it, so a later `setAccessLevel(TRUSTED_AND_UNTRUSTED_CONTEXTS)` or a
 * changed runtime default cannot silently hand `completed` to a page.
 * A no-op where the runtime or a test double does not offer the API.
 */
function keepStepUpGatePrivate(): void {
  try {
    const area = chrome.storage?.session as
      | { setAccessLevel?: (options: { accessLevel: "TRUSTED_CONTEXTS" }) => Promise<void> }
      | undefined;
    if (typeof area?.setAccessLevel !== "function") return;
    void area.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" }).catch(() => undefined);
  } catch {
    // A runtime that refuses keeps its default, which is already trusted-only.
    // Failing to harden must never be able to break the worker.
  }
}
keepStepUpGatePrivate();

/**
 * Read the persisted gate. Never throws, never invents state.
 *
 * A record that is missing, malformed or unreadable reads as "nothing owed" —
 * and that is not a hole, because the same storage area holds the VEK: an area
 * we cannot read yields no key material either, so `releaseCredential` answers
 * VAULT_LOCKED before anything could move. Swallowing here also keeps a storage
 * outage from surfacing in the release path as an error code the page has no
 * use for.
 */
async function readPersistedGate(): Promise<PersistedStepUpGate> {
  try {
    const stored = await chrome.storage.session.get([STEP_UP_GATE_KEY]);
    const raw: unknown = stored[STEP_UP_GATE_KEY];
    if (!isRecord(raw)) return { challenged: {}, completed: {} };
    return {
      // Only whole records are accepted. `canRetryRelease` re-checks the
      // binding and the `completed` flag, so a half-written entry fails the
      // gate rather than passing it.
      challenged: isRecord(raw.challenged)
        ? (raw.challenged as Record<string, StepUpBinding>)
        : {},
      completed: isRecord(raw.completed) ? (raw.completed as Record<string, StepUpSession>) : {},
    };
  } catch {
    return { challenged: {}, completed: {} };
  }
}

/** One writer at a time: concurrent releases would otherwise race the
 *  read-modify-write below and drop each other's binding. */
let stepUpGateWrite: Promise<void> = Promise.resolve();

/**
 * Read-modify-write one mutation into the persisted gate.
 *
 * Errors are swallowed on purpose: memory still gates THIS worker, so a failed
 * persist can only cost the part of the gate that survives a restart. Failing
 * the release the user is watching would trade a real refusal for a storage
 * hiccup.
 */
function persistGateChange(change: (gate: PersistedStepUpGate) => void): Promise<void> {
  const write = stepUpGateWrite.then(async () => {
    try {
      const gate = await readPersistedGate();
      change(gate);
      await chrome.storage.session.set({ [STEP_UP_GATE_KEY]: gate });
    } catch (err) {
      logger.warn("step-up gate could not be persisted", "Auditor", { error: String(err) });
    }
  });
  stepUpGateWrite = write;
  return write;
}

async function rememberChallenged(key: string, binding: StepUpBinding): Promise<void> {
  challengedBindings.set(key, binding);
  await persistGateChange((gate) => {
    gate.challenged[key] = binding;
  });
}

async function rememberCompleted(key: string, session: StepUpSession): Promise<void> {
  completedStepUps.set(key, session);
  await persistGateChange((gate) => {
    gate.completed[key] = session;
  });
}

/** One release spent both halves of the gate for this binding. */
async function spendStepUp(key: string): Promise<void> {
  challengedBindings.delete(key);
  completedStepUps.delete(key);
  await persistGateChange((gate) => {
    delete gate.challenged[key];
    delete gate.completed[key];
  });
}

/**
 * Does this browser session still owe a step-up for `binding`?
 *
 * Asked AFTER Plus has answered, and it can disagree with Plus: a grant from a
 * Plus that is wrong, misconfigured or attacked is exactly the single point of
 * failure R9 was filed about, so this session's own record of what it refused
 * gets the last word. Memory is consulted when it knows the binding (it is
 * already loaded, and it holds everything it ever wrote); otherwise the
 * persisted record decides. A binding neither has ever seen owes nothing here —
 * that release is Plus's call, as it always was.
 */
async function sessionOwesStepUp(key: string, binding: StepUpBinding): Promise<boolean> {
  if (challengedBindings.has(key)) {
    return !canRetryRelease(completedStepUps.get(key) ?? null, binding).ok;
  }
  const gate = await readPersistedGate();
  const owed: StepUpBinding | undefined = gate.challenged[key];
  if (!owed) return false;
  const completed: StepUpSession | undefined = gate.completed[key];
  return !canRetryRelease(completed ?? null, binding).ok;
}

/**
 * The bindings a step-up is still owed for.
 *
 * The content script that hit the denial is gone by the time the user reaches
 * the popup, so the worker is the only place that still knows which release
 * was refused. This hands that binding back so the popup can start a challenge
 * for it rather than inventing one — and it reads the persisted gate too, so an
 * eviction between the denial and the popup opening does not silently drop the
 * pending item the user was about to act on.
 */
async function handleGetPendingStepUp(
  _msg: GetPendingStepUpMessage,
): Promise<BackgroundResponse> {
  try {
    const gate = await readPersistedGate();
    const challenged = new Map<string, StepUpBinding>(Object.entries(gate.challenged));
    for (const [key, binding] of challengedBindings) challenged.set(key, binding);

    const completed = new Set<string>([
      ...Object.keys(gate.completed),
      ...completedStepUps.keys(),
    ]);

    const pending: StepUpBinding[] = [];
    for (const [key, binding] of challenged) {
      if (!completed.has(key)) pending.push(binding);
    }
    return { ok: true, data: pending };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, error: message };
  }
}

const STEP_UP_PLUS_URL = "http://localhost:3011";

/** A successful trigger hands back the id the PIN answers, plus its expiry. */
type ChallengeTriggerResult =
  | { readonly ok: true; readonly challengeId: string; readonly expiresAt: number }
  | { readonly ok: false; readonly error: string; readonly data?: { text: string } };

/**
 * Read the Release Share reference THIS worker holds for `credentialId`.
 *
 * The resource Plus binds a challenge to must be the SAME resource the
 * capability request names, or the two legs never join up. Core pins
 * `expected.resourceId` to the credential's release-share reference, so
 * that is what `fetchPlusMaterial` sends as `resourceId` — sending the
 * credential id here would create a challenge the capability route could
 * never find, and the third factor would stay unreachable in production
 * even though both calls succeed. The worker reads its own store rather
 * than trusting the caller to name a reference it has no business choosing.
 *
 * Returns "" when there is nothing to step up for: a credential this worker
 * does not hold (or a personal one, which needs no capability at all) cannot
 * be released, so there is no release for a challenge to authorize.
 */
async function resolveManagedReleaseShareRef(credentialId: string): Promise<string> {
  const stored = await chrome.storage.local.get([STORE_KEYS.RECORDS]);
  const records = stored[STORE_KEYS.RECORDS] as
    | Record<string, EncryptedCredentialRecord>
    | undefined;
  const record = records?.[credentialId];
  if (
    !record ||
    record.mode !== "managed" ||
    typeof record.releaseShareRef !== "string" ||
    record.releaseShareRef === ""
  ) {
    return "";
  }
  return record.releaseShareRef;
}

/**
 * Ask Plus to trigger the third factor for one binding. Every failure comes
 * back as a refusal the caller can return verbatim; transport failures are
 * left to the caller's catch, exactly as before.
 */
async function triggerPlusChallenge(input: {
  binding: StepUpBinding;
  secretRef: string;
  token: string;
  userId: string;
  /**
   * D1: R1 made every non-probe Plus route require `X-Service-Secret`, and
   * this call sends only `X-Core-Service` — so it returns 401 and the whole
   * step-up is dead. The two capability calls in this file already send the
   * secret; these two were simply missed.
   */
  serviceSecret: string;
}): Promise<ChallengeTriggerResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10_000);
  try {
    const res = await fetch(`${STEP_UP_PLUS_URL}/api/v1/challenges/trigger`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Core-Service": "cybervault-core",
        "X-Service-Secret": input.serviceSecret,
        Authorization: `Bearer ${input.token}`,
      },
      body: JSON.stringify({
        userId: input.userId,
        // Plus binds the challenge to (userId, resourceId, operation,
        // secretRef); all four must match what the capability request sends.
        resourceId: input.secretRef,
        operation: input.binding.operation,
        secretRef: input.secretRef,
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

    return {
      ok: true,
      challengeId: body.challengeId,
      expiresAt: body.expiresAt ?? Date.now() + 120_000,
    };
  } finally {
    clearTimeout(timer);
  }
}

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

    const secretRef = await resolveManagedReleaseShareRef(binding.credentialId);
    if (!secretRef) {
      return { ok: false, error: "BINDING_NOT_MANAGED" };
    }

    const auth = await chrome.storage.local.get([
      "cybervault_token",
      "cybervault_userId",
      "plus_service_secret",
    ]);
    const token = auth["cybervault_token"] as string | undefined;
    const userId = auth["cybervault_userId"] as string | undefined;
    if (!token || !userId) return { ok: false, error: "not authenticated" };
    const serviceSecret = (auth["plus_service_secret"] as string) || "";

    const triggered = await triggerPlusChallenge({
      binding,
      secretRef,
      token,
      userId,
      serviceSecret,
    });
    if (!triggered.ok) {
      return triggered;
    }

    stepUpChallenges.set(triggered.challengeId, { binding, expiresAt: triggered.expiresAt });

    return {
      ok: true,
      data: {
        challengeId: triggered.challengeId,
        expiresAt: triggered.expiresAt,
        attemptsRemaining: 3,
        binding,
      },
    };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  }
}

/**
 * R3 — the user approved a release. No PIN is involved anywhere in this
 * function, and there is nothing to compare.
 *
 * The chain is: ask Core to sign an approval for this binding, then hand that
 * approval to Plus, which verifies it against its pinned Core key and issues
 * the capability. Core can prove the user owns the credential; Plus cannot, and
 * does not need to, because the signature carries the proof.
 */
async function handleApproveStepUp(msg: ApproveStepUpMessage): Promise<BackgroundResponse> {
  try {
    const entry = stepUpChallenges.get(msg.challengeId);
    if (!entry) {
      // Unknown challenge: refuse without contacting either service, so the
      // response time does not distinguish "never existed" from "already
      // consumed".
      return { ok: false, error: "the approval was not accepted" };
    }
    if (Date.now() >= entry.expiresAt) {
      stepUpChallenges.delete(msg.challengeId);
      return { ok: false, error: "the approval was not accepted" };
    }

    const auth = await chrome.storage.local.get([
      "cybervault_token",
      "plus_service_secret",
      "core_base_url",
    ]);
    const token = auth["cybervault_token"] as string | undefined;
    if (!token) return { ok: false, error: "not authenticated" };
    const serviceSecret = (auth["plus_service_secret"] as string) || "";
    const coreBase = (auth["core_base_url"] as string) || "http://localhost:3010";

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 10_000);

    try {
      /* ---- 1. Core signs the approval. ----------------------------------
       * The request names only the credential and the operation. Core reads
       * the user from the token and the secretRef from the stored record, so
       * this body cannot be used to redirect the approval at another
       * credential's Release Share. */
      const approved = await fetch(`${coreBase}/api/v1/step-up/approve`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          challengeId: msg.challengeId,
          credentialId: entry.binding.credentialId,
          operation: entry.binding.operation,
        }),
        signal: controller.signal,
      });

      if (!approved.ok) {
        // Core refused: unknown credential, wrong owner, personal credential,
        // or no signing key configured. Deliberately not surfaced verbatim — a
        // Core reason could tell the user (or a script driving the popup) which
        // of those it was.
        return { ok: false, error: "the release could not be approved" };
      }

      const approvalBody = (await approved.json()) as { approval?: unknown };
      if (!approvalBody.approval) {
        return { ok: false, error: "the release could not be approved" };
      }

      /* ---- 2. Plus verifies the approval and issues the capability. ------ */
      const res = await fetch(`${STEP_UP_PLUS_URL}/api/v1/challenges/approve`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Core-Service": "cybervault-core",
          "X-Service-Secret": serviceSecret,
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          challengeId: msg.challengeId,
          approval: approvalBody.approval,
        }),
        signal: controller.signal,
      });

      if (!res.ok) {
        return { ok: false, error: "the approval was not accepted" };
      }

      const body = (await res.json()) as { success?: boolean; capabilityToken?: unknown };

      // A 2xx alone is not treated as success: Plus's `sendSuccess` does not
      // wrap every payload in `{ success: true }`, so a missing flag used to
      // read as `undefined` and report a completed approval as refused. The
      // capability itself is the real signal — an approve that issued nothing
      // has not approved anything.
      if (body.success === true || body.capabilityToken !== undefined) {
        // One-shot: a completed challenge cannot be replayed.
        stepUpChallenges.delete(msg.challengeId);
        // Record the completion against the binding the challenge was started
        // for, which is what `canRetryRelease` compares a later retry with.
        // The session carries no secret — only the binding and the expiry —
        // and it is persisted because the retry it authorises has to survive
        // an eviction as much as the refusal it answers does.
        await rememberCompleted(bindingKey(entry.binding), {
          challengeId: msg.challengeId,
          binding: entry.binding,
          expiresAt: entry.expiresAt,
          attemptsRemaining: 0,
          completed: true,
        });
        return { ok: true, data: { verified: true } };
      }

      return { ok: false, error: "the approval was not accepted" };
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

      case MESSAGE_TYPES.AUTHOR_CREDENTIAL:
        handlerPromise = handleAuthorCredential(message);
        break;

      case MESSAGE_TYPES.RELEASE_CREDENTIAL:
        handlerPromise = handleReleaseCredential(message);
        break;

      case MESSAGE_TYPES.START_STEP_UP:
        handlerPromise = handleStartStepUp(message);
        break;

      case MESSAGE_TYPES.APPROVE_STEP_UP:
        handlerPromise = handleApproveStepUp(message);
        break;

      case MESSAGE_TYPES.GET_PENDING_STEP_UP:
        handlerPromise = handleGetPendingStepUp(message);
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
