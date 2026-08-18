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
import { metrics } from "../shared/metrics";
import type { TrustEntry } from "../domain/repositories";

/* ------------------------------------------------------------------ */
/*  Message Types — must match content script requests                 */
/* ------------------------------------------------------------------ */

export const MESSAGE_TYPES = {
  VALIDATE_DOMAIN: "VALIDATE_DOMAIN",
  GET_TRUST_STATUS: "GET_TRUST_STATUS",
  REPORT_ANOMALY: "REPORT_ANOMALY",
  UNLOCK_VAULT: "UNLOCK_VAULT",
} as const;

export type MessageType =
  (typeof MESSAGE_TYPES)[keyof typeof MESSAGE_TYPES];

export interface ValidateDomainMessage {
  type: typeof MESSAGE_TYPES.VALIDATE_DOMAIN;
  hostname: string;
  expectedDomain: string;
  tabId?: number;
}

export interface GetTrustStatusMessage {
  type: typeof MESSAGE_TYPES.GET_TRUST_STATUS;
  domain: string;
}

export interface ReportAnomalyMessage {
  type: typeof MESSAGE_TYPES.REPORT_ANOMALY;
  domain: string;
  anomalyType: string;
  severity: "low" | "medium" | "high";
  details: string;
}

export interface UnlockVaultMessage {
  type: typeof MESSAGE_TYPES.UNLOCK_VAULT;
  vaultId: string;
  passphrase?: string;
}

export type BackgroundMessage =
  | ValidateDomainMessage
  | GetTrustStatusMessage
  | ReportAnomalyMessage
  | UnlockVaultMessage;

export interface BackgroundResponse<T = unknown> {
  ok: boolean;
  data?: T;
  error?: string;
}

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

      console.log("[CyberVault] Extension installed — default settings seeded");
    }

    if (reason === "update") {
      // Migration logic — check for stale trust store entries
      const trustEntries = await trustStore.list();
      const expiredCount = await trustStore.removeExpired(
        90 * 24 * 60 * 60 * 1000, // 90 days
      );

      if (expiredCount > 0) {
        console.log(
          `[CyberVault] Cleaned ${expiredCount} expired trust entries (${trustEntries.length} remaining)`,
        );
      }
    }
  },
);
