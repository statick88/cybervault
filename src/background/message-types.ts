/**
 * Message contract between the content scripts and the service worker.
 *
 * WHY THIS IS A SEPARATE MODULE
 * -----------------------------
 * The contract used to live inside `auditor.ts`, which registers a
 * `chrome.runtime.onMessage` listener as a side effect of being imported. That
 * made the message names untestable and unshareable: any consumer that imported
 * them in order to check a name was silently forced to also stand up a service
 * worker listener, which fails outside a browser.
 *
 * Keeping the contract here means both sides can import it with no side effects,
 * and a renamed message becomes a compile error in both places at once instead of
 * a runtime "unknown message type" that fails closed and looks like a dead
 * feature rather than a broken contract.
 *
 * @module background/message-types
 */

export const MESSAGE_TYPES = {
  /* AiTM / trust */
  VALIDATE_DOMAIN: "VALIDATE_DOMAIN",
  GET_TRUST_STATUS: "GET_TRUST_STATUS",
  REPORT_ANOMALY: "REPORT_ANOMALY",

  /* Vault session */
  UNLOCK_VAULT: "UNLOCK_VAULT",
  LOCK_VAULT: "LOCK_VAULT",
  CHECK_VAULT_STATUS: "CHECK_VAULT_STATUS",

  /* Local encryption (session key held by the worker) */
  ENCRYPT_DATA: "ENCRYPT_DATA",
  DECRYPT_DATA: "DECRYPT_DATA",

  /* Plus authorization */
  REQUEST_MANAGED_CAPABILITY: "REQUEST_MANAGED_CAPABILITY",
  REQUEST_RELEASE_SHARE: "REQUEST_RELEASE_SHARE",
  GET_PLUS_PUBLIC_KEY: "GET_PLUS_PUBLIC_KEY",

  /* Credential release — the guarded path to a form field */
  LIST_CREDENTIALS_FOR_ORIGIN: "LIST_CREDENTIALS_FOR_ORIGIN",
  RELEASE_CREDENTIAL: "RELEASE_CREDENTIAL",

  /* Step-up (third factor) — CHALLENGE_REQUIRED follow-up */
  START_STEP_UP: "START_STEP_UP",
  SUBMIT_STEP_UP_PIN: "SUBMIT_STEP_UP_PIN",
} as const;

export type MessageType = (typeof MESSAGE_TYPES)[keyof typeof MESSAGE_TYPES];

/* ------------------------------------------------------------------ */
/*  Payloads                                                           */
/* ------------------------------------------------------------------ */

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

export interface LockVaultMessage {
  type: typeof MESSAGE_TYPES.LOCK_VAULT;
}

export interface CheckVaultStatusMessage {
  type: typeof MESSAGE_TYPES.CHECK_VAULT_STATUS;
}

export interface EncryptDataMessage {
  type: typeof MESSAGE_TYPES.ENCRYPT_DATA;
  payload: string;
}

export interface DecryptDataMessage {
  type: typeof MESSAGE_TYPES.DECRYPT_DATA;
  payload: string;
}

export interface RequestManagedCapabilityMessage {
  type: typeof MESSAGE_TYPES.REQUEST_MANAGED_CAPABILITY;
  payload: {
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
  };
}

export interface RequestReleaseShareMessage {
  type: typeof MESSAGE_TYPES.REQUEST_RELEASE_SHARE;
  payload: {
    capabilityToken: {
      payload: unknown;
      signature: string;
      protectedHeader: string;
    };
    plusPublicKey: string;
  };
}

export interface GetPlusPublicKeyMessage {
  type: typeof MESSAGE_TYPES.GET_PLUS_PUBLIC_KEY;
}

/** Content script asks which credentials are bound to the page's origin. */
export interface ListCredentialsForOriginMessage {
  type: typeof MESSAGE_TYPES.LIST_CREDENTIALS_FOR_ORIGIN;
  origin: string;
}

/** Content script asks for a specific credential to be released. */
export interface ReleaseCredentialMessage {
  type: typeof MESSAGE_TYPES.RELEASE_CREDENTIAL;
  credentialId: string;
  origin: string;
  operation: "AUTOFILL" | "TOTP";
  documentOrigin: string;
  topLevelOrigin: string;
  isFramed: boolean;
}

/**
 * Content script starts a third-factor challenge for one exact release.
 *
 * The binding is echoed back on every subsequent call so the service worker can
 * refuse a PIN that is presented for a different credential, origin or operation
 * than the challenge was started for.
 */
export interface StartStepUpMessage {
  type: typeof MESSAGE_TYPES.START_STEP_UP;
  binding: {
    credentialId: string;
    origin: string;
    operation: "AUTOFILL" | "TOTP";
  };
}

/** Content script submits the PIN the user received. Never persisted. */
export interface SubmitStepUpPinMessage {
  type: typeof MESSAGE_TYPES.SUBMIT_STEP_UP_PIN;
  challengeId: string;
  pin: string;
}

export type BackgroundMessage =
  | ValidateDomainMessage
  | GetTrustStatusMessage
  | ReportAnomalyMessage
  | UnlockVaultMessage
  | LockVaultMessage
  | CheckVaultStatusMessage
  | EncryptDataMessage
  | DecryptDataMessage
  | RequestManagedCapabilityMessage
  | RequestReleaseShareMessage
  | GetPlusPublicKeyMessage
  | ListCredentialsForOriginMessage
  | ReleaseCredentialMessage
  | StartStepUpMessage
  | SubmitStepUpPinMessage;

export interface BackgroundResponse<T = unknown> {
  ok: boolean;
  data?: T;
  error?: string;
}
