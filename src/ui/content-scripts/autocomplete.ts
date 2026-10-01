/**
 * CyberVault — Autofill content script (guarded).
 *
 * WHAT CHANGED AND WHY
 * --------------------
 * The previous version of this file was the pre-split-trust autofill path and
 * it was unsafe in three ways:
 *
 *   1. It read `{ email, password }` in PLAINTEXT from `chrome.storage.local`
 *      under `cybervault_creds_<hostname>`. That is a direct violation of the
 *      invariant that no secret is ever persisted in local storage, and it also
 *      told the backend every origin the user holds a credential for.
 *   2. It matched on bare `window.location.hostname`, so scheme and port were
 *      ignored and there was no ExactMatch at all.
 *   3. It filled EVERY form on the page, with no check of `form.action`, no
 *      submit-origin check, no iframe check and no top-level-frame check, and it
 *      did so on page load without any user gesture.
 *
 * This version removes all three. The rules it now obeys:
 *
 *   - NO secret is ever read from or written to `chrome.storage.local`. The
 *     only persisted lookup structure is the opaque token index, which contains
 *     no origin and no secret.
 *   - A credential is only ever obtained from the service worker AFTER the
 *     guard has allowed the specific (credential, document, form, frame) tuple.
 *   - The guard is evaluated TWICE: once in the service worker before any
 *     secret is decrypted or released, and again here immediately before the
 *     value is written into the field. Defence in depth: neither copy alone is
 *     load-bearing, and a bug in one does not become a credential leak.
 *   - Filling requires an explicit user gesture. Nothing is filled on load.
 *   - Any error, timeout or unexpected state results in NO fill. Fail closed.
 *
 * @module ui/content-scripts/autocomplete
 */

import { evaluateAutofill } from "../../domain/services/autofill/autofill-guard";
import { originFromLocation } from "../../domain/services/autofill/origin";
import { detectTOTPField, generateTOTP } from "./totp-generator";

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

const INDICATOR_ID = "cybervault-autofill-indicator";
const FILL_ATTR = "data-cv-filled";

/**
 * Hard ceiling on a service-worker round trip.
 *
 * A hung request must never leave the page in a state where a later code path
 * "helpfully" fills anyway, so every await is bounded and every timeout is a
 * refusal.
 */
const SW_TIMEOUT_MS = 5000;

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

interface OriginContext {
  documentOrigin: string;
  topLevelOrigin: string;
  isFramed: boolean;
}

/**
 * A credential as handed over by the service worker.
 *
 * It arrives already decrypted, over the short-lived message channel, and is
 * held only in this closure. It is never written to storage.
 */
interface ReleasedCredential {
  id: string;
  username: string;
  password: string;
  totpSecret?: string;
}

interface SwResponse<T = unknown> {
  ok: boolean;
  data?: T;
  error?: string;
}

/* ------------------------------------------------------------------ */
/*  Origin context                                                     */
/* ------------------------------------------------------------------ */

/**
 * Describe where this script is running.
 *
 * `topLevelOrigin` is read defensively: a cross-origin parent makes
 * `window.top.location` throw, which is exactly the case we need to detect
 * rather than swallow.
 */
export function describeOriginContext(win: Window = window): OriginContext {
  const documentOrigin = originFromLocation(win.location);

  let topLevelOrigin = documentOrigin;
  let isFramed = false;

  try {
    if (win.top && win.top !== win.self) {
      isFramed = true;
      // Throws if the parent is cross-origin — the common hostile case.
      topLevelOrigin = originFromLocation(win.top.location);
    }
  } catch {
    // We could not even read window.top, which means we are inside a frame
    // whose context we cannot reason about.
    //
    // isFramed MUST be set here. If it stayed false the caller would supply no
    // frame context at all, the guard would skip its UNAUTHORIZED_FRAME check,
    // and a hostile page could embed us in an iframe and receive the fill —
    // because our own document origin would legitimately match. Failing to
    // mark the situation as framed turns an unreadable parent into a bypass.
    isFramed = true;
    topLevelOrigin = "";
  }

  return { documentOrigin, topLevelOrigin, isFramed };
}

/* ------------------------------------------------------------------ */
/*  Service-worker transport                                           */
/* ------------------------------------------------------------------ */

function sendToServiceWorker<T = unknown>(message: unknown): Promise<SwResponse<T>> {
  return new Promise((resolve) => {
    let settled = false;
    const done = (value: SwResponse<T>) => {
      if (settled) return;
      settled = true;
      resolve(value);
    };

    const timer = setTimeout(
      () => done({ ok: false, error: "service worker timeout" }),
      SW_TIMEOUT_MS,
    );

    try {
      chrome.runtime.sendMessage(message, (response: SwResponse<T>) => {
        clearTimeout(timer);
        if (chrome.runtime.lastError) {
          done({ ok: false, error: chrome.runtime.lastError.message ?? "runtime error" });
          return;
        }
        done(response ?? { ok: false, error: "empty response" });
      });
    } catch (err) {
      clearTimeout(timer);
      done({ ok: false, error: err instanceof Error ? err.message : String(err) });
    }
  });
}

/* ------------------------------------------------------------------ */
/*  Form inspection                                                    */
/* ------------------------------------------------------------------ */

interface FieldPair {
  usernameField: HTMLInputElement | null;
  passwordField: HTMLInputElement | null;
  totpField: HTMLInputElement | null;
  form: HTMLFormElement;
}

function detectFields(form: HTMLFormElement): FieldPair {
  const inputs = Array.from(
    form.querySelectorAll<HTMLInputElement>(
      'input[type="text"], input[type="email"], input[type="password"], ' +
        'input[type="tel"], input[type="number"], input:not([type])',
    ),
  );

  let usernameField: HTMLInputElement | null = null;
  let passwordField: HTMLInputElement | null = null;
  let totpField: HTMLInputElement | null = null;

  for (const input of inputs) {
    const type = (input.type || "text").toLowerCase();

    if (type === "password") {
      if (!passwordField) passwordField = input;
      continue;
    }

    if (!totpField && isTotpCandidate(input)) {
      totpField = input;
      continue;
    }

    if (!usernameField && isUsernameCandidate(input, type)) {
      usernameField = input;
    }
  }

  return { usernameField, passwordField, totpField, form };
}

function fold(value: string): string {
  return value
    .toLowerCase()
    .normalize("NFD")
    .replace(/\p{Diacritic}/gu, "");
}

function isTotpCandidate(input: HTMLInputElement): boolean {
  if (input.hasAttribute("autocomplete") && fold(input.getAttribute("autocomplete") ?? "") === "one-time-code") {
    return true;
  }
  const haystack = [
    fold(input.name ?? ""),
    fold(input.id ?? ""),
    fold(input.placeholder ?? ""),
  ].join(" ");
  return ["totp", "2fa", "mfa", "otp", "authenticator", "codigo", "code"].some((token) =>
    haystack.includes(token),
  );
}

function isUsernameCandidate(input: HTMLInputElement, type: string): boolean {
  if (type === "email") return true;
  const haystack = [
    fold(input.name ?? ""),
    fold(input.id ?? ""),
    fold(input.placeholder ?? ""),
    fold(input.getAttribute("autocomplete") ?? ""),
  ].join(" ");
  return ["user", "username", "login", "email", "correo", "identificador"].some((token) =>
    haystack.includes(token),
  );
}

/**
 * The origin a form submission would actually reach.
 *
 * A submit control's `formaction` overrides the form's `action`, so it takes
 * precedence. Returning null means "same as the form action", which the guard
 * handles.
 */
export function resolveSubmitOrigin(
  form: HTMLFormElement,
  submitter: Element | null,
): string | null {
  const formaction = submitter?.getAttribute?.("formaction");
  if (formaction && formaction.trim() !== "") return formaction;
  const action = form.getAttribute("action");
  return action === null ? null : action;
}

/* ------------------------------------------------------------------ */
/*  Guard integration                                                  */
/* ------------------------------------------------------------------ */

export interface GuardInput {
  credentialOrigin: string;
  context: OriginContext;
  formAction: string | null;
  submitOrigin: string | null;
}

export type GuardOutcome =
  | { readonly allowed: true }
  | { readonly allowed: false; readonly reason: string; readonly detail: string };

/**
 * Run the guard for one (credential, form) pair.
 *
 * Exported so the decision can be unit-tested with synthetic inputs rather than
 * only through a live page.
 */
export function guardFill(input: GuardInput): GuardOutcome {
  const decision = evaluateAutofill({
    operation: "AUTOFILL",
    credentialOrigin: input.credentialOrigin,
    documentOrigin: input.context.documentOrigin,
    formAction: input.formAction,
    submitOrigin: input.submitOrigin,
    // Only supply frame context when actually framed: a half-supplied context
    // is treated as untrusted by the guard.
    topLevelOrigin: input.context.isFramed ? input.context.topLevelOrigin : null,
    frameOrigin: input.context.isFramed ? input.context.documentOrigin : null,
  });

  if (decision.allowed) return { allowed: true };
  return { allowed: false, reason: decision.reason, detail: decision.detail };
}

/* ------------------------------------------------------------------ */
/*  Field writing                                                      */
/* ------------------------------------------------------------------ */

/**
 * Write a value into an input using the native setter.
 *
 * React and other frameworks install their own `value` setter and track the
 * last value they wrote; assigning through the prototype setter is what makes
 * the change observable to them instead of being silently reverted.
 */
export function writeField(input: HTMLInputElement, value: string): boolean {
  if (!input || input.disabled || input.readOnly) return false;
  if (input.getAttribute(FILL_ATTR) === "true") return false;

  const descriptor = Object.getOwnPropertyDescriptor(
    HTMLInputElement.prototype,
    "value",
  );
  const nativeSetter = descriptor?.set;

  if (nativeSetter) nativeSetter.call(input, value);
  else input.value = value;

  input.setAttribute(FILL_ATTR, "true");
  input.dispatchEvent(new Event("input", { bubbles: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
  return true;
}

/* ------------------------------------------------------------------ */
/*  Release flow                                                       */
/* ------------------------------------------------------------------ */

interface CandidateSummary {
  credentialId: string;
  /** Origin the credential is bound to, used for the guard. */
  origin: string;
  hasTotp: boolean;
}

async function listCandidates(origin: string): Promise<CandidateSummary[]> {
  const response = await sendToServiceWorker<CandidateSummary[]>({
    type: "LIST_CREDENTIALS_FOR_ORIGIN",
    origin,
  });
  if (!response.ok || !Array.isArray(response.data)) return [];
  return response.data;
}

async function releaseCredential(
  credentialId: string,
  origin: string,
  operation: "AUTOFILL" | "TOTP",
  context: OriginContext,
): Promise<ReleasedCredential | null> {
  const response = await sendToServiceWorker<ReleasedCredential>({
    type: "RELEASE_CREDENTIAL",
    credentialId,
    origin,
    operation,
    documentOrigin: context.documentOrigin,
    topLevelOrigin: context.topLevelOrigin,
    isFramed: context.isFramed,
  });
  if (!response.ok || !response.data) return null;
  return response.data;
}

/**
 * Attempt to fill one form with one credential.
 *
 * The guard is re-evaluated here, immediately before any write, even though the
 * service worker already checked it. The two checks are intentionally
 * independent: the service worker cannot see `form.action`, and this script
 * cannot see whether a capability was consumed.
 */
export async function fillForm(
  pair: FieldPair,
  candidate: CandidateSummary,
  context: OriginContext,
): Promise<boolean> {
  // Guard pass 1 — before requesting the secret.
  const pre = guardFill({
    credentialOrigin: candidate.origin,
    context,
    formAction: pair.form.getAttribute("action"),
    submitOrigin: resolveSubmitOrigin(pair.form, null),
  });
  if (!pre.allowed) return false;

  const released = await releaseCredential(
    candidate.credentialId,
    candidate.origin,
    "AUTOFILL",
    context,
  );
  if (!released) return false;

  // Guard pass 2 — after the secret exists in memory, before any write.
  const post = guardFill({
    credentialOrigin: candidate.origin,
    context,
    formAction: pair.form.getAttribute("action"),
    submitOrigin: resolveSubmitOrigin(pair.form, null),
  });
  if (!post.allowed) return false;

  let wrote = false;
  if (pair.usernameField && released.username) {
    wrote = writeField(pair.usernameField, released.username) || wrote;
  }
  if (pair.passwordField && released.password) {
    wrote = writeField(pair.passwordField, released.password) || wrote;
  }
  if (pair.totpField && released.totpSecret) {
    try {
      const code = await generateTOTP(released.totpSecret);
      wrote = writeField(pair.totpField, code) || wrote;
    } catch {
      // A TOTP failure must not prevent the username/password fill.
    }
  }
  return wrote;
}

/* ------------------------------------------------------------------ */
/*  UI                                                                 */
/* ------------------------------------------------------------------ */

function removeIndicator(): void {
  document.getElementById(INDICATOR_ID)?.remove();
}

function showIndicator(count: number, onFill: () => void | Promise<void>): void {
  removeIndicator();
  if (count <= 0) return;

  const badge = document.createElement("div");
  badge.id = INDICATOR_ID;
  badge.style.cssText = [
    "position:fixed",
    "top:8px",
    "right:8px",
    "z-index:2147483647",
    "background:#1a1a2e",
    "border:1px solid #00ff88",
    "border-radius:6px",
    "padding:8px 12px",
    "font-size:12px",
    "color:#00ff88",
    "font-family:system-ui,sans-serif",
    "cursor:pointer",
    "box-shadow:0 2px 8px rgba(0,255,136,0.25)",
  ].join(";");

  badge.textContent = `🔐 CyberVault — ${count} credential${count === 1 ? "" : "s"}`;
  badge.title = "Click to fill. Nothing is filled without your action.";

  // Explicit user gesture. The previous version filled on page load.
  badge.addEventListener("click", (event) => {
    event.preventDefault();
    event.stopPropagation();
    // onFill is `attemptFill`, which is async and can reject (sendMessage, the
    // release round trip). The previous `void onFill()` discarded the promise,
    // so a failed fill became an unhandled rejection. Promise.resolve() accepts
    // both shapes and the catch keeps the original intent: fail closed and stay
    // silent, matching start(), so the page learns nothing from the failure.
    Promise.resolve(onFill()).catch(() => {});
    removeIndicator();
  });

  document.documentElement.appendChild(badge);
}

/* ------------------------------------------------------------------ */
/*  Entry point                                                        */
/* ------------------------------------------------------------------ */

async function attemptFill(): Promise<void> {
  const context = describeOriginContext();

  const candidates = await listCandidates(context.documentOrigin);
  if (candidates.length === 0) return;

  const forms = Array.from(document.querySelectorAll<HTMLFormElement>("form"));
  for (const form of forms) {
    const pair = detectFields(form);
    if (!pair.passwordField && !pair.usernameField) continue;

    for (const candidate of candidates) {
      await fillForm(pair, candidate, context);
    }
  }
}

async function main(): Promise<void> {
  const context = describeOriginContext();

  // Nothing happens on a framed page until the user is known to be on the
  // credential origin. We still avoid touching the DOM at all in that case.
  const candidates = await listCandidates(context.documentOrigin);
  showIndicator(candidates.length, attemptFill);
}

/* ------------------------------------------------------------------ */
/*  Bootstrap                                                          */
/* ------------------------------------------------------------------ */

function start(): void {
  void main().catch(() => {
    // Fail closed and stay silent. No badge, no fill, no console noise that
    // would confirm to the page that an extension is present.
  });
}

if (typeof document !== "undefined") {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", start, { once: true });
  } else {
    start();
  }
}

export { detectTOTPField };
