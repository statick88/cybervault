/**
 * CyberVault — Autocomplete Content Script
 *
 * Runs at document_end on all pages. Detects credential fields, matches
 * the current domain against stored credentials, and fills them when
 * found. Shows a subtle indicator badge when credentials are available.
 *
 * @module ui/content-scripts/autocomplete
 */

(function() {

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

interface StoredCredential {
  domain: string;
  email: string;
  password: string;
  originalEmail?: string;
  originalPassword?: string;
  formUrl?: string;
  timestamp: number;
  lastUsed?: number;
}

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

const INDICATOR_ID = "cybervault-autocomplete-indicator";
const FILL_ATTR = "data-cv-filled";
const STORAGE_PREFIX = "cybervault_creds_";

/* ------------------------------------------------------------------ */
/*  Storage Helpers                                                    */
/* ------------------------------------------------------------------ */

function domainKey(domain: string): string {
  return `${STORAGE_PREFIX}${domain}`;
}

async function getCredentialsForDomain(
  domain: string,
): Promise<StoredCredential | null> {
  try {
    const result = await chrome.storage.local.get(domainKey(domain));
    const cred = result[domainKey(domain)] as StoredCredential | undefined;
    if (cred && typeof cred === "object" && "email" in cred && "password" in cred) {
      return cred;
    }
    return null;
  } catch {
    return null;
  }
}

async function markLastUsed(domain: string): Promise<void> {
  try {
    const key = domainKey(domain);
    const result = await chrome.storage.local.get(key);
    const cred = result[key] as Record<string, unknown> | undefined;
    if (cred && typeof cred === "object") {
      cred["lastUsed"] = Date.now();
      await chrome.storage.local.set({ [key]: cred });
    }
  } catch {
    // Ignore storage errors silently
  }
}

/* ------------------------------------------------------------------ */
/*  Field Detection                                                    */
/* ------------------------------------------------------------------ */

interface CredentialFields {
  emailField: HTMLInputElement | null;
  passwordField: HTMLInputElement | null;
}

function detectCredentialFields(form: HTMLFormElement): CredentialFields {
  const inputs = form.querySelectorAll<HTMLInputElement>(
    'input[type="text"], input[type="email"], input[type="password"]',
  );

  let emailField: HTMLInputElement | null = null;
  let passwordField: HTMLInputElement | null = null;

  inputs.forEach((input) => {
    const type = input.type.toLowerCase();
    const name = (input.name || "").toLowerCase();
    const id = (input.id || "").toLowerCase();
    const autocomplete = (input.getAttribute("autocomplete") || "").toLowerCase();
    const placeholder = (input.placeholder || "").toLowerCase();

    if (type === "password" && !passwordField) {
      passwordField = input;
    } else if (
      type === "email" ||
      autocomplete.includes("email") ||
      name.includes("email") ||
      id.includes("email") ||
      placeholder.includes("email") ||
      placeholder.includes("correo")
    ) {
      if (!emailField) emailField = input;
    } else if (
      type === "text" &&
      !emailField &&
      (name.includes("user") || name.includes("login") || id.includes("user"))
    ) {
      emailField = input;
    }
  });

  return { emailField, passwordField };
}

/* ------------------------------------------------------------------ */
/*  Fill Logic                                                         */
/* ------------------------------------------------------------------ */

function fillField(input: HTMLInputElement, value: string): void {
  if (input.getAttribute(FILL_ATTR)) return;

  const nativeSetter = Object.getOwnPropertyDescriptor(
    HTMLInputElement.prototype,
    "value",
  )?.set;

  if (nativeSetter) {
    nativeSetter.call(input, value);
  } else {
    input.value = value;
  }

  input.setAttribute(FILL_ATTR, "true");
  input.dispatchEvent(new Event("input", { bubbles: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
}

/* ------------------------------------------------------------------ */
/*  Indicator Badge                                                    */
/* ------------------------------------------------------------------ */

function showIndicator(email: string): void {
  if (document.getElementById(INDICATOR_ID)) return;

  const badge = document.createElement("div");
  badge.id = INDICATOR_ID;
  badge.style.cssText = `
    position:fixed;top:8px;right:8px;z-index:2147483646;
    background:#1a1a2e;border:1px solid #00ff88;border-radius:6px;
    padding:6px 12px;font-size:12px;color:#00ff88;
    font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
    box-shadow:0 2px 8px rgba(0,255,136,0.2);cursor:pointer;
    transition:opacity 0.2s;
  `;
  badge.textContent = `🔐 CyberVault: ${email}`;
  badge.title = "Click to auto-fill saved credentials";

  badge.addEventListener("click", () => {
    fillAllForms();
    badge.style.opacity = "0";
    setTimeout(() => badge.remove(), 200);
  });

  document.body.appendChild(badge);
}

/* ------------------------------------------------------------------ */
/*  Fill Orchestration                                                 */
/* ------------------------------------------------------------------ */

async function fillAllForms(): Promise<void> {
  const domain = window.location.hostname;
  const cred = await getCredentialsForDomain(domain);
  if (!cred) return;

  const forms = document.querySelectorAll<HTMLFormElement>("form");

  forms.forEach((form) => {
    const { emailField, passwordField } = detectCredentialFields(form);

    if (emailField && cred.email) {
      fillField(emailField, cred.email);
    }
    if (passwordField && cred.password) {
      fillField(passwordField, cred.password);
    }
  });

  await markLastUsed(domain);
}

/* ------------------------------------------------------------------ */
/*  Main                                                               */
/* ------------------------------------------------------------------ */

async function main(): Promise<void> {
  const domain = window.location.hostname;
  if (!domain) return;

  const cred = await getCredentialsForDomain(domain);
  if (!cred) return;

  // Show indicator badge
  showIndicator(cred.email);

  // Auto-fill forms on the page
  await fillAllForms();

  // Watch for dynamically added forms (SPAs)
  const observer = new MutationObserver(() => {
    const forms = document.querySelectorAll<HTMLFormElement>(
      `form:not([${FILL_ATTR}])`,
    );
    if (forms.length > 0) {
      fillAllForms();
    }
  });

  if (document.body) {
    observer.observe(document.body, { childList: true, subtree: true });
  }
}

// Kick off when DOM is ready
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", main);
} else {
  main();
}

})();
