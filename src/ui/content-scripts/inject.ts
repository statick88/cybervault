/**
 * CyberVault — Inject Content Script
 *
 * Runs at document_idle on all pages. Detects login forms, fingerprints
 * the page, validates the domain against the AITM pipeline, and blocks
 * form submissions when the domain is flagged as suspicious or malicious.
 *
 * @module ui/content-scripts/inject
 */

(function() {

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

interface PageFingerprint {
  url: string;
  hostname: string;
  formCount: number;
  loginFormCount: number;
  inputNames: string[];
}

interface ValidationResult {
  overallRisk: "low" | "medium" | "high";
  steps: Array<{ step: string; passed: boolean; reason?: string }>;
}

interface BackgroundResponse<T = unknown> {
  ok: boolean;
  data?: T;
  error?: string;
}

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

const CYBERVAULT_BLOCKED_CLASS = "cybervault-blocked";
const FORM_SUBMIT_SELECTOR = "form";

/* ------------------------------------------------------------------ */
/*  State                                                              */
/* ------------------------------------------------------------------ */

let lastValidationResult: ValidationResult | null = null;
let blockedForms = new WeakSet<HTMLFormElement>();

/* ------------------------------------------------------------------ */
/*  Fingerprinting                                                     */
/* ------------------------------------------------------------------ */

function generateFingerprint(): PageFingerprint {
  const forms = document.querySelectorAll<HTMLFormElement>("form");
  const loginForms = document.querySelectorAll<HTMLFormElement>(
    'input[type="password"]',
  );
  const inputs = document.querySelectorAll<HTMLInputElement>(
    "form input, form select",
  );

  const inputNames: string[] = [];
  inputs.forEach((input) => {
    if (input.name) inputNames.push(input.name);
  });

  return {
    url: window.location.href,
    hostname: window.location.hostname,
    formCount: forms.length,
    loginFormCount: loginForms.length,
    inputNames: [...new Set(inputNames)],
  };
}

/* ------------------------------------------------------------------ */
/*  Domain Validation                                                  */
/* ------------------------------------------------------------------ */

async function validateDomain(
  hostname: string,
): Promise<ValidationResult | null> {
  try {
    const response = await chrome.runtime.sendMessage(
      {
        type: "VALIDATE_DOMAIN",
        hostname,
        expectedDomain: hostname,
      },
    ) as { ok: boolean; data?: ValidationResult; error?: string } | undefined;

    if (response?.ok && response.data) {
      return response.data;
    }
    return null;
  } catch {
    // Extension context invalidated or background unreachable
    return null;
  }
}

/* ------------------------------------------------------------------ */
/*  Blocking UI                                                        */
/* ------------------------------------------------------------------ */

function showBlockingAlert(hostname: string, risk: string): void {
  const overlay = document.createElement("div");
  overlay.id = "cybervault-phishing-overlay";
  overlay.className = CYBERVAULT_BLOCKED_CLASS;

  // SECURITY: Use DOM APIs instead of innerHTML to prevent XSS
  // hostname and risk are user-controlled values that must be sanitized
  const container = document.createElement("div");
  container.style.cssText = "position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.85);z-index:2147483647;display:flex;align-items:center;justify-content:center;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;";

  const card = document.createElement("div");
  card.style.cssText = "background:#1a1a2e;border:2px solid #ff4444;border-radius:12px;padding:32px;max-width:480px;text-align:center;color:#fff;box-shadow:0 8px 32px rgba(255,0,0,0.3);";

  const icon = document.createElement("div");
  icon.style.cssText = "font-size:48px;margin-bottom:16px";
  icon.textContent = "\u26A0\uFE0F";

  const title = document.createElement("h2");
  title.style.cssText = "margin:0 0 12px;color:#ff4444;font-size:20px";
  title.textContent = "Phishing Detected";

  const desc = document.createElement("p");
  desc.style.cssText = "margin:0 0 8px;color:#ccc;font-size:14px";
  desc.appendChild(document.createTextNode("CyberVault has flagged this domain as "));
  const strong = document.createElement("strong");
  // Sanitize risk: only allow known values
  const safeRisk = ["high", "medium", "low", "critical"].includes(risk.toLowerCase()) ? risk : "unknown";
  strong.textContent = safeRisk;
  desc.appendChild(strong);
  desc.appendChild(document.createTextNode(" risk."));

  const domainLine = document.createElement("p");
  domainLine.style.cssText = "margin:0 0 20px;color:#888;font-size:13px";
  domainLine.appendChild(document.createTextNode("Domain: "));
  const code = document.createElement("code");
  code.style.cssText = "color:#ff8888";
  // SECURITY: textContent auto-escapes HTML entities
  code.textContent = hostname;
  domainLine.appendChild(code);

  const btn = document.createElement("button");
  btn.id = "cybervault-dismiss-btn";
  btn.style.cssText = "padding:10px 24px;background:#ff4444;color:#fff;border:none;border-radius:6px;cursor:pointer;font-size:14px;font-weight:bold";
  btn.textContent = "I understand the risk — continue";

  card.append(icon, title, desc, domainLine, btn);
  container.appendChild(card);
  overlay.appendChild(container);

  document.body.appendChild(overlay);

  overlay.querySelector("#cybervault-dismiss-btn")?.addEventListener("click", () => {
    overlay.remove();
  });
}

/* ------------------------------------------------------------------ */
/*  Form Interception                                                  */
/* ------------------------------------------------------------------ */

function interceptFormSubmit(form: HTMLFormElement): void {
  if (blockedForms.has(form)) return;

  form.addEventListener(
    "submit",
    (event) => {
      if (
        lastValidationResult &&
        lastValidationResult.overallRisk !== "low"
      ) {
        event.preventDefault();
        event.stopPropagation();

        if (!blockedForms.has(form)) {
          blockedForms.add(form);
          showBlockingAlert(
            window.location.hostname,
            lastValidationResult.overallRisk,
          );
        }
        return false;
      }
    },
    true,
  );
}

/* ------------------------------------------------------------------ */
/*  Form Scanning                                                      */
/* ------------------------------------------------------------------ */

function scanForLoginForms(): void {
  const passwordInputs = document.querySelectorAll<HTMLInputElement>(
    'input[type="password"]',
  );

  passwordInputs.forEach((input) => {
    const form = input.closest<HTMLFormElement>("form");
    if (form) {
      interceptFormSubmit(form);
    }
  });
}

/* ------------------------------------------------------------------ */
/*  Main                                                               */
/* ------------------------------------------------------------------ */

async function main(): Promise<void> {
  const hostname = window.location.hostname;

  // Skip non-http contexts
  if (!hostname) return;

  // Validate domain in background
  const result = await validateDomain(hostname);
  if (result) {
    lastValidationResult = result;

    if (result.overallRisk !== "low") {
      showBlockingAlert(hostname, result.overallRisk);
    }
  }

  // Initial scan
  scanForLoginForms();

  // Watch for dynamically added forms (SPAs, lazy-loaded content)
  const observer = new MutationObserver((mutations) => {
    let shouldScan = false;
    for (const mutation of mutations) {
      if (mutation.addedNodes.length > 0) {
        shouldScan = true;
        break;
      }
    }
    if (shouldScan) {
      scanForLoginForms();
    }
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true,
  });
}

// Kick off when DOM is ready
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", main);
} else {
  main();
}

})();
