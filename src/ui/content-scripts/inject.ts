/**
 * Content Script - Inyección en páginas
 * Detecta formularios de login y facilita el autofill de credenciales
 */

console.log("[CyberVault] Content script cargado");

// ============================================================================
// Types
// ============================================================================

interface PageCredential {
  id: string;
  title: string;
  username: string;
  url: string;
  password?: string; // Solo presente si el usuario lo solicita
}

interface SiteCredentials {
  domain: string;
  credentials: PageCredential[];
}

// ============================================================================
// State
// ============================================================================

let isEnabled: boolean = true;
let currentPageCredentials: PageCredential[] = [];

// ============================================================================
// DOM Detection
// ============================================================================

/**
 * Detecta todos los formularios de login en la página
 */
function detectLoginForms(): HTMLFormElement[] {
  const selectors = [
    'form[action*="login"]',
    'form[action*="signin"]',
    'form[id*="login"]',
    'form[id*="signin"]',
    'form[class*="login"]',
    'form[class*="signin"]',
    'form[name="loginForm"]',
    'form[name="signinForm"]',
    // Formularios genéricos con inputs de password
    'form:has(input[type="password"])',
  ];

  const forms: HTMLFormElement[] = [];

  for (const selector of selectors) {
    try {
      const matched = document.querySelectorAll<HTMLFormElement>(selector);
      matched.forEach((form) => {
        if (!forms.includes(form)) {
          forms.push(form);
        }
      });
    } catch (e) {
      // Selector puede no ser válido en algunos navegadores
    }
  }

  return forms;
}

/**
 * Detecta campos de username/email en la página
 */
function detectUsernameFields(): HTMLInputElement[] {
  const selectors = [
    'input[type="email"]',
    'input[type="text"][name*="user"]',
    'input[type="text"][name*="email"]',
    'input[type="text"][id*="user"]',
    'input[type="text"][id*="email"]',
    'input[name="username"]',
    'input[name="email"]',
    'input[id="username"]',
    'input[id="email"]',
  ];

  const fields: HTMLInputElement[] = [];

  for (const selector of selectors) {
    const matched = document.querySelectorAll<HTMLInputElement>(selector);
    matched.forEach((field) => {
      if (!fields.includes(field)) {
        fields.push(field);
      }
    });
  }

  return fields;
}

/**
 * Detecta campos de password
 */
function detectPasswordFields(): HTMLInputElement[] {
  const fields = document.querySelectorAll<HTMLInputElement>(
    'input[type="password"]',
  );
  return Array.from(fields);
}

// ============================================================================
// PageCredential Filling
// ============================================================================

/**
 * Busca credenciales para el dominio actual
 */
async function findPageCredentialsForDomain(): Promise<PageCredential[]> {
  const domain = window.location.hostname;

  try {
    // Mensaje al background script
    const response = await chrome.runtime.sendMessage({
      action: "getPageCredentialsForDomain",
      domain,
    });

    return response?.credentials || [];
  } catch (error) {
    console.error("[CyberVault] Error buscando credenciales:", error);
    return [];
  }
}

/**
 * Rellena las credenciales en el formulario
 */
function fillPageCredentials(credential: PageCredential): void {
  const usernameFields = detectUsernameFields();
  const passwordFields = detectPasswordFields();

  // Rellenar username
  if (usernameFields.length > 0) {
    const primaryField = usernameFields[0];
    primaryField.value = credential.username;
    primaryField.dispatchEvent(new Event("input", { bubbles: true }));
    primaryField.dispatchEvent(new Event("change", { bubbles: true }));
  }

  // Rellenar password
  if (passwordFields.length > 0 && credential.password) {
    const primaryPassword = passwordFields[0];
    primaryPassword.value = credential.password;
    primaryPassword.dispatchEvent(new Event("input", { bubbles: true }));
    primaryPassword.dispatchEvent(new Event("change", { bubbles: true }));
  }
}

/**
 * Crea el UI overlay para seleccionar credenciales
 */
function createPageCredentialSelector(credentials: PageCredential[]): void {
  // Remover selector existente si hay
  removePageCredentialSelector();

  const selector = document.createElement("div");
  selector.id = "cybervault-credential-selector";
  selector.innerHTML = `
    <style>
      #cybervault-credential-selector {
        position: fixed;
        bottom: 20px;
        right: 20px;
        z-index: 999999;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      }
      .cybervault-selector-btn {
        width: 48px;
        height: 48px;
        border-radius: 50%;
        background: #2563eb;
        color: white;
        border: none;
        cursor: pointer;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        font-size: 20px;
        display: flex;
        align-items: center;
        justify-content: center;
        transition: transform 0.2s, background 0.2s;
      }
      .cybervault-selector-btn:hover {
        transform: scale(1.1);
        background: #1d4ed8;
      }
      .cybervault-dropdown {
        position: absolute;
        bottom: 60px;
        right: 0;
        background: white;
        border-radius: 8px;
        box-shadow: 0 4px 20px rgba(0,0,0,0.15);
        min-width: 280px;
        max-height: 400px;
        overflow-y: auto;
        display: none;
      }
      .cybervault-dropdown.show {
        display: block;
      }
      .cybervault-dropdown-header {
        padding: 12px 16px;
        border-bottom: 1px solid #e2e8f0;
        font-weight: 600;
        color: #0f172a;
      }
      .cybervault-credential-item {
        padding: 12px 16px;
        cursor: pointer;
        border-bottom: 1px solid #f1f5f9;
        transition: background 0.2s;
      }
      .cybervault-credential-item:hover {
        background: #f8fafc;
      }
      .cybervault-credential-item:last-child {
        border-bottom: none;
      }
      .cybervault-credential-title {
        font-weight: 500;
        color: #0f172a;
        margin-bottom: 4px;
      }
      .cybervault-credential-username {
        font-size: 12px;
        color: #64748b;
      }
      .cybervault-empty {
        padding: 16px;
        text-align: center;
        color: #94a3b8;
        font-size: 13px;
      }
    </style>
    <button class="cybervault-selector-btn" title="CyberVault - Seleccionar credencial">
      🔐
    </button>
    <div class="cybervault-dropdown">
      <div class="cybervault-dropdown-header">
        Credenciales guardadas
      </div>
      ${
        credentials.length === 0
          ? '<div class="cybervault-empty">No hay credenciales para este sitio</div>'
          : credentials
              .map(
                (cred) => `
          <div class="cybervault-credential-item" data-username="${cred.username}" data-password="${cred.password || ""}">
            <div class="cybervault-credential-title">${escapeHtml(cred.title)}</div>
            <div class="cybervault-credential-username">${escapeHtml(cred.username)}</div>
          </div>
        `,
              )
              .join("")
      }
    </div>
  `;

  document.body.appendChild(selector);

  // Event listeners
  const btn = selector.querySelector(".cybervault-selector-btn");
  const dropdown = selector.querySelector(".cybervault-dropdown");

  btn?.addEventListener("click", () => {
    dropdown?.classList.toggle("show");
  });

  // Click fuera para cerrar
  document.addEventListener("click", (e) => {
    if (!selector.contains(e.target as Node)) {
      dropdown?.classList.remove("show");
    }
  });

  // Click en credencial
  selector.querySelectorAll(".cybervault-credential-item").forEach((item) => {
    item.addEventListener("click", () => {
      const username = item.getAttribute("data-username");
      const password = item.getAttribute("data-password");

      // Buscar credencial completa
      const cred = credentials.find((c) => c.username === username);
      if (cred) {
        fillPageCredentials(cred);
        dropdown?.classList.remove("show");
      }
    });
  });
}

function removePageCredentialSelector(): void {
  const existing = document.getElementById("cybervault-credential-selector");
  if (existing) {
    existing.remove();
  }
}

// ============================================================================
// Password Generator
// ============================================================================

/**
 * Crea botón de generación de password
 */
function createPasswordGenerator(): void {
  const passwordFields = detectPasswordFields();

  passwordFields.forEach((field) => {
    if (field.nextElementSibling?.classList.contains("cybervault-gen-btn")) {
      return; // Ya tiene botón
    }

    const genBtn = document.createElement("button");
    genBtn.type = "button";
    genBtn.className = "cybervault-gen-btn";
    genBtn.textContent = "🎲";
    genBtn.title = "Generar contraseña segura";
    genBtn.style.cssText = `
      margin-left: 4px;
      padding: 4px 8px;
      background: #f1f5f9;
      border: 1px solid #e2e8f0;
      border-radius: 4px;
      cursor: pointer;
      font-size: 14px;
    `;

    genBtn.addEventListener("click", async (e) => {
      e.preventDefault();
      e.stopPropagation();

      const password = await generateSecurePassword(16);
      field.value = password;
      field.dispatchEvent(new Event("input", { bubbles: true }));
      field.dispatchEvent(new Event("change", { bubbles: true }));
    });

    field.parentElement?.insertBefore(genBtn, field.nextSibling);
  });
}

/**
 * Genera contraseña segura
 */
async function generateSecurePassword(length: number): Promise<string> {
  const charset =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=";
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);

  let password = "";
  for (let i = 0; i < length; i++) {
    password += charset[array[i] % charset.length];
  }

  return password;
}

// ============================================================================
// Security Analysis
// ============================================================================

/**
 * Analiza la seguridad de la página actual
 */
function analyzePageSecurity(): {
  hasHTTPS: boolean;
  hasLoginForm: boolean;
  hasPasswordField: boolean;
  isTrusted: boolean;
} {
  const hasHTTPS = window.location.protocol === "https:";
  const hasLoginForm = detectLoginForms().length > 0;
  const hasPasswordField = detectPasswordFields().length > 0;

  // Verificar si es un dominio conocido
  // TODO: Verificar contra lista de dominios confiable

  return {
    hasHTTPS,
    hasLoginForm,
    hasPasswordField,
    isTrusted: hasHTTPS,
  };
}

// ============================================================================
// Message Handling
// ============================================================================

// Escuchar mensajes del popup/background
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  switch (message.action) {
    case "fillPageCredential":
      const cred = currentPageCredentials.find(
        (c) => c.id === message.credentialId,
      );
      if (cred) {
        fillPageCredentials(cred);
        sendResponse({ success: true });
      } else {
        sendResponse({ success: false, error: "PageCredential not found" });
      }
      break;

    case "getPageInfo":
      sendResponse({
        url: window.location.href,
        domain: window.location.hostname,
        security: analyzePageSecurity(),
        forms: detectLoginForms().length,
      });
      break;

    case "toggle":
      isEnabled = message.enabled;
      if (isEnabled) {
        init();
      } else {
        removePageCredentialSelector();
      }
      sendResponse({ success: true });
      break;

    default:
      sendResponse({ error: "Unknown action" });
  }

  return true;
});

// ============================================================================
// Initialization
// ============================================================================

async function init(): Promise<void> {
  if (!isEnabled) return;

  // Detectar si hay formularios de login
  const loginForms = detectLoginForms();
  const passwordFields = detectPasswordFields();

  if (loginForms.length > 0 || passwordFields.length > 0) {
    console.log(
      "[CyberVault] Formularios detectados, buscando credenciales...",
    );

    // Buscar credenciales para este dominio
    const credentials = await findPageCredentialsForDomain();
    currentPageCredentials = credentials;

    // Crear UI si hay credenciales
    if (credentials.length > 0) {
      createPageCredentialSelector(credentials);
    }

    // Añadir botones de generación de password
    createPasswordGenerator();
  }
}

// Ejecutar cuando el DOM esté listo
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}

// También ejecutar en SPAs cuando cambie el URL
let lastUrl = window.location.href;
new MutationObserver(() => {
  if (window.location.href !== lastUrl) {
    lastUrl = window.location.href;
    init();
  }
}).observe(document.body, { childList: true, subtree: true });

// Utils
function escapeHtml(text: string): string {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}
