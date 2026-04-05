/**
 * CyberVault Popup - Main UI Logic
 * Maneja la interacción del usuario con el popup de la extensión
 *
 * SECURITY: Zero Trust Architecture
 * - Never trust input: all data validated before use
 * - Assume breach: no sensitive data in logs
 * - Defense in depth: multiple security layers
 * - Least privilege: minimal data exposure
 * - Zero Knowledge: master key never stored, only verification hash
 */

import {
  escapeHtml,
  escapeAttribute,
  sanitizeUrl,
  getFaviconLetter,
  showModal,
  hideModal,
  copyToClipboard,
} from "../utils";

import {
  generateSecureCredentials,
  validatePasswordEntropy,
  generateSimplePassword,
} from "./credentials-integration";

// SECURITY: Import Master Key Manager for Zero Knowledge
import {
  isVaultInitialized,
  initializeVault,
  unlockVault,
  lockVault,
  isVaultUnlocked,
  encryptWithSessionKey,
  decryptWithSessionKey,
  resetVault,
} from "../../infrastructure/crypto/master-key-manager";

// ============================================================================
// SECURITY: Constants and Config
// ============================================================================

// Maximum values to prevent DoS
const MAX_CREDENTIALS = 1000;
const MAX_PASSWORD_LENGTH = 256;
const MAX_TITLE_LENGTH = 100;
const MAX_USERNAME_LENGTH = 254;
const MAX_URL_LENGTH = 2048;
const MAX_URL_URL = 2048; // Fixed typo
const MAX_NOTES_LENGTH = 10000;
const MAX_TAGS = 20;

// ============================================================================
// Types - Using strict typing for security
// ============================================================================

interface PopupCredential {
  id: string;
  title: string;
  username: string;
  // SECURITY: Password is now encrypted before storage
  encryptedPassword: string;
  url?: string;
  notes?: string;
  favorite: boolean;
  lastUsed?: string;
  createdAt?: string;
  updatedAt?: string;
  tags: string[];
}

interface VaultStatus {
  isUnlocked: boolean;
  lastSync?: string;
}

// ============================================================================
// State - Minimize exposure
// ============================================================================

let credentials: PopupCredential[] = [];
let filteredCredentials: PopupCredential[] = [];
let currentTab: "all" | "favorites" | "recent" = "all";

// SECURITY: Temporary password storage (in-memory, not DOM)
const passwordTokens = new Map<string, string>();

// SECURITY: Track initialization state
let isInitialized = false;

// ============================================================================
// SECURITY: Input Validation
// ============================================================================

/**
 * Sanitize and validate string input
 * SECURITY: Zero Trust - never trust user input
 */
function sanitizeString(input: string, maxLength: number): string {
  if (typeof input !== "string") return "";
  return input.trim().slice(0, maxLength);
}

/**
 * Validate URL format
 * SECURITY: Prevent SSRF and malicious URLs
 */
function isValidUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return ["http:", "https:"].includes(parsed.protocol);
  } catch {
    return false;
  }
}

/**
 * Validate email format
 */
function isValidEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

/**
 * Validate tags
 */
function validateTags(tags: string[]): string[] {
  return tags
    .slice(0, MAX_TAGS)
    .map((t) => sanitizeString(t, 30))
    .filter((t) => t.length > 0);
}

// ============================================================================
// DOM Elements
// ============================================================================

const popupElements = {
  credentialsList: document.getElementById("credentials-list") as HTMLElement,
  searchInput: document.getElementById("search-input") as HTMLInputElement,
  tabs: document.querySelectorAll(".tab") as NodeListOf<HTMLButtonElement>,
  btnAdd: document.getElementById("btn-add") as HTMLButtonElement,
  btnAudit: document.getElementById("btn-audit") as HTMLButtonElement,
  modalAddPopupCredential: document.getElementById(
    "modal-add-credential",
  ) as HTMLElement,
  formAddPopupCredential: document.getElementById(
    "form-add-credential",
  ) as HTMLFormElement,
  passwordGenerator: document.getElementById(
    "password-generator",
  ) as HTMLElement,
  btnGenerate: document.getElementById("btn-generate") as HTMLButtonElement,
  btnCopy: document.getElementById("btn-copy") as HTMLButtonElement,
  generatedPassword: document.getElementById(
    "generated-password",
  ) as HTMLInputElement,
  passwordLength: document.getElementById(
    "password-length",
  ) as HTMLInputElement,
  lengthDisplay: document.getElementById("length-display") as HTMLElement,
  vaultStatus: document.getElementById("vault-status") as HTMLElement,
};

// ============================================================================
// Initialization
// ============================================================================

document.addEventListener("DOMContentLoaded", async () => {
  await initialize();
  // Wake up service worker in background
  wakeUpServiceWorker();
});

// Wake up service worker silently
async function wakeUpServiceWorker(): Promise<void> {
  try {
    await chrome.runtime.sendMessage({ action: "ping" });
    console.log("[CyberVault] Service worker ready");
  } catch {
    // Silent fail - service worker will wake up on next message
  }
}

async function initialize(): Promise<void> {
  setupEventListeners();
  setupMasterKeyListeners();

  // SECURITY: Check vault status first
  const vaultInitialized = await isVaultInitialized();

  if (!vaultInitialized) {
    // First time - show setup modal
    showModal("modal-setup-master-key");
    updateVaultStatus();
    return;
  }

  // Vault exists but needs unlock
  showModal("modal-unlock-vault");
  updateVaultStatus();
}

// ============================================================================
// Event Listeners
// ============================================================================

function setupEventListeners(): void {
  // Search
  popupElements.searchInput.addEventListener("input", handleSearch);

  // Tabs
  popupElements.tabs.forEach((tab) => {
    tab.addEventListener("click", () =>
      handleTabChange(tab.dataset.tab as "all" | "favorites" | "recent"),
    );
  });

  // Add credential button
  popupElements.btnAdd.addEventListener("click", () =>
    showModal("modal-add-credential"),
  );

  // Audit button
  popupElements.btnAudit.addEventListener("click", runAudit);

  // Form submission
  popupElements.formAddPopupCredential.addEventListener(
    "submit",
    handleAddPopupCredential,
  );

  // Modal close buttons
  document.querySelectorAll(".modal-close, [data-modal]").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      const modalId = (e.currentTarget as HTMLElement).dataset.modal;
      if (modalId) hideModal(modalId);
    });
  });

  // Password generator
  popupElements.btnGenerate.addEventListener("click", handleGeneratePassword);
  popupElements.btnCopy.addEventListener("click", copyPassword);
  popupElements.passwordLength.addEventListener("input", () => {
    popupElements.lengthDisplay.textContent =
      popupElements.passwordLength.value;
  });

  // Toggle password visibility
  document.querySelectorAll(".toggle-password").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      const targetId = (e.currentTarget as HTMLElement).dataset.target;
      if (targetId) togglePasswordVisibility(targetId);
    });
  });

  // Generate password inline button
  document.querySelectorAll(".btn-generate-inline").forEach((btn) => {
    btn.addEventListener("click", async (e) => {
      const targetId = (e.currentTarget as HTMLElement).dataset.target;
      if (targetId) {
        await generatePasswordForField(targetId);
      }
    });
  });

  // Edit form submission
  document
    .getElementById("form-edit-credential")
    ?.addEventListener("submit", handleEditCredential);

  // Delete confirmation
  document
    .getElementById("btn-confirm-delete")
    ?.addEventListener("click", handleDeleteCredential);
}

// ============================================================================
// Master Key Event Listeners
// ============================================================================

function setupMasterKeyListeners(): void {
  // Setup master key form
  document
    .getElementById("form-setup-master-key")
    ?.addEventListener("submit", async (e) => {
      e.preventDefault();
      await handleSetupMasterKey();
    });

  // Unlock vault form
  document
    .getElementById("form-unlock-vault")
    ?.addEventListener("submit", async (e) => {
      e.preventDefault();
      await handleUnlockVault();
    });

  // Reset vault button
  document
    .getElementById("btn-reset-vault")
    ?.addEventListener("click", async () => {
      if (
        confirm(
          "⚠️ ¿Estás seguro? Esto eliminará TODAS tus credenciales. Esta acción no se puede deshacer.",
        )
      ) {
        await resetVault();
        window.location.reload();
      }
    });
}

// Handle master key setup (first time)
async function handleSetupMasterKey(): Promise<void> {
  const masterKey =
    (document.getElementById("master-key") as HTMLInputElement)?.value ?? "";
  const confirmKey =
    (document.getElementById("master-key-confirm") as HTMLInputElement)
      ?.value ?? "";
  const understood =
    (document.getElementById("master-key-understood") as HTMLInputElement)
      ?.checked ?? false;

  // Validate
  if (!masterKey || !confirmKey) {
    showNotification("Error: Completa todos los campos");
    return;
  }

  if (!understood) {
    showNotification("Error: Debes confirmar que entiendes el riesgo");
    return;
  }

  if (masterKey !== confirmKey) {
    showNotification("Error: Las claves no coinciden");
    return;
  }

  if (masterKey.length < 12) {
    showNotification("Error: La clave debe tener al menos 12 caracteres");
    return;
  }

  // Initialize vault
  const result = await initializeVault(masterKey);

  if (result.success) {
    hideModal("modal-setup-master-key");
    showNotification("🎉 Bóveda creada correctamente");
    await loadCredentials();
    renderCredentials();
    updateVaultStatus();
  } else {
    showNotification(result.error || "Error al crear la bóveda");
  }
}

// Handle vault unlock
async function handleUnlockVault(): Promise<void> {
  const masterKey =
    (document.getElementById("unlock-key") as HTMLInputElement)?.value ?? "";

  if (!masterKey) {
    showNotification("Error: Ingresa tu clave maestra");
    return;
  }

  // Attempt unlock
  const result = await unlockVault(masterKey);

  if (result.success) {
    hideModal("modal-unlock-vault");
    showNotification("🔓 Bóveda desbloqueada");
    await loadCredentials();
    renderCredentials();
    updateVaultStatus();
  } else {
    showNotification(result.error || "Error al desbloquear");
  }
}

// ============================================================================
// Data Loading
// ============================================================================

async function loadCredentials(): Promise<void> {
  try {
    // SECURITY: Validate data structure on load
    const stored = await chrome.storage.local.get("credentials");
    const rawData = stored.credentials;

    if (!Array.isArray(rawData)) {
      credentials = [];
    } else {
      // SECURITY: Validate each credential
      credentials = rawData
        .slice(0, MAX_CREDENTIALS)
        .filter((c): c is PopupCredential => {
          return (
            typeof c === "object" &&
            typeof c.id === "string" &&
            typeof c.title === "string" &&
            typeof c.username === "string" &&
            typeof c.encryptedPassword === "string"
          );
        });
    }

    filteredCredentials = [...credentials];

    // SECURITY: Never log credentials - only count
    console.log("[CyberVault] Credentials loaded:", credentials.length);
  } catch (error) {
    // SECURITY: Generic error message, no sensitive data
    console.error("Error loading credentials");
    credentials = [];
    filteredCredentials = [];
  }
}

async function saveCredentials(): Promise<void> {
  try {
    await chrome.storage.local.set({ credentials });
  } catch (error) {
    console.error("Error saving credentials:", error);
  }
}

// ============================================================================
// Rendering
// ============================================================================

function renderCredentials(): void {
  if (filteredCredentials.length === 0) {
    popupElements.credentialsList.innerHTML = `
      <div class="empty-state">
        <div class="empty-state-icon">🔑</div>
        <p>No hay credenciales</p>
        <p style="font-size: 12px; margin-top: 4px;">Click en "Nueva Credencial" para agregar</p>
      </div>
    `;
    return;
  }

  popupElements.credentialsList.innerHTML = filteredCredentials
    .map(
      (cred) => `
    <div class="credential-card" data-id="${escapeAttribute(cred.id)}">
      <div class="credential-icon">${getFaviconLetter(cred.title)}</div>
      <div class="credential-info">
        <div class="credential-title">${escapeHtml(cred.title)}</div>
        <div class="credential-username">${escapeHtml(cred.username)}</div>
      </div>
      <div class="credential-actions">
        ${cred.favorite ? "<span>⭐</span>" : ""}
        <button class="action-icon" data-action="view" data-id="${escapeAttribute(cred.id)}" title="Ver">👁️</button>
        <button class="action-icon" data-action="edit" data-id="${escapeAttribute(cred.id)}" title="Editar">✏️</button>
        <button class="action-icon" data-action="delete" data-id="${escapeAttribute(cred.id)}" title="Eliminar">🗑️</button>
      </div>
    </div>
  `,
    )
    .join("");

  // Add click handlers for card and actions
  popupElements.credentialsList
    .querySelectorAll(".credential-card")
    .forEach((card) => {
      card.addEventListener("click", (e) => {
        // Don't trigger if clicking on action buttons
        if ((e.target as HTMLElement).closest(".action-icon")) return;
        const id = (card as HTMLElement).dataset.id;
        if (id) handlePopupCredentialClick(id);
      });
    });

  // Action buttons handlers
  popupElements.credentialsList
    .querySelectorAll(".action-icon")
    .forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        const action = (btn as HTMLElement).dataset.action;
        const id = (btn as HTMLElement).dataset.id;
        if (action === "view") handleViewClick(id!);
        else if (action === "edit") handleEditClick(id!);
        else if (action === "delete") handleDeleteClick(id!);
      });
    });
}

function updateVaultStatus(): void {
  // SECURITY: Check actual vault status
  const statusIcon = popupElements.vaultStatus.querySelector(".status-icon");
  const statusText = popupElements.vaultStatus.querySelector(".status-text");
  const appContainer = document.querySelector(".app-container");

  const isUnlocked = isVaultUnlocked();

  if (statusIcon && statusText) {
    if (isUnlocked) {
      statusIcon.textContent = "🔓";
      statusText.textContent = "Bóveda desbloqueada";
      popupElements.vaultStatus.classList.add("secure");
      // Enable the app when unlocked
      appContainer?.classList.remove("locked");
    } else {
      statusIcon.textContent = "🔒";
      statusText.textContent = "Bóveda bloqueada";
      popupElements.vaultStatus.classList.remove("secure");
      // Lock the app when locked
      appContainer?.classList.add("locked");
    }
  }
}

// ============================================================================
// Handlers
// ============================================================================

function handleSearch(): void {
  const query = popupElements.searchInput.value.toLowerCase();
  filterPopupCredentials(query, currentTab);
}

function handleTabChange(tab: "all" | "favorites" | "recent"): void {
  // Update active tab
  popupElements.tabs.forEach((t) => t.classList.remove("active"));
  document.querySelector(`.tab[data-tab="${tab}"]`)?.classList.add("active");

  currentTab = tab;
  filterPopupCredentials(popupElements.searchInput.value.toLowerCase(), tab);
}

function filterPopupCredentials(
  query: string,
  tab: "all" | "favorites" | "recent",
): void {
  filteredCredentials = credentials.filter((cred) => {
    // Tab filter
    if (tab === "favorites" && !cred.favorite) return false;
    if (tab === "recent" && !cred.lastUsed) return false;

    // Search filter
    if (query) {
      const searchStr =
        `${cred.title} ${cred.username} ${cred.url || ""} ${cred.tags.join(" ")}`.toLowerCase();
      return searchStr.includes(query);
    }

    return true;
  });

  renderCredentials();
}

async function handlePopupCredentialClick(id: string): Promise<void> {
  const cred = credentials.find((c) => c.id === id);
  if (!cred) return;

  // Update last used
  cred.lastUsed = new Date().toISOString();
  await saveCredentials();

  // Copy username to clipboard
  await navigator.clipboard.writeText(cred.username);

  // Show notification
  showNotification(`Usuario copiado: ${cred.username}`);
}

async function handleAddPopupCredential(e: Event): Promise<void> {
  e.preventDefault();

  // SECURITY: Get raw values
  const titleRaw =
    (document.getElementById("cred-title") as HTMLInputElement)?.value ?? "";
  const urlRaw =
    (document.getElementById("cred-url") as HTMLInputElement)?.value ?? "";
  const usernameRaw =
    (document.getElementById("cred-username") as HTMLInputElement)?.value ?? "";
  const passwordRaw =
    (document.getElementById("cred-password") as HTMLInputElement)?.value ?? "";
  const notesRaw =
    (document.getElementById("cred-notes") as HTMLTextAreaElement)?.value ?? "";
  const tagsStr =
    (document.getElementById("cred-tags") as HTMLInputElement)?.value ?? "";
  const favorite =
    (document.getElementById("cred-favorite") as HTMLInputElement)?.checked ??
    false;

  // SECURITY: Validate and sanitize input
  const title = sanitizeString(titleRaw, MAX_TITLE_LENGTH);
  const username = sanitizeString(usernameRaw, MAX_USERNAME_LENGTH);
  const password = sanitizeString(passwordRaw, MAX_PASSWORD_LENGTH);
  const notes = sanitizeString(notesRaw, MAX_NOTES_LENGTH);
  const url = urlRaw ? sanitizeString(urlRaw, MAX_URL_URL) : undefined;

  // Validate required fields
  if (!title || !username || !password) {
    showNotification("Error: Título, usuario y contraseña son requeridos");
    return;
  }

  // SECURITY: Validate URL if provided
  if (url && !isValidUrl(url)) {
    showNotification("Error: URL inválida");
    return;
  }

  // SECURITY: Validate username format (email)
  if (!isValidEmail(username)) {
    showNotification("Warning: El formato de usuario no es un email");
  }

  // Validate password strength
  const entropyResult = validatePasswordEntropy(password);
  if (entropyResult.strength === "weak") {
    showNotification("Warning: Contraseña débil, considera usar el generador");
  }

  const tags = validateTags(tagsStr.split(","));

  // SECURITY: Check vault is unlocked
  if (!isVaultUnlocked()) {
    showNotification("Error: Bóveda bloqueada. Desbloquea primero.");
    showModal("modal-unlock-vault");
    return;
  }

  // SECURITY: Encrypt password with session key (Zero Knowledge)
  const encryptedPassword = await encryptWithSessionKey(password);

  if (!encryptedPassword) {
    showNotification("Error: No se pudo encriptar la contraseña");
    return;
  }

  const newPopupCredential: PopupCredential = {
    id: generateId(),
    title,
    username,
    encryptedPassword, // SECURITY: Store encrypted with session key
    url,
    notes: notes || undefined,
    favorite,
    tags,
    lastUsed: undefined,
    createdAt: new Date().toISOString(),
  };

  credentials.push(newPopupCredential);
  await saveCredentials();

  hideModal("modal-add-credential");
  popupElements.formAddPopupCredential.reset();

  filterPopupCredentials(
    popupElements.searchInput.value.toLowerCase(),
    currentTab,
  );
  showNotification("Credencial guardada correctamente");
}

async function runAudit(): Promise<void> {
  try {
    // Function to ping service worker with retry
    const pingWithRetry = async (
      retries = 3,
      delay = 300,
    ): Promise<boolean> => {
      for (let i = 0; i < retries; i++) {
        try {
          await chrome.runtime.sendMessage({ action: "ping" });
          return true;
        } catch {
          console.warn(
            `Ping attempt ${i + 1} failed, retrying in ${delay}ms...`,
          );
          await new Promise((r) => setTimeout(r, delay));
        }
      }
      return false;
    };

    // Try to wake up service worker with retry
    const isReady = await pingWithRetry();
    if (!isReady) {
      console.warn("Service worker not responding after retries");
    }

    // Send message to background script to run audit
    const response = await chrome.runtime.sendMessage({ action: "run_audit" });

    if (response && response.findings) {
      const criticalCount = response.findings.filter(
        (f: { severity: string }) => f.severity === "CRITICAL",
      ).length;
      const highCount = response.findings.filter(
        (f: { severity: string }) => f.severity === "HIGH",
      ).length;

      showNotification(`Audit: ${criticalCount} críticos, ${highCount} altos`);
    } else {
      showNotification("Audit completado: Sin vulnerabilidades");
    }
  } catch (error) {
    console.warn("Audit no disponible:", error);
    showNotification("Audit: Función no disponible");
  }
}

// ============================================================================
// Password Generator
// ============================================================================

function handleGeneratePassword(): void {
  const length = parseInt(popupElements.passwordLength.value);
  const uppercase = (
    document.getElementById("opt-uppercase") as HTMLInputElement
  ).checked;
  const lowercase = (
    document.getElementById("opt-lowercase") as HTMLInputElement
  ).checked;
  const numbers = (document.getElementById("opt-numbers") as HTMLInputElement)
    .checked;
  const symbols = (document.getElementById("opt-symbols") as HTMLInputElement)
    .checked;

  let chars = "";
  if (uppercase) chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  if (lowercase) chars += "abcdefghijklmnopqrstuvwxyz";
  if (numbers) chars += "0123456789";
  if (symbols) chars += "!@#$%^&*()_+-=[]{}|;:,.<>?";

  if (!chars) {
    showNotification("Selecciona al menos un tipo de carácter");
    return;
  }

  let password = "";
  const array = new Uint32Array(length);
  crypto.getRandomValues(array);

  for (let i = 0; i < length; i++) {
    password += chars[array[i] % chars.length];
  }

  popupElements.generatedPassword.value = password;
}

async function copyPassword(): Promise<void> {
  const password = popupElements.generatedPassword.value;
  if (!password) {
    showNotification("Genera una contraseña primero");
    return;
  }

  await navigator.clipboard.writeText(password);
  showNotification("Contraseña copiada");
}

function togglePasswordVisibility(inputId: string): void {
  const input = document.getElementById(inputId) as HTMLInputElement;
  if (input.type === "password") {
    input.type = "text";
  } else {
    input.type = "password";
  }
}

async function generatePasswordForField(targetId: string): Promise<void> {
  try {
    // Get current domain
    const [tab] = await chrome.tabs.query({
      active: true,
      currentWindow: true,
    });
    let domain = "example.com";

    if (tab.url) {
      try {
        const url = new URL(tab.url);
        domain = url.hostname;
      } catch (e) {
        console.warn("No se pudo extraer dominio");
      }
    }

    // Generate credentials with salt and pepper
    const result = await generateSecureCredentials(domain);

    // Set password in the target field
    const input = document.getElementById(targetId) as HTMLInputElement;
    if (input) {
      input.value = result.originalPassword;
    }

    // Validate entropy
    const entropyResult = validatePasswordEntropy(result.originalPassword);
    showNotification(
      `Contraseña generada (entropía: ${entropyResult.strength})`,
    );
  } catch (error) {
    console.error("Error generating password:", error);
    showNotification("Error al generar contraseña");
  }
}

// ============================================================================
// Notifications
// ============================================================================

function showNotification(message: string): void {
  // Simple notification - in real app use chrome.notifications
  const existing = document.querySelector(".toast-notification");
  if (existing) existing.remove();

  const toast = document.createElement("div");
  toast.className = "toast-notification";
  toast.textContent = message;
  toast.style.cssText = `
    position: fixed;
    bottom: 20px;
    left: 50%;
    transform: translateX(-50%);
    background: #0f172a;
    color: white;
    padding: 10px 20px;
    border-radius: 8px;
    font-size: 13px;
    z-index: 1000;
    animation: fadeIn 0.2s ease;
  `;

  document.body.appendChild(toast);

  setTimeout(() => {
    toast.style.animation = "fadeOut 0.2s ease";
    setTimeout(() => toast.remove(), 200);
  }, 2000);
}

// ============================================================================
// CRUD Operations
// ============================================================================

function handleEditClick(id: string): void {
  const cred = credentials.find((c) => c.id === id);
  if (!cred) return;

  // Populate edit form
  // SECURITY: Never show actual password, use placeholder
  (document.getElementById("edit-cred-id") as HTMLInputElement).value = cred.id;
  (document.getElementById("edit-cred-title") as HTMLInputElement).value =
    cred.title || "";
  (document.getElementById("edit-cred-url") as HTMLInputElement).value =
    cred.url || "";
  (document.getElementById("edit-cred-username") as HTMLInputElement).value =
    cred.username || "";
  (document.getElementById("edit-cred-password") as HTMLInputElement).value =
    ""; // SECURITY: Never expose
  (document.getElementById("edit-cred-notes") as HTMLTextAreaElement).value =
    cred.notes || "";
  (document.getElementById("edit-cred-tags") as HTMLInputElement).value = (
    cred.tags || []
  ).join(", ");
  (document.getElementById("edit-cred-favorite") as HTMLInputElement).checked =
    cred.favorite || false;

  showModal("modal-edit-credential");
}

async function handleEditCredential(e: Event): Promise<void> {
  e.preventDefault();

  const id = (document.getElementById("edit-cred-id") as HTMLInputElement)
    .value;
  const title = sanitizeString(
    (document.getElementById("edit-cred-title") as HTMLInputElement)?.value ??
      "",
    MAX_TITLE_LENGTH,
  );
  const url =
    (document.getElementById("edit-cred-url") as HTMLInputElement)?.value ?? "";
  const username = sanitizeString(
    (document.getElementById("edit-cred-username") as HTMLInputElement)
      ?.value ?? "",
    MAX_USERNAME_LENGTH,
  );
  const passwordInput =
    (document.getElementById("edit-cred-password") as HTMLInputElement)
      ?.value ?? "";
  const notes = sanitizeString(
    (document.getElementById("edit-cred-notes") as HTMLTextAreaElement)
      ?.value ?? "",
    MAX_NOTES_LENGTH,
  );
  const tagsStr =
    (document.getElementById("edit-cred-tags") as HTMLInputElement)?.value ??
    "";
  const favorite =
    (document.getElementById("edit-cred-favorite") as HTMLInputElement)
      ?.checked ?? false;

  // SECURITY: Only update password if new one provided
  let encryptedPassword = "";
  if (passwordInput) {
    // SECURITY: Check vault is unlocked
    if (!isVaultUnlocked()) {
      showNotification("Error: Bóveda bloqueada");
      return;
    }
    encryptedPassword = (await encryptWithSessionKey(passwordInput)) ?? "";
  }

  const tags = validateTags(tagsStr.split(","));

  // Find and update credential
  const index = credentials.findIndex((c) => c.id === id);
  if (index === -1) {
    showNotification("Error: Credencial no encontrada");
    return;
  }

  // SECURITY: Keep existing encrypted password if not changed
  const finalEncryptedPassword =
    encryptedPassword || credentials[index].encryptedPassword;

  credentials[index] = {
    ...credentials[index],
    title,
    username,
    encryptedPassword: finalEncryptedPassword,
    url: url || undefined,
    notes: notes || undefined,
    tags,
    favorite,
    updatedAt: new Date().toISOString(),
  };

  await saveCredentials();
  hideModal("modal-edit-credential");
  filterPopupCredentials(
    popupElements.searchInput.value.toLowerCase(),
    currentTab,
  );
  showNotification("Credencial actualizada correctamente");
}

function handleDeleteClick(id: string): void {
  const cred = credentials.find((c) => c.id === id);
  if (!cred) return;

  (document.getElementById("delete-cred-id") as HTMLInputElement).value = id;
  (document.getElementById("delete-cred-title") as HTMLElement).textContent =
    cred.title;
  showModal("modal-delete-confirm");
}

async function handleDeleteCredential(): Promise<void> {
  const id = (document.getElementById("delete-cred-id") as HTMLInputElement)
    .value;
  const index = credentials.findIndex((c) => c.id === id);

  if (index === -1) {
    showNotification("Error: Credencial no encontrada");
    hideModal("modal-delete-confirm");
    return;
  }

  credentials.splice(index, 1);
  await saveCredentials();

  hideModal("modal-delete-confirm");
  filterPopupCredentials(
    popupElements.searchInput.value.toLowerCase(),
    currentTab,
  );
  showNotification("Credencial eliminada");
}

function handleViewClick(id: string): void {
  const cred = credentials.find((c) => c.id === id);
  if (!cred) return;

  const content = document.getElementById(
    "view-credential-content",
  ) as HTMLElement;

  // SECURITY: Generate a one-time token for password copy
  const passwordToken = crypto.randomUUID();
  // Store encrypted password temporarily in memory (not in DOM)
  passwordTokens.set(passwordToken, cred.encryptedPassword);

  content.innerHTML = `
     <div class="view-detail">
       <label>Título</label>
       <p>${escapeHtml(cred.title || "-")}</p>
     </div>
     <div class="view-detail">
       <label>URL</label>
       <p>${cred.url ? `<a href="${sanitizeUrl(cred.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(cred.url)}</a>` : "-"}</p>
     </div>
     <div class="view-detail">
       <label>Usuario</label>
       <p>${escapeHtml(cred.username || "-")}</p>
     </div>
     <div class="view-detail">
       <label>Contraseña</label>
       <p class="password-display">
         <span class="masked">••••••••</span>
         <button class="btn-link" data-action="copy-password" data-token="${escapeAttribute(passwordToken)}">Copiar</button>
       </p>
     </div>
     <div class="view-detail">
       <label>Notas</label>
       <p>${escapeHtml(cred.notes || "-")}</p>
     </div>
     <div class="view-detail">
       <label>Etiquetas</label>
       <p>${(cred.tags || []).length ? cred.tags.map((t) => `<span class="tag">${escapeHtml(t)}</span>`).join(" ") : "-"}</p>
     </div>
     <div class="view-detail">
       <label>Creada</label>
       <p>${cred.createdAt ? new Date(cred.createdAt).toLocaleString() : "-"}</p>
     </div>
   `;

  // Add copy password handler using token - DECRYPT on copy
  content
    .querySelector('[data-action="copy-password"]')
    ?.addEventListener("click", async (e) => {
      const token = (e.target as HTMLElement).dataset.token;
      const encryptedPassword = token ? passwordTokens.get(token) : undefined;

      if (!encryptedPassword) {
        showNotification("Error: Token inválido");
        return;
      }

      // SECURITY: Check vault is unlocked
      if (!isVaultUnlocked()) {
        showNotification("Error: Bóveda bloqueada");
        return;
      }

      // SECURITY: Decrypt password with session key
      const decryptedPassword = await decryptWithSessionKey(encryptedPassword);

      if (decryptedPassword) {
        await navigator.clipboard.writeText(decryptedPassword);
        showNotification("Contraseña copiada");
      } else {
        showNotification("Error: No se pudo desencriptar");
      }

      // Clean up token
      passwordTokens.delete(token);
    });

  showModal("modal-view-credential");
}

// ============================================================================
// Utils
// ============================================================================

function generateId(): string {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return Array.from(array, (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * SECURITY: Hash password for storage
 * Uses SHA-256 with salt - NOT for authentication, just for storage protection
 * In production, use proper encryption with master key via CryptoService
 */
async function hashForStorage(password: string): Promise<string> {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(password + "cybervault_salt");
  const hashBuffer = await crypto.subtle.digest("SHA-256", dataBuffer);
  const hashArray = new Uint8Array(hashBuffer);
  // Convert to base64
  return btoa(String.fromCharCode(...hashArray));
}

/**
 * SECURITY: Verify stored password hash
 */
async function verifyStoredPassword(
  password: string,
  storedHash: string,
): Promise<boolean> {
  const hash = await hashForStorage(password);
  // Use timing-safe comparison
  return timingSafeEqual(hash, storedHash);
}

/**
 * SECURITY: Constant-time string comparison
 * Prevents timing attacks
 */
function timingSafeEqual(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}
