/**
 * CyberVault Popup - Main UI Logic
 * Maneja la interacción del usuario con el popup de la extensión
 */

import {
  escapeHtml,
  getFaviconLetter,
  showModal,
  hideModal,
  copyToClipboard,
} from "../utils";

// ============================================================================
// Types
// ============================================================================

interface PopupCredential {
  id: string;
  title: string;
  username: string;
  url?: string;
  favorite: boolean;
  lastUsed?: string;
  tags: string[];
}

interface VaultStatus {
  isUnlocked: boolean;
  lastSync?: string;
}

// ============================================================================
// State
// ============================================================================

let credentials: PopupCredential[] = [];
let filteredCredentials: PopupCredential[] = [];
let currentTab: "all" | "favorites" | "recent" = "all";

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
});

async function initialize(): Promise<void> {
  setupEventListeners();
  await loadCredentials();
  renderCredentials();
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
}

// ============================================================================
// Data Loading
// ============================================================================

async function loadCredentials(): Promise<void> {
  try {
    // Load from chrome storage
    const stored = await chrome.storage.local.get("credentials");
    credentials = (stored.credentials as PopupCredential[]) || [];
    filteredCredentials = [...credentials];
  } catch (error) {
    console.error("Error loading credentials:", error);
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
    <div class="credential-card" data-id="${cred.id}">
      <div class="credential-icon">${getFaviconLetter(cred.title)}</div>
      <div class="credential-info">
        <div class="credential-title">${escapeHtml(cred.title)}</div>
        <div class="credential-username">${escapeHtml(cred.username)}</div>
      </div>
      <div class="credential-actions">
        ${cred.favorite ? "<span>⭐</span>" : ""}
      </div>
    </div>
  `,
    )
    .join("");

  // Add click handlers
  popupElements.credentialsList
    .querySelectorAll(".credential-card")
    .forEach((card) => {
      card.addEventListener("click", () => {
        const id = (card as HTMLElement).dataset.id;
        if (id) handlePopupCredentialClick(id);
      });
    });
}

function updateVaultStatus(): void {
  // Simulate vault status check
  const statusIcon = popupElements.vaultStatus.querySelector(".status-icon");
  const statusText = popupElements.vaultStatus.querySelector(".status-text");

  if (statusIcon && statusText) {
    // For demo, show as unlocked
    statusIcon.textContent = "🔓";
    statusText.textContent = "Bóveda desbloqueada";
    popupElements.vaultStatus.classList.add("secure");
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

  const title = (document.getElementById("cred-title") as HTMLInputElement)
    .value;
  const url = (document.getElementById("cred-url") as HTMLInputElement).value;
  const username = (
    document.getElementById("cred-username") as HTMLInputElement
  ).value;
  const password = (
    document.getElementById("cred-password") as HTMLInputElement
  ).value;
  const notes = (document.getElementById("cred-notes") as HTMLTextAreaElement)
    .value;
  const tagsStr = (document.getElementById("cred-tags") as HTMLInputElement)
    .value;
  const favorite = (
    document.getElementById("cred-favorite") as HTMLInputElement
  ).checked;

  // Encrypt password (in real app, encrypt with master key)
  const encryptedPassword = btoa(password); // Base64 for demo

  const tags = tagsStr
    .split(",")
    .map((t) => t.trim())
    .filter((t) => t);

  const newPopupCredential: PopupCredential = {
    id: generateId(),
    title,
    username,
    url: url || undefined,
    favorite,
    tags,
    lastUsed: undefined,
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
    console.error("Audit error:", error);
    showNotification("Error al ejecutar audit");
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
// Utils
// ============================================================================

function generateId(): string {
  const array = new Uint8Array(16);
  crypto.getRandomValues(array);
  return Array.from(array, (b) => b.toString(16).padStart(2, "0")).join("");
}
