/**
 * CyberVault Popup - Refactorizado con PopupOrchestrator
 * Ahora solo maneja DOM events y delega toda la lógica al orchestrator
 */

import { popupOrchestrator } from "./PopupOrchestrator";

// ============================================================================
// State - Mantener estado mínimo
// ============================================================================

let currentTab: "all" | "favorites" | "recent" = "all";

// ============================================================================
// Utils - Funciones helper para rendering
// ============================================================================

function escapeHtml(text: string): string {
  const div = document.createElement("div");
  div.textContent = text;
  return div.innerHTML;
}

function escapeAttribute(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function getFaviconLetter(title: string): string {
  return title ? title.charAt(0).toUpperCase() : "?";
}

function sanitizeString(input: string, maxLength: number): string {
  if (typeof input !== "string") return "";
  return input.trim().slice(0, maxLength);
}

function isValidUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return ["http:", "https:"].includes(parsed.protocol);
  } catch {
    return false;
  }
}

function isValidEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

function validateTags(tags: string[]): string[] {
  return tags
    .slice(0, 20)
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
  wakeUpServiceWorker();
});

async function initialize(): Promise<void> {
  setupEventListeners();
  setupMasterKeyListeners();

  // Suscribirse a eventos del orchestrator
  popupOrchestrator.on("status:changed", updateVaultStatus);
  popupOrchestrator.on("credentials:changed", renderCredentials);
  popupOrchestrator.on("notification:show", (message) =>
    showNotification(message),
  );
  popupOrchestrator.on("loading", (payload) => {
    if (payload.isLoading) {
      // Podríamos mostrar spinner aquí
    }
  });
  popupOrchestrator.on("error", (error) => {
    console.error("Orchestrator error:", error);
  });

  // Inicializar orchestrator
  await popupOrchestrator.initialize();

  // Verificar estado de la bóveda y mostrar modal apropiado
  const status = popupOrchestrator.getVaultStatus();

  if (!status.initialized) {
    popupOrchestrator.showModal("modal-setup-master-key");
  } else if (!status.unlocked) {
    popupOrchestrator.showModal("modal-unlock-vault");
  }

  updateVaultStatus();
}

async function wakeUpServiceWorker(): Promise<void> {
  try {
    await chrome.runtime.sendMessage({ action: "ping" });
    console.log("[CyberVault] Service worker ready");
  } catch {
    // Silent fail
  }
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
    popupOrchestrator.showModal("modal-add-credential"),
  );

  // Audit button
  popupElements.btnAudit.addEventListener("click", runAudit);

  // Form submission - Add credential
  popupElements.formAddPopupCredential.addEventListener(
    "submit",
    handleAddPopupCredential,
  );

  // Modal close buttons
  document.querySelectorAll(".modal-close, [data-modal]").forEach((btn) => {
    btn.addEventListener("click", (e) => {
      const modalId = (e.currentTarget as HTMLElement).dataset.modal;
      if (modalId) popupOrchestrator.hideModal(modalId);
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
        await chrome.storage.local.clear();
        window.location.reload();
      }
    });
}

// ============================================================================
// Handlers
// ============================================================================

async function handleSetupMasterKey(): Promise<void> {
  const masterKey =
    (document.getElementById("master-key") as HTMLInputElement)?.value ?? "";
  const confirmKey =
    (document.getElementById("master-key-confirm") as HTMLInputElement)
      ?.value ?? "";
  const understood =
    (document.getElementById("master-key-understood") as HTMLInputElement)
      ?.checked ?? false;

  const result = await popupOrchestrator.setupMasterKey(
    masterKey,
    confirmKey,
    understood,
  );

  if (result.success) {
    popupOrchestrator.hideModal("modal-setup-master-key");
    renderCredentials();
  }
}

async function handleUnlockVault(): Promise<void> {
  const masterKey =
    (document.getElementById("unlock-key") as HTMLInputElement)?.value ?? "";

  const result = await popupOrchestrator.unlockVault(masterKey);

  if (result.success) {
    popupOrchestrator.hideModal("modal-unlock-vault");
    renderCredentials();
  }
}

function handleSearch(): void {
  const query = popupElements.searchInput.value.toLowerCase();
  filterPopupCredentials(query, currentTab);
}

function handleTabChange(tab: "all" | "favorites" | "recent"): void {
  popupElements.tabs.forEach((t) => t.classList.remove("active"));
  document.querySelector(`.tab[data-tab="${tab}"]`)?.classList.add("active");

  currentTab = tab;
  filterPopupCredentials(popupElements.searchInput.value.toLowerCase(), tab);
}

function filterPopupCredentials(
  query: string,
  tab: "all" | "favorites" | "recent",
): void {
  const credentials = popupOrchestrator.searchCredentials(query);

  const filtered = credentials.filter((cred) => {
    if (tab === "favorites" && !cred.favorite) return false;
    if (tab === "recent" && !cred.lastUsed) return false;
    return true;
  });

  renderFilteredCredentials(filtered);
}

async function handleAddPopupCredential(e: Event): Promise<void> {
  e.preventDefault();

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

  const title = sanitizeString(titleRaw, 100);
  const username = sanitizeString(usernameRaw, 254);
  const password = sanitizeString(passwordRaw, 256);
  const notes = sanitizeString(notesRaw, 10000);
  const url = urlRaw ? sanitizeString(urlRaw, 2048) : undefined;
  const tags = validateTags(tagsStr.split(","));

  if (!title || !username || !password) {
    popupOrchestrator.notification(
      "Error: Título, usuario y contraseña son requeridos",
      "error",
    );
    return;
  }

  if (url && !isValidUrl(url)) {
    popupOrchestrator.notification("Error: URL inválida", "error");
    return;
  }

  if (!isValidEmail(username)) {
    popupOrchestrator.notification(
      "Warning: El formato de usuario no es un email",
      "warning",
    );
  }

  const result = await popupOrchestrator.addCredential({
    title,
    username,
    password,
    url,
    notes,
    tags,
    favorite,
  });

  if (result.success) {
    popupOrchestrator.hideModal("modal-add-credential");
    popupElements.formAddPopupCredential.reset();
    renderCredentials();
  }
}

function handleEditClick(id: string): void {
  const credentials = popupOrchestrator.getCredentials();
  const cred = credentials.find((c) => c.id.toString() === id);
  if (!cred) return;

  (document.getElementById("edit-cred-id") as HTMLInputElement).value =
    cred.id.toString();
  (document.getElementById("edit-cred-title") as HTMLInputElement).value =
    cred.title || "";
  (document.getElementById("edit-cred-url") as HTMLInputElement).value =
    cred.url || "";
  (document.getElementById("edit-cred-username") as HTMLInputElement).value =
    cred.username || "";
  (document.getElementById("edit-cred-password") as HTMLInputElement).value =
    "";
  (document.getElementById("edit-cred-notes") as HTMLTextAreaElement).value =
    cred.notes || "";
  (document.getElementById("edit-cred-tags") as HTMLInputElement).value = (
    cred.tags || []
  ).join(", ");
  (document.getElementById("edit-cred-favorite") as HTMLInputElement).checked =
    cred.favorite || false;

  popupOrchestrator.showModal("modal-edit-credential");
}

async function handleEditCredential(e: Event): Promise<void> {
  e.preventDefault();

  const id = (document.getElementById("edit-cred-id") as HTMLInputElement)
    .value;
  const title = sanitizeString(
    (document.getElementById("edit-cred-title") as HTMLInputElement)?.value ??
      "",
    100,
  );
  const url =
    (document.getElementById("edit-cred-url") as HTMLInputElement)?.value ?? "";
  const username = sanitizeString(
    (document.getElementById("edit-cred-username") as HTMLInputElement)
      ?.value ?? "",
    254,
  );
  const passwordInput =
    (document.getElementById("edit-cred-password") as HTMLInputElement)
      ?.value ?? "";
  const notes = sanitizeString(
    (document.getElementById("edit-cred-notes") as HTMLTextAreaElement)
      ?.value ?? "",
    10000,
  );
  const tagsStr =
    (document.getElementById("edit-cred-tags") as HTMLInputElement)?.value ??
    "";
  const favorite =
    (document.getElementById("edit-cred-favorite") as HTMLInputElement)
      ?.checked ?? false;

  const updates: any = {
    title,
    username,
    url: url || undefined,
    notes: notes || undefined,
    tags: validateTags(tagsStr.split(",")),
    favorite,
  };

  if (passwordInput) {
    updates.password = passwordInput;
  }

  const result = await popupOrchestrator.editCredential(id, updates);

  if (result.success) {
    popupOrchestrator.hideModal("modal-edit-credential");
    renderCredentials();
  }
}

function handleDeleteClick(id: string): void {
  const credentials = popupOrchestrator.getCredentials();
  const cred = credentials.find((c) => c.id.toString() === id);
  if (!cred) return;

  (document.getElementById("delete-cred-id") as HTMLInputElement).value = id;
  (document.getElementById("delete-cred-title") as HTMLElement).textContent =
    cred.title;
  popupOrchestrator.showModal("modal-delete-confirm");
}

async function handleDeleteCredential(): Promise<void> {
  const id = (document.getElementById("delete-cred-id") as HTMLInputElement)
    .value;

  const result = await popupOrchestrator.deleteCredential(id);

  if (result.success) {
    popupOrchestrator.hideModal("modal-delete-confirm");
    renderCredentials();
  }
}

async function handlePopupCredentialClick(id: string): Promise<void> {
  const credentials = popupOrchestrator.getCredentials();
  const cred = credentials.find((c) => c.id.toString() === id);
  if (!cred) return;

  await navigator.clipboard.writeText(cred.username);
  popupOrchestrator.notification(
    `Usuario copiado: ${cred.username}`,
    "success",
  );
}

function handleViewClick(id: string): void {
  popupOrchestrator.viewCredential(id).then((result) => {
    if (result.success && result.data) {
      renderViewModal(result.data.credential, result.data.passwordToken);
      popupOrchestrator.showModal("modal-view-credential");
    }
  });
}

// ============================================================================
// Rendering
// ============================================================================

function renderCredentials(): void {
  const credentials = popupOrchestrator.getCredentials();
  renderFilteredCredentials(credentials);
}

function renderFilteredCredentials(credentials: any[]): void {
  if (credentials.length === 0) {
    popupElements.credentialsList.innerHTML = `
      <div class="empty-state">
        <div class="empty-state-icon">🔑</div>
        <p>No hay credenciales</p>
        <p style="font-size: 12px; margin-top: 4px;">Click en "Nueva Credencial" para agregar</p>
      </div>
    `;
    return;
  }

  popupElements.credentialsList.innerHTML = credentials
    .map(
      (cred) => `
    <div class="credential-card" data-id="${escapeAttribute(cred.id.toString())}">
      <div class="credential-icon">${getFaviconLetter(cred.title)}</div>
      <div class="credential-info">
        <div class="credential-title">${escapeHtml(cred.title)}</div>
        <div class="credential-username">${escapeHtml(cred.username)}</div>
      </div>
      <div class="credential-actions">
        ${cred.favorite ? "<span>⭐</span>" : ""}
        <button class="action-icon" data-action="view" data-id="${escapeAttribute(cred.id.toString())}" title="Ver">👁️</button>
        <button class="action-icon" data-action="edit" data-id="${escapeAttribute(cred.id.toString())}" title="Editar">✏️</button>
        <button class="action-icon" data-action="delete" data-id="${escapeAttribute(cred.id.toString())}" title="Eliminar">🗑️</button>
      </div>
    </div>
  `,
    )
    .join("");

  attachCredentialCardListeners();
}

function attachCredentialCardListeners(): void {
  popupElements.credentialsList
    .querySelectorAll(".credential-card")
    .forEach((card) => {
      card.addEventListener("click", (e) => {
        if ((e.target as HTMLElement).closest(".action-icon")) return;
        const id = (card as HTMLElement).dataset.id;
        if (id) handlePopupCredentialClick(id);
      });
    });

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

function renderViewModal(credential: any, passwordToken: string): void {
  const content = document.getElementById(
    "view-credential-content",
  ) as HTMLElement;

  content.innerHTML = `
    <div class="view-detail">
      <label>Título</label>
      <p>${escapeHtml(credential.title || "-")}</p>
    </div>
    <div class="view-detail">
      <label>URL</label>
      <p>${credential.url ? `<a href="${sanitizeUrl(credential.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(credential.url)}</a>` : "-"}</p>
    </div>
    <div class="view-detail">
      <label>Usuario</label>
      <p>${escapeHtml(credential.username || "-")}</p>
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
      <p>${escapeHtml(credential.notes || "-")}</p>
    </div>
    <div class="view-detail">
      <label>Etiquetas</label>
      <p>${(credential.tags || []).length ? credential.tags.map((t: string) => `<span class="tag">${escapeHtml(t)}</span>`).join(" ") : "-"}</p>
    </div>
    <div class="view-detail">
      <label>Creada</label>
      <p>${credential.createdAt ? new Date(credential.createdAt).toLocaleString() : "-"}</p>
    </div>
  `;

  content
    .querySelector('[data-action="copy-password"]')
    ?.addEventListener("click", async (e) => {
      const token = (e.target as HTMLElement).dataset.token;
      const result = await popupOrchestrator.copyPassword(token!);
      if (!result.success) {
        popupOrchestrator.notification(result.error || "Error", "error");
      }
    });
}

function updateVaultStatus(): void {
  const statusIcon = popupElements.vaultStatus.querySelector(".status-icon");
  const statusText = popupElements.vaultStatus.querySelector(".status-text");
  const appContainer = document.querySelector(".app-container");

  const status = popupOrchestrator.getVaultStatus();

  if (statusIcon && statusText) {
    if (status.unlocked) {
      statusIcon.textContent = "🔓";
      statusText.textContent = "Bóveda desbloqueada";
      popupElements.vaultStatus.classList.add("secure");
      appContainer?.classList.remove("locked");
    } else {
      statusIcon.textContent = "🔒";
      statusText.textContent = "Bóveda bloqueada";
      popupElements.vaultStatus.classList.remove("secure");
      appContainer?.classList.add("locked");
    }
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
    popupOrchestrator.notification(
      "Selecciona al menos un tipo de carácter",
      "error",
    );
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
    popupOrchestrator.notification("Genera una contraseña primero", "error");
    return;
  }

  await navigator.clipboard.writeText(password);
  popupOrchestrator.notification("Contraseña copiada", "success");
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
    const [tab] = await chrome.tabs.query({
      active: true,
      currentWindow: true,
    });
    let domain = "example.com";

    if (tab.url) {
      try {
        const url = new URL(tab.url);
        domain = url.hostname;
      } catch {
        // Usar dominio por defecto
      }
    }

    const { generateSecureCredentials } =
      await import("./credentials-integration");
    const result = await generateSecureCredentials(domain);

    const input = document.getElementById(targetId) as HTMLInputElement;
    if (input) {
      input.value = result.originalPassword;
    }

    popupOrchestrator.notification(
      `Contraseña generada para ${domain}`,
      "success",
    );
  } catch (error) {
    console.error("Error generating password:", error);
    popupOrchestrator.notification("Error al generar contraseña", "error");
  }
}

async function runAudit(): Promise<void> {
  try {
    await chrome.runtime.sendMessage({ action: "run_audit" });
    popupOrchestrator.notification("Audit iniciado", "success");
  } catch (error) {
    popupOrchestrator.notification("Audit: Función no disponible", "warning");
  }
}

// ============================================================================
// Notifications - Ya delegado al orchestrator
// ============================================================================

function showNotification(message: string): void {
  popupOrchestrator.notification(message);
}

// ============================================================================
// Sanitize URL helper (necesario para render)
// ============================================================================

function sanitizeUrl(url: string): string {
  try {
    const parsed = new URL(url);
    return parsed.href;
  } catch {
    return url;
  }
}
