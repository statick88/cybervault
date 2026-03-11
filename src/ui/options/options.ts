/**
 * CyberVault Options Page
 * Maneja la configuración de la extensión
 */

// ============================================================================
// Types
// ============================================================================

interface ExtensionSettings {
  enabled: boolean;
  autofill: boolean;
  passwordGenerator: boolean;
  breachCheck: boolean;
  blockTrackers: boolean;
  securityNotifications: boolean;
  auditFrequency: number;
  ipfsSync: boolean;
  ipfsGateway: string;
  secureMode: boolean;
  theme: "system" | "light" | "dark";
  icon: "default" | "minimal" | "color";
}

const DEFAULT_SETTINGS: ExtensionSettings = {
  enabled: true,
  autofill: true,
  passwordGenerator: true,
  breachCheck: true,
  blockTrackers: false,
  securityNotifications: true,
  auditFrequency: 24,
  ipfsSync: false,
  ipfsGateway: "https://ipfs.io",
  secureMode: false,
  theme: "system",
  icon: "default",
};

// ============================================================================
// DOM Elements
// ============================================================================

const optionsElements = {
  settingEnabled: document.getElementById(
    "setting-enabled",
  ) as HTMLInputElement,
  settingAutofill: document.getElementById(
    "setting-autofill",
  ) as HTMLInputElement,
  settingPasswordGenerator: document.getElementById(
    "setting-password-generator",
  ) as HTMLInputElement,
  settingBreachCheck: document.getElementById(
    "setting-breach-check",
  ) as HTMLInputElement,
  settingBlockTrackers: document.getElementById(
    "setting-block-trackers",
  ) as HTMLInputElement,
  settingSecurityNotifications: document.getElementById(
    "setting-security-notifications",
  ) as HTMLInputElement,
  settingAuditFrequency: document.getElementById(
    "setting-audit-frequency",
  ) as HTMLSelectElement,
  settingIpfsSync: document.getElementById(
    "setting-ipfs-sync",
  ) as HTMLInputElement,
  settingIpfsGateway: document.getElementById(
    "setting-ipfs-gateway",
  ) as HTMLInputElement,
  ipfsSettings: document.getElementById("ipfs-settings") as HTMLElement,
  settingSecureMode: document.getElementById(
    "setting-secure-mode",
  ) as HTMLInputElement,
  settingTheme: document.getElementById("setting-theme") as HTMLSelectElement,
  settingIcon: document.getElementById("setting-icon") as HTMLSelectElement,
  btnSave: document.getElementById("btn-save") as HTMLButtonElement,
  btnReset: document.getElementById("btn-reset") as HTMLButtonElement,
  btnExport: document.getElementById("btn-export") as HTMLButtonElement,
  btnImport: document.getElementById("btn-import") as HTMLButtonElement,
  btnClear: document.getElementById("btn-clear") as HTMLButtonElement,
  importFile: document.getElementById("import-file") as HTMLInputElement,
};

// ============================================================================
// Initialization
// ============================================================================

document.addEventListener("DOMContentLoaded", async () => {
  await loadSettings();
  setupOptionsEventListeners();
});

async function loadSettings(): Promise<void> {
  try {
    const stored = await chrome.storage.local.get("settings");
    const settings = stored.settings as Partial<ExtensionSettings> | undefined;

    if (settings) {
      applySettings({ ...DEFAULT_SETTINGS, ...settings });
    } else {
      applySettings(DEFAULT_SETTINGS);
    }
  } catch (error) {
    console.error("Error cargando configuración:", error);
    applySettings(DEFAULT_SETTINGS);
  }
}

function applySettings(settings: ExtensionSettings): void {
  optionsElements.settingEnabled.checked = settings.enabled;
  optionsElements.settingAutofill.checked = settings.autofill;
  optionsElements.settingPasswordGenerator.checked = settings.passwordGenerator;
  optionsElements.settingBreachCheck.checked = settings.breachCheck;
  optionsElements.settingBlockTrackers.checked = settings.blockTrackers;
  optionsElements.settingSecurityNotifications.checked =
    settings.securityNotifications;
  optionsElements.settingAuditFrequency.value =
    settings.auditFrequency.toString();
  optionsElements.settingIpfsSync.checked = settings.ipfsSync;
  optionsElements.settingIpfsGateway.value = settings.ipfsGateway;
  optionsElements.settingSecureMode.checked = settings.secureMode;
  optionsElements.settingTheme.value = settings.theme;
  optionsElements.settingIcon.value = settings.icon;

  // Mostrar/ocultar configuración IPFS
  optionsElements.ipfsSettings.style.display = settings.ipfsSync
    ? "flex"
    : "none";
}

function getSettingsFromForm(): ExtensionSettings {
  return {
    enabled: optionsElements.settingEnabled.checked,
    autofill: optionsElements.settingAutofill.checked,
    passwordGenerator: optionsElements.settingPasswordGenerator.checked,
    breachCheck: optionsElements.settingBreachCheck.checked,
    blockTrackers: optionsElements.settingBlockTrackers.checked,
    securityNotifications: optionsElements.settingSecurityNotifications.checked,
    auditFrequency: parseInt(optionsElements.settingAuditFrequency.value),
    ipfsSync: optionsElements.settingIpfsSync.checked,
    ipfsGateway: optionsElements.settingIpfsGateway.value,
    secureMode: optionsElements.settingSecureMode.checked,
    theme: optionsElements.settingTheme.value as ExtensionSettings["theme"],
    icon: optionsElements.settingIcon.value as ExtensionSettings["icon"],
  };
}

// ============================================================================
// Event Listeners
// ============================================================================

function setupOptionsEventListeners(): void {
  // Guardar configuración
  optionsElements.btnSave.addEventListener("click", handleSave);

  // Restablecer configuración
  optionsElements.btnReset.addEventListener("click", handleReset);

  // Exportar datos
  optionsElements.btnExport.addEventListener("click", handleExport);

  // Importar datos
  optionsElements.btnImport.addEventListener("click", () =>
    optionsElements.importFile.click(),
  );
  optionsElements.importFile.addEventListener("change", handleImport);

  // Eliminar todos los datos
  optionsElements.btnClear.addEventListener("click", handleClear);

  // Toggle IPFS settings
  optionsElements.settingIpfsSync.addEventListener("change", () => {
    optionsElements.ipfsSettings.style.display = optionsElements.settingIpfsSync
      .checked
      ? "flex"
      : "none";
  });

  // Keyboard shortcuts
  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "s") {
      e.preventDefault();
      handleSave();
    }
  });
}

// ============================================================================
// Handlers
// ============================================================================

async function handleSave(): Promise<void> {
  const settings = getSettingsFromForm();

  try {
    await chrome.storage.local.set({ settings });
    showNotification("Configuración guardada", "success");

    // Notificar al background script
    await chrome.runtime.sendMessage({
      action: "settingsUpdated",
      settings,
    });
  } catch (error) {
    console.error("Error guardando configuración:", error);
    showNotification("Error al guardar configuración", "error");
  }
}

async function handleReset(): Promise<void> {
  if (confirm("¿Restablecer configuración a valores predeterminados?")) {
    applySettings(DEFAULT_SETTINGS);
    await chrome.storage.local.set({ settings: DEFAULT_SETTINGS });
    showNotification("Configuración restablecida", "success");
  }
}

async function handleExport(): Promise<void> {
  try {
    // Obtener todos los datos
    const data = await chrome.storage.local.get(null);

    // Crear blob
    const blob = new Blob([JSON.stringify(data, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);

    // Descargar
    const a = document.createElement("a");
    a.href = url;
    a.download = `cybervault-backup-${new Date().toISOString().split("T")[0]}.json`;
    a.click();

    URL.revokeObjectURL(url);
    showNotification("Datos exportados correctamente", "success");
  } catch (error) {
    console.error("Error exportando datos:", error);
    showNotification("Error al exportar datos", "error");
  }
}

async function handleImport(): Promise<void> {
  const file = optionsElements.importFile.files?.[0];
  if (!file) return;

  try {
    const text = await file.text();
    const data = JSON.parse(text);

    // Validar estructura básica
    if (!data.credentials && !data.settings) {
      throw new Error("Archivo de respaldo inválido");
    }

    // Importar
    await chrome.storage.local.set(data);

    // Recargar configuración
    await loadSettings();

    showNotification("Datos importados correctamente", "success");
  } catch (error) {
    console.error("Error importando datos:", error);
    showNotification("Error al importar datos. Archivo inválido.", "error");
  }

  // Limpiar input
  optionsElements.importFile.value = "";
}

async function handleClear(): Promise<void> {
  const confirmed = confirm(
    "¿Estás seguro de eliminar TODOS los datos?\n\n" +
      "Esta acción NO se puede deshacer.\n" +
      "Se eliminarán:\n" +
      "• Todas las credenciales\n" +
      "• Configuración\n" +
      "• Historial\n" +
      "• Configuración de bóveda",
  );

  if (!confirmed) return;

  const doubleConfirmed = confirm(
    "¿REALMENTE quieres eliminar todo?\n\n" +
      'Escribe "ELIMINAR" para confirmar.',
  );

  if (doubleConfirmed) {
    try {
      await chrome.storage.local.clear();
      applySettings(DEFAULT_SETTINGS);
      showNotification("Todos los datos han sido eliminados", "success");
    } catch (error) {
      console.error("Error eliminando datos:", error);
      showNotification("Error al eliminar datos", "error");
    }
  }
}

// ============================================================================
// Notifications
// ============================================================================

function showNotification(
  message: string,
  type: "success" | "error" = "success",
): void {
  const existing = document.querySelector(".toast-notification");
  if (existing) existing.remove();

  const toast = document.createElement("div");
  toast.className = "toast-notification";
  toast.textContent = message;
  toast.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    background: ${type === "success" ? "#16a34a" : "#dc2626"};
    color: white;
    padding: 12px 20px;
    border-radius: 8px;
    font-size: 14px;
    font-weight: 500;
    z-index: 10000;
    animation: slideIn 0.3s ease;
    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
  `;

  document.body.appendChild(toast);

  setTimeout(() => {
    toast.style.animation = "slideOut 0.3s ease";
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

// Animations
const style = document.createElement("style");
style.textContent = `
  @keyframes slideIn {
    from { transform: translateX(100%); opacity: 0; }
    to { transform: translateX(0); opacity: 1; }
  }
  @keyframes slideOut {
    from { transform: translateX(0); opacity: 1; }
    to { transform: translateX(100%); opacity: 0; }
  }
`;
document.head.appendChild(style);
