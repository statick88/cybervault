/**
 * CyberVault Options Page — settings and trusted domains management
 *
 * Uses chrome.storage.local for all persistence. Reads/writes settings
 * under the same keys seeded by auditor.ts on install.
 */

(function() {
/* ------------------------------------------------------------------ */
/*  Storage keys                                                       */
/* ------------------------------------------------------------------ */

const SETTINGS_KEY = "cybervault_settings";
const TRUSTED_DOMAINS_KEY = "cybervault_trusted_domains";
const ANOMALY_LOG_KEY = "cybervault_anomaly_log";
const VAULT_KEY = "vault_data";

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

interface Settings {
  autoValidate: boolean;
  blockHighRisk: boolean;
  showNotifications: boolean;
  sessionTimeoutMinutes: number;
}

interface AnomalyEntry {
  domain: string;
  anomalyType: string;
  severity: string;
  details: string;
  timestamp: number;
}

/* ------------------------------------------------------------------ */
/*  DOM References                                                     */
/* ------------------------------------------------------------------ */

const $ = <T extends HTMLElement = HTMLElement>(sel: string) =>
  document.querySelector<T>(sel)!;

const domainInput = $<HTMLInputElement>("#domain-input");
const domainAddBtn = $<HTMLButtonElement>("#domain-add");
const domainList = $<HTMLUListElement>("#domain-list");

const cfgAutoValidate = $<HTMLInputElement>("#cfg-auto-validate");
const cfgBlockHighRisk = $<HTMLInputElement>("#cfg-block-high-risk");
const cfgShowNotifications = $<HTMLInputElement>("#cfg-show-notifications");
const cfgSessionTimeout = $<HTMLInputElement>("#cfg-session-timeout");

const exportBtn = $<HTMLButtonElement>("#export-btn");
const importBtn = $<HTMLButtonElement>("#import-btn");
const importFile = $<HTMLInputElement>("#import-file");
const dataStatus = $<HTMLParagraphElement>("#data-status");

const anomalyLog = $<HTMLUListElement>("#anomaly-log");
const anomalyEmpty = $<HTMLParagraphElement>("#anomaly-empty");

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

async function readStorage<T>(key: string): Promise<T | undefined> {
  const result = await chrome.storage.local.get([key]);
  return result[key] as T | undefined;
}

async function writeStorage(data: Record<string, unknown>): Promise<void> {
  await chrome.storage.local.set(data);
}

function showStatus(msg: string, type: "success" | "error" = "success"): void {
  dataStatus.textContent = msg;
  dataStatus.className = `data-status data-status--${type}`;
  dataStatus.hidden = false;
  setTimeout(() => (dataStatus.hidden = true), 3000);
}

function formatDate(ts: number): string {
  return new Date(ts).toLocaleString();
}

/* ------------------------------------------------------------------ */
/*  Trusted Domains                                                    */
/* ------------------------------------------------------------------ */

async function loadDomains(): Promise<string[]> {
  const domains = await readStorage<string[]>(TRUSTED_DOMAINS_KEY);
  return Array.isArray(domains) ? domains : [];
}

async function renderDomains(): Promise<void> {
  const domains = await loadDomains();
  domainList.innerHTML = "";

  for (const domain of domains) {
    const li = document.createElement("li");
    li.className = "domain-item";

    const span = document.createElement("span");
    span.textContent = domain;

    const removeBtn = document.createElement("button");
    removeBtn.className = "domain-item__remove";
    removeBtn.textContent = "×";
    removeBtn.title = `Remove ${domain}`;
    removeBtn.addEventListener("click", () => removeDomain(domain));

    li.appendChild(span);
    li.appendChild(removeBtn);
    domainList.appendChild(li);
  }
}

async function addDomain(): Promise<void> {
  const domain = domainInput.value.trim().toLowerCase();
  if (!domain) return;

  const domains = await loadDomains();
  if (domains.includes(domain)) {
    domainInput.value = "";
    return;
  }

  domains.push(domain);
  await writeStorage({ [TRUSTED_DOMAINS_KEY]: domains });
  domainInput.value = "";
  await renderDomains();
}

async function removeDomain(domain: string): Promise<void> {
  let domains = await loadDomains();
  domains = domains.filter((d) => d !== domain);
  await writeStorage({ [TRUSTED_DOMAINS_KEY]: domains });
  await renderDomains();
}

/* ------------------------------------------------------------------ */
/*  AITM Settings                                                      */
/* ------------------------------------------------------------------ */

async function loadSettings(): Promise<Settings> {
  const defaults: Settings = {
    autoValidate: true,
    blockHighRisk: true,
    showNotifications: true,
    sessionTimeoutMinutes: 30,
  };
  const stored = await readStorage<Settings>(SETTINGS_KEY);
  return stored ? { ...defaults, ...stored } : defaults;
}

async function saveSettings(): Promise<void> {
  const settings: Settings = {
    autoValidate: cfgAutoValidate.checked,
    blockHighRisk: cfgBlockHighRisk.checked,
    showNotifications: cfgShowNotifications.checked,
    sessionTimeoutMinutes: Math.max(1, parseInt(cfgSessionTimeout.value, 10) || 30),
  };
  await writeStorage({ [SETTINGS_KEY]: settings });
  showStatus("Settings saved");
}

async function populateSettings(): Promise<void> {
  const s = await loadSettings();
  cfgAutoValidate.checked = s.autoValidate;
  cfgBlockHighRisk.checked = s.blockHighRisk;
  cfgShowNotifications.checked = s.showNotifications;
  cfgSessionTimeout.value = String(s.sessionTimeoutMinutes);
}

/* ------------------------------------------------------------------ */
/*  Export / Import                                                    */
/* ------------------------------------------------------------------ */

async function handleExport(): Promise<void> {
  const vault = await readStorage(VAULT_KEY);
  if (!vault) {
    showStatus("No vault to export", "error");
    return;
  }

  const blob = new Blob([JSON.stringify(vault, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);

  const a = document.createElement("a");
  a.href = url;
  a.download = `cybervault-export-${Date.now()}.json`;
  a.click();

  URL.revokeObjectURL(url);
  showStatus("Vault exported");
}

function handleImportClick(): void {
  importFile.click();
}

async function handleImportFile(): Promise<void> {
  const file = importFile.files?.[0];
  if (!file) return;

  try {
    const text = await file.text();
    const data = JSON.parse(text);

    if (!data || typeof data !== "object") {
      throw new Error("Invalid vault file format");
    }

    await writeStorage({ [VAULT_KEY]: data });
    showStatus("Vault imported successfully");
  } catch (err) {
    const msg = err instanceof Error ? err.message : "Import failed";
    showStatus(msg, "error");
  } finally {
    importFile.value = "";
  }
}

/* ------------------------------------------------------------------ */
/*  Anomaly Log                                                        */
/* ------------------------------------------------------------------ */

async function loadAnomalyLog(): Promise<void> {
  const log = await readStorage<AnomalyEntry[]>(ANOMALY_LOG_KEY);
  const entries = Array.isArray(log) ? log : [];

  anomalyLog.innerHTML = "";

  if (entries.length === 0) {
    anomalyEmpty.hidden = false;
    return;
  }

  anomalyEmpty.hidden = true;

  // Show most recent first, cap at 50
  const recent = entries.slice(-50).reverse();

  for (const entry of recent) {
    const li = document.createElement("li");
    li.className = "anomaly-item";

    const domain = document.createElement("span");
    domain.className = "anomaly-item__domain";
    domain.textContent = entry.domain;

    const severity = document.createElement("span");
    severity.className = `anomaly-item__severity anomaly-item__severity--${entry.severity}`;
    severity.textContent = entry.severity;

    const time = document.createElement("span");
    time.className = "anomaly-item__time";
    time.textContent = formatDate(entry.timestamp);

    li.appendChild(domain);
    li.appendChild(severity);
    li.appendChild(time);
    anomalyLog.appendChild(li);
  }
}

/* ------------------------------------------------------------------ */
/*  Event Binding                                                      */
/* ------------------------------------------------------------------ */

domainAddBtn.addEventListener("click", addDomain);
domainInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") addDomain();
});

cfgAutoValidate.addEventListener("change", saveSettings);
cfgBlockHighRisk.addEventListener("change", saveSettings);
cfgShowNotifications.addEventListener("change", saveSettings);
cfgSessionTimeout.addEventListener("change", saveSettings);

exportBtn.addEventListener("click", handleExport);
importBtn.addEventListener("click", handleImportClick);
importFile.addEventListener("change", handleImportFile);

/* ------------------------------------------------------------------ */
/*  Init                                                               */
/* ------------------------------------------------------------------ */

(async () => {
  await Promise.all([
    renderDomains(),
    populateSettings(),
    loadAnomalyLog(),
  ]);
})();

})();
