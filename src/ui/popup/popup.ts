/**
 * CyberVault Popup — credential quick-access UI
 *
 * Communicates with the service worker via chrome.runtime.sendMessage
 * and persists vault state in chrome.storage.local / chrome.storage.session.
 */

(function() {
/* ------------------------------------------------------------------ */
/*  Storage keys (must match auditor.ts and repositories)              */
/* ------------------------------------------------------------------ */

const VAULT_KEY = "vault_data";
const SETTINGS_KEY = "cybervault_settings";
const UNLOCK_STATE_KEY = "cybervault_unlock_state";

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

interface CredentialPlain {
  id: string;
  vaultId: string;
  title: string;
  username: string;
  encryptedPassword: string;
  url?: string;
  notes?: string;
  tags: string[];
  favorite: boolean;
  createdAt: string;
  updatedAt: string;
  lastUsed?: string;
}

interface VaultPlain {
  id: string;
  name: string;
  description?: string;
  encryptedData: string;
  encryptionKeyId: string;
  metadata?: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
}

interface BackgroundResponse<T = unknown> {
  ok: boolean;
  data?: T;
  error?: string;
}

/* ------------------------------------------------------------------ */
/*  DOM References                                                     */
/* ------------------------------------------------------------------ */

const $ = <T extends HTMLElement = HTMLElement>(sel: string) =>
  document.querySelector<T>(sel)!;

const lockedView = $<HTMLDivElement>("#locked-view");
const unlockedView = $<HTMLDivElement>("#unlocked-view");
const passphraseInput = $<HTMLInputElement>("#passphrase-input");
const unlockBtn = $<HTMLButtonElement>("#unlock-btn");
const lockError = $<HTMLParagraphElement>("#lock-error");
const lockToggle = $<HTMLButtonElement>("#lock-toggle");
const lockIcon = $<HTMLSpanElement>("#lock-icon");
const searchInput = $<HTMLInputElement>("#search-input");
const addBtn = $<HTMLButtonElement>("#add-btn");
const credentialList = $<HTMLUListElement>("#credential-list");
const emptyState = $<HTMLDivElement>("#empty-state");
const addForm = $<HTMLDivElement>("#add-form");
const addTitle = $<HTMLInputElement>("#add-title");
const addUsername = $<HTMLInputElement>("#add-username");
const addPassword = $<HTMLInputElement>("#add-password");
const addUrl = $<HTMLInputElement>("#add-url");
const addSave = $<HTMLButtonElement>("#add-save");
const addCancel = $<HTMLButtonElement>("#add-cancel");
const optionsLink = $<HTMLAnchorElement>("#options-link");

/* ------------------------------------------------------------------ */
/*  State                                                              */
/* ------------------------------------------------------------------ */

let isUnlocked = false;
let credentials: CredentialPlain[] = [];

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

async function sendMessage<T = unknown>(
  message: Record<string, unknown>,
): Promise<BackgroundResponse<T>> {
  return chrome.runtime.sendMessage(message);
}

async function readStorage<T>(key: string): Promise<T | undefined> {
  const result = await chrome.storage.local.get([key]);
  return result[key] as T | undefined;
}

async function writeStorage(data: Record<string, unknown>): Promise<void> {
  await chrome.storage.local.set(data);
}

function renderCredentialList(items: CredentialPlain[]): void {
  credentialList.innerHTML = "";

  if (items.length === 0) {
    emptyState.hidden = false;
    return;
  }

  emptyState.hidden = true;

  for (const cred of items) {
    const li = document.createElement("li");
    li.className = "credential-item";
    li.dataset.id = cred.id;

    const info = document.createElement("div");
    info.className = "credential-item__info";

    const title = document.createElement("div");
    title.className = "credential-item__title";
    title.textContent = cred.title;

    const user = document.createElement("div");
    user.className = "credential-item__user";
    user.textContent = cred.username;

    info.appendChild(title);
    info.appendChild(user);

    const actions = document.createElement("div");
    actions.className = "credential-item__actions";

    const copyUserBtn = document.createElement("button");
    copyUserBtn.className = "credential-item__btn";
    copyUserBtn.textContent = "👤";
    copyUserBtn.title = "Copy username";
    copyUserBtn.addEventListener("click", () => copyToClipboard(cred.username, copyUserBtn));

    const copyPassBtn = document.createElement("button");
    copyPassBtn.className = "credential-item__btn";
    copyPassBtn.textContent = "🔑";
    copyPassBtn.title = "Copy password";
    copyPassBtn.addEventListener("click", () =>
      copyToClipboard("[encrypted]", copyPassBtn),
    );

    actions.appendChild(copyUserBtn);
    actions.appendChild(copyPassBtn);

    li.appendChild(info);
    li.appendChild(actions);
    credentialList.appendChild(li);
  }
}

async function copyToClipboard(text: string, btn: HTMLButtonElement): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    btn.classList.add("credential-item__btn--copied");
    setTimeout(() => btn.classList.remove("credential-item__btn--copied"), 1200);
  } catch {
    // Fallback for environments without clipboard API
    const textarea = document.createElement("textarea");
    textarea.value = text;
    textarea.style.position = "fixed";
    textarea.style.opacity = "0";
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand("copy");
    document.body.removeChild(textarea);
    btn.classList.add("credential-item__btn--copied");
    setTimeout(() => btn.classList.remove("credential-item__btn--copied"), 1200);
  }
}

/* ------------------------------------------------------------------ */
/*  Vault Lock / Unlock                                                */
/* ------------------------------------------------------------------ */

async function checkLockState(): Promise<void> {
  const session = await chrome.storage.session.get([UNLOCK_STATE_KEY]);
  const state = session[UNLOCK_STATE_KEY] as
    | { expiresAt: number }
    | undefined;

  if (state && Date.now() < state.expiresAt) {
    setUnlocked(true);
  } else {
    setUnlocked(false);
  }
}

function setUnlocked(unlocked: boolean): void {
  isUnlocked = unlocked;
  lockedView.hidden = unlocked;
  unlockedView.hidden = !unlocked;
  lockIcon.textContent = unlocked ? "🔓" : "🔒";
  lockToggle.setAttribute(
    "aria-label",
    unlocked ? "Lock vault" : "Unlock vault",
  );
}

async function handleUnlock(): Promise<void> {
  const passphrase = passphraseInput.value.trim();
  if (!passphrase) {
    lockError.textContent = "Passphrase required";
    lockError.hidden = false;
    return;
  }

  lockError.hidden = true;

  // In a full implementation, the passphrase would derive a key that decrypts
  // vault data. Here we store the unlock session via the service worker.
  const vaultData = await readStorage<VaultPlain>(VAULT_KEY);
  if (!vaultData) {
    lockError.textContent = "No vault found. Create one in Settings.";
    lockError.hidden = false;
    return;
  }

  const resp = await sendMessage<{ unlocked: boolean }>({
    type: "UNLOCK_VAULT",
    vaultId: vaultData.id,
    passphrase,
  });

  if (resp.ok) {
    setUnlocked(true);
    passphraseInput.value = "";
    await loadCredentials();
  } else {
    lockError.textContent = resp.error || "Unlock failed";
    lockError.hidden = false;
  }
}

async function handleLock(): Promise<void> {
  await chrome.storage.session.remove(UNLOCK_STATE_KEY);
  setUnlocked(false);
  credentials = [];
  credentialList.innerHTML = "";
}

/* ------------------------------------------------------------------ */
/*  Credential Loading                                                 */
/* ------------------------------------------------------------------ */

async function loadCredentials(): Promise<void> {
  // Credentials are embedded in vault metadata as an array of plain objects.
  // In a production build the Vault entity would manage this; here we read
  // directly from storage for simplicity.
  const vaultData = await readStorage<VaultPlain>(VAULT_KEY);
  if (!vaultData?.metadata?.credentials) {
    credentials = [];
    renderCredentialList([]);
    return;
  }

  credentials = vaultData.metadata.credentials as CredentialPlain[];
  renderCredentialList(credentials);
}

/* ------------------------------------------------------------------ */
/*  Search                                                             */
/* ------------------------------------------------------------------ */

function handleSearch(): void {
  const query = searchInput.value.trim().toLowerCase();
  if (!query) {
    renderCredentialList(credentials);
    return;
  }

  const filtered = credentials.filter(
    (c) =>
      c.title.toLowerCase().includes(query) ||
      c.username.toLowerCase().includes(query) ||
      c.url?.toLowerCase().includes(query) ||
      c.tags.some((t) => t.toLowerCase().includes(query)),
  );

  renderCredentialList(filtered);
}

/* ------------------------------------------------------------------ */
/*  Quick Add                                                          */
/* ------------------------------------------------------------------ */

function showAddForm(): void {
  addForm.hidden = false;
  addTitle.focus();
}

function hideAddForm(): void {
  addForm.hidden = true;
  addTitle.value = "";
  addUsername.value = "";
  addPassword.value = "";
  addUrl.value = "";
}

async function handleAddCredential(): Promise<void> {
  const title = addTitle.value.trim();
  const username = addUsername.value.trim();
  const password = addPassword.value;
  const url = addUrl.value.trim();

  if (!title || !username || !password) {
    return;
  }

  const newCred: CredentialPlain = {
    id: crypto.randomUUID(),
    vaultId: "",
    title,
    username,
    encryptedPassword: btoa(password), // placeholder — real encryption in vault domain
    url: url || undefined,
    tags: [],
    favorite: false,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  // Update vault metadata in storage
  const vaultData = await readStorage<VaultPlain>(VAULT_KEY);
  if (vaultData) {
    const existing = (vaultData.metadata?.credentials as CredentialPlain[]) || [];
    existing.push(newCred);
    vaultData.metadata = { ...vaultData.metadata, credentials: existing };
    vaultData.updatedAt = new Date().toISOString();
    await writeStorage({ [VAULT_KEY]: vaultData });
  }

  hideAddForm();
  await loadCredentials();
}

/* ------------------------------------------------------------------ */
/*  Options Link                                                       */
/* ------------------------------------------------------------------ */

function openOptions(): void {
  chrome.runtime.openOptionsPage();
}

/* ------------------------------------------------------------------ */
/*  Event Binding                                                      */
/* ------------------------------------------------------------------ */

unlockBtn.addEventListener("click", handleUnlock);
passphraseInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") handleUnlock();
});

lockToggle.addEventListener("click", () => {
  if (isUnlocked) handleLock();
  else {
    setUnlocked(false);
    passphraseInput.focus();
  }
});

searchInput.addEventListener("input", handleSearch);
addBtn.addEventListener("click", showAddForm);
addCancel.addEventListener("click", hideAddForm);
addSave.addEventListener("click", handleAddCredential);
optionsLink.addEventListener("click", (e) => {
  e.preventDefault();
  openOptions();
});

/* ------------------------------------------------------------------ */
/*  Init                                                               */
/* ------------------------------------------------------------------ */

checkLockState();

})();
