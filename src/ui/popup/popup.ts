/**
 * CyberVault Popup — credential quick-access UI
 *
 * Communicates with the service worker via chrome.runtime.sendMessage
 * and persists vault state in chrome.storage.local / chrome.storage.session.
 *
 * Flow: Login -> Unlock -> Manage credentials
 */

(function() {
/* ------------------------------------------------------------------ */
/*  Storage keys (must match auditor.ts and repositories)              */
/* ------------------------------------------------------------------ */

const VAULT_KEY = "vault_data";
const SETTINGS_KEY = "cybervault_settings";
const UNLOCK_STATE_KEY = "cybervault_unlock_state";
const AUTH_TOKEN_KEY = "cybervault_token";
const USER_ID_KEY = "cybervault_userId";

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

interface CredentialPlain {
  id: string;
  vaultId: string;
  title: string;
  username: string;
  password: string;
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

interface LoginResponse {
  userId: string;
  email: string;
  token: string;
  refreshToken: string;
  message: string;
}

/* ------------------------------------------------------------------ */
/*  DOM References                                                     */
/* ------------------------------------------------------------------ */

const $ = <T extends HTMLElement = HTMLElement>(sel: string) =>
  document.querySelector<T>(sel)!;

// Views
const loginView = $<HTMLDivElement>("#login-view");
const lockedView = $<HTMLDivElement>("#locked-view");
const unlockedView = $<HTMLDivElement>("#unlocked-view");

// Login form
const loginForm = $<HTMLFormElement>("#login-form");
const loginEmail = $<HTMLInputElement>("#login-email");
const loginPassword = $<HTMLInputElement>("#login-password");
const loginBtn = $<HTMLButtonElement>("#login-btn");
const loginError = $<HTMLParagraphElement>("#login-error");

// Lock/Unlock
const passphraseInput = $<HTMLInputElement>("#passphrase-input");
const unlockBtn = $<HTMLButtonElement>("#unlock-btn");
const lockError = $<HTMLParagraphElement>("#lock-error");
const lockToggle = $<HTMLButtonElement>("#lock-toggle");
const lockIcon = $<HTMLSpanElement>("#lock-icon");

// Credentials
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
let authToken: string | null | undefined = null;

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

const API_BASE = "http://localhost:3010";

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

/* ------------------------------------------------------------------ */
/*  PBKDF2 Key Derivation (same as EncryptionService)                  */
/* ------------------------------------------------------------------ */

const ENCRYPTION_CONFIG = {
  AES: { ALGORITHM: "AES-GCM" as const, KEY_LENGTH: 256, IV_LENGTH: 12, TAG_LENGTH: 128 },
  PBKDF2: { ALGORITHM: "PBKDF2" as const, HASH: "SHA-512" as const, ITERATIONS: 600000, SALT_LENGTH: 16 }
};

function base64ToBinary(base64: string): Uint8Array {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes;
}

async function decryptVault(encryptedData: string, masterKey: string): Promise<string> {
  const combined = base64ToBinary(encryptedData);
  const saltLength = ENCRYPTION_CONFIG.PBKDF2.SALT_LENGTH;
  const ivLength = ENCRYPTION_CONFIG.AES.IV_LENGTH;

  const salt = combined.slice(0, saltLength);
  const iv = combined.slice(saltLength, saltLength + ivLength);
  const ciphertextWithTag = combined.slice(saltLength + ivLength);

  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(masterKey),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  const aesKey = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt as unknown as BufferSource,
      iterations: ENCRYPTION_CONFIG.PBKDF2.ITERATIONS,
      hash: ENCRYPTION_CONFIG.PBKDF2.HASH,
    },
    keyMaterial,
    { name: ENCRYPTION_CONFIG.AES.ALGORITHM, length: ENCRYPTION_CONFIG.AES.KEY_LENGTH },
    false,
    ["decrypt"]
  );

  const decryptedBuffer = await crypto.subtle.decrypt(
    {
      name: ENCRYPTION_CONFIG.AES.ALGORITHM,
      iv: iv as unknown as BufferSource,
      tagLength: ENCRYPTION_CONFIG.AES.TAG_LENGTH,
    },
    aesKey,
    ciphertextWithTag as unknown as BufferSource
  );

  return new TextDecoder().decode(decryptedBuffer);
}

/* ------------------------------------------------------------------ */
/*  Login                                                              */
/* ------------------------------------------------------------------ */

async function handleLogin(e: Event): Promise<void> {
  e.preventDefault();
  loginError.hidden = true;

  const email = loginEmail.value.trim();
  const password = loginPassword.value;

  if (!email || !password) {
    loginError.textContent = "Email y contraseña requeridos";
    loginError.hidden = false;
    return;
  }

  loginBtn.disabled = true;
  loginBtn.textContent = "Ingresando...";

  try {
    const res = await fetch(`${API_BASE}/api/v1/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password })
    });

    const data = await res.json();

    if (res.ok && data.token) {
      // Store auth data
      authToken = data.token;
      await writeStorage({
        [AUTH_TOKEN_KEY]: data.token,
        [USER_ID_KEY]: data.userId,
        "cybervault_email": email
      });

      // Show locked view
      showView("locked");
      passphraseInput.focus();
    } else {
      loginError.textContent = data.error || "Credenciales incorrectas";
      loginError.hidden = false;
    }
  } catch (err) {
    loginError.textContent = `Error de conexión: ${err instanceof Error ? err.message : err}`;
    loginError.hidden = false;
  } finally {
    loginBtn.disabled = false;
    loginBtn.textContent = "Iniciar Sesión";
  }
}

/* ------------------------------------------------------------------ */
/*  View Management                                                    */
/* ------------------------------------------------------------------ */

function showView(view: "login" | "locked" | "unlocked"): void {
  loginView.hidden = view !== "login";
  lockedView.hidden = view !== "locked";
  unlockedView.hidden = view !== "unlocked";
  lockToggle.hidden = view === "login";

  if (view === "unlocked") {
    lockIcon.textContent = "🔓";
    lockToggle.setAttribute("aria-label", "Lock vault");
  } else {
    lockIcon.textContent = "🔒";
    lockToggle.setAttribute("aria-label", "Unlock vault");
  }
}

/* ------------------------------------------------------------------ */
/*  Vault Lock / Unlock                                                */
/* ------------------------------------------------------------------ */

async function checkAuthState(): Promise<void> {
  authToken = await readStorage<string>(AUTH_TOKEN_KEY);
  const unlockState = await chrome.storage.session.get([UNLOCK_STATE_KEY]);
  const state = unlockState[UNLOCK_STATE_KEY] as { expiresAt: number } | undefined;

  if (state && Date.now() < state.expiresAt) {
    // Already unlocked in this session
    showView("unlocked");
    await loadCredentials();
  } else if (authToken) {
    // Authenticated but vault locked
    showView("locked");
  } else {
    // Not authenticated
    showView("login");
  }
}

async function handleUnlock(): Promise<void> {
  const passphrase = passphraseInput.value.trim();
  if (!passphrase) {
    lockError.textContent = "Passphrase required";
    lockError.hidden = false;
    return;
  }

  lockError.hidden = true;
  unlockBtn.disabled = true;
  unlockBtn.textContent = "Descifrando...";

  try {
    // Fetch vault list from API
    const vaultRes = await fetch(`${API_BASE}/api/v1/vaults`, {
      headers: { "Authorization": `Bearer ${authToken}` }
    });

    if (vaultRes.status === 401) {
      // Token expired, go back to login
      await writeStorage({ [AUTH_TOKEN_KEY]: null });
      authToken = null;
      showView("login");
      return;
    }

    const vaultData = await vaultRes.json();

    if (!vaultData.vaults || vaultData.vaults.length === 0) {
      lockError.textContent = "No vault found. Create one in the web app first.";
      lockError.hidden = false;
      return;
    }

    const vault = vaultData.vaults[0];

    // Get encrypted data
    const unlockRes = await fetch(`${API_BASE}/api/v1/vaults/${vault.id}/unlock`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${authToken}`,
        "Content-Type": "application/json"
      }
    });

    if (!unlockRes.ok) {
      throw new Error("Failed to fetch vault data");
    }

    const unlockData = await unlockRes.json();

    // Decrypt locally with passphrase
    const decrypted = await decryptVault(unlockData.encryptedData, passphrase);
    const parsedCredentials = JSON.parse(decrypted);

    // Store decrypted credentials temporarily
    await writeStorage({ [VAULT_KEY]: { ...vault, metadata: { credentials: parsedCredentials } } });

    // Set unlock session (30 min)
    await chrome.storage.session.set({
      [UNLOCK_STATE_KEY]: {
        vaultId: vault.id,
        unlockedAt: Date.now(),
        expiresAt: Date.now() + 30 * 60 * 1000,
      },
    });

    // Show unlocked view
    showView("unlocked");
    passphraseInput.value = "";
    await loadCredentials();

  } catch (err) {
    console.error("Unlock failed:", err);
    lockError.textContent = "Frase maestra incorrecta o error al descifrar";
    lockError.hidden = false;
  } finally {
    unlockBtn.disabled = false;
    unlockBtn.textContent = "Unlock";
  }
}

async function handleLock(): Promise<void> {
  await chrome.storage.session.remove(UNLOCK_STATE_KEY);
  await chrome.storage.local.remove(VAULT_KEY);
  isUnlocked = false;
  credentials = [];
  credentialList.innerHTML = "";
  showView("locked");
}

/* ------------------------------------------------------------------ */
/*  Credential Loading                                                 */
/* ------------------------------------------------------------------ */

async function loadCredentials(): Promise<void> {
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
/*  Credential Rendering                                               */
/* ------------------------------------------------------------------ */

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
    copyPassBtn.addEventListener("click", () => copyToClipboard(cred.password, copyPassBtn));

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
    password,
    url: url || undefined,
    tags: [],
    favorite: false,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

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

loginForm.addEventListener("submit", handleLogin);
unlockBtn.addEventListener("click", handleUnlock);
passphraseInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") handleUnlock();
});

lockToggle.addEventListener("click", () => {
  if (isUnlocked) handleLock();
  else {
    showView("locked");
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

checkAuthState();

})();
