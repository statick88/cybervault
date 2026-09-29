/**
 * CyberVault Popup — credential quick-access UI (Secure Storage Version)
 *
 * SECURITY INVARIANTS:
 * - NO plaintext secrets in chrome.storage.local
 * - Session key (VEK) ONLY in chrome.storage.session
 * - Credentials stored ENCRYPTED in local storage
 * - Decryption happens on-demand using session key from session storage
 *
 * Communicates with service worker via chrome.runtime.sendMessage
 * and uses master-key-manager for all crypto operations.
 */

import type {
  BackgroundMessage,
  BackgroundResponse,
} from "../../background/message-types";

/*
 * The message contract above is IMPORTED, not redeclared. This file used to
 * send messages typed as `Record<string, unknown>`, which is why it could send
 * UNLOCK_VAULT without the `vaultId` the worker requires and nothing complained
 * — a structural type erases the contract instead of checking it. Every send
 * below is now checked against the worker's own union.
 */

(function() {
/* ------------------------------------------------------------------ */
/*  Storage keys                                                       */
/* ------------------------------------------------------------------ */

const VAULT_KEY = "vault_data";           // Encrypted vault data only
const SETTINGS_KEY = "cybervault_settings";
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
  password: string;  // Only in memory, never persisted
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
  encryptedData: string;  // ENCRYPTED - ciphertext only
  encryptionKeyId: string;
  metadata?: Record<string, unknown>;
  createdAt: string;
  updatedAt: string;
}

interface LoginResponse {
  userId: string;
  email: string;
  token: string;
  refreshToken: string;
  message: string;
}

interface UnlockVaultResponse {
  encryptedData: string;  // Vault data encrypted with session key
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
const addError = $<HTMLParagraphElement>("#add-error");
const optionsLink = $<HTMLAnchorElement>("#options-link");

// Step-up (third factor)
const stepUpPanel = $<HTMLDivElement>("#step-up-panel");
const stepUpStatus = $<HTMLParagraphElement>("#step-up-status");
const stepUpPin = $<HTMLInputElement>("#step-up-pin");
const stepUpSubmit = $<HTMLButtonElement>("#step-up-submit");
const stepUpDismiss = $<HTMLButtonElement>("#step-up-dismiss");
const stepUpError = $<HTMLParagraphElement>("#step-up-error");

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
  message: BackgroundMessage,
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
/*  Secure Storage API (uses master-key-manager via background)       */
/* ------------------------------------------------------------------ */

async function unlockVaultWithPassphrase(
  passphrase: string,
  vaultId: string,
): Promise<BackgroundResponse<{ success: boolean; unlocked: boolean; vaultId: string }>> {
  return sendMessage({ type: "UNLOCK_VAULT", vaultId, passphrase });
}

async function lockVaultSecure(): Promise<void> {
  await sendMessage({ type: "LOCK_VAULT" });
}

async function encryptCredentialData(data: string): Promise<string | null> {
  const response = await sendMessage<string>({ type: "ENCRYPT_DATA", payload: data });
  return response.ok && typeof response.data === "string" ? response.data : null;
}

async function decryptCredentialData(encryptedData: string): Promise<string | null> {
  const response = await sendMessage<string>({ type: "DECRYPT_DATA", payload: encryptedData });
  return response.ok && typeof response.data === "string" ? response.data : null;
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
      authToken = data.token;
      await writeStorage({
        [AUTH_TOKEN_KEY]: data.token,
        [USER_ID_KEY]: data.userId,
        "cybervault_email": email
      });
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
/*  Vault Lock / Unlock (Secure)                                       */
/* ------------------------------------------------------------------ */

async function checkAuthState(): Promise<void> {
  authToken = await readStorage<string>(AUTH_TOKEN_KEY);

  // Check if vault is unlocked via secure storage
  const status = await sendMessage<{ unlocked: boolean }>({
    type: "CHECK_VAULT_STATUS"
  });

  if (status.ok && status.data?.unlocked) {
    isUnlocked = true;
    showView("unlocked");
    await loadCredentials();
    await checkPendingStepUp();
  } else if (authToken) {
    showView("locked");
  } else {
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

    // Get encrypted vault data
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

    const unlockData: UnlockVaultResponse = await unlockRes.json();

    // Unlock vault using secure storage (stores session key in session storage)
    const unlock = await unlockVaultWithPassphrase(passphrase, vault.id);

    if (!unlock.ok || !unlock.data?.unlocked) {
      throw new Error(unlock.error ?? "Frase maestra incorrecta o error al descifrar");
    }

    // Store encrypted vault data locally (ciphertext only).
    //
    // encryptedData must be a TOP-LEVEL field: loadCredentials() reads
    // vaultData.encryptedData, and the single writer above used to nest it
    // under metadata, so the guard there was always undefined and the popup
    // rendered "No credentials yet" after every successful unlock. The vault
    // list from GET /api/v1/vaults is a toSafeObject() that carries no
    // encryptedData either, so the spread never supplied one either.
    await writeStorage({
      [VAULT_KEY]: { ...vault, encryptedData: unlockData.encryptedData },
    });

    // Show unlocked view
    isUnlocked = true;
    showView("unlocked");
    passphraseInput.value = "";
    await loadCredentials();
    await checkPendingStepUp();

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
  await lockVaultSecure();
  await writeStorage({ [VAULT_KEY]: null });
  isUnlocked = false;
  credentials = [];
  credentialList.innerHTML = "";
  // The worker drops its step-up registries on lock; this UI must not keep
  // offering a PIN entry for a challenge that no longer exists.
  hideStepUp();
  showView("locked");
}

/* ------------------------------------------------------------------ */
/*  Credential Loading (Decrypt on-demand)                             */
/* ------------------------------------------------------------------ */

async function loadCredentials(): Promise<void> {
  const vaultData = await readStorage<VaultPlain>(VAULT_KEY);
  if (!vaultData?.encryptedData) {
    credentials = [];
    renderCredentialList([]);
    return;
  }

  // Decrypt credentials on-demand using session key
  const decrypted = await decryptCredentialData(vaultData.encryptedData);
  if (!decrypted) {
    credentials = [];
    renderCredentialList([]);
    return;
  }

  try {
    credentials = JSON.parse(decrypted) as CredentialPlain[];
    renderCredentialList(credentials);
  } catch {
    credentials = [];
    renderCredentialList([]);
  }
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
/*  Quick Add (Encrypt before storing)                                 */
/* ------------------------------------------------------------------ */

function showAddForm(): void {
  addForm.hidden = false;
  addTitle.focus();
}

function hideAddForm(): void {
  addForm.hidden = true;
  addError.hidden = true;
  addTitle.value = "";
  addUsername.value = "";
  addPassword.value = "";
  addUrl.value = "";
}

/**
 * Canonicalize the site a credential will be bound to.
 *
 * Returns null when the value is not an absolute http(s) origin. A bare host
 * such as `github.com` has no scheme and guessing one would bind the credential
 * to a site the user never named — `authorCredential` refuses the same inputs
 * on the worker side, so checking here simply tells the user what is wrong
 * instead of letting a save appear to succeed while authoring nothing.
 */
function toBoundOrigin(raw: string): string | null {
  const trimmed = raw.trim();
  if (trimmed === "") return null;
  try {
    const parsed = new URL(trimmed);
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return null;
    return parsed.origin;
  } catch {
    return null;
  }
}

function showAddError(message: string): void {
  addError.textContent = message;
  addError.hidden = false;
}

async function handleAddCredential(): Promise<void> {
  const title = addTitle.value.trim();
  const username = addUsername.value.trim();
  const password = addPassword.value;

  if (!title || !username || !password) {
    return;
  }

  const origin = toBoundOrigin(addUrl.value);
  if (!origin) {
    showAddError(
      "Add the site as a full origin, e.g. https://example.com — a credential with no site can never be filled.",
    );
    return;
  }
  addError.hidden = true;

  // The write side of the release store. The worker mints the id, validates the
  // origin and seals the secret; this supplies only what the user typed. Until
  // this call existed, `cybervault_cred_records` and `cybervault_cred_index`
  // had no writer at all, so autofill had nothing to release.
  const authored = await sendMessage<{
    id: string;
    title: string;
    usernameHint: string;
    origin: string;
  }>({
    type: "AUTHOR_CREDENTIAL",
    payload: { origin, username, password, title },
  });
  if (!authored.ok || !authored.data?.id) {
    showAddError(authored.error ?? "The credential could not be saved.");
    return;
  }

  const newCred: CredentialPlain = {
    id: authored.data.id,
    vaultId: "",
    title,
    username,
    password,
    url: origin,
    tags: [],
    favorite: false,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };

  // Add to in-memory list
  credentials.push(newCred);

  // Encrypt and store entire credentials array
  await saveCredentialsEncrypted();

  hideAddForm();
  renderCredentialList(credentials);
}

async function saveCredentialsEncrypted(): Promise<void> {
  const vaultData = await readStorage<VaultPlain>(VAULT_KEY);
  if (!vaultData) return;

  const encrypted = await encryptCredentialData(JSON.stringify(credentials));
  if (encrypted) {
    await writeStorage({ [VAULT_KEY]: { ...vaultData, encryptedData: encrypted } });
  }
}

/* ------------------------------------------------------------------ */
/*  Step-up (third factor)                                             */
/*                                                                     */
/*  The worker refuses a release whose policy demands a third factor    */
/*  and remembers WHICH release it refused. The content script that hit */
/*  the denial is gone by the time the user opens the popup, so the     */
/*  popup is the only place left to finish the flow: read the pending   */
/*  binding, start a challenge for it, collect the PIN, submit it.      */
/*  Without a sender here, START_STEP_UP and SUBMIT_STEP_UP_PIN were    */
/*  route cases nothing ever reached.                                   */
/* ------------------------------------------------------------------ */

/** Challenge the worker is currently holding for `pendingBinding`. */
let pendingChallengeId: string | null = null;
let pendingBinding: { credentialId: string; origin: string; operation: "AUTOFILL" | "TOTP" } | null = null;

function showStepUp(status: string): void {
  stepUpStatus.textContent = status;
  stepUpError.hidden = true;
  stepUpPanel.hidden = false;
}

function hideStepUp(): void {
  stepUpPanel.hidden = true;
  stepUpPin.value = "";
}

async function checkPendingStepUp(): Promise<void> {
  const pending = await sendMessage<
    Array<{ credentialId: string; origin: string; operation: "AUTOFILL" | "TOTP" }>
  >({ type: "GET_PENDING_STEP_UP" });

  const binding = pending.ok && Array.isArray(pending.data) ? pending.data[0] : undefined;
  if (!binding) {
    pendingChallengeId = null;
    pendingBinding = null;
    hideStepUp();
    return;
  }

  pendingBinding = binding;
  showStepUp(`Step-up required for ${binding.origin}. Requesting a challenge…`);

  const started = await sendMessage<{ challengeId: string }>({
    type: "START_STEP_UP",
    binding,
  });
  if (!started.ok || !started.data?.challengeId) {
    stepUpError.textContent = started.error ?? "The challenge could not be started.";
    stepUpError.hidden = false;
    return;
  }

  pendingChallengeId = started.data.challengeId;
  stepUpStatus.textContent = "Enter the PIN you received to release this credential.";
  stepUpSubmit.disabled = false;
}

async function handleSubmitStepUp(): Promise<void> {
  const pin = stepUpPin.value.trim();
  if (!pin || !pendingChallengeId) {
    stepUpError.textContent = "Enter the PIN from the challenge message.";
    stepUpError.hidden = false;
    return;
  }

  stepUpSubmit.disabled = true;
  try {
    const verified = await sendMessage({ type: "SUBMIT_STEP_UP_PIN", challengeId: pendingChallengeId, pin });
    if (!verified.ok) {
      stepUpError.textContent = verified.error ?? "the PIN was not accepted";
      stepUpError.hidden = false;
      return;
    }

    pendingChallengeId = null;
    pendingBinding = null;
    stepUpStatus.textContent = "Verified. Retry the fill to release the credential.";
    stepUpPin.value = "";
  } finally {
    stepUpSubmit.disabled = false;
  }
}

function handleDismissStepUp(): void {
  pendingChallengeId = null;
  pendingBinding = null;
  hideStepUp();
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
stepUpSubmit.addEventListener("click", handleSubmitStepUp);
stepUpPin.addEventListener("keydown", (e) => {
  if (e.key === "Enter") handleSubmitStepUp();
});
stepUpDismiss.addEventListener("click", handleDismissStepUp);
optionsLink.addEventListener("click", (e) => {
  e.preventDefault();
  openOptions();
});

/* ------------------------------------------------------------------ */
/*  Init                                                               */
/* ------------------------------------------------------------------ */

checkAuthState();

})();