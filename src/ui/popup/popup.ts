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
// R11 — proof material is built HERE, in the popup: the only context where
// the passphrase is typed or `navigator.credentials` may be invoked. The
// module is browser-safe by design (no node:crypto), so esbuild's browser
// bundle gets the exact same PBKDF2 algebra Core verifies with.
import type { StepUpProof } from "../../infrastructure/crypto/step-up-proof";
import {
  base64UrlToBytes,
  bytesToBase64Url,
  derivePassphraseProof,
} from "../../infrastructure/crypto/step-up-proof";

// RQ2 Pilot
import { recordGestureStart } from "../../background/rq2-pilot";

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
const stepUpDetail = $<HTMLParagraphElement>("#step-up-detail");
const stepUpSubmit = $<HTMLButtonElement>("#step-up-submit");
const stepUpDismiss = $<HTMLButtonElement>("#step-up-dismiss");
const stepUpError = $<HTMLParagraphElement>("#step-up-error");
// R11 — the passphrase proof field and the device enrollment button.
const stepUpPassphrase = $<HTMLInputElement>("#step-up-passphrase");
const stepUpRegister = $<HTMLButtonElement>("#step-up-register");

/* ------------------------------------------------------------------ */
/*  State                                                              */
/* ------------------------------------------------------------------ */

let isUnlocked = false;
let credentials: CredentialPlain[] = [];
let authToken: string | null | undefined = null;

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

/**
 * TypeScript 5.9 types `BufferSource` as `ArrayBufferView<ArrayBuffer>`, but
 * a `Uint8Array` from `base64UrlToBytes` is `Uint8Array<ArrayBufferLike>`.
 * The repo widens at exactly this boundary (`as unknown as BufferSource` in
 * EncryptionService and step-up-proof); this is the same widening, named
 * once, for the `navigator.credentials` calls below.
 */
const asSource = (bytes: Uint8Array): BufferSource => bytes as unknown as BufferSource;

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
/*  binding, start a challenge for it, and take the user's approval.  */
/*  Without a sender here, START_STEP_UP and APPROVE_STEP_UP were      */
/*  route cases nothing ever reached.                                   */
/* ------------------------------------------------------------------ */

/** Challenge the worker is currently holding for `pendingBinding`. */
let pendingChallengeId: string | null = null;
let pendingBinding: { credentialId: string; origin: string; operation: "AUTOFILL" | "TOTP" } | null = null;

/** The approval-challenge shape Core returns (phase 1 of R11). */
interface ApprovalChallenge {
  approvalChallengeId: string;
  /** The binding id: the release challengeId for release, the row id for enroll. */
  challengeId: string;
  purpose: "release" | "enroll";
  challenge: string;
  salt: string;
  userSalt: string;
  rpId: string | null;
  hasAuthenticator: boolean;
  credentialIds: string[];
  expiresAt: number;
}

function showStepUp(status: string): void {
  stepUpStatus.textContent = status;
  stepUpError.hidden = true;
  stepUpPanel.hidden = false;
}

function hideStepUp(): void {
  stepUpPanel.hidden = true;
  stepUpDetail.textContent = "";
  // R11: unlike R3's empty panel, the panel now holds typed material — a
  // passphrase in the input. It is never persisted, but it must not survive
  // the panel either.
  stepUpPassphrase.value = "";
}

function showStepUpError(message: string): void {
  stepUpError.textContent = message;
  stepUpError.hidden = false;
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
  // A different release means different proof material: never let a passphrase
  // typed for one challenge be reused as if it belonged to the next.
  stepUpPassphrase.value = "";
  showStepUp(`Step-up required for ${binding.origin}. Requesting a challenge…`);

  const started = await sendMessage<{ challengeId: string }>({
    type: "START_STEP_UP",
    binding,
  });
  if (!started.ok || !started.data?.challengeId) {
    showStepUpError(started.error ?? "The challenge could not be started.");
    return;
  }

  pendingChallengeId = started.data.challengeId;
  // R3: tell the user exactly what they are authorising. They are the one
  // approving, so the site and the operation are the whole point of the
  // prompt — a generic "confirm?" would make a blind click indistinguishable
  // from a deliberate one.
  stepUpStatus.textContent = "Approve releasing this credential to the site below?";
  stepUpDetail.textContent = `${binding.origin} · ${binding.operation}`;
  stepUpSubmit.disabled = false;
}

/**
 * Phase 1 — fetch the one-time material a proof is bound to, directly from
 * Core (the same Bearer-authenticated `fetch` pattern as login and vaults).
 *
 * Called fresh on EVERY attempt: a failed proof burns the row server-side,
 * so reusing a previous response would fail even with correct material.
 * The response never contains anything a stolen token could turn into a
 * valid proof on its own — `salt`/`userSalt` are useless without the
 * passphrase, and the WebAuthn parts are useless without the authenticator.
 */
async function fetchApprovalChallenge(
  challengeId: string,
  purpose: "release" | "enroll",
): Promise<ApprovalChallenge | { error: string }> {
  if (!authToken) return { error: "You are not signed in." };
  try {
    const res = await fetch(`${API_BASE}/api/v1/step-up/approval-challenge`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${authToken}`,
      },
      body: JSON.stringify({ challengeId, purpose }),
    });
    const body = (await res.json().catch(() => ({}))) as {
      approvalChallenge?: ApprovalChallenge;
      error?: string;
    };
    if (!res.ok || !body.approvalChallenge) {
      // Deliberately generic: which part of the request failed is not the
      // popup's business to narrate.
      return { error: body.error ?? "The approval challenge is unavailable." };
    }
    return body.approvalChallenge;
  } catch {
    return { error: "Could not reach the approval service." };
  }
}

/**
 * Build a WebAuthn assertion for `challenge`, or null when no authenticator
 * is available / the ceremony was cancelled or failed.
 *
 * Cancellation returns null WITHOUT an inline error so the caller can steer
 * the user toward the passphrase fallback instead of dead-ending on
 * "NotAllowedError".
 */
async function getWebAuthnAssertionProof(
  challenge: ApprovalChallenge,
): Promise<StepUpProof | null> {
  if (
    !challenge.hasAuthenticator ||
    !challenge.rpId ||
    !challenge.credentialIds.length ||
    !navigator.credentials?.get
  ) {
    return null;
  }
  try {
    const credential = (await navigator.credentials.get({
      publicKey: {
        challenge: asSource(base64UrlToBytes(challenge.challenge)),
        rpId: challenge.rpId,
        allowCredentials: challenge.credentialIds.map((id) => ({
          id: asSource(base64UrlToBytes(id)),
          type: "public-key" as const,
        })),
        userVerification: "required" as const,
        timeout: 60_000,
      },
    })) as PublicKeyCredential | null;
    if (!credential?.response) return null;
    const response = credential.response as AuthenticatorAssertionResponse;
    return {
      type: "webauthn",
      challengeId: challenge.challengeId,
      approvalChallengeId: challenge.approvalChallengeId,
      credentialId: bytesToBase64Url(new Uint8Array(credential.rawId)),
      clientDataJSON: bytesToBase64Url(new Uint8Array(response.clientDataJSON)),
      authenticatorData: bytesToBase64Url(new Uint8Array(response.authenticatorData)),
      signature: bytesToBase64Url(new Uint8Array(response.signature)),
    };
  } catch {
    // User cancelled, the authenticator is unavailable, or the browser
    // refused — all answered by the passphrase fallback, not an error here.
    return null;
  }
}

/**
 * Turn the phase-1 challenge + what the user provided into a proof.
 *
 * Precedence is deliberate:
 *   1. a filled passphrase field → passphrase proof (an explicit choice);
 *   2. else a registered device → WebAuthn assertion (the stronger factor);
 *   3. else → a message that names what the user must do.
 *
 * The passphrase path derives LOCALLY: hop 1 reproduces `users.hash` from
 * the typed passphrase and `userSalt`, hop 2 binds it to this one challenge.
 * Core receives only the hop-2 value — never the passphrase.
 */
async function buildApprovalProof(
  challenge: ApprovalChallenge,
): Promise<StepUpProof | { error: string }> {
  const passphrase = stepUpPassphrase.value;
  if (passphrase) {
    try {
      const value = await derivePassphraseProof(
        passphrase,
        challenge.userSalt,
        challenge.challengeId,
        challenge.salt,
      );
      return {
        type: "passphrase",
        challengeId: challenge.challengeId,
        approvalChallengeId: challenge.approvalChallengeId,
        value,
      };
    } catch {
      return { error: "The approval proof could not be derived." };
    }
  }

  const assertion = await getWebAuthnAssertionProof(challenge);
  if (assertion) return assertion;

  if (challenge.hasAuthenticator) {
    return {
      error: "The device check was not completed. Try again, or enter your passphrase.",
    };
  }
  return { error: "Enter your passphrase to approve this release." };
}

async function handleSubmitStepUp(): Promise<void> {
  if (!pendingChallengeId) {
    showStepUpError("There is no pending approval.");
    return;
  }

  stepUpSubmit.disabled = true;
  stepUpError.hidden = true;
  try {
    // Phase 1: one-time material, fetched fresh for this attempt.
    const challenge = await fetchApprovalChallenge(pendingChallengeId, "release");
    if ("error" in challenge) {
      showStepUpError(challenge.error);
      return;
    }

    const proof = await buildApprovalProof(challenge);
    if ("error" in proof) {
      showStepUpError(proof.error);
      return;
    }

    // Phase 2: the worker forwards the proof verbatim — it never sees the
    // passphrase, and cannot forge a proof it does not build.
    // Phase 2: the worker forwards the proof verbatim — it never sees the
  // passphrase, and cannot forge a proof it does not build.
  // RQ2 Pilot: record gesture start (user interaction with authenticator)
  await recordGestureStart();

  const verified = await sendMessage({
    type: "APPROVE_STEP_UP",
    challengeId: pendingChallengeId,
    proof,
  });
    if (!verified.ok) {
      showStepUpError(verified.error ?? "the approval was not accepted");
      // The approval challenge was burned by the failed attempt; the typed
      // material must not linger to be silently reused against the next one.
      stepUpPassphrase.value = "";
      return;
    }

    stepUpPassphrase.value = "";
    pendingChallengeId = null;
    pendingBinding = null;
    stepUpStatus.textContent = "Approved. Retry the fill to release the credential.";
    stepUpDetail.textContent = "";
  } catch {
    showStepUpError("The approval could not be completed.");
  } finally {
    stepUpSubmit.disabled = false;
    stepUpRegister.disabled = false;
  }
}

/**
 * R11 — bind an authenticator so later releases can use a real assertion
 * instead of the passphrase fallback. Runs WHILE the release stays pending:
 * registration is proof-gated server-side with its own one-time challenge
 * (purpose `enroll`), and a proof minted for enrollment can never approve a
 * release (the server checks `purpose` on the consumed row).
 */
async function handleRegisterStepUp(): Promise<void> {
  if (!pendingChallengeId) {
    showStepUpError("There is no pending approval to register from.");
    return;
  }

  stepUpRegister.disabled = true;
  stepUpSubmit.disabled = true;
  stepUpError.hidden = true;
  try {
    const challenge = await fetchApprovalChallenge(pendingChallengeId, "enroll");
    if ("error" in challenge) {
      showStepUpError(challenge.error);
      return;
    }

    const proof = await buildApprovalProof(challenge);
    if ("error" in proof) {
      showStepUpError(proof.error);
      return;
    }

    if (!challenge.rpId || !navigator.credentials?.create) {
      showStepUpError("This browser cannot register an approval device.");
      return;
    }
    const userId = await readStorage<string>(USER_ID_KEY);
    const email = await readStorage<string>("cybervault_email");
    if (!userId || !email) {
      showStepUpError("Your account could not be identified.");
      return;
    }

    const created = (await navigator.credentials.create({
      publicKey: {
        challenge: asSource(base64UrlToBytes(challenge.challenge)),
        rp: { id: challenge.rpId, name: "Cyber Vault" },
        user: {
          // Stable per account: the authenticator uses it to distinguish
          // credentials of the same relying party.
          id: new TextEncoder().encode(userId),
          name: email,
          displayName: email,
        },
        // ES256 only — the server's verifier exists for exactly this alg.
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
        authenticatorSelection: {
          userVerification: "required",
          residentKey: "preferred",
        },
        // Attestation would send a device-identifying statement Core has no
        // policy for; the assertion path verifies with the bare key.
        attestation: "none",
        timeout: 60_000,
      },
    })) as PublicKeyCredential | null;
    if (!created?.response) {
      showStepUpError("The device was not registered.");
      return;
    }

    const attestation = created.response as AuthenticatorAttestationResponse;
    const publicKey = attestation.getPublicKey?.();
    if (!publicKey) {
      // Without the key there is nothing to verify later assertions against.
      showStepUpError("The device was not registered.");
      return;
    }
    const getTransports = (
      attestation as unknown as { getResponseTransports?: () => string[] }
    ).getResponseTransports;
    const transports =
      typeof getTransports === "function" ? getTransports.call(attestation) : [];

    const res = await fetch(`${API_BASE}/api/v1/step-up/authenticator/register`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${authToken ?? ""}`,
      },
      body: JSON.stringify({
        proof,
        credentialId: bytesToBase64Url(new Uint8Array(created.rawId)),
        // DER SubjectPublicKeyInfo, exactly `getPublicKey()` returned — the
        // server parses SPKI (with COSE accepted) and normalizes to raw.
        publicKey: bytesToBase64Url(new Uint8Array(publicKey)),
        alg: -7,
        transports,
      }),
    });
    if (!res.ok) {
      showStepUpError("The device could not be registered.");
      return;
    }

    stepUpPassphrase.value = "";
    stepUpStatus.textContent = "Device registered. Approve the release when ready.";
  } catch {
    showStepUpError("The device could not be registered.");
  } finally {
    stepUpRegister.disabled = false;
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
stepUpRegister.addEventListener("click", handleRegisterStepUp);
stepUpDismiss.addEventListener("click", handleDismissStepUp);
stepUpPassphrase.addEventListener("keydown", (e) => {
  if (e.key === "Enter") handleSubmitStepUp();
});
optionsLink.addEventListener("click", (e) => {
  e.preventDefault();
  openOptions();
});

/* ------------------------------------------------------------------ */
/*  Init                                                               */
/* ------------------------------------------------------------------ */

checkAuthState();

})();