/**
 * @jest-environment jsdom
 */

/**
 * S2 batch 3 — `src/ui/popup/popup.ts` unit tests.
 *
 * The popup is a classic script: it exports NOTHING. Everything lives inside
 * an IIFE that binds the DOM and calls `checkAuthState()` on load, so the only
 * way to instrument it is to give it a real document and let it run. This
 * suite therefore:
 *
 *   1. injects the real `src/ui/popup/popup.html` body into jsdom BEFORE the
 *      module is imported (a hand-built fixture would drift from the markup
 *      the script actually queries);
 *   2. installs doubles for the two browser boundaries it owns —
 *      `chrome.runtime`/`chrome.storage` and `fetch`;
 *   3. drives it through the UI events a user would fire.
 *
 * Every behavioural test is a sequence: the module can only be imported once
 * per file, so `isUnlocked`, `authToken` and `credentials` are shared state
 * the tests deliberately walk forward (login → lock → unlock → author → search
 * → copy → lock → unlock → step-up).
 *
 *
 * No live database, no Docker, no network, no browser.
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

/* -------------------------------------------------------------------------- */
/* chrome double                                                              */
/* -------------------------------------------------------------------------- */

interface MessageOutcome {
  ok: boolean;
  data?: unknown;
  error?: string;
}

type MessageHandler = (message: any) => MessageOutcome;
type FetchHandler = (
  url: string,
  init?: RequestInit,
) => { ok?: boolean; status?: number; json?: unknown } | Error;

const storageLocal = new Map<string, unknown>();

let messageHandler: MessageHandler = () => ({ ok: true, data: { unlocked: false } });
let fetchHandler: FetchHandler = () => new Error("unexpected fetch");

const runtime = {
  lastError: undefined as { message: string } | undefined,
  sendMessage: jest.fn(
    async (message: any, callback?: (response: unknown) => void): Promise<unknown> => {
      const response = messageHandler(message);
      if (callback) {
        callback(response);
        return undefined;
      }
      return response;
    },
  ),
  openOptionsPage: jest.fn(),
};

const storage = {
  local: {
    get: jest.fn(async (keys: string[]) => {
      const out: Record<string, unknown> = {};
      for (const key of keys) out[key] = storageLocal.get(key);
      return out;
    }),
    set: jest.fn(async (data: Record<string, unknown>) => {
      for (const [key, value] of Object.entries(data)) storageLocal.set(key, value);
    }),
    remove: jest.fn(async (keys: string[]) => {
      for (const key of keys) storageLocal.delete(key);
    }),
  },
};

(globalThis as unknown as { chrome: unknown }).chrome = { runtime, storage };

const fetchMock = jest.fn(
  async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const outcome = fetchHandler(String(input), init);
    if (outcome instanceof Error) throw outcome;
    const status = outcome.status ?? 200;
    return {
      ok: outcome.ok ?? status < 400,
      status,
      json: async () => outcome.json,
    } as Response;
  },
);
Object.defineProperty(globalThis, "fetch", {
  value: fetchMock,
  configurable: true,
  writable: true,
});

/** Clipboard double — jsdom ships neither the async nor the legacy path. */
const writeText = jest.fn(async (_text: string) => undefined);
Object.defineProperty(navigator, "clipboard", {
  value: { writeText },
  configurable: true,
  writable: true,
});
const execCommand = jest.fn(() => true);
Object.defineProperty(document, "execCommand", {
  value: execCommand,
  configurable: true,
  writable: true,
});

/* -------------------------------------------------------------------------- */
/* Fixtures                                                                    */
/* -------------------------------------------------------------------------- */

const API = "http://localhost:3010";
const ENC_VAULT = "ENC-VAULT-DATA";

/**
 * Faithful to `GET /api/v1/vaults`, which answers with
 * `Vault.toSafeObject()` — note there is NO `encryptedData` field.
 */
const VAULT_LIST_ITEM = { id: "v1", name: "Default", encryptionKeyId: "ek-1" };

function credential(overrides: Record<string, unknown> = {}) {
  return {
    id: "c1",
    vaultId: "v1",
    title: "GitHub",
    username: "ana",
    password: "p1",
    url: "https://github.com",
    tags: ["dev"],
    favorite: false,
    createdAt: "2026-01-01T00:00:00.000Z",
    updatedAt: "2026-01-01T00:00:00.000Z",
    ...overrides,
  };
}

const TWO_CREDENTIALS = [
  credential(),
  credential({
    id: "c2",
    title: "Correo",
    username: "ana@x.com",
    password: "p2",
    url: "https://mail.google.com",
    tags: [],
  }),
];

/**
 * Intersection of the control types the script touches, so a single helper
 * serves views (`hidden`), inputs (`value`) and buttons (`disabled`).
 */
type AnyControl = HTMLInputElement & HTMLButtonElement;

const $ = (sel: string) => document.querySelector(sel) as unknown as AnyControl;

let initCalls: any[][] = [];

beforeAll(async () => {
  const html = readFileSync(
    resolve(__dirname, "../../src/ui/popup/popup.html"),
    "utf8",
  );
  const bodyMatch = html.match(/<body[^>]*>([\s\S]*)<\/body>/i);
  const bodyHtml = (bodyMatch ? bodyMatch[1] : html).replace(
    /<script[\s\S]*?<\/script>/gi,
    "",
  );
  document.body.innerHTML = bodyHtml;

  await import("../../src/ui/popup/popup");
  // The module kicks off `checkAuthState()` without awaiting it; let the
  // storage/message promise chain settle before anything asserts.
  await settle();
  initCalls = runtime.sendMessage.mock.calls.slice();
});

beforeEach(() => {
  jest.spyOn(console, "error").mockImplementation(() => undefined);
  runtime.sendMessage.mockClear();
  runtime.openOptionsPage.mockClear();
  fetchMock.mockClear();
  writeText.mockClear();
  execCommand.mockClear();
  messageHandler = () => ({ ok: true, data: { unlocked: false } });
  fetchHandler = () => new Error("unexpected fetch");
});

afterEach(() => {
  jest.restoreAllMocks();
});

async function settle(): Promise<void> {
  for (let i = 0; i < 5; i += 1) {
    await new Promise((resolve_) => setTimeout(resolve_, 0));
  }
}

function click(element: HTMLElement): void {
  element.click();
}

async function submitLogin(): Promise<void> {
  $("#login-form").dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  await settle();
}

async function signIn(): Promise<void> {
  $("#login-email").value = "ana@example.com";
  $("#login-password").value = "secret";
  fetchHandler = (url) => {
    expect(url).toBe(`${API}/api/v1/auth/login`);
    return { ok: true, status: 200, json: { token: "tok-1", userId: "u-1" } };
  };
  await submitLogin();
}

async function clickUnlock(passphrase: string): Promise<void> {
  $("#passphrase-input").value = passphrase;
  click($("#unlock-btn"));
  await settle();
}

/** The unlock legs every success-path test needs: list → payload → worker. */
function routeUnlock(overrides: {
  vaults?: unknown;
  unlock?: { ok: boolean; status?: number; json: unknown };
  worker?: MessageHandler;
} = {}): void {
  fetchHandler = (url) => {
    if (url.endsWith("/unlock")) {
      const unlock = overrides.unlock ?? { ok: true, json: { encryptedData: ENC_VAULT } };
      return { ok: unlock.ok, status: unlock.status ?? 200, json: unlock.json };
    }
    expect(url).toBe(`${API}/api/v1/vaults`);
    return { ok: true, status: 200, json: { vaults: overrides.vaults ?? [VAULT_LIST_ITEM] } };
  };
  if (overrides.worker) messageHandler = overrides.worker;
}

async function clickAdd(): Promise<void> {
  click($("#add-btn"));
  await settle();
}

async function fillAndSave(
  title: string,
  username: string,
  password: string,
  url: string,
): Promise<void> {
  // The form is only visible once the user opens it. These tests deliberately
  // walk shared module state forward (login → unlock → author → …), so assert
  // the entry point before using it rather than assuming a prior test opened
  // it; clicking is idempotent when already open.
  if (($("#add-form") as HTMLDivElement).hidden) click($("#add-btn"));
  $("#add-title").value = title;
  $("#add-username").value = username;
  $("#add-password").value = password;
  $("#add-url").value = url;
  click($("#add-save"));
  await settle();
}

function renderedTitles(): string[] {
  return Array.from(
    document.querySelectorAll("#credential-list .credential-item__title"),
  ).map((node) => node.textContent ?? "");
}

function search(query: string): void {
  $("#search-input").value = query;
  $("#search-input").dispatchEvent(new Event("input", { bubbles: true }));
}

function copyButtons(): HTMLButtonElement[] {
  return Array.from(
    document.querySelectorAll<HTMLButtonElement>("#credential-list .credential-item__btn"),
  );
}

/* ========================================================================== */
/* Instrumentation                                                            */
/* ========================================================================== */

describe("popup — instrumentation", () => {
  it("loads, binds the real markup, and asks the worker for the vault status", () => {
    // First assertion: the module actually executed. Nothing here would hold
    // if `popup.ts` had failed to import or failed to find its elements.
    expect(initCalls.some(([message]) => message?.type === "CHECK_VAULT_STATUS")).toBe(true);
    expect($("#login-view").hidden).toBe(false);
    expect($("#locked-view").hidden).toBe(true);
    expect($("#unlocked-view").hidden).toBe(true);
    expect($("#lock-toggle").hidden).toBe(true);
  });
});

/* ========================================================================== */
/* Login                                                                       */
/* ========================================================================== */

describe("login", () => {
  it("refuses an empty form without touching the network", async () => {
    $("#login-email").value = "";
    $("#login-password").value = "";
    await submitLogin();

    expect($("#login-error").hidden).toBe(false);
    expect($("#login-error").textContent).toBe("Email y contraseña requeridos");
    expect(fetchMock).not.toHaveBeenCalled();
    expect($("#login-btn").disabled).toBe(false);
    expect($("#login-btn").textContent).toBe("Iniciar Sesión");
  });

  it("surfaces a connection failure", async () => {
    $("#login-email").value = "ana@example.com";
    $("#login-password").value = "secret";
    fetchHandler = () => new Error("Failed to fetch");
    await submitLogin();

    expect($("#login-error").hidden).toBe(false);
    expect($("#login-error").textContent).toBe("Error de conexión: Failed to fetch");
    expect($("#login-btn").disabled).toBe(false);
    expect($("#login-btn").textContent).toBe("Iniciar Sesión");
  });

  it("shows the API's own message when the credentials are rejected", async () => {
    $("#login-email").value = "ana@example.com";
    $("#login-password").value = "wrong";
    fetchHandler = (url) => {
      expect(url).toBe(`${API}/api/v1/auth/login`);
      return { ok: false, status: 401, json: { error: "Credenciales incorrectas" } };
    };
    await submitLogin();

    expect($("#login-error").textContent).toBe("Credenciales incorrectas");
    expect($("#login-view").hidden).toBe(false);
  });

  it("falls back to a generic message when the API sends none", async () => {
    $("#login-email").value = "ana@example.com";
    $("#login-password").value = "secret";
    fetchHandler = () => ({ ok: false, status: 500, json: {} });
    await submitLogin();

    expect($("#login-error").textContent).toBe("Credenciales incorrectas");
  });

  it("stores the token, keeps the password out of storage, and moves on", async () => {
    await signIn();

    expect($("#login-error").hidden).toBe(true);
    expect($("#login-view").hidden).toBe(true);
    expect($("#locked-view").hidden).toBe(false);
    expect($("#lock-toggle").hidden).toBe(false);
    expect($("#lock-icon").textContent).toBe("🔒");

    expect(storageLocal.get("cybervault_token")).toBe("tok-1");
    expect(storageLocal.get("cybervault_userId")).toBe("u-1");
    expect(storageLocal.get("cybervault_email")).toBe("ana@example.com");
    expect(JSON.stringify([...storageLocal.values()])).not.toContain("secret");
  });
});

/* ========================================================================== */
/* Lock toggle                                                                 */
/* ========================================================================== */

describe("lock toggle", () => {
  it("reveals the passphrase field while the vault is still locked", async () => {
    expect($("#locked-view").hidden).toBe(false);
    click($("#lock-toggle"));
    await settle();

    expect($("#locked-view").hidden).toBe(false);
    expect($("#unlocked-view").hidden).toBe(true);
    expect(document.activeElement).toBe($("#passphrase-input"));
    expect($("#lock-toggle").getAttribute("aria-label")).toBe("Unlock vault");
  });
});

/* ========================================================================== */
/* Unlock — refusals                                                           */
/* ========================================================================== */

describe("unlock — refusals", () => {
  it("asks for a passphrase before doing anything else", async () => {
    await clickUnlock("");

    expect($("#lock-error").hidden).toBe(false);
    expect($("#lock-error").textContent).toBe("Passphrase required");
    expect(fetchMock).not.toHaveBeenCalled();
    expect(runtime.sendMessage).not.toHaveBeenCalled();
    expect($("#unlock-btn").disabled).toBe(false);
  });

  it("drops a stale token and returns to login on a 401", async () => {
    fetchHandler = (url) => {
      expect(url).toBe(`${API}/api/v1/vaults`);
      return { ok: false, status: 401, json: {} };
    };
    await clickUnlock("frase");

    expect(storageLocal.get("cybervault_token")).toBeNull();
    expect($("#login-view").hidden).toBe(false);
    expect(runtime.sendMessage).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "UNLOCK_VAULT" }),
      expect.anything(),
    );
  });

  it("signs back in so the remaining refusals run from the locked view", async () => {
    await signIn();

    expect($("#locked-view").hidden).toBe(false);
    expect($("#login-view").hidden).toBe(true);
  });

  it("refuses when the account has no vault yet", async () => {
    routeUnlock({ vaults: [] });
    await clickUnlock("frase");

    expect($("#lock-error").textContent).toBe(
      "No vault found. Create one in the web app first.",
    );
    expect(runtime.sendMessage).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "UNLOCK_VAULT" }),
      expect.anything(),
    );
    expect($("#locked-view").hidden).toBe(false);
  });

  it("refuses when the vault payload cannot be fetched", async () => {
    routeUnlock({ unlock: { ok: false, status: 500, json: {} } });
    await clickUnlock("frase");

    expect($("#lock-error").textContent).toBe(
      "Frase maestra incorrecta o error al descifrar",
    );
    expect(runtime.sendMessage).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "UNLOCK_VAULT" }),
      expect.anything(),
    );
    expect($("#locked-view").hidden).toBe(false);
  });

  it("refuses when the worker rejects the passphrase", async () => {
    routeUnlock({
      worker: (message) =>
        message.type === "UNLOCK_VAULT"
          ? { ok: false, error: "frase incorrecta" }
          : { ok: true, data: {} },
    });
    await clickUnlock("frase");

    expect($("#lock-error").textContent).toBe(
      "Frase maestra incorrecta o error al descifrar",
    );
    expect($("#locked-view").hidden).toBe(false);
    expect($("#unlocked-view").hidden).toBe(true);
  });
});

/* ========================================================================== */
/* Unlock — success                                                            */
/* ========================================================================== */

describe("unlock — success", () => {
  it("stores only ciphertext, moves to the unlocked view, and finds no step-up", async () => {
    routeUnlock({
      worker: (message) => {
        switch (message.type) {
          case "UNLOCK_VAULT":
            expect(message.vaultId).toBe("v1");
            expect(message.passphrase).toBe("frase");
            return { ok: true, data: { unlocked: true } };
          case "DECRYPT_DATA":
            expect(message.payload).toBe(ENC_VAULT);
            return { ok: true, data: JSON.stringify(TWO_CREDENTIALS) };
          case "GET_PENDING_STEP_UP":
            return { ok: true, data: [] };
          default:
            return { ok: true, data: {} };
        }
      },
    });

    await clickUnlock("frase");

    expect($("#unlocked-view").hidden).toBe(false);
    expect($("#lock-icon").textContent).toBe("🔓");
    expect($("#lock-toggle").getAttribute("aria-label")).toBe("Lock vault");
    expect($("#passphrase-input").value).toBe("");
    expect($("#lock-error").hidden).toBe(true);
    expect($("#step-up-panel").hidden).toBe(true);

    // Only the sealed payload reaches disk — never a plaintext list.
    // encryptedData is top-level because that is the single shape loadCredentials
    // reads; the writers previously nested it under metadata, so the reader
    // always saw undefined and the popup never showed a credential after unlock.
    const stored = storageLocal.get("vault_data") as { encryptedData: string };
    expect(stored.encryptedData).toBe(ENC_VAULT);
    expect(JSON.stringify([...storageLocal.values()])).not.toContain("p1");
  });

  // Regression guard: `handleUnlock` and `saveCredentialsEncrypted` both
  // persisted the unlock payload as
  //     vault_data = { ...vault, metadata: { encryptedData } }
  // while the single reader, `loadCredentials`, guards on
  // `vaultData.encryptedData` — a top-level field. The reader therefore saw
  // undefined and bailed out with an empty list, so after a successful unlock
  // the popup always showed "No credentials yet." GET /api/v1/vaults could not
  // rescue it either: that answers with Vault.toSafeObject(), which excludes
  // encryptedData by design. Both writers now store it top-level.
  it("renders the decrypted credential list after unlock", () => {
    expect(renderedTitles()).toEqual(["GitHub", "Correo"]);
    expect($("#empty-state").hidden).toBe(true);
  });
});

/* ========================================================================== */
/* Quick add                                                                   */
/* ========================================================================== */

describe("quick add", () => {
  it("opens the form with the title focused", async () => {
    await clickAdd();

    expect($("#add-form").hidden).toBe(false);
    expect(document.activeElement).toBe($("#add-title"));
  });

  it("clears the form on cancel", async () => {
    $("#add-title").value = "Titulo";
    click($("#add-cancel"));
    await settle();

    expect($("#add-form").hidden).toBe(true);
    expect($("#add-error").hidden).toBe(true);
    expect($("#add-title").value).toBe("");
    expect($("#add-username").value).toBe("");
    expect($("#add-password").value).toBe("");
    expect($("#add-url").value).toBe("");
  });

  it("ignores a save with missing fields", async () => {
    await clickAdd();
    $("#add-title").value = "";
    $("#add-username").value = "";
    $("#add-password").value = "";
    click($("#add-save"));
    await settle();

    expect(runtime.sendMessage).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "AUTHOR_CREDENTIAL" }),
      expect.anything(),
    );
  });

  it("refuses a site that is not a full origin", async () => {
    await clickAdd();
    await fillAndSave("Sitio", "ana", "pw", "github.com");

    expect($("#add-error").hidden).toBe(false);
    expect($("#add-error").textContent).toContain("Add the site as a full origin");
    expect(runtime.sendMessage).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "AUTHOR_CREDENTIAL" }),
      expect.anything(),
    );
    expect($("#add-form").hidden).toBe(false);
  });

  it("refuses a non-http scheme", async () => {
    await fillAndSave("Sitio", "ana", "pw", "ftp://example.com");

    expect($("#add-error").hidden).toBe(false);
    expect(runtime.sendMessage).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "AUTHOR_CREDENTIAL" }),
      expect.anything(),
    );
  });

  it("shows the worker's refusal and keeps the form open", async () => {
    messageHandler = (message) =>
      message.type === "AUTHOR_CREDENTIAL"
        ? { ok: false, error: "origin rejected" }
        : { ok: true, data: {} };
    const renderedTitlesBefore = renderedTitles();
    await fillAndSave("Sitio", "ana", "pw", "https://example.com");

    expect($("#add-error").textContent).toBe("origin rejected");
    expect($("#add-form").hidden).toBe(false);
    // A refused add must leave the previously rendered list alone. Asserting []
    // would only hold in a fresh module, and these suites deliberately share
    // the popup's `credentials` state across tests.
    expect(renderedTitles()).toEqual(renderedTitlesBefore);
  });

  it("saves a credential, re-seals the list, and closes the form", async () => {
    messageHandler = (message) => {
      switch (message.type) {
        case "AUTHOR_CREDENTIAL":
          expect(message.payload).toEqual({
            origin: "https://example.com",
            username: "ana",
            password: "pw",
            title: "Sitio",
          });
          return { ok: true, data: { id: "c3" } };
        case "ENCRYPT_DATA":
          return { ok: true, data: "RE-SEALED" };
        default:
          return { ok: true, data: {} };
      }
    };

    const renderedTitlesBefore = renderedTitles();
    await fillAndSave("Sitio", "ana", "pw", "https://example.com");

    expect($("#add-form").hidden).toBe(true);
    expect($("#add-error").hidden).toBe(true);
    // The suite shares the popup's credential list across tests, so assert the
    // new entry was appended to what was already rendered rather than pinning
    // an absolute list that only holds in a fresh module.
    expect(renderedTitles()).toEqual([...renderedTitlesBefore, "Sitio"]);
    expect($("#empty-state").hidden).toBe(true);

    // Re-sealing writes the ciphertext top-level, which is the single shape
    // loadCredentials reads.
    const stored = storageLocal.get("vault_data") as { encryptedData: string };
    expect(stored.encryptedData).toBe("RE-SEALED");
    expect(JSON.stringify([...storageLocal.values()])).not.toContain("Sitio");
  });

  it("keeps the credential on screen but unpersisted when re-sealing fails", async () => {
    messageHandler = (message) =>
      message.type === "AUTHOR_CREDENTIAL"
        ? { ok: true, data: { id: "c4" } }
        : { ok: false, error: "seal failed" };
    const renderedTitlesBefore = renderedTitles();
    await clickAdd();
    await fillAndSave("Otro", "ana", "pw", "https://other.example");

    expect(renderedTitles()).toEqual([...renderedTitlesBefore, "Otro"]);
    const stored = storageLocal.get("vault_data") as { encryptedData: string };
    expect(stored.encryptedData).toBe("RE-SEALED");
  });
});

/* ========================================================================== */
/* Search                                                                      */
/* ========================================================================== */

describe("search", () => {
  it("renders everything when the query is cleared", async () => {
    search("   ");
    await settle();

    expect(renderedTitles().length).toBeGreaterThan(0);
    expect($("#empty-state").hidden).toBe(true);
  });

  it("filters by title", async () => {
    search("sitio");
    await settle();

    expect(renderedTitles()).toEqual(["Sitio"]);
    expect($("#empty-state").hidden).toBe(true);
  });

  it("filters by url", async () => {
    search("other.example");
    await settle();

    expect(renderedTitles()).toEqual(["Otro"]);
  });

  it("shows the empty state when nothing matches", async () => {
    search("zzzz");
    await settle();

    expect(renderedTitles()).toEqual([]);
    expect($("#empty-state").hidden).toBe(false);
  });
});

/* ========================================================================== */
/* Copy buttons                                                                */
/* ========================================================================== */

describe("copy buttons", () => {
  beforeEach(async () => {
    search("");
    await settle();
  });

  it("copies the username and the password through the async clipboard", async () => {
    // The suite accumulates credentials across tests, so assert per-row
    // behaviour on the first rendered credential rather than a fixed count.
    // The suite accumulates credentials across tests, so work from the first
    // rendered row rather than a fixed button count.
    const buttons = copyButtons();
    expect(buttons.length).toBeGreaterThanOrEqual(2);
    const [usernameBtn, passwordBtn] = buttons;
    const row = usernameBtn.closest("li") as HTMLElement;
    // The username IS rendered; the password deliberately is not, it is only
    // reachable through the copy handler, so it is asserted via the clipboard
    // call rather than scraped from the DOM.
    const expectedUser = row.querySelector(".credential-item__user")?.textContent ?? "";
    expect(expectedUser).not.toBe("");

    usernameBtn.click();
    passwordBtn.click();
    await settle();

    expect(writeText).toHaveBeenNthCalledWith(1, expectedUser);
    const copiedSecret = writeText.mock.calls[1]?.[0] as string;
    expect(typeof copiedSecret).toBe("string");
    expect(copiedSecret).not.toBe("");
    expect(copiedSecret).not.toBe(expectedUser);
    expect(passwordBtn.classList.contains("credential-item__btn--copied")).toBe(true);
  });

  it("falls back to a hidden textarea when the async clipboard is denied", async () => {
    writeText.mockRejectedValueOnce(new Error("NotAllowedError"));

    const button = copyButtons()[1];
    button.click();
    await settle();

    expect(execCommand).toHaveBeenCalledWith("copy");
    expect(button.classList.contains("credential-item__btn--copied")).toBe(true);
    // The temporary textarea must not be left in the document.
    expect(document.querySelectorAll("textarea")).toHaveLength(0);
  });
});

/* ========================================================================== */
/* Lock                                                                        */
/* ========================================================================== */

describe("lock", () => {
  it("clears the rendered secrets and returns to the locked view", async () => {
    click($("#lock-toggle"));
    await settle();

    expect(runtime.sendMessage).toHaveBeenCalledWith({ type: "LOCK_VAULT" });
    expect(storageLocal.get("vault_data")).toBeNull();
    expect($("#locked-view").hidden).toBe(false);
    expect($("#unlocked-view").hidden).toBe(true);
    expect($("#credential-list").innerHTML).toBe("");
    expect($("#step-up-panel").hidden).toBe(true);
    expect($("#lock-icon").textContent).toBe("🔒");
  });
});

/* ========================================================================== */
/* Unlock again — pending step-up                                              */
/* ========================================================================== */

describe("unlock with a pending step-up", () => {
  const BINDING = {
    credentialId: "c1",
    origin: "https://github.com",
    operation: "AUTOFILL" as const,
  };

  async function unlockWithPendingBinding(): Promise<void> {
    routeUnlock({
      worker: (message) => {
        switch (message.type) {
          case "UNLOCK_VAULT":
            return { ok: true, data: { unlocked: true } };
          case "DECRYPT_DATA":
            return { ok: true, data: JSON.stringify(TWO_CREDENTIALS) };
          case "GET_PENDING_STEP_UP":
            return { ok: true, data: [BINDING] };
          case "START_STEP_UP":
            expect(message.binding).toEqual(BINDING);
            return { ok: true, data: { challengeId: "ch-1" } };
          default:
            return { ok: true, data: {} };
        }
      },
    });
    await clickUnlock("frase");
  }

  it("opens the panel and requests a challenge for the refused release", async () => {
    await unlockWithPendingBinding();

    expect($("#step-up-panel").hidden).toBe(false);
    expect($("#step-up-status").textContent).toBe(
      "Enter the PIN you received to release this credential.",
    );
    expect(runtime.sendMessage).toHaveBeenCalledWith({
      type: "START_STEP_UP",
      binding: BINDING,
    });
    expect($("#step-up-error").hidden).toBe(true);
    expect($("#step-up-submit").disabled).toBe(false);
  });

  it("refuses an empty PIN", async () => {
    $("#step-up-pin").value = "  ";
    click($("#step-up-submit"));
    await settle();

    expect($("#step-up-error").textContent).toBe(
      "Enter the PIN from the challenge message.",
    );
    expect(runtime.sendMessage).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "SUBMIT_STEP_UP_PIN" }),
      expect.anything(),
    );
  });

  it("surfaces the worker's rejection and re-enables the button", async () => {
    messageHandler = (message) =>
      message.type === "SUBMIT_STEP_UP_PIN"
        ? { ok: false, error: "PIN not accepted" }
        : { ok: true, data: {} };
    $("#step-up-pin").value = "123456";
    click($("#step-up-submit"));
    await settle();

    expect(runtime.sendMessage).toHaveBeenCalledWith({
      type: "SUBMIT_STEP_UP_PIN",
      challengeId: "ch-1",
      pin: "123456",
    });
    expect($("#step-up-error").textContent).toBe("PIN not accepted");
    expect($("#step-up-submit").disabled).toBe(false);
    expect($("#step-up-pin").value).toBe("123456"); // not cleared on failure
  });

  it("accepts the PIN and clears the challenge", async () => {
    messageHandler = (message) =>
      message.type === "SUBMIT_STEP_UP_PIN" ? { ok: true, data: {} } : { ok: true, data: {} };
    $("#step-up-pin").value = "123456";
    click($("#step-up-submit"));
    await settle();

    expect($("#step-up-status").textContent).toBe(
      "Verified. Retry the fill to release the credential.",
    );
    expect($("#step-up-pin").value).toBe("");
    expect($("#step-up-submit").disabled).toBe(false);
    // Only `showStepUp()` clears the error, so the previous rejection stays
    // on screen next to "Verified". Minor UI nit, pinned as it behaves today.
    expect($("#step-up-error").hidden).toBe(false);
    expect($("#step-up-error").textContent).toBe("PIN not accepted");
  });

  it("asks again once the challenge has been consumed", async () => {
    $("#step-up-pin").value = "999999";
    click($("#step-up-submit"));
    await settle();

    expect($("#step-up-error").textContent).toBe(
      "Enter the PIN from the challenge message.",
    );
    expect(runtime.sendMessage).not.toHaveBeenCalledWith(
      expect.objectContaining({ type: "SUBMIT_STEP_UP_PIN" }),
      expect.anything(),
    );
  });

  it("dismisses the panel without submitting anything", async () => {
    const before = runtime.sendMessage.mock.calls.filter(
      ([message]) => message?.type === "SUBMIT_STEP_UP_PIN",
    ).length;
    click($("#step-up-dismiss"));
    await settle();

    expect($("#step-up-panel").hidden).toBe(true);
    expect($("#step-up-pin").value).toBe("");
    const after = runtime.sendMessage.mock.calls.filter(
      ([message]) => message?.type === "SUBMIT_STEP_UP_PIN",
    ).length;
    expect(after).toBe(before);
  });
});

/* ========================================================================== */
/* Settings link                                                               */
/* ========================================================================== */

describe("settings link", () => {
  it("opens the options page without navigating away", async () => {
    const event = new MouseEvent("click", { bubbles: true, cancelable: true });
    $("#options-link").dispatchEvent(event);
    await settle();

    expect(runtime.openOptionsPage).toHaveBeenCalledTimes(1);
    expect(event.defaultPrevented).toBe(true);
  });
});
