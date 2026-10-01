/**
 * @jest-environment jsdom
 * @jest-environment-options {"url": "https://accounts.example.com/register"}
 */

/**
 * S2 batch 3 — `src/domain/services/autocompletado/autocomplete-service.ts`.
 *
 * Environment notes:
 *   - jsdom has no `TextEncoder` / `TextDecoder`, and
 *     `EntropyValidator.validatePasswordEntropy()` needs them, so Node's
 *     implementations are installed before any credential is generated.
 *   - `AutocompleteService.start()` observes `document.body` with a
 *     `MutationObserver` and then appends its own suggestion card into that
 *     same subtree, so the raw service re-enters itself until the microtask
 *     queue starves (macrotasks — including Jest's timers — never run). Every
 *     test therefore installs a *bounded* observer that forwards at most
 *     `observerBound` deliveries to the service. The default is 0, which
 *     makes rendering deterministic; the dedicated regression tests below
 *     raise it to expose the loop without hanging the suite.
 *
 * No live database, no Docker, no network, no browser.
 */

import { TextDecoder, TextEncoder } from "node:util";

import { AutocompleteService } from "../../../src/domain/services/autocompletado/autocomplete-service";

for (const [name, value] of Object.entries({ TextEncoder, TextDecoder })) {
  if (typeof (globalThis as Record<string, unknown>)[name] !== "function") {
    Object.defineProperty(globalThis, name, {
      value,
      configurable: true,
      writable: true,
    });
  }
}

const DOMAIN = "accounts.example.com";

const REGISTRATION_FORM = `
  <form id="register-form" action="/register">
    <input type="email" name="email" id="email-field" />
    <input type="password" name="password" id="password-field" />
    <button type="submit">Crear cuenta</button>
  </form>`;

const RealMutationObserver = globalThis.MutationObserver;
let observerDeliveries = 0;
let observerBound = 0;

class BoundedMutationObserver extends RealMutationObserver {
  constructor(callback: MutationCallback) {
    super((records, observer) => {
      if (observerDeliveries >= observerBound) return;
      observerDeliveries += 1;
      callback(records, observer);
    });
  }
}

function cardCount(): number {
  return document.querySelectorAll(".cybervault-suggestion-container").length;
}

function card(index = 0): HTMLElement {
  const found = document.querySelectorAll(".cybervault-suggestion-container")[index];
  if (!found) throw new Error(`no suggestion card #${index}`);
  return found as HTMLElement;
}

/** Drain the microtask queue (the service's whole pipeline is microtasks). */
async function flush(): Promise<void> {
  await new Promise((resolve) => setTimeout(resolve, 0));
  await new Promise((resolve) => setTimeout(resolve, 0));
}

function input(id: string): HTMLInputElement {
  const el = document.getElementById(id);
  if (!el) throw new Error(`no #${id}`);
  return el as HTMLInputElement;
}

let service: AutocompleteService;
let alertSpy: jest.SpyInstance;

beforeEach(() => {
  document.head.innerHTML = "";
  document.body.innerHTML = "";
  observerDeliveries = 0;
  observerBound = 0;
  globalThis.MutationObserver =
    BoundedMutationObserver as unknown as typeof MutationObserver;

  jest.spyOn(console, "log").mockImplementation(() => undefined);
  jest.spyOn(console, "warn").mockImplementation(() => undefined);
  jest.spyOn(console, "info").mockImplementation(() => undefined);
  jest.spyOn(console, "error").mockImplementation(() => undefined);
  document.addEventListener("submit", (event) => event.preventDefault());

  alertSpy = jest.spyOn(window, "alert").mockImplementation(() => undefined);
  service = new AutocompleteService();
});

afterEach(() => {
  jest.restoreAllMocks();
  globalThis.MutationObserver = RealMutationObserver;
});

/* ========================================================================== */
/* Instrumentation                                                            */
/* ========================================================================== */

describe("AutocompleteService — instrumentation", () => {
  it("loads and instruments the module under test", () => {
    expect(typeof AutocompleteService).toBe("function");
    expect(service).toBeInstanceOf(AutocompleteService);
    expect(typeof service.start).toBe("function");
    expect(typeof service.getStoredCredentials).toBe("function");
    expect(typeof service.clearAllSuggestions).toBe("function");
    expect(service.getStoredCredentials(DOMAIN)).toBeUndefined();
  });

  it("starts cleanly on a page with no registration form", async () => {
    document.body.innerHTML = `<p>Nothing to fill in.</p>`;

    service.start();
    await flush();

    expect(cardCount()).toBe(0);
    expect(service.getStoredCredentials(DOMAIN)).toBeUndefined();
    expect(observerDeliveries).toBe(0);
  });
});

/* ========================================================================== */
/* Rendering the suggestion card                                               */
/* ========================================================================== */

describe("suggestion card", () => {
  beforeEach(() => {
    document.body.innerHTML = REGISTRATION_FORM;
  });

  // Regression guard for the observer self-trigger loop (defect #8).
  //
  // setupEventListeners() observes document.body with {childList: true,
  // subtree: true} so single-page-app forms are picked up, and
  // showSuggestionUI() appends the suggestion card into that same subtree.
  // Treating our own append as a page change re-entered checkCurrentPage(),
  // which appended again, which re-entered the observer. MutationObserver
  // callbacks are microtasks, so macrotasks (timers, painting, input) never
  // got a turn and any page with a registration form froze.
  //
  // The fix filters deliveries whose added nodes are all our own container.
  // Counting the DOM converging proves the cycle is dead; counting observer
  // deliveries would only prove the observer was never called at all, which is
  // a weaker and less honest signal.
  it("settles instead of re-detecting when its own card mutates the observed subtree", async () => {
    observerBound = 0; // no bound: this must terminate on its own
    document.body.innerHTML = REGISTRATION_FORM;

    service.start();
    await flush();

    expect(cardCount()).toBe(1);
  });
});
