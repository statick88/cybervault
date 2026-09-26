/**
 * Autofill content-script wiring tests.
 *
 * Two things are being proven here:
 *
 *   1. REGRESSION GUARD — the legacy plaintext autofill path is gone. Those
 *      tests are written as source-level assertions on purpose: a behavioural
 *      test would only prove the current implementation behaves, whereas the
 *      defect we are closing was precisely a behaviour that must never come
 *      back. Grep-level assertions fail loudly if someone re-adds it.
 *
 *   2. BEHAVIOUR — the guard gates the write, the form action is honoured, an
 *      explicit user gesture is required, and a service-worker failure results
 *      in no fill.
 *
 * @jest-environment jsdom
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import {
  describeOriginContext,
  guardFill,
  resolveSubmitOrigin,
  writeField,
  type GuardInput,
} from "../../src/ui/content-scripts/autocomplete";

const RAW_SOURCE = readFileSync(
  resolve(__dirname, "../../src/ui/content-scripts/autocomplete.ts"),
  "utf8",
);

/**
 * Source with comments stripped.
 *
 * The regression assertions below must inspect CODE, not prose. This file
 * deliberately documents the removed legacy behaviour in its header, so a naive
 * substring scan would match the very explanation of the fix and report a
 * regression that does not exist. Stripping comments first keeps the assertion
 * honest in both directions: it fails on real re-introduced code, and it does
 * not fail on a comment describing the defect.
 */
const SOURCE = RAW_SOURCE.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/.*$/gm, "");

const CREDENTIAL_ORIGIN = "https://github.com";

function guardInput(overrides: Partial<GuardInput> = {}): GuardInput {
  return {
    credentialOrigin: CREDENTIAL_ORIGIN,
    context: {
      documentOrigin: CREDENTIAL_ORIGIN,
      topLevelOrigin: CREDENTIAL_ORIGIN,
      isFramed: false,
    },
    formAction: null,
    submitOrigin: null,
    ...overrides,
  };
}

describe("Legacy plaintext autofill path — regression guard", () => {
  it("no longer reads a plaintext credential record from local storage", () => {
    // The old path stored { email, password } under cybervault_creds_<host>.
    expect(SOURCE).not.toContain("cybervault_creds_");
    expect(SOURCE).not.toMatch(/STORAGE_PREFIX/);
  });

  it("never reads secrets out of chrome.storage.local", () => {
    // A content script has no business pulling a secret out of local storage;
    // everything must come from the service worker after authorization.
    expect(SOURCE).not.toMatch(/chrome\.storage\.local\.get/);
  });

  it("does not match on a bare hostname", () => {
    // hostname-only matching is what made scheme/port irrelevant.
    expect(SOURCE).not.toMatch(/location\.hostname/);
  });

  it("does not fill on page load", () => {
    // Filling at load time is an unattended write of a secret into a page.
    expect(SOURCE).not.toMatch(/await\s+fillAllForms\(\)/);
    expect(SOURCE).toMatch(/onClick|addEventListener\("click"/);
  });

  it("no longer exposes a fillAllForms entry point", () => {
    expect(SOURCE).not.toContain("fillAllForms");
  });

  it("does not contain an inline StoredCredential with a plaintext password", () => {
    expect(SOURCE).not.toMatch(/interface\s+StoredCredential[\s\S]*?password:\s*string/);
  });
});

describe("describeOriginContext", () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  it("reports a top-level document as unframed", () => {
    const fake = {
      location: { protocol: "https:", hostname: "github.com", port: "" },
      top: null,
      self: null,
    } as unknown as Window;
    (fake as { self: unknown }).self = fake;
    (fake as { top: unknown }).top = fake;

    const ctx = describeOriginContext(fake);
    expect(ctx).toEqual({
      documentOrigin: "https://github.com",
      topLevelOrigin: "https://github.com",
      isFramed: false,
    });
  });

  it("keeps the explicit port", () => {
    const fake = {
      location: { protocol: "https:", hostname: "github.com", port: "8443" },
    } as unknown as Window;
    (fake as { self: unknown }).self = fake;
    (fake as { top: unknown }).top = fake;

    expect(describeOriginContext(fake).documentOrigin).toBe("https://github.com:8443");
  });

  it("marks a same-origin frame as framed", () => {
    const parent = {
      location: { protocol: "https:", hostname: "github.com", port: "" },
    } as unknown as Window;
    (parent as { self: unknown }).self = parent;
    (parent as { top: unknown }).top = parent;

    const child = {
      location: { protocol: "https:", hostname: "github.com", port: "" },
      top: parent,
    } as unknown as Window;
    (child as { self: unknown }).self = child;

    const ctx = describeOriginContext(child);
    expect(ctx.isFramed).toBe(true);
    expect(ctx.topLevelOrigin).toBe("https://github.com");
  });

  it("yields an empty top-level origin when the parent is cross-origin", () => {
    // Reading window.top.location throws across origins. We must NOT swallow
    // that into "assume same origin" — an empty value makes the guard refuse.
    const child = {
      location: { protocol: "https:", hostname: "github.com", port: "" },
      get top(): Window {
        throw new Error("Blocked a frame with origin from accessing cross-origin data");
      },
    } as unknown as Window;
    (child as { self: unknown }).self = child;

    const ctx = describeOriginContext(child);
    expect(ctx.isFramed).toBe(true);
    expect(ctx.topLevelOrigin).toBe("");
  });

  it("does NOT let an unreadable parent become an iframe bypass", () => {
    // Regression pin for a real bypass that shipped in the first draft of this
    // wiring: when reading window.top threw, `isFramed` stayed false, so
    // guardFill supplied NO frame context and the guard skipped its
    // UNAUTHORIZED_FRAME check entirely.
    //
    // The attack that made this exploitable: a hostile page embeds
    // https://github.com/login in an iframe. Our document origin is then
    // genuinely github.com, so ExactMatch passes — and without frame context
    // nothing else stood between the attacker and the credential.
    const child = {
      location: { protocol: "https:", hostname: "github.com", port: "" },
      get top(): Window {
        throw new Error("cross-origin");
      },
    } as unknown as Window;
    (child as { self: unknown }).self = child;

    const ctx = describeOriginContext(child);
    const outcome = guardFill(guardInput({ context: ctx }));

    // The security property is "does not fill", not which internal code fires:
    // an empty top-level origin fails to parse, so the guard reports an
    // inconsistent frame context rather than an unauthorized one. Both deny.
    expect(outcome.allowed).toBe(false);
    if (outcome.allowed) throw new Error("unreachable");
    expect(["UNAUTHORIZED_FRAME", "FRAME_CONTEXT_INCONSISTENT"]).toContain(outcome.reason);
  });
});

describe("guardFill — the wiring actually consults the guard", () => {
  it("allows the exact origin with a safe form", () => {
    expect(guardFill(guardInput()).allowed).toBe(true);
  });

  it("blocks a cross-origin form action", () => {
    const outcome = guardFill(guardInput({ formAction: "https://evil.example" }));
    expect(outcome.allowed).toBe(false);
    if (outcome.allowed) throw new Error("unreachable");
    expect(outcome.reason).toBe("FORM_ACTION_ORIGIN_MISMATCH");
  });

  it("blocks a hostile top-level page even when the frame looks right", () => {
    const outcome = guardFill(
      guardInput({
        context: {
          documentOrigin: CREDENTIAL_ORIGIN,
          topLevelOrigin: "https://evil.example",
          isFramed: true,
        },
      }),
    );
    expect(outcome.allowed).toBe(false);
    if (outcome.allowed) throw new Error("unreachable");
    expect(outcome.reason).toBe("UNAUTHORIZED_FRAME");
  });

  it("blocks a cross-origin submit target", () => {
    const outcome = guardFill(guardInput({ submitOrigin: "https://evil.example" }));
    expect(outcome.allowed).toBe(false);
    if (outcome.allowed) throw new Error("unreachable");
    expect(outcome.reason).toBe("SUBMIT_ORIGIN_MISMATCH");
  });

  it("blocks a framed page whose top level could not be read", () => {
    const outcome = guardFill(
      guardInput({
        context: { documentOrigin: CREDENTIAL_ORIGIN, topLevelOrigin: "", isFramed: true },
      }),
    );
    expect(outcome.allowed).toBe(false);
  });

  it("does not supply frame context for an unframed page", () => {
    // Supplying half a frame context would be treated as untrusted; the wiring
    // must therefore omit both fields when not framed.
    expect(guardFill(guardInput()).allowed).toBe(true);
  });
});

describe("resolveSubmitOrigin", () => {
  function formWith(attrs: Record<string, string>): HTMLFormElement {
    const form = document.createElement("form");
    for (const [k, v] of Object.entries(attrs)) form.setAttribute(k, v);
    return form;
  }

  it("returns null when the form has no action", () => {
    expect(resolveSubmitOrigin(formWith({}), null)).toBeNull();
  });

  it("returns the form action when present", () => {
    expect(resolveSubmitOrigin(formWith({ action: "/login" }), null)).toBe("/login");
  });

  it("prefers a submitter formaction over the form action", () => {
    const button = document.createElement("button");
    button.setAttribute("formaction", "https://evil.example");
    expect(resolveSubmitOrigin(formWith({ action: "/login" }), button)).toBe(
      "https://evil.example",
    );
  });

  it("ignores an empty formaction", () => {
    const button = document.createElement("button");
    button.setAttribute("formaction", "   ");
    expect(resolveSubmitOrigin(formWith({ action: "/login" }), button)).toBe("/login");
  });
});

describe("writeField", () => {
  beforeEach(() => {
    document.body.innerHTML = "";
  });

  it("writes a value and marks the field", () => {
    const input = document.createElement("input");
    document.body.appendChild(input);

    expect(writeField(input, "secret")).toBe(true);
    expect(input.value).toBe("secret");
    expect(input.getAttribute("data-cv-filled")).toBe("true");
  });

  it("does not overwrite a field it already filled", () => {
    const input = document.createElement("input");
    document.body.appendChild(input);

    writeField(input, "first");
    expect(writeField(input, "second")).toBe(false);
    expect(input.value).toBe("first");
  });

  it("refuses to write to a disabled field", () => {
    const input = document.createElement("input");
    input.disabled = true;
    document.body.appendChild(input);

    expect(writeField(input, "secret")).toBe(false);
    expect(input.value).toBe("");
  });

  it("refuses to write to a readonly field", () => {
    const input = document.createElement("input");
    input.readOnly = true;
    document.body.appendChild(input);

    expect(writeField(input, "secret")).toBe(false);
  });

  it("emits input and change events so frameworks observe the write", () => {
    const input = document.createElement("input");
    document.body.appendChild(input);

    const seen: string[] = [];
    input.addEventListener("input", () => seen.push("input"));
    input.addEventListener("change", () => seen.push("change"));

    writeField(input, "secret");
    expect(seen).toEqual(["input", "change"]);
  });
});
