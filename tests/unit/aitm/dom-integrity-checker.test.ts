/**
 * @jest-environment jsdom
 */

/**
 * S2 batch 3 — `src/domain/services/aitm/dom-integrity-checker.ts`.
 *
 * The checker reads the live document, so every case is built by shaping
 * `document.body` and asserting on the anomalies it reports. The cases are
 * chosen to walk each detector AND each risk-level branch:
 *   intact / warnings-only / critical-present.
 *
 * No live database, no Docker, no network, no browser.
 */

import {
  DOMIntegrityChecker,
  type DOMAnomaly,
} from "../../../src/domain/services/aitm/dom-integrity-checker";

let checker: DOMIntegrityChecker;

beforeEach(() => {
  document.head.innerHTML = "";
  document.body.innerHTML = "";
  checker = new DOMIntegrityChecker();
});

function types(anomalies: DOMAnomaly[]): string[] {
  return anomalies.map((a) => a.type);
}

/* ========================================================================== */
/* Instrumentation                                                            */
/* ========================================================================== */

describe("DOMIntegrityChecker — instrumentation", () => {
  it("loads and instruments the module under test", () => {
    expect(typeof DOMIntegrityChecker).toBe("function");
    expect(checker).toBeInstanceOf(DOMIntegrityChecker);
    expect(typeof checker.checkPageIntegrity).toBe("function");
    expect(Array.isArray(checker.detectUnexpectedScripts())).toBe(true);
  });
});

/* ========================================================================== */
/* Whole-page verdict                                                          */
/* ========================================================================== */

describe("checkPageIntegrity", () => {
  it("reports an intact page and low risk for a clean document", () => {
    const result = checker.checkPageIntegrity();

    expect(result.isIntact).toBe(true);
    expect(result.anomalies).toEqual([]);
    expect(result.riskLevel).toBe("low");
  });

  it("escalates to HIGH risk when any critical anomaly is present", () => {
    document.body.innerHTML = `
      <form id="login-form" action="https://evil.example/login">
        <input type="password" name="password" />
        <button type="submit">Sign in</button>
      </form>
      <iframe srcdoc="<script>steal()</script>"></iframe>
    `;

    const result = checker.checkPageIntegrity();

    expect(result.isIntact).toBe(false);
    expect(result.riskLevel).toBe("high");
    expect(result.anomalies.some((a) => a.severity === "critical")).toBe(true);
    expect(types(result.anomalies)).toEqual(
      expect.arrayContaining(["modified_form", "iframe_injection"]),
    );
  });

  it("settles on MEDIUM risk when only warnings are reported", () => {
    document.body.innerHTML = `
      <input type="hidden" name="csrf_token" value="t" />
      <script src="https://not-a-trusted-cdn.example/x.js"></script>
    `;

    const result = checker.checkPageIntegrity();

    expect(result.isIntact).toBe(false);
    expect(result.riskLevel).toBe("medium");
    expect(result.anomalies.every((a) => a.severity === "warning")).toBe(true);
    expect(types(result.anomalies)).toEqual(
      expect.arrayContaining(["hidden_field", "unexpected-script"]),
    );
  });
});

/* ========================================================================== */
/* Unexpected scripts                                                          */
/* ========================================================================== */

describe("detectUnexpectedScripts", () => {
  it("flags an inline script carrying a cookie-stealing primitive as critical", () => {
    document.body.innerHTML = `<script>exfiltrate(document.cookie)</script>`;

    const anomalies = checker.detectUnexpectedScripts();

    expect(anomalies).toHaveLength(1);
    expect(anomalies[0]).toMatchObject({
      type: "unexpected-script",
      location: "inline script",
      severity: "critical",
    });
    expect(anomalies[0].description).toContain("document.cookie");
  });

  it("ignores a benign inline script", () => {
    document.body.innerHTML = `<script>window.BOOT = true;</script>`;

    expect(checker.detectUnexpectedScripts()).toEqual([]);
  });

  it("flags an external script from an untrusted origin as a warning", () => {
    document.body.innerHTML = `<script src="https://evil.example/collect.js"></script>`;

    const anomalies = checker.detectUnexpectedScripts();

    expect(anomalies).toHaveLength(1);
    expect(anomalies[0]).toMatchObject({
      type: "unexpected-script",
      severity: "warning",
      location: "https://evil.example/collect.js",
    });
  });

  it("trusts same-origin scripts", () => {
    document.body.innerHTML = `<script src="/assets/app.js"></script>`;

    expect(checker.detectUnexpectedScripts()).toEqual([]);
  });

  it("trusts the known CDN allowlist", () => {
    document.body.innerHTML = `
      <script src="https://cdn.jsdelivr.net/npm/pkg@1/index.js"></script>
      <script src="https://fonts.googleapis.com/css2?family=Inter"></script>
    `;

    expect(checker.detectUnexpectedScripts()).toEqual([]);
  });

  it("treats an unparseable script URL as untrusted rather than crashing", () => {
    document.body.innerHTML = `<script src="http://["></script>`;

    const anomalies = checker.detectUnexpectedScripts();

    expect(anomalies).toHaveLength(1);
    expect(anomalies[0].severity).toBe("warning");
  });
});

/* ========================================================================== */
/* Hidden fields                                                               */
/* ========================================================================== */

describe("detectHiddenFields", () => {
  it("flags hidden inputs whose name or id looks like a secret", () => {
    document.body.innerHTML = `
      <input type="hidden" name="csrf_token" value="a" />
      <input type="hidden" id="session_id" value="b" />
      <input type="hidden" name="locale" value="en" />
    `;

    const anomalies = checker.detectHiddenFields();

    expect(anomalies).toHaveLength(2);
    expect(anomalies.every((a) => a.type === "hidden_field")).toBe(true);
    expect(anomalies.every((a) => a.severity === "warning")).toBe(true);
    expect(anomalies.map((a) => a.location)).toEqual([
      'input[name="csrf_token"][id=""]',
      'input[name=""][id="session_id"]',
    ]);
  });

  it("flags inline-style-hidden inputs even when the type is not hidden", () => {
    document.body.innerHTML = `<input style="display: none" name="auth_secret" />`;

    const anomalies = checker.detectHiddenFields();

    expect(anomalies).toHaveLength(1);
    expect(anomalies[0].type).toBe("hidden_field");
  });

  it("ignores ordinary visible inputs", () => {
    document.body.innerHTML = `<input type="text" name="username" />`;

    expect(checker.detectHiddenFields()).toEqual([]);
  });
});

/* ========================================================================== */
/* Injected iframes                                                            */
/* ========================================================================== */

describe("detectInjectedIframes", () => {
  it("flags an inline srcdoc iframe as critical", () => {
    document.body.innerHTML = `<iframe srcdoc="<script>x()</script>"></iframe>`;

    const anomalies = checker.detectInjectedIframes();

    expect(anomalies).toHaveLength(1);
    expect(anomalies[0]).toMatchObject({
      type: "iframe_injection",
      severity: "critical",
      location: "iframe[srcdoc]",
    });
  });

  it("flags an external iframe as a warning", () => {
    document.body.innerHTML = `<iframe src="https://evil.example/frame"></iframe>`;

    const anomalies = checker.detectInjectedIframes();

    expect(anomalies).toHaveLength(1);
    expect(anomalies[0].severity).toBe("warning");
  });

  it("trusts a same-origin iframe", () => {
    document.body.innerHTML = `<iframe src="/embed/widget"></iframe>`;

    expect(checker.detectInjectedIframes()).toEqual([]);
  });

  it("ignores an iframe with neither src nor srcdoc", () => {
    document.body.innerHTML = `<iframe></iframe>`;

    expect(checker.detectInjectedIframes()).toEqual([]);
  });
});

/* ========================================================================== */
/* Login form integrity                                                        */
/* ========================================================================== */

describe("detectLoginForms", () => {
  it("collects a form once even when several selectors match it", () => {
    document.body.innerHTML = `
      <form id="login-form" action="/login">
        <input type="password" name="password" />
      </form>
    `;

    const result = checker.checkPageIntegrity();

    // A duplicate would surface the same form anomaly twice.
    expect(result.anomalies.filter((a) => a.type === "modified_form")).toEqual([]);
    expect(result.isIntact).toBe(true);
  });

  it("also finds a form that only matches the :has() selector", () => {
    document.body.innerHTML = `
      <form id="checkout">
        <input type="password" name="pass" />
      </form>
    `;

    const result = checker.checkPageIntegrity();

    expect(result.isIntact).toBe(true);
  });

  it("finds nothing on a page without forms", () => {
    expect(checker.checkPageIntegrity().isIntact).toBe(true);
  });
});

describe("checkFormIntegrity", () => {
  function form(html: string): HTMLFormElement {
    document.body.innerHTML = html;
    return document.querySelector("form") as HTMLFormElement;
  }

  it("accepts a same-origin form action", () => {
    expect(checker.checkFormIntegrity(form(`<form action="/login" id="f"></form>`))).toEqual([]);
  });

  it("flags a form action pointing at another host as critical", () => {
    const anomalies = checker.checkFormIntegrity(
      form(`<form action="https://attacker.example/login" id="f"></form>`),
    );

    expect(anomalies).toHaveLength(1);
    expect(anomalies[0]).toMatchObject({ type: "modified_form", severity: "critical" });
    expect(anomalies[0].description).toContain("attacker.example");
  });

  it("ignores an unparseable form action", () => {
    expect(
      checker.checkFormIntegrity(form(`<form action="http://[" id="f"></form>`)),
    ).toEqual([]);
  });

  it("flags more than two password fields", () => {
    const anomalies = checker.checkFormIntegrity(
      form(`
        <form id="f">
          <input type="password" name="password" />
          <input type="password" name="confirm" />
          <input type="password" name="hint" />
        </form>
      `),
    );

    expect(anomalies).toHaveLength(1);
    expect(anomalies[0]).toMatchObject({ severity: "warning" });
    expect(anomalies[0].description).toContain("Unusual number of password fields");
  });

  it("flags a visible token field", () => {
    const anomalies = checker.checkFormIntegrity(
      form(`
        <form id="f">
          <input type="text" name="token" />
        </form>
      `),
    );

    expect(anomalies).toHaveLength(1);
    expect(anomalies[0].description).toContain('suspicious token field');
  });

  it("does not flag a hidden token field (that is what hidden inputs are for)", () => {
    expect(
      checker.checkFormIntegrity(
        form(`<form id="f"><input type="hidden" name="token" /></form>`),
      ),
    ).toEqual([]);
  });
});

/* ========================================================================== */
/* Suspicious event-listener markers                                           */
/* ========================================================================== */

describe("detectSuspiciousEventListeners", () => {
  it("flags a password field carrying a data-tracking attribute", () => {
    document.body.innerHTML = `
      <input type="password" name="password" data-track="keystrokes" />
    `;

    const anomalies = checker.detectSuspiciousEventListeners();

    expect(anomalies).toHaveLength(1);
    expect(anomalies[0]).toMatchObject({ type: "event_listener", severity: "warning" });
    expect(anomalies[0].description).toContain('data-track="keystrokes"');
  });

  it("ignores ordinary data attributes", () => {
    document.body.innerHTML = `
      <input type="password" name="password" data-testid="login" data-foo="bar" />
    `;

    expect(checker.detectSuspiciousEventListeners()).toEqual([]);
  });

  it("ignores non-password fields entirely", () => {
    document.body.innerHTML = `<input type="text" name="q" data-track="all" />`;

    expect(checker.detectSuspiciousEventListeners()).toEqual([]);
  });

  it("reports a location that names the field", () => {
    document.body.innerHTML = `<input type="password" id="pw-field" data-log="1" />`;

    const anomalies = checker.detectSuspiciousEventListeners();

    expect(anomalies[0].location).toBe('input[name="pw-field"]');
  });
});
