/**
 * @jest-environment jsdom
 * @jest-environment-options {"url": "https://www.example.com/"}
 */

/**
 * S2 batch 3 — `src/domain/services/aitm/aitm-detector.ts`.
 *
 * The detector is the aggregate layer over five signals (hostname, content
 * fingerprint, DOM integrity, timing, cookies). The suite walks every branch
 * of every signal and then checks the aggregate result.
 *
 * Two environment facts matter:
 *   - the page URL is pinned to `https://www.example.com/` so the hostname
 *     signal's exact / subdomain / mismatch branches are all reachable;
 *   - jsdom ships a `crypto` object WITHOUT `subtle`, and
 *     `ContentFingerprinter` needs it, so Node's WebCrypto is installed first.
 *
 * Where a branch is only reachable by forcing a collaborator (e.g. a DOM
 * anomaly with severity `info`, which no real checker ever emits), the
 * collaborator is stubbed — the branch under test is the detector's own.
 *
 * No live database, no Docker, no network, no browser.
 */

import { webcrypto } from "node:crypto";
import { TextDecoder, TextEncoder } from "node:util";

import {
  AiTMDetector,
} from "../../../src/domain/services/aitm/aitm-detector";
import {
  ContentFingerprinter,
  type PageFingerprint,
} from "../../../src/domain/services/aitm/content-fingerprinter";
import type {
  DOMIntegrityChecker,
  DOMIntegrityResult,
} from "../../../src/domain/services/aitm/dom-integrity-checker";
import type { AiTMDetectionResult, DetectionSignal } from "../../../src/domain/services/aitm/types";

Object.defineProperty(globalThis, "crypto", {
  value: webcrypto,
  configurable: true,
  writable: true,
});

// jsdom also ships no `TextEncoder` / `TextDecoder`; `hashNormalizedDOM` needs both.
for (const [name, value] of Object.entries({ TextEncoder, TextDecoder })) {
  if (typeof (globalThis as Record<string, unknown>)[name] !== "function") {
    Object.defineProperty(globalThis, name, {
      value,
      configurable: true,
      writable: true,
    });
  }
}

const DOMAIN = "www.example.com";

let detector: AiTMDetector;
let consoleError: jest.SpyInstance;
let consoleWarn: jest.SpyInstance;

beforeEach(() => {
  document.head.innerHTML = "";
  document.body.innerHTML = "";
  document.cookie = "";
  detector = new AiTMDetector();
  consoleError = jest.spyOn(console, "error").mockImplementation(() => undefined);
  consoleWarn = jest.spyOn(console, "warn").mockImplementation(() => undefined);
});

afterEach(() => {
  jest.restoreAllMocks();
});

function signalOf(result: AiTMDetectionResult, type: DetectionSignal["type"]): DetectionSignal {
  const found = result.signals.find((s) => s.type === type);
  if (!found) throw new Error(`no "${type}" signal in ${JSON.stringify(result.signals)}`);
  return found;
}

function fingerprinterOf(d: AiTMDetector): ContentFingerprinter {
  return (d as unknown as { fingerprinter: ContentFingerprinter }).fingerprinter;
}

function integrityCheckerOf(d: AiTMDetector): DOMIntegrityChecker {
  return (d as unknown as { integrityChecker: DOMIntegrityChecker }).integrityChecker;
}

async function pageFingerprint(): Promise<PageFingerprint> {
  return new ContentFingerprinter().generateFingerprint();
}

/* ========================================================================== */
/* Instrumentation                                                            */
/* ========================================================================== */

describe("AiTMDetector — instrumentation", () => {
  it("loads and instruments the module under test", () => {
    expect(typeof AiTMDetector).toBe("function");
    expect(detector).toBeInstanceOf(AiTMDetector);
    expect(typeof detector.validatePage).toBe("function");
    expect(typeof detector.registerKnownFingerprint).toBe("function");
    expect(typeof detector.getValidationStats).toBe("function");
  });

  it("has no timing samples before any validation runs", () => {
    expect(detector.getValidationStats()).toEqual({
      sampleCount: 0,
      avgLatency: 0,
      maxLatency: 0,
      minLatency: 0,
    });
  });
});

/* ========================================================================== */
/* Hostname signal                                                             */
/* ========================================================================== */

describe("hostname signal", () => {
  const SKIP = { skipContentCheck: true, skipDOMCheck: true };

  it("passes an exact hostname match", async () => {
    const result = await detector.validatePage(DOMAIN, SKIP);

    expect(signalOf(result, "hostname")).toMatchObject({
      status: "pass",
      score: 0,
      confidence: 1.0,
      weight: 0.25,
    });
  });

  it("matches case-insensitively", async () => {
    const result = await detector.validatePage("WWW.EXAMPLE.COM", SKIP);

    expect(signalOf(result, "hostname").status).toBe("pass");
  });

  it("warns on a subdomain of the expected domain", async () => {
    const result = await detector.validatePage("example.com", SKIP);

    const signal = signalOf(result, "hostname");
    expect(signal).toMatchObject({ status: "warn", score: 25, confidence: 0.8 });
    expect(signal.details).toContain("Subdomain match");
  });

  it("fails on a completely different domain", async () => {
    const result = await detector.validatePage("evil.test", SKIP);

    const signal = signalOf(result, "hostname");
    expect(signal).toMatchObject({ status: "fail", score: 100, confidence: 0.95 });
    expect(signal.details).toContain("Hostname mismatch");
  });

  it("always reports the hostname signal, even when the other checks are skipped", async () => {
    const result = await detector.validatePage(DOMAIN, SKIP);

    expect(result.signals.map((s) => s.type)).toEqual(["hostname", "timing", "cookie-security"]);
  });
});

/* ========================================================================== */
/* Aggregate result                                                            */
/* ========================================================================== */

describe("validatePage aggregate", () => {
  it("runs all five signals when nothing is skipped", async () => {
    const before = Date.now();
    const result = await detector.validatePage(DOMAIN);

    expect(result.signals.map((s) => s.type)).toEqual([
      "hostname",
      "content-hash",
      "dom-integrity",
      "timing",
      "cookie-security",
    ]);
    expect(result.riskScore).toBeGreaterThanOrEqual(0);
    expect(result.riskScore).toBeLessThanOrEqual(100);
    expect(typeof result.recommendation).toBe("string");
    expect(result.recommendation.length).toBeGreaterThan(0);
    expect(result.evaluatedAt).toBeGreaterThanOrEqual(before);
    expect(result.evaluatedAt).toBeLessThanOrEqual(Date.now());
  });

  it("records one timing sample per validation", async () => {
    await detector.validatePage(DOMAIN, { skipContentCheck: true, skipDOMCheck: true });
    await detector.validatePage(DOMAIN, { skipContentCheck: true, skipDOMCheck: true });

    const stats = detector.getValidationStats();
    expect(stats.sampleCount).toBe(2);
    expect(stats.minLatency).toBeLessThanOrEqual(stats.avgLatency);
    expect(stats.avgLatency).toBeLessThanOrEqual(stats.maxLatency);
    expect(stats.maxLatency).toBeGreaterThanOrEqual(0);
  });
});

/* ========================================================================== */
/* Content fingerprint signal                                                  */
/* ========================================================================== */

describe("content fingerprint signal", () => {
  it("warns on a first visit with no registered fingerprint", async () => {
    const result = await detector.validatePage(DOMAIN, { skipDOMCheck: true });

    const signal = signalOf(result, "content-hash");
    expect(signal).toMatchObject({ status: "warn", score: 30, confidence: 0.5 });
    expect(signal.details).toContain("first visit");
  });

  it("keys the registry per domain", async () => {
    detector.registerKnownFingerprint("other.example", await pageFingerprint());

    const result = await detector.validatePage(DOMAIN, { skipDOMCheck: true });

    expect(signalOf(result, "content-hash").details).toContain("first visit");
  });

  // ⚠️ INTENTIONAL FAILURE — production defect #7.
  // `ContentFingerprinter.compareFingerprints()` documents itself as
  // "retorna similitud (0-1)" but byte-identical fingerprints come back at
  // 0.9, never 1.0, whenever the page has no external resources:
  //   matches += 0.1 * (sharedResources / (maxResources || 1))   // 0/1 === 0
  // every other component gives full credit for an identical value.
  // Because `validateContentFingerprint` passes at `similarity >= 0.9`, a clean
  // page only just clears the bar — one more component drift would turn an
  // identical page into a warning. The assertion below states what the
  // contract promises; it is deliberately NOT weakened.
  it("passes when the registered fingerprint is identical", async () => {
    detector.registerKnownFingerprint(DOMAIN, await pageFingerprint());

    const result = await detector.validatePage(DOMAIN, { skipDOMCheck: true });

    const signal = signalOf(result, "content-hash");
    expect(signal).toMatchObject({ status: "pass", score: 0, confidence: 0.9 });
    expect(signal.details).toContain("Content fingerprint matches");
    expect(signal.details).toContain("100.0%");
  });

  it("warns on a partially matching fingerprint (similarity inside 0.7-0.9)", async () => {
    const known = await pageFingerprint();
    detector.registerKnownFingerprint(DOMAIN, {
      ...known,
      scriptCount: known.scriptCount + 7,
      externalResources: ["https://cdn.other.example/widget.js"],
    });

    const result = await detector.validatePage(DOMAIN, { skipDOMCheck: true });

    const signal = signalOf(result, "content-hash");
    expect(signal).toMatchObject({ status: "warn", score: 50, confidence: 0.7 });
    expect(signal.details).toContain("partially matches");
  });

  it("fails on a mismatched fingerprint", async () => {
    detector.registerKnownFingerprint(DOMAIN, {
      url: "https://www.example.com/",
      contentHash: "0".repeat(64),
      formStructure: "different-form-structure",
      scriptCount: 9999,
      externalResources: [],
      timestamp: 0,
    });

    const result = await detector.validatePage(DOMAIN, { skipDOMCheck: true });

    const signal = signalOf(result, "content-hash");
    expect(signal).toMatchObject({ status: "fail", score: 100, confidence: 0.85 });
    expect(signal.details).toContain("Content fingerprint mismatch");
  });

  it("degrades to a low-confidence warning when fingerprinting itself throws", async () => {
    jest
      .spyOn(fingerprinterOf(detector), "generateFingerprint")
      .mockRejectedValue(new Error("hash unavailable"));

    const result = await detector.validatePage(DOMAIN, { skipDOMCheck: true });

    const signal = signalOf(result, "content-hash");
    expect(signal).toMatchObject({ status: "warn", score: 50, confidence: 0.3 });
    expect(signal.details).toContain("hash unavailable");
  });
});

/* ========================================================================== */
/* DOM integrity signal                                                        */
/* ========================================================================== */

describe("DOM integrity signal", () => {
  it("passes on a clean document", async () => {
    const result = await detector.validatePage(DOMAIN, { skipContentCheck: true });

    const signal = signalOf(result, "dom-integrity");
    expect(signal).toMatchObject({ status: "pass", score: 0, confidence: 0.85 });
    expect(signal.details).toContain("no anomalies detected");
  });

  it("fails on a critical anomaly", async () => {
    document.body.innerHTML = `<script>steal(document.cookie)</script>`;

    const result = await detector.validatePage(DOMAIN, { skipContentCheck: true });

    const signal = signalOf(result, "dom-integrity");
    expect(signal).toMatchObject({ status: "fail", score: 100, confidence: 0.9 });
    expect(signal.details).toContain("Critical DOM anomalies");
    expect(signal.details).toContain("unexpected-script");
  });

  it("warns when only warnings are reported", async () => {
    document.body.innerHTML = `<script src="https://evil.example/x.js"></script>`;

    const result = await detector.validatePage(DOMAIN, { skipContentCheck: true });

    const signal = signalOf(result, "dom-integrity");
    expect(signal).toMatchObject({ status: "warn", score: 50, confidence: 0.7 });
    expect(signal.details).toContain("DOM warnings");
  });

  it("accepts anomalies that are neither warnings nor critical", async () => {
    // No real checker emits severity `info` today, so this branch is only
    // reachable by stubbing the collaborator. The branch under test is the
    // detector's own aggregation.
    const stub: DOMIntegrityResult = {
      isIntact: false,
      riskLevel: "low",
      anomalies: [
        {
          type: "modified_form",
          location: "form#x",
          description: "cosmetic",
          severity: "info",
        },
      ],
    };
    jest.spyOn(integrityCheckerOf(detector), "checkPageIntegrity").mockReturnValue(stub);

    const result = await detector.validatePage(DOMAIN, { skipContentCheck: true });

    const signal = signalOf(result, "dom-integrity");
    expect(signal).toMatchObject({ status: "pass", score: 10, confidence: 0.8 });
    expect(signal.details).toContain("minor anomalies");
  });

  it("degrades to a low-confidence warning when the checker itself throws", async () => {
    jest
      .spyOn(integrityCheckerOf(detector), "checkPageIntegrity")
      .mockImplementation(() => {
        throw new Error("checker exploded");
      });

    const result = await detector.validatePage(DOMAIN, { skipContentCheck: true });

    const signal = signalOf(result, "dom-integrity");
    expect(signal).toMatchObject({ status: "warn", score: 50, confidence: 0.3 });
    expect(signal.details).toContain("checker exploded");
  });
});

/* ========================================================================== */
/* Timing signal                                                               */
/* ========================================================================== */

describe("timing signal", () => {
  const SKIP = { skipContentCheck: true, skipDOMCheck: true };

  function clockFor(validationTimeMs: number): void {
    jest
      .spyOn(performance, "now")
      .mockReturnValue(0)
      .mockReturnValueOnce(0)
      .mockReturnValueOnce(validationTimeMs);
  }

  it("passes for a fast validation", async () => {
    clockFor(150);

    const result = await detector.validatePage(DOMAIN, SKIP);

    expect(signalOf(result, "timing")).toMatchObject({
      status: "pass",
      score: 0,
      confidence: 0.8,
    });
  });

  it("warns when latency sits inside the proxy band", async () => {
    clockFor(250);

    const result = await detector.validatePage(DOMAIN, SKIP);

    const signal = signalOf(result, "timing");
    expect(signal).toMatchObject({ status: "warn", score: 50, confidence: 0.5 });
    expect(signal.details).toContain("elevated");
  });

  it("fails above twice the proxy threshold", async () => {
    clockFor(600);

    const result = await detector.validatePage(DOMAIN, SKIP);

    const signal = signalOf(result, "timing");
    expect(signal).toMatchObject({ status: "fail", score: 100, confidence: 0.7 });
    expect(signal.details).toContain("high latency");
  });

  it("uses the observed duration as the sample, not the wall clock", async () => {
    clockFor(400);

    await detector.validatePage(DOMAIN, SKIP);

    expect(detector.getValidationStats()).toMatchObject({
      sampleCount: 1,
      avgLatency: 400,
      maxLatency: 400,
      minLatency: 400,
    });
  });
});

/* ========================================================================== */
/* Cookie security signal                                                      */
/* ========================================================================== */

describe("cookie security signal", () => {
  const SKIP = { skipContentCheck: true, skipDOMCheck: true };

  it("passes on a page with no cookies and no cross-origin scripts", async () => {
    const result = await detector.validatePage(DOMAIN, SKIP);

    expect(signalOf(result, "cookie-security")).toMatchObject({
      status: "pass",
      score: 0,
      confidence: 0.7,
    });
  });

  it("warns about cookies that carry no SameSite marker", async () => {
    document.cookie = "session=abc";

    const result = await detector.validatePage(DOMAIN, SKIP);

    const signal = signalOf(result, "cookie-security");
    expect(signal).toMatchObject({ status: "warn", score: 30, confidence: 0.5 });
    expect(signal.details).toContain("SameSite");
  });

  it("accepts a cookie whose value advertises SameSite", async () => {
    document.cookie = "note=SameSite=Strict";

    const result = await detector.validatePage(DOMAIN, SKIP);

    expect(signalOf(result, "cookie-security").status).toBe("pass");
  });

  it("warns about external scripts reading the page", async () => {
    document.body.innerHTML = `<script src="https://evil.example/harvest.js"></script>`;

    const result = await detector.validatePage(DOMAIN, SKIP);

    const signal = signalOf(result, "cookie-security");
    expect(signal).toMatchObject({ status: "warn", score: 50, confidence: 0.6 });
    expect(signal.details).toContain("External scripts detected");
  });

  it("degrades to a low-confidence warning when the DOM query throws", async () => {
    jest
      .spyOn(document, "querySelectorAll")
      .mockImplementation(() => {
        throw new Error("selector exploded");
      });

    const result = await detector.validatePage(DOMAIN, SKIP);

    const signal = signalOf(result, "cookie-security");
    expect(signal).toMatchObject({ status: "warn", score: 50, confidence: 0.3 });
    expect(signal.details).toContain("selector exploded");
  });

  it("does not log the expected failures", async () => {
    await detector.validatePage("evil.test", SKIP);

    expect(consoleError).not.toHaveBeenCalled();
    expect(consoleWarn).not.toHaveBeenCalled();
  });
});
