/**
 * Step-up flow tests.
 *
 * The centrepiece is the cross-binding suite: a challenge satisfied for one
 * credential must not authorize a release of another. That is the escalation
 * this module exists to prevent, and it is invisible server-side — Plus sees a
 * legitimately completed step-up — so it can only be caught here.
 */

import {
  beginStepUp,
  submitStepUpPin,
  checkSession,
  canRetryRelease,
  type StepUpBinding,
  type StepUpDeps,
  type StepUpSession,
} from "../../src/domain/services/autofill/step-up-flow";

const NOW = 1_700_000_000_000;
const PIN = "123456";

const BINDING: StepUpBinding = {
  credentialId: "cred-low-value",
  origin: "https://github.com:443",
  operation: "AUTOFILL",
};

interface Recorder {
  deps: StepUpDeps;
  started: StepUpBinding[];
  submitted: Array<{ challengeId: string; pin: string }>;
  setNow(ms: number): void;
  setPinResult(r: Awaited<ReturnType<StepUpDeps["submitPin"]>>): void;
  setStartResult(r: Awaited<ReturnType<StepUpDeps["startChallenge"]>>): void;
}

function recorder(overrides: Partial<StepUpDeps> = {}): Recorder {
  let now = NOW;
  let pinResult: Awaited<ReturnType<StepUpDeps["submitPin"]>> = { ok: true };
  let startResult: Awaited<ReturnType<StepUpDeps["startChallenge"]>> = {
    challengeId: "chal-1",
    expiresAt: NOW + 120_000,
    attemptsRemaining: 3,
  };

  const started: StepUpBinding[] = [];
  const submitted: Array<{ challengeId: string; pin: string }> = [];

  const deps: StepUpDeps = {
    startChallenge: async (binding) => {
      started.push(binding);
      return startResult;
    },
    submitPin: async (challengeId, pin) => {
      submitted.push({ challengeId, pin });
      return pinResult;
    },
    now: () => now,
    ...overrides,
  };

  return {
    deps,
    started,
    submitted,
    setNow: (ms) => {
      now = ms;
    },
    setPinResult: (r) => {
      pinResult = r;
    },
    setStartResult: (r) => {
      startResult = r;
    },
  };
}

async function sessionFor(
  binding: StepUpBinding = BINDING,
  rec: Recorder = recorder(),
): Promise<StepUpSession> {
  const begun = await beginStepUp(binding, rec.deps);
  if (!begun.ok) throw new Error(`begin failed: ${begun.code}`);
  return begun.session;
}

describe("beginStepUp", () => {
  it("captures the binding it was started for", async () => {
    const rec = recorder();
    const session = await sessionFor(BINDING, rec);
    expect(session.binding).toEqual(BINDING);
    expect(session.completed).toBe(false);
    expect(session.challengeId).toBe("chal-1");
  });

  it("freezes the binding so later mutation cannot retarget it", async () => {
    const mutable: StepUpBinding = { ...BINDING };
    const rec = recorder();
    const session = await sessionFor(mutable, rec);

    // The caller mutates its own object after the challenge is in flight.
    (mutable as { credentialId: string }).credentialId = "cred-high-value";

    expect(session.binding.credentialId).toBe("cred-low-value");
    expect(Object.isFrozen(session.binding)).toBe(true);
  });

  it("fails when Plus issues no challenge", async () => {
    const rec = recorder();
    rec.setStartResult(null);
    const result = await beginStepUp(BINDING, rec.deps);
    expect(result).toMatchObject({ ok: false, code: "CHALLENGE_UNAVAILABLE" });
  });

  it("fails on an unusable challenge id", async () => {
    const rec = recorder();
    rec.setStartResult({ challengeId: "", expiresAt: NOW + 1000, attemptsRemaining: 3 });
    const result = await beginStepUp(BINDING, rec.deps);
    expect(result).toMatchObject({ ok: false, code: "CHALLENGE_UNAVAILABLE" });
  });
});

describe("submitStepUpPin — happy path", () => {
  it("accepts the correct PIN and marks the session completed", async () => {
    const rec = recorder();
    const session = await sessionFor(BINDING, rec);
    const result = await submitStepUpPin(session, BINDING, PIN, rec.deps);

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("unreachable");
    expect(result.session.completed).toBe(true);
    expect(result.session.attemptsRemaining).toBe(0);
  });

  it("passes the PIN through to the transport", async () => {
    const rec = recorder();
    const session = await sessionFor(BINDING, rec);
    await submitStepUpPin(session, BINDING, PIN, rec.deps);
    expect(rec.submitted).toEqual([{ challengeId: "chal-1", pin: PIN }]);
  });

  it("never stores the PIN on the session", async () => {
    const rec = recorder();
    const session = await sessionFor(BINDING, rec);
    const result = await submitStepUpPin(session, BINDING, PIN, rec.deps);

    const serialized = JSON.stringify(result);
    expect(serialized).not.toContain(PIN);
    expect(serialized).not.toMatch(/"pin"/i);
  });

  it("rejects an empty PIN without contacting the transport", async () => {
    const rec = recorder();
    const session = await sessionFor(BINDING, rec);
    const result = await submitStepUpPin(session, BINDING, "   ", rec.deps);
    expect(result).toMatchObject({ ok: false, code: "PIN_INVALID" });
    expect(rec.submitted).toHaveLength(0);
  });
});

describe("CROSS-BINDING — the escalation this module prevents", () => {
  it("refuses a PIN submitted against a different credential", async () => {
    const rec = recorder();
    const session = await sessionFor(BINDING, rec);

    const other: StepUpBinding = { ...BINDING, credentialId: "prod-database-root" };
    const result = await submitStepUpPin(session, other, PIN, rec.deps);

    expect(result).toMatchObject({ ok: false, code: "BINDING_MISMATCH" });
    // The PIN must never reach the transport for a foreign binding.
    expect(rec.submitted).toHaveLength(0);
  });

  it("refuses a PIN submitted against a different origin", async () => {
    const rec = recorder();
    const session = await sessionFor(BINDING, rec);

    const result = await submitStepUpPin(
      session,
      { ...BINDING, origin: "https://evil.example:443" },
      PIN,
      rec.deps,
    );
    expect(result).toMatchObject({ ok: false, code: "BINDING_MISMATCH" });
    expect(rec.submitted).toHaveLength(0);
  });

  it("refuses a PIN submitted against a different operation", async () => {
    const rec = recorder();
    const session = await sessionFor(BINDING, rec);

    // An AUTOFILL step-up must not authorize a TOTP release.
    const result = await submitStepUpPin(
      session,
      { ...BINDING, operation: "TOTP" },
      PIN,
      rec.deps,
    );
    expect(result).toMatchObject({ ok: false, code: "BINDING_MISMATCH" });
    expect(rec.submitted).toHaveLength(0);
  });

  it("refuses a completed step-up to be spent on another credential", async () => {
    const rec = recorder();
    const session = await sessionFor(BINDING, rec);
    const done = await submitStepUpPin(session, BINDING, PIN, rec.deps);
    if (!done.ok) throw new Error("unreachable");

    const other: StepUpBinding = { ...BINDING, credentialId: "prod-database-root" };
    const retry = canRetryRelease(done.session, other);
    expect(retry).toMatchObject({ ok: false, code: "BINDING_MISMATCH" });
  });

  it("does not echo either binding in the mismatch detail", async () => {
    const rec = recorder();
    const session = await sessionFor(BINDING, rec);
    const result = await submitStepUpPin(
      session,
      { ...BINDING, credentialId: "prod-database-root" },
      PIN,
      rec.deps,
    );
    if (result.ok) throw new Error("unreachable");
    // A message naming both credentials would disclose the real target.
    expect(result.detail).not.toContain("prod-database-root");
    expect(result.detail).not.toContain("cred-low-value");
  });

  it("allows the legitimate binding to proceed after a mismatch", async () => {
    const rec = recorder();
    const session = await sessionFor(BINDING, rec);

    await submitStepUpPin(session, { ...BINDING, credentialId: "other" }, PIN, rec.deps);
    const good = await submitStepUpPin(session, BINDING, PIN, rec.deps);

    expect(good.ok).toBe(true);
    expect(rec.submitted).toHaveLength(1); // only the legitimate attempt
  });
});

describe("expiry and attempts", () => {
  it("refuses an expired session without contacting the transport", async () => {
    const rec = recorder();
    const session = await sessionFor(BINDING, rec);
    rec.setNow(session.expiresAt);

    const result = await submitStepUpPin(session, BINDING, PIN, rec.deps);
    expect(result).toMatchObject({ ok: false, code: "SESSION_EXPIRED" });
    expect(rec.submitted).toHaveLength(0);
  });

  it("treats the expiry instant itself as expired", async () => {
    const rec = recorder();
    const session = await sessionFor(BINDING, rec);
    rec.setNow(session.expiresAt - 1);
    expect(checkSession(session, BINDING, rec.deps)).toHaveProperty("usable", true);
    rec.setNow(session.expiresAt);
    expect(checkSession(session, BINDING, rec.deps)).toMatchObject({ code: "SESSION_EXPIRED" });
  });

  it("refuses once attempts are exhausted", async () => {
    const rec = recorder();
    rec.setStartResult({ challengeId: "c", expiresAt: NOW + 1000, attemptsRemaining: 0 });
    const session = await sessionFor(BINDING, rec);

    const result = await submitStepUpPin(session, BINDING, PIN, rec.deps);
    expect(result).toMatchObject({ ok: false, code: "ATTEMPTS_EXHAUSTED" });
    expect(rec.submitted).toHaveLength(0);
  });

  it("decrements the remaining attempts reported by the transport", async () => {
    const rec = recorder();
    const session = await sessionFor(BINDING, rec);
    rec.setPinResult({ ok: false, attemptsRemaining: 2 });

    const result = await submitStepUpPin(session, BINDING, "000000", rec.deps);
    expect(result).toMatchObject({ ok: false, code: "PIN_REJECTED" });
  });

  it("ends the session when the last attempt fails", async () => {
    const rec = recorder();
    const session = await sessionFor(BINDING, rec);
    rec.setPinResult({ ok: false, attemptsRemaining: 0 });

    const result = await submitStepUpPin(session, BINDING, "000000", rec.deps);
    expect(result).toMatchObject({ ok: false, code: "ATTEMPTS_EXHAUSTED" });
  });

  it("gives a generic reason so challenge existence cannot be probed", async () => {
    const rec = recorder();
    const session = await sessionFor(BINDING, rec);
    rec.setPinResult({ ok: false, attemptsRemaining: 1, reason: "no such challenge" });

    const result = await submitStepUpPin(session, BINDING, "000000", rec.deps);
    if (result.ok) throw new Error("unreachable");
    expect(result.detail).toBe("the PIN was not accepted");
  });
});

describe("session state guards", () => {
  it("refuses with no session at all", async () => {
    const rec = recorder();
    expect(await submitStepUpPin(null, BINDING, PIN, rec.deps)).toMatchObject({
      ok: false,
      code: "SESSION_MISSING",
    });
  });

  it("refuses a second submission after completion", async () => {
    const rec = recorder();
    const session = await sessionFor(BINDING, rec);
    const done = await submitStepUpPin(session, BINDING, PIN, rec.deps);
    if (!done.ok) throw new Error("unreachable");

    const again = await submitStepUpPin(done.session, BINDING, PIN, rec.deps);
    expect(again).toMatchObject({ ok: false, code: "ALREADY_COMPLETED" });
    expect(rec.submitted).toHaveLength(1);
  });

  it("canRetryRelease requires a completed session", async () => {
    const rec = recorder();
    const session = await sessionFor(BINDING, rec);
    expect(canRetryRelease(session, BINDING)).toMatchObject({ ok: false });
  });

  it("canRetryRelease allows the bound release once completed", async () => {
    const rec = recorder();
    const session = await sessionFor(BINDING, rec);
    const done = await submitStepUpPin(session, BINDING, PIN, rec.deps);
    if (!done.ok) throw new Error("unreachable");
    expect(canRetryRelease(done.session, BINDING)).toHaveProperty("ok", true);
  });

  it("canRetryRelease refuses with no session", () => {
    expect(canRetryRelease(null, BINDING)).toMatchObject({ ok: false, code: "SESSION_MISSING" });
  });
});

describe("module hygiene", () => {
  it("performs no storage or console access", () => {
    // A PIN must not reach persistent storage or a log. Asserted on the source
    // because the alternative is a behavioural test that only covers the paths
    // someone thought to exercise.
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { readFileSync } = require("node:fs") as typeof import("node:fs");
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { resolve } = require("node:path") as typeof import("node:path");
    const src = readFileSync(
      resolve(__dirname, "../../src/domain/services/autofill/step-up-flow.ts"),
      "utf8",
    );
    expect(src).not.toMatch(/chrome\.storage/);
    expect(src).not.toMatch(/console\./);
    expect(src).not.toMatch(/localStorage/);
    expect(src).not.toMatch(/sessionStorage/);
  });
});

describe("service-worker step-up handlers", () => {
  const src = (() => {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { readFileSync } = require("node:fs") as typeof import("node:fs");
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { resolve } = require("node:path") as typeof import("node:path");
    return readFileSync(resolve(__dirname, "../../src/background/auditor.ts"), "utf8");
  })();

  function body(name: string): string {
    const start = src.indexOf(`async function ${name}`);
    expect(start).toBeGreaterThan(-1);
    return src.slice(start, src.indexOf("\n}\n", start));
  }

  it("keeps challenges in memory, never in storage", () => {
    // A challenge is a live authorization. Persisting it would hand any code
    // with storage access a handle on an in-flight third factor.
    expect(body("handleStartStepUp")).not.toMatch(/chrome\.storage\.(local|session)\.set/);
    expect(src).toMatch(/const stepUpChallenges = new Map/);
  });

  it("refuses an unknown challenge without contacting Plus", () => {
    // Otherwise response timing distinguishes "never existed" from "consumed".
    const b = body("handleSubmitStepUpPin");
    expect(b).toMatch(/if \(!entry\)/);
    expect(b).toMatch(/return \{ ok: false, error: "the PIN was not accepted" \}/);
  });

  it("never forwards a server-supplied reason to the client", () => {
    // "no such challenge" would be an existence oracle for live challenges.
    const b = body("handleSubmitStepUpPin");
    expect(b).not.toMatch(/body\.error/);
    expect(b).not.toMatch(/error:\s*body\./);
  });

  it("deletes a challenge once it is completed, so it cannot be replayed", () => {
    const b = body("handleSubmitStepUpPin");
    expect(b).toMatch(/if \(body\.success\) \{[\s\S]*?stepUpChallenges\.delete/);
  });

  it("deletes a challenge once attempts are exhausted", () => {
    expect(body("handleSubmitStepUpPin")).toMatch(
      /remaining <= 0\) stepUpChallenges\.delete/,
    );
  });

  it("deletes an expired challenge", () => {
    expect(body("handleSubmitStepUpPin")).toMatch(
      /Date\.now\(\) >= entry\.expiresAt\) \{[\s\S]*?stepUpChallenges\.delete/,
    );
  });

  it("uses the PIN exactly once, only in the outbound request body", () => {
    // Comments stripped: the handler documents this rule inline, and counting
    // the prose would make the assertion measure the comment rather than the code.
    const code = body("handleSubmitStepUpPin")
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/\/\/.*$/gm, "");
    const occurrences = code.match(/msg\.pin/g) ?? [];
    expect(occurrences).toHaveLength(1);
    // And it must be inside the request body, not a header or a log line.
    expect(code).toMatch(/JSON\.stringify\(\{[^}]*pin: msg\.pin/);
  });

  it("refuses a start request with no binding", () => {
    expect(body("handleStartStepUp")).toMatch(/BINDING_MISSING/);
  });
});
