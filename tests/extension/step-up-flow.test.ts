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
  submitApproval,
  checkSession,
  canRetryRelease,
  type StepUpBinding,
  type StepUpDeps,
  type StepUpSession,
} from "../../src/domain/services/autofill/step-up-flow";

const NOW = 1_700_000_000_000;

const BINDING: StepUpBinding = {
  credentialId: "cred-low-value",
  origin: "https://github.com:443",
  operation: "AUTOFILL",
};

interface Recorder {
  deps: StepUpDeps;
  started: StepUpBinding[];
  submitted: Array<{ challengeId: string }>;
  setNow(ms: number): void;
  setApprovalResult(r: Awaited<ReturnType<StepUpDeps["submitApproval"]>>): void;
  setStartResult(r: Awaited<ReturnType<StepUpDeps["startChallenge"]>>): void;
}

function recorder(overrides: Partial<StepUpDeps> = {}): Recorder {
  let now = NOW;
  let approvalResult: Awaited<ReturnType<StepUpDeps["submitApproval"]>> = { ok: true };
  let startResult: Awaited<ReturnType<StepUpDeps["startChallenge"]>> = {
    challengeId: "chal-1",
    expiresAt: NOW + 120_000,
    attemptsRemaining: 3,
  };

  const started: StepUpBinding[] = [];
  // R3: the transport receives no secret, so there is no `pin` field to
  // assert on. The absence of one is the guarantee.
  const submitted: Array<{ challengeId: string }> = [];

  const deps: StepUpDeps = {
    startChallenge: async (binding) => {
      started.push(binding);
      return startResult;
    },
    submitApproval: async (challengeId) => {
      // No secret is captured, because none is offered. Recording the
      // challenge id alone is the whole observable surface of this port.
      submitted.push({ challengeId });
      return approvalResult;
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
    setApprovalResult: (r) => {
      approvalResult = r;
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

describe("submitApproval — happy path", () => {
  it("accepts the approval and marks the session completed", async () => {
    const rec = recorder();
    const session = await sessionFor(BINDING, rec);
    const result = await submitApproval(session, BINDING, rec.deps);

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("unreachable");
    expect(result.session.completed).toBe(true);
    expect(result.session.attemptsRemaining).toBe(0);
  });

  it("passes only the challenge id to the transport", async () => {
    const rec = recorder();
    const session = await sessionFor(BINDING, rec);
    await submitApproval(session, BINDING, rec.deps);

    // No secret accompanies the challenge, and asserting the exact object
    // shape is what would fail loudly if a `pin` field ever reappeared.
    expect(rec.submitted).toEqual([{ challengeId: "chal-1" }]);
  });

  it("stores no secret on the session", async () => {
    const rec = recorder();
    const session = await sessionFor(BINDING, rec);
    const result = await submitApproval(session, BINDING, rec.deps);

    const serialized = JSON.stringify(result);
    expect(serialized).not.toMatch(/"pin"/i);
    expect(serialized).not.toMatch(/"secret"/i);
  });
});

describe("CROSS-BINDING — the escalation this module prevents", () => {
  it("refuses an approval submitted against a different credential", async () => {
    const rec = recorder();
    const session = await sessionFor(BINDING, rec);

    const other: StepUpBinding = { ...BINDING, credentialId: "prod-database-root" };
    const result = await submitApproval(session, other, rec.deps);

    expect(result).toMatchObject({ ok: false, code: "BINDING_MISMATCH" });
    // Nothing reaches the transport for a foreign binding.
    expect(rec.submitted).toHaveLength(0);
  });

  it("refuses an approval submitted against a different origin", async () => {
    const rec = recorder();
    const session = await sessionFor(BINDING, rec);

    const result = await submitApproval(
      session,
      { ...BINDING, origin: "https://evil.example:443" },
      rec.deps,
    );
    expect(result).toMatchObject({ ok: false, code: "BINDING_MISMATCH" });
    expect(rec.submitted).toHaveLength(0);
  });

  it("refuses a PIN submitted against a different operation", async () => {
    const rec = recorder();
    const session = await sessionFor(BINDING, rec);

    // An AUTOFILL step-up must not authorize a TOTP release.
    const result = await submitApproval(
      session,
      { ...BINDING, operation: "TOTP" },
      rec.deps,
    );
    expect(result).toMatchObject({ ok: false, code: "BINDING_MISMATCH" });
    expect(rec.submitted).toHaveLength(0);
  });

  it("refuses a completed step-up to be spent on another credential", async () => {
    const rec = recorder();
    const session = await sessionFor(BINDING, rec);
    const done = await submitApproval(session, BINDING, rec.deps);
    if (!done.ok) throw new Error("unreachable");

    const other: StepUpBinding = { ...BINDING, credentialId: "prod-database-root" };
    const retry = canRetryRelease(done.session, other);
    expect(retry).toMatchObject({ ok: false, code: "BINDING_MISMATCH" });
  });

  it("does not echo either binding in the mismatch detail", async () => {
    const rec = recorder();
    const session = await sessionFor(BINDING, rec);
    const result = await submitApproval(
      session,
      { ...BINDING, credentialId: "prod-database-root" },
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

    await submitApproval(session, { ...BINDING, credentialId: "other" }, rec.deps);
    const good = await submitApproval(session, BINDING, rec.deps);

    expect(good.ok).toBe(true);
    expect(rec.submitted).toHaveLength(1); // only the legitimate attempt
  });
});

describe("expiry and attempts", () => {
  it("refuses an expired session without contacting the transport", async () => {
    const rec = recorder();
    const session = await sessionFor(BINDING, rec);
    rec.setNow(session.expiresAt);

    const result = await submitApproval(session, BINDING, rec.deps);
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

  it("takes no secret: the approval is the whole submission", async () => {
    const rec = recorder();
    const session = await sessionFor(BINDING, rec);

    // No PIN argument exists any more, so there is nothing that could be sent
    // wrongly. The transport is called with the challenge id alone.
    const result = await submitApproval(session, BINDING, rec.deps);
    expect(result.ok).toBe(true);
    expect(rec.submitted).toHaveLength(1);
  });

  it("refuses when the transport reports the approval was not accepted", async () => {
    const rec = recorder();
    const session = await sessionFor(BINDING, rec);
    rec.setApprovalResult({ ok: false });

    const result = await submitApproval(session, BINDING, rec.deps);
    expect(result).toMatchObject({ ok: false, code: "APPROVAL_REJECTED" });
  });

  it("does not carry a per-attempt budget across refusals", async () => {
    // With no PIN there is no budget. A refusal is a deliberate stop, and the
    // session is not quietly shortened by having tried.
    const rec = recorder();
    const session = await sessionFor(BINDING, rec);
    rec.setApprovalResult({ ok: false });

    await submitApproval(session, BINDING, rec.deps);
    const again = await submitApproval(session, BINDING, rec.deps);

    expect(again).toMatchObject({ ok: false, code: "APPROVAL_REJECTED" });
  });

  it("gives a generic reason so challenge existence cannot be probed", async () => {
    const rec = recorder();
    const session = await sessionFor(BINDING, rec);
    rec.setApprovalResult({ ok: false, reason: "no such challenge" });

    const result = await submitApproval(session, BINDING, rec.deps);
    if (result.ok) throw new Error("unreachable");
    // The transport's own reason is discarded: forwarding it would be an
    // existence oracle for live challenge ids.
    expect(result.detail).toBe("the approval was not accepted");
  });
});

describe("session state guards", () => {
  it("refuses with no session at all", async () => {
    const rec = recorder();
    expect(await submitApproval(null, BINDING, rec.deps)).toMatchObject({
      ok: false,
      code: "SESSION_MISSING",
    });
  });

  it("refuses a second submission after completion", async () => {
    const rec = recorder();
    const session = await sessionFor(BINDING, rec);
    const done = await submitApproval(session, BINDING, rec.deps);
    if (!done.ok) throw new Error("unreachable");

    const again = await submitApproval(done.session, BINDING, rec.deps);
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
    const done = await submitApproval(session, BINDING, rec.deps);
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

  it("refuses an unknown challenge without contacting either service", () => {
    // Otherwise response timing distinguishes "never existed" from "consumed".
    const b = body("handleApproveStepUp");
    expect(b).toMatch(/if \(!entry\)/);
    expect(b).toMatch(/return \{ ok: false, error: "the approval was not accepted" \}/);
  });

  it("never forwards a server-supplied reason to the client", () => {
    // "no such challenge" would be an existence oracle for live challenges.
    const b = body("handleApproveStepUp");
    expect(b).not.toMatch(/body\.error/);
    expect(b).not.toMatch(/error:\s*body\./);
  });

  it("deletes a challenge once it is completed, so it cannot be replayed", () => {
    const b = body("handleApproveStepUp");
    // The success condition is a two-armed check: `success === true` for a Plus
    // that wraps its payload, or a capability present for one that does not.
    // Matching on either arm keeps this pinned to the behaviour rather than to
    // one response shape.
    expect(b).toMatch(
      /if \(body\.success === true \|\| body\.capabilityToken !== undefined\) \{[\s\S]*?stepUpChallenges\.delete/,
    );
  });

  it("never treats a 2xx with neither flag nor capability as a completion", () => {
    // The other half of the same rule. Accepting a bare 200 would record a
    // completion that never happened, which is worse than the bug it replaces:
    // the user believes they approved a release that was refused.
    const b = body("handleApproveStepUp");
    expect(b).not.toMatch(/if \(res\.ok\) \{/);
  });

  it("deletes an expired challenge", () => {
    expect(body("handleApproveStepUp")).toMatch(
      /Date\.now\(\) >= entry\.expiresAt\) \{[\s\S]*?stepUpChallenges\.delete/,
    );
  });

    it("sends no secret at all: the outbound body carries the challenge and the approval", () => {
    // Comments stripped: the handler documents this rule inline, and counting
    // the prose would make the assertion measure the comment rather than the code.
    const code = body("handleApproveStepUp")
      .replace(/\/\*[\s\S]*?\*\//g, "")
      .replace(/\/\/.*$/gm, "");
    // Nothing resembling a PIN is read, forwarded or stored.
    expect(code).not.toMatch(/msg\.pin|\bpin\b/i);
    // The only two fields the body carries are the challenge and Core's
    // signature over it. The approval arrives from the Core call above, not
    // from the message, so a caller cannot supply their own.
    expect(code).toMatch(
      /JSON\.stringify\(\{\s*challengeId: msg\.challengeId,\s*approval: approvalBody\.approval,?\s*\}\)/,
    );
  });

  it("refuses a start request with no binding", () => {
    expect(body("handleStartStepUp")).toMatch(/BINDING_MISSING/);
  });
});
