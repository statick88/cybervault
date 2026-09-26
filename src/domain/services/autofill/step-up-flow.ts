/**
 * Step-up flow — client side, from a CHALLENGE_REQUIRED denial to a retry.
 *
 * WHEN THIS RUNS
 * --------------
 * The release path already refuses a managed credential whose policy demands a
 * third factor, returning `CHALLENGE_REQUIRED`. The extension then runs this
 * flow: start a challenge, collect the PIN the user received by email, submit
 * it, and retry the release with the assurance-3 capability Plus issues.
 *
 * THE ONE PROPERTY THIS MODULE EXISTS TO ENFORCE
 * ----------------------------------------------
 * A challenge is a capability to release ONE credential for ONE operation at ONE
 * origin. The client must therefore bind the challenge it started to the exact
 * release it is about to perform, and refuse to reuse it for anything else.
 *
 * Without that binding, a user who completes a step-up for a low-risk
 * credential could be steered into satisfying a challenge and having the resulting
 * assurance-3 capability spent on a different, higher-value credential. Plus
 * would consider the step-up satisfied because, from its side, the user did
 * authenticate. The escalation is invisible at the server and catastrophic at the
 * client, so the client is where it has to be prevented.
 *
 * Plus already binds a challenge to resourceId/operation/secretRef. This module
 * is not a substitute for that — it is the matching local check, so a bug or a
 * confused deputy on either side still cannot cross-bind.
 *
 * PIN HANDLING
 * ------------
 * The PIN is held only as a function argument for the duration of one submit
 * call. It is never stored, never logged, never included in an error message and
 * never attached to a session. A leaked PIN is a spent third factor.
 *
 * @module domain/services/autofill/step-up-flow
 */

/** Operations that can require a third factor. */
export type StepUpOperation = "AUTOFILL" | "TOTP";

/**
 * The exact release a challenge authorizes.
 *
 * All three fields participate. Matching on credential alone would let a
 * challenge for one origin release the same credential id on another; matching on
 * origin alone would let an AUTOFILL challenge release a TOTP.
 */
export interface StepUpBinding {
  readonly credentialId: string;
  readonly origin: string;
  readonly operation: StepUpOperation;
}

export interface StepUpSession {
  readonly challengeId: string;
  /** Immutable binding captured when the challenge was started. */
  readonly binding: StepUpBinding;
  readonly expiresAt: number;
  readonly attemptsRemaining: number;
  /** Set once Plus has verified the PIN. */
  readonly completed: boolean;
}

export type StepUpFailureCode =
  | "CHALLENGE_UNAVAILABLE"
  | "SESSION_EXPIRED"
  | "ATTEMPTS_EXHAUSTED"
  | "BINDING_MISMATCH"
  | "ALREADY_COMPLETED"
  | "PIN_REJECTED"
  | "PIN_INVALID"
  | "SESSION_MISSING";

export type StepUpFailure = { readonly ok: false; readonly code: StepUpFailureCode; readonly detail: string };

export interface StepUpDeps {
  /** Ask Plus to start a challenge for this exact binding. */
  startChallenge(
    binding: StepUpBinding,
  ): Promise<{ challengeId: string; expiresAt: number; attemptsRemaining: number } | null>;
  /** Submit the PIN. Implementations must not retain it. */
  submitPin(
    challengeId: string,
    pin: string,
  ): Promise<
    | { ok: true }
    | { ok: false; attemptsRemaining?: number; reason?: string }
  >;
  /** Injectable clock, so expiry is testable without sleeping. */
  now(): number;
}

/* ------------------------------------------------------------------ */
/*  Session lifecycle                                                  */
/* ------------------------------------------------------------------ */

function fail(code: StepUpFailureCode, detail: string): StepUpFailure {
  return { ok: false, code, detail };
}

function bindingsMatch(a: StepUpBinding, b: StepUpBinding): boolean {
  return a.credentialId === b.credentialId && a.origin === b.origin && a.operation === b.operation;
}

/**
 * Start a challenge bound to `binding`.
 *
 * The binding is copied into the session, so later mutation of the caller's
 * object cannot retarget a challenge that is already in flight.
 */
export async function beginStepUp(
  binding: StepUpBinding,
  deps: StepUpDeps,
): Promise<{ ok: true; session: StepUpSession } | StepUpFailure> {
  const frozen: StepUpBinding = Object.freeze({ ...binding });

  const started = await deps.startChallenge(frozen);
  if (!started) {
    return fail("CHALLENGE_UNAVAILABLE", "Plus did not issue a challenge");
  }
  if (typeof started.challengeId !== "string" || started.challengeId === "") {
    return fail("CHALLENGE_UNAVAILABLE", "Plus returned an unusable challenge id");
  }

  return {
    ok: true,
    session: {
      challengeId: started.challengeId,
      binding: frozen,
      expiresAt: started.expiresAt,
      attemptsRemaining: started.attemptsRemaining,
      completed: false,
    },
  };
}

/**
 * Is this session still usable for `binding`?
 *
 * Checked before every state transition so an expired or cross-bound session is
 * refused rather than silently retried.
 */
export function checkSession(
  session: StepUpSession | null | undefined,
  binding: StepUpBinding,
  deps: Pick<StepUpDeps, "now">,
): { usable: true } | StepUpFailure {
  if (!session) {
    return fail("SESSION_MISSING", "no step-up session in progress");
  }
  if (!bindingsMatch(session.binding, binding)) {
    // Deliberately does not echo the two bindings: a log line that prints both
    // would disclose which credential the user was actually attempting.
    return fail("BINDING_MISMATCH", "challenge is not bound to this release");
  }
  if (session.completed) {
    return fail("ALREADY_COMPLETED", "step-up already completed for this release");
  }
  if (deps.now() >= session.expiresAt) {
    return fail("SESSION_EXPIRED", "challenge has expired");
  }
  if (session.attemptsRemaining <= 0) {
    return fail("ATTEMPTS_EXHAUSTED", "no PIN attempts remain");
  }
  return { usable: true };
}

/**
 * Submit a PIN against the session.
 *
 * `binding` is supplied again by the caller rather than read from the session,
 * precisely so the two can be compared. Reading only the session would make the
 * check vacuous.
 *
 * The PIN is passed straight through and never retained.
 */
export async function submitStepUpPin(
  session: StepUpSession | null | undefined,
  binding: StepUpBinding,
  pin: string,
  deps: StepUpDeps,
): Promise<{ ok: true; session: StepUpSession } | StepUpFailure> {
  const usable = checkSession(session, binding, deps);
  if (!("usable" in usable)) return usable;

  if (typeof pin !== "string" || pin.trim() === "") {
    return fail("PIN_INVALID", "a PIN is required");
  }

  const result = await deps.submitPin(session!.challengeId, pin);
  // `pin` goes out of scope here and is never stored on the session.

  if (result.ok) {
    return {
      ok: true,
      session: { ...session!, attemptsRemaining: 0, completed: true },
    };
  }

  const remaining =
    typeof result.attemptsRemaining === "number" ? result.attemptsRemaining : 0;

  if (remaining <= 0) {
    return fail("ATTEMPTS_EXHAUSTED", "no PIN attempts remain");
  }

  return {
    ok: false,
    code: "PIN_REJECTED",
    // Always generic, and the transport's own reason is deliberately DISCARDED.
    //
    // An earlier draft forwarded `result.reason` verbatim, which handed back
    // strings like "no such challenge". That is an existence oracle: it tells an
    // attacker whether a challenge id is real, turning PIN entry into a way to
    // enumerate live challenges. Plus logs the specific reason server-side; the
    // client only learns that the attempt did not succeed.
    detail: "the PIN was not accepted",
  };
}

/**
 * Whether a completed session authorizes an immediate retry of `binding`.
 *
 * A completed step-up is good for exactly one retry of exactly this release. The
 * capability it yields carries a one-time JTI which Core consumes atomically, so
 * a second retry with the same capability would be rejected anyway; refusing here
 * just avoids spending a round trip to learn that.
 */
export function canRetryRelease(
  session: StepUpSession | null | undefined,
  binding: StepUpBinding,
): { ok: true } | StepUpFailure {
  if (!session) {
    return fail("SESSION_MISSING", "no step-up session in progress");
  }
  if (!bindingsMatch(session.binding, binding)) {
    return fail("BINDING_MISMATCH", "step-up was completed for a different release");
  }
  if (!session.completed) {
    return fail("PIN_REJECTED", "step-up has not been completed");
  }
  return { ok: true };
}
