/**
 * Autofill Guard — the single gate between a credential and a form field.
 *
 * DESIGN RULE: THIS MODULE IS PURE.
 * No chrome.* APIs, no DOM access, no network. It takes a description of the
 * situation and returns ALLOW or BLOCK with a reason. That is deliberate: the
 * decision that releases a secret must be unit-testable without a browser, and
 * it must be impossible for a content script to quietly widen it.
 *
 * THE THREAT THIS DEFEATS
 * ----------------------
 * A page at `https://github.com` is trusted. A page that merely *looks* like
 * github.com, or that embeds a real github.com form in a frame it controls,
 * must never receive a github.com credential. Concretely it blocks:
 *
 *   - scheme downgrade            http://github.com
 *   - subdomain impersonation     https://www.github.com
 *   - suffix attack               https://github.com.evil.example
 *   - lookalike domain             https://github-login.example
 *   - port confusion              https://github.com:8443
 *   - cross-origin form target    <form action="https://evil.example">
 *   - credential-in-iframe        evil.example embedding github.com's login
 *   - form submit to third party  <button formaction="https://evil.example">
 *
 * FAIL CLOSED
 * -----------
 * Every malformed, missing or unparseable input yields BLOCK. There is no
 * "unknown => assume the page is fine" branch anywhere in this file, and adding
 * one would be a security regression even if it made a test pass.
 *
 * This guard is necessary but NOT sufficient. It is checked twice by design:
 * once in the service worker before any secret is decrypted or released, and
 * again here in the content script immediately before the value is written into
 * the field. Defence in depth means neither copy alone is load-bearing.
 */

import {
  compareAbsoluteOrigins,
  parseAbsoluteOrigin,
  resolveAgainstOrigin,
  type CanonicalOrigin,
} from "./origin";

/** Operations that may put a secret into a page. */
export type ReleasableOperation = "AUTOFILL" | "VIEW" | "TOTP";

/**
 * Every way a fill can be refused.
 *
 * These are distinct codes rather than a boolean so that the audit log can
 * distinguish "the site was hostile" from "we could not parse the page" from
 * "this operation is not permitted here". Collapsing them into one boolean
 * destroys the evidence needed to investigate an incident.
 */
export type AutofillBlockReason =
  /** The credential has no origin bound to it. */
  | "CREDENTIAL_ORIGIN_MISSING"
  /** The credential origin is present but unusable. */
  | "CREDENTIAL_ORIGIN_INVALID"
  /** The requesting document's origin is missing or unusable. */
  | "DOCUMENT_ORIGIN_INVALID"
  /** The page is not the exact origin the credential is bound to. */
  | "EXACT_MATCH_FAILED"
  /** The form posts to a different origin. */
  | "FORM_ACTION_ORIGIN_MISMATCH"
  /** The form's action attribute could not be resolved. */
  | "FORM_ACTION_UNRESOLVABLE"
  /** The submit would go to a different origin (e.g. formaction). */
  | "SUBMIT_ORIGIN_MISMATCH"
  /** Running inside a frame that is not the authorized top-level context. */
  | "UNAUTHORIZED_FRAME"
  /** Frame context was supplied but internally inconsistent. */
  | "FRAME_CONTEXT_INCONSISTENT"
  /** The requested operation is not permitted for autofill. */
  | "OPERATION_NOT_RELEASABLE";

export interface AutofillGuardRequest {
  /** Operation being attempted. */
  readonly operation: ReleasableOperation;
  /** The exact origin the credential is bound to. */
  readonly credentialOrigin: string | null | undefined;
  /** Origin of the document requesting the fill. */
  readonly documentOrigin: string;
  /**
   * The form's `action` attribute, exactly as authored — it may be relative,
   * empty or absent. Use `submitOrigin` for a pre-resolved submit target.
   */
  readonly formAction?: string | null;
  /**
   * Pre-resolved origin the submit will actually reach, when the caller can
   * determine it (e.g. a submit button's `formaction`). Takes precedence over
   * `formAction` for the submit-target check.
   */
  readonly submitOrigin?: string | null;
  /**
   * Origin of the top-level browsing context. Required whenever the fill is
   * happening inside a frame.
   */
  readonly topLevelOrigin?: string | null;
  /** Origin of the frame performing the fill; omit when top-level. */
  readonly frameOrigin?: string | null;
}

export interface AutofillGuardAllow {
  readonly allowed: true;
  readonly operation: ReleasableOperation;
  /** Canonical origin the credential is bound to. */
  readonly origin: CanonicalOrigin;
  /** Every check that was evaluated, for the audit trail. */
  readonly checksPassed: readonly string[];
}

export interface AutofillGuardBlock {
  readonly allowed: false;
  readonly reason: AutofillBlockReason;
  /** Audit-safe explanation. Never contains secret material. */
  readonly detail: string;
  /** Checks completed before the refusal, in order. */
  readonly checksPassed: readonly string[];
}

export type AutofillDecision = AutofillGuardAllow | AutofillGuardBlock;

const ALLOWED_OPERATIONS: ReadonlySet<string> = new Set<ReleasableOperation>([
  "AUTOFILL",
  "VIEW",
  "TOTP",
]);

function block(
  reason: AutofillBlockReason,
  detail: string,
  checksPassed: readonly string[],
): AutofillGuardBlock {
  return { allowed: false, reason, detail, checksPassed };
}

/**
 * Evaluate whether a secret may be released into the described context.
 *
 * Check order is deliberate and is itself part of the contract: cheap
 * structural rejections come first, and the frame check runs before the
 * form-action check so that an iframe credential-harvest is reported as such
 * rather than as a confusing form mismatch.
 */
export function evaluateAutofill(request: AutofillGuardRequest): AutofillDecision {
  const passed: string[] = [];

  /* 1. The operation must be one that may touch a page at all. */
  if (!ALLOWED_OPERATIONS.has(request.operation)) {
    return block(
      "OPERATION_NOT_RELEASABLE",
      `operation "${request.operation}" is not a releasable operation`,
      passed,
    );
  }
  passed.push("operation-releasable");

  /* 2. The credential must actually be bound to an origin. */
  if (
    request.credentialOrigin === null ||
    request.credentialOrigin === undefined ||
    request.credentialOrigin.trim() === ""
  ) {
    return block(
      "CREDENTIAL_ORIGIN_MISSING",
      "credential has no origin bound to it; refusing to release",
      passed,
    );
  }
  passed.push("credential-origin-present");

  const credential = parseAbsoluteOrigin(request.credentialOrigin);
  if (!credential.ok) {
    return block(
      "CREDENTIAL_ORIGIN_INVALID",
      `credential origin unusable (${credential.reason})`,
      passed,
    );
  }
  passed.push("credential-origin-valid");

  const document = parseAbsoluteOrigin(request.documentOrigin);
  if (!document.ok) {
    return block(
      "DOCUMENT_ORIGIN_INVALID",
      `document origin unusable (${document.reason})`,
      passed,
    );
  }
  passed.push("document-origin-valid");

  /* 3. Frame context must be coherent, and authorized.
   *
   * A frame is authorized only when BOTH the frame and the top-level context are
   * the credential origin. That second condition is the whole point: it stops
   * `evil.example` from hosting an <iframe src="https://github.com/login"> and
   * harvesting what we inject into it. */
  const hasFrame = request.frameOrigin !== null && request.frameOrigin !== undefined;
  const hasTopLevel =
    request.topLevelOrigin !== null && request.topLevelOrigin !== undefined;

  if (hasFrame !== hasTopLevel) {
    return block(
      "FRAME_CONTEXT_INCONSISTENT",
      hasFrame
        ? "frameOrigin supplied without topLevelOrigin; frame context cannot be trusted"
        : "topLevelOrigin supplied without frameOrigin; frame context cannot be trusted",
      passed,
    );
  }

  if (hasFrame && hasTopLevel) {
    const frame = parseAbsoluteOrigin(request.frameOrigin);
    const topLevel = parseAbsoluteOrigin(request.topLevelOrigin);
    if (!frame.ok || !topLevel.ok) {
      return block(
        "FRAME_CONTEXT_INCONSISTENT",
        `frame context unusable (frame=${frame.ok ? "ok" : frame.reason}, topLevel=${
          topLevel.ok ? "ok" : topLevel.reason
        })`,
        passed,
      );
    }
    if (frame.origin.serialized !== credential.origin.serialized) {
      return block(
        "UNAUTHORIZED_FRAME",
        `frame origin ${frame.origin.serialized} is not the credential origin ${credential.origin.serialized}`,
        passed,
      );
    }
    if (topLevel.origin.serialized !== credential.origin.serialized) {
      return block(
        "UNAUTHORIZED_FRAME",
        `top-level origin ${topLevel.origin.serialized} is not the credential origin ${credential.origin.serialized}; refusing to release into an embedded frame`,
        passed,
      );
    }
    passed.push("frame-authorized");
  }

  /* 4. Absolute ExactMatch: the page itself must BE the credential origin. */
  const pageMatch = compareAbsoluteOrigins(
    credential.origin.serialized,
    document.origin.serialized,
  );
  if (!pageMatch.equal) {
    return block(
      "EXACT_MATCH_FAILED",
      `page origin ${document.origin.serialized} is not the credential origin ${credential.origin.serialized} (${pageMatch.reason})`,
      passed,
    );
  }
  passed.push("exact-match");

  /* 5. The form must post back to the credential origin.
   *
   * An absent or empty action means self-submit, which resolveAgainstOrigin
   * handles. A present action pointing elsewhere is the classic
   * "<form action=\"https://evil.example\">" credential harvester. */
  const formTarget = resolveAgainstOrigin(request.formAction, document.origin.serialized);
  if (!formTarget.ok) {
    return block(
      "FORM_ACTION_UNRESOLVABLE",
      `form action could not be resolved (${formTarget.reason})`,
      passed,
    );
  }
  const formMatch = compareAbsoluteOrigins(
    credential.origin.serialized,
    formTarget.origin.serialized,
  );
  if (!formMatch.equal) {
    return block(
      "FORM_ACTION_ORIGIN_MISMATCH",
      `form posts to ${formTarget.origin.serialized}, not the credential origin ${credential.origin.serialized}`,
      passed,
    );
  }
  passed.push("form-action-origin");

  /* 6. An explicit submit target (formaction) gets the same treatment. */
  if (request.submitOrigin !== null && request.submitOrigin !== undefined) {
    const submitMatch = compareAbsoluteOrigins(
      credential.origin.serialized,
      request.submitOrigin,
    );
    if (!submitMatch.equal) {
      return block(
        "SUBMIT_ORIGIN_MISMATCH",
        `submit target ${request.submitOrigin} is not the credential origin ${credential.origin.serialized} (${submitMatch.reason})`,
        passed,
      );
    }
    passed.push("submit-origin");
  }

  return {
    allowed: true,
    operation: request.operation,
    origin: credential.origin,
    checksPassed: passed,
  };
}

/** Convenience predicate for call sites that only need a yes/no. */
export function mayReleaseSecret(request: AutofillGuardRequest): boolean {
  return evaluateAutofill(request).allowed;
}
