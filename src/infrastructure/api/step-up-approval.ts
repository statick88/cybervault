/**
 * R11 — Core-side verification of a human-presence proof (T5).
 *
 * `verifyStepUpProof` is the single gate every proof passes through, for
 * both `POST /api/v1/step-up/approve` (purpose `release`) and the
 * authenticator registration route (purpose `enroll`). Concentrating it here
 * means the two routes cannot drift — a registration that forgot the proof
 * check would let a stolen bearer token enroll its own P-256 key and defeat
 * R11 in one request.
 *
 * Failure contract: every refusal is `{ ok: false, status, error }` with a
 * GENERIC message at the route boundary. The specific `reason`s below are
 * for server-side logs only — an oracle that distinguishes "unknown
 * challenge" from "bad signature" tells an attacker which part of a forged
 * proof to fix.
 *
 * @module infrastructure/api/step-up-approval
 */

import type {
  IStepUpAuthenticatorStore,
  StepUpApprovalChallenge,
} from "../../domain/repositories";
import type { StoredUser } from "./auth";
import {
  base64UrlToBytes,
  hexToBytesOrNull,
  isStepUpProofType,
  verifyPassphraseProof,
  verifyWebAuthnAssertion,
  type StepUpProof,
} from "../crypto/step-up-proof";

/**
 * WebAuthn relying-party configuration, read from the environment once per
 * request. Both values must be present: without an rpId the assertion's
 * rpIdHash cannot be checked, and without an origin the clientData origin
 * cannot — so `configured: false` makes every webauthn proof fail closed
 * instead of being checked against a guess.
 *
 * The origin is the ORIGIN OF THE PAGE THAT CALLS `navigator.credentials`
 * (the extension popup — `chrome-extension://<id>`), NOT the origin of this
 * API. They are configured independently on purpose.
 */
export interface WebAuthnConfig {
  readonly configured: boolean;
  readonly rpId: string;
  readonly origin: string;
}

export function readWebAuthnConfig(env: NodeJS.ProcessEnv = process.env): WebAuthnConfig {
  const rpId = env.STEP_UP_WEBAUTHN_RP_ID?.trim() ?? "";
  const origin = env.STEP_UP_WEBAUTHN_ORIGIN?.trim() ?? "";
  return { configured: rpId !== "" && origin !== "", rpId, origin };
}

export type ProofVerification =
  | {
      readonly ok: true;
      /** Present only for webauthn: observed signature counter, if it advanced. */
      readonly signCount?: number;
      readonly credentialId?: string;
    }
  | { readonly ok: false; readonly status: number; readonly error: string };

const reject = (status: number, error: string): ProofVerification => ({
  ok: false,
  status,
  error,
});

/**
 * Verify one already-consumed approval challenge.
 *
 * PRECONDITION — `row` comes from `IStepUpApprovalChallengeStore.consume`,
 * i.e. it is OWNED by the caller's user, UNEXPIRED and now spent. Callers
 * consume BEFORE calling this on purpose: a failed proof still burns the
 * challenge, so a captured assertion (or a guessing attacker) cannot retry
 * against the same row — the user simply requests a fresh challenge.
 *
 * What is checked here:
 *   1. the row is for the purpose the route serves (`release` vs `enroll`);
 *   2. `proof.challengeId` equals the row's binding — a proof minted for
 *      another release can never be presented against this one;
 *   3. the type-specific material (derived PBKDF2 value / assertion) against
 *      what Core issued and stored.
 */
export async function verifyStepUpProof(
  proof: StepUpProof,
  row: StepUpApprovalChallenge,
  user: StoredUser,
  requiredPurpose: StepUpApprovalChallenge["purpose"],
  authenticators: IStepUpAuthenticatorStore,
  webauthn: WebAuthnConfig,
): Promise<ProofVerification> {
  if (row.purpose !== requiredPurpose) {
    return reject(403, "Approval proof rejected");
  }
  if (proof.challengeId !== row.bindingId) {
    // The binding is the whole point: this proof was derived against a
    // different challenge (or forged field), so it authorises nothing here.
    return reject(403, "Approval proof rejected");
  }

  if (proof.type === "passphrase") {
    if (typeof proof.value !== "string" || proof.value === "") {
      return reject(403, "Approval proof rejected");
    }
    const valid = await verifyPassphraseProof(
      user.hash,
      row.salt,
      row.bindingId,
      proof.value,
    );
    if (!valid) return reject(403, "Approval proof rejected");
    return { ok: true };
  }

  if (proof.type !== "webauthn") {
    // Unknown type is a malformed request, not a failed proof: 400 so a
    // client bug is loud, without revealing anything about valid proofs.
    return reject(400, "Unsupported proof type");
  }

  if (!webauthn.configured || !row.rpId || !row.origin) {
    // Fail closed: no configured rpId/origin means the assertion cannot be
    // checked against anything trustworthy — never "check" against a guess.
    return reject(403, "Approval proof rejected");
  }
  if (typeof proof.credentialId !== "string" || proof.credentialId === "") {
    return reject(403, "Approval proof rejected");
  }

  const authenticator = await authenticators.findByCredentialId(proof.credentialId);
  if (!authenticator || authenticator.userId !== row.userId) {
    return reject(403, "Approval proof rejected");
  }

  // The assertion travels as base64url and is decoded inside
  // `verifyWebAuthnAssertion`, which owns the bounds checks. Decoding here and
  // handing over bytes would split the parsing across two files and make the
  // length validation the caller's problem instead of the verifier's.
  const { clientDataJSON, authenticatorData, signature } = proof;

  const result = await verifyWebAuthnAssertion(
    { clientDataJSON, authenticatorData, signature },
    {
      challenge: row.challenge,
      origin: row.origin,
      rpId: row.rpId,
      publicKey: authenticator.publicKey,
      storedCounter: authenticator.counter,
    },
  );
  if (!result.ok) {
    return reject(403, "Approval proof rejected");
  }
  return { ok: true, signCount: result.signCount, credentialId: authenticator.credentialId };
}

/**
 * Structural pre-check shared by both routes, executed BEFORE the challenge
 * is consumed so a plainly malformed proof (missing id, mismatched binding
 * id, unknown type) does not burn a legitimate in-flight challenge. Deep
 * material checks live in `verifyStepUpProof`, after consumption.
 *
 * Returns the parsed proof or a refusal. `expectedChallengeId` is the
 * request's own binding: for approve it is the release `challengeId` in the
 * body (which must equal `proof.challengeId`); for registration it is `null`
 * — an enroll row binds to its own minted id, which `verifyStepUpProof`
 * re-checks against the consumed row, so no pre-consume value is known yet.
 */
export function precheckProofShape(
  rawProof: unknown,
  expectedChallengeId: string | null,
): { proof: StepUpProof } | { status: number; error: string } {
  if (rawProof === null || typeof rawProof !== "object") {
    return { status: 403, error: "Approval proof required" };
  }
  const candidate = rawProof as Partial<StepUpProof> & Record<string, unknown>;
  if (!isStepUpProofType(candidate.type)) {
    return { status: 400, error: "Unsupported proof type" };
  }
  if (
    typeof candidate.approvalChallengeId !== "string" ||
    candidate.approvalChallengeId === ""
  ) {
    return { status: 403, error: "Approval proof rejected" };
  }
  if (
    typeof candidate.challengeId !== "string" ||
    (expectedChallengeId !== null && candidate.challengeId !== expectedChallengeId)
  ) {
    // An assertion derived for one challenge presented for another is the
    // exact cross-challenge replay R11 exists to refuse.
    return { status: 403, error: "Approval proof rejected" };
  }
  if (candidate.type === "passphrase" && typeof candidate.value !== "string") {
    return { status: 403, error: "Approval proof rejected" };
  }
  if (candidate.type === "webauthn") {
    for (const field of ["credentialId", "clientDataJSON", "authenticatorData", "signature"] as const) {
      if (typeof candidate[field] !== "string" || candidate[field] === "") {
        return { status: 403, error: "Approval proof rejected" };
      }
    }
  }
  return { proof: candidate as StepUpProof };
}
