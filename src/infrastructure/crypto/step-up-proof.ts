/**
 * Proof-of-possession for a step-up approval (R11).
 *
 * ## Why this module exists
 *
 * R3 replaced the step-up PIN with an approval that **Core signs and Plus
 * verifies**. That closes forgery, replay and cross-credential reuse. It does
 * not close R11, which it could never close on its own:
 *
 *     The signature proves CORE AUTHORISED. It does not prove a PERSON
 *     DECIDED TO.
 *
 * `POST /api/v1/step-up/approve` signed for any authenticated caller naming a
 * credential they owned. The R11 attacker is not a network attacker — it is
 * code running as the extension's background worker, holding the bearer token,
 * the userId, and the credential ids the user owns. It called the endpoint
 * itself and received a validly signed approval.
 *
 * ## The two proofs, and why the difference is the whole point
 *
 * **WebAuthn.** The private key lives in the platform authenticator. It is
 * never readable by Core, by the extension, or by any JavaScript context. A
 * fully compromised worker can *request* an assertion and cannot produce one:
 * the authenticator requires user presence, and this module verifies against a
 * key the attacker does not hold.
 *
 * **Passphrase.** PBKDF2 over the challenge, keyed by the existing
 * `users.hash` / `users.salt`. It defeats an AUTOMATED caller holding a stolen
 * token. It does **not** defeat a worker that can read memory — such a worker
 * already holds the master passphrase. It is a raised bar, not a wall, and the
 * threat model says so rather than implying otherwise.
 *
 * ## No WebAuthn library, and why that is fine
 *
 * The project has `@noble/*` but no webauthn/cbor dependency, and this adds
 * none. Registration uses `attestation: "none"`, which is what makes that
 * possible: there is no attestation object to parse. The public key is stored
 * as the 65-byte uncompressed SEC1 point in hex, so CBOR decoding happens once
 * at registration and never again on the verify path.
 *
 * A general CBOR library here would be a dependency added for a shape one
 * function can read in thirty lines, and a supply-chain surface for no benefit.
 *
 * ## The check that makes this R11 and not decoration
 *
 * The **user-presence flag** (authenticator data byte 32, bit 0x01). Without
 * it the signature is a signature, and a signature can be produced by software.
 * With it, the authenticator has asserted that a human touched the device. If
 * this check is ever relaxed, R11 returns in full.
 *
 * ## Browser safety
 *
 * This module is imported by the popup. It must not reach for `node:crypto`:
 * esbuild bundles it for the browser, and Core runs it under Node. Everything
 * here is `crypto.subtle` and `TextEncoder`, which both provide identically.
 */

/** PBKDF2 parameters — must match `HASH_ITERATIONS` in `src/infrastructure/api/auth.ts`. */
const PBKDF2_ITERATIONS = 600_000;
const PBKDF2_KEY_LENGTH = 64;
const PBKDF2_DIGEST = "SHA-512";

/** Proof challenges are short-lived on purpose. */
export const APPROVAL_CHALLENGE_TTL_MS = 2 * 60 * 1000;

/**
 * The PBKDF2 parameters every step-up proof hop uses.
 *
 * Exported so a test can assert the algebra against Node's own PBKDF2 rather
 * than against a second implementation of it in the test file. Two
 * implementations agreeing proves nothing about either.
 */
export const STEP_UP_KDF = {
  iterations: PBKDF2_ITERATIONS,
  keyLength: PBKDF2_KEY_LENGTH,
  digest: PBKDF2_DIGEST,
} as const;

/**
 * Domain separator for the second PBKDF2 hop.
 *
 * Without it the proof would be a bare PBKDF2 output over a user hash, the
 * same shape Core stores for login — and a value lifted from one context would
 * be valid in the other. Prefixing the material makes the two contexts
 * non-interchangeable, which is HKDF's `info` argument doing the same job.
 */
export const PASSPHRASE_PROOF_PREFIX = "cybervault/step-up/v1:";

/* ------------------------------------------------------------------ */
/*  The proof contract                                                 */
/* ------------------------------------------------------------------ */

export interface PassphraseStepUpProof {
  type: "passphrase";
  /**
   * The step-up challenge this proof authorises — the release being approved.
   *
   * Checked by Core against the stored binding, so a proof derived for one
   * credential cannot authorise another.
   */
  challengeId: string;
  /**
   * The proof challenge Core issued. Single use: consuming it is what stops a
   * captured proof from being replayed.
   *
   * Distinct from `challengeId` because a proof carries BOTH — the release and
   * the one-shot challenge guarding it. Collapsing the two names is how a
   * proof ends up bound to the wrong thing.
   */
  approvalChallengeId: string;
  /** base64url PBKDF2 output. */
  value: string;
}

export interface WebAuthnStepUpProof {
  type: "webauthn";
  /** The step-up challenge this proof authorises. */
  challengeId: string;
  /** The proof challenge Core issued, base64url. */
  approvalChallengeId: string;
  credentialId: string;
  clientDataJSON: string;
  authenticatorData: string;
  signature: string;
}

export type StepUpProof = PassphraseStepUpProof | WebAuthnStepUpProof;

/**
 * The two proof types, and nothing else.
 *
 * `isStepUpProofType` is checked before the proof body is read, so an unknown
 * type is refused without being parsed. That ordering matters: the parser is
 * the untrusted-input boundary, and the cheapest safe answer to a string it
 * does not recognise is "no".
 */
export function isStepUpProofType(value: unknown): value is StepUpProof["type"] {
  return value === "passphrase" || value === "webauthn";
}

/* ------------------------------------------------------------------ */
/*  base64url — WebAuthn is base64url, the shared helpers are base64    */
/* ------------------------------------------------------------------ */

/**
 * Decode base64url to bytes.
 *
 * Distinct from the project's `base64ToBinary`, which is standard base64.
 * WebAuthn is base64url everywhere, and mixing the two alphabet produces
 * bytes that parse as valid JSON roughly half the time — a silent failure
 * that would read as a malformed challenge rather than a wrong decode.
 */
export function base64UrlToBytes(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const withPadding = padded + "=".repeat((4 - (padded.length % 4)) % 4);
  const binary = atob(withPadding);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/** Encode bytes as base64url, without padding. */
export function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Lowercase hex of a byte array — how a public key is stored. */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Parse a hex string into bytes, or `null` if it is not valid hex.
 *
 * `null` rather than a throw: the input comes from a database row that a
 * migration or a hand-edited value could have corrupted, and a throw here
 * would surface as a 500 on the approve path. Refusing the proof is correct.
 */
export function hexToBytesOrNull(value: string): Uint8Array | null {
  if (value.length % 2 !== 0) return null;
  if (!/^[0-9a-fA-F]*$/.test(value)) return null;
  const bytes = new Uint8Array(value.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(value.substr(i * 2, 2), 16);
  }
  return bytes;
}

/**
 * An uncompressed SEC1 P-256 public key point: `0x04 || x || y`, 65 bytes.
 *
 * Accepts either the 65-byte point itself or a DER SubjectPublicKeyInfo
 * wrapping it, because that is what a WebAuthn client naturally produces —
 * `navigator.credentials.create()` hands back an SPKI, not a bare point.
 * Requiring the caller to strip the ASN.1 header by hand would be a
 * transcription step, and transcription steps are where keys get mangled.
 *
 * Anything else is refused: a raw 32-byte key, a compressed point, or a length
 * that is not 65. Importing the wrong bytes would either throw or, worse,
 * verify against a key the caller did not register.
 */
export function parseP256PublicKey(input: Uint8Array | string): Uint8Array | null {
  let bytes: Uint8Array;
  if (typeof input === "string") {
    const fromHex = hexToBytesOrNull(input);
    if (fromHex) {
      bytes = fromHex;
    } else {
      try {
        bytes = base64UrlToBytes(input);
      } catch {
        return null;
      }
    }
  } else {
    bytes = input;
  }

  // A COSE_Key is also a legitimate wire form — it is what the WebAuthn
  // `credentialPublicKey` arrives as — so accept it and flatten to the point.
  // Checking CBOR map headers first means a COSE blob is never mistaken for a
  // truncated point, and vice versa.
  if (bytes.length !== 65 && (bytes[0] === 0xa4 || bytes[0] === 0xa5)) {
    const cose = readCoseP256Key(bytes);
    if (!cose) return null;
    bytes = new Uint8Array(65);
    bytes[0] = 0x04;
    bytes.set(cose.x, 1);
    bytes.set(cose.y, 33);
  }

  // A DER SPKI for P-256 is a fixed prefix followed by the 65-byte point.
  // Checking the exact prefix means a longer or shorter encoding cannot
  // slip through and be sliced at the wrong offset.
  // SEQUENCE(89) { SEQUENCE(19){ OID ecPublicKey, OID prime256v1 }
  //               BITSTRING(66){ 0 unused bits, 0x04 || x || y } }
  // The 0x42 length is 1 + 65: the "unused bits" byte plus the point.
  const SPKI_PREFIX = new Uint8Array([
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
  ]);
  if (bytes.length === SPKI_PREFIX.length + 65) {
    if (!constantTimeEqual(bytes.slice(0, SPKI_PREFIX.length), SPKI_PREFIX)) {
      return null;
    }
    bytes = bytes.slice(SPKI_PREFIX.length);
  }

  if (bytes.length !== 65) return null;
  if (bytes[0] !== 0x04) return null;
  return bytes;
}

/**
 * Read a COSE_Key for EC2 / P-256.
 *
 * Only used at registration, and only for the credential's public key when a
 * client sends COSE rather than SPKI. The structure is a CBOR map of five small
 * integers:
 *
 *   1 -> kty (2 = EC2)   -1 -> crv (1 = P-256)
 *   3 -> alg (-7 = ES256)  -2 -> x  -3 -> y
 *
 * Deliberately not a general CBOR decoder: accepting more means accepting key
 * types this code has no business verifying, and every extra branch is a place
 * to get the bounds wrong. Returns `null` rather than throwing, because the
 * input is attacker-supplied and a throw would surface as a 500.
 */
export function readCoseP256Key(cose: Uint8Array): { x: Uint8Array; y: Uint8Array } | null {
  try {
    if (cose.length < 5) return null;

    const header = cose[0];
    let entries: number;
    if (header === 0xa5) entries = 5;
    else if (header === 0xa4) entries = 4;
    else return null;

    let offset = 1;
    const map = new Map<number, Uint8Array>();

    for (let i = 0; i < entries; i++) {
      const keyByte = cose[offset];
      if (keyByte === undefined) return null;

      let key: number;
      if (keyByte < 24) {
        key = keyByte;
        offset += 1;
      } else if (keyByte >= 0x20 && keyByte <= 0x37) {
        // CBOR: 0x20 == -1, 0x21 == -2, 0x22 == -3. The offset is 0x1f, not
        // 0x20: `-(keyByte - 0x20)` maps 0x21 to -1 and shifts every key by one,
        // so `-2` (the x coordinate) is read as `-1` (the curve) and the key
        // silently parses as a curve with no coordinates.
        key = -1 * (keyByte - 0x1f);
        offset += 1;
      } else {
        return null;
      }

      const valueHeader = cose[offset];
      if (valueHeader === undefined) return null;

      if (valueHeader <= 0x17) {
        map.set(key, new Uint8Array([valueHeader]));
        offset += 1;
      } else if (valueHeader >= 0x20 && valueHeader <= 0x37) {
        // Negative integer, 0x20..0x37 == -1..-24. `alg: -7` (ES256) is
        // encoded as 0x26 and lives here. Without this branch the parser meets
        // 0x26, matches neither a small unsigned int nor a byte string, and
        // returns null on every real COSE key.
        map.set(key, new Uint8Array([valueHeader]));
        offset += 1;
      } else if (valueHeader >= 0x40 && valueHeader <= 0x5b) {
        // CBOR byte strings: 0x40..0x57 carry the length inline (0..23),
        // 0x58 means "one more byte holds the length". 0x58 is therefore
        // length 24 only when the FOLLOWING byte is 24 — which is how a
        // 32-byte P-256 coordinate is encoded. Reading 0x58 as "32 bytes"
        // instead is the natural mistake and silently truncates every key.
        let length = valueHeader - 0x40;
        let headerLen = 1;
        if (valueHeader === 0x58) {
          const lenByte = cose[offset + 1];
          if (lenByte === undefined) return null;
          length = lenByte;
          headerLen = 2;
        }
        const start = offset + headerLen;
        const slice = cose.slice(start, start + length);
        // A truncated byte string is malformed, not short. Refusing here stops
        // a short `x` from being silently zero-padded into a different key.
        if (slice.length !== length) return null;
        map.set(key, slice);
        offset = start + length;
      } else {
        return null;
      }
    }

    // Trailing bytes are a rejection, not a shrug. A COSE_Key with a valid
    // prefix and appended garbage parses to a *correct* key under a lenient
    // reader, which means two different byte strings verify against the same
    // credential — and a signature check would no longer be proof of which
    // bytes were actually registered.
    if (offset !== cose.length) return null;

    const kty = map.get(1)?.[0];
    const alg = map.get(3)?.[0];
    const crv = map.get(-1)?.[0];
    const x = map.get(-2);
    const y = map.get(-3);

    if (kty !== 2) return null; // EC2
    // -7 arrives as 0x26 (0x20 | 6); ES256 is 0xf7 when encoded unsigned.
    if (alg !== undefined && alg !== 0x26 && alg !== 0xf7) return null;
    if (crv !== 1) return null; // P-256
    if (!x || !y || x.length !== 32 || y.length !== 32) return null;

    return { x, y };
  } catch {
    return null;
  }
}

/* ------------------------------------------------------------------ */
/*  WebAuthn assertion verification                                    */
/* ------------------------------------------------------------------ */

export interface WebAuthnExpectation {
  /** The base64url challenge Core issued for this proof. */
  challenge: string;
  /** Expected `clientDataJSON.origin`. */
  origin: string;
  /** Expected relying-party id. */
  rpId: string;
  /**
   * The stored public key: hex of the 65-byte uncompressed SEC1 point.
   *
   * Hex rather than base64url because it is what the repository stores, and
   * `parseP256PublicKey` normalises whichever arrives.
   */
  publicKey: string;
  /** The counter persisted at registration or last use. */
  storedCounter: number;
}

export type WebAuthnResult =
  | { ok: true; signCount: number }
  | { ok: false; error: string };

/**
 * Verify a WebAuthn assertion.
 *
 * Every check is present because skipping any one reopens a specific attack:
 *
 *   type / challenge / origin — a signature harvested from another ceremony.
 *   rpIdHash                   — a credential registered for another site.
 *   user presence              — a software signer, i.e. no human. THIS IS R11.
 *   counter                    — a cloned authenticator.
 *   signature                  — everything above, on a forged assertion.
 */
export async function verifyWebAuthnAssertion(
  assertion: { clientDataJSON: string; authenticatorData: string; signature: string },
  expected: WebAuthnExpectation,
): Promise<WebAuthnResult> {
  /* ---- clientDataJSON ---- */
  let clientData: { type?: string; challenge?: string; origin?: string };
  try {
    clientData = JSON.parse(new TextDecoder().decode(base64UrlToBytes(assertion.clientDataJSON)));
  } catch {
    return { ok: false, error: "Malformed clientDataJSON" };
  }

  if (clientData.type !== "webauthn.get") {
    return { ok: false, error: "Wrong ceremony type" };
  }
  if (!constantTimeEqualStr(clientData.challenge ?? "", expected.challenge)) {
    return { ok: false, error: "Challenge mismatch" };
  }
  if (clientData.origin !== expected.origin) {
    return { ok: false, error: "Origin mismatch" };
  }

  /* ---- authenticatorData ---- */
  let authData: Uint8Array;
  let signatureBytes: Uint8Array;
  try {
    authData = base64UrlToBytes(assertion.authenticatorData);
    signatureBytes = base64UrlToBytes(assertion.signature);
  } catch {
    return { ok: false, error: "Malformed assertion" };
  }

  // rpIdHash(32) + flags(1) + signCount(4) is the floor; anything longer
  // carries attested credential data this code does not use.
  if (authData.length < 37) {
    return { ok: false, error: "authenticatorData too short" };
  }

  const rpIdHash = authData.slice(0, 32);
  const flags = authData[32];
  const signCount = readUint32(authData, 33);

  const expectedRpIdHash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", new TextEncoder().encode(expected.rpId)),
  );
  if (!constantTimeEqual(rpIdHash, expectedRpIdHash)) {
    return { ok: false, error: "RP ID hash mismatch" };
  }

  // ---- R11 itself -------------------------------------------------------
  // Bit 0 of the flags byte: the authenticator asserting a human was present.
  // A software-produced signature has this clear, and without this check the
  // flow is self-approvable by a compromised worker — which is the whole
  // defect R11 exists to close.
  const USER_PRESENT = 0x01;
  if ((flags & USER_PRESENT) === 0) {
    return { ok: false, error: "No user presence" };
  }

  // Clone detection, with the caveat the spec forces: platform authenticators
  // (Touch ID, Windows Hello, a phone) report a counter of 0 on EVERY
  // assertion, because their signature is backed by the secure enclave and
  // there is nothing to count. So "did not advance" is only evidence of a
  // clone when BOTH sides are non-zero. Refusing 0 <= 0 would lock out every
  // user whose credential is a platform authenticator — the most common kind.
  //
  // A real clone shows up as a counter that goes backwards, or stalls at a
  // non-zero value while the stored one climbs.
  if (expected.storedCounter > 0 && signCount <= expected.storedCounter) {
    return { ok: false, error: "Sign count did not advance" };
  }

  /* ---- signature ---- */
  const keyPoint = parseP256PublicKey(expected.publicKey);
  if (!keyPoint) {
    return { ok: false, error: "Stored key is not a usable P-256 point" };
  }

  let publicKey: CryptoKey;
  try {
    publicKey = await crypto.subtle.importKey(
      "raw",
      toArrayBuffer(keyPoint),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
  } catch {
    return { ok: false, error: "Could not import the stored key" };
  }

  // The signed message is `authenticatorData || SHA-256(clientDataJSON)`, per
  // the WebAuthn spec. Signing authenticatorData alone would leave
  // clientDataJSON — and therefore the challenge and origin — outside the
  // signature, so a captured authenticatorData could be replayed against a
  // different ceremony. This is why the client-data checks above are not
  // redundant with the signature check: they are what the signature commits to.
  const clientDataHash = new Uint8Array(
    await crypto.subtle.digest("SHA-256", toArrayBuffer(base64UrlToBytes(assertion.clientDataJSON))),
  );
  // WebAuthn is explicit that the hash is over the RAW clientDataJSON bytes —
  // the base64url here is transport encoding, and hashing the decoded form is
  // what a real authenticator does.
  const signedMessage = new Uint8Array(authData.length + clientDataHash.length);
  signedMessage.set(authData, 0);
  signedMessage.set(clientDataHash, authData.length);

  let signatureOk: boolean;
  try {
    signatureOk = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      publicKey,
      toArrayBuffer(signatureBytes),
      toArrayBuffer(signedMessage),
    );
  } catch {
    return { ok: false, error: "Signature verification failed" };
  }

  if (!signatureOk) {
    return { ok: false, error: "Invalid signature" };
  }

  return { ok: true, signCount };
}

/* ------------------------------------------------------------------ */
/*  Passphrase proof — defence in depth, honestly scoped               */
/* ------------------------------------------------------------------ */

/**
 * Derive the proof a correct passphrase produces.
 *
 * ## Why this is two PBKDF2 rounds and not one
 *
 * Core stores `users.hash = PBKDF2(passphrase, users.salt)` and never the
 * passphrase. So a naive "client sends PBKDF2(passphrase, challenge)" proof
 * could not be verified by the server at all — it has nothing to compare
 * against. The first version of this code fell into exactly that trap and
 * "verified" a well-formed 64-byte value, which any caller can send.
 *
 * The fix is a challenge-response over a key Core already holds:
 *
 *   1. client: userHash = PBKDF2(passphrase, userSalt)   — the popup has the
 *      passphrase and the salt, so it can reproduce the value Core stores
 *      WITHOUT Core ever sending the hash. Sending it would be handing the
 *      client a password-equivalent verifier.
 *   2. client: value = PBKDF2(userHash, salt || challengeId)
 *   3. server: expected = PBKDF2(user.hash, salt || challengeId)
 *
 * Core recomputes step 3 from the hash it already holds. The client proves
 * knowledge of the passphrase by producing step 2, which is only computable
 * from the passphrase. And the proof is bound to this one challenge, so a
 * captured value cannot be replayed against another release.
 *
 * Step 2 uses `userHash` as a PBKDF2 password. That is sound: `userHash` is
 * 64 bytes of PBKDF2-SHA512 output over 600k iterations, not a
 * human-chosen secret, so its second use is not a weakening.
 */
export async function derivePassphraseProof(
  passphrase: string,
  userSalt: string,
  stepUpChallengeId: string,
  proofSalt: string,
): Promise<string> {


  const passphraseKey = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(passphrase),
    "PBKDF2",
    false,
    ["deriveBits"],
  );

  // Round 1 — reproduce what Core stored, from the passphrase and the salt the
  // client already legitimately holds.
  const userHashBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: new TextEncoder().encode(userSalt),
      iterations: PBKDF2_ITERATIONS,
      hash: PBKDF2_DIGEST,
    },
    passphraseKey,
    PBKDF2_KEY_LENGTH * 8,
  );
  const userHash = new Uint8Array(userHashBits);

  // Round 2 — the actual proof, bound to this challenge and this release.
  // Hex on the wire, not base64url. The proof travels inside a JSON body next
  // to identifiers that are already hex, and a 64-byte PBKDF2 output rendered
  // as hex survives every log, proxy and debug view intact. Base64url would
  // too, but mixing alphabets inside one object is how a field gets decoded
  // with the wrong function — the exact mistake R9 had with a stub answering
  // a shape the server never sent.
  return bytesToHex(
    await pbkdf2Bytes(userHash, `${PASSPHRASE_PROOF_PREFIX}${stepUpChallengeId}:${proofSalt}`),
  );
}

/**
 * Verify a presented passphrase proof against the one Core derives.
 *
 * `userSalt` is deliberately absent: the stored hash already has it folded in,
 * so passing it again would be a second, unverifiable input. Four inputs, each
 * of which changes the expected value.
 *
 * Constant time: a byte-wise compare would leak the matching prefix of the
 * proof through response timing — the same mistake R1 fixed for the service
 * secret.
 */
export async function verifyPassphraseProof(
  userHash: string,
  proofSalt: string,
  stepUpChallengeId: string,
  presented: string,
): Promise<boolean> {
  const hashBytes = hexToBytesOrNull(userHash);
  if (!hashBytes || hashBytes.length !== PBKDF2_KEY_LENGTH) {
    // A user row whose hash is not a well-formed PBKDF2 output cannot be
    // verified against. Refusing is correct; guessing is not.
    return false;
  }

  const expected = await pbkdf2Bytes(
    hashBytes,
    `${PASSPHRASE_PROOF_PREFIX}${stepUpChallengeId}:${proofSalt}`,
  );

  let presentedBytes: Uint8Array;
  try {
    presentedBytes = hexToBytesOrNull(presented) ?? base64UrlToBytes(presented);
  } catch {
    return false;
  }
  if (presentedBytes.length !== PBKDF2_KEY_LENGTH) return false;

  return constantTimeEqual(expected, presentedBytes);
}

/** PBKDF2 over a byte-array key, returned as raw bytes. */
async function pbkdf2Bytes(keyMaterial: Uint8Array, salt: string): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    toArrayBuffer(keyMaterial),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: new TextEncoder().encode(salt),
      iterations: PBKDF2_ITERATIONS,
      hash: PBKDF2_DIGEST,
    },
    key,
    PBKDF2_KEY_LENGTH * 8,
  );
  return new Uint8Array(bits);
}

/* ------------------------------------------------------------------ */
/*  helpers                                                            */
/* ------------------------------------------------------------------ */

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const buffer = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(buffer).set(bytes);
  return buffer;
}

function readUint32(bytes: Uint8Array, offset: number): number {
  return (
    ((bytes[offset] ?? 0) * 0x1000000) +
    ((bytes[offset + 1] ?? 0) << 16) +
    ((bytes[offset + 2] ?? 0) << 8) +
    (bytes[offset + 3] ?? 0)
  ) >>> 0;
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}

function constantTimeEqualStr(a: string, b: string): boolean {
  return constantTimeEqual(new TextEncoder().encode(a), new TextEncoder().encode(b));
}
