/**
 * Key Derivation Service — CRITICAL-2 regression suite.
 *
 * The pre-remediation implementation passed an `info` string into WebCrypto
 * **PBKDF2**, which has no `info` field (that belongs to HKDF) and silently
 * ignored it. The consequences, reproduced here with this repository's exact
 * 600k/SHA-512 parameters:
 *
 *   - the "verification hash" was 512 bits of PBKDF2 output, and
 *   - the session key was the FIRST 256 bits of that identical output.
 *
 * so anyone reading `chrome.storage.local` recovered the session key with no
 * master passphrase.
 *
 * The first test in this file is the assertion the old code failed: the
 * context label must actually change the derived output. It is a property of
 * the construction, not a spot check of one vector.
 */

import {
  KeyDerivationService,
  KEY_DERIVATION_CONFIG,
  VERIFIER_SCHEME_PREFIX,
  keyDerivationService,
} from "../../src/infrastructure/crypto/key-derivation-service";
import { binaryToBase64, base64ToBinary } from "../../src/shared/utils";

const PASSPHRASE = "correct horse battery staple 42";

/** Independent reproduction of the OLD scheme (PBKDF2 only, `info` ignored). */
async function legacyPbkdf2(
  password: string,
  salt: Uint8Array,
  bits: number,
  info?: string,
): Promise<string> {
  const encoder = new TextEncoder();
  const passwordBuffer = encoder.encode(password);
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    passwordBuffer as BufferSource,
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  // `info` is deliberately passed the way the old code passed it: into the
  // PBKDF2 params object, where WebCrypto drops it on the floor.
  const params = {
    name: "PBKDF2",
    salt: salt as unknown as BufferSource,
    iterations: KEY_DERIVATION_CONFIG.ITERATIONS,
    hash: KEY_DERIVATION_CONFIG.HASH,
    ...(info ? { info: encoder.encode(info) } : {}),
  } as unknown as Pbkdf2Params;
  const derived = await crypto.subtle.deriveBits(params, keyMaterial, bits);
  return binaryToBase64(new Uint8Array(derived));
}

describe("KeyDerivationService — context binding (HKDF `info`)", () => {
  const service = new KeyDerivationService();
  const salt = service.generateSalt();

  let verifier!: string;
  let sessionKey!: string;
  let labelA!: string;
  let labelB!: string;
  let legacyVerify!: string;
  let legacySession!: string;

  beforeAll(async () => {
    verifier = await service.deriveVerificationHash(PASSPHRASE, salt);
    sessionKey = await service.deriveSessionKey(PASSPHRASE, salt);
    labelA = await service.deriveKey(
      PASSPHRASE,
      salt,
      KEY_DERIVATION_CONFIG.ITERATIONS,
      KEY_DERIVATION_CONFIG.OUTPUT_BITS,
      "cybervault|alpha|v2",
    );
    labelB = await service.deriveKey(
      PASSPHRASE,
      salt,
      KEY_DERIVATION_CONFIG.ITERATIONS,
      KEY_DERIVATION_CONFIG.OUTPUT_BITS,
      "cybervault|beta|v2",
    );
    legacyVerify = await legacyPbkdf2(PASSPHRASE, salt, 512);
    legacySession = await legacyPbkdf2(PASSPHRASE, salt, 256);
  });

  it("the context label changes the derived output (PBKDF2-only would fail this)", () => {
    // Every input is identical except the label. Under the old construction
    // these two strings were byte-for-byte equal.
    expect(labelA).not.toBe(labelB);
    expect(base64ToBinary(labelA).length).toBe(
      KEY_DERIVATION_CONFIG.OUTPUT_BITS / 8,
    );
    expect(base64ToBinary(labelB).length).toBe(
      KEY_DERIVATION_CONFIG.OUTPUT_BITS / 8,
    );
  });

  it("documents the defect: the old construction ignored `info` entirely", () => {
    // Reproduction of the parent-verified finding: same password + salt, the
    // 512-bit PBKDF2 output truncated at 32 bytes IS the 256-bit output, and
    // passing `info` changed nothing.
    const first32 = base64ToBinary(legacyVerify).slice(0, 32);
    expect(binaryToBase64(first32)).toBe(legacySession);
  });

  it("keeps the stored verifier independent of the session key", () => {
    expect(verifier).not.toBe(sessionKey);
    // Neither may appear inside the other as prefix, suffix or substring.
    expect(verifier.includes(sessionKey)).toBe(false);
    expect(sessionKey.includes(verifier)).toBe(false);
    // And the session key is not a truncation of the verifier (old scheme
    // made exactly this true).
    const verifierBytes = base64ToBinary(verifier);
    expect(binaryToBase64(verifierBytes.slice(0, 32))).not.toBe(sessionKey);
    expect(binaryToBase64(verifierBytes)).not.toBe(legacySession);
  });

  it("is deterministic for identical inputs and the same label", async () => {
    const again = await service.deriveKey(
      PASSPHRASE,
      salt,
      KEY_DERIVATION_CONFIG.ITERATIONS,
      KEY_DERIVATION_CONFIG.OUTPUT_BITS,
      "cybervault|alpha|v2",
    );
    expect(again).toBe(labelA);
    expect(await service.deriveVerificationHash(PASSPHRASE, salt)).toBe(
      verifier,
    );
  });

  it("changes the output when the per-vault salt changes", async () => {
    const otherSalt = service.generateSalt();
    const otherVerifier = await service.deriveVerificationHash(
      PASSPHRASE,
      otherSalt,
    );
    const otherSession = await service.deriveSessionKey(
      PASSPHRASE,
      otherSalt,
    );
    expect(otherVerifier).not.toBe(verifier);
    expect(otherSession).not.toBe(sessionKey);
    expect(otherVerifier.includes(sessionKey)).toBe(false);
    expect(otherSession.includes(verifier)).toBe(false);
  });

  it("emits scheme-tagged, correctly sized outputs", () => {
    // 256 bits => 32 bytes => 44 base64 chars (the old verifier was 64 bytes).
    expect(base64ToBinary(verifier)).toHaveLength(32);
    expect(base64ToBinary(sessionKey)).toHaveLength(32);
    expect(VERIFIER_SCHEME_PREFIX).toBe(`${KEY_DERIVATION_CONFIG.SCHEME}$`);
    // The service returns the bare verifier; the manager adds the prefix.
    expect(verifier.startsWith(VERIFIER_SCHEME_PREFIX)).toBe(false);
  });

  it("produces a session key usable as an AES-GCM-256 key", async () => {
    const raw = base64ToBinary(sessionKey);
    const key = await crypto.subtle.importKey(
      "raw",
      raw as unknown as BufferSource,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"],
    );
    expect(key).toBeDefined();
  });

  it("generates 32-byte cryptographically random salts", () => {
    const a = service.generateSalt();
    const b = service.generateSalt();
    expect(a).toHaveLength(32);
    expect(b).toHaveLength(32);
    expect(binaryToBase64(a)).not.toBe(binaryToBase64(b));
  });
});

describe("KeyDerivationService — export surface", () => {
  it("exposes a singleton instance", () => {
    expect(keyDerivationService).toBeInstanceOf(KeyDerivationService);
  });

  it("exports the scheme identifier used for versioning", () => {
    expect(KEY_DERIVATION_CONFIG.SCHEME).toBe("hkdf-sha256-v2");
  });
});
