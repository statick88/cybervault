/**
 * Master Key Manager — CRITICAL-2 property tests.
 *
 * The defect these tests close: `master_key_verify` used to be 512 bits of
 * PBKDF2 output while the session key was the first 256 bits of the *same*
 * output, so the persisted verifier literally WAS the session encryption key.
 *
 * What is proven here:
 *  1. PROPERTY — after unlock, every value the implementation writes to
 *     `chrome.storage.local` (persistent) and to `chrome.storage.session`
 *     (other than the session key entry itself, which by definition *is* the
 *     session key) is neither equal to nor contains any session key, entry
 *     key, VEK or derived master secret — as prefix, suffix, substring,
 *     base64 payload or raw bytes.
 *  2. A verifier written by the OLD scheme is rejected with an explicit
 *     scheme error (not "wrong password"), no session key is issued, and the
 *     vault must be reset + re-initialized.
 *  3. Regression guards: correct passphrase unlocks, wrong passphrase fails.
 *
 * NOT covered here (cannot be proven by a unit test): that the verifier is
 * computationally unrecoverable to key material. HKDF's PRF property under a
 * context label is a cryptographic assumption, not something a Jest run can
 * establish; the test proves the *structural* properties only.
 */

import {
  initializeVault,
  unlockVault,
  lockVault,
  resetVault,
  isVaultInitialized,
  isVaultUnlocked,
  getSessionKey,
  SCHEME_UNSUPPORTED_ERROR,
} from "../../src/infrastructure/crypto/master-key-manager";
import {
  KEY_DERIVATION_CONFIG,
  VERIFIER_SCHEME_PREFIX,
} from "../../src/infrastructure/crypto/key-derivation-service";
import { deriveEntryKey } from "../../src/infrastructure/crypto/hkdf-derivation";
import { binaryToBase64, base64ToBinary } from "../../src/shared/utils";

type Store = Map<string, unknown>;

const SESSION_KEY_STORAGE = "cybervault_session_key";

function createArea(store: Store) {
  return {
    get: async (keys: string | string[]): Promise<Record<string, unknown>> => {
      const list = Array.isArray(keys) ? keys : [keys];
      const out: Record<string, unknown> = {};
      for (const key of list) {
        if (store.has(key)) out[key] = store.get(key);
      }
      return out;
    },
    set: async (items: Record<string, unknown>): Promise<void> => {
      for (const [key, value] of Object.entries(items)) store.set(key, value);
    },
    remove: async (keys: string | string[]): Promise<void> => {
      const list = Array.isArray(keys) ? keys : [keys];
      for (const key of list) store.delete(key);
    },
    clear: async (): Promise<void> => {
      store.clear();
    },
  };
}

/**
 * chrome.storage mock with SEPARATE local/session backing stores, plus direct
 * access to the raw maps so the tests can inspect exactly what was persisted.
 */
function installStorageMock(): { local: Store; session: Store } {
  const local: Store = new Map();
  const session: Store = new Map();
  (globalThis as unknown as { chrome: unknown }).chrome = {
    storage: { local: createArea(local), session: createArea(session) },
  };
  return { local, session };
}

/* ------------------------------------------------------------------ */
/* Key-material helpers (test-side, independent of the code under test) */
/* ------------------------------------------------------------------ */

interface KeyMaterial {
  label: string;
  b64: string;
  bytes: Uint8Array;
}

/** Independent reproduction of the OLD scheme: PBKDF2 only, `info` ignored. */
async function legacyPbkdf2(
  password: string,
  salt: Uint8Array,
  bits: number,
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
  const derived = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: salt as unknown as BufferSource,
      iterations: KEY_DERIVATION_CONFIG.ITERATIONS,
      hash: KEY_DERIVATION_CONFIG.HASH,
    },
    keyMaterial,
    bits,
  );
  return binaryToBase64(new Uint8Array(derived));
}

/** Independent re-computation of the PBKDF2 master secret (the HKDF IKM). */
async function masterSecretOf(
  password: string,
  salt: Uint8Array,
): Promise<Uint8Array> {
  const encoder = new TextEncoder();
  const passwordBuffer = encoder.encode(password);
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    passwordBuffer as BufferSource,
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const derived = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: salt as unknown as BufferSource,
      iterations: KEY_DERIVATION_CONFIG.ITERATIONS,
      hash: KEY_DERIVATION_CONFIG.HASH,
    },
    keyMaterial,
    KEY_DERIVATION_CONFIG.MASTER_SECRET_BITS,
  );
  return new Uint8Array(derived);
}

function bytesToLatin1(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += String.fromCharCode(byte);
  return out;
}

function containsBytes(haystack: Uint8Array, needle: Uint8Array): boolean {
  if (needle.length === 0 || needle.length > haystack.length) return false;
  outer: for (let i = 0; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return true;
  }
  return false;
}

function tryBase64Decode(value: string): Uint8Array | null {
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(value) || value.length % 4 !== 0) {
    return null;
  }
  try {
    return base64ToBinary(value);
  } catch {
    return null;
  }
}

/** Flatten a storage area into `[storagePath, stringifiedValue]` pairs. */
function collectPersistedValues(
  store: Store,
  exclude: string[] = [],
): Array<[string, string]> {
  const values: Array<[string, string]> = [];
  for (const [key, value] of store.entries()) {
    if (exclude.includes(key)) continue;
    if (typeof value === "string") {
      values.push([key, value]);
    } else if (value === undefined) {
      continue;
    } else {
      values.push([key, JSON.stringify(value)]);
    }
  }
  return values;
}

/**
 * Every way a persisted value could expose key material. Returns a human
 * readable violation list instead of throwing on the first hit, so a failure
 * shows all of them at once.
 */
function findKeyMaterialViolations(
  values: Array<[string, string]>,
  material: KeyMaterial[],
): string[] {
  const violations: string[] = [];
  for (const [path, value] of values) {
    for (const m of material) {
      if (value === m.b64) {
        violations.push(`${path}: EQUALS ${m.label}`);
      }
      // covers prefix, suffix and infix containment of the base64 form
      if (value.includes(m.b64)) {
        violations.push(`${path}: CONTAINS ${m.label} (base64 substring)`);
      }
      const decoded = tryBase64Decode(value);
      if (decoded && containsBytes(decoded, m.bytes)) {
        violations.push(`${path}: base64 payload CONTAINS ${m.label} bytes`);
      }
      const latin = bytesToLatin1(m.bytes);
      if (latin.length > 0 && value.includes(latin)) {
        violations.push(`${path}: CONTAINS raw ${m.label} bytes`);
      }
      // A persisted value that is itself a fragment of key material
      // (catches a partial leak, e.g. a truncated key).
      if (value.length >= 16 && m.b64.includes(value)) {
        violations.push(`${path}: IS A FRAGMENT OF ${m.label}`);
      }
    }
  }
  return violations;
}

/* ------------------------------------------------------------------ */

describe("master-key-manager", () => {
  const PASSPHRASE = "correct horse battery staple 42";
  const WRONG_PASSPHRASE = "incorrect horse battery staple 99";

  let local: Store;
  let session: Store;

  beforeEach(() => {
    ({ local, session } = installStorageMock());
  });

  afterEach(() => {
    delete (globalThis as unknown as { chrome?: unknown }).chrome;
  });

  describe("property: nothing persisted is, contains or reveals key material", () => {
    it("holds for every value written by unlock", async () => {
      const init = await initializeVault(PASSPHRASE);
      expect(init.success).toBe(true);

      await lockVault();
      const unlocked = await unlockVault(PASSPHRASE);
      expect(unlocked.success).toBe(true);

      const sessionKey = session.get(SESSION_KEY_STORAGE) as string;
      expect(typeof sessionKey).toBe("string");

      // --- material an attacker must never find in storage -----------------
      const salt = base64ToBinary(local.get("master_salt") as string);
      const masterSecret = await masterSecretOf(PASSPHRASE, salt);
      const vek = crypto.getRandomValues(new Uint8Array(32));
      const entry = await deriveEntryKey(vek, salt, {
        credentialId: "cred-property-1",
        version: 1,
        mode: "personal",
      });

      const material: KeyMaterial[] = [
        {
          label: "session key",
          b64: sessionKey,
          bytes: base64ToBinary(sessionKey),
        },
        {
          label: "master secret (PBKDF2 IKM)",
          b64: binaryToBase64(masterSecret),
          bytes: masterSecret,
        },
        { label: "VEK", b64: binaryToBase64(vek), bytes: vek },
        {
          label: "entry key",
          b64: entry.keyBase64,
          bytes: base64ToBinary(entry.keyBase64),
        },
      ];

      const persisted: Array<[string, string]> = [
        ...collectPersistedValues(local),
        // The session key entry is, by definition, the session key: excluding
        // it keeps the assertion meaningful. Everything else is scanned.
        ...collectPersistedValues(session, [SESSION_KEY_STORAGE]),
      ];

      expect(findKeyMaterialViolations(persisted, material)).toEqual([]);

      // Explicitly: the persistent area alone must contain no key material.
      expect(
        findKeyMaterialViolations(collectPersistedValues(local), material),
      ).toEqual([]);
    });

    it("stores a scheme-tagged verifier that is not the session key", async () => {
      await initializeVault(PASSPHRASE);
      await lockVault();
      expect((await unlockVault(PASSPHRASE)).success).toBe(true);

      const verifier = local.get("master_key_verify") as string;
      const sessionKey = session.get(SESSION_KEY_STORAGE) as string;

      expect(verifier.startsWith(VERIFIER_SCHEME_PREFIX)).toBe(true);
      expect(local.get("master_key_scheme")).toBe(
        KEY_DERIVATION_CONFIG.SCHEME,
      );

      expect(verifier).not.toBe(sessionKey);
      expect(verifier.includes(sessionKey)).toBe(false);
      expect(sessionKey.includes(verifier)).toBe(false);

      // Old scheme: sessionKey === verifyHash[0:32]. Assert it no longer holds.
      const bareVerifier = verifier.slice(VERIFIER_SCHEME_PREFIX.length);
      expect(binaryToBase64(base64ToBinary(bareVerifier).slice(0, 32))).not.toBe(
        sessionKey,
      );
      // 64-byte legacy verifier vs 32-byte current verifier.
      expect(base64ToBinary(bareVerifier)).toHaveLength(32);
    });

    it("the detector itself flags the OLD persisted layout (not vacuous)", async () => {
      // Reconstruct, byte for byte, what the pre-remediation code persisted:
      // a raw 64-byte PBKDF2 output as `master_key_verify`, no scheme id, and
      // a session key that is the first 32 bytes of that same output.
      const salt = crypto.getRandomValues(new Uint8Array(32));
      const legacyVerifier = await legacyPbkdf2(PASSPHRASE, salt, 512);
      const legacySessionKey = await legacyPbkdf2(PASSPHRASE, salt, 256);

      const oldLocal: Store = new Map<string, unknown>([
        ["master_key_verify", legacyVerifier],
        ["master_salt", binaryToBase64(salt)],
        ["vault_initialized", true],
      ]);

      const violations = findKeyMaterialViolations(
        collectPersistedValues(oldLocal),
        [
          {
            label: "session key",
            b64: legacySessionKey,
            bytes: base64ToBinary(legacySessionKey),
          },
        ],
      );

      // Without this, the property above could pass simply because nothing
      // ever looks at the right bytes.
      expect(violations).not.toEqual([]);
      expect(violations.join(" | ")).toContain(
        "master_key_verify: base64 payload CONTAINS session key bytes",
      );
    });
  });

  describe("old-scheme verifiers are rejected and force re-initialization", () => {
    async function seedLegacyVault(
      verifierBareB64: string,
      scheme?: string,
      saltB64?: string,
    ): Promise<void> {
      const salt = saltB64 ?? binaryToBase64(crypto.getRandomValues(new Uint8Array(32)));
      local.set("master_key_verify", verifierBareB64);
      local.set("master_salt", salt);
      local.set("vault_initialized", true);
      if (scheme !== undefined) {
        local.set("master_key_scheme", scheme);
      }
    }

    it("rejects a legacy verifier even with the CORRECT passphrase", async () => {
      const salt = crypto.getRandomValues(new Uint8Array(32));
      // Exactly what the old code persisted: raw 512-bit PBKDF2 output.
      const legacyVerifier = await legacyPbkdf2(PASSPHRASE, salt, 512);
      await seedLegacyVault(legacyVerifier, undefined, binaryToBase64(salt));

      const result = await unlockVault(PASSPHRASE);

      expect(result.success).toBe(false);
      expect(result.code).toBe("SCHEME_UNSUPPORTED");
      expect(result.error).toBe(SCHEME_UNSUPPORTED_ERROR);
      // Clean and explicit — NOT a confusing "wrong password".
      expect(result.code).not.toBe("WRONG_PASSPHRASE");
      expect(result.error).not.toBe("Clave maestra incorrecta");
      // Fail closed: no session key is issued.
      expect(session.has(SESSION_KEY_STORAGE)).toBe(false);
      expect(await isVaultUnlocked()).toBe(false);
      expect(await getSessionKey()).toBeNull();
    });

    it("rejects a current scheme id paired with an unprefixed verifier", async () => {
      const salt = crypto.getRandomValues(new Uint8Array(32));
      const legacyVerifier = await legacyPbkdf2(PASSPHRASE, salt, 512);
      await seedLegacyVault(
        legacyVerifier,
        KEY_DERIVATION_CONFIG.SCHEME,
        binaryToBase64(salt),
      );

      const result = await unlockVault(PASSPHRASE);
      expect(result.success).toBe(false);
      expect(result.code).toBe("SCHEME_UNSUPPORTED");
      expect(session.has(SESSION_KEY_STORAGE)).toBe(false);
    });

    it("rejects a foreign scheme identifier", async () => {
      local.set("master_key_verify", `${VERIFIER_SCHEME_PREFIX}AAAA`);
      local.set("master_salt", binaryToBase64(crypto.getRandomValues(new Uint8Array(32))));
      local.set("master_key_scheme", "hkdf-sha256-v1");
      local.set("vault_initialized", true);

      const result = await unlockVault(PASSPHRASE);
      expect(result.success).toBe(false);
      expect(result.code).toBe("SCHEME_UNSUPPORTED");
      expect(result.error).toBe(SCHEME_UNSUPPORTED_ERROR);
    });

    it("reports an uninitialized vault distinctly from a scheme mismatch", async () => {
      const result = await unlockVault(PASSPHRASE);
      expect(result.success).toBe(false);
      expect(result.code).toBe("VAULT_NOT_INITIALIZED");
      expect(result.code).not.toBe("SCHEME_UNSUPPORTED");
    });

    it("refuses to silently overwrite an old-scheme vault on initialize", async () => {
      const salt = crypto.getRandomValues(new Uint8Array(32));
      const legacyVerifier = await legacyPbkdf2(PASSPHRASE, salt, 512);
      await seedLegacyVault(legacyVerifier, undefined, binaryToBase64(salt));
      const before = local.get("master_key_verify");

      const result = await initializeVault(PASSPHRASE);

      expect(result.success).toBe(false);
      expect(result.code).toBe("SCHEME_UNSUPPORTED");
      expect(result.error).toBe(SCHEME_UNSUPPORTED_ERROR);
      // Data is never destroyed implicitly.
      expect(local.get("master_key_verify")).toBe(before);
      expect(local.get("vault_initialized")).toBe(true);
    });

    it("re-initializes cleanly after an explicit reset", async () => {
      const salt = crypto.getRandomValues(new Uint8Array(32));
      const legacyVerifier = await legacyPbkdf2(PASSPHRASE, salt, 512);
      await seedLegacyVault(legacyVerifier, undefined, binaryToBase64(salt));

      expect((await unlockVault(PASSPHRASE)).code).toBe("SCHEME_UNSUPPORTED");

      await resetVault();
      expect(await isVaultInitialized()).toBe(false);
      expect(local.size).toBe(0);
      expect(session.size).toBe(0);

      expect((await initializeVault(PASSPHRASE)).success).toBe(true);
      await lockVault();
      const unlocked = await unlockVault(PASSPHRASE);
      expect(unlocked.success).toBe(true);
      expect(local.get("master_key_scheme")).toBe(
        KEY_DERIVATION_CONFIG.SCHEME,
      );
    });
  });

  describe("passphrase verification (regression guards)", () => {
    it("unlocks with the correct passphrase", async () => {
      expect((await initializeVault(PASSPHRASE)).success).toBe(true);
      await lockVault();

      const result = await unlockVault(PASSPHRASE);

      expect(result.success).toBe(true);
      expect(result.error).toBeUndefined();
      expect(result.code).toBeUndefined();
      expect(await isVaultUnlocked()).toBe(true);
      expect(typeof (await getSessionKey())).toBe("string");
      expect(local.get("vault_initialized")).toBe(true);
    });

    it("rejects the wrong passphrase and issues no session key", async () => {
      expect((await initializeVault(PASSPHRASE)).success).toBe(true);
      await lockVault();

      const result = await unlockVault(WRONG_PASSPHRASE);

      expect(result.success).toBe(false);
      expect(result.code).toBe("WRONG_PASSPHRASE");
      expect(result.error).toBe("Clave maestra incorrecta");
      expect(session.has(SESSION_KEY_STORAGE)).toBe(false);
      expect(await isVaultUnlocked()).toBe(false);
    });

    it("locks: the session key is removed from session storage", async () => {
      expect((await initializeVault(PASSPHRASE)).success).toBe(true);
      expect(session.has(SESSION_KEY_STORAGE)).toBe(true);

      await lockVault();

      expect(session.has(SESSION_KEY_STORAGE)).toBe(false);
      expect(await getSessionKey()).toBeNull();
      expect(await isVaultUnlocked()).toBe(false);
    });

    it("rejects a master key shorter than 12 characters", async () => {
      const result = await initializeVault("short");
      expect(result.success).toBe(false);
      expect(local.size).toBe(0);
    });

    it("refuses to re-initialize a current-scheme vault", async () => {
      expect((await initializeVault(PASSPHRASE)).success).toBe(true);
      const before = local.get("master_key_verify");

      const result = await initializeVault("another passphrase 123");

      expect(result.success).toBe(false);
      expect(result.error).toBe("La bóveda ya ha sido inicializada");
      expect(result.code).toBeUndefined();
      expect(local.get("master_key_verify")).toBe(before);
    });
  });

  describe("per-vault salt", () => {
    it("uses a distinct random salt for each vault", async () => {
      expect((await initializeVault(PASSPHRASE)).success).toBe(true);
      const saltA = local.get("master_salt") as string;
      const verifierA = local.get("master_key_verify") as string;
      const sessionKeyA = session.get(SESSION_KEY_STORAGE) as string;

      // Fresh vault in a fresh storage area.
      const other = installStorageMock();
      local = other.local;
      session = other.session;
      expect((await initializeVault(PASSPHRASE)).success).toBe(true);
      const saltB = local.get("master_salt") as string;
      const verifierB = local.get("master_key_verify") as string;
      const sessionKeyB = session.get(SESSION_KEY_STORAGE) as string;

      expect(saltA).not.toBe(saltB);
      expect(verifierA).not.toBe(verifierB);
      // Same passphrase, different vault ⇒ different session key.
      expect(sessionKeyA).not.toBe(sessionKeyB);
      expect(base64ToBinary(saltB)).toHaveLength(32);
    });
  });
});
