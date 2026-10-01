/**
 * S2 batch 3 — `src/infrastructure/crypto/crypto-service.ts` unit tests.
 *
 * The service is pure WebCrypto plumbing (ECDSA P-256 keypairs, AES-GCM-256
 * with a 600k-iteration PBKDF2/SHA-512 key schedule, SHA-256 hashing), so the
 * suite exercises the REAL primitives rather than mocking them — a mocked
 * `crypto.subtle` would prove nothing about the constructions.
 *
 * What is pinned:
 *   - the wire format `encrypt` produces (`salt|iv|ciphertext`, base64) and
 *     that it carries no key material;
 *   - round-trip correctness AND its negatives: a wrong key, a tampered
 *     ciphertext and a truncated payload must all fail as a DECRYPTION
 *     FAILURE, never as a raw library error, because the class documents a
 *     generic error message precisely so callers cannot build an oracle;
 *   - signature verification rejects tampered data, a foreign public key and
 *     malformed key/signature input, always as `false` rather than throwing;
 *   - the derived-key output is deterministic for a given salt and iteration
 *     count, and changes with either.
 *
 * No live database, no Docker, no network, no browser.
 */

import {
  CryptoService,
} from "../../src/infrastructure/crypto/crypto-service";
import { base64ToBinary, binaryToBase64 } from "../../src/shared/utils";

const MASTER_KEY = "correct horse battery staple 42";
const PLAINTEXT = "hola-mundo-contrasena-secreta";

let service: CryptoService;

beforeEach(() => {
  service = new CryptoService();
});

/* ========================================================================== */
/* Instrumentation — the reason this file exists                               */
/* ========================================================================== */

describe("CryptoService — instrumentation", () => {
  it("loads and instruments the module under test", () => {
    expect(typeof CryptoService).toBe("function");
    expect(CryptoService.name).toBe("CryptoService");
    expect(service).toBeInstanceOf(CryptoService);
  });
});

/* ========================================================================== */
/* Key pairs                                                                   */
/* ========================================================================== */

describe("CryptoService.generateKeyPair", () => {
  it("emits both halves as JSON Web Keys on P-256", async () => {
    const { publicKey, privateKey } = await service.generateKeyPair();

    const pub = JSON.parse(publicKey) as JsonWebKey;
    const priv = JSON.parse(privateKey) as JsonWebKey;

    expect(pub.kty).toBe("EC");
    expect(pub.crv).toBe("P-256");
    expect(typeof pub.x).toBe("string");
    expect(typeof pub.y).toBe("string");
    expect(pub.d).toBeUndefined(); // the public half carries no private scalar

    expect(priv.kty).toBe("EC");
    expect(priv.crv).toBe("P-256");
    expect(typeof priv.d).toBe("string");
  });

  it("generates a fresh pair every call", async () => {
    const a = await service.generateKeyPair();
    const b = await service.generateKeyPair();

    expect(a.publicKey).not.toBe(b.publicKey);
    expect(a.privateKey).not.toBe(b.privateKey);
  });
});

/* ========================================================================== */
/* Sign / verify                                                               */
/* ========================================================================== */

describe("CryptoService sign/verify", () => {
  it("verifies a signature produced from the matching key pair", async () => {
    const { publicKey, privateKey } = await service.generateKeyPair();

    const signature = await service.sign(PLAINTEXT, privateKey);

    expect(base64ToBinary(signature)).toHaveLength(64); // r || s, P-256
    await expect(service.verify(PLAINTEXT, signature, publicKey)).resolves.toBe(
      true,
    );
  });

  it("rejects tampered DATA", async () => {
    const { publicKey, privateKey } = await service.generateKeyPair();
    const signature = await service.sign(PLAINTEXT, privateKey);

    await expect(
      service.verify(`${PLAINTEXT}!`, signature, publicKey),
    ).resolves.toBe(false);
  });

  it("rejects a tampered SIGNATURE", async () => {
    const { publicKey, privateKey } = await service.generateKeyPair();
    const signature = await service.sign(PLAINTEXT, privateKey);

    const bytes = base64ToBinary(signature);
    bytes[0] ^= 0xff;

    await expect(
      service.verify(PLAINTEXT, binaryToBase64(bytes), publicKey),
    ).resolves.toBe(false);
  });

  it("rejects a signature verified against a DIFFERENT key pair", async () => {
    const { privateKey } = await service.generateKeyPair();
    const other = await service.generateKeyPair();
    const signature = await service.sign(PLAINTEXT, privateKey);

    await expect(
      service.verify(PLAINTEXT, signature, other.publicKey),
    ).resolves.toBe(false);
  });

  it("returns false — never throws — for a malformed public key", async () => {
    const { privateKey } = await service.generateKeyPair();
    const signature = await service.sign(PLAINTEXT, privateKey);

    await expect(
      service.verify(PLAINTEXT, signature, "not json at all"),
    ).resolves.toBe(false);
    await expect(
      service.verify(PLAINTEXT, signature, JSON.stringify({ kty: "oct" })),
    ).resolves.toBe(false);
  });

  it("returns false — never throws — for a malformed signature", async () => {
    const { publicKey, privateKey } = await service.generateKeyPair();
    await service.sign(PLAINTEXT, privateKey);

    await expect(
      service.verify(PLAINTEXT, "!!not base64!!", publicKey),
    ).resolves.toBe(false);
    await expect(
      service.verify(PLAINTEXT, binaryToBase64(new Uint8Array(3)), publicKey),
    ).resolves.toBe(false);
  });

  it("throws when the private key is not a JWK — the caller supplied the input", async () => {
    await expect(service.sign(PLAINTEXT, "nope")).rejects.toThrow();
  });
});

/* ========================================================================== */
/* Encrypt / decrypt                                                           */
/* ========================================================================== */

describe("CryptoService encrypt/decrypt", () => {
  it("round-trips the plaintext", async () => {
    const encrypted = await service.encrypt(PLAINTEXT, MASTER_KEY);

    expect(typeof encrypted).toBe("string");
    await expect(service.decrypt(encrypted, MASTER_KEY)).resolves.toBe(
      PLAINTEXT,
    );
  });

  it("produces salt(16) | iv(12) | ciphertext+tag and embeds NO key material", async () => {
    const encrypted = await service.encrypt(PLAINTEXT, MASTER_KEY);
    const combined = base64ToBinary(encrypted);

    expect(combined).toHaveLength(16 + 12 + PLAINTEXT.length + 16);
    // The master key must never appear in the payload.
    expect(encrypted).not.toContain(MASTER_KEY);
    expect(Buffer.from(combined).includes(Buffer.from(MASTER_KEY))).toBe(false);
  });

  it("salts every encryption — the same plaintext under the same key differs", async () => {
    const a = await service.encrypt(PLAINTEXT, MASTER_KEY);
    const b = await service.encrypt(PLAINTEXT, MASTER_KEY);

    expect(a).not.toBe(b);
    await expect(service.decrypt(a, MASTER_KEY)).resolves.toBe(PLAINTEXT);
    await expect(service.decrypt(b, MASTER_KEY)).resolves.toBe(PLAINTEXT);
  });

  it("refuses a WRONG key with the documented generic message", async () => {
    const encrypted = await service.encrypt(PLAINTEXT, MASTER_KEY);

    await expect(
      service.decrypt(encrypted, "a completely different passphrase"),
    ).rejects.toThrow("Decryption failed");
  });

  it("refuses a TAMPERED ciphertext with the same generic message", async () => {
    const encrypted = await service.encrypt(PLAINTEXT, MASTER_KEY);
    const combined = base64ToBinary(encrypted);
    combined[combined.length - 1] ^= 0xff; // flip a bit inside the GCM tag

    await expect(
      service.decrypt(binaryToBase64(combined), MASTER_KEY),
    ).rejects.toThrow("Decryption failed");
  });

  it("refuses a TRUNCATED payload with the same generic message", async () => {
    const encrypted = await service.encrypt(PLAINTEXT, MASTER_KEY);
    const combined = base64ToBinary(encrypted);

    await expect(
      service.decrypt(binaryToBase64(combined.slice(0, 20)), MASTER_KEY),
    ).rejects.toThrow("Decryption failed");
  });

  it("refuses payload input that is not base64 at all", async () => {
    // The class documents a generic "Decryption failed" so a caller cannot
    // distinguish malformed input from a wrong key. Anything else escaping
    // here would be a distinguishable error channel.
    await expect(
      service.decrypt("!!! not base64 !!!", MASTER_KEY),
    ).rejects.toThrow("Decryption failed");
  });

  it("never returns the plaintext when decryption fails", async () => {
    const encrypted = await service.encrypt(PLAINTEXT, MASTER_KEY);
    const combined = base64ToBinary(encrypted);
    combined[20] ^= 0xff; // corrupt the ciphertext itself

    let returned: string | null = null;
    let thrown: Error | null = null;
    try {
      returned = await service.decrypt(binaryToBase64(combined), MASTER_KEY);
    } catch (error) {
      thrown = error as Error;
    }

    expect(thrown).not.toBeNull();
    expect(returned).not.toBe(PLAINTEXT);
  });
});

/* ========================================================================== */
/* hash / deriveKey / generateSalt                                             */
/* ========================================================================== */

describe("CryptoService.hash", () => {
  it("returns the SHA-256 digest as lowercase hex", async () => {
    const hash = await service.hash("abc");

    // SHA-256("abc"), the published vector.
    expect(hash).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
    expect(hash).toHaveLength(64);
    expect(hash).toMatch(/^[0-9a-f]+$/);
  });

  it("is deterministic and distinguishes different inputs", async () => {
    expect(await service.hash("a")).toBe(await service.hash("a"));
    expect(await service.hash("a")).not.toBe(await service.hash("b"));
    expect(await service.hash("")).toHaveLength(64);
  });
});

describe("CryptoService.deriveKey", () => {
  const SALT = binaryToBase64(new Uint8Array(16).fill(1));

  it("derives a 32-byte key deterministically for a given salt", async () => {
    const one = await service.deriveKey("pass", SALT, 1000);
    const two = await service.deriveKey("pass", SALT, 1000);

    expect(one).toBe(two);
    expect(base64ToBinary(one)).toHaveLength(32);
  });

  it("changes with the salt", async () => {
    const other = binaryToBase64(new Uint8Array(16).fill(2));

    expect(await service.deriveKey("pass", SALT, 1000)).not.toBe(
      await service.deriveKey("pass", other, 1000),
    );
  });

  it("changes with the iteration count", async () => {
    expect(await service.deriveKey("pass", SALT, 1000)).not.toBe(
      await service.deriveKey("pass", SALT, 1001),
    );
  });

  it("defaults to the configured 600k iterations", async () => {
    const explicit = await service.deriveKey("pass", SALT, 600000);
    const defaulted = await service.deriveKey("pass", SALT);

    expect(defaulted).toBe(explicit);
  });
});

describe("CryptoService.generateSalt", () => {
  it("emits a 16-byte (128-bit) salt in base64", async () => {
    const salt = await service.generateSalt();

    expect(base64ToBinary(salt)).toHaveLength(16);
  });

  it("is random — two calls never collide", async () => {
    const salts = await Promise.all([
      service.generateSalt(),
      service.generateSalt(),
      service.generateSalt(),
    ]);

    expect(new Set(salts).size).toBe(salts.length);
  });
});
