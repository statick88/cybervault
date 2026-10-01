/**
 * TOTP Generator Tests — RFC 6238 Compliance
 *
 * Ground truth is the RFC 6238 Appendix B test-vector table (the seed is the
 * ASCII string "12345678901234567890", truncated/extended per algorithm).
 * These vectors were independently cross-checked against a reference HMAC
 * implementation, so a PASS here means the implementation agrees with the RFC
 * rather than merely agreeing with itself.
 */

import {
  generateTOTP,
  verifyTOTP,
  generateTOTPWindow,
  parseOTPAuthURI,
  normalizeTOTPAlgorithm,
  base32ToBase64,
  base64ToBase32,
  generateOTPAuthURI,
  DEFAULT_TOTP_CONFIG,
  type TOTPAlgorithm,
} from "../../src/ui/content-scripts/totp-generator";
import { binaryToBase64 } from "../../src/shared/utils";

/* ------------------------------------------------------------------ */
/*  RFC 6238 Appendix B seeds (ASCII)                                  */
/* ------------------------------------------------------------------ */

const SEED_SHA1 = new TextEncoder().encode("12345678901234567890");
const SEED_SHA256 = new TextEncoder().encode("12345678901234567890123456789012");
const SEED_SHA512 = new TextEncoder().encode(
  "1234567890123456789012345678901234567890123456789012345678901234",
);

const b64 = (bytes: Uint8Array): string => binaryToBase64(bytes);

/** RFC 6238 Appendix B: [unixTime, sha1(8), sha256(8), sha512(8)] */
const RFC_6238_VECTORS: Array<[number, string, string, string]> = [
  [59, "94287082", "46119246", "90693936"],
  [1111111109, "07081804", "68084774", "25091201"],
  [1111111111, "14050471", "67062674", "99943326"],
  [1234567890, "89005924", "91819424", "93441116"],
  [2000000000, "69279037", "90698825", "38618901"],
  [20000000000, "65353130", "77737706", "47863826"],
];

describe("TOTP Generator — RFC 6238", () => {
  describe("RFC 6238 Appendix B test vectors", () => {
    const config = (algorithm: TOTPAlgorithm) => ({
      algorithm,
      digits: 8,
      period: 30,
    });

    it.each(RFC_6238_VECTORS)(
      "T=%i matches the RFC vector for every algorithm",
      async (unixTime, sha1, sha256, sha512) => {
        const timestamp = unixTime * 1000;

        await expect(
          generateTOTP(b64(SEED_SHA1), config("SHA-1"), timestamp),
        ).resolves.toBe(sha1);
        await expect(
          generateTOTP(b64(SEED_SHA256), config("SHA-256"), timestamp),
        ).resolves.toBe(sha256);
        await expect(
          generateTOTP(b64(SEED_SHA512), config("SHA-512"), timestamp),
        ).resolves.toBe(sha512);
      },
    );
  });

  describe("generateTOTP", () => {
    it("defaults to 6 digits, SHA-1, 30s period", () => {
      expect(DEFAULT_TOTP_CONFIG).toEqual({
        algorithm: "SHA-1",
        digits: 6,
        period: 30,
      });
    });

    it("always emits exactly the configured digit count", async () => {
      const secret = b64(SEED_SHA1);
      const six = await generateTOTP(secret, { ...DEFAULT_TOTP_CONFIG, digits: 6 });
      const eight = await generateTOTP(secret, { ...DEFAULT_TOTP_CONFIG, digits: 8 });

      expect(six).toMatch(/^\d{6}$/);
      expect(eight).toMatch(/^\d{8}$/);
    });

    it("pads with leading zeros rather than truncating", async () => {
      // RFC vector 1111111109 -> "07081804": the leading zero must survive.
      const code = await generateTOTP(
        b64(SEED_SHA1),
        { algorithm: "SHA-1", digits: 8, period: 30 },
        1111111109 * 1000,
      );
      expect(code).toBe("07081804");
      expect(code.startsWith("0")).toBe(true);
    });

    it("6-digit output is the low 6 digits of the 8-digit output", async () => {
      // Dynamic truncation then mod: mod 10^6 == last 6 digits of mod 10^8.
      const secret = b64(SEED_SHA256);
      const timestamp = 1234567890 * 1000;
      const eight = await generateTOTP(secret, { algorithm: "SHA-256", digits: 8, period: 30 }, timestamp);
      const six = await generateTOTP(secret, { algorithm: "SHA-256", digits: 6, period: 30 }, timestamp);

      expect(six).toBe(eight.slice(-6));
    });

    it("is deterministic for a fixed timestamp", async () => {
      const secret = b64(SEED_SHA1);
      const t = 1111111111 * 1000;
      const a = await generateTOTP(secret, undefined, t);
      const b = await generateTOTP(secret, undefined, t);
      expect(a).toBe(b);
    });

    it("changes exactly at the period boundary", async () => {
      const secret = b64(SEED_SHA1);
      const base = 999_999_900_000; // exactly divisible by the 30s period
      expect(base % 30_000).toBe(0);

      const lastMsOfWindow = base + 29_999;
      const firstMsOfNext = base + 30_000;

      const a = await generateTOTP(secret, undefined, lastMsOfWindow);
      const b = await generateTOTP(secret, undefined, firstMsOfNext);

      expect(a).not.toBe(b);
    });

    it("is stable within a single time window", async () => {
      const secret = b64(SEED_SHA1);
      const base = 999_999_900_000; // exactly divisible by the 30s period
      const a = await generateTOTP(secret, undefined, base);
      const b = await generateTOTP(secret, undefined, base + 29_999);
      expect(a).toBe(b);
    });
  });

  describe("verifyTOTP", () => {
    const secret = b64(SEED_SHA1);
    const timestamp = 1_700_000_000_000;

    it("accepts the current code", async () => {
      const code = await generateTOTP(secret, undefined, timestamp);
      await expect(verifyTOTP(secret, code, undefined, timestamp, 0)).resolves.toBe(true);
    });

    it("accepts the previous and next window when skew is allowed", async () => {
      const previous = await generateTOTP(secret, undefined, timestamp - 30_000);
      const next = await generateTOTP(secret, undefined, timestamp + 30_000);

      await expect(verifyTOTP(secret, previous, undefined, timestamp, 1)).resolves.toBe(true);
      await expect(verifyTOTP(secret, next, undefined, timestamp, 1)).resolves.toBe(true);
    });

    it("rejects those same codes when skew is disabled", async () => {
      const previous = await generateTOTP(secret, undefined, timestamp - 30_000);
      const next = await generateTOTP(secret, undefined, timestamp + 30_000);

      await expect(verifyTOTP(secret, previous, undefined, timestamp, 0)).resolves.toBe(false);
      await expect(verifyTOTP(secret, next, undefined, timestamp, 0)).resolves.toBe(false);
    });

    it("rejects a code from outside the window", async () => {
      const stale = await generateTOTP(secret, undefined, timestamp - 300_000);
      await expect(verifyTOTP(secret, stale, undefined, timestamp, 1)).resolves.toBe(false);
    });

    it("rejects a wrong code", async () => {
      const code = await generateTOTP(secret, undefined, timestamp);
      const wrong = code === "000000" ? "111111" : "000000";
      await expect(verifyTOTP(secret, wrong, undefined, timestamp, 1)).resolves.toBe(false);
    });

    it("does not accept a code generated from a different secret", async () => {
      const other = b64(new TextEncoder().encode("09876543210987654321"));
      const foreignCode = await generateTOTP(other, undefined, timestamp);
      await expect(verifyTOTP(secret, foreignCode, undefined, timestamp, 1)).resolves.toBe(false);
    });
  });

  describe("generateTOTPWindow", () => {
    it("returns current, previous and next codes", async () => {
      const { current, previous, next } = await generateTOTPWindow(b64(SEED_SHA1));
      expect(current).toMatch(/^\d{6}$/);
      expect(previous).toMatch(/^\d{6}$/);
      expect(next).toMatch(/^\d{6}$/);
    });

    it("omits neighbours when the window is zero", async () => {
      const { current, previous, next } = await generateTOTPWindow(
        b64(SEED_SHA1),
        DEFAULT_TOTP_CONFIG,
        Date.now(),
        0,
      );
      expect(current).toMatch(/^\d{6}$/);
      expect(previous).toBeUndefined();
      expect(next).toBeUndefined();
    });

    it("neighbours are the adjacent time steps", async () => {
      const secret = b64(SEED_SHA1);
      const t = 1_700_000_000_000;
      const { previous, next } = await generateTOTPWindow(secret, DEFAULT_TOTP_CONFIG, t, 1);

      expect(previous).toBe(await generateTOTP(secret, DEFAULT_TOTP_CONFIG, t - 30_000));
      expect(next).toBe(await generateTOTP(secret, DEFAULT_TOTP_CONFIG, t + 30_000));
    });
  });

  describe("normalizeTOTPAlgorithm", () => {
    it("accepts the dashless otpauth spelling", () => {
      expect(normalizeTOTPAlgorithm("SHA1")).toBe("SHA-1");
      expect(normalizeTOTPAlgorithm("SHA256")).toBe("SHA-256");
      expect(normalizeTOTPAlgorithm("SHA512")).toBe("SHA-512");
    });

    it("accepts the dashed spelling", () => {
      expect(normalizeTOTPAlgorithm("SHA-1")).toBe("SHA-1");
      expect(normalizeTOTPAlgorithm("SHA-256")).toBe("SHA-256");
      expect(normalizeTOTPAlgorithm("SHA-512")).toBe("SHA-512");
    });

    it("is case insensitive", () => {
      expect(normalizeTOTPAlgorithm("sha1")).toBe("SHA-1");
      expect(normalizeTOTPAlgorithm("sha-256")).toBe("SHA-256");
    });

    it("defaults to SHA-1 when absent", () => {
      expect(normalizeTOTPAlgorithm(null)).toBe("SHA-1");
      expect(normalizeTOTPAlgorithm(undefined)).toBe("SHA-1");
      expect(normalizeTOTPAlgorithm("")).toBe("SHA-1");
    });

    it("rejects anything that is not an HMAC", () => {
      expect(normalizeTOTPAlgorithm("MD5")).toBeNull();
      expect(normalizeTOTPAlgorithm("SHA-384")).toBeNull();
    });
  });

  describe("parseOTPAuthURI", () => {
    it("parses a standard otpauth URI", () => {
      const parsed = parseOTPAuthURI(
        "otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA1&digits=6&period=30",
      );
      expect(parsed).not.toBeNull();
      expect(parsed!.secret).toBe("JBSWY3DPEHPK3PXP");
      expect(parsed!.label).toBe("Example:user@example.com");
      expect(parsed!.issuer).toBe("Example");
      expect(parsed!.algorithm).toBe("SHA-1");
      expect(parsed!.digits).toBe(6);
      expect(parsed!.period).toBe(30);
    });

    it("parses a URI without an issuer", () => {
      const parsed = parseOTPAuthURI("otpauth://totp/user@example.com?secret=JBSWY3DPEHPK3PXP");
      expect(parsed).not.toBeNull();
      expect(parsed!.issuer).toBeUndefined();
      expect(parsed!.algorithm).toBe("SHA-1");
    });

    it("parses SHA-256 and SHA-512", () => {
      expect(
        parseOTPAuthURI("otpauth://totp/X?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=60")!
          .algorithm,
      ).toBe("SHA-256");
      expect(
        parseOTPAuthURI("otpauth://totp/X?secret=JBSWY3DPEHPK3PXP&algorithm=SHA512")!.algorithm,
      ).toBe("SHA-512");
    });

    it("strips whitespace and uppercases the secret", () => {
      const parsed = parseOTPAuthURI("otpauth://totp/X?secret=jbsw%20y3dp%20ehpk3pxp");
      expect(parsed!.secret).toBe("JBSWY3DPEHPK3PXP");
    });

    it("rejects a non-otpauth scheme", () => {
      expect(parseOTPAuthURI("https://example.com/totp?secret=JBSWY3DPEHPK3PXP")).toBeNull();
    });

    it("rejects a non-totp type", () => {
      expect(parseOTPAuthURI("otpauth://hotp/X?secret=JBSWY3DPEHPK3PXP")).toBeNull();
    });

    it("rejects a missing secret", () => {
      expect(parseOTPAuthURI("otpauth://totp/X?issuer=Example")).toBeNull();
    });

    it("rejects an unsupported algorithm", () => {
      expect(parseOTPAuthURI("otpauth://totp/X?secret=JBSWY3DPEHPK3PXP&algorithm=MD5")).toBeNull();
    });

    it("rejects an unsupported digit count", () => {
      expect(parseOTPAuthURI("otpauth://totp/X?secret=JBSWY3DPEHPK3PXP&digits=7")).toBeNull();
    });

    it("rejects a non-positive period", () => {
      expect(parseOTPAuthURI("otpauth://totp/X?secret=JBSWY3DPEHPK3PXP&period=0")).toBeNull();
    });
  });

  describe("Base32 / Base64 conversion", () => {
    it("round-trips without loss", () => {
      const original = b64(SEED_SHA1);
      const asBase32 = base64ToBase32(original);
      expect(base32ToBase64(asBase32)).toBe(original);
    });

    it("decodes the canonical authenticator example", () => {
      // "Hello!\xde\xad\xbe\xef" — 16 Base32 chars decode to 10 bytes.
      const decoded = base32ToBase64("JBSWY3DPEHPK3PXP");
      expect(decoded).toBe("SGVsbG8h3q2+7w==");
      expect(base64ToBinaryLength(decoded)).toBe(10);
    });

    it("emits spec-legal Base32 with padding", () => {
      const encoded = base64ToBase32(b64(SEED_SHA1));
      expect(encoded).toMatch(/^[A-Z2-7]+=*$/);
      expect(encoded.length % 8).toBe(0);
    });

    it("ignores characters outside the Base32 alphabet", () => {
      expect(base32ToBase64("JBSWY3DPEHPK3PXP")).toBe(
        base32ToBase64("JBSW-Y3DP EHPK3PXP"),
      );
    });
  });

  describe("generateOTPAuthURI", () => {
    it("emits the dashless algorithm spelling required by authenticator apps", () => {
      const uri = generateOTPAuthURI(b64(SEED_SHA1), "user@example.com", "Example");
      expect(uri).toContain("algorithm=SHA1");
      expect(uri).not.toContain("algorithm=SHA-1");
    });

    it("round-trips through the parser", () => {
      const secret = b64(SEED_SHA1);
      const uri = generateOTPAuthURI(secret, "user@example.com", "Example", {
        algorithm: "SHA-256",
        digits: 8,
        period: 60,
      });

      const parsed = parseOTPAuthURI(uri)!;
      expect(parsed).not.toBeNull();
      expect(parsed.algorithm).toBe("SHA-256");
      expect(parsed.digits).toBe(8);
      expect(parsed.period).toBe(60);
      expect(parsed.issuer).toBe("Example");
      expect(base32ToBase64(parsed.secret)).toBe(secret);
    });

    it("omits the issuer parameter when not supplied", () => {
      const uri = generateOTPAuthURI(b64(SEED_SHA1), "user@example.com");
      expect(uri).not.toContain("issuer=");
    });
  });
});

/** Local helper so the byte-length assertion stays readable. */
function base64ToBinaryLength(base64: string): number {
  return Buffer.from(base64, "base64").length;
}
