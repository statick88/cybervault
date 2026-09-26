/**
 * TOTP Generator — RFC 6238 Time-based One-Time Password
 *
 * Generates TOTP codes for both personal and managed credentials.
 * For managed TOTP secrets, uses split-trust (VEK + ReleaseShare).
 *
 * Supports:
 * - SHA-1 (standard RFC 6238)
 * - SHA-256, SHA-512 (RFC 6238 extensions)
 * - 30-second time steps (standard)
 * - 6-digit output (standard)
 */

import { base64ToBinary, binaryToBase64 } from "../../shared/utils";
import { secureZero } from "../../infrastructure/crypto/secure-memory";

/** Convert Uint8Array to ArrayBuffer for Web Crypto API */
function toArrayBuffer(data: Uint8Array): ArrayBuffer {
  const buf = new ArrayBuffer(data.byteLength);
  new Uint8Array(buf).set(data);
  return buf;
}

/** TOTP Algorithm */
export type TOTPAlgorithm = "SHA-1" | "SHA-256" | "SHA-512";

/** TOTP Configuration */
export interface TOTPConfig {
  algorithm: TOTPAlgorithm;
  digits: number;        // 6 or 8
  period: number;        // time step in seconds (default 30)
}

/** Default TOTP configuration per RFC 6238 */
export const DEFAULT_TOTP_CONFIG: TOTPConfig = {
  algorithm: "SHA-1",
  digits: 6,
  period: 30,
};

/** TOTP Secret metadata */
export interface TOTPSecretMetadata {
  algorithm: TOTPAlgorithm;
  digits: number;
  period: number;
  label?: string;
  issuer?: string;
}

/**
 * Generate TOTP code from secret key
 *
 * @param secretKey - Base64 encoded secret key (decrypted TOTP secret)
 * @param config - TOTP configuration
 * @param timestamp - Optional timestamp (default: now)
 * @returns TOTP code as string (padded with leading zeros)
 */
export async function generateTOTP(
  secretKeyBase64: string,
  config: TOTPConfig = DEFAULT_TOTP_CONFIG,
  timestamp: number = Date.now(),
): Promise<string> {
  const secret = base64ToBinary(secretKeyBase64);

  try {
    // Calculate time counter (Unix time / period)
    const timeCounter = Math.floor(timestamp / 1000 / config.period);
    const counterBuffer = new ArrayBuffer(8);
    const counterView = new DataView(counterBuffer);
    counterView.setUint32(4, timeCounter, false); // Big-endian

    // Import secret key for HMAC
    const cryptoKey = await crypto.subtle.importKey(
      "raw",
      toArrayBuffer(secret),
      { name: "HMAC", hash: config.algorithm },
      false,
      ["sign"],
    );

    // Generate HMAC.
    // NOTE: subtle.sign takes the *primitive* name ("HMAC"). The hash is bound
    // to the imported key above — passing config.algorithm here is a TypeError
    // ("Unrecognized algorithm name") in every WebCrypto implementation.
    const hmac = await crypto.subtle.sign("HMAC", cryptoKey, counterBuffer);

    // Dynamic truncation per RFC 4226/RFC 6238
    const hmacBytes = new Uint8Array(hmac);
    const offset = hmacBytes[hmacBytes.length - 1] & 0x0f;
    const code =
      ((hmacBytes[offset] & 0x7f) << 24) |
      ((hmacBytes[offset + 1] & 0xff) << 16) |
      ((hmacBytes[offset + 2] & 0xff) << 8) |
      (hmacBytes[offset + 3] & 0xff);

    const modulo = Math.pow(10, config.digits);
    const otp = code % modulo;

    // Pad with leading zeros
    return otp.toString().padStart(config.digits, "0");
  } finally {
    secureZero(secret);
  }
}

/**
 * Generate multiple TOTP codes (current, previous, next) for clock skew tolerance
 */
export async function generateTOTPWindow(
  secretKeyBase64: string,
  config: TOTPConfig = DEFAULT_TOTP_CONFIG,
  timestamp: number = Date.now(),
  windowSize: number = 1,
): Promise<{ current: string; previous?: string; next?: string }> {
  const current = await generateTOTP(secretKeyBase64, config, timestamp);

  let previous: string | undefined;
  let next: string | undefined;

  if (windowSize > 0) {
    previous = await generateTOTP(
      secretKeyBase64,
      config,
      timestamp - config.period * 1000,
    );
    next = await generateTOTP(
      secretKeyBase64,
      config,
      timestamp + config.period * 1000,
    );
  }

  return { current, previous, next };
}

/**
 * Verify a TOTP code
 */
export async function verifyTOTP(
  secretKeyBase64: string,
  code: string,
  config: TOTPConfig = DEFAULT_TOTP_CONFIG,
  timestamp: number = Date.now(),
  windowSize: number = 1,
): Promise<boolean> {
  const { current, previous, next } = await generateTOTPWindow(
    secretKeyBase64,
    config,
    timestamp,
    windowSize,
  );

  return code === current || code === previous || code === next;
}

/**
 * Normalize a TOTP algorithm name to the canonical dashed form.
 *
 * The otpauth:// URI specification (and Google Authenticator) emit algorithm
 * names WITHOUT a dash — "SHA1", "SHA256", "SHA512" — while WebCrypto's
 * HMAC importKey requires the dashed form — "SHA-1", "SHA-256", "SHA-512".
 * Both spellings are accepted on input; only the canonical form is returned.
 *
 * @param raw - Algorithm name from a URI or user input (may be null/undefined)
 * @returns Canonical algorithm, or null when the value is not a supported HMAC
 */
export function normalizeTOTPAlgorithm(raw: string | null | undefined): TOTPAlgorithm | null {
  if (!raw) return "SHA-1"; // otpauth default when the parameter is absent

  const canonical = raw.toUpperCase().replace(/-/g, "");
  switch (canonical) {
    case "SHA1":
      return "SHA-1";
    case "SHA256":
      return "SHA-256";
    case "SHA512":
      return "SHA-512";
    default:
      return null;
  }
}

/**
 * Render an algorithm in the dashless otpauth:// URI spelling.
 */
function algorithmToURIParam(algorithm: TOTPAlgorithm): string {
  return algorithm.replace(/-/g, "");
}

/**
 * Parse otpauth:// URI (Google Authenticator format)
 * otpauth://totp/Label?secret=BASE32&issuer=Issuer&algorithm=SHA1&digits=6&period=30
 */
export function parseOTPAuthURI(uri: string): {
  secret: string; // Base32 encoded
  label: string;
  issuer?: string;
  algorithm: TOTPAlgorithm;
  digits: number;
  period: number;
} | null {
  try {
    const url = new URL(uri);
    if (url.protocol !== "otpauth:" || url.hostname !== "totp") {
      return null;
    }

    const secret = url.searchParams.get("secret");
    if (!secret) return null;

    const label = decodeURIComponent(url.pathname.slice(1)); // Remove leading /
    const issuer = url.searchParams.get("issuer") || undefined;

    const algorithm = normalizeTOTPAlgorithm(url.searchParams.get("algorithm"));
    if (!algorithm) return null;

    const digits = parseInt(url.searchParams.get("digits") || "6", 10);
    const period = parseInt(url.searchParams.get("period") || "30", 10);

    if (![6, 8].includes(digits)) return null;
    if (period <= 0) return null;

    return {
      secret: secret.replace(/\s/g, "").toUpperCase(), // Base32 without spaces
      label,
      issuer,
      algorithm,
      digits,
      period,
    };
  } catch {
    return null;
  }
}

/**
 * Convert Base32 secret to Base64 for internal storage
 * Base32 (RFC 4648) -> raw bytes -> Base64
 */
export function base32ToBase64(base32: string): string {
  // Remove padding
  const clean = base32.replace(/=/g, "");
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];

  for (const char of clean) {
    let val: number;
    if (char >= "A" && char <= "Z") val = char.charCodeAt(0) - 65;
    else if (char >= "2" && char <= "7") val = char.charCodeAt(0) - 24;
    else continue;

    value = (value << 5) | val;
    bits += 5;

    if (bits >= 8) {
      bytes.push((value >> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  return binaryToBase64(new Uint8Array(bytes));
}

/**
 * Convert Base64 secret to Base32 for otpauth URI
 */
export function base64ToBase32(base64: string): string {
  const bytes = base64ToBinary(base64);
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  let output = "";

  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;

    while (bits >= 5) {
      output += alphabet[(value >> (bits - 5)) & 0x1f];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += alphabet[(value << (5 - bits)) & 0x1f];
  }

  // Add padding
  while (output.length % 8 !== 0) {
    output += "=";
  }

  return output;
}

/**
 * Generate otpauth:// URI for QR code display
 */
export function generateOTPAuthURI(
  secretBase64: string,
  label: string,
  issuer?: string,
  config: TOTPConfig = DEFAULT_TOTP_CONFIG,
): string {
  const secretBase32 = base64ToBase32(secretBase64);
  const params = new URLSearchParams({
    secret: secretBase32,
    algorithm: algorithmToURIParam(config.algorithm),
    digits: config.digits.toString(),
    period: config.period.toString(),
  });

  if (issuer) {
    params.set("issuer", issuer);
  }

  const encodedLabel = encodeURIComponent(`${issuer ? `${issuer}:` : ""}${label}`);
  return `otpauth://totp/${encodedLabel}?${params.toString()}`;
}

/**
 * Lowercase a value and strip diacritics, so that "código", "codigo" and
 * "CÓDIGO" all collapse to the same token.
 *
 * Real-world forms are inconsistent about accents far more often than not, and
 * a missed match here means a legitimate 2FA field is silently not filled.
 */
function foldForMatch(value: string): string {
  return value
    .toLowerCase()
    .normalize("NFD")
    .replace(/\p{Diacritic}/gu, "");
}

/**
 * Detect TOTP input field in a form
 */
export function detectTOTPField(form: HTMLFormElement): HTMLInputElement | null {
  const inputs = Array.from(
    form.querySelectorAll<HTMLInputElement>(
      'input[type="text"], input[type="tel"], input[type="number"]',
    ),
  );

  for (const input of inputs) {
    const autocomplete = foldForMatch(input.getAttribute("autocomplete") || "");
    const name = foldForMatch(input.name || "");
    const id = foldForMatch(input.id || "");
    const placeholder = foldForMatch(input.placeholder || "");

    if (
      autocomplete === "one-time-code" ||
      name.includes("totp") ||
      name.includes("2fa") ||
      name.includes("mfa") ||
      name.includes("otp") ||
      name.includes("authenticator") ||
      id.includes("totp") ||
      id.includes("2fa") ||
      id.includes("mfa") ||
      id.includes("otp") ||
      placeholder.includes("totp") ||
      placeholder.includes("2fa") ||
      placeholder.includes("codigo") ||
      placeholder.includes("code")
    ) {
      return input;
    }
  }

  return null;
}

/**
 * Fill TOTP field with generated code
 */
export async function fillTOTPField(
  input: HTMLInputElement,
  secretKeyBase64: string,
  config: TOTPConfig = DEFAULT_TOTP_CONFIG,
): Promise<boolean> {
  try {
    const code = await generateTOTP(secretKeyBase64, config);
    fillField(input, code);
    return true;
  } catch {
    return false;
  }
}

/**
 * Fill field using native value setter (same as autocomplete.ts)
 */
function fillField(input: HTMLInputElement, value: string): void {
  const nativeSetter = Object.getOwnPropertyDescriptor(
    HTMLInputElement.prototype,
    "value",
  )?.set;

  if (nativeSetter) {
    nativeSetter.call(input, value);
  } else {
    input.value = value;
  }

  input.dispatchEvent(new Event("input", { bubbles: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
}