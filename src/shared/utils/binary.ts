/**
 * Secure binary utilities for base64 encoding/decoding
 * Replaces unsafe direct btoa/atob usage throughout the project
 */

/**
 * Converts Uint8Array to base64 string
 * Uses btoa with String.fromCharCode which is safe for binary data (0-255)
 */
export function binaryToBase64(data: Uint8Array): string {
  let binary = "";
  const len = data.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(data[i]);
  }
  return btoa(binary);
}

/**
 * Converts base64 string to Uint8Array
 * Uses atob which is safe for pure base64 strings
 */
export function base64ToBinary(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Encodes a string to base64
 * Convenience wrapper around binaryToBase64
 */
export function stringToBase64(str: string): string {
  return binaryToBase64(new TextEncoder().encode(str));
}

/**
 * Decodes a base64 string to string
 * Convenience wrapper around base64ToBinary
 */
export function base64ToString(base64: string): string {
  return new TextDecoder().decode(base64ToBinary(base64));
}
