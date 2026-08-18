/**
 * Unicode Confusables — Homograph attack detection
 *
 * Scans input for non-Latin script characters that visually resemble
 * Latin characters. Uses script range checks for fast detection and
 * the CONFUSABLE_LOOKUP map for detailed evidence.
 *
 * @module domain/utils/unicode-confusables
 */

import {
  CONFUSABLE_LOOKUP,
  SCRIPT_RANGES,
} from "../../infrastructure/security/unicode-confusables";

/** Evidence of a confusable character found in the input. */
export interface ConfusableEvidence {
  /** The character that was detected */
  char: string;
  /** Unicode code point (decimal) */
  codePoint: number;
  /** Script name (e.g., "Cyrillic", "Greek") */
  script: string;
  /** The Latin character it resembles */
  lookalike: string;
  /** Category of confusable */
  category: "homograph" | "zerowidth" | "combining" | "fullwidth";
  /** Index position in the original input */
  index: number;
}

/**
 * Zero-width / invisible characters to strip.
 * U+200B ZERO WIDTH SPACE
 * U+200C ZERO WIDTH NON-JOINER
 * U+200D ZERO WIDTH JOINER
 * U+FEFF BOM / ZERO WIDTH NO-BREAK SPACE
 * U+2060 WORD JOINER
 * U+00AD SOFT HYPHEN
 */
const ZERO_WIDTH_RE =
  /[\u200B\u200C\u200D\uFEFF\u2060\u00AD]/g;

/**
 * Strip zero-width and invisible characters from a string.
 */
export function stripZeroWidth(input: string): string {
  return input.replace(ZERO_WIDTH_RE, "");
}

/**
 * Detect confusable characters in the input.
 *
 * Returns evidence entries for each character that belongs to a non-Latin
 * script capable of homograph attacks (Cyrillic, Greek, Armenian, Hebrew,
 * Arabic, Fullwidth, Latin Extended, MathBold).
 */
export function detectConfusables(input: string): ConfusableEvidence[] {
  const results: ConfusableEvidence[] = [];

  for (let i = 0; i < input.length; i++) {
    const ch = input[i];
    const cp = ch.codePointAt(0);
    if (cp === undefined) continue;

    // Check CONFUSABLE_LOOKUP first (most precise)
    const known = CONFUSABLE_LOOKUP.get(ch);
    if (known) {
      results.push({
        char: known.char,
        codePoint: known.codePoint,
        script: known.script,
        lookalike: known.lookalike,
        category: known.category,
        index: i,
      });
      continue;
    }

    // Fall back to SCRIPT_RANGES for range-based detection
    for (const range of SCRIPT_RANGES) {
      if (cp >= range.start && cp <= range.end) {
        results.push({
          char: ch,
          codePoint: cp,
          script: range.script,
          lookalike: "",
          category: "homograph",
          index: i,
        });
        break;
      }
    }
  }

  return results;
}
