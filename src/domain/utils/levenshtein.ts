/**
 * Levenshtein Similarity — Normalized edit distance
 *
 * Computes Levenshtein edit distance using a single-row DP buffer,
 * then normalizes to a similarity score in [0, 1].
 *
 * @module domain/utils/levenshtein
 */

const MAX_LENGTH = 100;

/**
 * Compute normalized Levenshtein similarity between two strings.
 *
 * Returns `1.0 - (distance / max(len(a), len(b)))`.
 *
 * - Both empty → 1.0
 * - One empty → 0.0
 * - Throws if either input exceeds 100 characters.
 */
export function levenshteinSimilarity(a: string, b: string): number {
  if (a.length > MAX_LENGTH || b.length > MAX_LENGTH) {
    throw new Error(
      `Input length exceeds hard limit (${MAX_LENGTH})`,
    );
  }

  const m = a.length;
  const n = b.length;

  if (m === 0) return n === 0 ? 1.0 : 0.0;
  if (n === 0) return 0.0;

  const maxLen = Math.max(m, n);

  // Single-row buffer DP
  const prev = new Array<number>(n + 1);
  const curr = new Array<number>(n + 1);

  for (let j = 0; j <= n; j++) prev[j] = j;

  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    const aChar = a[i - 1];

    for (let j = 1; j <= n; j++) {
      if (aChar === b[j - 1]) {
        curr[j] = prev[j - 1];
      } else {
        curr[j] = 1 + Math.min(prev[j], curr[j - 1], prev[j - 1]);
      }
    }

    // Swap rows
    for (let j = 0; j <= n; j++) prev[j] = curr[j];
  }

  const distance = prev[n];
  return 1.0 - distance / maxLen;
}
