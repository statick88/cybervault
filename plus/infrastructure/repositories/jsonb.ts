/**
 * `jsonb` column decoding — Plus Infrastructure
 *
 * PostgreSQL `jsonb` columns arrive from `pg` ALREADY parsed: the driver
 * installs a type parser for OID 3802 that turns the wire text into a JS value
 * before any repository sees it. Calling `JSON.parse()` on that result is a
 * double parse, and it throws:
 *
 *     JSON.parse({a:1})  ->  SyntaxError: "[object Object]" is not valid JSON
 *
 * So every read of a `jsonb` column must use this helper rather than
 * `JSON.parse`. It stays tolerant of a raw string, because that is what the
 * column looks like if a query is issued with a driver configuration that
 * disables the type parser, and because hand-written SQL may cast to text.
 */

/** Decode a `jsonb` column that may arrive already parsed, as a string, or as SQL NULL. */
export function parseJsonbColumn<T = Record<string, unknown>>(value: unknown): T | undefined {
  if (value === null || value === undefined) return undefined;

  // `pg` already parsed it; `JSON.parse` here would throw.
  if (typeof value === "object") return value as T;

  if (typeof value === "string") {
    const trimmed = value.trim();
    if (trimmed.length === 0) return undefined;
    return JSON.parse(trimmed) as T;
  }

  return value as T;
}
