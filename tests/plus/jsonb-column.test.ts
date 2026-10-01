import { parseJsonbColumn } from "../../src/shared/jsonb";

/**
 * Regression guard for the double-parse defect found during the Plus runtime
 * work (2026-09-28).
 *
 * The three pre-existing Plus repositories read `metadata JSONB` columns with
 * `JSON.parse(row.metadata)`. `pg` installs a type parser for OID 3802, so the
 * value handed to the repository is ALREADY an object, and `JSON.parse` on it
 * throws:
 *
 *     JSON.parse({a: 1})  ->  SyntaxError: "[object Object]" is not valid JSON
 *
 * The bug was latent only because no row with non-NULL `metadata` had been read
 * yet. Any entitlement lookup would have thrown at runtime.
 */
describe("parseJsonbColumn", () => {
  it("returns an already-parsed object without attempting a second parse", () => {
    // This is the exact shape `pg` produces for a jsonb column.
    const fromDriver = { a: 1, nested: { b: true } };

    expect(() => parseJsonbColumn(fromDriver)).not.toThrow();
    expect(parseJsonbColumn(fromDriver)).toEqual({ a: 1, nested: { b: true } });
  });

  it("would have thrown under the previous JSON.parse implementation", () => {
    // Proves the defect was real, not hypothetical.
    const fromDriver = { a: 1 };
    expect(() => JSON.parse(fromDriver as unknown as string)).toThrow(SyntaxError);
  });

  it("still decodes a raw string, for drivers with the type parser disabled", () => {
    expect(parseJsonbColumn('{"a":1}')).toEqual({ a: 1 });
  });

  it("maps SQL NULL and undefined to undefined", () => {
    expect(parseJsonbColumn(null)).toBeUndefined();
    expect(parseJsonbColumn(undefined)).toBeUndefined();
  });

  it("treats an empty or whitespace-only string as absent", () => {
    expect(parseJsonbColumn("")).toBeUndefined();
    expect(parseJsonbColumn("   ")).toBeUndefined();
  });

  it("preserves falsy-but-present values rather than dropping them", () => {
    expect(parseJsonbColumn({ count: 0, flag: false })).toEqual({ count: 0, flag: false });
  });
});
