import { levenshteinSimilarity } from "../../../src/domain/utils/levenshtein";

describe("levenshteinSimilarity", () => {
  describe("identical strings", () => {
    it("returns 1.0 for identical non-empty strings", () => {
      expect(levenshteinSimilarity("hello", "hello")).toBe(1.0);
    });

    it("returns 1.0 for two empty strings", () => {
      expect(levenshteinSimilarity("", "")).toBe(1.0);
    });
  });

  describe("empty strings", () => {
    it("returns 0.0 when first string is empty", () => {
      expect(levenshteinSimilarity("", "abc")).toBe(0.0);
    });

    it("returns 0.0 when second string is empty", () => {
      expect(levenshteinSimilarity("abc", "")).toBe(0.0);
    });
  });

  describe("one character off", () => {
    it("returns high similarity for one substitution", () => {
      const sim = levenshteinSimilarity("hello", "hullo");
      expect(sim).toBeGreaterThan(0.7);
      expect(sim).toBeLessThan(1.0);
    });

    it("returns high similarity for one insertion", () => {
      const sim = levenshteinSimilarity("abc", "abcd");
      expect(sim).toBeCloseTo(0.75, 1);
    });

    it("returns high similarity for one deletion", () => {
      const sim = levenshteinSimilarity("abcd", "abc");
      expect(sim).toBeCloseTo(0.75, 1);
    });
  });

  describe("very different strings", () => {
    it("returns low similarity for very different strings", () => {
      const sim = levenshteinSimilarity("abc", "xyz");
      expect(sim).toBeLessThan(0.5);
    });

    it("returns 0.0 for completely different single characters", () => {
      expect(levenshteinSimilarity("a", "z")).toBe(0.0);
    });
  });

  describe("max length limit", () => {
    it("throws when first input exceeds 100 chars", () => {
      const long = "a".repeat(101);
      expect(() => levenshteinSimilarity(long, "short")).toThrow("exceeds hard limit");
    });

    it("throws when second input exceeds 100 chars", () => {
      const long = "a".repeat(101);
      expect(() => levenshteinSimilarity("short", long)).toThrow("exceeds hard limit");
    });

    it("accepts exactly 100 characters", () => {
      const max = "a".repeat(100);
      expect(() => levenshteinSimilarity(max, max)).not.toThrow();
    });
  });

  describe("edge cases", () => {
    it("handles single character strings", () => {
      expect(levenshteinSimilarity("a", "a")).toBe(1.0);
    });

    it("handles longer identical strings", () => {
      expect(levenshteinSimilarity("abcdef", "abcdef")).toBe(1.0);
    });

    it("handles case sensitivity", () => {
      const sim = levenshteinSimilarity("AbC", "aBc");
      expect(sim).toBeLessThan(1.0);
    });
  });
});
