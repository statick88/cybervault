import {
  detectConfusables,
  stripZeroWidth,
} from "../../../src/domain/utils/unicode-confusables";

describe("stripZeroWidth", () => {
  it("removes ZERO WIDTH SPACE (U+200B)", () => {
    expect(stripZeroWidth("hel\u200Blo")).toBe("hello");
  });

  it("removes ZERO WIDTH NON-JOINER (U+200C)", () => {
    expect(stripZeroWidth("hel\u200Clo")).toBe("hello");
  });

  it("removes ZERO WIDTH JOINER (U+200D)", () => {
    expect(stripZeroWidth("hel\u200Dlo")).toBe("hello");
  });

  it("removes BOM (U+FEFF)", () => {
    expect(stripZeroWidth("\uFEFFhello")).toBe("hello");
  });

  it("removes WORD JOINER (U+2060)", () => {
    expect(stripZeroWidth("hel\u2060lo")).toBe("hello");
  });

  it("removes SOFT HYPHEN (U+00AD)", () => {
    expect(stripZeroWidth("hel\u00ADlo")).toBe("hello");
  });

  it("does not alter clean text", () => {
    expect(stripZeroWidth("hello")).toBe("hello");
  });

  it("removes multiple zero-width chars from one string", () => {
    expect(stripZeroWidth("h\u200Be\u200Cl\u200Dlo")).toBe("hello");
  });
});

describe("detectConfusables", () => {
  describe("clean Latin text", () => {
    it("returns empty array for plain ASCII", () => {
      expect(detectConfusables("google.com")).toEqual([]);
    });

    it("returns empty array for empty string", () => {
      expect(detectConfusables("")).toEqual([]);
    });
  });

  describe("Cyrillic homograph attack", () => {
    it("detects Cyrillic 'a' (U+0430) resembling Latin 'a'", () => {
      const results = detectConfusables("gооgle.com");
      // 'о' is Cyrillic (U+043E) not Latin 'o'
      expect(results.length).toBeGreaterThan(0);
      const cyrillicO = results.find((r) => r.script === "Cyrillic");
      expect(cyrillicO).toBeDefined();
      expect(cyrillicO!.lookalike).toBe("o");
    });

    it("detects multiple Cyrillic characters", () => {
      // "аpple" with Cyrillic 'а'
      const results = detectConfusables("\u0430pple");
      expect(results.length).toBe(1);
      expect(results[0].script).toBe("Cyrillic");
    });
  });

  describe("Greek homograph attack", () => {
    it("detects Greek omicron (U+03BF) resembling Latin 'o'", () => {
      const results = detectConfusables("g\u03BF\u03BFgle.com");
      expect(results.length).toBeGreaterThan(0);
      const greekChar = results.find((r) => r.script === "Greek");
      expect(greekChar).toBeDefined();
      expect(greekChar!.lookalike).toBe("o");
    });
  });

  describe("mixed scripts", () => {
    it("detects both Cyrillic and Greek in same string", () => {
      const results = detectConfusables("\u0430\u03BF"); // Cyrillic a + Greek o
      expect(results.length).toBe(2);
      const scripts = results.map((r) => r.script);
      expect(scripts).toContain("Cyrillic");
      expect(scripts).toContain("Greek");
    });
  });

  describe("Fullwidth characters", () => {
    it("detects fullwidth Latin letters", () => {
      const results = detectConfusables("\uFF27\uFF4F\uFF4F\uFF47\uFF4C\uFF45");
      expect(results.length).toBeGreaterThan(0);
      expect(results[0].category).toBe("fullwidth");
    });
  });

  describe("evidence structure", () => {
    it("returns correct index for detected character", () => {
      const results = detectConfusables("a\u0430b");
      expect(results.length).toBe(1);
      expect(results[0].index).toBe(1);
    });

    it("includes codePoint in evidence", () => {
      const results = detectConfusables("\u0430");
      expect(results[0].codePoint).toBe(0x0430);
    });
  });
});
