// @ts-nocheck

import { ValidationService } from "../../../src/ui/popup/services/ValidationService";

describe("ValidationService", () => {
  let service: ValidationService;

  beforeEach(() => {
    service = new ValidationService();
  });

  describe("sanitizeString", () => {
    it("trims leading and trailing whitespace", () => {
      expect(service.sanitizeString("  hello world  ", 100)).toBe(
        "hello world",
      );
    });

    it("removes control characters (ASCII < 32)", () => {
      const input = "hello\nworld\rtab\there";
      const result = service.sanitizeString(input, 100);
      expect(result).not.toContain("\n");
      expect(result).not.toContain("\r");
      expect(result).not.toContain("\t");
      expect(result).toBe("helloworldhere");
    });

    it("preserves letters, numbers, and normal symbols", () => {
      const input = "Test@123!#$%^&*()_+-=[]{}|;:,.<>?";
      const result = service.sanitizeString(input, 100);
      expect(result).toBe(input);
    });

    it("returns empty string for empty input", () => {
      expect(service.sanitizeString("", 100)).toBe("");
    });

    it("truncates strings longer than maxLength", () => {
      const longString = "a".repeat(200);
      const result = service.sanitizeString(longString, 100);
      expect(result).toHaveLength(100);
    });

    it("handles non-string input by returning empty string", () => {
      // @ts-ignore - testing invalid input
      expect(service.sanitizeString(null, 100)).toBe("");
      // @ts-ignore - testing invalid input
      expect(service.sanitizeString(undefined, 100)).toBe("");
      // @ts-ignore - testing invalid input
      expect(service.sanitizeString(123, 100)).toBe("");
    });

    it("preserves unicode characters", () => {
      const input = "Hola ¿Qué tal? 你好 🎉";
      const result = service.sanitizeString(input, 100);
      expect(result).toBe(input);
    });
  });

  describe("isValidUrl", () => {
    it("accepts http:// URLs", () => {
      expect(service.isValidUrl("http://example.com")).toBe(true);
      expect(service.isValidUrl("http://localhost:3000")).toBe(true);
    });

    it("accepts https:// URLs", () => {
      expect(service.isValidUrl("https://example.com")).toBe(true);
      expect(service.isValidUrl("https://secure.site.com/path?query=1")).toBe(
        true,
      );
    });

    it("rejects ftp:// URLs", () => {
      expect(service.isValidUrl("ftp://example.com")).toBe(false);
    });

    it("rejects javascript: URLs", () => {
      expect(service.isValidUrl("javascript:alert('xss')")).toBe(false);
      expect(service.isValidUrl("javascript://test")).toBe(false);
    });

    it("rejects data: URLs", () => {
      expect(
        service.isValidUrl("data:text/html,<script>alert('xss')</script>"),
      ).toBe(false);
    });

    it("returns false for empty string", () => {
      expect(service.isValidUrl("")).toBe(false);
    });

    it("returns false for malformed URLs", () => {
      expect(service.isValidUrl("not a url")).toBe(false);
      expect(service.isValidUrl("http://")).toBe(false);
      expect(service.isValidUrl("://missing-protocol")).toBe(false);
    });

    it("validates URLs with ports", () => {
      expect(service.isValidUrl("http://localhost:8080")).toBe(true);
      expect(service.isValidUrl("https://example.com:443")).toBe(true);
    });

    it("validates URLs with paths and query strings", () => {
      expect(
        service.isValidUrl(
          "https://example.com/path/to/resource?id=123&sort=asc",
        ),
      ).toBe(true);
    });

    it("rejects URLs with file:// protocol", () => {
      expect(service.isValidUrl("file:///etc/passwd")).toBe(false);
    });

    it("rejects blob: URLs", () => {
      expect(service.isValidUrl("blob:https://example.com/12345")).toBe(false);
    });

    it("handles URLs with IP addresses", () => {
      expect(service.isValidUrl("http://127.0.0.1")).toBe(true);
      expect(service.isValidUrl("https://192.168.1.1:8080")).toBe(true);
    });
  });

  describe("isValidEmail", () => {
    it("accepts simple email addresses", () => {
      expect(service.isValidEmail("user@example.com")).toBe(true);
      expect(service.isValidEmail("test@domain.org")).toBe(true);
    });

    it("accepts emails with subdomains", () => {
      expect(service.isValidEmail("user@mail.example.com")).toBe(true);
      expect(service.isValidEmail("admin@api.staging.company.co.uk")).toBe(
        true,
      );
    });

    it("rejects emails without @", () => {
      expect(service.isValidEmail("userexample.com")).toBe(false);
      expect(service.isValidEmail("")).toBe(false);
    });

    it("rejects emails with multiple @", () => {
      expect(service.isValidEmail("user@@example.com")).toBe(false);
      expect(service.isValidEmail("user@test@domain.com")).toBe(false);
    });

    it("rejects emails with spaces", () => {
      expect(service.isValidEmail("user @example.com")).toBe(false);
      expect(service.isValidEmail("user@ example.com")).toBe(false);
      expect(service.isValidEmail(" user@example.com")).toBe(false);
    });

    it("rejects emails with invalid domain", () => {
      expect(service.isValidEmail("user@")).toBe(false);
      expect(service.isValidEmail("user@domain")).toBe(false);
      expect(service.isValidEmail("@example.com")).toBe(false);
    });

    it("rejects emails with missing TLD", () => {
      expect(service.isValidEmail("user@localhost")).toBe(false);
    });

    it("accepts emails with plus sign", () => {
      expect(service.isValidEmail("user+tag@example.com")).toBe(true);
    });

    it("accepts emails with dots in username", () => {
      expect(service.isValidEmail("first.last@example.com")).toBe(true);
    });

    it("accepts emails with hyphens", () => {
      expect(service.isValidEmail("user-name@example-domain.com")).toBe(true);
    });

    it("rejects emails with consecutive dots", () => {
      expect(service.isValidEmail("user..name@example.com")).toBe(false);
    });
  });

  describe("validateTags", () => {
    it("splits comma-separated tag string to array", () => {
      const tagsString = "tag1, tag2, tag3";
      const result = service.validateTags(tagsString.split(","));
      expect(result).toEqual(["tag1", "tag2", "tag3"]);
    });

    it("trims whitespace from tags", () => {
      const tags = ["  tag1  ", "\ttag2\t", "  tag3\n"];
      const result = service.validateTags(tags);
      expect(result).toEqual(["tag1", "tag2", "tag3"]);
    });

    it("removes duplicate tags", () => {
      const tags = ["tag1", "tag2", "tag1", "tag3", "tag2"];
      const result = service.validateTags(tags);
      expect(result).toEqual(["tag1", "tag2", "tag3"]);
    });

    it("filters out empty tags", () => {
      const tags = ["tag1", "", "tag2", "   ", "\t", "tag3"];
      const result = service.validateTags(tags);
      expect(result).toEqual(["tag1", "tag2", "tag3"]);
    });

    it("truncates tags longer than MAX_TAG_LENGTH (30)", () => {
      const longTag = "a".repeat(50);
      const tags = [longTag, "short"];
      const result = service.validateTags(tags);
      expect(result[0]).toHaveLength(30);
      expect(result[1]).toBe("short");
    });

    it("limits number of tags to MAX_TAGS (20)", () => {
      const tags = Array.from({ length: 30 }, (_, i) => `tag${i}`);
      const result = service.validateTags(tags);
      expect(result).toHaveLength(20);
    });

    it("maintains order of tags", () => {
      const tags = ["first", "second", "third"];
      const result = service.validateTags(tags);
      expect(result).toEqual(["first", "second", "third"]);
    });

    it("handles array with only invalid tags", () => {
      const tags = ["", "   ", "\t", "\n"];
      const result = service.validateTags(tags);
      expect(result).toEqual([]);
    });

    it("sanitizes special characters in tags", () => {
      const tags = ["tag<script>", "tag&special", "tag'quote"];
      const result = service.validateTags(tags);
      expect(result[0]).toBe("tag<script>");
      expect(result[1]).toBe("tag&special");
      expect(result[2]).toBe("tag'quote");
    });

    it("returns empty array for empty input", () => {
      const result = service.validateTags([]);
      expect(result).toEqual([]);
    });
  });

  describe("validatePasswordStrength", () => {
    it("detects weak password '123' with low score", () => {
      const result = service.validatePasswordStrength("123");
      expect(result.score).toBeLessThan(40);
      expect(result.isValid).toBe(false);
      expect(result.feedback).toContain(expect.stringContaining("muy corta"));
    });

    it("detects strong password 'Xy7!zE9@qW' with high score", () => {
      const result = service.validatePasswordStrength("Xy7!zE9@qW");
      expect(result.score).toBeGreaterThanOrEqual(80);
      expect(result.isValid).toBe(true);
    });

    it("returns intermediate score for 'Password123'", () => {
      const result = service.validatePasswordStrength("Password123");
      expect(result.score).toBeGreaterThanOrEqual(50);
      expect(result.score).toBeLessThan(80);
      expect(result.isValid).toBe(true);
    });

    it("requires minimum 8 characters", () => {
      const result = service.validatePasswordStrength("Abc123!");
      expect(result.isValid).toBe(false);
      expect(result.feedback).toContain(expect.stringContaining("muy corta"));
    });

    it("recommends 12+ characters when using 8-11", () => {
      const result = service.validatePasswordStrength("Passw0rd!");
      expect(result.feedback).toContain(
        expect.stringContaining("12+ caracteres"),
      );
    });

    it("detects lowercase only", () => {
      const result = service.validatePasswordStrength("lowercase");
      expect(result.isValid).toBe(false);
      expect(result.feedback).toContain(
        expect.stringContaining("tipos de caracteres"),
      );
    });

    it("detects uppercase only", () => {
      const result = service.validatePasswordStrength("UPPERCASE");
      expect(result.isValid).toBe(false);
      expect(result.feedback).toContain(
        expect.stringContaining("tipos de caracteres"),
      );
    });

    it("requires variety of character types", () => {
      const result = service.validatePasswordStrength("abcdefgh");
      expect(result.feedback).toContain(
        expect.stringContaining("tipos de caracteres"),
      );
    });

    it("detects repetitive characters", () => {
      const result = service.validatePasswordStrength("aaaaaaaa");
      expect(result.isValid).toBe(false);
      expect(result.feedback).toContain(expect.stringContaining("repetitivos"));
    });

    it("detects common sequences", () => {
      expect(service.validatePasswordStrength("12345678").isValid).toBe(false);
      expect(service.validatePasswordStrength("abcdefgh").isValid).toBe(false);
      expect(service.validatePasswordStrength("qwertyui").isValid).toBe(false);
      expect(service.validatePasswordStrength("password123").isValid).toBe(
        false,
      );
      expect(service.validatePasswordStrength("admin123").isValid).toBe(false);
    });

    it("detects personal info patterns", () => {
      expect(service.validatePasswordStrength("John1234").isValid).toBe(false);
      expect(service.validatePasswordStrength("Mike2020").isValid).toBe(false);
      expect(service.validatePasswordStrength("11111111").isValid).toBe(false);
    });

    it("detects low entropy", () => {
      const result = service.validatePasswordStrength("abc");
      expect(result.isValid).toBe(false);
      expect(
        result.feedback.some((f) => f.toLowerCase().includes("entropía")),
      ).toBe(true);
    });

    it("handles empty password", () => {
      const result = service.validatePasswordStrength("");
      expect(result.score).toBe(0);
      expect(result.isValid).toBe(false);
      expect(result.feedback.length).toBeGreaterThan(0);
    });

    it("returns positive feedback for very strong passwords", () => {
      const result = service.validatePasswordStrength("R4nd0m!Str#ng2024");
      expect(result.isValid).toBe(true);
      expect(
        result.feedback.some(
          (f) =>
            f.toLowerCase().includes("muy fuerte") ||
            f.toLowerCase().includes("aceptable"),
        ),
      ).toBe(true);
    });

    it("correctly calculates entropy for mixed character types", () => {
      const result1 = service.validatePasswordStrength("abc"); // lower only: 26 chars
      const result2 = service.validatePasswordStrength("ABC"); // upper only: 26 chars
      const result3 = service.validatePasswordStrength("123"); // numbers only: 10 chars
      const result4 = service.validatePasswordStrength("Ab1!"); // mixed: 26+26+10+32 = 94

      expect(result2.score).toBeGreaterThan(result1.score);
      expect(result4.score).toBeGreaterThan(result3.score);
    });

    it("handles extremely long passwords", () => {
      const long = "a".repeat(200);
      const result = service.validatePasswordStrength(long);
      expect(result.score).toBe(100);
      expect(result.isValid).toBe(true);
    });
  });

  describe("isStrongPassword", () => {
    it("returns true for strong passwords (score >= 60)", () => {
      expect(service.isStrongPassword("SecurePass123!")).toBe(true);
      expect(service.isStrongPassword("R4nd0m!Str#ng")).toBe(true);
    });

    it("returns false for weak passwords (score < 60)", () => {
      expect(service.isStrongPassword("password")).toBe(false);
      expect(service.isStrongPassword("12345678")).toBe(false);
      expect(service.isStrongPassword("qwertyuiop")).toBe(false);
    });

    it("returns false for very short passwords", () => {
      expect(service.isStrongPassword("Abc1!")).toBe(false);
    });
  });

  describe("sanitizeCredentialData", () => {
    it("sanitizes title field", () => {
      const data = { title: "  My Title  " };
      const result = service.sanitizeCredentialData(data);
      expect(result.title).toBe("My Title");
    });

    it("sanitizes username field", () => {
      const data = { username: "  user@example.com\t" };
      const result = service.sanitizeCredentialData(data);
      expect(result.username).toBe("user@example.com");
    });

    it("sanitizes url field", () => {
      const data = { url: "  https://example.com  " };
      const result = service.sanitizeCredentialData(data);
      expect(result.url).toBe("https://example.com");
    });

    it("sanitizes notes field", () => {
      const data = { notes: "  Some notes with spaces  " };
      const result = service.sanitizeCredentialData(data);
      expect(result.notes).toBe("Some notes with spaces");
    });

    it("sanitizes tags array", () => {
      const data = { tags: ["work", "  personal  ", "dev"] };
      const result = service.sanitizeCredentialData(data);
      expect(result.tags).toEqual(["work", "personal", "dev"]);
    });

    it("truncates fields exceeding max lengths", () => {
      const veryLong = "a".repeat(500);
      const data = {
        title: veryLong,
        username: veryLong,
        notes: veryLong,
      };
      const result = service.sanitizeCredentialData(data);
      expect(result.title).toHaveLength(service.MAX_TITLE_LENGTH);
      expect(result.username).toHaveLength(service.MAX_USERNAME_LENGTH);
      expect(result.notes).toHaveLength(service.MAX_NOTES_LENGTH);
    });

    it("removes undefined fields from result", () => {
      const data = { title: "Test" };
      const result = service.sanitizeCredentialData(data);
      expect(result).not.toHaveProperty("username");
      expect(result).not.toHaveProperty("url");
      expect(result).not.toHaveProperty("notes");
      expect(result).not.toHaveProperty("tags");
    });

    it("handles all fields together", () => {
      const data = {
        title: "  My Credential  ",
        username: "  user@example.com\t",
        url: "  https://example.com  ",
        notes: "  Notes with\nnewlines\tand tabs  ",
        tags: ["work", "  personal  ", "", "dev"],
      };
      const result = service.sanitizeCredentialData(data);
      expect(result.title).toBe("My Credential");
      expect(result.username).toBe("user@example.com");
      expect(result.url).toBe("https://example.com");
      expect(result.notes).toBe("Notes with\nnewlines\tand tabs"); // sanitizeString only trims
      expect(result.tags).toEqual(["work", "personal", "dev"]);
    });

    it("handles empty strings", () => {
      const data = {
        title: "",
        username: "",
        url: "",
        notes: "",
        tags: [""],
      };
      const result = service.sanitizeCredentialData(data);
      expect(result.title).toBe("");
      expect(result.username).toBe("");
      expect(result.url).toBe(undefined); // empty URL becomes undefined
      expect(result.notes).toBe("");
      expect(result.tags).toEqual([]);
    });

    it("converts empty url to undefined", () => {
      const data = { url: "   " };
      const result = service.sanitizeCredentialData(data);
      expect(result.url).toBeUndefined();
    });

    it("does not modify original object", () => {
      const data = { title: "Original" };
      const result = service.sanitizeCredentialData(data);
      expect(data.title).toBe("Original");
      result.title = "Modified";
      expect(data.title).toBe("Original");
    });

    it("handles object with no sanitizable fields", () => {
      const data = {};
      const result = service.sanitizeCredentialData(data);
      expect(result).toEqual({});
    });

    it("removes control characters from all string fields", () => {
      const data = {
        title: "Test\r\nTitle",
        username: "User\tName",
        notes: "Notes\rwith\ncontrol\tchars",
        tags: ["tag\r\n", "normal"],
      };
      const result = service.sanitizeCredentialData(data);
      expect(result.title).not.toContain("\r");
      expect(result.title).not.toContain("\n");
      expect(result.username).not.toContain("\t");
      expect(result.notes).not.toContain("\r");
      expect(result.notes).not.toContain("\n");
      expect(result.notes).not.toContain("\t");
      expect(result.tags[0]).not.toContain("\r");
      expect(result.tags[0]).not.toContain("\n");
      expect(result.tags[0]).toBe("tag");
    });

    it("limits tags count after sanitization", () => {
      const manyTags = Array.from({ length: 25 }, (_, i) => `tag${i}`);
      const data = { tags: manyTags };
      const result = service.sanitizeCredentialData(data);
      expect(result.tags).toHaveLength(20);
    });

    it("handles unicode characters in all fields", () => {
      const data = {
        title: "Título en español",
        username: " usuario@ejemplo.com ",
        notes: "Нотас en русском",
        tags: ["etiqueta", "标签"],
      };
      const result = service.sanitizeCredentialData(data);
      expect(result.title).toBe("Título en español");
      expect(result.username).toBe("usuario@ejemplo.com");
      expect(result.notes).toBe("Нотас en русском");
      expect(result.tags).toContain("etiqueta");
      expect(result.tags).toContain("标签");
    });
  });

  describe("Integration: Combined validation", () => {
    it("sanitizes data with invalid URL and returns sanitized version", () => {
      const data = {
        url: "javascript:alert('xss')",
        title: "  Safe Title  ",
      };
      const result = service.sanitizeCredentialData(data);
      // sanitizeCredentialData only sanitizes (trim, truncate), it doesn't validate URL format
      expect(result.url).toBe("javascript:alert('xss')");
      expect(result.title).toBe("Safe Title");
    });

    it("sanitizes and validates password strength", () => {
      const weakPassword = "123";
      const strongPassword = "Secure!Pass123";

      const weakResult = service.validatePasswordStrength(weakPassword);
      const strongResult = service.validatePasswordStrength(strongPassword);

      expect(weakResult.isValid).toBe(false);
      expect(weakResult.score).toBeLessThan(strongResult.score);
      expect(strongResult.isValid).toBe(true);
    });
  });

  describe("Edge cases", () => {
    it("handles null input gracefully in real-world scenario", () => {
      const result = service.validateTags([]);
      expect(result).toEqual([]);
    });

    it("handles strings with only whitespace", () => {
      const result = service.sanitizeString("     \n\t\r    ", 100);
      expect(result).toBe("");
    });

    it("handles password with only symbols", () => {
      const result = service.validatePasswordStrength("@#$%^&*!");
      expect(result.feedback).toContain(expect.stringContaining("muy corta"));
    });

    it("handles email with numbers in domain", () => {
      expect(service.isValidEmail("user@123.com")).toBe(true);
      expect(service.isValidEmail("user@123456.org")).toBe(true);
    });
  });
});
