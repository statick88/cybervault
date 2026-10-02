/**
 * The committed template must satisfy the validation that reads it.
 *
 * ## Why this file exists
 *
 * `.env.example` shipped `JWT_SECRET=your-secret-key` — 15 characters — while
 * `validateConfig()` (`src/shared/config.ts`) requires ≥32 and throws at
 * import time in EVERY `NODE_ENV`. So the documented onboarding path (copy the
 * template, start the server) could never work: the template itself failed the
 * rule the code enforces, and nothing in the suite read the two together. That
 * is the same class as `package-scripts.test.ts` — a committed declaration that
 * contradicts the thing consuming it — one layer out: not a path that does not
 * exist, but a value the code refuses.
 *
 * ## What is asserted
 *
 * 1. The template's own declared environment (its `NODE_ENV`) must pass
 *    `validateConfig()` when every key the validator reads is taken from the
 *    template alone — so a too-short or missing secret turns this red.
 * 2. The rules the template must satisfy must still exist at their boundaries
 *    (unset fails, 31 fails, 32 passes) — deleting or relaxing a rule turns
 *    this red too, not only fixing the template.
 * 3. The production-only rules must still fire with the template's production
 *    keys unset — the template documents them as out of scope for development,
 *    and that documentation must not drift silently.
 * 4. The set of keys `validateConfig()` reads is pinned, so a new rule landing
 *    there without being added to this file shows up as a red, not as coverage
 *    that silently stopped covering it.
 *
 * Environment mutation is restored in `finally`: jest isolates test *files*
 * into workers, so the snapshot/restore below only has to be correct within
 * this file.
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { validateConfig } from "../../src/shared/config";

const repoRoot = resolve(__dirname, "..", "..");
const envExamplePath = resolve(repoRoot, ".env.example");
const configSourcePath = resolve(repoRoot, "src", "shared", "config.ts");

/** Minimal `KEY=VALUE` parser: blank lines and `#` comments skipped. */
function parseEnvExample(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq === -1) throw new Error(`not a KEY=VALUE line: ${JSON.stringify(raw)}`);
    out[line.slice(0, eq).trim()] = line.slice(eq + 1).trim();
  }
  return out;
}

/**
 * Every environment key `validateConfig()` reads. If a new rule lands in
 * `validateConfig()` without being added here, the template assertions below
 * stop covering it — so this list is pinned against the function's source.
 */
const VALIDATED_KEYS = [
  "NODE_ENV",
  "JWT_SECRET",
  "VAULT_MASTER_KEY",
  "VAULT_ENCRYPTION_SALT",
  "DB_PASSWORD",
  "DATABASE_URL",
] as const;

/**
 * Run `body` with `process.env` carrying exactly the template's values for
 * every key the validator touches (template-declared or not), then restore the
 * previous environment even if `body` throws.
 */
function withTemplateEnv(template: Record<string, string>, body: () => void): void {
  const keys = [...new Set([...VALIDATED_KEYS, ...Object.keys(template)])];
  const saved = new Map<string, string | undefined>();
  for (const key of keys) saved.set(key, process.env[key]);
  try {
    for (const key of keys) delete process.env[key];
    for (const [key, value] of Object.entries(template)) process.env[key] = value;
    body();
  } finally {
    for (const [key, value] of saved) {
      if (value === undefined) delete process.env[key];
      else process.env[key] = value;
    }
  }
}

/** `validateConfig()`'s message, or "" if it did not throw. */
function validationMessage(): string {
  try {
    validateConfig();
    return "";
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
}

function template(): Record<string, string> {
  return parseEnvExample(readFileSync(envExamplePath, "utf8"));
}

describe(".env.example satisfies the validation that reads it", () => {
  // Extraction must not be vacuous: if the parser stops matching, every case
  // below would pass against a template it never actually read.
  it("parses KEY=VALUE lines and pins the template's declared environment", () => {
    expect(parseEnvExample("# comment\nA=b\n\nC=d=e\n")).toEqual({ A: "b", C: "d=e" });
    expect(() => parseEnvExample("NOT_A_PAIR")).toThrow(/KEY=VALUE/);

    const env = template();
    expect(Object.keys(env).length).toBeGreaterThan(10);
    // Which rules apply is decided by the template's own NODE_ENV: development
    // keeps the production-only rules off, and this is what makes the
    // production case below the precise complement rather than a duplicate.
    expect(env.NODE_ENV).toBe("development");
    expect(env).toHaveProperty("JWT_SECRET");
  });

  it("covers every key validateConfig reads", () => {
    const source = readFileSync(configSourcePath, "utf8");
    const start = source.indexOf("export function validateConfig");
    const end = source.indexOf("// Validate on import");
    // Both markers must be found: a refactor that renames either one fails
    // here instead of silently comparing an empty slice to an empty set.
    expect(start).toBeGreaterThan(-1);
    expect(end).toBeGreaterThan(start);
    const body = source.slice(start, end);
    const readKeys = [...body.matchAll(/process\.env\.([A-Z_0-9]+)/g)].map((m) => m[1]);
    expect(readKeys.length).toBeGreaterThan(0);
    expect(new Set(readKeys)).toEqual(new Set(VALIDATED_KEYS));
  });

  it("passes validateConfig() as committed, in the environment it declares", () => {
    withTemplateEnv(template(), () => {
      expect(validationMessage()).toBe("");
    });
  });

  it("keeps the JWT rules the template must satisfy (unset / 31 / 32 boundary)", () => {
    withTemplateEnv(template(), () => {
      delete process.env.JWT_SECRET;
      expect(validationMessage()).toMatch(/JWT_SECRET is required/);

      process.env.JWT_SECRET = "x".repeat(31);
      expect(validationMessage()).toMatch(/JWT_SECRET must be at least 32 characters/);

      process.env.JWT_SECRET = "x".repeat(32);
      expect(validationMessage()).toBe("");
    });
  });

  it("still enforces the production-only rules the template documents as off", () => {
    withTemplateEnv(template(), () => {
      process.env.NODE_ENV = "production";
      // The template declares no VAULT_* values and no DB_PASSWORD, and its
      // DATABASE_URL is postgres, not sqlite — exactly the three production
      // errors its comment promises stay off under NODE_ENV=development.
      const message = validationMessage();
      expect(message).toMatch(/VAULT_MASTER_KEY is required in production/);
      expect(message).toMatch(/VAULT_ENCRYPTION_SALT is required in production/);
      expect(message).toMatch(/DB_PASSWORD is required in production/);
    });
  });
});
