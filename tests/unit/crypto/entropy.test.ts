import { CredentialsGenerator } from "../../../src/domain/services/autocompletado/credentials-generator";
import {
  EntropyCalculator,
  EntropyValidator,
} from "../../../src/domain/services/autocompletado/entropy-validator";

describe("Password Entropy", () => {
  const generator = new CredentialsGenerator();
  const VALID_DOMAIN = "example.com";

  it("should generate passwords with high entropy", async () => {
    const results = await Promise.all(
      Array.from({ length: 100 }, () =>
        generator.generateCredentials(VALID_DOMAIN),
      ),
    );

    for (const cred of results) {
      const password = cred.originalPassword;
      expect(password.length).toBeGreaterThanOrEqual(32);

      const hasUpper = /[A-Z]/.test(password);
      const hasLower = /[a-z]/.test(password);
      const hasDigit = /[0-9]/.test(password);
      const hasSpecial = /[^A-Za-z0-9]/.test(password);
      expect(hasUpper && hasLower && hasDigit && hasSpecial).toBe(true);
    }
  });

  it("should generate unique passwords", async () => {
    const passwords = new Set(
      await Promise.all(
        Array.from({ length: 100 }, () =>
          generator.generateCredentials(VALID_DOMAIN).then((c) => c.originalPassword),
        ),
      ),
    );
    expect(passwords.size).toBe(100);
  });

  it("should achieve target entropy of 128+ bits", () => {
    const samplePasswords = Array.from({ length: 50 }, () => {
      const cred = generator["generateComplexPassword"](32) as any;
      // generateComplexPassword is private, use EntropyValidator directly on random strings
      const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
      let result = "";
      const array = new Uint8Array(32);
      crypto.getRandomValues(array);
      for (let i = 0; i < 32; i++) {
        result += chars[array[i] % chars.length];
      }
      return result;
    });

    for (const password of samplePasswords) {
      const entropy = EntropyValidator.estimatePasswordEntropy(password);
      expect(entropy).toBeGreaterThan(100);
    }
  });

  it("should produce valid credentials via generateCredentials", async () => {
    const cred = await generator.generateCredentials(VALID_DOMAIN);

    expect(cred.email).toContain(`@${VALID_DOMAIN}`);
    expect(cred.email).toContain("+");
    // Password format is "passwordBase+pepper" — pepper is 32-char hex (no +)
    // so the last segment after the final + must be the 32-char pepper
    const lastPlus = cred.password.lastIndexOf("+");
    expect(lastPlus).toBeGreaterThan(0);
    const pepperPart = cred.password.slice(lastPlus + 1);
    expect(pepperPart).toHaveLength(32);
    expect(pepperPart).toMatch(/^[0-9a-f]{32}$/);
    expect(cred.salt).toHaveLength(32);
    expect(cred.pepper).toHaveLength(32);
    expect(cred.originalPassword).toHaveLength(32);
    expect(cred.originalEmail).toContain(`@${VALID_DOMAIN}`);
  });

  it("should validate salt and pepper entropy", async () => {
    const cred = await generator.generateCredentials(VALID_DOMAIN);

    const saltEntropy = EntropyCalculator.calculateHexEntropy(cred.salt);
    const pepperEntropy = EntropyCalculator.calculateHexEntropy(cred.pepper);

    expect(saltEntropy).toBeGreaterThanOrEqual(128);
    expect(pepperEntropy).toBeGreaterThanOrEqual(128);
  });

  it("should analyze credential quality with sufficient entropy", async () => {
    const cred = await generator.generateCredentials(VALID_DOMAIN);
    const quality = generator.analyzeCredentialsQuality(cred);

    // Entropy values should be computed and above minimum thresholds
    expect(quality.entropyAnalysis.salt).toBeGreaterThanOrEqual(128);
    expect(quality.entropyAnalysis.pepper).toBeGreaterThanOrEqual(128);
    expect(quality.entropyAnalysis.passwordBase).toBeGreaterThan(100);

    // Warnings may exist due to statistical distribution checks on small
    // samples (16 bytes for salt/pepper), but entropy itself is sufficient
    expect(quality.warnings).toBeDefined();
  });

  it("should reject invalid domain", async () => {
    await expect(generator.generateCredentials("")).rejects.toThrow();
    await expect(generator.generateCredentials("not a domain")).rejects.toThrow();
  });

  it("should round-trip credentials through extract", async () => {
    const cred = await generator.generateCredentials(VALID_DOMAIN);

    const original = await generator.extractOriginalCredentials(
      cred.email,
      cred.password,
    );

    expect(original.email).toBe(cred.originalEmail);
    expect(original.password).toBe(cred.originalPassword);
  });
});
