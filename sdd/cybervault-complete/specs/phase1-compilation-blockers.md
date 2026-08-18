# SDD Delta Spec — Phase 1: Compilation Blockers

**Change**: `cybervault-complete`
**Phase**: 1 of 5
**Purpose**: Resolve all missing module errors that prevent TypeScript compilation
**Date**: 2026-08-14

---

## Summary

12 files are missing that block `tsc`. Every file below is a value-object, utility function, or barrel export that existing code already imports. No behavior changes — these are pure interface/type implementations that satisfy the existing import graph.

---

## 1. `src/domain/value-objects/ids.ts`

**Module path**: `src/domain/value-objects/ids.ts`
**Dependencies**: None (leaf module)
**Consumers**: vault.ts, credential.ts, vulnerability.ts, all repositories, crypto-service.ts

### Exports

```typescript
// Generic branded ID class
class DomainId {
  private readonly value: string;

  protected constructor(value: string);

  toString(): string;
  equals(other: DomainId): boolean;

  static generate(): DomainId; // UUID v4
}

// Concrete ID types — each extends DomainId with its own brand
class VaultId extends DomainId {
  static fromString(value: string): VaultId;
  static generate(): VaultId;
}

class CredentialId extends DomainId {
  static fromString(value: string): CredentialId;
  static generate(): CredentialId;
}

class VulnerabilityId extends DomainId {
  static fromString(value: string): VulnerabilityId;
  static generate(): VulnerabilityId;
}

// CryptoHash — a branded string for crypto hash results
class CryptoHash extends DomainId {
  static fromString(value: string): CryptoHash;
}
```

### Behavior

- `generate()` produces a UUID v4 string (crypto.randomUUID or fallback).
- `fromString()` validates format (basic UUID regex) and throws on invalid.
- `equals()` compares the raw string values.
- `toString()` returns the raw UUID string.
- Uses TypeScript branded types via `declare` symbol pattern to prevent accidental mixing.

### Acceptance Criteria

- [ ] VaultId.fromString("550e8400-e29b-41d4-a716-446655440000") succeeds
- [ ] VaultId.fromString("invalid") throws
- [ ] VaultId.generate() !== VaultId.generate()
- [ ] CryptoHash.fromString("abc123") succeeds
- [ ] All existing `import { VaultId } from "../value-objects/ids"` resolve

---

## 2. `src/domain/value-objects/isolated-cookie-metadata.ts`

**Module path**: `src/domain/value-objects/isolated-cookie-metadata.ts`
**Dependencies**: None
**Consumers**: i-cookie-isolation-policy.ts, chrome-storage-cookie-isolation-adapter.ts

### Exports

```typescript
export interface IsolatedCookieMetadata {
  readonly name: string;
  readonly domain: string;
  readonly path: string;
  readonly secure: boolean;
  readonly httpOnly: boolean;
  readonly sameSite: 'Strict' | 'Lax' | 'None';
  readonly expirationDate?: number;
}
```

### Behavior

- Pure interface — no runtime code.
- Documents the shape of cookie metadata needed for secure cookie isolation.

### Acceptance Criteria

- [ ] `import type { IsolatedCookieMetadata } from "..."` compiles
- [ ] Existing cookie isolation adapter compiles

---

## 3. `src/domain/value-objects/binding-signature.ts`

**Module path**: `src/domain/value-objects/binding-signature.ts`
**Dependencies**: None
**Consumers**: i-channel-binding-protocol.ts, subtle-crypto-channel-binding-adapter.ts

### Exports

```typescript
export class BindingSignature {
  private readonly props: BindingSignatureProps;

  constructor(props: BindingSignatureProps);

  get domain(): string;
  get timestamp(): number;
  get nonce(): string; // base64
  get signature(): string; // base64

  isValid(currentTimestamp: number, maxAgeMs?: number): boolean;

  toPlainObject(): { domain: string; timestamp: number; nonce: string; signature: string };

  static create(domain: string, timestamp: number, nonce: string, signature: string): BindingSignature;

  static fromPlainObject(obj: { domain: string; timestamp: number; nonce: string; signature: string }): BindingSignature;
}

interface BindingSignatureProps {
  readonly domain: string;
  readonly timestamp: number;
  readonly nonce: string;
  readonly signature: string;
}
```

### Behavior

- Value object — immutable after construction.
- `isValid()` checks that `currentTimestamp - timestamp` is within `maxAgeMs` (default 300_000 = 5 minutes).
- `create()` factory normalizes domain to lowercase/trim.
- `fromPlainObject()` deserializes.

### Acceptance Criteria

- [ ] BindingSignature.create("example.com", Date.now(), "nonce", "sig") succeeds
- [ ] isValid returns true for recent timestamp, false for expired
- [ ] subtle-crypto-channel-binding-adapter.ts compiles

---

## 4. `src/domain/value-objects/validation-context.ts`

**Module path**: `src/domain/value-objects/validation-context.ts`
**Dependencies**: None
**Consumers**: DomainValidator.ts, ExactMatchStep.ts, ConfusableDetectionStep.ts, TyposquattingStep.ts, ValidateFormSubmission.ts

### Exports

```typescript
export interface ValidationContext {
  readonly currentDomain: string;
  readonly trustedDomains: ReadonlySet<string>;
  readonly timestamp: number;
}
```

### Behavior

- Pure interface — no runtime code.

### Acceptance Criteria

- [ ] All DomainValidator step files compile
- [ ] ValidateFormSubmission.ts compiles

---

## 5. `src/domain/value-objects/domain-status.ts`

**Module path**: `src/domain/value-objects/domain-status.ts`
**Dependencies**: None
**Consumers**: DomainValidator.ts, ExactMatchStep.ts, ConfusableDetectionStep.ts, TyposquattingStep.ts, ValidateFormSubmission.ts

### Exports

```typescript
export type ValidationStatus = 'valid' | 'suspicious' | 'malicious';

export interface ValidationResult {
  readonly status: ValidationStatus;
  readonly latencyMs: number;
  readonly reason: string;
  readonly step: string;
}
```

### Behavior

- Pure interface + type alias — no runtime code.
- `status` is the validation verdict.
- `latencyMs` tracks performance of the validation step.
- `step` identifies which validation step produced the result.

### Acceptance Criteria

- [ ] All files importing ValidationResult compile
- [ ] DomainValidator.ts type-checks

---

## 6. `src/domain/value-objects/integrity-score.ts`

**Module path**: `src/domain/value-objects/integrity-score.ts`
**Dependencies**: None
**Consumers**: aitm/types.ts, BrowserIntegrityEvaluatorAdapter.ts, IBrowserIntegrityEvaluator.ts

### Exports

```typescript
export class IntegrityScore {
  private readonly props: IntegrityScoreProps;

  constructor(props: IntegrityScoreProps);

  get hostname(): number;
  get contentHash(): number;
  get timing(): number;
  get domIntegrity(): number;
  get cookieSecurity(): number;
  get overall(): number; // weighted average
  get evaluatedAt(): number;

  static create(
    scores: {
      hostname: number;
      contentHash: number;
      timing: number;
      domIntegrity: number;
      cookieSecurity: number;
    },
    evaluatedAt: number,
  ): IntegrityScore;

  static fromPlainObject(obj: {
    hostname: number;
    contentHash: number;
    timing: number;
    domIntegrity: number;
    cookieSecurity: number;
    evaluatedAt: number;
  }): IntegrityScore;

  toPlainObject(): { hostname: number; contentHash: number; timing: number; domIntegrity: number; cookieSecurity: number; evaluatedAt: number; overall: number };
}

interface IntegrityScoreProps {
  readonly hostname: number;
  readonly contentHash: number;
  readonly timing: number;
  readonly domIntegrity: number;
  readonly cookieSecurity: number;
  readonly evaluatedAt: number;
}
```

### Behavior

- Value object — immutable.
- `overall` computed as: `Math.round(hostname * 0.25 + contentHash * 0.30 + timing * 0.15 + domIntegrity * 0.20 + cookieSecurity * 0.10)` (mirrors WEIGHTS from aitm/types.ts).
- Scores are 0-100 integers (higher = more secure).

### Acceptance Criteria

- [ ] IntegrityScore.create({...}, Date.now()) succeeds
- [ ] overall matches expected weighted formula
- [ ] BrowserIntegrityEvaluatorAdapter.ts compiles

---

## 7. `src/domain/value-objects/fingerprint-anomaly.ts`

**Module path**: `src/domain/value-objects/fingerprint-anomaly.ts`
**Dependencies**: None
**Consumers**: aitm/types.ts, BrowserIntegrityEvaluatorAdapter.ts, IBrowserIntegrityEvaluator.ts

### Exports

```typescript
export type FingerprintAnomalyType =
  | 'content-hash-mismatch'
  | 'form-structure-modified'
  | 'script-count-anomaly'
  | 'unexpected-external-resource'
  | 'missing-expected-resource'
  | 'timestamp-skew';

export type FingerprintAnomalySeverity = 'info' | 'warning' | 'critical';

export class FingerprintAnomaly {
  private readonly props: FingerprintAnomalyProps;

  constructor(props: FingerprintAnomalyProps);

  get type(): FingerprintAnomalyType;
  get severity(): FingerprintAnomalySeverity;
  get expected(): string;
  get actual(): string;
  get description(): string;
  get detectedAt(): number;

  static create(
    type: FingerprintAnomalyType,
    severity: FingerprintAnomalySeverity,
    expected: string,
    actual: string,
    description: string,
    detectedAt: number,
  ): FingerprintAnomaly;

  toPlainObject(): { type: FingerprintAnomalyType; severity: FingerprintAnomalySeverity; expected: string; actual: string; description: string; detectedAt: number };
}

interface FingerprintAnomalyProps {
  readonly type: FingerprintAnomalyType;
  readonly severity: FingerprintAnomalySeverity;
  readonly expected: string;
  readonly actual: string;
  readonly description: string;
  readonly detectedAt: number;
}
```

### Behavior

- Value object — immutable.
- Documents a single anomaly detected in a page fingerprint comparison.
- `create()` is the only factory (no fromPlainObject needed for Phase 1).

### Acceptance Criteria

- [ ] FingerprintAnomaly.create('content-hash-mismatch', 'critical', 'old', 'new', 'desc', Date.now()) succeeds
- [ ] aitm/types.ts compiles with FingerprintAnomaly imports

---

## 8. `src/domain/utils/levenshtein.ts`

**Module path**: `src/domain/utils/levenshtein.ts`
**Dependencies**: None
**Consumers**: aitm/steps/typosquatting-step.ts, aitm/domain-validator.ts

### Exports

```typescript
export function levenshteinSimilarity(a: string, b: string): number;
```

### Behavior

- Computes Levenshtein edit distance between `a` and `b`.
- Returns `1.0 - (distance / maxLength)` — similarity score in `[0, 1]`.
- Identical strings → `1.0`, completely different → `0.0`.
- Empty strings: if both empty → `1.0`, if one empty → `0.0`.
- Hard limit: input length ≤ 100 chars (throws if exceeded).
- Reuses the same algorithm from `LevenshteinCalculator.ts` (the existing class).

### Acceptance Criteria

- [ ] levenshteinSimilarity("google", "google") === 1.0
- [ ] levenshteinSimilarity("google", "gooogle") >= 0.8
- [ ] levenshteinSimilarity("google", "example") < 0.5
- [ ] levenshteinSimilarity("", "") === 1.0
- [ ] levenshteinSimilarity("a".repeat(101), "b") throws

---

## 9. `src/domain/utils/dns-normalize.ts`

**Module path**: `src/domain/utils/dns-normalize.ts`
**Dependencies**: None
**Consumers**: aitm/steps/exact-match-step.ts, aitm/steps/typosquatting-step.ts, chrome-storage-trust-store.ts

### Exports

```typescript
export function dnsNormalize(hostname: string): string;
```

### Behavior

- Normalizes a domain name per RFC 1035:
  - Lowercase
  - Trim whitespace
  - Remove trailing dot (root zone)
  - Remove trailing dots
- Does NOT perform Punycode/IDN conversion (URL constructor handles that elsewhere).
- Simple, deterministic transformation.

### Acceptance Criteria

- [ ] dnsNormalize("Google.COM") === "google.com"
- [ ] dnsNormalize("example.com.") === "example.com"
- [ ] dnsNormalize("  Mail.Google.COM  ") === "mail.google.com"
- [ ] dnsNormalize("") === ""
- [ ] exact-match-step.ts compiles

---

## 10. `src/domain/utils/unicode-confusables.ts`

**Module path**: `src/domain/utils/unicode-confusables.ts`
**Dependencies**: None
**Consumers**: aitm/steps/confusable-detection-step.ts

### Exports

```typescript
export interface ConfusableEvidence {
  readonly char: string;
  readonly codePoint: number;
  readonly script: string;
  readonly position: number;
}

export function detectConfusables(input: string): ConfusableEvidence[];
export function stripZeroWidth(input: string): string;
```

### Behavior

**detectConfusables()**:
- Scans each character in `input`.
- Detects characters from these scripts that visually resemble Latin letters:
  - Cyrillic (U+0400–U+04FF)
  - Greek (U+0370–U+03FF) — only lookalikes (alpha, beta, etc.)
  - Arabic (U+0600–U+06FF) — selected lookalikes
  - Fullwidth forms (U+FF01–U+FF5E)
  - Latin Extended (U+0100–U+024F) — confusables with diacritics
- Returns array of evidence objects with char, codePoint, script name, and position.
- Returns empty array if no confusables found.

**stripZeroWidth()**:
- Removes zero-width characters: U+200B (ZWSP), U+200C (ZWNJ), U+200D (ZWJ), U+FEFF (BOM), U+2060 (Word Joiner), U+00AD (Soft Hyphen).

### Acceptance Criteria

- [ ] detectConfusables("google") returns []
- [ ] detectConfusables("gооgle") (Cyrillic 'о') returns evidence with script "Cyrillic"
- [ ] stripZeroWidth("hel\u200Blo") === "hello"
- [ ] confusable-detection-step.ts compiles

---

## 11. `src/domain/repositories/index.ts`

**Module path**: `src/domain/repositories/index.ts`
**Dependencies**: entities (Vault, Credential, Vulnerability), value-objects (ids)
**Consumers**: All infrastructure repositories, api/server.ts, application use-cases

### Exports

```typescript
import type { Vault } from '../entities/vault';
import type { Credential } from '../entities/credential';
import type { Vulnerability } from '../entities/vulnerability';
import type { VaultId, CredentialId, VulnerabilityId } from '../value-objects/ids';

export interface IVaultRepository {
  save(vault: Vault): Promise<Vault>;
  findById(id: VaultId): Promise<Vault | null>;
  delete(id: VaultId): Promise<boolean>;
  list(): Promise<Vault[]>;
}

export interface ICredentialRepository {
  save(credential: Credential): Promise<Credential>;
  findById(id: CredentialId): Promise<Credential | null>;
  findByVaultId(vaultId: VaultId): Promise<Credential[]>;
  delete(id: CredentialId): Promise<boolean>;
  list(): Promise<Credential[]>;
}

export interface IVulnerabilityRepository {
  save(vulnerability: Vulnerability): Promise<Vulnerability>;
  findById(id: VulnerabilityId): Promise<Vulnerability | null>;
  search(criteria: { severity?: string; status?: string; dateFrom?: Date; dateTo?: Date }): Promise<Vulnerability[]>;
  delete(id: VulnerabilityId): Promise<boolean>;
}

export interface TrustEntry {
  domain: string;
  trustLevel: 'trusted' | 'untrusted' | 'unknown';
  firstSeen?: number;
  lastSeen: number;
  fingerprint?: string;
  visitCount: number;
}

export interface ITrustStoreRepository {
  save(entry: TrustEntry): Promise<void>;
  findByDomain(domain: string): Promise<TrustEntry | null>;
  revoke(domain: string): Promise<void>;
  list(): Promise<TrustEntry[]>;
  removeExpired(maxAgeMs: number): Promise<number>;
  saveFingerprint(domain: string, fingerprint: string): Promise<void>;
  getFingerprint(domain: string): Promise<string | null>;
  removeFingerprint(domain: string): Promise<void>;
}
```

### Behavior

- Pure interface definitions — no runtime code.
- IVaultRepository matches the existing PostgresVaultRepository and ChromeStorageVaultRepository implementations.
- ICredentialRepository matches PostgresCredentialRepository.
- IVulnerabilityRepository matches InMemoryVulnerabilityRepository.
- ITrustStoreRepository matches ChromeStorageTrustStore.

### Acceptance Criteria

- [ ] All repository implementations compile
- [ ] `infrastructure/repositories/index.ts` barrel re-exports compile
- [ ] api/server.ts compiles

---

## 12. `src/domain/constants/cookie-isolation.ts`

**Module path**: `src/domain/constants/cookie-isolation.ts`
**Dependencies**: None
**Consumers**: chrome-storage-cookie-isolation-adapter.ts

### Exports

```typescript
export const COOKIE_TTL_MS: number = 30 * 60 * 1000; // 30 minutes
```

### Behavior

- Single constant — 30-minute TTL for isolated cookies.
- Used by ChromeStorageCookieIsolationAdapter to set expiration on stored entries.

### Acceptance Criteria

- [ ] chrome-storage-cookie-isolation-adapter.ts compiles
- [ ] COOKIE_TTL_MS === 1_800_000

---

## Barrel Exports (if needed)

Two barrel files are imported by existing code but don't exist:

### `src/domain/services/index.ts`

Needed for `import type { ICryptoService } from "../../domain/services"` and `import type { IIPFSService } from "../../domain/services"`.

```typescript
export type { ICryptoService, EncryptedPayload, SignedPayload } from '../ports/ICryptoService';
export type { IIPFSService } from '../ports/IIPFSService';
```

### `src/domain/value-objects/index.ts`

Optional but good practice. Re-exports all value objects for convenient imports.

---

## Dependency Graph

```
ids.ts ──────────────────────────┬── vault.ts
                                 ├── credential.ts
                                 ├── vulnerability.ts
                                 ├── all repositories
                                 └── crypto-service.ts

isolated-cookie-metadata.ts ──────── i-cookie-isolation-policy.ts
binding-signature.ts ──────────────── i-channel-binding-protocol.ts
validation-context.ts ─────────────── DomainValidator.ts + steps
domain-status.ts ──────────────────── DomainValidator.ts + steps
integrity-score.ts ────────────────── aitm/types.ts + BrowserIntegrityEvaluatorAdapter.ts
fingerprint-anomaly.ts ────────────── aitm/types.ts + BrowserIntegrityEvaluatorAdapter.ts
levenshtein.ts ────────────────────── aitm/steps/typosquatting-step.ts + domain-validator.ts
dns-normalize.ts ──────────────────── aitm/steps/exact-match-step.ts + typosquatting-step.ts + trust-store
unicode-confusables.ts ────────────── aitm/steps/confusable-detection-step.ts
repositories/index.ts ─────────────── all infrastructure repositories
constants/cookie-isolation.ts ──────── chrome-storage-cookie-isolation-adapter.ts
```

---

## Implementation Order

1. **Leaf modules first** (no dependencies):
   - `ids.ts`, `isolated-cookie-metadata.ts`, `binding-signature.ts`
   - `validation-context.ts`, `domain-status.ts`
   - `integrity-score.ts`, `fingerprint-anomaly.ts`
   - `levenshtein.ts`, `dns-normalize.ts`, `unicode-confusables.ts`
   - `constants/cookie-isolation.ts`

2. **Barrel exports** (depend on leaf modules):
   - `domain/repositories/index.ts`
   - `domain/services/index.ts` (if needed)

3. **Verification**:
   - Run `npx tsc --noEmit` from project root
   - Zero new errors (only pre-existing errors from other missing phases)
