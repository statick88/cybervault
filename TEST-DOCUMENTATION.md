# CyberVault v2 — Test Documentation

## Repository

| Property | Value |
|----------|-------|
| **GitHub** | *Por crear* — `github.com/statick88/cybervault` (recomendado) |
| **Organization** | [github.com/statick88](https://github.com/statick88) |
| **Default branch** | `main` |
| **Language** | TypeScript (Node.js 24) |
| **License** | MIT |

> ⚠️ CyberVault aún no tiene repositorio propio en GitHub. El código fuente se encuentra en `/home/search14/cybervault/`.

---

## Overview

CyberVault v2 implements a comprehensive testing strategy across three tiers: **unit tests** (isolated function/class verification), **integration tests** (multi-component interaction), and **end-to-end tests** (full browser extension workflow).

| Tier | Files | describe() | it() | Execution |
|------|-------|------------|------|-----------|
| Unit | 15 | 53 | 180 | `npm test` |
| Integration | 4 | 11 | 38 | `npm test` |
| E2E | 3 | 4 | 21 | `npx playwright test` |
| **Total** | **22** | **68** | **239** | — |

**Coverage target:** All domain logic, cryptographic operations, pipeline steps, API endpoints, and browser extension UI components.

---

## Quick Start

```bash
# Install dependencies
cd /home/search14/cybervault
npm install

# Run all tests
npm test

# Run benchmarks
npx tsx benchmarks/domain-validation.bench.ts
```

---

## Prerequisites

```bash
# Install dependencies
npm install

# E2E tests require Chrome (not Chromium)
# The extension-fixture.ts searches for Chrome binary
npx playwright install
```

---

## Running Tests

### Unit + Integration Tests

```bash
# Full test suite
npm test

# With coverage
npm test -- --coverage

# Watch mode
npm test -- --watch

# Run specific file
npx jest tests/unit/utils/levenshtein.test.ts

# Run by pattern
npx jest --testPathPattern="aitm"
```

### E2E Tests (Chrome Extension)

```bash
# All E2E tests (skips if Chrome not installed)
npx playwright test

# Specific E2E suite
npx playwright test tests/e2e/popup.spec.ts
npx playwright test tests/e2e/content-scripts.spec.ts
npx playwright test tests/e2e/background.spec.ts
```

### Benchmarks

```bash
# Domain validation benchmarks
npx tsx benchmarks/domain-validation.bench.ts

# Custom parameters
npx tsx benchmarks/domain-validation.bench.ts \
  --iterations 50000 \
  --warmup 500
```

---

## Test Architecture

```
tests/
├── jest.setup.js                    # Global test setup (NODE_ENV, JWT_SECRET)
├── unit/
│   ├── aitm/
│   │   └── pipeline-steps.test.ts   # Domain validation pipeline steps
│   ├── crypto/
│   │   ├── encryption-service.test.ts  # AES-256-GCM encrypt/decrypt
│   │   └── entropy.test.ts          # Password generation entropy
│   ├── security/
│   │   └── hibp.test.ts            # HaveIBeenPwned breach check
│   ├── shared/
│   │   ├── cache-service.test.ts    # Redis cache operations
│   │   ├── circuit-breaker.test.ts  # Circuit breaker state machine
│   │   ├── metrics.test.ts          # Prometheus metrics collector
│   │   ├── redis-client.test.ts     # Redis connection management
│   │   └── retry.test.ts           # Retry with exponential backoff
│   ├── utils/
│   │   ├── dns-normalize.test.ts    # DNS normalization (RFC 1035)
│   │   ├── levenshtein.test.ts      # Levenshtein similarity function
│   │   └── unicode-confusables.test.ts  # Unicode TR39 confusable detection
│   └── value-objects/
│       ├── binding-signature.test.ts   # Binding signature value object
│       ├── ids.test.ts              # Branded ID types (VaultId, CredentialId, etc.)
│       └── integrity-score.test.ts  # Integrity score calculation
├── integration/
│   ├── aitm-pipeline.test.ts       # Full pipeline orchestration
│   ├── api-server.test.ts          # HTTP API endpoints
│   ├── ipfs-adapter.test.ts        # IPFS upload/download/sync
│   └── swagger.test.ts            # OpenAPI documentation
├── e2e/
│   ├── fixtures/
│   │   └── test-page.html          # HTML fixture for content scripts
│   ├── helpers/
│   │   └── extension-fixture.ts    # Playwright Chrome Extension fixture
│   ├── background.spec.ts          # Service worker message handling
│   ├── content-scripts.spec.ts     # inject.ts + autocomplete.ts
│   └── popup.spec.ts              # Extension popup UI
└── benchmarks/
    ├── domain-validation.bench.ts  # Performance benchmarks
    └── datasets/
        ├── synthetic.json          # 47 synthetic scenarios
        └── real-world.json         # 28 real-world phishing domains
```

---

## Unit Tests (180 test cases)

### Domain Validation Pipeline (`tests/unit/aitm/pipeline-steps.test.ts`)

Tests the three-phase domain validation pipeline that is the core phishing prevention mechanism.

**ExactMatchStep** (7 tests):
- Correct step name (`"ExactMatch"`)
- Returns `valid` for exact domain match
- Case normalization before matching (RFC 1035)
- Trailing dot handling (`google.com.` → `google.com`)
- Subdomain validation (allows `mail.google.com` for trusted `google.com`)
- Returns `invalid` for non-matching domain
- Returns `invalid` for visually similar but different domain

**ConfusableDetectionStep** (5 tests):
- Correct step name (`"ConfusableDetection"`)
- Returns `valid` for clean ASCII domain
- Returns `invalid` for Cyrillic homograph attack (e.g., `аpple.com` with Cyrillic `а`)
- Returns `invalid` for Greek characters
- Strips zero-width characters before detection
- Returns high risk for mixed Cyrillic/Latin

**TyposquattingStep** (6 tests):
- Correct step name (`"LevenshteinTypoSquatting"`)
- Returns `valid` for exact registrable domain match
- Returns `invalid` for very similar domain above threshold (0.85)
- Returns `valid` for very different domain below threshold
- Strips common TLDs (`.com`, `.org`, `.net`) before comparison
- Respects custom threshold
- Handles subdomains by extracting registrable domain

### Cryptography (`tests/unit/crypto/`)

**EncryptionService** (`encryption-service.test.ts`, 8 tests):
- Returns base64-encoded output
- Produces valid GCM format: `salt|iv|ciphertext` (3 components)
- Round-trip: `decrypt(encrypt(data, key), key) === data`
- Round-trip with Unicode content
- Throws `"Decryption failed"` with wrong key
- Throws with tampered ciphertext
- Different encryptions of same data produce different ciphertexts (random salt/IV)
- Throws with empty ciphertext

**Entropy** (`entropy.test.ts`, 8 tests):
- Generates passwords with high entropy (≥32 chars, upper+lower+digit+special)
- Generates 100 unique passwords (no duplicates)
- Achieves target entropy of 128+ bits
- Produces valid credentials via `generateCredentials`
- Validates salt and pepper entropy (≥128 bits)
- Analyzes credential quality with sufficient entropy
- Rejects invalid domain format
- Round-trips credentials through extract

### Unicode Confusables (`tests/unit/utils/unicode-confusables.test.ts`, 15 tests)

**Zero-width character stripping** (6 tests):
- Removes ZERO WIDTH SPACE (U+200B)
- Removes ZERO WIDTH NON-JOINER (U+200C)
- Removes ZERO WIDTH JOINER (U+200D)
- Removes BOM (U+FEFF)
- Removes WORD JOINER (U+2060)
- Removes SOFT HYPHEN (U+00AD)

**Confusable detection** (9 tests):
- Returns empty array for plain ASCII
- Returns empty array for empty string
- Detects Cyrillic 'а' (U+0430) resembling Latin 'a'
- Detects multiple Cyrillic characters
- Detects Greek omicron (U+03BF) resembling Latin 'o'
- Detects both Cyrillic and Greek in same string
- Detects fullwidth Latin letters
- Returns correct index for detected character
- Includes `codePoint` in evidence

### Levenshtein Similarity (`tests/unit/utils/levenshtein.test.ts`, 15 tests)

- Returns 1.0 for identical non-empty strings
- Returns 1.0 for two empty strings
- Returns 0.0 when first string is empty
- Returns 0.0 when second string is empty
- Returns high similarity for one substitution
- Returns high similarity for one insertion
- Returns high similarity for one deletion
- Returns low similarity for very different strings
- Returns 0.0 for completely different single characters
- Throws when first input exceeds 100 chars
- Throws when second input exceeds 100 chars
- Accepts exactly 100 characters
- Handles single character strings
- Handles case sensitivity
- Handles longer identical strings

### DNS Normalization (`tests/unit/utils/dns-normalize.test.ts`, 12 tests)

- Lowercases uppercase hostname
- Lowercases mixed-case hostname
- Leaves lowercase unchanged
- Removes trailing dot
- Removes trailing dot from mixed case
- Does not remove dots in the middle
- Trims leading whitespace
- Trims trailing whitespace
- Trims both leading and trailing whitespace
- Trims tabs
- Applies lowercase, trim, and trailing dot removal together
- Handles single character hostname

### Resilience Patterns (`tests/unit/shared/`)

**Retry** (`retry.test.ts`, 7 tests):
- Succeeds on first attempt without retrying
- Retries on failure and eventually succeeds
- Exhausts maxAttempts and throws the last error
- Respects custom delay by using exponential backoff
- Breaks early on non-retryable error when `retryableErrors` is set
- Retries when error matches `retryableErrors` pattern
- Wraps non-Error throws into Error objects

**Circuit Breaker** (`circuit-breaker.test.ts`, 8 tests):
- Starts in CLOSED state
- Opens after reaching failure threshold
- Transitions to HALF_OPEN after resetTimeout elapses
- Closes again after success in HALF_OPEN
- `execute()` passes through result on success
- `execute()` throws when circuit is OPEN
- Success in HALF_OPEN resets failure count
- `reset()` returns circuit to CLOSED state

**Cache Service** (`cache-service.test.ts`, 13 tests):
- Returns null for missing keys
- Stores and retrieves JSON values
- Sets with custom TTL
- Returns false when Redis unavailable (graceful degradation)
- Returns null when Redis unavailable
- Stores value with TTL
- Deletes keys
- Returns 0 when Redis unavailable
- Returns true for existing keys
- Returns false for missing keys
- Returns multiple values
- Returns all null when Redis unavailable
- Deletes all prefixed keys
- Prepends prefix to all keys

**Metrics** (`metrics.test.ts`, 14 tests):
- Creates a counter with value 1 on first call
- Increments counter on subsequent calls
- Tracks counters with different labels separately
- Sets gauge value
- Overwrites gauge value on subsequent calls
- Tracks gauges with labels independently
- Records observations and produces bucket output
- Calculates sum correctly
- Tracks histograms with labels
- Produces valid Prometheus text format with HELP and TYPE
- Only emits HELP/TYPE once per metric family
- Returns empty string when no metrics exist
- Clears all metrics
- Returns series data for a named metric

**Redis Client** (`redis-client.test.ts`, 5 tests):
- Returns null client when REDIS_HOST is not set
- Returns null when not connected
- Connects when REDIS_HOST is set
- Disconnects gracefully
- Does not throw on disconnect when no client

### Value Objects (`tests/unit/value-objects/`)

**IDs** (`ids.test.ts`, 16 tests):
- VaultId: generates unique IDs, creates from string, throws on empty, equality
- CredentialId: same pattern
- VulnerabilityId: same pattern
- CryptoHash: creates from string, throws on empty, equality

**BindingSignature** (`binding-signature.test.ts`, 13 tests):
- Creates valid signature with normalized domain
- Trims whitespace from domain
- Throws on empty/whitespace-only domain
- Throws on zero/negative timestamp
- Throws on empty nonce/signature
- Returns true when within age window
- Returns false when timestamp exceeds max age
- Roundtrips through plain object
- Is frozen after creation

**IntegrityScore** (`integrity-score.test.ts`, 11 tests):
- Creates with all scores at 100/0
- Throws on zero/negative evaluatedAt
- Computes correct weighted average (contentHash=0.30, cookieSecurity=0.10)
- Clamps individual scores [0, 100]
- Rounds the overall score
- Roundtrips through plain object
- Is frozen after creation

### Security (`tests/unit/security/`)

**HIBP** (`hibp.test.ts`, 3 tests):
- Checks password against HIBP API
- Handles unique passwords (not breached)
- Fails open on API errors (always returns a result)

---

## Integration Tests (38 test cases)

### API Server (`tests/integration/api-server.test.ts`, 18 tests)

Tests the full HTTP API using `supertest`.

**Auth endpoints:**
- `POST /api/v1/auth/register` — registers new user (201)
- `POST /api/v1/auth/register` — rejects duplicate email (200, anti-enumeration)
- `POST /api/v1/auth/register` — rejects missing fields (400)
- `POST /api/v1/auth/register` — rejects short password (400)
- `POST /api/v1/auth/register` — rejects invalid email (400)
- `POST /api/v1/auth/login` — logs in with valid credentials (200 + JWT)
- `POST /api/v1/auth/login` — rejects wrong password (401)
- `POST /api/v1/auth/login` — rejects non-existent user (401)
- `POST /api/v1/auth/login` — rejects missing fields (400)

**Vault CRUD:**
- `POST /api/v1/vaults` — creates a vault (201)
- `GET /api/v1/vaults` — lists vaults (200)
- `GET /api/v1/vaults/:id` — gets vault by ID (200)
- `GET /api/v1/vaults/:id` — returns 404 for non-existent vault
- `DELETE /api/v1/vaults/:id` — deletes a vault (200)
- `DELETE /api/v1/vaults/:id` — returns 404 when deleting non-existent
- `POST /api/v1/vaults` — rejects missing required fields (400)

**Credentials:**
- `POST /api/v1/credentials/generate` — generates credentials (201)
- `POST /api/v1/credentials/generate` — rejects missing domain (400)

**Health/misc:**
- `GET /health` — returns 200
- `GET /ready` — returns 200
- `GET /api` — returns API info
- Returns 404 for unknown routes

### AiTM Pipeline Integration (`tests/integration/aitm-pipeline.test.ts`, 13 tests)

Tests the full pipeline orchestration with real step instances.

- Allows exact match
- Allows subdomains of trusted domain
- Allows different trusted domain
- Detects single-character substitution (typosquatting)
- Detects character duplication
- Detects character omission
- Does not flag very different domains
- Detects Cyrillic homograph
- Allows clean ASCII domains
- Short-circuits on exact match (performance optimization)
- Reports per-step confidence [0, 1]
- Respects global timeout
- Handles empty hostname / trailing dot / case-insensitive

### Swagger (`tests/integration/swagger.test.ts`, 5 tests)

- `GET /api/docs` returns HTML (Swagger UI)
- `GET /api/docs/openapi.json` returns valid JSON
- OpenAPI spec contains all 13 expected paths
- OpenAPI spec has `bearerAuth` security scheme
- OpenAPI spec has 10 data schemas defined

### IPFS Adapter (`tests/integration/ipfs-adapter.test.ts`, 12 tests)

Tests IPFS operations with real node (skipped if no IPFS) and in-memory fallback.

**Real IPFS (when `IPFS_API_URL` set):**
- Uploads a string and returns a CID
- Uploads a Uint8Array and returns a CID
- Uploads encrypted data by default
- Downloads previously uploaded data
- Throws when CID does not exist
- Lists pinned CIDs after upload
- Returns an array when no CIDs exist
- Unpins a CID
- Returns false for non-existent CID

**Fallback mode (when IPFS unavailable):**
- Uses in-memory store
- Sync returns zeros

---

## End-to-End Tests (21 test cases)

E2E tests use Playwright to launch a real Chrome browser with the extension loaded. Tests skip automatically if Chrome is not installed.

### Test Fixture (`tests/e2e/helpers/extension-fixture.ts`)

Provides:
- `extensionContext` — Chromium persistent context with extension loaded
- `serviceWorker` — background service worker handle
- `extensionId` — extracted from service worker URL
- `openPopup()` — opens popup via `chrome-extension://` URL
- `openTestPage()` — opens HTML fixture page
- `skipIfNoChrome()` — guard for skipping when Chrome unavailable

### Popup UI (`tests/e2e/popup.spec.ts`, 9 tests)

- Popup opens successfully (title = "CyberVault")
- Shows lock screen with password input
- Shows error when unlocking without vault ("No vault found")
- Unlocked view is hidden initially
- Lock icon shows locked state
- Clicking lock toggle shows lock screen
- Settings link is present
- Add button exists in unlocked view structure
- Add form elements exist (title/username/password/url/save/cancel)

### Content Scripts (`tests/e2e/content-scripts.spec.ts`, 7 tests)

**inject.ts:**
- Detects login forms on the page
- Submit button triggers form submit event
- Page has correct form structure for content script detection
- Form has proper input names for field detection

**autocomplete.ts:**
- Detects credential fields in a login form
- Password field has expected attributes (`type="password"`)
- Username field has user-related attributes (name/id/autocomplete)

### Background Service Worker (`tests/e2e/background.spec.ts`, 5 tests)

- Service worker loads successfully (URL matches `chrome-extension://`)
- Responds to `VALIDATE_DOMAIN` message
- Responds to `GET_TRUST_STATUS` message
- Responds to `UNLOCK_VAULT` message
- Returns error for unknown message type

---

## Benchmarks

### Domain Validation (`benchmarks/domain-validation.bench.ts`)

Measures performance of the three-phase domain validation pipeline.

**Metrics captured:**
- Exact-match latency (mean, p95, p99)
- Similarity analysis latency (mean, p95, p99)
- Throughput (comparisons/second)
- Memory usage

**Datasets:**
- `benchmarks/datasets/synthetic.json` — 47 scenarios (20 legitimate, 20 typosquatting, 4 homograph, 3 unknown)
- `benchmarks/datasets/real-world.json` — 28 real-world phishing domains

**Results:**
- Exact-match latency: 0.003 ms
- Similarity latency: 0.005 ms
- Throughput: 328,103 exact-match / 185,688 similarity per second

---

## Test Configuration

### Jest (`jest.config.js`)

```javascript
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/tests'],
  testMatch: ['**/*.test.ts'],
  setupFilesAfterSetup: ['<rootDir>/tests/jest.setup.js'],
  collectCoverageFrom: ['src/**/*.ts', '!src/**/*.d.ts'],
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80,
    },
  },
};
```

### Playwright (`playwright.config.ts`)

```typescript
export default {
  testDir: './tests/e2e',
  testMatch: '*.spec.ts',
  timeout: 30_000,
  retries: 0,
  use: {
    headless: false,  // Chrome Extension requires headed mode
  },
};
```

---

## Test Patterns

### Mocking

- **Value objects**: Mocked via `jest.mock("../../src/domain/value-objects/ids")`
- **Redis**: Full `ioredis` mock with in-memory `Map<string, string>` store
- **IPFS**: Conditional test execution based on `IPFS_API_URL` env var
- **HTTP**: `supertest` wraps the server for integration tests
- **Browser**: Playwright with real Chrome + extension loaded

### Graceful Degradation

Many tests verify graceful behavior when dependencies are unavailable:
- Redis unavailable → null/false/0 returns (no exceptions)
- IPFS unavailable → in-memory fallback
- Chrome unavailable → tests skip (not fail)

### Test Data

- Synthetic phishing scenarios: `benchmarks/datasets/synthetic.json`
- Real-world phishing domains: `benchmarks/datasets/real-world.json`
- HTML fixture: `tests/e2e/fixtures/test-page.html`

---

## CI/CD Integration (GitHub Actions)

### Required Workflows

Create `.github/workflows/test.yml`:

```yaml
name: Tests

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  unit-integration:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        node-version: [22, 24]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: ${{ matrix.node-version }}
          cache: 'npm'
      - run: npm ci
      - run: npm test
      - name: Upload coverage
        if: matrix.node-version == 24
        uses: actions/upload-artifact@v4
        with:
          name: coverage
          path: coverage/
          retention-days: 7

  e2e:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 24
          cache: 'npm'
      - run: npm ci
      - name: Install Chrome
        uses: browser-actions/setup-chrome@v1
        with:
          chrome-version: stable
      - run: npx playwright install --with-deps
      - run: npx playwright test
      - name: Upload test results
        if: failure()
        uses: actions/upload-artifact@v4
        with:
          name: playwright-report
          path: playwright-report/
          retention-days: 7

  benchmarks:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 24
          cache: 'npm'
      - run: npm ci
      - name: Run benchmarks
        run: npx tsx benchmarks/domain-validation.bench.ts
      - name: Upload benchmark results
        uses: actions/upload-artifact@v4
        with:
          name: benchmark-results
          path: benchmarks/results/
          retention-days: 30
```

### Required Secrets

| Secret | Purpose |
|--------|---------|
| `CODECOV_TOKEN` | Coverage upload (optional) |

### GitHub Features

- **Dependabot**: Auto-updates npm dependencies (`.github/dependabot.yml`)
- **Branch protection**: Require PR reviews + status checks on `main`
- **Issue templates**: Bug report + feature request (`.github/ISSUE_TEMPLATE/`)
- **PR template**: Checklist for tests + documentation (`.github/PULL_REQUEST_TEMPLATE.md`)

---

## Project Structure

```
cyber-guardians/
├── .github/
│   ├── workflows/
│   │   └── test.yml           # CI/CD pipeline
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md
│   │   └── feature_request.md
│   ├── PULL_REQUEST_TEMPLATE.md
│   └── dependabot.yml
├── src/                       # Source code (107 files, 14,829 LOC)
│   ├── domain/                # Business logic
│   ├── application/           # Use cases
│   ├── infrastructure/        # External services
│   └── ui/                    # Browser extension
├── tests/                     # Test suite (22 files, 239 tests)
│   ├── unit/
│   ├── integration/
│   └── e2e/
├── benchmarks/                # Performance benchmarks
│   ├── datasets/
│   └── results/
├── dist/                      # Built extension
├── paper-v2-final.md          # Research paper
├── TEST-DOCUMENTATION.md      # This file
└── package.json
```

---

## Badges

Add to `README.md`:

```markdown
[![Tests](https://github.com/statick88/cyber-guardians/actions/workflows/test.yml/badge.svg)](https://github.com/statick88/cyber-guardians/actions/workflows/test.yml)
[![Coverage](https://codecov.io/gh/statick88/cyber-guardians/branch/main/graph/badge.svg)](https://codecov.io/gh/statick88/cyber-guardians)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
```
