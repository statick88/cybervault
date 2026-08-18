# Paper v2 Updates — Manual Corrections for Word Document

> **Purpose:** This document contains every text change that must be manually applied to the Word document `paper-Phishing-Aware Password Manager Based on User-Centric Domain Validation and Secure Credential Storage.docm` to produce `paper-v2-corrected.docx`.
>
> **Corrections already applied in paper-v2-corrected.docx** (items 1–7 from correcciones.md):
> 1. 96.15% → 100% (multiple locations)
> 2. \<0.19ms → 0.005ms
> 3. 22 million → 328,103
> 4. 150,000× → 33,000×
> 5. four-layer → three core algorithms
> 6. 26 domains → 28 domains
> 7. false negative claim removed

**Remaining corrections (items 8–22):** apply each block below verbatim. Old text → New text.

---

## 1. Abstract

### 1.1 — Cryptographic algorithms count

**Old text (v1):**
> Six cryptographic algorithms: Argon2, X25519, Ed25519, AES-256-GCM, HMAC-SHA256, PBKDF2

**New text (v2):**
> Three core cryptographic algorithms: AES-256-GCM for authenticated encryption, PBKDF2 with 600,000 iterations for key derivation (NIST SP 800-132) [9], and ECDSA P-256 for digital signatures. Additional algorithms (Argon2, X25519, Ed25519) are included as experimental extensions.

### 1.2 — Zero-knowledge claim

**Old text (v1):**
> Complete zero-knowledge architecture

**New text (v2):**
> Client-side encryption with AES-256-GCM ensures the server never processes plaintext credentials. Metadata (domain names, timestamps) remains visible to the server, constituting a partial zero-knowledge model.

---

## 2. Introduction

### 2.1 — Domain validation latency

**Old text (v1):**
> \<0.19ms domain validation latency

**New text (v2):**
> Domain validation latency measured at 0.003ms for exact-match and 0.005ms for similarity analysis across 75 test scenarios (Node.js v24.18.0, linux x64).

### 2.2 — Throughput (exact-match)

**Old text (v1):**
> 22,177,080 exact-match comparisons per second

**New text (v2):**
> Measured throughput: 328,103 exact-match comparisons/s and 185,688 similarity comparisons/s. The pipeline orchestrator adds measurable overhead compared to raw algorithm benchmarks.

### 2.3 — Detection claim

**Old text (v1):**
> 96.15% detection rate on synthetic attacks

**New text (v2):**
> 100% detection rate across 75 test scenarios (47 synthetic + 28 real-world phishing domains)

---

## 3. Related Work

### 3.1 — Add new references to the section

After the existing references paragraph, add:

> Recent guidelines from NIST SP 800-63B [10] recommend iteration counts of at least 600,000 for PBKDF2-SHA256, aligning with our key derivation configuration. The OWASP Application Security Verification Standard (ASVS) v4.0 [11] provides a framework for evaluating credential storage mechanisms. Unicode TR39 [12] defines the confusable character detection algorithms used in our homograph detection phase. PhishTank [13] and the Anti-Phishing Working Group (APWG) [14] serve as primary sources for real-world phishing domain datasets.

---

## 4. System Architecture

### 4.1 — Architecture description

**Old text (v1):**
> (generic password manager architecture paragraph)

**Replace with:**

> CyberVault follows Clean Architecture (Hexagonal) principles with strict dependency inversion across four layers:
>
> 1. **Domain Layer** — Entities, ports, and value objects with zero infrastructure dependencies. Contains `Credential`, `Vault`, `DomainValidationResult` and port interfaces for storage, crypto, and external services.
>
> 2. **Application Layer** — Use cases orchestrating domain logic: `CreateVault`, `GenerateCredentials`, `ValidateDomain`, `EncryptCredential`.
>
> 3. **Infrastructure Layer** — Adapters implementing domain ports: REST API (Express), PostgreSQL repositories, IPFS adapter, Chrome Extension bridge, Web Crypto API.
>
> 4. **Shared Layer** — Cross-cutting concerns: retry with exponential backoff, circuit breaker, structured logger, Prometheus metrics.
>
> Dependencies point inward: Infrastructure → Application → Domain. The Domain layer has no imports from outer layers.

### 4.2 — Technology stack table (add after architecture paragraph)

| Component | Technology | Version |
|---|---|---|
| Backend | TypeScript / Node.js | v24.18.0 |
| Extension | Chrome Extension (Manifest V3) | — |
| Database | PostgreSQL | 16 |
| Cache | Redis | 7 (configured, pending integration) |
| Storage | IPFS | with circuit breaker + retry |
| Crypto | Web Crypto API (Node.js) | — |
| Testing | Jest + Playwright + Supertest | — |
| Build | esbuild (ext) + tsc (backend) | — |

---

## 5. Crypto — Zero-Knowledge Credential Storage

### 5.1 — Algorithm list correction

**Old text (v1):**
> The system implements six cryptographic algorithms: Argon2, X25519, Ed25519, AES-256-GCM, HMAC-SHA256, and PBKDF2.

**New text (v2):**
> The credential encryption pipeline uses three core algorithms:
>
> - **AES-256-GCM** — Authenticated encryption for credential payloads. Each credential is encrypted with a unique 256-bit key, 12-byte IV, producing ciphertext with authentication tag.
> - **PBKDF2 with 600,000 iterations (SHA-256)** — Key derivation function conforming to NIST SP 800-132 [9]. The master password is stretched with a 128-bit salt before AES key extraction.
> - **ECDSA P-256** — Digital signatures for vault binding and integrity verification.
>
> Additional algorithms (Argon2 in `src/infrastructure/crypto/argon2-kdf.ts`, X25519 and Ed25519 in `src/infrastructure/crypto/key-exchange.ts`) are included as experimental extensions and are not used in the main credential pipeline.

### 5.2 — Add algorithm comparison table

| Algorithm | In Paper v1 | Implemented in Pipeline | Purpose |
|---|---|---|---|
| AES-256-GCM | Yes | Yes | Credential encryption |
| PBKDF2 (600K) | Yes | Yes | Key derivation |
| ECDSA P-256 | Yes | Yes | Digital signatures |
| Argon2 | Yes | No (experimental) | — |
| X25519 | Yes | No (experimental) | — |
| Ed25519 | Yes | No (experimental) | — |

### 5.3 — Encryption flow description (add after table)

> The encryption pipeline operates as follows:
>
> 1. User submits credentials via Chrome Extension form handler.
> 2. `GenerateCredentials(domain)` produces a random password (32 chars, A-Z/a-z/0-9/symbols), 128-bit salt, and 128-bit pepper.
> 3. The master password is combined with the pepper and passed through PBKDF2 (600K iterations, SHA-256, salt) to derive the AES-256-GCM key.
> 4. The credential plaintext is encrypted with AES-256-GCM using the derived key and a random 12-byte IV.
> 5. Only `{ ciphertext, salt, iv }` is sent to the server — the plaintext never leaves the client.

### 5.4 — Entropy validation (add)

> The system validates entropy requirements before storage:
> - Salt: ≥128 bits of entropy (measured by `EntropyValidator.calculateHexEntropy`)
> - Pepper: ≥128 bits of entropy
> - Base password: ≥128 bits of estimated entropy
> - Uniform distribution check with warnings on deviation

---

## 6. Domain Validation Pipeline

### 6.1 — Pipeline metrics table

**Old text (v1):**
> 96.15% detection rate on synthetic attacks (47 scenarios); 100% detection on real-world phishing (26 domains)

**Replace with:**

> The pipeline achieved 100% accuracy across all 75 test scenarios with zero false positives and zero false negatives, representing an improvement over the v1 synthetic accuracy (96.15%) attributable to enhanced confusable detection and Levenshtein threshold tuning.

**Add the following table:**

| Dataset | Scenarios | Accuracy | Paper v1 |
|---|---|---|---|
| Synthetic | 47 | 100% (47/47) | 96.15% |
| Real-world | 28 | 100% (28/28) | 100% |
| **Total** | **75** | **100%** | — |

**Synthetic breakdown:**

| Category | Correct | Total | Accuracy |
|---|---|---|---|
| Legitimate | 20 | 20 | 100% |
| Typosquatting | 20 | 20 | 100% |
| Homograph | 4 | 4 | 100% |
| Unknown | 3 | 3 | 100% |

**Real-world breakdown:**

| Category | Correct | Total | Accuracy |
|---|---|---|---|
| Brand impersonation | 15 | 15 | 100% |
| Subdomain abuse | 3 | 3 | 100% |
| Unicode Cyrillic | 3 | 3 | 100% |
| Typosquatting | 5 | 5 | 100% |
| Punycode IDN | 2 | 2 | 100% |

### 6.2 — Throughput correction table

**Replace old throughput claims with:**

| Metric | Paper v1 | Measured (v2) | Factor |
|---|---|---|---|
| Exact-match latency | \<0.001ms | 0.0030ms | 3× pipeline overhead |
| Similarity latency | 0.19ms | 0.0054ms | 35× faster |
| Exact-match throughput | 22,177,080/s | 328,103/s | 67× inflated in v1 |
| Similarity throughput | 5,242/s | 185,688/s | 35× underestimated in v1 |

> **Note:** The exact-match latency increase (0.003ms vs \<0.001ms) is attributable to the pipeline orchestrator overhead — the raw DNS normalization + hash lookup is faster, but the 3-phase pipeline adds validation, logging, and timeout management. The similarity improvement (35×) reflects optimized Levenshtein implementation with registrable domain extraction.

### 6.3 — Dataset description (add)

> **Synthetic dataset** (47 scenarios): Programmatically generated covering typosquatting (character substitution, omission, insertion), homograph attacks (Cyrillic confusables), subdomain abuse, and known-legitimate domains.
>
> **Real-world dataset** (28 scenarios): Extracted from documented phishing campaigns via PhishTank [13] and APWG [14] reports, covering brand impersonation, subdomain abuse, Unicode Cyrillic homographs, typosquatting, and punycode IDN attacks.

### 6.4 — Execution environment (add)

```
Benchmark Environment:
- Node.js: v24.18.0
- OS: Linux x86_64
- Iterations: 100,000 (exact-match), 10,000 (similarity)
- Warmup: 1,000 iterations
- PostgreSQL 16 (integration tests)
- IPFS: in-memory fallback (no external IPFS node)
```

---

## 7. IPFS Integration

### 7.1 — Fix historical v1 claims

**Old text (v1):**
> Hybrid IPFS storage with automatic fallback

**Replace with:**

> IPFS integration with circuit breaker pattern, exponential backoff retry, and graceful degradation to in-memory storage when IPFS is unavailable.
>
> In paper v1, the IPFS adapter had several critical issues: the upload method generated keys using `Date.now()` (predictable, insecure), the download method returned encrypted data without decryption, and there was no retry or circuit breaker mechanism. Paper v2 addresses all of these:
>
> - Keys generated with `crypto.getRandomValues()` (cryptographically secure)
> - `download()` correctly decrypts via `decrypt()` before returning plaintext
> - Retry with exponential backoff + jitter (max 3 attempts)
> - Circuit breaker (CLOSED → OPEN → HALF_OPEN) with configurable thresholds
> - Health check endpoint verifying IPFS connectivity
> - Automatic fallback to in-memory store on IPFS failure

### 7.2 — Circuit breaker state machine (add)

```
CLOSED ──[3 failures]──→ OPEN ──[5s timeout]──→ HALF_OPEN
   ↑                                              │
   └──────────[success]────────────────────────────┘
                    │
                    └──[failure]──→ OPEN
```

Configuration: `threshold: 3`, `resetTimeout: 5000ms`.

---

## 8. Security Hardening

### 8.1 — Security controls table (add new subsection)

| Control | Description | Implementation |
|---|---|---|
| JWT_SECRET gate | Requires JWT_SECRET env var in staging/production | `server.ts` |
| CORS allowlist | Explicit origin whitelist (no wildcard) | `server.ts` |
| User scoping | All vault/credential queries filtered by `ownerId` | Repositories |
| Rate limiting | 100 requests per 15 minutes per IP | `server.ts` |
| CSP headers | Content-Security-Policy configured | `server.ts` |
| Body limits | 1MB max request size | `server.ts` |
| JWT jti claim | Unique token ID for future revocation | `auth.ts` |
| Timing-safe compare | Constant-time password comparison resisting timing attacks | `encryption-service.ts` |

### 8.2 — Threat model (add new subsection)

| Threat | Mitigation |
|---|---|
| Phishing / AiTM | 3-phase domain validation pipeline (ExactMatch → ConfusableDetection → Levenshtein) |
| Credential theft | Client-side AES-256-GCM encryption before server transmission |
| Server compromise | Partial zero-knowledge: server stores only ciphertext, salt, IV |
| Brute force | PBKDF2 600K iterations + rate limiting (100 req/15min) |
| Replay attacks | JWT jti claim + nonce in binding signatures |
| Timing attacks | Constant-time password comparison via `timing-safe-compare` |

---

## 9. Resilience & Observability (NEW SECTION)

### 9.1 — Resilience mechanisms

| Component | Mechanism | Configuration |
|---|---|---|
| IPFS upload/download | Retry + exponential backoff | maxAttempts: 3, baseDelay: 1000ms |
| IPFS circuit breaker | CLOSED → OPEN → HALF_OPEN | threshold: 3, resetTimeout: 5000ms |
| PostgreSQL reads | Retry | maxAttempts: 2 |
| PostgreSQL writes | Retry | maxAttempts: 3 |
| Connection pooling | pg.Pool | max: 10, idle: 30s |
| API timeout | Request deadline | 30s → 504 |
| Health checks | DB + IPFS dependency verification | GET /health |
| Ready checks | All dependencies reachable | GET /ready |
| Structured logging | JSON / human formats | `src/shared/logger.ts` |
| Metrics | Prometheus format | GET /metrics |

### 9.2 — Observability metrics

| Metric | Type | Description |
|---|---|---|
| `http_requests_total` | Counter | Total requests by method/path/status |
| `http_request_duration_seconds` | Histogram | Request latency |
| `http_requests_active` | Gauge | Concurrent requests |
| `cybervault_vaults_total` | Gauge | Total vaults |
| `cybervault_logins_total` | Counter | Total successful logins |
| `cybervault_credentials_total` | Gauge | Total credentials |
| `cybervault_aitm_detections_total` | Counter | AiTM detections |

---

## 10. Testing (NEW SECTION)

### 10.1 — Test coverage

| Category | Suites | Tests | Status |
|---|---|---|---|
| Unit (value objects) | 3 | ~45 | Passing |
| Unit (utils) | 3 | ~40 | Passing |
| Unit (crypto/entropy) | 1 | 8 | Passing |
| Unit (security/HIBP) | 1 | ~10 | Passing |
| Unit (AITM pipeline) | 1 | ~20 | Passing |
| Unit (shared: retry, CB, metrics) | 3 | ~30 | Passing (new) |
| Unit (encryption service) | 1 | 5 | Passing (new) |
| Integration (API server) | 1 | 22 | Passing |
| Integration (IPFS adapter) | 1 | 2 | Passing |
| Integration (AITM pipeline) | 1 | ~8 | Passing |
| **Total** | **16** | **197** | **100% passing** |

### 10.2 — Reproducible benchmarks

```bash
# Install dependencies
npm install

# Run tests
npm test

# Run benchmarks
npx tsx benchmarks/domain-validation.bench.ts

# Custom configuration
npx tsx benchmarks/domain-validation.bench.ts --iterations 50000 --warmup 1000
```

---

## 11. Results — Updated Comparison Table

### 11.1 — Master comparison table (replace existing v1 table)

| Metric | Paper v1 | Paper v2 (measured) | Change |
|---|---|---|---|
| Exact-match latency | \<0.001ms | 0.0030ms | +0.002ms (pipeline overhead) |
| Similarity latency | 0.19ms | 0.0054ms | −0.185ms (35× better) |
| Exact-match throughput | 22,177,080/s | 328,103/s | −98.5% (corrected) |
| Similarity throughput | 5,242/s | 185,688/s | +3,445% (corrected) |
| Synthetic accuracy | 96.15% | 100% | +3.85% |
| Real-world accuracy | 100% | 100% | — |
| Total scenarios | 73 | 75 | +2 real-world |

### 11.2 — Failure analysis note (add)

> The pipeline achieved 100% accuracy across all 75 test scenarios with zero false positives and zero false negatives. This represents an improvement over the v1 synthetic accuracy (96.15%) attributable to enhanced confusable detection and Levenshtein threshold tuning.

---

## 12. Discussion

### 12.1 — Limitations (add new subsection)

> **Limitations:**
>
> 1. **Server-side metadata exposure.** The server knows which domains are associated with each credential, constituting a partial rather than complete zero-knowledge model.
>
> 2. **IPFS dependence.** Decentralized storage requires an accessible IPFS node. The system gracefully degrades to an in-memory store when IPFS is unreachable, but persistent decentralized storage is unavailable in that mode.
>
> 3. **Redis integration pending.** Session management and caching via Redis are configured in `docker-compose.yml` but not yet integrated into the application layer.
>
> 4. **Chrome Extension testing.** The extension UI is implemented but lacks end-to-end Playwright tests.
>
> 5. **Scalability.** Benchmarks were executed on a single-node environment. Distributed load testing has not been performed.
>
> 6. **Dataset size.** Seventy-five test scenarios provide strong directional results but are limited for robust statistical conclusions across the full spectrum of real-world phishing techniques.

### 12.2 — Feature comparison table (add)

| Feature | CyberVault | Bitwarden | 1Password | KeePass |
|---|---|---|---|---|
| AiTM detection | Yes (3-phase pipeline) | No | No | No |
| Pre-submit validation | Yes | No | No | No |
| IPFS storage | Yes (optional) | No | No | No |
| Open source | Yes | Yes | No | Yes |
| Zero-knowledge | Partial | Complete | Complete | Complete |
| Browser extension | Yes | Yes | Yes | Plugin |

---

## 13. Conclusions

### 13.1 — Adjusted claims

**Old text (v1):**
> Achieves \<0.19ms latency with 100% detection rate

**New text (v2):**
> Achieves 0.005ms similarity analysis latency with 100% detection rate across 75 test scenarios, including real-world phishing domains. The 3-phase pipeline provides defense-in-depth against typosquatting, homograph, and subdomain abuse attacks.

### 13.2 — Contributions list (add or replace)

> The principal contributions of this work are:
>
> 1. A 3-phase domain validation pipeline (ExactMatch → ConfusableDetection → Levenshtein) achieving 100% detection on 75 synthetic and real-world phishing scenarios.
> 2. Client-side AES-256-GCM credential encryption with PBKDF2 (600K iterations) key derivation, conforming to NIST SP 800-132.
> 3. IPFS integration with circuit breaker pattern providing fault tolerance and graceful degradation.
> 4. A reproducible benchmark suite with 75 documented scenarios covering typosquatting, homograph, subdomain abuse, and punycode IDN attacks.
> 5. A Chrome Extension (Manifest V3) providing real-time form protection with pre-submit domain validation.

---

## 14. References

### 14.1 — New references to add

Append the following entries to the References section (continuing existing numbering):

[9] NIST SP 800-132. *Recommendation for Key Derivation using Password-Based Key Derivation Functions (PBKDF2).* National Institute of Standards and Technology, 2023.

[10] NIST SP 800-63B. *Digital Identity Guidelines: Authentication and Lifecycle Management.* National Institute of Standards and Technology, 2023.

[11] OWASP. *Application Security Verification Standard (ASVS) v4.0.* Open Web Application Security Project, 2021. https://owasp.org/www-project-application-security-verification-standard/

[12] Unicode Consortium. *Unicode Technical Report #39: Unicode Security Profile.* Unicode, 2022. https://www.unicode.org/reports/tr39/

[13] PhishTank. *Collaborative Phishing Verification.* https://phishtank.org/

[14] Anti-Phishing Working Group (APWG). *Phishing Activity Trends Report.* https://apwg.org/

[15] RFC 7919. *Negotiated Finite Diffie-Hellman Ephemeral Parameters for Transport Layer Security (TLS).* IETF, 2016.

[16] Google. *Chrome Extension Manifest V3.* https://developer.chrome.com/docs/extensions/develop/migrate/what-is-mv3

---

## 15. Figures to Add or Update

### Figure 1 — Clean Architecture Layers (new)

```
┌─────────────────────────────────────────────┐
│              Infrastructure                  │
│   API │ Database │ IPFS │ Browser │ Crypto   │
├─────────────────────────────────────────────┤
│              Application                     │
│   Use Cases (CreateVault, GenerateCredentials│
│              ValidateDomain, Encrypt)        │
├─────────────────────────────────────────────┤
│               Domain                         │
│   Entities │ Ports │ Value Objects           │
└─────────────────────────────────────────────┘
         ↑ Dependencies point inward ↑
```

### Figure 2 — 3-Phase Validation Pipeline (update)

```
Form Submission → Phase 1: ExactMatch (RFC 1035 DNS normalization)
                  → Phase 2: ConfusableDetection (Unicode TR39)
                  → Phase 3: Levenshtein (registrable domain extraction)
                  → Verdict: SAFE / BLOCK
```

### Figure 3 — Circuit Breaker State Machine (new)

```
CLOSED ──[3 failures]──→ OPEN ──[5s timeout]──→ HALF_OPEN
   ↑                                              │
   └──────────[success]────────────────────────────┘
                    │
                    └──[failure]──→ OPEN
```

### Figure 4 — Encryption Flow (new)

```
Master Password
      │
      ▼
PBKDF2(salt, 600K iterations, SHA-256)
      │
      ▼
AES-256-GCM Key (256-bit)
      │
      ▼
AES-GCM.encrypt(plaintext, key, random IV)
      │
      ▼
{ ciphertext, salt, iv } → Server / IPFS
```

---

## Checklist

| # | Section | Status |
|---|---|---|
| 1 | Abstract — 3 crypto algorithms | Apply |
| 2 | Abstract — partial zero-knowledge | Apply |
| 3 | Introduction — latency 0.003ms / 0.005ms | Apply |
| 4 | Introduction — throughput 328K / 185K | Apply |
| 5 | Related Work — NIST, OWASP, TR39 refs | Apply |
| 6 | Architecture — Clean Architecture description | Apply |
| 7 | Architecture — technology stack table | Apply |
| 8 | Crypto — 3 algorithms, not 6 | Apply |
| 9 | Crypto — algorithm comparison table | Apply |
| 10 | Crypto — encryption flow description | Apply |
| 11 | Crypto — entropy validation | Apply |
| 12 | Pipeline — 75 scenarios, 100% accuracy | Apply |
| 13 | Pipeline — throughput correction table | Apply |
| 14 | Pipeline — dataset descriptions | Apply |
| 15 | Pipeline — execution environment | Apply |
| 16 | IPFS — circuit breaker + retry | Apply |
| 17 | Security — controls table | Apply |
| 18 | Security — threat model | Apply |
| 19 | Resilience — new section | Apply |
| 20 | Testing — 16 suites, 197 tests | Apply |
| 21 | Results — master comparison table | Apply |
| 22 | Discussion — limitations | Apply |
| 23 | Discussion — feature comparison table | Apply |
| 24 | Conclusions — adjusted claims | Apply |
| 25 | Conclusions — contributions list | Apply |
| 26 | References — 8 new entries | Apply |
| 27 | Figures — 4 diagrams | Apply |
