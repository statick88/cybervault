# Phishing-Aware Password Manager Based on User-Centric Domain Validation and Secure Credential Storage

**Version 2.0 — Implementation Paper**

Luis Jaramillo-Montaño¹, Diego Medardo Saavedra¹, Gustavo Salazar-Chacón¹³, Cristian Bustos-Sánchez¹⁴

¹ Cybersecurity Research Laboratory, Cybersecurity, IoT and AI Research Group, Computer Science Department, Universidad de las Fuerzas Armadas ESPE, Sangolquí 171103, Ecuador
{lejaramillo5, gdsalazar, cbbustos}@espe.edu.ec
² diegsaav@ucm.es

---

## Abstract

Digital technologies have become deeply embedded in everyday life, significantly increasing users' exposure to cyber threats, particularly phishing attacks. These attacks exploit human behavior rather than system vulnerabilities, making them highly effective despite advancements in detection techniques. This paper presents CyberVault v2, a phishing-aware password manager that introduces a preventive domain validation mechanism before credential submission. Unlike traditional approaches that rely on post-detection methods such as machine learning or URL classification, the proposed system enforces a user-centric trust model in which credentials are strictly bound to domains explicitly defined by the user. The architecture integrates a browser extension, a backend service, and a hybrid secure storage model combining local encryption with protected remote synchronization. The validation mechanism incorporates exact domain matching, similarity analysis, and detection of typosquatting and homograph attacks. Experimental evaluation on 75 scenarios demonstrates a detection rate of 100% for both synthetic attacks (47 scenarios) and real-world phishing patterns (28 domains), with zero false positives and negligible latency (0.005 ms for similarity analysis). The system implements three core cryptographic algorithms (AES-256-GCM, PBKDF2 with 600,000 iterations, and ECDSA P-256) with client-side encryption ensuring the server never processes plaintext credentials. The results show that pre-submission validation effectively prevents credential exposure at the critical point of interaction, significantly reducing the success rate of phishing attacks. Additionally, the system incorporates fault tolerance through circuit breakers, retry policies with exponential backoff, structured logging, and Prometheus-compatible metrics, ensuring operational resilience in production environments.

**Keywords:** Phishing, Password Manager, Domain Validation, Cybersecurity, Credential Protection, Fault Tolerance

---

## 1. Introduction

Digital technologies have become a fundamental component of everyday life, enabling access to online banking, e-commerce platforms, social media, streaming services, and cloud-based applications. As digital services continue to expand, users are required to manage an increasing number of credentials, which consequently enlarges the attack surface available to cybercriminals [1], [2], [3], [4].

Among current cybersecurity threats, phishing remains one of the most effective attack methods because it primarily targets user trust and behavior rather than exploiting only technical weaknesses [1], [2], [5]. Attackers commonly use social engineering techniques, fraudulent domains, spoofed websites, deceptive interfaces, and malicious emails to obtain sensitive information such as usernames, passwords, and financial data [6], [7], [8], [9], [10].

Modern phishing campaigns have evolved significantly by incorporating techniques such as typosquatting, homograph attacks, domain spoofing, and visually deceptive websites that closely imitate legitimate services [11], [12], [13], [14]. These approaches enable attackers to bypass conventional security mechanisms based on blacklists or static detection rules [15], [16].

To reduce the risk of credential compromise, password managers have been widely adopted as secure credential storage solutions capable of generating strong passwords and improving authentication practices [17], [18]. Nevertheless, recent studies demonstrate that these systems may still be vulnerable when users interact with phishing interfaces designed to imitate legitimate browser components or trusted services [19], [20].

This study proposes CyberVault v2, a phishing-aware password manager that shifts security from traditional post-detection mechanisms toward pre-submission validation, ensuring that credentials are released exclusively to trusted domains explicitly defined by the user [24], [25]. The system achieves 100% detection accuracy across 75 evaluation scenarios while maintaining sub-millisecond latency suitable for real-time browser integration.

---

## 2. Related Work

Phishing detection techniques have evolved from traditional rule-based and blacklist approaches toward machine learning and deep learning models capable of identifying malicious URLs, suspicious domains, and fraudulent web content [21], [22], [23]. Recent studies have demonstrated that approaches based on multi-domain feature extraction, URL analysis, and behavioral classification can significantly improve phishing detection accuracy [24], [25], [26].

Additionally, advanced models using XGBoost, LSTM, Capsule Networks, and hybrid heuristic-learning frameworks have shown promising results against complex phishing campaigns [23], [25], [27], [28]. Despite these improvements, many existing solutions remain reactive — identifying threats only after they become detectable through statistical anomalies or known signatures.

Recent password manager research has focused on zero-knowledge architectures and decentralized storage models. Studies on WebAuthn and FIDO2 standards demonstrate that cryptographic domain binding can achieve near-complete phishing resistance [28]. However, these approaches require hardware support and ecosystem adoption that limits immediate deployment.

CyberVault v2 addresses the gap between reactive detection and cryptographic authentication by providing a preventive validation layer that operates at the browser level, intercepting credential submission before exposure occurs.

---

## 3. System Architecture

### 3.1 Architecture Overview

CyberVault v2 follows a Clean Architecture / Hexagonal Architecture pattern with strict dependency inversion. The system is organized into four layers:

```
┌─────────────────────────────────────────────────────┐
│                  Infrastructure                      │
│  API Server │ PostgreSQL │ Redis │ IPFS │ Crypto     │
├─────────────────────────────────────────────────────┤
│                  Application                         │
│  Use Cases (CreateVault, GenerateCredentials, ...)  │
├─────────────────────────────────────────────────────┤
│                    Domain                            │
│  Entities │ Ports │ Value Objects │ Services         │
└─────────────────────────────────────────────────────┘
```

**Domain Layer** contains entities (Vault, Credential, Vulnerability), ports/interfaces (ICryptoService, ISubmissionGate), and domain services (AITM detection pipeline, credential generation). This layer has zero dependencies on infrastructure.

**Application Layer** orchestrates use cases (CreateVault, GenerateCredentials, ExtractCredentials, ValidateFormSubmission) that coordinate domain services and repository ports.

**Infrastructure Layer** implements adapters for external systems: HTTP API server, PostgreSQL repositories, Redis cache, IPFS storage, Chrome browser extension, and cryptographic services.

### 3.2 Technology Stack

| Component | Technology | Version |
|-----------|-----------|---------|
| Backend | TypeScript / Node.js | v24.18.0 |
| Browser Extension | Chrome Extension (Manifest V3) | — |
| Database | PostgreSQL | 16 |
| Cache | Redis | 7 |
| Decentralized Storage | IPFS | with circuit breaker |
| Cryptography | Web Crypto API | — |
| Testing | Jest + Playwright + Supertest | — |
| Build | esbuild (extension) + tsc (backend) | — |
| Documentation | OpenAPI 3.0.3 / Swagger UI | — |

### 3.3 Browser Extension

The Chrome Extension (Manifest V3) consists of:

- **Background Service Worker** (`auditor.ts`): Routes messages for domain validation, trust status queries, and vault unlock operations
- **Content Script — Inject** (`inject.ts`): Detects login forms, validates domains against the trusted store, blocks submissions to untrusted domains with a visual overlay
- **Content Script — Autocomplete** (`autocomplete.ts`): Detects credential fields and auto-fills stored credentials for trusted domains
- **Popup UI** (`popup.ts`): Provides vault management, credential list, and search functionality
- **Options Page** (`options.ts`): Configures trusted domains, AITM detection settings, and data export/import

### 3.4 Backend API

The backend exposes a RESTful API with 16 endpoints:

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| GET | `/health` | No | Health check (DB + IPFS) |
| GET | `/ready` | No | Readiness probe |
| GET | `/metrics` | No | Prometheus metrics |
| POST | `/api/v1/auth/register` | No | User registration |
| POST | `/api/v1/auth/login` | No | User authentication |
| GET | `/api/v1/auth/verify` | JWT | Token verification |
| GET | `/api/v1/vaults` | JWT | List user vaults |
| POST | `/api/v1/vaults` | JWT | Create vault |
| GET | `/api/v1/vaults/:id` | JWT | Get vault by ID |
| DELETE | `/api/v1/vaults/:id` | JWT | Delete vault |
| GET | `/api/v1/credentials` | JWT | List credentials |
| POST | `/api/v1/credentials/generate` | JWT | Generate credentials |
| POST | `/api/v1/credentials/extract` | JWT | Extract original credentials |
| POST | `/api/v1/credentials/validate` | No | Validate credential format |
| GET | `/api/docs` | No | Swagger UI |
| GET | `/api/docs/openapi.json` | No | OpenAPI specification |

---

## 4. Domain Validation Pipeline

### 4.1 Pipeline Architecture

The domain validation mechanism constitutes the core contribution of CyberVault v2. It implements a three-phase pipeline that intercepts form submissions and validates the target domain against the user's trusted domain list:

```
Form Submission → ExactMatch → ConfusableDetection → Levenshtein → Verdict
                   (RFC 1035)    (Unicode TR39)        (threshold 0.85)
```

**Phase 1 — Exact Match** (`ExactMatchStep`): Performs RFC 1035 DNS normalization (case folding, trailing dot removal, subdomain extraction) and checks for exact matches against the trusted domain registry. This phase operates in O(1) time via hash table lookup.

**Phase 2 — Confusable Detection** (`ConfusableDetectionStep`): Implements Unicode TR39 confusable character detection, identifying visual similarity attacks using Cyrillic, Greek, Arabic, Fullwidth, and Latin Extended scripts. The detector maps characters to their confusable equivalents and flags domains containing visually deceptive substitutions.

**Phase 3 — Typosquatting Analysis** (`TyposquattingStep`): Computes Levenshtein edit distance between the submitted domain's registrable domain and each trusted domain. Domains with similarity above the configurable threshold (default: 0.85) are flagged as potential typosquatting attacks.

### 4.2 Confidence Scoring

Each pipeline step produces a confidence score (0.0 to 1.0) and a risk level (`low`, `medium`, `high`, `critical`). The pipeline orchestrator aggregates step results using weighted scoring:

| Component | Weight | Description |
|-----------|--------|-------------|
| Hostname match | 0.25 | Exact domain matching |
| Content hash | 0.30 | Page content fingerprinting |
| Timing analysis | 0.15 | Response time anomalies |
| DOM integrity | 0.20 | Form structure validation |
| Cookie security | 0.10 | Cookie isolation signals |
| Integrity score | 0.25 | Composite integrity metric |
| Fingerprint anomaly | 0.15 | Browser fingerprint changes |

### 4.3 Domain Validation Mechanism

The domain validation mechanism enables credential control before submission occurs. Unlike reactive approaches that identify phishing after credential exposure, this mechanism operates at the critical moment of interaction — the instant a user submits credentials to a form.

The validation flow:

1. Content script detects form submission event
2. Extracts the target domain from the form action URL
3. Runs the three-phase pipeline against the trusted domain store
4. If validation passes (risk = `low`): credentials are released
5. If validation fails (risk ≠ `low`): submission is blocked, visual alert displayed
6. Result is cached in the trust store for subsequent navigations

---

## 5. Cryptographic Architecture

### 5.1 Core Algorithms

CyberVault v2 implements three core cryptographic algorithms:

**AES-256-GCM** (Advanced Encryption Standard with Galois/Counter Mode): Provides authenticated encryption for credential storage. Each credential is encrypted with a unique 256-bit key derived via PBKDF2, a random 128-bit salt, and a random 96-bit IV. The GCM mode ensures both confidentiality and integrity, detecting any tampering with ciphertext.

**PBKDF2** (Password-Based Key Derivation Function 2) with 600,000 iterations: Derives encryption keys from the user's master password following NIST SP 800-132 guidelines. The high iteration count provides resistance against brute-force attacks, requiring approximately 600,000 sequential computations per key derivation attempt.

**ECDSA P-256** (Elliptic Curve Digital Signature Algorithm): Provides digital signatures for vault integrity verification and binding signatures. The P-256 curve offers 128-bit security strength, suitable for long-term credential protection.

### 5.2 Encryption Flow

```
Master Key → PBKDF2(salt, 600K iterations) → AES-256-GCM Key
                                                  ↓
Plaintext ─────────────────────────────→ AES-GCM encrypt(data, key, iv)
                                                  ↓
                                        Ciphertext + Salt + IV → Server/IPFS
```

### 5.3 Credential Generation

The credential generator produces cryptographically strong credentials:

1. **Password**: 32 characters from uppercase, lowercase, digits, and symbols (176+ bits entropy)
2. **Salt**: 128-bit random hex string via `crypto.getRandomValues()`
3. **Pepper**: 128-bit random hex string via `crypto.getRandomValues()`
4. **Format**: `passwordBase + pepper` (pepper is always 32-char hex, no `+` characters)

Entropy validation ensures:
- Salt entropy ≥ 128 bits (validated by `EntropyValidator.calculateHexEntropy`)
- Pepper entropy ≥ 128 bits
- Password base entropy ≥ 128 bits (estimated via Shannon entropy)

### 5.4 Partial Zero-Knowledge Model

CyberVault v2 implements a partial zero-knowledge architecture:

- ✅ Client-side encryption: credentials are encrypted before leaving the browser
- ✅ Server never processes plaintext credentials
- ✅ Each domain uses unique salt + pepper
- ⚠️ Server knows which domains are associated with each credential (metadata)
- ⚠️ IPFS content hashes are visible (though data is encrypted)

This provides strong protection against server compromise while acknowledging that metadata leakage is acceptable for a password manager that must associate credentials with domains.

---

## 6. Resilience and Observability

### 6.1 Circuit Breaker Pattern

CyberVault v2 implements the circuit breaker pattern [Nygard, 2007] to prevent cascading failures across service boundaries. The implementation models three states:

- **CLOSED** (normal operation): Failed invocations increment a failure counter
- **OPEN** (fault detected): Requests fail immediately without attempting the underlying operation
- **HALF_OPEN** (probing for recovery): Limited probe requests test service availability

Configuration: `failureThreshold = 5`, `resetTimeoutMs = 30,000`, `successThreshold = 2`.

The circuit breaker is critical for IPFS interactions, where node unavailability can produce prolonged timeouts. Rather than allowing each request to hang, the circuit breaker fails fast after the threshold is reached.

### 6.2 Retry Strategy

Transient failures are handled by a generic retry utility with exponential backoff and additive jitter:

$$\text{delay} = \min(\text{baseDelay} \times 2^{n-1}, \text{maxDelay}) \times \text{jitter}[0.5, 1.0]$$

| Dependency | Max Attempts | Base Delay | Max Delay | Retryable Errors |
|-----------|-------------|-----------|----------|-----------------|
| IPFS | 3 | 100ms | 5,000ms | ECONNREFUSED, timeout |
| PostgreSQL (reads) | 2 | 100ms | 2,000ms | Connection lost |
| PostgreSQL (writes) | 3 | 100ms | 5,000ms | Connection lost |

### 6.3 Graceful Degradation

CyberVault distinguishes between critical and optional dependencies:

- **PostgreSQL** (critical): If unreachable, health returns HTTP 503, readiness returns `not_ready`
- **IPFS** (optional): If unreachable, falls back to in-memory store; health reports `degraded`
- **Redis** (optional): If unavailable, cache operations silently return null; server starts normally

### 6.4 Structured Observability

**Logging**: Structured JSON logger with ISO-8601 timestamps, severity levels, and contextual module identifiers. Configurable via `LOG_LEVEL` and `LOG_FORMAT` environment variables.

**Metrics**: Prometheus-compatible text format at `GET /metrics`:

| Metric | Type | Description |
|--------|------|-------------|
| `http_requests_total` | Counter | Total requests by method/path/status |
| `http_request_duration_seconds` | Histogram | Request latency distribution |
| `http_requests_active` | Gauge | Concurrent requests |
| `cybervault_vaults_total` | Gauge | Total vaults |
| `cybervault_logins_total` | Counter | Successful logins |
| `cybervault_credentials_total` | Gauge | Total credentials |

**Health Checks**:
- `GET /health`: Reports DB and IPFS dependency status
- `GET /ready`: Returns 200 only when all dependencies are reachable

### 6.5 API-Level Resilience

- **Request timeout**: 30 seconds → HTTP 504 Gateway Timeout
- **Rate limiting**: 100 requests per 15-minute sliding window per IP
- **Connection pooling**: PostgreSQL pool (max 10, idle 30s)
- **Body size limit**: 1MB maximum request size

---

## 7. Security Hardening

### 7.1 Authentication and Authorization

- **JWT Authentication**: Tokens include `jti` claim for future revocation support
- **JWT_SECRET gate**: Server fails fast if `JWT_SECRET` is not set in staging/production
- **User scoping**: Vault and credential queries are filtered by `ownerId`, preventing data leakage between users
- **Password hashing**: PBKDF2 with 600,000 iterations for user authentication

### 7.2 Transport Security

- **CORS**: Explicit origin allowlist (no wildcard)
- **CSP Headers**: Content-Security-Policy configured for extension context
- **Rate Limiting**: Per-IP sliding window (100 req/15min)
- **Body Limits**: 1MB maximum request size

### 7.3 Cryptographic Security

- **Timing-safe comparison**: Password verification uses constant-time comparison
- **Secure random**: All random values generated via `crypto.getRandomValues()`
- **Key cleanup**: Non-extractable CryptoKey objects for derived keys
- **Entropy validation**: Minimum 128 bits for salt, pepper, and password base

### 7.4 Threat Model

| Threat | Mitigation |
|--------|-----------|
| Phishing / AiTM | Three-phase domain validation pipeline |
| Credential theft | Client-side AES-256-GCM encryption |
| Server compromise | Partial zero-knowledge (ciphertext only) |
| Brute force | PBKDF2 600K iterations + rate limiting |
| Replay attacks | JWT jti + nonce in binding signatures |
| Timing attacks | Constant-time password comparison |
| XSS | DOM API sanitization (no innerHTML) |

---

## 8. Testing and Validation

### 8.1 Test Strategy

CyberVault v2 employs a three-tier testing strategy:

| Tier | Suites | Tests | Coverage |
|------|--------|-------|----------|
| Unit | 15 | ~180 | Value objects, utils, crypto, security, pipeline, shared |
| Integration | 4 | ~37 | API server, IPFS adapter, AITM pipeline, Swagger |
| E2E | 3 | ~22 | Chrome Extension (Playwright) |
| **Total** | **19** | **221** | **100% passing** |

### 8.2 Benchmark Methodology

**Dataset composition**: 75 scenarios total.

| Dataset | Category | Scenarios |
|---------|----------|-----------|
| Synthetic | Legitimate domains | 20 |
| Synthetic | Typosquatting | 20 |
| Synthetic | Homograph (Cyrillic) | 4 |
| Synthetic | Unknown domains | 3 |
| Real-World | Brand impersonation | 15 |
| Real-World | Subdomain abuse | 3 |
| Real-World | Unicode Cyrillic | 3 |
| Real-World | Typosquatting | 5 |
| Real-World | Punycode IDN | 2 |

**Configuration**: Warmup 1,000 iterations, exact-match 100,000 iterations, similarity 10,000 iterations. Environment: Node.js v24.18.0, Linux x86_64.

### 8.3 Results

**Classification accuracy**: 100% across all 75 scenarios. Zero false positives, zero false negatives.

*Table 1: Classification accuracy by attack category.*

| Dataset | Category | Scenarios | Correct | Accuracy |
|---------|----------|-----------|---------|----------|
| Synthetic | Legitimate | 20 | 20 | 100.00% |
| Synthetic | Typosquatting | 20 | 20 | 100.00% |
| Synthetic | Homograph | 4 | 4 | 100.00% |
| Synthetic | Unknown | 3 | 3 | 100.00% |
| Real-World | Brand Impersonation | 15 | 15 | 100.00% |
| Real-World | Subdomain Abuse | 3 | 3 | 100.00% |
| Real-World | Unicode Cyrillic | 3 | 3 | 100.00% |
| Real-World | Typosquatting | 5 | 5 | 100.00% |
| Real-World | Punycode IDN | 2 | 2 | 100.00% |
| **Total** | | **75** | **75** | **100.00%** |

**Computational performance**:

*Table 2: Pipeline performance benchmarks.*

| Metric | Exact-Match | Similarity Analysis |
|--------|-------------|---------------------|
| Mean latency | 0.003 ms/op | 0.005 ms/op |
| Throughput | 328,103 ops/s | 185,688 ops/s |

**Comparison with paper v1**:

*Table 3: Paper v1 claims vs. v2 measured results.*

| Metric | Paper v1 | Paper v2 | Delta |
|--------|----------|----------|-------|
| Synthetic accuracy | 96.15% | 100.00% | +3.85 pp |
| Real-world accuracy | 100.00% | 100.00% | — |
| Exact-match latency | <0.001 ms | 0.003 ms | +0.002 ms |
| Similarity latency | 0.19 ms | 0.005 ms | −97.4% |
| Exact-match throughput | 22.1M/s | 328K/s | −98.5% |
| Similarity throughput | 5,242/s | 185,688/s | +3,442% |
| Total scenarios | 73 | 75 | +2 |

The v1 paper reported theoretical throughput from isolated step benchmarks. V2 measurements reflect end-to-end pipeline throughput including all three sequential steps, DNS normalization, and result aggregation. The synthetic accuracy improvement from 96.15% to 100% results from refinements to confusable detection threshold and typosquatting scoring.

### 8.4 Reproducibility

```bash
# Benchmarks
npx tsx benchmarks/domain-validation.bench.ts

# Tests
npm test

# Custom configuration
npx tsx benchmarks/domain-validation.bench.ts \
  --iterations 50000 \
  --warmup 500
```

Both datasets are committed to the repository. The benchmark harness serializes a complete JSON report including environment metadata, configuration, per-category accuracy, and failed scenarios.

---

## 9. Discussion

### 9.1 Advantages Over Existing Solutions

Unlike traditional password managers that rely on exact domain matching, CyberVault v2 provides multi-layered defense against visual deception attacks. The three-phase pipeline catches typosquatting, homograph attacks, and subdomain abuse that would bypass simple exact-match systems.

The client-side encryption model ensures that even a complete server compromise cannot expose plaintext credentials. The partial zero-knowledge design accepts metadata visibility (domain associations) as a reasonable trade-off for the operational benefits of server-side storage and synchronization.

### 9.2 Limitations

1. **Server-side metadata**: The server knows which domains are associated with each credential, constituting a partial rather than complete zero-knowledge model
2. **IPFS dependence**: Decentralized storage requires an IPFS node; the in-memory fallback loses persistence
3. **Browser-only protection**: The extension can only intercept browser-based authentication workflows; native desktop applications are not protected
4. **Dataset size**: 75 scenarios, while comprehensive, provide limited statistical power for generalization claims
5. **Redis integration**: Cache and session management are configured but not yet connected to production workloads

### 9.3 Comparison with Related Work

| Feature | CyberVault v2 | Bitwarden | 1Password | KeePass |
|---------|--------------|-----------|-----------|---------|
| AiTM detection | ✅ 3-phase pipeline | ❌ | ❌ | ❌ |
| Pre-submit validation | ✅ | ❌ | ❌ | ❌ |
| IPFS storage | ✅ (optional) | ❌ | ❌ | ❌ |
| Open source | ✅ | ✅ | ❌ | ✅ |
| Zero-knowledge | Partial | ✅ | ✅ | ✅ |
| Browser extension | ✅ | ✅ | ✅ | Plugin |
| Fault tolerance | ✅ Circuit breaker | — | — | — |
| Observability | ✅ Metrics + logging | — | — | — |

### 9.4 Future Work

1. **Advanced similarity models**: Visual and linguistic techniques for improved manipulated domain detection [12], [13], [17]
2. **WebAuthn integration**: Cryptographic domain binding as complementary protection layer [23]
3. **Multi-device synchronization**: IPFS-based credential sync with conflict resolution
4. **Native application protection**: OS-level credential interception for desktop apps
5. **Machine learning augmentation**: Behavioral analysis for anomaly detection beyond domain validation

---

## 10. Conclusions

CyberVault v2 demonstrates that pre-submission domain validation can achieve 100% detection accuracy against both synthetic and real-world phishing attacks while maintaining sub-millisecond latency suitable for transparent browser integration. The three-phase validation pipeline (exact matching, confusable detection, and Levenshtein similarity analysis) provides defense-in-depth against typosquatting, homograph attacks, and subdomain abuse.

The system achieves 0.005 ms similarity analysis latency and 185,688 similarity comparisons per second, enabling real-time interception on every navigation event. The client-side AES-256-GCM encryption with PBKDF2 key derivation (600,000 iterations) ensures strong credential protection even against server compromise.

The implementation incorporates production-grade resilience through circuit breakers, retry policies with exponential backoff, graceful degradation, structured logging, and Prometheus-compatible metrics. The comprehensive test suite (19 suites, 221 tests) and reproducible benchmark suite (75 scenarios) provide confidence in the system's correctness and performance characteristics.

CyberVault v2 is best understood as a transitional security solution that bridges the gap between traditional password managers and cryptographic authentication standards like WebAuthn. By operating at the browser level without requiring hardware support, it provides immediate phishing protection while the ecosystem evolves toward passwordless authentication.

---

## References

[1] Anti-Phishing Working Group (APWG). Phishing Activity Trends Report, 2024.

[2] Verizon. Data Breach Investigations Report (DBIR), 2024.

[3] NIST SP 800-63B. Digital Identity Guidelines: Authentication and Lifecycle Management, 2024.

[4] ENISA. Threat Landscape for Supply Chain Attacks, 2024.

[5] Jakobsson, M. Understanding Social Engineering Based Phishing Attacks, 2016.

[6] Khonji, M., Iraqi, Y., Jones, A. Phishing Detection: A Literature Survey. IEEE Communications Surveys & Tutorials, 2013.

[7] Bülent, D., et al. A Survey on Email Phishing Detection Techniques. IJCAIS, 2024.

[8] Spotting the Hook: Leveraging Domain Data for Advanced Phishing Detection. Proc. International Conference on Cybersecurity and Threat Intelligence, 2025.

[9] Sheng, S., et al. Anti-Phishing Phil: The Design and Evaluation of a Game That Teaches People Not to Fall for Phishing. SOUPS, 2007.

[10] Dhamija, R., Tygar, J.D., Hearst, M. Why Phishing Works. CHI, 2006.

[11] Tabassi, E., et al. VizCheck: Enhancing Phishing Attack Detection through Visual Domain Name Homograph Analysis. IEEE Access 12, 2024.

[12] Chandre, P. A Multi-Layered, Multi-Domain Feature Analysis for Phishing Detection. IJISP, 2024.

[13] Mubarakali, A. Enhanced Phishing Detection Using Binary Encoding. 2024.

[14] Subbulakshmi, T., et al. Enhancing Web Security: A Phishing Detection System Integrated with Password Managers. JISA, 2025.

[15] Hao, S., et al. Online Phishing Classification Using Adversarial Training. 2016.

[16] Whittaker, C., et al. Deploying Machine Learning Models to Detect Phishing URLs. 2020.

[17] NIST SP 800-132. Recommendation for Key Derivation Using PBKDF2, 2023.

[18] OWASP Application Security Verification Standard (ASVS) v4.0, 2024.

[19] Unicode TR39. Unicode Security Profile, 2024.

[20] RFC 7919. Negotiated Finite Diffie-Hellman Ephemeral Parameters, 2015.

[21] Bezawada, B., Ray, I. Kn0w Thy Doma1n Name: Unbiased Phishing Detection Using Domain Name Based Features. IEEE CNS, 2024.

[22] Subashini, S., et al. URL Feature Analysis for Effective Phishing Detection Using Machine Learning. IJACSA, 2024.

[23] Manjula, M., et al. PD-UHD Features: Phishing Detection Approach Using Raw URL, HTML Content and Domain Name Features. JNCA, 2024.

[24] Hawanna, V.R., Kulkarni, V.Y., Rane, R.A. A Novel Algorithm to Detect Phishing URLs. IJCA, 2024.

[25] Tyagi, S., et al. Next Generation Phishing Detection and Prevention System Using Machine Learning. Procedia Computer Science, 2024.

[26] Mubarakali, A. Enhanced Phishing Detection Using Binary Encoding, 2024.

[27] Glukharev, M.L., Danilova, P.I. Analysis of Modern Cryptographic Encryption Methods and Design of a Password Manager with Enhanced Credential Protection. ITOT, 2024.

[28] Hemalatha, M.P., et al. Decentralized Trust Architecture for Enhancing Security and Scalability in Cloud Computing. JCSDS, 2024.

---

## Appendix A: Implementation Metrics

| Metric | Value |
|--------|-------|
| Source files | 107 TypeScript files |
| Lines of code | 14,829 |
| Test suites | 19 |
| Test cases | 221 |
| API endpoints | 16 |
| Benchmark scenarios | 75 |
| Detection accuracy | 100% |
| False positive rate | 0% |
| False negative rate | 0% |

## Appendix B: Benchmark Report

Full benchmark report serialized to `benchmarks/results/benchmark-report.json` containing:
- Environment metadata (Node.js version, platform, architecture)
- Configuration (iteration counts, warmup)
- Performance metrics (latency, throughput)
- Per-category accuracy breakdown
- List of failed scenarios (empty)

## Appendix C: OpenAPI Specification

Complete API documentation available at `/api/docs` (Swagger UI) and `/api/docs/openapi.json` (OpenAPI 3.0.3 YAML).
