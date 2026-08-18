# Phishing-Aware Password Manager Based on User-Centric Domain Validation and Secure Credential Storage

Luis Jaramillo-Montaño¹ [0009-0005-4878-2800], Diego Medardo Saavedra¹ [0000-0001-5727-0640], Gustavo Salazar-Chacón¹³ [0000-0003-2394-3506], Cristian Bustos-Sánchez¹⁴ [0009-0004-9983-1046]

¹ Cybersecurity Research Laboratory, Cybersecurity, IoT and AI Research Group, Computer Science Department, Universidad de las Fuerzas Armadas ESPE, Sangolquí 171103, Ecuador {lejaramillo5, gdsalazar, cbbustos}@espe.edu.ec
² diegsaav@ucm.es

---

## Abstract

Digital technologies have become deeply embedded in everyday life, significantly increasing users' exposure to cyber threats, particularly phishing attacks. These attacks exploit human behavior rather than system vulnerabilities, making them highly effective despite advancements in detection techniques. This paper presents CyberVault v2, a phishing-aware password manager that introduces a preventive domain validation mechanism before credential submission. Unlike traditional approaches that rely on post-detection methods such as machine learning or URL classification, the proposed system enforces a user-centric trust model in which credentials are strictly bound to domains explicitly defined by the user. The architecture integrates a browser extension, a backend service, and a hybrid secure storage model combining local encryption with protected remote synchronization. The validation mechanism incorporates exact domain matching, similarity analysis, and detection of typosquatting and homograph attacks. Experimental evaluation on 75 scenarios demonstrates a detection rate of 100% for both synthetic attacks (47 scenarios) and real-world phishing patterns (28 domains), with zero false positives and negligible latency (0.005 ms for similarity analysis). The system implements three core cryptographic algorithms (AES-256-GCM, PBKDF2 with 600,000 iterations, and ECDSA P-256) with client-side encryption ensuring encrypted-at-rest storage. A partial zero-knowledge model prevents long-term credential exposure while maintaining operational synchronization capabilities. The results show that pre-submission validation effectively prevents credential exposure at the critical point of interaction, significantly reducing the success rate of phishing attacks.

**Keywords:** Phishing, Password Manager, Domain Validation, Cybersecurity, Credential Protection

---

## 1. Introduction

Digital technologies have become a fundamental component of everyday life, enabling access to online banking, e-commerce platforms, social media, streaming services, and cloud-based applications. As digital services continue to expand, users are required to manage an increasing number of credentials, which consequently enlarges the attack surface available to cybercriminals [1], [2], [3], [4].

Among current cybersecurity threats, phishing remains one of the most effective attack methods because it primarily targets user trust and behavior rather than exploiting only technical weaknesses [1], [2], [5]. Attackers commonly use social engineering techniques, fraudulent domains, spoofed websites, deceptive interfaces, and malicious emails to obtain sensitive information such as usernames, passwords, and financial data [6], [7], [8], [9], [10].

Modern phishing campaigns have evolved significantly by incorporating techniques such as typosquatting, homograph attacks, domain spoofing, and visually deceptive websites that closely imitate legitimate services [11], [12], [13], [14]. These approaches enable attackers to bypass conventional security mechanisms based on blacklists or static detection rules [15], [16].

To reduce the risk of credential compromise, password managers have been widely adopted as secure credential storage solutions capable of generating strong passwords and improving authentication practices [17], [18]. Nevertheless, recent studies demonstrate that these systems may still be vulnerable when users interact with phishing interfaces designed to imitate legitimate browser components or trusted services [19], [20].

At the same time, machine learning and deep learning approaches have shown promising results for phishing detection through the analysis of URLs, domain characteristics, and HTML content [21], [22], [23]. However, these methods remain inherently reactive because phishing attempts are identified only after suspicious indicators become detectable.

This study proposes CyberVault v2, a phishing-aware password manager that shifts security from traditional post-detection mechanisms toward pre-submission validation, ensuring that credentials are released exclusively to trusted domains explicitly defined by the user [24], [25]. The system achieves 100% detection accuracy across 75 evaluation scenarios while maintaining sub-millisecond latency suitable for real-time browser integration.

---

## 2. Related Work

Phishing detection techniques have evolved from traditional rule-based and blacklist approaches toward machine learning and deep learning models capable of identifying malicious URLs, suspicious domains, and fraudulent web content [21], [22], [23]. Recent studies have demonstrated that approaches based on multi-domain feature extraction, URL analysis, and behavioral classification can significantly improve phishing detection accuracy [24], [25], [26].

Additionally, advanced models using XGBoost, LSTM, Capsule Networks, and hybrid heuristic-learning frameworks have shown promising results against complex phishing campaigns [23], [25], [27], [28]. Despite these improvements, many existing solutions remain reactive — identifying threats only after they become detectable through statistical anomalies or known signatures.

Recent password manager research has focused on zero-knowledge architectures and decentralized storage models. Studies on WebAuthn and FIDO2 standards demonstrate that cryptographic domain binding can achieve near-complete phishing resistance [28]. However, these approaches require hardware support and ecosystem adoption that limits immediate deployment.

The proposed architecture follows a hybrid model focused on real-time credential control by integrating domain validation and secure credential storage directly into the authentication workflow. Unlike systems that rely on post-detection, CyberVault v2 operates at the critical moment of credential submission [19], [20]. During the authentication process, the browser extension extracts the active domain and compares it against the registered domain associated with the stored credential. If the validation fails, credential release is blocked before exposure occurs.

---

## 3. System Architecture

### 3.1 System Design and Components

The system is implemented as a distributed architecture in which the main control logic resides on a backend service responsible for user authentication, session management, and synchronization across devices. The architecture integrates three primary components: a browser extension, a backend service, and a hybrid secure storage model.

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

**Figure 1.** Architecture of a password manager oriented towards phishing prevention.

### 3.2 Browser Extension Components

The Chrome Extension (Manifest V3) implements the following internal components:

- **Background Service Worker** (`auditor.ts`): Routes messages for domain validation, trust status queries, and vault unlock operations
- **Content Script — Inject** (`inject.ts`): Detects login forms, validates domains against the trusted store, blocks submissions to untrusted domains
- **Content Script — Autocomplete** (`autocomplete.ts`): Detects credential fields and auto-fills stored credentials for trusted domains
- **Popup UI** (`popup.ts`): Provides vault management, credential list, and search functionality
- **Options Page** (`options.ts`): Configures trusted domains, AITM detection settings, and data export/import

**Figure 2.** Internal components of the browser extension.

### 3.3 Backend Services

The backend is responsible for user authentication, session management, and synchronization across devices. Communication between the browser extension and the backend follows a RESTful API design with JWT authentication.

The backend exposes 16 endpoints covering authentication, vault management, credential operations, health checks, and API documentation:

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

**Figure 3.** Main backend services.

### 3.4 Secure Storage System

The credential storage system follows a hybrid approach that combines encrypted local storage with secure remote synchronization. This design improves both availability and resistance against credential theft.

```
Master Key → PBKDF2(salt, 600K iterations) → AES-256-GCM Key
                                                  ↓
Plaintext ─────────────────────────────→ AES-GCM encrypt(data, key, iv)
                                                  ↓
                                        Ciphertext + Salt + IV → Server/IPFS
```

**Figure 4.** Secure storage system.

---

## 4. Domain Validation Mechanism

The domain validation mechanism constitutes the core component of the proposed system, enabling credential control before submission occurs. Unlike reactive approaches that identify phishing after credential exposure, this mechanism operates at the critical moment of interaction — the instant a user submits credentials to a form.

The validation mechanism incorporates a three-phase pipeline: exact domain matching, similarity analysis, and detection of typosquatting and homograph attacks. Domain validation follows a three-phase process: exact matching (O(1)), confusable detection (Unicode TR39), and similarity analysis using Levenshtein distance (threshold = 0.85) [11], [12], [13], [16].

```
Form Submission → ExactMatch → ConfusableDetection → Levenshtein → Verdict
                   (RFC 1035)    (Unicode TR39)        (threshold 0.85)
```

**Phase 1 — Exact Match** (`ExactMatchStep`): Performs RFC 1035 DNS normalization (case folding, trailing dot removal, subdomain extraction) and checks for exact matches against the trusted domain registry.

**Phase 2 — Confusable Detection** (`ConfusableDetectionStep`): Implements Unicode TR39 confusable character detection, identifying visual similarity attacks using Cyrillic, Greek, Arabic, Fullwidth, and Latin Extended scripts.

**Phase 3 — Typosquatting Analysis** (`TyposquattingStep`): Computes Levenshtein edit distance between the submitted domain's registrable domain and each trusted domain. Domains with similarity above the configurable threshold (default: 0.85) are flagged as potential typosquatting attacks.

If the similarity score exceeds the threshold τ, the domain is classified as suspicious and an alert is generated; otherwise, access is blocked. This mechanism enables the system to differentiate between legitimate access, potential phishing attacks, and visual deception techniques [11], [12], [13], [15], [16].

**Figure 5.** Domain validation workflow to prevent phishing.

---

## 5. Secure Management

Credential protection is achieved through client-side encryption and secure key management mechanisms. The proposed system follows four main principles: prevention of plaintext credential storage, domain-bound credential release, entropy-validated password generation, and secure key derivation.

### 5.1 Cryptographic Algorithms

The system implements three core cryptographic algorithms:

- **AES-256-GCM** (Advanced Encryption Standard with Galois/Counter Mode): Provides authenticated encryption for credential storage. Each credential is encrypted with a unique 256-bit key derived via PBKDF2, a random 128-bit salt, and a random 96-bit IV.
- **PBKDF2** with 600,000 iterations: Derives encryption keys from the user's master password following NIST SP 800-132 guidelines.
- **ECDSA P-256** (Elliptic Curve Digital Signature Algorithm): Provides digital signatures for vault integrity verification.

### 5.2 Credential Generation

The credential generator produces cryptographically strong credentials:

1. **Password**: 32 characters from uppercase, lowercase, digits, and symbols (~207 bits entropy)
2. **Salt**: 128-bit random hex string via `crypto.getRandomValues()`
3. **Pepper**: 128-bit random hex string via `crypto.getRandomValues()`
4. **Format**: `passwordBase + pepper`

Entropy validation ensures salt and pepper entropy ≥ 128 bits, and password base entropy ≥ 128 bits (NIST SP 800-63B compliant).

### 5.3 Partial Zero-Knowledge Model

CyberVault v2 implements a partial zero-knowledge architecture:

- Client-side encryption: credentials are encrypted before persistent storage
- Encrypted-at-rest: vault data stored with AES-256-GCM, never persisted in plaintext
- Each domain uses unique salt + pepper
- Server handles credential generation/extraction with ephemeral plaintext (not persisted)

---

## 6. Evaluation

### 6.1 Experimental Setup

The evaluation was conducted on the CyberVault v2 implementation (v2.0.0) under controlled synthetic scenarios and real-world phishing domain patterns. The evaluation focused on phishing detection accuracy, false positives, credential generation quality, system performance, and comparative analysis against existing password managers and phishing protection mechanisms.

The evaluation combined two datasets:

**Synthetic dataset (47 scenarios):** 20 legitimate domains, 20 typosquatting variants, 4 homograph attacks, and 3 unknown domains.

**Real-world dataset (28 domains):** Including brand impersonation, subdomain abuse, Unicode confusables, typosquatting, and Punycode/IDN phishing patterns extracted from active phishing campaigns reported in APWG datasets and related studies [11], [12], [13], [15].

The system implements three core cryptographic algorithms: AES-256-GCM encryption, PBKDF2 with 600,000 iterations for key derivation, and ECDSA P-256 signatures [20], [24], [25].

### 6.2 Operational Detection and Enforcement Analysis

The system achieved an operational protection rate of 100% (95% CI: [95.8%, 100.0%]) against synthetic attack scenarios, correctly identifying typosquatting variants with an average similarity score of 92.40%. Variants involving duplication, omission, and substitution were consistently flagged. No false negatives were observed across all evaluated scenarios, consistent with DNS standards.

Detection reached 100.00% across all categories, including brand impersonation, subdomain abuse, Unicode confusables, typosquatting, and Punycode/IDN. Table 1 summarizes the detection results by phishing category, confirming consistent performance across all real-world attack patterns.

*Table 1. Real-World Phishing Domain Detection by Category.*

| Category | Scenarios | Detected | Rate |
|----------|-----------|----------|------|
| Brand impersonation | 15 | 15 | 100.00% |
| Subdomain abuse | 3 | 3 | 100.00% |
| Unicode Cyrillic | 3 | 3 | 100.00% |
| Typosquatting | 5 | 5 | 100.00% |
| Punycode IDN | 2 | 2 | 100.00% |
| **Total** | **28** | **28** | **100.00%** |

All evaluated homograph attack variants triggered the Unicode confusable-detection phase, resulting in operational protection outcomes equivalent to 100.00% coverage within the evaluated synthetic corpus.

### 6.3 Confusion Matrix (Combined Datasets)

| Metric | Value |
|--------|-------|
| Accuracy | 100.0% |
| Precision | 100.0% |
| Recall | 100.0% |
| F1-Score | 100.0% |

### 6.4 Comparison with Existing Solutions

Table 2 presents a comparative analysis of phishing protection mechanisms across CyberVault v2, Bitwarden, KeePassXC, and 1Password.

*Table 2. Phishing Protection Mechanisms Comparison.*

| Feature | CyberVault v2 | Bitwarden | KeePassXC | 1Password |
|---------|--------------|-----------|-----------|-----------|
| Pre-submit validation | ✅ | ❌ | ❌ | ❌ |
| AiTM detection | ✅ | ❌ | ❌ | ❌ |
| Similarity analysis | ✅ | ❌ | ❌ | ❌ |
| Homograph detection | ✅ | ❌ | ❌ | ❌ |
| Client-side encryption | ✅ | ✅ | ✅ | ✅ |
| IPFS storage | ✅ | ❌ | ❌ | ❌ |
| Open source | ✅ | ✅ | ✅ | ❌ |

While commercial solutions such as Bitwarden and 1Password provide stronger authentication models, the proposed approach offers a practical transitional protection layer for environments that continue relying on password-based authentication [28].

---

## 7. Performance Metrics

Key results: exact-match latency 0.003 ms, similarity check latency 0.005 ms, with isolated microbenchmark throughput of 328,103 exact-match comparisons per second. Under the evaluated conditions, the validation process operated approximately 33,000× faster than the typical user credential submission window.

*Table 3. Performance Metrics.*

| Metric | Exact-Match | Similarity Analysis |
|--------|-------------|---------------------|
| Mean latency | 0.003 ms | 0.005 ms |
| Throughput | 328,103 /s | 185,688 /s |
| Std deviation | σ = 0.01 | σ = 0.02 |

### 7.1 Comparison with Paper v1

*Table 4. Paper v1 claims vs. v2 measured results.*

| Metric | Paper v1 | Paper v2 | Delta |
|--------|----------|----------|-------|
| Synthetic accuracy | 96.15% | 100.00% | +3.85 pp |
| Real-world accuracy | 100.00% | 100.00% | — |
| Exact-match latency | <0.001 ms | 0.003 ms | +0.002 ms |
| Similarity latency | 0.19 ms | 0.005 ms | −97.4% |
| Exact-match throughput | 22.1M/s | 328K/s | −98.5% |
| Similarity throughput | 5,242/s | 185,688/s | +3,442% |
| Total scenarios | 73 | 75 | +2 |

The v1 paper reported theoretical throughput from isolated step benchmarks. V2 measurements reflect end-to-end pipeline throughput including all three sequential steps, DNS normalization, and result aggregation.

---

## 8. Validation

The experimental evaluation supports the defined threat model across multiple domain-based phishing scenarios. The architecture demonstrated strong operational protection against opportunistic typosquatting, Unicode homograph attacks, and brand impersonation patterns. The three-phase domain validation pipeline — combining exact matching, Unicode confusable detection, and Levenshtein similarity analysis (~95% heuristic coverage) — prevented credential release during evaluated visually deceptive phishing scenarios [11], [12], [15].

The system achieved 100% detection rate (95% CI: [95.8%, 100.0%]) against both synthetic and real-world phishing scenarios, while maintaining a 0.00% false positive rate on legitimate domains. The three-phase domain validation mechanism combining exact-matching, confusable detection, and similarity analysis achieved latency of 0.005 ms, allowing intervention approximately 33,000× faster than the typical user credential submission window [11], [12], [16]. Additionally, the hybrid secure storage model, based on AES-256-GCM encryption with PBKDF2 key derivation, ensured strong confidentiality guarantees through encrypted-at-rest storage, while the password generator achieved an average entropy of 207 bits, exceeding standard cryptographic thresholds [3], [25], [29].

Traditional password managers, which rely primarily on exact domain matching and user warnings, the proposed system provides active similarity-based detection with pre-submission blocking, offering stronger protection in password-based authentication workflows. WebAuthn remains the most robust solution, achieving near-complete phishing resistance through cryptographic domain binding [28]. Therefore, the proposed system is best understood as a transitional security solution for environments that continue relying on password-based authentication.

---

## 9. Limitations

One limitation of the proposed architecture is the use of case-insensitive domain normalization consistent with RFC 1035. While this behavior aligns with standard DNS resolution, it may not detect certain typosquatting patterns. Additionally, the proposed protection model is limited to browser-based authentication workflows in which extensions can intercept credential-submission events. Native desktop applications, mobile apps, and non-browser-based authentication flows remain outside the protection scope.

The partial zero-knowledge model accepts metadata visibility (domain associations) as a reasonable trade-off for the operational benefits of server-side storage and synchronization. Users who require complete zero-knowledge guarantees should consider solutions that preserve that incorrect trust relationship. Consequently, the protection guarantees of the proposed model remain dependent on the user's ability to correctly configure trusted domains.

The evaluation dataset, while comprehensive (75 scenarios), provides limited statistical power for generalization claims. Future evaluations should include larger datasets and longitudinal studies of real-world phishing campaigns.

---

## 10. Future Work

Future work includes the incorporation of more advanced similarity analysis models, including visual and linguistic techniques for improving manipulated domain detection [12], [13], [17]. Additionally, the integration with passwordless authentication standards such as WebAuthn, which provide native resistance against phishing attacks [23]. In this context, the proposed system may operate as a complementary or transitional protection layer in environments that continue relying on password-based authentication [19], [20].

Other future directions include:

1. **Multi-device synchronization**: IPFS-based credential sync with conflict resolution
2. **Native application protection**: OS-level credential interception for desktop apps
3. **Machine learning augmentation**: Behavioral analysis for anomaly detection beyond domain validation
4. **Hardware security module integration**: HSM-backed key storage for enterprise deployments

---

## 11. Conclusions

The experimental results validate the effectiveness of the proposed approach. The system achieved a 100% detection rate (95% CI: [95.8%, 100.0%]) against both synthetic and real-world phishing scenarios, with zero false positives and zero false negatives. Detection performance remained consistent across attack categories: 100.00% for typosquatting variants and 100.00% for homograph and real-world phishing scenarios, while maintaining a 0.00% false positive rate on legitimate domains.

The three-phase domain validation mechanism combining exact-matching, confusable detection, and similarity analysis achieved latency of 0.005 ms, allowing intervention approximately 33,000× faster than the typical user credential submission window [11], [12], [16]. Additionally, the hybrid secure storage model, based on AES-256-GCM encryption with PBKDF2 key derivation, ensured strong confidentiality guarantees through encrypted-at-rest storage, while the password generator achieved an average entropy of 207 bits, exceeding standard cryptographic thresholds [3], [25], [29].

Compared to traditional password managers, which rely primarily on exact domain matching and user warnings, the proposed system provides active similarity-based detection with pre-submission blocking, offering stronger protection in password-based authentication workflows. WebAuthn remains the most robust solution, achieving near-complete phishing resistance through cryptographic domain binding [28]. Therefore, the proposed system is best understood as a transitional security solution for environments that continue relying on password-based authentication.

---

## Acknowledgments

The authors gratefully acknowledge the Cybersecurity Research Laboratory (CYBERLAB-ESPE), and the Cybersecurity, IoT and AI Research Group of the Computer Science Department at Universidad de las Fuerzas Armadas ESPE, Sangolquí, Ecuador, for providing the infrastructure, technical expertise, and research environment that made this work possible.

---

## References

[1] Bitdefender Ecuador: El phishing y el fraude digital marcan el ritmo de la ciberseguridad en 2026. https://bitdefenderecuador.com/noticia/2026/03/el-phishing-y-el-fraude-digital-marcan-el-ritmo-de-la-ciberseguridad-en-2026.html. Accessed 9 Apr 2026.

[2] Bitdefender Ecuador: Ecuador entre los países más vulnerables a ciberataques: ¿Qué pueden hacer empresas y profesionales ahora? https://bitdefenderecuador.com/noticia/2025/11/ecuador-entre-los-paises-mas-vulnerables-a-ciberataques-que-pueden-hacer-empresas-y-profesionales-ahora. Accessed 9 Apr 2026.

[3] NIST SP 800-63B. Digital Identity Guidelines: Authentication and Lifecycle Management, 2024.

[4] ECUCERT: AL-2026-004 Aviso de seguridad: Campaña de phishing mediante suplantación de Microsoft. https://www.ecucert.gob.ec/wp-content/uploads/2026/01/AL-2026-004-Aviso-de-seguridad-suplantacion-Microsoft.pdf. Accessed 9 Apr 2026.

[5] ESED Seguridad Digital: Sistemas de verificación antispam y antiphishing para correos electrónicos. https://www.esedsl.com/blog/sistemas-de-verificacion-antispam-y-antiphishing-para-correos-electronicos. Accessed 9 Apr 2026.

[6] A Survey on Email Phishing Detection Techniques. International Journal of Computer Applications and Information Security, 2024.

[7] Spotting the Hook: Leveraging Domain Data for Advanced Phishing Detection. Proceedings of the International Conference on Cybersecurity and Threat Intelligence, 2025.

[8] Khonji, M., Iraqi, Y., Jones, A. Phishing Detection: A Literature Survey. IEEE Communications Surveys & Tutorials, 2013.

[9] Sheng, S., et al. Anti-Phishing Phil: The Design and Evaluation of a Game That Teaches People Not to Fall for Phishing. SOUPS, 2007.

[10] Dhamija, R., Tygar, J.D., Hearst, M. Why Phishing Works. CHI, 2006.

[11] Basak, P., Patni, J.C. PCDF: Phishing Attack Using Cyrillic Homograph Domain Forgery. In: Proceedings of the International Conference on Cyber Security, 2024.

[12] Zouahi, H., Talhi, C., Boudar, O. VizCheck: Enhancing Phishing Attack Detection through Visual Domain Name Homograph Analysis. IEEE Access 12, 2024.

[13] Fouss, B., Ross, D.M., Wollaber, A.B., Gomez, S.R. PunyVis: A Visual Analytics Approach for Identifying Homograph Phishing Attacks. ACM Symposium on Visualization for Cyber Security, 2024.

[14] Mubarakali, A. Enhanced phishing detection using binary encoding and LSTM feature extraction and capsule network classification. International Journal of Information Security 25, 2026.

[15] Piredda, P., et al. Deepsquatting: Learning-Based Typosquatting Detection at Deeper Domain Levels. Computers & Security, 2024.

[16] Shirazi, H., Bezawada, B., Ray, I. Kn0w Thy Doma1n Name: Unbiased Phishing Detection Using Domain Name Based Features. In: IEEE Conference on Communications and Network Security (CNS), 2024.

[17] Kanjikar, M., et al. Password Manager. International Journal of Engineering Research and Technology (IJERT), 2024.

[18] Dharmateja, M., et al. Password Manager with Multi-Factor Authentication. International Journal of Innovative Research in Technology (IJIRT), 2024.

[19] Subbulakshmi, T., et al. Enhancing Web Security: A Phishing Detection System Integrated with Password Managers. Journal of Information Security and Applications, 2025.

[20] Anliker, C., Lain, D., Capkun, S. Phishing Attacks against Password Manager Browser Extensions. In: USENIX Security Symposium, 2024.

[21] Subashini, S., et al. URL Feature Analysis for Effective Phishing Detection using Machine Learning. International Journal of Advanced Computer Science and Applications (IJACSA), 2024.

[22] Manjula, M., et al. PD-UHD Features: Phishing Detection Approach using raw URL, HTML content and Domain Name Features. Journal of Network and Computer Applications, 2024.

[23] Mubarakali, A. Enhanced phishing detection using binary encoding and LSTM feature extraction and capsule network classification. Int. J. Inf. Secur. 25, 2026.

[24] Jadhav, A., Chandre, P. A Multi-Layered, Multi-Domain Feature Analysis for Phishing Detection. International Journal of Information Security and Privacy, 2024.

[25] Tyagi, S., et al. Next Generation Phishing Detection and Prevention System using Machine Learning. Procedia Computer Science, 2024.

[26] A Hybrid Heuristic-Machine Learning Framework for Phishing Detection Using Multi-Domain Feature Analysis. IEEE Access, 2024.

[27] Hawanna, V.R., Kulkarni, V.Y., Rane, R.A. A Novel Algorithm to Detect Phishing URLs. International Journal of Computer Applications, 2024.

[28] El-Feky, A.M., Basha, A.E., Gomaa, K.M., El-Etreby, Y.A., Saleh, Y.N.M., Abdel-Hamid, A.A. Passwordless Decentralized Authentication Management System. In: International Conference on Computing and Information Technology, 2025.

[29] Glukharev, M.L., Danilova, P.I. Analysis of Modern Cryptographic Encryption Methods and Design of a Password Manager with Enhanced Credential Protection. Intellectual Technologies on Transport, 2024.

---

## Appendix A: Implementation Metrics

| Metric | Value |
|--------|-------|
| Source files | 107 TypeScript files |
| Lines of code | 14,829 |
| Test suites | 19 |
| Test cases | 231 |
| API endpoints | 16 |
| Benchmark scenarios | 75 |
| Detection accuracy | 100% |
| False positive rate | 0% |
| False negative rate | 0% |
| Exact-match latency | 0.003 ms |
| Similarity latency | 0.005 ms |

## Appendix B: Reproducibility

All benchmarks are fully reproducible:

```bash
# Full benchmark suite
npx tsx benchmarks/domain-validation.bench.ts

# Test suite
npm test

# Custom configuration
npx tsx benchmarks/domain-validation.bench.ts \
  --iterations 50000 \
  --warmup 500
```

Both datasets are committed to the repository:
- `benchmarks/datasets/synthetic.json` (47 scenarios)
- `benchmarks/datasets/real-world.json` (28 scenarios)

The benchmark harness serializes a complete JSON report to `benchmarks/results/benchmark-report.json`.
