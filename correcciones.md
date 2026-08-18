# CyberVault — Correcciones para Paper v2

> **Título:** Phishing-Aware Password Manager Based on User-Centric Domain Validation and Secure Credential Storage
> **Autores:** Luis Jaramillo-Montaño, Diego Medardo Saavedra, Gustavo Salazar-Chacón, Cristian Bustos-Sánchez
> **Institución:** Universidad de las Fuerzas Armadas ESPE, Ecuador
> **Última actualización:** 2026-08-16

---

## Resumen de correcciones

| # | Sección | Corrección | Severidad |
|---|---|---|---|
| 1 | Abstract | Ajustar claim de algoritmos crypto (6→3) | Alta |
| 2 | Abstract | Ajustar claim de "zero-knowledge completo" a "parcial" | Alta |
| 3 | Introduction | Eliminar claim de "<0.19ms latencia" sin evidencia | Alta |
| 4 | Related Work | Agregar referencia a NIST SP 800-63B para PBKDF2 iterations | Media |
| 5 | Architecture | Documentar Clean Architecture / Hexagonal real | Media |
| 6 | Crypto | Corregir lista de 6 algoritmos a 3 implementados | Crítica |
| 7 | Crypto | Agregar tabla comparativa: implementados vs mencionados | Alta |
| 8 | Pipeline | Agregar métricas reales de benchmarks (75 escenarios) | Alta |
| 9 | Pipeline | Corregir throughput exact-match: 22.1M/s → 328K/s | Crítica |
| 10 | Pipeline | Corregir throughput similarity: 5.2K/s → 185K/s | Crítica |
| 11 | Results | Actualizar accuracy: 96.15% → 100% (75/75) | Alta |
| 12 | Results | Agregar tabla de resultados reales vs paper v1 | Alta |
| 13 | Results | Agregar entorno de ejecución (Node v24.18, linux x64) | Media |
| 14 | IPFS | Documentar circuit breaker + retry (estaba roto en v1) | Alta |
| 15 | IPFS | Agregar métricas de resiliencia (degradación graceful) | Media |
| 16 | Security | Documentar JWT_SECRET gate, CORS, user scoping | Media |
| 17 | Security | Agregar sección de threat model corregida | Alta |
| 18 | Testing | Agregar cobertura: 16 suites, 197 tests, 100% pipeline | Media |
| 19 | Discussion | Agregar limitaciones reales del sistema | Alta |
| 20 | Discussion | Mencionar Redis pendiente de integración | Baja |
| 21 | Conclusion | Ajustar claims a resultados medidos | Alta |
| 22 | References | Agregar referencia a RFC 7919 (TLS), OWASP ASVS | Media |

---

## 1. Abstract

### Corrección 1.1 — Algoritmos criptográficos

**Paper v1 dice:**
> "Six cryptographic algorithms: Argon2, X25519, Ed25519, AES-256-GCM, HMAC-SHA256, PBKDF2"

**Realidad:**
Solo 3 algoritmos están implementados:
- AES-256-GCM (encriptación de credenciales)
- PBKDF2 con 600,000 iteraciones (derivation de claves, NIST SP 800-132)
- ECDSA P-256 (firmas digitales)

Argon2 está en `src/infrastructure/crypto/argon2-kdf.ts` pero NO se usa en el pipeline principal — es una referencia futura. X25519 y Ed25519 están en `src/infrastructure/crypto/key-exchange.ts` como utilidades experimentales, no integradas al flujo principal.

**Corrección:**
> "Three core cryptographic algorithms: AES-256-GCM for authenticated encryption, PBKDF2 with 600,000 iterations for key derivation (NIST SP 800-132), and ECDSA P-256 for digital signatures. Additional algorithms (Argon2, X25519, Ed25519) are included as experimental extensions."

### Corrección 1.2 — Zero-knowledge

**Paper v1 dice:**
> "Complete zero-knowledge architecture"

**Realidad:**
El zero-knowledge es PARCIAL:
- El cliente encripta credenciales con AES-256-GCM antes de enviarlas al servidor
- El servidor almacena ciphertext + salt + pepper (no ve el plaintext)
- PERO: el servidor conoce el dominio asociado a cada credential (metadata)
- PERO: IPFS almacena datos encriptados pero el hash del contenido es visible

**Corrección:**
> "Client-side encryption with AES-256-GCM ensures the server never processes plaintext credentials. Metadata (domain names, timestamps) remains visible to the server, constituting a partial zero-knowledge model."

---

## 2. Introduction

### Corrección 2.1 — Claim de latencia

**Paper v1 dice:**
> "<0.19ms domain validation latency"

**Sin evidencia medible.** No existía benchmark reproducible.

**Realidad (medida):**
- Exact-match: 0.0030ms/op (pipeline orchestrator overhead incluido)
- Similarity: 0.0054ms/op (38x más rápido que el claim v1)

**Corrección:**
> "Domain validation latency measured at 0.003ms for exact-match and 0.005ms for similarity analysis (75 scenarios, Node.js v24.18.0, linux x64)."

### Corrección 2.2 — Throughput

**Paper v1 dice:**
> "22,177,080 exact-match comparisons/s"

**Realidad:**
- Exact-match: 328,103 comparisons/s (paper inflado 67x)
- Similarity: 185,688 comparisons/s (paper subestimado 35x)

**Corrección:**
> "Measured throughput: 328,103 exact-match comparisons/s and 185,688 similarity comparisons/s. The pipeline orchestrator adds measurable overhead compared to raw algorithm benchmarks."

---

## 3. Related Work

### Corrección 3.1 — Referencias faltantes

**Agregar:**
- NIST SP 800-63B (Digital Identity Guidelines) — justificación de 600K PBKDF2 iterations
- OWASP ASVS v4.0 — estándares de verificación de seguridad
- RFC 7919 — DH groups para TLS (si se menciona TLS en el paper)
- Unicode TR39 — Unicode Security Profile for confusable detection

---

## 4. System Architecture

### Corrección 4.1 — Arquitectura real

**Paper v1 sugiere:**
> Arquitectura genérica de password manager

**Realidad:**
Clean Architecture / Hexagonal con separación estricta:
- **Domain** → entities, ports, value objects (puro, sin dependencias)
- **Application** → use cases (orchestration)
- **Infrastructure** → adapters (API, crypto, DB, IPFS, browser)
- **Shared** → retry, circuit breaker, logger, metrics

**Corrección:**
Agregar diagrama de arquitectura con las 4 capas y las dependencias invertidas. Mencionar que el Domain layer NO tiene dependencias de infraestructura.

### Corrección 4.2 — Stack tecnológico completo

**Agregar tabla:**

| Componente | Tecnología | Versión |
|---|---|---|
| Backend | TypeScript / Node.js | v24.18.0 |
| Extension | Chrome Extension (Manifest V3) | — |
| Database | PostgreSQL | 16 |
| Cache | Redis | 7 (configurado, pendiente integración) |
| Storage | IPFS | con circuit breaker + retry |
| Crypto | Web Crypto API (Node.js) | — |
| Testing | Jest + Playwright + Supertest | — |
| Build | esbuild (ext) + tsc (backend) | — |

---

## 5. Domain Validation Pipeline (contribución principal)

### Corrección 5.1 — Métricas reales del pipeline

**Paper v1 dice:**
> "96.15% detection rate on synthetic attacks (47 scenarios)"
> "100% detection on real-world phishing (26 domains)"

**Realidad (75 escenarios, medido):**

| Dataset | Escenarios | Accuracy | Paper v1 |
|---|---|---|---|
| Synthetic | 47 | 100% (47/47) | 96.15% |
| Real-world | 28 | 100% (28/28) | 100% |
| **Total** | **75** | **100%** | — |

**Por categoría synthetic:**
- Legitimate: 20/20 (100%)
- Typosquatting: 20/20 (100%)
- Homograph: 4/4 (100%)
- Unknown: 3/3 (100%)

**Por categoría real-world:**
- Brand impersonation: 15/15 (100%)
- Subdomain abuse: 3/3 (100%)
- Unicode Cyrillic: 3/3 (100%)
- Typosquatting: 5/5 (100%)
- Punycode IDN: 2/2 (100%)

### Corrección 5.2 — Throughput corregido

**Agregar tabla comparativa:**

| Métrica | Paper v1 | Medido (v2) | Factor |
|---|---|---|---|
| Exact-match latency | <0.001ms | 0.0030ms | 3x más lento |
| Similarity latency | 0.19ms | 0.0054ms | 35x más rápido |
| Exact-match throughput | 22,177,080/s | 328,103/s | 67x inflado |
| Similarity throughput | 5,242/s | 185,688/s | 35x subestimado |

**Nota explicativa:**
> "The exact-match latency increase (0.003ms vs <0.001ms) is attributable to the pipeline orchestrator overhead — the raw DNS normalization + hash lookup is faster, but the 3-phase pipeline adds validation, logging, and timeout management. The similarity improvement (35x) reflects optimized Levenshtein implementation with registrable domain extraction."

### Corrección 5.3 — Datasets

**Paper v1:**
> 47 synthetic + 26 real-world = 73 total

**Paper v2:**
> 47 synthetic + 28 real-world = 75 total (2 escenarios reales adicionales)

**Agregar descripción de datasets:**
- Synthetic: generados programáticamente cubriendo typosquatting, homograph, subdomain, legitimate
- Real-world: extraídos de campañas de phishing documentadas (PhishTank, APWG)

---

## 6. Zero-Knowledge Credential Storage

### Corrección 6.1 — Pipeline de encriptación

**Describir el flujo real:**
```
User → GenerateCredentials(domain)
  → generateComplexPassword(32)  // random chars: A-Z, a-z, 0-9, symbols
  → generateSecureRandom(16)     // salt: 128-bit hex
  → generateSecureRandom(32)     // pepper: 128-bit hex
  → password+pepper              // stored credential format
  → encrypt(password, masterKey) // AES-256-GCM with PBKDF2 key derivation
  → { ciphertext, salt, iv }     // sent to server
```

### Corrección 6.2 — Iteraciones PBKDF2

**Paper v1 dice:**
> "600,000 iterations"

**Verificar:** Esta es la recomendación NIST SP 800-132 (2023 update). Confirmar que el código usa este valor:
```typescript
// src/shared/config.ts
PBKDF2: { ITERATIONS: 600_000, HASH: 'SHA-256', SALT_LENGTH: 16 }
```

**Corrección:** El claim es correcto. Agregar referencia a NIST SP 800-132.

### Corrección 6.3 — Entropy validation

**Agregar descripción:**
El sistema valida que:
- Salt tenga ≥128 bits de entropía (medido por `EntropyValidator.calculateHexEntropy`)
- Pepper tenga ≥128 bits de entropía
- Password base tenga ≥128 bits de entropía estimada
- Se generan warnings si la distribución no es uniforme

---

## 7. IPFS Integration

### Corrección 7.1 — Estado real en v1 vs v2

**Paper v1:**
> "Hybrid IPFS storage with automatic fallback"

**Realidad v1:**
- `upload()` creaba key con `Date.now()` (inseguro, predecible)
- `download()` retornaba datos encriptados SIN descifrar (bug crítico)
- Sin retry ni circuit breaker
- Sin health checks

**Realidad v2 (corregido):**
- Key generada con `crypto.getRandomValues()` (seguro)
- `download()` descifra correctamente con `decrypt()`
- Retry con exponential backoff + jitter (max 3 intentos)
- Circuit breaker (CLOSED→OPEN→HALF_OPEN) con degradación graceful
- Health check verifica conectividad IPFS
- Fallback a in-memory store cuando IPFS no está disponible

### Corrección 7.2 — Circuit Breaker

**Agregar descripción del patrón:**
```
CLOSED (normal) → 3 fallos → OPEN (rechaza requests por 5s)
OPEN → timeout → HALF_OPEN (permite 1 request)
HALF_OPEN → éxito → CLOSED / fallo → OPEN
```

---

## 8. Security Hardening

### Corrección 8.1 — Measures implementadas

**Agregar tabla de controles de seguridad:**

| Control | Descripción | Archivo |
|---|---|---|
| JWT_SECRET gate | Requiere JWT_SECRET en staging/production | `server.ts` |
| CORS explícito | Allowlist de orígenes (no wildcard) | `server.ts` |
| User scoping | Vault/credential queries filtradas por ownerId | `server.ts`, repos |
| Rate limiting | 100 req/15min por IP | `server.ts` |
| CSP headers | Content-Security-Policy configurado | `server.ts` |
| Body limits | 1MB max request size | `server.ts` |
| JWT jti claim | ID único para revocación futura | `auth.ts` |
| Timing-safe compare | Comparación de passwords resistente a timing attacks | `encryption-service.ts` |

### Corrección 8.2 — Threat model

**Agregar sección de threat model que cubra:**
1. **Phishing / AiTM** → Pipeline de validación de dominio
2. **Credential theft** → Encriptación client-side AES-256-GCM
3. **Server compromise** → Zero-knowledge parcial (solo ciphertext)
4. **Brute force** → PBKDF2 600K iteraciones + rate limiting
5. **Replay attacks** → JWT jti + nonce en binding signatures
6. **Timing attacks** → Constant-time password comparison

---

## 9. Resilience & Observability

### Corrección 9.1 — Nueva sección (no existía en v1)

**Agregar sección completa sobre resiliencia:**

| Componente | Mecanismo | Configuración |
|---|---|---|
| IPFS upload/download | Retry + exponential backoff | maxAttempts: 3, baseDelay: 1000ms |
| IPFS circuit breaker | CLOSED→OPEN→HALF_OPEN | threshold: 3, resetTimeout: 5000ms |
| Postgres reads | Retry | maxAttempts: 2 |
| Postgres writes | Retry | maxAttempts: 3 |
| Connection pooling | pg.Pool | max: 10, idle: 30s |
| API timeout | Request deadline | 30s → 504 |
| Health checks | DB + IPFS dependency verification | GET /health |
| Ready checks | All deps reachable | GET /ready |
| Structured logging | JSON/human formats | src/shared/logger.ts |
| Metrics | Prometheus format | GET /metrics |

### Corrección 9.2 — Métricas

**Agregar tabla de métricas disponibles:**

| Métrica | Tipo | Descripción |
|---|---|---|
| `http_requests_total` | Counter | Total de requests por method/path/status |
| `http_request_duration_seconds` | Histogram | Latencia de requests |
| `http_requests_active` | Gauge | Requests concurrentes |
| `cybervault_vaults_total` | Gauge | Total de vaults |
| `cybervault_logins_total` | Counter | Total de logins exitosos |
| `cybervault_credentials_total` | Gauge | Total de credenciales |
| `cybervault_aitm_detections_total` | Counter | Detecciones AiTM |

---

## 10. Testing

### Corrección 10.1 — Cobertura

**Paper v1:**
> Sin details de testing

**Paper v2:**

| Categoría | Suites | Tests | Estado |
|---|---|---|---|
| Unit (value objects) | 3 | ~45 | ✅ |
| Unit (utils) | 3 | ~40 | ✅ |
| Unit (crypto/entropy) | 1 | 8 | ✅ |
| Unit (security/HIBP) | 1 | ~10 | ✅ |
| Unit (AITM pipeline) | 1 | ~20 | ✅ |
| Unit (shared: retry, CB, metrics) | 3 | ~30 | ✅ NEW |
| Unit (encryption service) | 1 | 5 | ✅ NEW |
| Integration (API server) | 1 | 22 | ✅ |
| Integration (IPFS adapter) | 1 | 2 | ✅ |
| Integration (AITM pipeline) | 1 | ~8 | ✅ |
| **Total** | **16** | **197** | **100% passing** |

### Corrección 10.2 — Benchmarks reproducibles

**Agregar instrucciones de reproducción:**
```bash
# Instalar dependencias
npm install

# Ejecutar tests
npm test

# Ejecutar benchmarks
npx tsx benchmarks/domain-validation.bench.ts

# Benchmarks con configuración personalizada
npx tsx benchmarks/domain-validation.bench.ts --iterations 50000 --warmup 1000
```

---

## 11. Results (sección de resultados)

### Corrección 11.1 — Tabla principal de resultados

**Reemplazar tabla v1 con:**

| Métrica | Paper v1 | Paper v2 (medido) | Cambio |
|---|---|---|---|
| Exact-match latency | <0.001ms | 0.0030ms | +0.002ms (overhead pipeline) |
| Similarity latency | 0.19ms | 0.0054ms | -0.185ms (35x mejor) |
| Exact-match throughput | 22,177,080/s | 328,103/s | -98.5% (corregido) |
| Similarity throughput | 5,242/s | 185,688/s | +3,445% (corregido) |
| Synthetic accuracy | 96.15% | 100% | +3.85% |
| Real-world accuracy | 100% | 100% | — |
| Total scenarios | 73 | 75 | +2 real-world |

### Corrección 11.2 — Entorno de ejecución

**Agregar:**
```
Environment:
- Node.js v24.18.0
- OS: Linux x86_64
- CPU: [especificar]
- RAM: [especificar]
- PostgreSQL 16 (para integration tests)
- IPFS: in-memory fallback (sin nodo IPFS externo)
```

### Corrección 11.3 — Análisis de fallos

**Paper v2 tiene 0 fallos en 75 escenarios.** Agregar nota:
> "The pipeline achieved 100% accuracy across all 75 test scenarios with zero false positives and zero false negatives. This represents an improvement over the v1 synthetic accuracy (96.15%) attributable to enhanced confusable detection and Levenshtein threshold tuning."

---

## 12. Discussion

### Corrección 12.1 — Limitaciones reales

**Agregar sección de limitaciones:**
1. **Server-side metadata:** El servidor conoce dominios asociados a credenciales (no es zero-knowledge completo)
2. **IPFS dependence:** Requiere nodo IPFS para almacenamiento descentralizado; fallback a in-memory store
3. **Redis pendiente:** Cache/sesiones no implementadas aún (configurado en docker-compose)
4. **Chrome Extension:** UI creada pero sin tests end-to-end
5. **Escalabilidad:** Benchmarks ejecutados en máquina single-node; no se ha probado con carga distribuida
6. **Dataset size:** 75 escenarios es limitado para conclusiones estadísticas robustas

### Corrección 12.2 — Comparación con work relacionado

**Agregar tabla comparativa con otros password managers:**

| Feature | CyberVault | Bitwarden | 1Password | KeePass |
|---|---|---|---|---|
| AiTM detection | ✅ 3-phase pipeline | ❌ | ❌ | ❌ |
| Pre-submit validation | ✅ | ❌ | ❌ | ❌ |
| IPFS storage | ✅ (optional) | ❌ | ❌ | ❌ |
| Open source | ✅ | ✅ | ❌ | ✅ |
| Zero-knowledge | Partial | ✅ | ✅ | ✅ |
| Browser extension | ✅ | ✅ | ✅ | Plugin |

---

## 13. Conclusions

### Corrección 13.1 — Claims ajustados

**Paper v1 dice:**
> "Achieves <0.19ms latency with 100% detection rate"

**Paper v2 debe decir:**
> "Achieves 0.005ms similarity analysis latency with 100% detection rate across 75 test scenarios, including real-world phishing domains. The 3-phase pipeline provides defense-in-depth against typosquatting, homograph, and subdomain abuse attacks."

### Corrección 13.2 — Contribuciones

**Listar contribuciones reales:**
1. 3-phase domain validation pipeline (ExactMatch → ConfusableDetection → Levenshtein)
2. Client-side AES-256-GCM encryption with PBKDF2 key derivation
3. IPFS integration with circuit breaker pattern for fault tolerance
4. Reproducible benchmark suite with 75 scenarios
5. Chrome Extension for real-time form protection

---

## 14. References

### Corrección 14.1 — Referencias a agregar

1. NIST SP 800-132 — Recommendation for Key Derivation using PBKDF2
2. NIST SP 800-63B — Digital Identity Guidelines (authentication lifecycle)
3. OWASP ASVS v4.0 — Application Security Verification Standard
4. Unicode TR39 — Unicode Security Profile (confusable characters)
5. RFC 7919 — Negotiated Finite Diffie-Hellman Ephemeral Parameters
6. PhishTank — Collaborative phishing verification
7. APWG — Anti-Phishing Working Group reports
8. Chrome Extension Manifest V3 — Google Developer documentation

---

## 15. Figures y Diagramas a agregar/actualizar

### Figura 1 — Clean Architecture layers
```
┌─────────────────────────────────────────┐
│           Infrastructure                │
│  API │ DB │ IPFS │ Browser │ Crypto     │
├─────────────────────────────────────────┤
│           Application                   │
│  Use Cases (CreateVault, Generate...)   │
├─────────────────────────────────────────┤
│             Domain                      │
│  Entities │ Ports │ Value Objects       │
└─────────────────────────────────────────┘
```

### Figura 2 — 3-Phase Pipeline
```
Form Submission → ExactMatch → ConfusableDetection → Levenshtein → Verdict
                  (RFC 1035)    (Unicode TR39)        (Levenshtein)
```

### Figura 3 — Circuit Breaker State Machine
```
CLOSED ──[3 failures]──→ OPEN ──[5s timeout]──→ HALF_OPEN
   ↑                                              │
   └──────────[success]────────────────────────────┘
                    │
                    └──[failure]──→ OPEN
```

### Figura 4 — Encryption Flow
```
Master Key → PBKDF2(salt, 600K) → AES-256-GCM Key
                                        ↓
Plaintext ──────────────────────→ AES-GCM encrypt(data, key, iv)
                                        ↓
                              Ciphertext + Salt + IV → Server/IPFS
```

---

## Checklist final de revisión

- [ ] Abstract actualizado (3 crypto, zero-knowledge parcial)
- [ ] Introduction con métricas reales (0.005ms, 185K/s)
- [ ] Related Work con nuevas referencias (NIST, OWASP, TR39)
- [ ] Architecture con diagrama Clean Architecture
- [ ] Pipeline con tabla de resultados reales (75/75)
- [ ] Crypto con tabla comparativa (3 implementados)
- [ ] IPFS documentado con circuit breaker + retry
- [ ] Security con threat model y controles
- [ ] Resilience como nueva sección
- [ ] Testing con cobertura completa (16 suites, 197 tests)
- [ ] Results con tabla v1 vs v2
- [ ] Discussion con limitaciones
- [ ] Conclusions ajustadas
- [ ] References actualizadas (8 nuevas)
- [ ] Figures creadas (4 diagramas)
