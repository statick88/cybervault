# CyberVault — Paper v2 Corrections Summary

**Documento original:** `paper-Phishing-Aware Password Manager Based on User-Centric Domain Validation and Secure Credential Storage.docm`
**Documento corregido:** `paper-v2-corrected.docx`
**Script de automatización:** `apply_paper_corrections.py`
**Fecha:** 2026-09-23
**Estado:** 25/43 correcciones aplicadas automáticamente (58%), 18 estructurales pendientes (manual)

---

## 📋 Enlaces Rápidos

| Archivo | Descripción |
|---------|-------------|
| [paper-v2-corrected.docx](./paper-v2-corrected.docx) | **Documento Word con correcciones aplicadas** |
| [paper-v2-updates.md](./paper-v2-updates.md) | Lista completa de 43 correcciones (markdown) |
| [apply_paper_corrections.py](./apply_paper_corrections.py) | Script python-docx para automatización |
| [docs/INSTALACION_PLUGIN.md](./docs/INSTALACION_PLUGIN.md) | **Manual completo de instalación** |
| [docs/correcciones.md](./docs/correcciones.md) | Documentación de bugfixes y correcciones |

---

## ✅ Correcciones Aplicadas Automáticamente (25)

### Texto / Párrafos (8)

| # | Ubicación | Antes | Después |
|---|-----------|-------|---------|
| 1 | **Para 9 (Abstract)** | `negligible latency (<0.19 ms)` | `average latency of 0.003ms for exact-match and 0.005ms for similarity analysis across 75 test scenarios (Node.js v24.18.0, linux x64)` |
| 2 | **Para 9 (Abstract)** | — | Agregado: `and zero false negatives` |
| 3 | **Para 113** | `95.00% (19/20) of typosquatting variants` | `100% (20/20) of typosquatting variants` |
| 4 | **Para 137** | `exact-match latency <0.001 ms, similarity similarity latency 0.005 ms... 33,000× faster` | `exact-match latency 0.0030ms, similarity latency 0.0054ms, exact-match throughput 328,103/s, similarity throughput 185,688/s. The pipeline orchestrator adds measurable overhead compared to raw algorithm benchmarks.` |
| 5 | **Para 164** | `95.00% for typosquatting variants` | `100% for typosquatting variants` |
| 6 | **Para 166** | `average latency of <0.19 ms` | `average latency of 0.005ms` |
| 7 | **Para 166** | `33,000× faster` | `35× faster` |
| 8 | **Para 166** | `Argon2id key derivation` | `PBKDF2 with 600,000 iterations key derivation` |

### Tabla 0 — Confusion Matrix (3)

| Celda | Antes | Después |
|-------|-------|---------|
| Row 2 Col 1 (Attack Allowed) | `1` | `0` |
| Row 2 Col 2 (Attack Prevented) | `71` | `72` |
| Row 3 Col 1 (Metrics) | `Overall Accuracy: 99.1%\nPrecision: 100.0%\nRecall: 98.6%\nF1-Score: 99.3%` | `Overall Accuracy: 100%\nPrecision: 100.0%\nRecall: 100%\nF1-Score: 100%` |

### Tabla 2 — Feature Comparison (2)

| Celda | Antes | Después |
|-------|-------|---------|
| Row 3 Col 1 (Typosquatting) | `Yes (95%)` | `Yes (100%)` |
| Row 7 Col 1 (Zero-knowledge) | `Yes` | `Partial` |

### Tabla 3 — Performance Metrics (12)

| Métrica | Antes (Paper v1) | Después (Paper v2 Medido) |
|---------|------------------|---------------------------|
| Exact-match latency | `< 0.001 ms` | `0.0030 ms` |
| Exact-match throughput | `22,177,080/s` | `328,103/s` |
| Similarity-analysis latency | `0.19 ms` | `0.0054 ms` |
| Similarity-analysis throughput | `5,242/s` | `185,688/s` |
| Cryptographic operations | `Non-blocking (software-based)` | `Non-blocking (software-based)` |
| Memory footprint | `< 50 MB` | `< 50 MB` |

---

## 📝 Correcciones Pendientes — Manuales (18)

Estas requieren edición manual en **Word / LibreOffice** por ser adiciones estructurales (nuevas secciones, tablas, figuras, referencias):

| # | Sección | Acción Requerida |
|---|---------|------------------|
| 1 | **3. Related Work** | Insertar párrafo con referencias NIST SP 800-63B [10], OWASP ASVS v4.0 [11], Unicode TR39 [12], PhishTank [13], APWG [14] |
| 2 | **4.1 Architecture** | Reemplazar párrafo "generic password manager architecture" por descripción Clean Architecture 4 capas (Domain, Application, Infrastructure, Shared) |
| 3 | **4.2 Tech Stack** | Insertar tabla: Component / Technology / Version (9 filas: Backend, Extension, Database, Cache, Storage, Crypto, Testing, Build) |
| 4 | **5. Crypto** | Reescribir sección completa: 3 algoritmos core (no 6), tabla comparación, flow encryption, entropy validation |
| 5 | **6.1 Pipeline Metrics** | Reemplazar claim 96.15% por texto + tabla 75 escenarios (Synthetic 47/47, Real-world 28/28, Total 100%) + desglose por categoría |
| 6 | **6.2 Throughput Correction** | Insertar tabla: Metric / Paper v1 / Measured v2 / Factor (4 filas con correcciones 3× overhead, 35× faster, 67× inflated, 35× underestimated) |
| 7 | **6.3 Dataset Description** | Agregar descripción datasets: Synthetic 47 (20 legit, 20 typo, 4 homo, 3 unk), Real-world 28 (15 brand, 3 subdomain, 3 cyrillic, 5 typo, 2 punycode) |
| 8 | **6.4 Execution Environment** | Insertar bloque de código con entorno: Node.js v24.18.0, Linux x86_64, 100K/10K iteraciones, warmup 1K, PostgreSQL 16, IPFS in-memory |
| 9 | **7. IPFS** | Reescribir: circuit breaker, retry, secure keys, health checks, fallback. Agregar diagrama state machine CLOSED→OPEN→HALF_OPEN |
| 10 | **8. Security Hardening** | Nueva subsección: tabla 8 controles (JWT_SECRET, CORS, User scoping, Rate limiting, CSP, Body limits, JWT jti, Timing-safe) + threat model tabla 6 amenazas |
| 11 | **9. Resilience & Observability** | Nueva sección completa: tabla 8 mecanismos (retry, CB, pooling, timeout, health, ready, logging, metrics) + tabla 8 métricas Prometheus |
| 12 | **10. Testing** | Nueva sección: tabla cobertura 16 suites / 197 tests + comandos reproducibles benchmarks |
| 13 | **11. Results** | Nueva tabla maestra v1 vs v2: 7 métricas con Change column |
| 14 | **12.1 Limitations** | Nueva subsección: 6 limitaciones (metadata server, IPFS dependency, Redis pending, E2E testing, scalability, dataset size) |
| 15 | **12.2 Feature Comparison** | Nueva tabla: Feature / CyberVault / Bitwarden / 1Password / KeePass (7 features) |
| 16 | **13. Conclusions** | Ajustar claims: 0.005ms latency, 100% across 75 scenarios, 3-phase pipeline defense-in-depth |
| 17 | **13.2 Contributions** | Nueva lista: 5 contribuciones principales |
| 18 | **14. References** | Agregar 8 nuevas entradas [9]-[16] al final de referencias |
| 19 | **15. Figures** | Agregar/actualizar 4 figuras: Clean Architecture, 3-Phase Pipeline, Circuit Breaker, Encryption Flow |

---

## 🚀 Instalación Rápida (Resumen)

```bash
# 1. Clonar repositorio
git clone <URL_REPO>
cd cybervault

# 2. Configurar entorno
cp .env.example .env
# Editar .env con POSTGRES_PASSWORD, JWT_SECRET, etc.

# 3. Levantar servicios (Docker)
docker compose up -d postgres redis api

# 4. Verificar servicios
curl -s http://localhost:3010/health | python3 -m json.tool

# 5. Instalar dependencias y compilar extensión
npm install
npm run build:all

# 6. Instalar en Chrome
# chrome://extensions/ → Modo desarrollador → Cargar sin empaquetar → Seleccionar carpeta dist/

# 7. Probar detección AITM
# http://localhost:3010/test-plugin.html
```

### 📖 Manual Completo de Instalación

**Archivo:** [`docs/INSTALACION_PLUGIN.md`](./docs/INSTALACION_PLUGIN.md) (755 líneas)

Incluye:
- ✅ Prerrequisitos (Node.js 18+, Docker, Chrome 120+)
- ✅ Arquitectura del sistema (diagrama ASCII)
- ✅ Servicios backend (Docker Compose, variables de entorno)
- ✅ Verificación (health/ready checks, DB, Redis)
- ✅ Build del plugin Chrome (npm run build:all)
- ✅ Instalación en Chrome (2 opciones)
- ✅ Configuración (dominios confiables, opciones)
- ✅ Uso básico (flujo primer uso, generación credenciales)
- ✅ Troubleshooting (errores comunes, logs, reinicio, limpieza)
- ✅ Variables de entorno (referencia completa 17 variables)
- ✅ Endpoints API (16 endpoints documentados)
- ✅ Acceso por red (local, LAN, Tailscale)
- ✅ Seguridad (controles, headers, permisos)
- ✅ Página de prueba (49 dominios categorizados)
- ✅ Credenciales de prueba (4 usuarios pre-creados con JWT tokens)

---

## 📊 Estado del Proyecto

| Componente | Estado |
|------------|--------|
| **Paper v2** | 25/43 correcciones aplicadas |
| **CI Pipeline** | ✅ GitHub Actions con `setup-chrome` configurado |
| **E2E Tests** | 22 tests listos (se ejecutan en CI con Chrome real) |
| **Security Audit** | 0 CRITICAL, 0 HIGH, 0 MEDIUM (RDD approved) |
| **Build** | ✅ Manifest V3, IIFE, sin Node.js globals |
| **Documentación** | ✅ Manual instalación completo |

---

## 🔗 Referencias de Commits

| Commit | Mensaje |
|--------|---------|
| `7aa4cfb` | `doc: apply 25 Paper v2 corrections via python-docx script` |
| `40710ed` | `chore: update progress — Paper v2 25 corrections applied via python-docx` |
| `47bb0d1` | `test: add channel: 'chrome' to playwright config for E2E tests` |

---

## 📌 Próximos Pasos Recomendados

1. **Editar manualmente** `paper-v2-corrected.docx` en Word/LibreOffice para las 18 correcciones estructurales
2. **Push a main** → GitHub Actions ejecutará 22 E2E tests automáticamente
3. **Verificar** resultados en CI y cerrar SDD `cybervault-100-completion` con Verify + Archive