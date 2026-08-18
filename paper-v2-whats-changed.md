# Paper v2 — What Changed (Executive Summary)

> One-page overview of all corrections from paper v1 to paper v2.

---

## Critical Fixes

| Metric | Paper v1 (claimed) | Paper v2 (measured) | Issue |
|---|---|---|---|
| Exact-match throughput | 22,177,080/s | **328,103/s** | Inflated 67× — no benchmark existed |
| Similarity throughput | 5,242/s | **185,688/s** | Underestimated 35× |
| Synthetic accuracy | 96.15% | **100%** (47/47) | 3 false negatives eliminated |
| Crypto algorithms | 6 claimed | **3 implemented** | Argon2, X25519, Ed25519 are experimental only |
| Domain count | 26 real-world | **28 real-world** | 2 additional phishing domains |
| Zero-knowledge | "Complete" | **Partial** | Server knows domain metadata |

---

## Structural Changes

| Area | Paper v1 | Paper v2 |
|---|---|---|
| Architecture | Generic description | Clean Architecture (Hexagonal) with 4 layers |
| Crypto section | 6 algorithms listed | 3 core + 3 experimental, with comparison table |
| IPFS | "Automatic fallback" claimed | Circuit breaker + retry documented; v1 bugs fixed |
| Security | None | Threat model + 8 security controls table |
| Resilience | None | New section: retry, circuit breaker, health checks, metrics |
| Testing | None | 16 suites, 197 tests, 100% passing |
| Discussion | None | 6 limitations + feature comparison with Bitwarden/1Password/KeePass |
| References | Baseline | 8 new references (NIST, OWASP, TR39, PhishTank, APWG, RFC 7919, MV3) |

---

## What Was Already Corrected (v2-corrected.docx)

1. 96.15% → 100% (all locations)
2. \<0.19ms → 0.005ms
3. 22 million → 328,103
4. 150,000× → 33,000×
5. four-layer → three core algorithms
6. 26 domains → 28 domains
7. False negative claim removed

## What Still Needs Manual Application

Items 8–22 from correcciones.md — all remaining text changes are documented in:
**`/home/search14/cybervault/paper-v2-updates.md`**

---

## Benchmark Results (from benchmark-report.json)

```
Environment: Node.js v24.18.0, Linux x86_64
Iterations:  100,000 (exact-match), 10,000 (similarity)
Warmup:      1,000

Exact-match:  0.0030ms/op  —  328,103 comparisons/s
Similarity:   0.0054ms/op  —  185,688 comparisons/s

Accuracy: 75/75 scenarios (100%) — 0 failures
  Synthetic:  47/47 (100%)
  Real-world: 28/28 (100%)
```

---

## Files Created

| File | Purpose |
|---|---|
| `paper-v2-updates.md` | Complete diff: old text → new text for every section |
| `paper-v2-whats-changed.md` | This executive summary |
