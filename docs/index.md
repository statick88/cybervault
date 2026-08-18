---
layout: default
title: CyberVault v2
description: Phishing-Aware Password Manager Based on User-Centric Domain Validation and Secure Credential Storage
---

# CyberVault v2

**Phishing-Aware Password Manager Based on User-Centric Domain Validation and Secure Credential Storage**

[![Tests](https://github.com/statick88/cybervault/actions/workflows/test.yml/badge.svg)](https://github.com/statick88/cybervault/actions/workflows/test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Release](https://img.shields.io/badge/release-v2.0.0-blue.svg)](https://github.com/statick88/cybervault/releases/tag/v2.0.0)
[![GitHub Pages](https://img.shields.io/badge/docs-GitHub%20Pages-blue)](https://statick88.github.io/cybervault/)

---

## Overview

CyberVault v2 is a phishing-aware password manager that introduces a preventive domain validation mechanism before credential submission. Unlike traditional approaches that rely on post-detection methods, CyberVault enforces a user-centric trust model in which credentials are strictly bound to domains explicitly defined by the user.

### Key Features

- **3-Phase Domain Validation**: ExactMatch → ConfusableDetection → Typosquatting
- **Client-Side Encryption**: AES-256-GCM with PBKDF2 600K iterations
- **Digital Signatures**: ECDSA P-256 for vault integrity
- **Chrome Extension**: Manifest V3 with background worker, content scripts, popup UI
- **REST API**: 16 endpoints with JWT authentication
- **Redis Integration**: Caching and session management
- **IPFS Storage**: Decentralized credential synchronization
- **OpenAPI Documentation**: Swagger UI at `/api/docs`

---

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/statick88/cybervault.git
cd cybervault

# Install dependencies
npm install

# Build the extension
npm run build

# Load in Chrome
# 1. Open chrome://extensions
# 2. Enable Developer mode
# 3. Click 'Load unpacked'
# 4. Select the 'dist' folder
```

### Running Tests

```bash
# Unit + Integration tests
npm test

# E2E tests (requires Chrome)
npx playwright test

# Benchmarks
npx tsx benchmarks/domain-validation.bench.ts
```

### Starting the Server

```bash
# Start the API server
npm start

# Server runs on http://localhost:3000
# API docs at http://localhost:3000/api/docs
```

---

## Architecture

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

### Domain Validation Pipeline

```
Form Submission → ExactMatch → ConfusableDetection → Levenshtein → Verdict
                   (RFC 1035)    (Unicode TR39)        (threshold 0.85)
```

---

## Documentation

| Document | Description |
|----------|-------------|
| [Test Documentation](TEST-DOCUMENTATION.md) | Complete test suite documentation |
| [Research Paper](paper-v2-final.md) | Academic paper (v2) |
| [API Specification](openapi.yaml) | OpenAPI 3.0.3 specification |
| [Corrections Plan](correcciones.md) | Paper v1 → v2 corrections |

---

## Performance

| Metric | Value |
|--------|-------|
| Exact-match latency | 0.003 ms |
| Similarity latency | 0.005 ms |
| Throughput | 328,103 exact-match / 185,688 similarity per second |
| Detection accuracy | 100% |
| False positive rate | 0% |
| Test cases | 239 |
| Benchmark scenarios | 75 |

---

## Download

Download the latest release: [v2.0.0](https://github.com/statick88/cybervault/releases/tag/v2.0.0)

---

## License

MIT License - see [LICENSE](LICENSE) for details.
