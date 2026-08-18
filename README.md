# CyberVault

A phishing-aware password manager that combines zero-knowledge credential storage with real-time AiTM (Adversary-in-the-Middle) detection. Credentials are generated with salt + pepper per domain, encrypted client-side, and backed up to IPFS.

## Architecture

CyberVault follows Clean / Hexagonal Architecture with three layers:

```
src/
  domain/          ← Entities, value objects, ports, domain services (aitm/, autocompletado/)
  application/     ← Use cases (create-vault, generate-credentials, extract-credentials)
  infrastructure/  ← API server, crypto services, repositories, browser extension
```

**Key domain services:**

- **AITM Pipeline** (`domain/services/aitm/`) — composable step-based domain validation: exact match, Unicode confusable detection, typosquatting (Levenshtein), DOM integrity, content fingerprinting
- **Credentials Generator** (`domain/services/autocompletado/`) — salt + pepper credential generation with entropy validation
- **Crypto Layer** (`infrastructure/crypto/`) — Argon2 KDF, X25519 key exchange, Ed25519 signatures, AES-GCM encryption, secure memory

## Quick Start

```bash
# 1. Start infrastructure (Postgres, Redis)
docker-compose up -d postgres redis

# 2. Install dependencies
npm install

# 3. Build
npm run build

# 4. Start the API server
node dist/infrastructure/api/server.js
```

Or with Docker Compose (full stack):

```bash
docker-compose up -d
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/health` | Health check |
| `GET` | `/ready` | Readiness check |
| `POST` | `/api/v1/auth/register` | Register user |
| `POST` | `/api/v1/auth/login` | Login |
| `GET` | `/api/v1/auth/verify` | Verify JWT token |
| `POST` | `/api/v1/vaults` | Create vault |
| `GET` | `/api/v1/vaults` | List vaults |
| `GET` | `/api/v1/vaults/:id` | Get vault |
| `DELETE` | `/api/v1/vaults/:id` | Delete vault |
| `POST` | `/api/v1/credentials/generate` | Generate salt+pepper credentials |
| `POST` | `/api/v1/credentials/extract` | Extract original credentials |
| `GET` | `/api/v1/credentials/validate` | Validate credential format |
| `GET` | `/api` | API info |

## Chrome Extension

The browser extension lives in `src/ui/` (popup, content scripts, options).

```bash
# Build the extension
npm run build:ext

# Load in Chrome:
# 1. chrome://extensions → Enable Developer mode
# 2. Load unpacked → select the dist/ directory
```

## Testing

```bash
# Run all tests
npm test

# Unit tests only
npm run test:unit

# Integration tests only
npm run test:integration

# With coverage
npm run test:coverage

# E2E tests (Playwright)
npm run test:e2e
```

## Benchmarks

```bash
npx tsx benchmarks/domain-validation.bench.ts
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | API server port |
| `NODE_ENV` | `development` | Environment |
| `JWT_SECRET` | _(none)_ | JWT signing secret. Without it, auth is disabled (dev mode) |
| `USE_POSTGRES` | `false` | Use PostgreSQL instead of in-memory storage |
| `DATABASE_URL` | — | PostgreSQL connection string |
| `REDIS_URL` | `redis://localhost:6379` | Redis connection string |
| `IPFS_API_URL` | `http://localhost:5001` | IPFS node API endpoint |
| `HIBP_ENABLED` | `true` | Check passwords against Have I Been Pwned |
| `RATE_LIMIT_MAX` | `100` | Max requests per window |
| `RATE_LIMIT_WINDOW_MS` | `900000` | Rate limit window (15 min) |
| `HTTPS_ENABLED` | `false` | Enable HTTPS with TLS certs |
| `TLS_CERT_PATH` | `./certs/server.crt` | TLS certificate path |
| `TLS_KEY_PATH` | `./certs/server.key` | TLS key path |

## Security Features

- **Domain Validation Pipeline** — multi-step validation (exact match, Unicode homograph detection, typosquatting via Levenshtein distance, DOM integrity checks)
- **Zero-Knowledge Encryption** — credentials encrypted client-side with AES-256-GCM; server never sees plaintext
- **Salt + Pepper** — per-domain credential isolation using email salting and password peppering (128-bit entropy each)
- **Entropy Validation** — cryptographic entropy verification for all generated secrets (minimum 128 bits)
- **AiTM Detection** — real-time adversary-in-the-middle detection using content fingerprinting, timing analysis, and cookie security signals
- **Post-Quantum Ready** — X25519 + Ed25519 key exchange and signatures via `@noble/curves`
- **Rate Limiting** — per-IP request throttling
- **Security Headers** — CSP, HSTS, X-Frame-Options, X-XSS-Protection

## Paper

This project implements the system described in:

> **"Phishing-Aware Password Manager Based on User-Centric Domain Validation and Secure Credential Storage"**
>
> See `paper-Phishing-Aware Password Manager Based on User-Centric Domain Validation and Secure Credential Storage.docm` in the repository root.

## License

MIT
