# CyberVault Architecture

This document describes the system **as the code behaves**, not as any audit or
design document claims it behaves. Every assertion below is traceable to a file
and an enforcement point, cited as `path:line`. Where a property is only
*intended* — that is, the code comments, tests, or documentation express an
intent that no executable check enforces — it is labelled **[intended only]**.

---

## 1. How to read this document

| Convention | Meaning |
|---|---|
| `path:line` | A verifiable reference. The line exists in the working tree at the time of writing. |
| **[intended only]** | The guarantee is expressed in prose or comments but is not enforced by code on the execution path. |
| **Not wired** | The code exists and is unit-tested, but no production entry point constructs or calls it. |

Verification commands for every claim in this document are listed in
[§9](#9-verification-commands-and-what-each-one-proves).

---

## 2. Components

| Component | Entry point | Default port | Responsibility |
|---|---|---|---|
| Core API | `src/infrastructure/api/server.ts:1718` (`start`) | 3000 (`src/shared/config.ts:33`) | Vault lifecycle, credential storage, session authentication, managed release |
| Plus API | `plus/api/main.ts:40` (`main`) | 3001 (`plus/api/main.ts:38`) | Entitlements, capability issuance, step-up challenges |
| Browser extension | `src/infrastructure/manifest/manifest.json:20` (`background.service_worker`) | n/a | Origin binding, autofill guard, credential release, step-up UX |
| Postgres | `docker-compose.yml:147` | internal only | Credential, vault, release-share, and Plus tables |
| Redis | `docker-compose.yml:168` | internal only | Core cache/session backend; **not** used by the JTI store (see [§5.3](#53-jti-single-use)) |

Both Node processes are written in TypeScript with `"module": "commonjs"`
(`tsconfig.json:4`), and both compile to `dist/` before running in Docker
(`docker/Dockerfile.api:71`, `docker/Dockerfile.plus:81`).

---

## 3. Processes and trust boundaries

```
  ┌──────────────────────────── Browser ────────────────────────────┐
  │  popup (ui/popup/popup.ts)                                     │
  │  content scripts (inject.ts, autocomplete.ts)                   │
  │                     │ chrome.runtime.sendMessage               │
  │                     ▼                                          │
  │  service worker (background/auditor.ts) ── holds VEK in memory │
  └──────────────┬──────────────────────────────────┬──────────────┘
                 │ HTTPS/HTTP + Bearer JWT          │ HTTPS/HTTP
                 ▼                                  ▼
  ┌──────────── Core API ────────────┐   ┌──────── Plus API ─────────┐
  │  session auth (auth.ts:196)      │   │  no caller auth (see §6)  │
  │  pins PLUS_PUBLIC_KEY (env)      │   │  holds Ed25519 signing key│
  │  holds Release Share KEK (env)   │   │  issues capabilities      │
  │  wraps Release Shares            │   │  issues step-up challenges│
  └────────────┬─────────────────────┘   └────────────┬──────────────┘
               │                                      │
               ▼                                      ▼
        Postgres (tables §7)                   Postgres (migration 005)
```

### Trust boundaries

| # | Boundary | What crosses it | Enforcement point |
|---|---|---|---|
| B1 | Browser ↔ Core API | Bearer access token, capability token, `credentialId`, `deviceId` | `src/infrastructure/api/auth.ts:196` (`authenticate`), called via `handleAuthRoute` (`src/infrastructure/api/server.ts:1592`) |
| B2 | Browser ↔ Plus API | Capability request fields including `userId` | **No enforcement** — see [§6.1](#61-plus-api-has-no-caller-authentication) |
| B3 | Core ↔ Plus | Nothing at runtime. Core does not call Plus; the browser is the only party that talks to both. | Structural: `PlusBridge` (`src/infrastructure/plus/plus-bridge.ts:102`) has no production caller |
| B4 | Core/Plus ↔ Postgres | Parameterised SQL, JSONB columns | `src/infrastructure/repositories/*.ts`, `plus/infrastructure/repositories/*.ts` |
| B5 | Service worker ↔ page DOM | Form values, autofill decisions | `src/background/credential-release.ts:23` (binding proof → guard → decrypt, in that order) |

**Key structural fact:** the two servers never talk to each other. The browser
extension is the sole client of both, and the capability token is the object
that carries Plus's authorization decision across B1 into Core.

---

## 4. Cryptographic architecture

### 4.1 Key hierarchy

```
User passphrase
  └─ PBKDF2-SHA512, 600 000 iters, 32-byte salt
       key-derivation-service.ts:27
       ├─→ 512-bit master secret   (never persisted)
       │     ├─→ verifier  HKDF "cybervault|master_key_verify|v2"
       │     │                key-derivation-service.ts:42 → chrome.storage.local
       │     └─→ session key HKDF "cybervault|session_key|v2"
       │                    key-derivation-service.ts:43 → chrome.storage.session
       │                    (15 min, master-key-manager.ts:48)
       └─→ VEK  (Vault Encryption Key)  → chrome.storage.session only
             ├─→ EntryKey (personal) = HKDF(VEK, salt, info)
             │        hkdf-derivation.ts:127
             ├─→ EntryKey (managed)  = HKDF(VEK ‖ ReleaseShare, salt, info)
             │        hkdf-derivation.ts:150
             └─→ DomainIndexKey = HKDF(VEK, "cybervault|domain-index|v1")
                      domain-index.ts:41, deriveDomainIndexKey at domain-index.ts:76

RELEASE_SHARE_KEK_SECRET  (exactly 32 bytes, env)
  └─→ Release Share KEK = HKDF("cybervault|release-share-kek|v1")
        release-share-kek.ts:50, deriveReleaseShareKek at release-share-kek.ts:94
        └─→ wrappedShare = base64( iv(12) ‖ AES-256-GCM(ct‖tag) ),
            secretRef as GCM AAD — release-share-kek.ts:38, :181

Ed25519 key pair (Plus)
  └─→ private: PLUS_CAPABILITY_PRIVATE_KEY, or generated at boot
        plus/api/server.ts:147–149
  └─→ public : PLUS_PUBLIC_KEY, pinned in Core
        ed25519-capability.ts:103, loadPlusPublicKey at ed25519-capability.ts:168
```

Enforcement points:

- **The master secret is never written.** Only its verifier hash and salt reach
  storage, under a scheme-tagged key (`src/infrastructure/crypto/master-key-manager.ts:187`–`190`).
  A scheme mismatch from an older build fails closed with `SCHEME_UNSUPPORTED`
  rather than silently re-deriving (`src/infrastructure/crypto/master-key-manager.ts:51`,
  checked at `src/infrastructure/crypto/master-key-manager.ts:161`).
- **The VEK has no persistent storage key.** `STORAGE_KEYS` separates the two
  halves explicitly: `MASTER_KEY_VERIFY` / `SALT` / `SCHEME` / `VAULT_INITIALIZED`
  are commented as `chrome.storage.local`, and `SESSION_KEY` /
  `SESSION_UNLOCK_TIME` as `chrome.storage.session`
  (`src/infrastructure/crypto/master-key-manager.ts:36`–`46`). There is no entry
  under which the VEK is written to disk; it is written only at
  `src/infrastructure/crypto/master-key-manager.ts:196`.
- **Every HKDF label is domain-separated.** The full set of labels actually
  emitted by code:

  | Label | Where |
  |---|---|
  | `cybervault\|master_key_verify\|v2` | `src/infrastructure/crypto/key-derivation-service.ts:42` |
  | `cybervault\|session_key\|v2` | `src/infrastructure/crypto/key-derivation-service.ts:43` |
  | `cybervault\|derive_key\|v2` | `src/infrastructure/crypto/key-derivation-service.ts:44` |
  | `cybervault\|{credentialId}\|v{n}\|{mode}` | `src/infrastructure/crypto/hkdf-derivation.ts:60` |
  | `cybervault\|domain-index\|v1` | `src/domain/services/autofill/domain-index.ts:41` |
  | `cybervault\|release-share-kek\|v1` | `src/infrastructure/crypto/release-share-kek.ts:50` |

  Nothing derives two different secrets under the same label. The personal and
  managed EntryKey paths additionally differ by *input key material* (VEK vs.
  VEK ‖ ReleaseShare) and by mode byte in the info string
  (`src/infrastructure/crypto/hkdf-derivation.ts:150`–`168`).

### 4.2 Who holds the Release Share

- The plaintext Release Share is **never persisted**. Postgres stores only
  `wrapped_share` — three opaque columns, no key material
  (`src/infrastructure/db/migrations/002_release_shares.sql:1`– header comment).
- The only party that can unwrap it is Core, using `RELEASE_SHARE_KEK_SECRET`
  (`src/infrastructure/crypto/release-share-kek.ts:140`; `:103` refuses a secret
  that is not exactly 32 bytes), and only after a capability has been verified
  and its JTI consumed
  (`src/application/use-cases/managed-release.use-case.ts:157`).
- The unwrapped share is zeroized immediately after base64 encoding
  (`src/application/use-cases/managed-release.use-case.ts:185`).
- The share exists in plaintext only inside the extension's service worker for
  the duration of one release, then is combined with the VEK and discarded
  (`src/infrastructure/crypto/hkdf-derivation.ts:150`–`170`;
  `secureZero(combined)` is at `:170` in the `finally` block).

**Core is the sole holder of the Release Share** in the sense that no other
component can produce it: the KEK secret is Core's environment variable, and
Plus has no code path that reads it (`RELEASE_SHARE_KEK_SECRET` appears only in
Core configuration — `docker-compose.yml:58`).

### 4.3 Storage locations

| Secret | Location | Lifetime |
|---|---|---|
| Master verifier hash + salt | `chrome.storage.local` (`src/infrastructure/crypto/master-key-manager.ts:187`–`189`) | Until reset |
| Session key | `chrome.storage.session` (`src/infrastructure/crypto/master-key-manager.ts:196`) | 15 minutes (`src/infrastructure/crypto/master-key-manager.ts:48`) |
| VEK | `chrome.storage.session` only — no `STORAGE_KEYS` entry exists for it | Session |
| Credential ciphertext + index | `chrome.storage.local` — `cybervault_cred_records`, `cybervault_cred_index` (`src/background/auditor.ts:604`–`605`) | Persistent |
| Capability token | **Memory of the service worker only** — created in `src/background/auditor.ts:740` and passed as an argument to `src/background/auditor.ts:442`; never written to `chrome.storage` | One request chain |
| Release Share (plaintext) | Memory only, zeroized (`src/application/use-cases/managed-release.use-case.ts:185`, `src/infrastructure/crypto/hkdf-derivation.ts:170`) | Microseconds |
| Ed25519 private key | Plus environment (`PLUS_CAPABILITY_PRIVATE_KEY`) | Process lifetime |
| `RELEASE_SHARE_KEK_SECRET` | Core environment (`docker-compose.yml:58`) | Process lifetime |

---

## 5. Capability lifecycle

### 5.1 Issuance (Plus)

1. `POST /api/v1/capabilities/request` → `handleCapabilitiesRequest`
   (`plus/api/server.ts:401`).
2. Input validation and an operation whitelist run **before** any signature is
   produced (`plus/api/server.ts:435`).
3. `authorizeCapabilityRequest` (`plus/api/server.ts:444`) gates on entitlement,
   risk, and challenge state. **[intended only]** as far as "decides before it
   signs" — the ordering is enforced by code position, not by a type that makes
   signing unreachable.
4. `CapabilityIssuer.issue` (`plus/domain/services/capability-issuer.ts:96`)
   builds the payload, signs it, and **self-verifies its own signature** as
   defense in depth (`plus/domain/services/capability-issuer.ts:134`).

### 5.2 Verification (Core only)

Verification happens in exactly two places, both in Core:

| Site | File:line |
|---|---|
| `ManagedReleaseUseCase` | `src/application/use-cases/managed-release.use-case.ts:136` (signature), `:157` (JTI) |
| `GetCredentialWithCapabilityUseCase` | `src/application/use-cases/managed-release.use-case.ts:376` (signature), `:392` (JTI) |

Signature verification binds the capability to server-derived values — never to
anything in the request body:

```ts
const expected: CapabilityBindingContext = {
  userId,                     // from the Bearer token, not the body
  resourceId: requestedSecretRef,  // from Core's own store
  secretRef:  requestedSecretRef,
  deviceId,                   // declared, then compared field by field
};
```
(`src/infrastructure/api/server.ts:1080`–`1086`)

`verifyCapabilityBindings` (`src/infrastructure/crypto/ed25519-capability.ts:432`)
compares each field individually, so a capability minted for one secret cannot be
replayed against another even if the signature is valid.

The verification key is **pinned configuration**, never request data: the
handler reads `capabilityToken` and `credentialId` from the body and ignores any
key material in it (`src/infrastructure/api/server.ts:1021`–`1030` carries that
warning verbatim), while the key itself is loaded once in the constructor at
`src/infrastructure/api/server.ts:157`.
When `PLUS_PUBLIC_KEY` is unset or malformed, both verification sites refuse
with an explicit message rather than skipping the check
(`src/application/use-cases/managed-release.use-case.ts:211`, `:440`).

**`GetCredentialWithCapabilityUseCase` is Not wired.** It is constructed only
by tests (`tests/application/managed-release.test.ts`). No production route
instantiates it. The live endpoint is `POST /api/v1/vaults/{vaultId}/managed-release`
(`src/infrastructure/api/server.ts:1502` regex, handler
`src/infrastructure/api/server.ts:1000`, wrapped in `handleAuthRoute` at
`src/infrastructure/api/server.ts:1592`), which runs `ManagedReleaseUseCase`.

### 5.3 JTI single-use

- `verifyAndConsumeJti` (`src/infrastructure/crypto/jti-store.ts:177`) is the
  only entry point used by the release flow
  (`src/application/use-cases/managed-release.use-case.ts:157`).
- Two implementations: `InMemoryJtiStore` (`src/infrastructure/crypto/jti-store.ts:34`)
  and `RedisJtiStore` (`src/infrastructure/crypto/jti-store.ts:89`).
- Selection happens in `createJtiStore` (`src/infrastructure/crypto/jti-store.ts:143`):
  Redis is used **only** when `REDIS_URL` is set *and* is not the
  `redis://localhost:6379` default.
- **In the shipped Compose topology the JTI store is in-process.** Compose sets
  `REDIS_HOST`/`REDIS_PORT` (`docker-compose.yml:43`–`44`) but never `REDIS_URL`,
  so `createJtiStore` returns `InMemoryJtiStore`. Consequence: replay protection
  does not survive a Core restart and is not shared between two Core replicas.
- Consumption order inside the release flow is fixed by position: signature →
  TTL → JTI → credential resolution → unwrap
  (`src/application/use-cases/managed-release.use-case.ts:136` → `:153` → `:157`
  → `:169` → `:179`).

**Plus does not consume JTIs at issuance.** `CapabilityIssuer.issue` signs and
self-verifies but never touches the JTI store
(`plus/domain/services/capability-issuer.ts:96`–`150`).
`verifyCapabilityCore` (`plus/domain/services/capability-issuer.ts:304`) and
`consumeCapabilityJti` (`plus/domain/services/capability-issuer.ts:322`) are
exported but have **no callers anywhere in `src/` or `plus/`**. Plus does
consume a JTI in one place: the step-up PIN path, inside
`ChallengeService.verifyPin` (`plus/domain/services/challenge.ts:361`), which is
the JTI of the *challenge*, not of the capability.

### 5.4 What carries the capability between the two services

Nothing, at the server level. The browser requests a capability from Plus,
receives it in the response, and posts it to Core. This is why B2 ([§3](#3-processes-and-trust-boundaries))
matters: an unauthenticated caller can ask Plus for a capability, but they still
need a valid Bearer token and vault ownership to spend it at Core.

---

## 6. Plus API surface

### 6.1 Plus API has no caller authentication

`routeRequest` (`plus/api/server.ts:791`–`820`) dispatches eight routes and
performs no authentication step:

| Route | Handler |
|---|---|
| `GET /health` | `handleHealth` (`plus/api/server.ts:241`) |
| `GET /ready` | `handleReady` (`plus/api/server.ts:252`) |
| `POST /api/v1/capabilities/request` | `handleCapabilitiesRequest` (`plus/api/server.ts:401`) |
| `POST /api/v1/entitlements/check` | `handleEntitlementsCheck` (`plus/api/server.ts:536`) |
| `POST /api/v1/challenges/trigger` | `handleChallengeTrigger` (`plus/api/server.ts:615`) |
| `POST /api/v1/challenges/verify` | `handleChallengeVerify` (`plus/api/server.ts:661`) |
| `GET /api/v1/crypto/public-key` | `handlePublicKey` (`plus/api/server.ts:696`) |
| `POST /api/v1/audit` | `handleAudit` (`plus/api/server.ts:712`) |

Supporting facts, all verified:

- `PlusConfig.serviceSecret` exists (`plus/api/server.ts:110`) but is **read
  nowhere else in `plus/`**. The extension *does* send `X-Service-Secret`,
  `X-Core-Service`, and an `Authorization` header on capability requests
  (`src/background/auditor.ts:398`–`400`); the Plus server never inspects them.
- `userId` is taken from the request body (`plus/api/server.ts:401`).
- CORS is `Access-Control-Allow-Origin: *`
  (`plus/api/server.ts:757`) — versus Core, which pins one origin
  (`src/infrastructure/api/middleware/cors.ts:3`).
- Rate limiting is a **no-op**: `checkRateLimitOrError` returns `true`
  unconditionally with the comment "Simple in-memory rate limiting (production
  would use Redis)" (`plus/api/server.ts:236`–`239`). Core's equivalent
  actually calls `checkRateLimit` (`src/infrastructure/api/server.ts:397`–`398`).

### 6.2 Single signing key

If `PLUS_CAPABILITY_PRIVATE_KEY` is unset the server generates an ephemeral
keypair at boot and warns; the same key is handed to both the capability issuer
and the challenge service, and both singletons are reset so they cannot hold a
stale key (`plus/api/server.ts:147`–`156`). Practical consequence: an ephemeral
key means capabilities issued before a restart are rejected after it — which,
combined with the in-memory JTI store, makes the whole capability system
process-local in the default deployment.

---

## 7. Data model

Applied by `npx tsx src/infrastructure/db/cli.ts up` → `MigrationRunner`
(`src/infrastructure/db/migrate.ts:21`), which executes each `.sql` file in
lexical order inside a transaction with a `schema_migrations` ledger
(`src/infrastructure/db/migrate.ts:76`–`87`).

| Migration | Adds |
|---|---|
| `001_initial_schema.sql` | `vaults`, `credentials` (baseline), `users`, `trust_store` |
| `002_release_shares.sql` | `release_shares(secret_ref PK, wrapped_share, created_at)` — **no key material** |
| `003_credentials_authoring_and_secret_ref.sql` | `credentials.mode`, `.salt`, `.version`, `.release_share_ref` + unique index `uq_credentials_release_share_ref` |
| `004_optimistic_locking.sql` | `lock_version BIGINT NOT NULL DEFAULT 1` on `vaults` and `credentials`, guarded `UPDATE ... WHERE lock_version = $2` |
| `005_plus_schema.sql` | `challenges`, `plus_entitlements`, `plus_users`, `plus_resources` |

**Column types (correcting a common misreading):** `mode` is `VARCHAR(20)`,
`salt` is `TEXT`, `version` is `INTEGER`. They are plain single-word columns,
not a composite or a mapping. The `credentials` table has **no `metadata`
column**.

The repository mirrors the DDL at runtime so a container pointed at an
unmigrated database still boots: `PostgresCredentialRepository.initializeTable`
emits `CREATE TABLE IF NOT EXISTS credentials` plus
`ALTER TABLE ... ADD COLUMN IF NOT EXISTS`, declaring
`mode VARCHAR(20) DEFAULT 'personal'`, `salt TEXT`, `version INTEGER DEFAULT 1`,
`release_share_ref VARCHAR(255)`.

Row mapping is centralised: `src/infrastructure/repositories/row-mappers.ts`
(`mapVaultRow:170`, `mapCredentialRow:195`), with JSONB parsing in
`src/shared/jsonb.ts:30` (`parseJsonbColumn`) — one place that tolerates both a
string and an already-parsed object.

---

## 8. Browser extension

### 8.1 What actually ships

The MV3 manifest declares (`src/infrastructure/manifest/manifest.json`):

- `manifest_version: 3` (`src/infrastructure/manifest/manifest.json:2`)
- `background.service_worker: "background/auditor.js"` (`src/infrastructure/manifest/manifest.json:20`)
- `permissions: ["storage", "alarms", "tabs"]` (`src/infrastructure/manifest/manifest.json:22`)
- content scripts `ui/content-scripts/inject.js` + `autocomplete.js` (`src/infrastructure/manifest/manifest.json:28`)
- CSP with `connect-src 'self'` plus exactly three hosts, and
  `frame-ancestors 'none'` (`src/infrastructure/manifest/manifest.json:47`)

The esbuild bundler (`scripts/build-extension.mjs`) has five entry points —
`background/auditor.ts` (`scripts/build-extension.mjs:44`),
`ui/popup/popup.ts` (`scripts/build-extension.mjs:63`),
`ui/content-scripts/inject.ts` (`scripts/build-extension.mjs:78`),
`autocomplete.ts` (`scripts/build-extension.mjs:92`),
`ui/options/options.ts` (`scripts/build-extension.mjs:108`) — all emitted as
`iife` for a browser platform.

**Not shipped:** `src/ui/content-scripts/managed-decrypt.ts` is neither in the
manifest nor in any build entry point. It has tests
(`tests/ui/managed-decrypt.test.ts`) but no bundle reaches it. The live
release path runs entirely through the service worker. (`totp-generator.ts` is
also not an entry point, but it is reachable — imported by `autocomplete.ts:38`.)

### 8.2 The release path and its ordering guarantee

`src/background/credential-release.ts:23`–`31` documents, and the code
implements, a strict order:

1. **Origin-binding proof.** `lookupToken(origin) = HMAC(DomainIndexKey,
   canonicalOrigin)` (`src/domain/services/autofill/domain-index.ts:19`) gives an
   opaque index. No origin string is stored, so a database dump of the extension
   storage reveals no browsing history.
2. **Guard.** `evaluateAutofill` decides whether this origin may receive the
   credential.
3. **Capability → Release Share → derive → decrypt.** Only after 1 and 2 pass
   does the code ask Plus for a capability and Core for the share.

Failure codes are enumerated rather than free-form
(`src/background/credential-release.ts:108`–`115`). The extension's release
outcome types are `ReleaseOutcome` / `ReleaseDenialCode`
(`src/background/credential-release.ts:108`).

### 8.3 Step-up state

Step-up state is **in-memory only**, inside the service worker:
`stepUpChallenges` (`src/background/auditor.ts:1036`), `challengedBindings`
(`src/background/auditor.ts:1046`), `completedStepUps`
(`src/background/auditor.ts:1049`), keyed by `bindingKey` — a serialization of
the credential + origin + operation triple (`src/background/auditor.ts:1058`).
MV3 service workers are evicted, so completed step-ups do not survive worker
restarts.

The step-up endpoint URL is hard-coded to `http://localhost:3011`
(`src/background/auditor.ts:1085`), which matches the configurable
`plus_base_url` default (`src/background/auditor.ts:375`, `:561`, `:838`) but
**not** the Compose-published port (`docker-compose.yml:99` publishes
`${PLUS_PORT:-3001}`). See [§10](#10-known-divergences).

### 8.4 Step-up challenge issuance

- `ChallengeService.createChallenge` (`plus/domain/services/challenge.ts:196`)
  reuses an outstanding challenge for the same binding
  (`plus/domain/services/challenge.ts:208`), sets a 10-minute TTL
  (`plus/domain/services/challenge.ts:215`) and `maxAttempts: 3`
  (`plus/domain/services/challenge.ts:216`), and generates a 32-byte nonce
  (`plus/domain/services/challenge.ts:219`).
- The PIN is 6 digits from a rejection-sampled CSPRNG
  (`plus/domain/services/challenge.ts:395`–`414`), stored as
  `HMAC-SHA256(pinSalt, pin)` via `computePinHmac`
  (`plus/domain/services/challenge.ts:424`, called at
  `plus/domain/services/challenge.ts:231`).
- **Plaintext hygiene:** `metadata.generatedPin` is attached in memory at
  `plus/domain/services/challenge.ts:255`, and every repository write runs
  through `sanitizeMetadata`
  (`plus/infrastructure/repositories/PostgresChallengeRepository.ts:112`), which
  drops `PLAINTEXT_PIN_METADATA_KEY = "generatedPin"`
  (`plus/infrastructure/repositories/PostgresChallengeRepository.ts:49`) before
  binding (`plus/infrastructure/repositories/PostgresChallengeRepository.ts:184`).
  The `pin_hmac` / `pin_salt` columns are what the migration creates.
  **The PIN itself is not persisted in plaintext.**
- **No delivery channel in the default wiring.** `createChallenge` sends the
  email to the literal `user@example.com`
  (`plus/domain/services/challenge.ts:265`), and `plus/api/main.ts` passes no
  `emailService`, so `PlusApiServer` falls back to `NoOpEmailService`
  (`plus/api/server.ts:134`). In the shipped configuration nothing delivers the
  PIN to the user.

---

## 9. Verification commands and what each one proves

| Command | Result | Proves | Does **not** prove |
|---|---|---|---|
| `npx tsc --noEmit` | exit 0, 0 errors | The `src/` + `plus/` program type-checks under `strict` (with `plus/admin` excluded, `tsconfig.json:23`–`28`) | Anything about runtime behaviour |
| `npx jest --silent` | 86 suites passed, 3 skipped; 1561 tests passed, 0 failed, 17 skipped | Unit and behavioural coverage of crypto, release ordering, contract, and schema assertions | Live infrastructure: the 3 skipped suites and 10 of the 17 skipped tests are gated on `CYBERVAULT_TEST_DATABASE_URL` (`migration-003`, `migration-004`, `postgres-release-share-store`) and `IPFS_API_URL` (`tests/integration/ipfs-adapter.test.ts:3`). The other 7 skipped tests are the `it.skip` placeholders inside those DB suites. |
| `npx tsx src/infrastructure/db/cli.ts status` | migration ledger | Which migrations the configured database has applied | That the schema matches the code's expectations for columns added outside a migration |
| `npm run build:ext` | `dist/` | The five entry points bundle | That the manifest references them (check `manifest.json` separately) |
| SonarQube `api/qualitygates/project_status?projectKey=cybervault` | 401 anonymously | — | The gate status. **The quality-gate figures quoted elsewhere (STATUS OK, `new_coverage` 82.7% vs 80%, 0 pending hotspots) are the last reported analysis and were not re-verified in this session.** |

### IPFS: verified behaviour

The README advertises IPFS storage. What the code does:

1. `tsconfig.json:4` sets `"module": "commonjs"`, so the emitted
   `dist/src/infrastructure/ipfs/ipfs-adapter.js:75` contains
   `require("ipfs-http-client")`, not a native dynamic `import()`.
2. `ipfs-http-client@60` is `"type": "module"` with `exports` and no CJS main;
   `require("ipfs-http-client")` fails with `ERR_PACKAGE_PATH_NOT_EXPORTED`.
3. `IPFSAdapter.createClient` catches everything
   (`src/infrastructure/ipfs/ipfs-adapter.ts:76`–`82`) and returns `null`, which
   selects the in-memory store.

This was confirmed by executing the compiled adapter: it logs
`[IPFS] Unable to connect ... — using in-memory fallback.` for the default
`localhost:5001` configuration even though the failure is module resolution,
not connectivity; `isHealthy()` returns `false` and round-trips still succeed
in memory. So **the in-memory fallback is the only path exercised under the
CommonJS build**; the real client would work only under a native-ESM runtime.

---

## 10. Known divergences

Things the code does that differ from documentation, configuration defaults, or
comments. Each is verified; none is fixed here.

| # | Divergence | Evidence |
|---|---|---|
| D1 | Extension defaults to `localhost:3010` (Core) and `localhost:3011` (Plus); Compose publishes `3000` and `3001` | `src/background/auditor.ts:457`, `:375`, `src/ui/popup/popup.ts:140` vs. `docker-compose.yml:25`, `:99` |
| D2 | `PlusConfig.serviceSecret` is defined but never read; the extension's service-secret headers are ignored | `plus/api/server.ts:110`; no reader in `plus/` |
| D3 | `verifyCapabilityCore` / `consumeCapabilityJti` exported with no callers | `plus/domain/services/capability-issuer.ts:304`, `:322`; no matches in `src/` or `plus/` |
| D4 | `GetCredentialWithCapabilityUseCase` is test-only | constructed only in `tests/application/managed-release.test.ts` |
| D5 | `PlusBridge` has no production caller | `src/infrastructure/plus/plus-bridge.ts:102`; only `tests/crypto/plus-bridge.test.ts` imports it |
| D6 | `src/ui/content-scripts/managed-decrypt.ts` is neither in the manifest nor in any build entry | `src/infrastructure/manifest/manifest.json:28`; `scripts/build-extension.mjs:44`, `:63`, `:78`, `:92`, `:108` |
| D7 | `plus/admin` pages call endpoints that do not exist: every list route 404s, `GET /api/v1/audit` 405s (server side is POST-only) | `plus/admin/src/services/api.ts:170`–`252` vs. `routeRequest` (`plus/api/server.ts:791`–`820`); `plus/admin/src/pages/Audit.tsx:30` |
| D8 | Compose publishes no host port for Postgres or Redis, and sets no `REDIS_URL` | `docker-compose.yml:147`, `:168`; no `REDIS_URL` key |
| D9 | `swagger` and `plus` both default to host port 3001 | `docker-compose.yml:99` and `:209` |
| D10 | The IPFS warning message blames connectivity when the real failure is module resolution | `src/infrastructure/ipfs/ipfs-adapter.ts:76`–`82` |
| D11 | `docs/index.md` claims "16 endpoints", "ECDSA P-256", "Redis ... session management", "IPFS storage" without qualification | `docs/index.md` Key Features |

---

## 11. Status of this documentation

This file exists because `odd/tasks/cybervault-final-security-architecture.md:704`
lists `ARCHITECTURE.md` as **Missing (severity M)** and line 141 marks it
`pending`. Writing the document closes that documentation item only.

**There is no review certificate attached to this work.** The independent
reviewer step could not be executed in this environment (four attempts, all
identical failure: the reviewer sub-agent cannot be dispatched because
"OpenCode's free tier can only be used from within OpenCode"). Treat this
document as unreviewed until an independent pass signs off on it.
