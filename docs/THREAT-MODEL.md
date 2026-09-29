# CyberVault Threat Model

Companion to [`ARCHITECTURE.md`](./ARCHITECTURE.md). Same rule: every claim is
cited to a file and an enforcement point (`path:line`), and properties that are
only *expressed* rather than *enforced* are labelled **[intended only]**.

---

## 1. Method

1. Enumerate assets and where they live.
2. Enumerate trust boundaries and what an attacker on each side of one can do.
3. For each defended attack, name the single line of code that defends it —
   if no such line exists, the attack is listed as residual, not addressed.
4. Report residual risks without mitigation claims.

No claim in this document comes from an audit report. Where this document
disagrees with an audit document, the code was followed and the divergence is
recorded in [`ARCHITECTURE.md §10`](./ARCHITECTURE.md#10-known-divergences).

---

## 2. Assets

| Asset | Where it lives | Consequence of compromise |
|---|---|---|
| **A1** Credential secrets | AES-256-GCM ciphertext in `chrome.storage.local`; also `credentials` rows in Postgres | Full credential theft |
| **A2** Master passphrase / master secret | User memory; master secret derived in RAM, never persisted (`src/infrastructure/crypto/master-key-manager.ts:187`–`190`) | Vault unlock for the session |
| **A3** VEK (Vault Encryption Key) | `chrome.storage.session` only | Decrypt every credential for that session |
| **A4** Release Share | Wrapped in Postgres under the Core-held KEK; plaintext only in RAM during release | Second factor of every managed credential |
| **A5** `RELEASE_SHARE_KEK_SECRET` | Core environment (`docker-compose.yml:58`) | Unwrap every Release Share ever stored |
| **A6** Plus Ed25519 private key | Plus environment (`PLUS_CAPABILITY_PRIVATE_KEY`) | Mint arbitrary capabilities |
| **A7** User's session JWT (`JWT_SECRET`) | Core environment | Act as any user against Core |
| **A8** Origin-binding index | `chrome.storage.local`, HMAC outputs only | Learn which sites the user holds credentials for |
| **A9** Step-up PINs | `pin_hmac` + `pin_salt` columns of the `challenges` table (`src/infrastructure/db/migrations/005_plus_schema.sql:75`–`76`) | Bypass the third factor |
| **A10** Browsing history / typed secrets on page | The DOM | Classic phishing / keylogging |

---

## 3. Trust boundaries and assumptions

| Boundary | Attacker position | Assumption the design makes |
|---|---|---|
| **B1** Page ↔ service worker | Full control of page JS, frames, and form fields | Page cannot forge the extension's origin-binding token; content scripts are isolated |
| **B2** Browser ↔ Core | Can send arbitrary HTTP, hold/steal tokens | Stolen refresh token is not enough (`src/infrastructure/api/auth.ts:191`, `:222`); possession of a JWT still requires vault ownership (`src/infrastructure/api/server.ts:1014`) |
| **B3** Browser ↔ Plus | Can send arbitrary HTTP to Plus | Plus's decisions are only *useful* if Core independently re-verifies; see [`ARCHITECTURE.md §6.1`](./ARCHITECTURE.md#61-plus-api-has-no-caller-authentication) |
| **B4** Core ↔ Plus | Network attacker between processes | They are never connected ([`ARCHITECTURE.md §3`](./ARCHITECTURE.md#3-processes-and-trust-boundaries)) |
| **B5** DB admin | Read + write on Postgres | Cannot decrypt A1/A3/A4 without A5 and the passphrase; **qualified** for A9 — see R5 |
| **B6** TLS termination | On-path attacker | Production refuses to start in plaintext — T17 below, and [`ARCHITECTURE.md §10`](./ARCHITECTURE.md#10-known-divergences) |

### Explicit assumptions

- **A-I** The browser extension is installed from a reviewed bundle. MV3 does
  not defend against a malicious extension with `storage` + `tabs` permission.
- **A-II** `JWT_SECRET`, `RELEASE_SHARE_KEK_SECRET` and
  `PLUS_CAPABILITY_PRIVATE_KEY` are high-entropy and distinct. Nothing in the
  code enforces this.
- **A-III** Only one user's passphrase protects the VEK. There is no key
  escrow, no recovery path, no multi-party unlock.
- **A-IV** The page cannot read `chrome.storage` or the service worker's
  memory. This is an MV3 platform guarantee, not a CyberVault control.

---

## 4. Attacks addressed

Each row names the line that defends it. If the defence could be deleted
without a test failing, it is marked **[intended only]**.

| # | Attack | Defence | Enforcement point | Status |
|---|---|---|---|---|
| T1 | Replay a stolen capability against a different credential or vault | `verifyCapabilityBindings` compares `userId`, `resourceId`, `secretRef`, `deviceId` field by field; `resourceId`/`secretRef` come from Core's own store, not the request | `src/infrastructure/crypto/ed25519-capability.ts:432`; expected context built at `src/infrastructure/api/server.ts:1080`–`1086` | Enforced |
| T2 | Replay the same capability twice | JTI consumed atomically before any secret material is read | `src/infrastructure/crypto/jti-store.ts:177`, called at `src/application/use-cases/managed-release.use-case.ts:157` | Enforced — but see R2 |
| T3 | Forge a capability by supplying your own public key in the request | The request body's key material is ignored; `PLUS_PUBLIC_KEY` is pinned configuration loaded in the constructor | `src/infrastructure/api/server.ts:1021`–`1030`, `src/infrastructure/crypto/ed25519-capability.ts:168` | Enforced |
| T4 | Use a capability after its TTL | `capabilityTtlSeconds` checked before JTI consumption | `src/application/use-cases/managed-release.use-case.ts:153`–`156` | Enforced |
| T5 | Skip capability verification by leaving `PLUS_PUBLIC_KEY` unset | Both verification sites fail closed with an explicit refusal | `src/application/use-cases/managed-release.use-case.ts:211`, `:440` | Enforced |
| T6 | Autofil a credential into a site the user never authorised | Three-stage order: origin-binding proof → autofill guard → only then key material | `src/background/credential-release.ts:23`–`31`, outcome codes `src/background/credential-release.ts:108`–`115` | Enforced |
| T7 | Recover the user's visited origins from extension storage | `lookupToken = HMAC(DomainIndexKey, canonicalOrigin)`; no origin is stored | `src/domain/services/autofill/domain-index.ts:19`, `:41` | Enforced |
| T8 | Extract the master secret from storage | Only the PBKDF2 verifier hash + salt are written, scheme-tagged | `src/infrastructure/crypto/master-key-manager.ts:187`–`190` | Enforced |
| T9 | Keep the vault unlocked indefinitely | Session key expires after 15 minutes | `src/infrastructure/crypto/master-key-manager.ts:48`, checked at `:219` | Enforced |
| T10 | Read the VEK from disk | VEK is only ever in `chrome.storage.session`, never `chrome.storage.local` | `src/infrastructure/crypto/master-key-manager.ts:36`–`46` (`STORAGE_KEYS` has no local slot for it), written at `:196` | Enforced |
| T11 | Recover plaintext Release Shares from the database | Only `wrapped_share` is stored; AEAD with `secretRef` as additional authenticated data; zeroized after use | `src/infrastructure/db/migrations/002_release_shares.sql:1`, `src/infrastructure/crypto/release-share-kek.ts:181`, `src/application/use-cases/managed-release.use-case.ts:185` | Enforced |
| T12 | Unwrap with a wrong-length KEK secret | Refuses unless exactly 32 bytes | `src/infrastructure/crypto/release-share-kek.ts:103`, `:144` | Enforced |
| T13 | Persist a step-up PIN in plaintext via the metadata column | `sanitizeMetadata` strips `generatedPin` on every write path | `plus/infrastructure/repositories/PostgresChallengeRepository.ts:112`, key at `:49`, applied at `:184` | Enforced |
| T14 | Brute-force the step-up PIN by repeated verification | 3 attempts per challenge, 10-minute TTL | `plus/domain/services/challenge.ts:308` (attempts), `:215` (TTL), `:216` (`maxAttempts`) | Enforced — but see R4 |
| T15 | Use a 7-day refresh token as a 7-day session | `authenticate` requires `type === "access"` | `src/infrastructure/api/auth.ts:191`, `:222` | Enforced |
| T16 | Point Core at a caller-supplied verification key | The key is never read from the body | `src/infrastructure/api/server.ts:1021`–`1030` | Enforced |
| T17 | Run production in plaintext HTTP | Both servers refuse to start | `src/infrastructure/api/server.ts:1675` (called at `:1719`); `plus/api/server.ts:851` (called at `:892`) | Enforced |
| T18 | Overwrite a concurrently updated credential or vault | Optimistic locking with `lock_version`, guarded `UPDATE ... WHERE lock_version = $2` | `src/infrastructure/db/migrations/004_optimistic_locking.sql:1` | Enforced |
| T19 | Second-order SQL injection through JSONB columns | One parser handles string-or-object, repositories bind parameters | `src/shared/jsonb.ts:30`, `src/infrastructure/repositories/row-mappers.ts:170`, `:195` | Enforced |
| T20 | Cross-origin request from an arbitrary site to Core | Single pinned `CORS_ORIGIN` | `src/infrastructure/api/middleware/cors.ts:3`, applied at `src/infrastructure/api/server.ts:1414` | Enforced — but see R7 |
| T21 | Session fixation / cross-user release | Vault ownership checked against the authenticated principal before the capability is even parsed | `src/infrastructure/api/server.ts:1014`–`1019` | Enforced |
| T22 | Existence oracle across vaults | An id from another vault returns the same 404 as a non-existent one | `src/infrastructure/api/server.ts:1060`–`1063` | Enforced |

---

## 5. Residual risks

Listed because they are real, not because they are severe. Severity is
subjective and not from any scoring system.

### R1 — The Plus API authenticates nobody (High, design)

`routeRequest` (`plus/api/server.ts:791`–`820`) has no auth step. Concretely:

- `userId` comes from the request body (`plus/api/server.ts:401`).
- `PLUS_SERVICE_SECRET` is defined (`plus/api/server.ts:110`) and **read
  nowhere**; the headers the extension sends (`src/background/auditor.ts:398`–`400`)
  are never inspected.
- CORS is `*` (`plus/api/server.ts:757`).
- Rate limiting is a stub returning `true` (`plus/api/server.ts:236`–`239`).

*Why it is not fatal today:* Plus only **issues** capabilities and challenges.
Spending one requires a valid Core Bearer token and vault ownership
(`src/infrastructure/api/server.ts:1592`, `:1014`). So an anonymous caller can
probe entitlements and drive challenge creation, but cannot read a credential.

*What it does expose:* `POST /api/v1/challenges/trigger` and
`POST /api/v1/challenges/verify` are reachable without credentials, and
`handleEntitlementsCheck` will answer for any `userId` it is given.

### R2 — Replay protection is process-local in the shipped topology (Medium)

`createJtiStore` (`src/infrastructure/crypto/jti-store.ts:143`) picks Redis only
when `REDIS_URL` is set and is not the localhost default. Compose sets
`REDIS_HOST`/`REDIS_PORT` (`docker-compose.yml:43`–`44`) and **never**
`REDIS_URL`. Therefore:

- A Core restart clears all consumed JTIs — previously spent capabilities
  become spendable again until their own TTL expires.
- Two Core replicas do not share state; each has its own consumed set.

The JTI TTL is bounded by the capability TTL, so the window equals the
capability lifetime, not infinity.

### R3 — Step-up PIN has no delivery channel, and a small space (Medium)

Verified facts:

- `createChallenge` addresses the email to the literal `user@example.com`
  (`plus/domain/services/challenge.ts:265`).
- `plus/api/main.ts` passes no `emailService`, so `PlusApiServer` uses
  `NoOpEmailService` (`plus/api/server.ts:134`).
- Therefore in the shipped configuration **nothing delivers the PIN to the
  user**, and `generatedPin` has no production reader (it is stripped before
  persistence anyway — T13).

Independently: the PIN is 6 digits (`plus/domain/services/challenge.ts:395`–`414`),
~10⁶ values, stored as `HMAC-SHA256(pinSalt, pin)` via `computePinHmac`
(`plus/domain/services/challenge.ts:424`). Combined with R4, a DB reader can
enumerate it offline. **[intended only]** — `src/infrastructure/db/migrations/005_plus_schema.sql:23`–`25`
claims a database administrator reading the table "gains nothing that lets them
pass the third factor"; the code does not make that true for a 6-digit space.

### R4 — Challenge verification is unauthenticated and unthrottled (Medium)

`POST /api/v1/challenges/verify` (`plus/api/server.ts:661`) requires only
`challengeId` + `pin`. There is no session, no caller identity, and
`checkRateLimitOrError` is a no-op (`plus/api/server.ts:236`). The
per-challenge attempt counter (T14) is the only brake. Defeating it requires a
new challenge per binding, which itself is unauthenticated (R1).

### R5 — DB read ⇒ offline PIN recovery (Low–Medium)

Follows from R3: `pin_hmac` + `pin_salt` are sufficient to brute-force ~10⁶
candidates without any further access. This is the one asset in §2 whose
"hashed at rest" property does not meaningfully resist its adversary model.

### R6 — No server-to-server authentication channel exists (Low today, structural)

`PlusBridge` (`src/infrastructure/plus/plus-bridge.ts:102`) has no production
caller, so there is no Core→Plus or Plus→Core traffic to secure. If a future
change introduces one, `PLUS_SERVICE_SECRET` would need an actual reader — today
it is decoration.

### R7 — Core CORS and rate limits are single-instance (Low)

`src/infrastructure/api/middleware/cors.ts:3` reads `CORS_ORIGIN` once at module
load (default `http://localhost:3000`). `checkRateLimit`
(`src/infrastructure/api/middleware/rate-limiter.ts:14`) is an in-memory map, so
it is per-process and resets on restart. Core does have real rate limiting
(`src/infrastructure/api/server.ts:397`–`398`) — unlike Plus (R1).

### R8 — TLS is the only transport control (Low, by design)

Compose publishes plaintext HTTP on the host (`docker-compose.yml:25`, `:99`)
with `NODE_ENV` defaulting to `development` (`docker-compose.yml:36`, `:107`).
The fail-closed guard (T17) only engages under `NODE_ENV=production`. Local
development is therefore plaintext by design; production is not — **provided the
operator sets `NODE_ENV=production`**, which is an operational assumption (A-II
family), not a code-enforced one.

Also noted: `Strict-Transport-Security` is emitted on every response
(`src/infrastructure/api/middleware/security-headers.ts:49`–`51`) including
plain-HTTP dev responses, where browsers ignore it. Harmless, but it means the
header's presence proves nothing about how the response arrived.

### R9 — MV3 worker eviction drops security state (Low)

Step-up completion state (`src/background/auditor.ts:1036`, `:1046`, `:1049`)
lives in worker memory. Eviction resets it, so the user is asked to step up
again — a fail-closed outcome, not a fail-open one, but it means the guarantee is
"at most one step-up per worker lifetime", not "at most one step-up ever".

### R10 — Extension defaults and Compose ports disagree (Low, operational)

Extension defaults: `localhost:3010` / `localhost:3011`
(`src/background/auditor.ts:457`, `:375`, `src/ui/popup/popup.ts:140`).
Compose publishes `3000` / `3001` (`docker-compose.yml:25`, `:99`). Out of the
box the extension does not reach the containers. Correctable through
`core_base_url` / `plus_base_url` in `chrome.storage.local`, but not wired by
default.

---

## 6. Explicitly out of scope

| Item | Reason |
|---|---|
| Compromise of the browser itself | A-II / A-IV: MV3 is the boundary |
| Supply-chain attack on npm dependencies | No dependency auditing performed in this pass |
| Physical access to the machine while the vault is unlocked | VEK is in session storage by design |
| DoS against Core or Plus | Availability is not modelled here; note that Core caps a request at 30 seconds (`src/infrastructure/api/server.ts:103`, applied at `:1418`) |
| IPFS confidentiality | The IPFS path is currently unreachable under the CommonJS build ([`ARCHITECTURE.md §9`](./ARCHITECTURE.md#9-verification-commands-and-what-each-one-proves)); nothing is stored there |
| `plus/admin` UI | Its data endpoints do not exist server-side ([`ARCHITECTURE.md §10`, D7](./ARCHITECTURE.md#10-known-divergences)); the UI is not a trust boundary because it has no backing |

---

## 7. What was verified, and how

| Claim | How |
|---|---|
| Test baseline: 1561 passed / 0 failed / 17 skipped, 86 passed + 3 skipped suites | Re-ran `npx jest --silent` this session; exit 0 |
| Type baseline: 0 errors | Re-ran `npx tsc --noEmit` this session; exit 0 |
| Composition of the 17 skipped tests | Counted: 10 in `tests/integration/ipfs-adapter.test.ts` (gated on `IPFS_API_URL`), 2 + 2 + 3 in the three suites gated on `CYBERVAULT_TEST_DATABASE_URL` |
| `ipfs-http-client` cannot be `require`d | Executed `require('ipfs-http-client')` → `ERR_PACKAGE_PATH_NOT_EXPORTED`; confirmed the emitted `dist/src/infrastructure/ipfs/ipfs-adapter.js:75` uses `require`; executed the compiled adapter → in-memory fallback, `isHealthy() === false` |
| Plus has no auth on its routes | Read `routeRequest` in full; searched `plus/api/server.ts` for `Authorization` / `X-Service-Secret` / `authenticate` — the only match is the outbound CORS header line |
| `serviceSecret` has no reader | `grep -rn "serviceSecret" plus/` returns only its definition |
| Compose sets no `REDIS_URL` | Key scan of `docker-compose.yml` |
| `verifyCapabilityCore` / `consumeCapabilityJti` are dead | No matches outside their definitions in `src/` or `plus/` |
| All `path:line` citations in both documents | Automated check over every citation: the file exists, the line number is in range, and the cited line was read back and compared against the claim it supports. The first pass found 29 structural defects (non-existent path, ambiguous basename, or out-of-range line) plus several wrong-but-in-range line numbers; all were corrected before this document was finalised. Final result: **248 citations, 0 problems.** |

### Not verified in this session

- **SonarQube quality-gate figures.** `localhost:9000` returns HTTP 401 for
  anonymous API calls, so `STATUS OK`, `new_coverage 82.7%` against the 80%
  threshold, and "0 pending security hotspots" are reported here as the **last
  reported analysis, not a fresh measurement.**
- **Any live end-to-end capability cycle** against a running Postgres with
  migration 005 applied.
- **No independent review certificate exists.** The reviewer sub-agent could
  not be dispatched (four attempts, identical failure: "OpenCode's free tier
  can only be used from within OpenCode"). This document is **not certified**;
  it must not be cited as if it were.
