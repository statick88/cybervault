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
| T2 | Replay the same capability twice | JTI consumed atomically before any secret material is read, backed by Redis in the shipped topology | `src/infrastructure/crypto/jti-store.ts`, called at `src/application/use-cases/managed-release.use-case.ts:157` | Enforced (was per-process — R2 resolved) |
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
| T13 | Persist a step-up PIN in plaintext via the metadata column | The PIN no longer exists; `sanitizeMetadata` still strips the key defensively | `plus/infrastructure/repositories/PostgresChallengeRepository.ts` | Enforced (vacuous since R3) |
| T14 | Brute-force the step-up factor by repeated verification | There is nothing to brute-force: the factor is a signed approval, unforgeable and single-use | `src/infrastructure/crypto/ed25519-approval.ts`, `plus/domain/services/challenge.ts` (`verifyApproval`) | Enforced (R3); human consent is R11 |
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

| T26 | Replay a step-up approval to release the same credential twice | `jti` consumed atomically before anything is issued, plus the challenge state machine refuses a second completion | `plus/domain/services/challenge.ts` (`verifyApproval`), shared JTI store | Enforced |

### R1 — RESOLVED — the Plus API authenticated nobody (was High, design)

`routeRequest` had no auth step at all. Concretely, as it stood:

- `userId` came from the request body.
- `PLUS_SERVICE_SECRET` was defined (`plus/api/server.ts`) and **read nowhere**;
  the headers the extension sends (`src/background/auditor.ts`) were never
  inspected.
- CORS was `*`.
- `checkRateLimitOrError` was a stub returning `true`.

Any anonymous caller could probe entitlements for an arbitrary `userId`,
drive challenge creation, and attempt PIN verification — the last being the
sharp edge, because `/api/v1/challenges/verify` is the gate that completes a
step-up.

*Resolution* (`a8c217b`):

- Every route except `/health` and `/ready` now requires `X-Service-Secret`,
  compared in constant time (a byte-wise compare leaks the length and the
  matching prefix through response timing). Failure messages never echo either
  side. A readiness probe has no business carrying a credential, so those two
  stay open by design.
- `/api/v1/crypto/public-key` is behind the secret too. Handing the signing
  key to any origin is how an attacker learns the key Core pins.
- The rate limit is real: a per-IP sliding window, 60 requests per minute, with
  an opportunistic sweep so IP rotation cannot grow the map for the lifetime of
  the process.
- CORS is an exact-match allow-list from `PLUS_ALLOWED_ORIGINS`, never a suffix
  match, and unset admits nothing — fails closed. A native caller such as the
  service worker is unaffected by CORS.

*Residual, now tracked as R7:* the rate limit is in-process and therefore
per-replica. Behind more than one Plus instance the effective limit multiplies.

### R2 — RESOLVED — replay protection was process-local (was Medium)

`createJtiStore` picks Redis only when `REDIS_URL` is set and is not the
localhost default. Compose set `REDIS_HOST`/`REDIS_PORT` and **never**
`REDIS_URL`, so every consumed JTI lived in the Core process:

- A Core restart cleared all consumed JTIs — previously spent capabilities
  became spendable again until their own TTL expired.
- Two Core replicas did not share state; each kept its own consumed set.

*Why it was never wired:* the store connected with no credential at all, while
`redis-server` runs with `--requirepass`. Connecting that way fails, which is
almost certainly why nobody ever set the variable.

*Resolution* (`c143c24`): `REDIS_URL=redis://redis:6379` in compose (the
service name deliberately does not match the localhost sentinel, which stays
the development case), and the client now embeds `REDIS_PASSWORD`,
percent-encoded so a password containing `@` or `/` cannot truncate the
authority and connect to the wrong host. A URL that already carries
credentials still wins; `rediss://` keeps its scheme.

The JTI TTL is bounded by the capability TTL, so the window equals the
capability lifetime, not infinity.

### R3 — RESOLVED — the third factor was unobtainable (was Medium)

This was worse than it was written up as, and correcting the record matters more
than the fix.

**The PIN was never delivered to anyone.** `createChallenge` generated a 6-digit
PIN, stored only `HMAC-SHA256(pinSalt, pin)`, and discarded the plaintext. It
was never emailed (`sendChallengeEmail` receives only a URL holding the
`challengeId`, and `generateChallengeHtml` never mentioned a PIN), never
returned (`createChallenge` returns `{challengeId, expiresAt}`), never logged,
and `PostgresChallengeRepository.sanitizeMetadata` stripped
`metadata.generatedPin` before persistence. The only surviving copy was
in-memory, where the tests read it off a fake repository.

So the third factor was not weak. It was **unobtainable**: a user could trigger
a challenge, receive an id, and never receive a PIN, so every submission
failed. The step-up was un-completable in the shipped configuration while 1595
tests passed.

R4's per-user PIN lockout was, as a consequence, guarding a lock with no key
behind it.

**Why the suite was green.** Every test of this flow sat on one side of the
Core/Plus boundary. The Plus suite constructed its own server; the extension
suite stubbed `fetch` and answered 200 regardless of headers. Nothing crossed
it. The PIN-reading helper in
`tests/plus/capability-request-step-up.test.ts` bypassed the exact point where
the PIN was lost.

**Resolution.** The PIN is removed entirely and the factor is the user's
decision:

    popup shows the site and operation  ->  the user approves
    ->  Core signs an Ed25519 approval  ->  Plus verifies it against a pinned
    Core public key  ->  Plus issues the capability

Core signs because it can prove the user owns the credential; Plus verifies
because it is the issuer. `src/infrastructure/crypto/ed25519-approval.ts` is a
separate artifact type from the capability, with its own `typ` in the protected
header, so a capability can never satisfy the approval verifier or vice versa.

**Limitations, stated rather than implied away:**

- A signed approval proves **Core** authorised the release. It does not by
  itself prove a **human** clicked: a compromised background worker holding a
  live session token can call `POST /api/v1/step-up/approve` itself and receive
  a validly signed approval. What signing does buy is unforgeability,
  tamper-evidence, single-use, a short TTL, binding to one exact credential, and
  a real audit record. Closing the human-in-the-loop gap needs re-proof at
  approve time — passphrase re-entry or a WebAuthn assertion — and is
  deliberately **out of scope** here. This is R11.
- The DB columns `pin_hmac` and `pin_salt` remain (written as empty strings).
  Dropping them gains nothing and would need a migration over real rows.

*Verified:* `tests/integration/step-up-approval-flow.test.ts` boots both
services, signs with a real Core key and verifies with a real Plus key, and
completes the release with no PIN anywhere in the exchange. That test's absence
is what hid the defect.

### R4 — RESOLVED — the step-up PIN was brute-forceable (was Medium)

The per-challenge attempt counter (T14, 3 attempts) was the only brake. It
capped three guesses **per challenge**, so minting the next challenge reset the
budget entirely. With R1's rate limit that is still 60 challenges/min × 3
attempts = 180 guesses/min against a 6-digit PIN.

*Resolution* (`c14e3ca`): the brake moved to the user row, so it outlives the
challenge that earned it.

- `failed_pin_attempts` and `locked_until` on `plus_users`
  (migration `006_pin_lockout.sql`, additive and idempotent).
- Five failures arm a 15-minute lock. Only a correct PIN clears it; an expired
  lock re-arms on the next mistake rather than granting a fresh budget.
- The lock is checked **before** any PIN HMAC is computed, and a locked user
  receives exactly what a wrong PIN receives — same error string, same
  `attemptsRemaining`. No HMAC means no timing oracle for the correct PIN, and
  an identical message means the caller cannot distinguish "locked" from
  "wrong".
- `recordFailedPinAttempt` is an atomic
  `failed_pin_attempts = failed_pin_attempts + 1 ... RETURNING`, not a
  read-modify-write. Two concurrent guesses would otherwise overwrite each
  other and hold the counter under the threshold indefinitely.
- The two lockout columns are deliberately absent from `save()`'s column list
  and from its `ON CONFLICT` clause, so upserting a stale entity cannot clear
  a lock.
- A PIN that is not exactly `PIN_LENGTH` characters is rejected before hashing
  and is **not** counted — otherwise anyone reaching the route could lock an
  account by sending five pieces of garbage.
- An unknown user warns and no-ops rather than throwing, so the route is not a
  user-enumeration oracle. SQL errors do rethrow: a broken lockout store must
  fail closed, not open.
- The lockout store is a **required** constructor argument, so no caller can
  build a service that silently has no lockout.

Verified against live PostgreSQL 16: five concurrent increments land at
exactly five.

*Still relies on:* the 6-digit PIN space itself, and the PIN reaching the user
out of band. Both are R3.

### R5 — RESOLVED — DB read ⇒ offline PIN recovery (was Low–Medium)

Was: `pin_hmac` + `pin_salt` were sufficient to enumerate ~10⁶ candidates
offline, so a database administrator gained exactly what the third factor was
supposed to prevent. `src/infrastructure/db/migrations/005_plus_schema.sql`
claimed the opposite; the claim was false and is now moot.

*Resolution:* the PIN no longer exists. There is no credential material stored
per challenge to enumerate, so there is nothing to attack with a stolen table.
The empty `pin_hmac` / `pin_salt` columns hold no secret.

Note this makes R5 a *consequence* of R3 rather than an independent fix. Removing
the guessable secret removed the offline attack with it — which is why the
migration's claim needed no correction so much as deletion of its premise.

### R6 — No server-to-server authentication channel exists (Low today, structural)

`PlusBridge` (`src/infrastructure/plus/plus-bridge.ts:102`) still has no
production caller, so there is no Core→Plus or Plus→Core traffic to secure.

*Partly retired by R1:* `PLUS_SERVICE_SECRET` used to be decoration — declared
and read nowhere. It now has a real reader in `plus/api/server.ts` and is
enforced with a constant-time comparison. What remains true here is narrower:
the extension→Plus channel is authenticated by a **shared symmetric secret**,
which means every holder can both mint and verify, and there is no
server-to-server identity. A future Core→Plus caller would need a channel of
its own rather than reusing the extension's secret.

### R7 — Core CORS and rate limits are single-instance (Low)

`src/infrastructure/api/middleware/cors.ts:3` reads `CORS_ORIGIN` once at module
load (default `http://localhost:3000`). `checkRateLimit`
(`src/infrastructure/api/middleware/rate-limiter.ts:14`) is an in-memory map, so
it is per-process and resets on restart. Core does have real rate limiting
(`src/infrastructure/api/server.ts:397`–`398`).

This now also describes the **Plus** side: the rate limit R1 added is likewise
an in-process map, so behind N Plus replicas the effective limit is N × 60/min
rather than 60/min. Both limits belong to the "single instance" pattern, and
both need a shared store — Redis is already a dependency, and R2 wires it for
the JTI store, so the same mechanism applies here.

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

### R9 — RESOLVED — the step-up gate did not survive MV3 eviction (was Medium; filed as Low)

The entry used to claim eviction was "fail-closed: the user is asked to step up
again". That was a claim about behaviour nobody had tested, and at the layer it
named it was false.

The gate in `handleReleaseCredential` read:

    if (challengedBindings.has(key)) { ...refuse unless completed... }

(`src/background/auditor.ts:991`)

That is a **remembering** guard. After eviction the map is empty, `has(key)` is
false, and the block is skipped entirely — so the question was not "does the
user step up again" but "does the guard run at all". It did not.

Measured in `tests/extension/worker-eviction.test.ts`: guarded while memory was
intact, attempted after eviction, and — with Plus answering "granted" — released
with no step-up ever completed. The denial a user still saw came from Plus
refusing a capability request, so the two-service defence had quietly become a
one-service defence, and the survivor was the one holding the
capability-issuing key.

*Resolution* (`4a3f89d`). The extension no longer remembers whether a release
needed a step-up in order to decide whether to gate it. Authority is split by
who decides what:

- **Plus is the authority on what is *owed*.** It is consulted for every
  release and answers `challengeRequired` for an incomplete step-up.
- **The session is the authority on what has been *paid*.** A completion is
  recorded in `chrome.storage.session`, and a release requires both.
- The in-memory map keeps only a fast path that **may refuse early and may
  never allow**.

Neither pure option works, and the reasons are worth keeping:

- "Let Plus be the only authority" fails on the granting-Plus case — if Plus
  says yes, the release goes through, which is the defect itself.
- "Deny from persisted state before the round trip" fails the case that must
  still reach Plus, because after eviction the persisted state is identical
  whether a challenge was ever started.

`chrome.storage.session` rather than `.local`, deliberately: session storage is
`TRUSTED_CONTEXTS` by default, so a content script cannot write it. A page able
to pre-mark its own binding as completed would make the persistence worthless.
Locking the vault removes the gate key and then **verifies** the removal,
refusing to report a successful lock if the key survived.

Bindings never challenged in a session remain Plus's decision, so the
assurance-2 path and production behaviour are unchanged. Cost is one extra
`storage.session` read per successful release; the round-trip count is
unchanged.

*Residual:* the gate trusts `chrome.storage.session` to be un-writable from a
content script. That is a platform guarantee this project does not control and
does not test. A page that could write it would restore the original defect.

### R10 — Extension defaults and Compose ports disagree (Low, operational)

Extension defaults: `localhost:3010` / `localhost:3011`
(`src/background/auditor.ts:457`, `:375`, `src/ui/popup/popup.ts:140`).
Compose publishes `3000` / `3001` (`docker-compose.yml:25`, `:99`). Out of the
box the extension does not reach the containers. Correctable through
`core_base_url` / `plus_base_url` in `chrome.storage.local`, but not wired by
default.

### R11 — The approval proves authorisation, not a human (Medium, accepted)

Introduced by R3, and stated rather than buried.

`POST /api/v1/step-up/approve` (`src/infrastructure/api/server.ts`) signs an
approval for any authenticated caller who names a credential they own. The
signature proves **Core** authorised that exact release. It does not prove a
person decided to.

A compromised background worker (`src/background/auditor.ts`) holding a live
session token can therefore call the endpoint itself, obtain a validly signed
approval, and complete the step-up with no user present. The popup's approve
button is the intended control; it is not a cryptographic one.

What the signature *does* prevent, and this is not nothing:

- Forging or editing an approval.
- Replaying one against a different credential, operation or secret.
- Replaying one after it expires, or a second time (the `jti` is consumed
  atomically before anything is issued).
- Using an approval without Core's key.
- Doing any of it without leaving an audit record in Core.

*Accepted because:* closing it requires the user to re-prove something at
approve time — a passphrase re-entry, or a WebAuthn assertion bound to the
challenge. That is a materially larger change than the release flow, and it
interacts with R9 (MV3 eviction would drop an in-flight WebAuthn ceremony).
Shipping a signature that is genuinely unforgeable and honestly scoped is
better than not shipping it; shipping it *as if* it proved human consent would
not be.

*To close:* add a proof-of-possession step to `POST /api/v1/step-up/approve`,
and require it to be bound to `challengeId` so it cannot be lifted onto another
release.

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
| Test baseline: 1645 passed / 0 failing / 17 skipped, 91 passed + 3 skipped suites | Re-ran `npx jest --silent` this session; exit 0 |
| Type baseline: 0 errors | Re-ran `npx tsc --noEmit` this session; exit 0 |
| Composition of the 17 skipped tests | Counted: 10 in `tests/integration/ipfs-adapter.test.ts` (gated on `IPFS_API_URL`), 2 + 2 + 3 in the three suites gated on `CYBERVAULT_TEST_DATABASE_URL` |
| `ipfs-http-client` cannot be `require`d | Executed `require('ipfs-http-client')` → `ERR_PACKAGE_PATH_NOT_EXPORTED`; confirmed the emitted `dist/src/infrastructure/ipfs/ipfs-adapter.js:75` uses `require`; executed the compiled adapter → in-memory fallback, `isHealthy() === false` |
| Plus requires `X-Service-Secret` on every non-probe route (R1) | 7 new cases: both probes open; missing secret → 401; wrong secret → 401 with neither value echoed; all 5 minting routes → 401; public-key route → 401; authenticated request → 200; rate limit trips at exactly 60 |
| `serviceSecret` now has a reader | `authenticateServiceRequest` in `plus/api/server.ts`, called from `routeRequest`; constant-time via `timingSafeEqual` |
| CORS is no longer `*` | Exact-match allow-list from `PLUS_ALLOWED_ORIGINS`; unset admits nothing |
| Compose sets `REDIS_URL` to the non-sentinel host (R2) | 2 cases assert the compose value directly, so the regression is caught at review time and not by reading the file |
| Redis credentials are actually sent (R2) | `withRedisCredentials` unit-tested: encoding, scheme, pre-credentialed URL, no-password no-op |
| The PIN lockout is per user, not per challenge (R4) | 9 cases: threshold trip, correct PIN refused while locked, reset on success, a *new* challenge still refused, malformed PIN rejected |
| The lockout increment is atomic (R4) | Live PostgreSQL 16: 5 concurrent `recordFailedPinAttempt` calls returned exactly `[1,2,5,4,3]`; second `npm run db:migrate` applied 0 migrations |
| `save()` cannot clear a lock (R4) | The lockout columns are absent from its INSERT column list and from its `ON CONFLICT` clause |
| The step-up is obtainable end to end (R3) | `tests/integration/step-up-approval-flow.test.ts` boots Core AND Plus, signs with a real Core key, verifies with a real Plus pinned key, and completes the release. 6 cases; the suite turns red when the pinned Core key is wrong, so it bites |
| No PIN exists anywhere in the new flow | No route accepts one; the popup has no PIN input in the DOM (asserted); no approve-path request body carries a `pin` key; the signed token contains no PIN material |
| A Core user cannot approve someone else's credential (R3) | Live server: 404 with the identical message as "no such credential", so ids cannot be enumerated |
| An approval for the wrong credential is refused (R3) | Live Plus: 400, with a genuine Core signature on a mismatched `secretRef` |
| An approval signed by an unpinned key is refused (R3) | Live Plus: 400 |
| MV3 eviction **was** fail-open, and the suite still measures it (R9) | `tests/extension/worker-eviction.test.ts` restarts the module for fresh maps. Case 3 asserts the release is now REFUSED; reverting the fix turns it red, which is how the coverage was confirmed rather than assumed |
| A completed step-up still releases on retry (R9) | New case in the same suite: pay-then-retry succeeds inside the session, so the persistence did not break the legitimate path |
| Locking clears the step-up gate and verifies it (R9) | `handleLockVault` removes the key and re-reads it; it refuses to report a successful lock if the key survived |
| A real approval was reported to the user as REFUSED (R9) | Plus's `sendSuccess` does not wrap its payload, so `body.success` read `undefined`. Fixed on both sides, and the stub now models both response shapes |
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
