# RQ5 — Which detectable failures does the suite miss?

**Status:** executed. Branch `research/rq5-mutation-analysis`.
**Method:** mutation analysis per `PROTOCOL.md` P1.
**Baseline before:** 97 suites / 1731 tests / 0 failures.
**After:** 100 suites / 1738 tests / 0 failures.

## Result — 5 of 8 killed

Three of the eight security properties this project lists as resolved were, at
the moment of the test, **untested**. The fixes were correct; nothing had proved
they were. That is the exact distinction R3 and R9 failed on, measured rather
than asserted.

| # | Property | Mutation | Result |
|---|---|---|---|
| 4 | R11 user-presence flag | accept an assertion with UP clear | **killed** — `tests/unit/step-up-proof.test.ts` |
| 5 | R3 approval binding | ignore the `challengeId` match | **killed** — unit + `tests/integration/step-up-approval-flow.test.ts` |
| 6 | R2 JTI consumption | allow a second use | **killed** — 6 tests across 5 files |
| 7 | R9 eviction gate | skip when the session has no record | **killed** — `tests/extension/worker-eviction.test.ts` |
| 8 | R11 `secretRef` binding | return any credential | **killed** — `tests/application/managed-authoring.test.ts` |
| 1 | R1 secret compare | constant-time → byte-wise | **survived** |
| 2 | R1 origin check | allow-list accepts any origin | **survived** |
| 3 | R4 lockout | never locks | **survived** |

### What the survivors mean

**R1 origin check — no test in 1731 had ever asserted a CORS header.** The
allow-list was correct and R1 genuinely closed the vulnerability, but the
wrong-origin case was never exercised. Pinned now by
`tests/plus/cors-origin-allowlist.test.ts`, which probes the real `PlusApiServer`
over HTTP with raw `Origin` headers: unset allow-list, empty allow-list, and
exact-match-only including a `…evil.example` look-alike.

**R4 lockout — no test drove a login past the failure threshold.** The policy
documenting the brute-force limit was never crossed in a test. Pinned now by
`tests/integration/login-lockout.test.ts` at the HTTP route rather than at the
limiter, so the route↔limiter wiring is pinned too.

**R1 secret compare — a mutant class, not a gap.** `hash === storedHash` and
`crypto.timingSafeEqual` return the same value on every possible input. The
difference is early-exit latency, which leaks the matching prefix. **No
functional coverage can distinguish them**, because no input produces a
different result — only a different clock. Pinned structurally instead:
`verifyPassword` must reach its comparison *through* `crypto.timingSafeEqual`.

## Three findings about the plan itself

The plan named eight targets. Three of the locations were wrong, and the
mistakes had a common shape — **documentation about code, mistaken for code**.

| Plan said | Actually |
|---|---|
| `IPinLockoutStore` for the lockout | **Zero production consumers.** Dead since R3 removed the PIN. Mutating it would have produced a survivor that looked like a test gap and was a dead-code finding |
| `ed25519-approval.ts:257` for JTI | That line *describes* JTI consumption in a comment. The consumer is `verifyAndConsumeJti` in `jti-store.ts:219` |
| `auditor.ts:306` for the R9 gate | That is clear-on-lock. The fail-open decision is `sessionOwesStepUp` at `auditor.ts:1300` |

The first is the important one. The protocol's step 3 for a survivor is "record
the missing assertion, then write it" — applied blindly to a dead predicate it
sends someone to write a test for code nothing calls, and records a false gap
in the project's own documents. **A mutation protocol that cannot distinguish a
test gap from dead code will manufacture findings.**

## Verification

Each new assertion was verified to bite — mutant applied → red, mutant reverted
→ green — by re-applying all three mutations directly:

| New test | Red with mutant |
|---|---|
| `tests/plus/cors-origin-allowlist.test.ts` | 3 / 3 |
| `tests/unit/security/constant-time-password-compare.test.ts` | 2 / 2 |
| `tests/integration/login-lockout.test.ts` | 1 / 2 |

The lockout figure is 1 of 2, and that is correct rather than a gap. The second
case asserts the **opposite half** of the same property — that a valid login
clears the counter — so a never-lock mutant satisfies it by construction. One
test kills "never locks", the other kills "locks forever"; the pair covers the
predicate. Reporting this as 2/2 would have overstated the result.

Restored, the full suite is **100 suites / 1738 tests / 0 failures**, and the
tracked tree is byte-identical to `main`.

## What this does not establish

Three limitations, stated because they cut against the number:

1. **The mutant set was chosen by whoever wrote the predicates.** A property
   nobody thought to mutate cannot appear. This bounds the damage; it does not
   remove it.
2. **Timing properties are invisible to this method** (survivor 1). Any kill
   rate overstates confidence in defences that depend on *how* an operation
   happens rather than *what* it returns.
3. **The suite sits on the near side of the Core/Plus boundary** in most cases.
   A mutation only the integration suite can kill is a mutation the unit suite
   was never pinning — a finding about the tests, not a pass.

RDD was not available for this branch, so none of it is independently reviewed.
No receipt or lineage exists.