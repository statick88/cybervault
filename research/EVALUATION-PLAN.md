# CyberVault — Evaluation Plan

Research prototype. This document states what will be measured, against which
baselines, and **what result would refute each claim**.

Measured state at the time of writing (`7b822e8`): 1714 tests passing, 0
failing, `tsc` 0 errors, SonarQube Quality Gate PASSED, coverage 83.2% against
an 80% gate.

> **RDD is not certified.** Eight review attempts, all blocked by the host
> runtime ("OpenCode's free tier can only be used from within OpenCode") or by
> a lens context budget. The sixth isolated its candidate correctly and created
> the authority; the final block was the host, not the candidate. **No review
> receipt or lineage exists for any commit on this branch, and nothing in this
> document may be presented as independently reviewed.**

## 1. Why these questions

The risk register is down to R6 and R8. The interesting work is no longer
"does it function" but "does the security property hold under conditions
nobody has tested".

The questions are selected by one rule: **each must be answerable with
evidence this repository can actually produce, and each must be
falsifiable.** That rule is not stylistic. Three defects in this codebase —
R3's unobtainable third factor, R9's fail-open gate, R1's broken call sites —
were each a documented claim that no test checked. A question whose answer
cannot contradict the claim is decoration.

## 2. Baselines

Every managed-path measurement is reported against a control, so "slower and
safer" is a number rather than an impression.

| ID | Baseline | What it is | Why |
|---|---|---|---|
| **B1** | Personal-credential path | No step-up, no Plus | The control condition. Everything managed is relative to this. |
| **B2** | Pre-R11 approval | Signed approval, no proof | What R11 replaced. Isolates the cost of proof-of-possession. |
| **B3** | In-memory rate limit | Per-process `Map` | What R7 replaced. Isolates the cost and the benefit of sharing. |

## 3. Research questions

### RQ1 — Does the split-trust invariant hold?

**Claim.** Core holds the VEK, master phrase, recovery key, TOTP seed and
Release Share. Plus holds none of them: it only ever sees a capability, a
`secretRef`, and per-entry derived material.

**Why it is the load-bearing property.** The entire architecture is this
asymmetry. If it leaks, nothing else matters.

**Method.** Static reachability analysis from every Plus entry point, plus a
runtime assertion that no key material reaches a Plus boundary. Enumerate
rather than sample: the value of the result is in the completeness of the
enumeration, not in a spot check.

**Refutation.** One reachable path carrying key material into Plus refutes
it. There is no partial credit — the property is a conjunction.

**Current status.** Enforced by code review and by the structure of the
service boundary, not by an assertion. That is a gap this RQ is designed to
expose.

### RQ2 — Does the third factor bind intent, or only attention?

**Claim.** An R11 WebAuthn proof proves a human was present. It does **not**
prove a human decided to release *this* credential.

**Why it matters most.** R11's residual states this. A compromised background
worker can request an assertion and surface the prompt at a moment of its
choosing. The user is present, so the factor passes.

**Method.** A controlled experiment with a simulated compromised worker:
present the step-up prompt out of context, out of order, and at a time
unrelated to any release the user initiated. Measure completion rate against
an honest baseline where the prompt follows a genuine user action.

**Refutation.** If completion rate on unexpected prompts is statistically
indistinguishable from the honest baseline, the factor does not bind intent
and the residual is materially larger than documented. If a meaningful
fraction of completions are refused on unexpected prompts, it binds
something.

**Requires human subjects.** This cannot be run unattended, and until it is,
R11's residual stays a **stated hypothesis, not a measured property**.

### RQ3 — What does the approval path cost?

**Claim.** Two PBKDF2 rounds at 600k iterations plus a WebAuthn ceremony sit
on the critical path of every managed release.

**Method.** End-to-end p50/p95/p99 for three paths: passphrase proof,
WebAuthn proof, and — as a floor — the B2 approval with no proof. Measured on
a cold start and warm, because PBKDF2 cost is dominated by whether the
runtime has JIT-warmed.

**Refutation.** A p99 that makes the feature unusable is a finding, not a
detail. It would justify an adaptive scheme: skip the second PBKDF2 round
entirely when a registered authenticator is present, since the WebAuthn proof
already carries the binding. The passphrase path exists precisely so the
WebAuthn path can be made cheap.

### RQ4 — Does the R7 fallback fail in the direction the design claims?

**Claim.** When Redis is unreachable the rate limiter degrades to a per-process
limit, which is better than failing closed. The stated reasoning: a limiter
that throws turns a Redis outage into an outage for every API client, and
removing the service does not bound load.

**Method.** Inject Redis failure at three points — connection refused, command
timeout, and mid-window loss — and measure availability and request outcomes
against a fail-closed variant of the same limiter.

**Refutation.** If availability under Redis loss is not meaningfully higher
than under fail-closed, **the trade was wrong** and the design should change.
The current choice is reasoned but unmeasured, and this RQ exists to possibly
overturn it.

### RQ5 — Which detectable failures does the suite miss?

**Claim.** The suite pins the security properties of R1, R4 and R11.

**Method.** Mutation analysis. Introduce known-bad variants of the
security-critical predicates and record whether the suite kills each:

| Target | Mutation | Property at stake |
|---|---|---|
| R1 secret compare | byte-wise instead of constant-time | timing side channel |
| R1 origin check | allow-list accepts any origin | CORS |
| R4 lockout threshold | never locks | brute force |
| R11 user-presence flag | accept an assertion with the flag clear | **R11 itself** |
| R11 binding check | ignore `secretRef` | cross-credential release |
| R3 approval binding | accept a proof for another `challengeId` | replay |
| R2 JTI consumption | allow a second use | replay across restart |
| R9 gate | skip when the session has no record | fail-open on eviction |

**Refutation.** A surviving mutant is a test gap with a named location. This
is the RQ that generalises: it reports which properties are **pinned** and
which are merely **believed**, which is the exact distinction R3 and R9 failed
on.

**Known limitation.** The mutants are chosen by the party that wrote the
predicates, so this cannot detect a property nobody thought to mutate. It
bounds confidence, it does not establish it.

### RQ6 — Does the design resist an adversary holding the database?

**Claim.** R5 was closed by *removing* the PIN rather than protecting it, so
the question is sharper than "is the PIN safe": given every row in every
table, what can an attacker actually recover?

**Method.** Per table, enumerate the stored material and state the recovery
path for each. Include the tables that exist only because of closed risks —
`step_up_approval_challenges` (R11), `user_authenticators` (R11),
`plus_users.failed_pin_attempts` (R4, now vestigial).

**Refutation.** Any table from which a key, a usable proof, or a
bypass condition can be derived refutes the split-trust claim for that
asset. The vestigial R4 columns are called out because dead columns are still
attacker-visible surface.

## 4. Metrics

| Metric | Applies to | Unit | Why this unit |
|---|---|---|---|
| Completion rate | RQ2 | ratio, with n | A rate without n is not evidence |
| p50 / p95 / p99 | RQ3 | ms, warm and cold | p99 is what a user feels |
| Mutation kill rate | RQ5 | ratio, per target | Per-target, so a gap is named |
| Reachable key paths | RQ1, RQ6 | count | Zero is the only acceptable value |
| Availability under store loss | RQ4 | ratio vs fail-closed | The comparison is the result |

## 5. Threats to validity

Named up front because three of R1–R11 were found by exactly this scepticism,
and a protocol that does not name its own weaknesses repeats the pattern.

- **No external replication.** One codebase, one author, one threat model.
  Every RQ is answered from inside the system under test. An outside reader
  should treat the results as design evidence, not as validation.
- **RDD is uncertified.** No receipt, no lineage. Nothing here is
  independently reviewed, and the absence is a property of the environment
  rather than of the code.
- **RQ2 requires human subjects** and cannot be automated. Until it runs, the
  intent-binding residual is a hypothesis.
- **Self-selection.** The RQs were chosen by the party that wrote the code.
  RQ5 is the partial corrective — it tests properties that party selected,
  which bounds the damage but does not remove it.
- **Single deployment shape.** Everything is measured against the compose
  stack. Multi-replica behaviour is reasoned about in R7 and RQ4, and not yet
  observed under load.
- **Coverage is not a proxy.** 83.2% is a Quality Gate input, not evidence of
  a security property. RQ5 exists precisely because those are different
  things.

## 6. Execution order

RQ5 first: it is cheap, automated, and it tells us which other results are
worth trusting. RQ3 next, because it is cheap and may change the design of
the path RQ2 measures. RQ1 and RQ6 together, since both are enumeration over
the same tables. RQ4 after RQ5, because the fallback's importance depends on
how well the limit is actually pinned. RQ2 last and deliberately: it needs
human subjects, and its result may be sensitive enough that it should be
reviewed before it is published.

## 7. What is explicitly not claimed

- No certificate, receipt, lineage, or independent review exists for any
  commit on this branch.
- No RQ has been executed. This document is a design, and every metric in §4
  is currently unmeasured.
- RQ2's residual in R11 is a stated hypothesis, not a finding.
- The risk register's remaining entries (R6, R8) are open, and this plan does
  not address them.
