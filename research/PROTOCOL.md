# CyberVault — Research Protocol

How each research question in `EVALUATION-PLAN.md` is executed, what counts as
a result, and what may not be claimed.

> **No RQ in this document has been executed.** It is a protocol, not findings.
> **RDD is uncertified** — no review receipt or lineage exists for any commit
> on this branch. See `docs/THREAT-MODEL.md` §7 for the attempt history.

## Principles

Three rules, each derived from a defect this repository actually shipped.

**1. A result is a measurement, not an argument.**
R9's threat-model entry read "fail-closed: the user is asked to step up
again". That was a sentence, it was wrong, and no test stood behind it. Every
protocol step below produces a number, a count, or a named path.

**2. Cross the boundary the defect lived at.**
R1's regression and R3's dead third factor were both invisible because every
test sat on one side of a boundary. Where a protocol step uses a mock, the
mock must be on the *far* side of the boundary being tested, and the reason is
written down.

**3. Falsification is defined before execution.**
Each RQ in the plan states what would refute it. A protocol that can only
confirm is not an experiment. If a result contradicts an expectation in the
plan, that is a finding and it gets reported as one.

## P1 — Mutation analysis of the security predicates (RQ5)

**Why first.** It tells us which other results are worth trusting. If the
user-presence mutant survives, RQ2's result is about a control that is not
actually enforced.

**Procedure.**

1. For each of the eight targets in the plan, apply the mutation to a scratch
   branch. One mutation at a time, so a kill is attributable.
2. Run the full suite unmodified. Record: killed, survived, or killed-only-
   by-a-specific-file.
3. For a surviving mutant, record the file and the assertion that *should*
   have caught it, then write that assertion.
4. Re-run. A mutation that now survives after its assertion exists is a
   finding about the assertion, not about the mutant.

**Result format.** A table: target, killed by, or survived with the missing
assertion named.

**Boundary note.** The mutants are applied to production predicates and the
suite is run unchanged. The suite is on the near side of the Core/Plus
boundary in most cases, which is precisely the limitation RQ5 exists to
measure — a mutation that only the integration suite can kill is a mutation
the unit suite was never pinning.

**What it cannot show.** That no untargeted mutation survives. The mutant set
was chosen by the party that wrote the predicates.

## P2 — End-to-end approval latency (RQ3)

**Procedure.**

1. Build with production flags. Record the build, because JIT warm-up
   dominates the first measurement and a cold number presented as typical is
   the usual error here.
2. Three paths, 200 iterations each after a 20-iteration warm-up discarded:
   - WebAuthn proof against a registered authenticator
   - passphrase proof (two PBKDF2 rounds, 600k iterations)
   - B2, no proof
3. Record p50/p95/p99 separately for the first and second half of each run,
   so JIT warm-up is visible rather than averaged away.
4. Repeat the whole procedure on a cold process.

**Result format.** Percentile table per path, cold and warm, with n stated.

**Refutation.** A p99 on the passphrase path that exceeds a stated usability
threshold refutes the premise that the passphrase path is an acceptable
fallback. That threshold is **not** set in advance, and this is a known
weakness of the protocol: it must be fixed before execution, not after a
number is seen. Fixing it afterwards is how a threshold gets reverse-fitted to
the result.

**Boundary note.** The measurement crosses Core, Plus and the proof verifier —
all real, nothing stubbed. A stubbed PBKDF2 would report the cost of a
function call rather than of 1.2 million SHA-512 iterations.

## P3 — Split-trust enumeration (RQ1 and RQ6)

**Procedure.**

1. Enumerate every entry point into Plus: HTTP routes, and the constructors
   and exported functions reachable from them.
2. For each, trace every value that reaches it and record whether it is key
   material, derived material, or an identifier. Enumerate completely; the
   value of the result is exhaustiveness, and a spot check proves nothing about
   a property this structural.
3. Enumerate every table. Per table: what is stored, whether a key or usable
   proof is derivable, and the recovery path.
4. Include the vestigial tables. `plus_users.failed_pin_attempts` and
   `locked_until` are dead since R3 removed the PIN. Dead columns are still
   attacker-visible surface, and "we stopped writing it" is a weaker claim
   than "it is not there".

**Result format.** A table per Plus entry point, and a table per database
table.

**Refutation.** One reachable key-material path refutes RQ1 outright. One
table from which a key or a usable proof is derivable refutes RQ6 for that
asset. Neither is partial credit.

**What it cannot show.** That no path exists which the enumeration missed.
This is the fundamental limit of a white-box reachability argument, and it is
why the runtime assertion in step 5 matters: it catches what the reading did
not.

## P4 — Store-failure injection (RQ4)

**Procedure.**

1. Three failure modes, injected at the Redis client: connection refused,
   command timeout, and loss of connection mid-window (after a counter is
   written but before the response arrives).
2. For each, measure: request outcomes, `/health` status, the reported
   `rateLimitMode`, and time to recovery.
3. Repeat against a fail-closed variant of the same limiter, built for the
   experiment and not merged.
4. The mid-window case is the one that matters and the one a naive test
   misses: the counter was incremented in Redis, the caller did not get a
   response, and the retry may double-count or lose the increment.

**Result format.** Per failure mode: outcome distribution, health status,
degradation visibility, recovery time — and the same for the fail-closed
variant.

**Refutation.** If fail-open availability is not meaningfully higher than
fail-closed, the R7 design choice is wrong and the document says so. The
current choice is reasoned and unmeasured; this is the step that can overturn
it.

**Boundary note.** The failure is injected at the client, not simulated by
mocking the limiter. Mocking the store tests the mock.

## P5 — Intent-binding experiment (RQ2)

**Not runnable unattended.** Requires human subjects, informed consent, and an
ethics review of the protocol. Recorded here so the requirement is visible
rather than discovered at the end.

**Procedure.**

1. Honest baseline: the user initiates a release, the prompt appears in
   context, they approve. Establishes the base rate.
2. Out-of-context: the prompt appears with no initiating action, at a
   randomised delay.
3. Mismatched context: the prompt names a site the user was not visiting.
4. Recruit enough participants to detect the effect the hypothesis predicts.
   The sample size must be fixed by power analysis **before** data collection
   — choosing n after seeing a non-significant result is how a null is
   manufactured.
5. Report completion rate per condition with n and confidence intervals.

**Refutation.** Completion on out-of-context prompts statistically
indistinguishable from the honest baseline means the factor does not bind
intent, and R11's residual is materially larger than written.

**Ethical constraint.** Condition 3 tells the participant their credential
may be released to a site they were not visiting. A false statement of that
kind requires explicit, separately obtained consent. No participant may be
deceived about whether their real credentials are at risk; the experiment
must use synthetic credentials throughout.

**Until this runs, R11's residual is a stated hypothesis and must not be
described as measured.**

## Result standards

**A result is admissible when** the boundary it crosses is the one its
question names, the falsification criterion was fixed before execution, and
the sample size and environment are stated.

**A result is inadmissible when** it comes from a mock on the near side of
the boundary, when the threshold was chosen after the number was seen, or when
it is reported without `n`.

**A null is a result.** RQ4 and RQ2 are both designed so that the current
design might be wrong. Reporting only the confirmations would make the
protocol worthless and would repeat the pattern this document exists to
correct.

## What may not be claimed

- No review certificate, receipt or lineage exists for any commit on this
  branch. RDD was attempted eight times and blocked by the host runtime.
- No result here has been externally replicated. Every RQ is answered from
  inside the system under test, by the party that wrote it.
- Coverage (83.2% against an 80% gate) is a Quality Gate input, not evidence
  of a security property.
- R6 and R8 remain open in the risk register and are not addressed here.
