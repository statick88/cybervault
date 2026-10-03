# RQ2 Pilot Protocol — Intention vs Attention in WebAuthn Step-Up

**Status:** Draft v0.1
**Branch:** `research/rq2-pilot`
**Depends on:** R11 complete (WebAuthn step-up implemented)
**Ethics:** Internal pilot only — no IRB, no external participants, no PII stored

---

## 1. Research Question

> **RQ2:** Does the current WebAuthn step-up flow capture the user's *intention* (conscious decision to authorize a specific action) or merely their *attention* (physical presence at the authenticator)?

**Hypothesis:**
- **H₀:** Users approve step-up challenges based on presence alone (attention), not conscious authorization of the specific action (intention).
- **H₁:** Adding explicit context (action, resource, user) to the WebAuthn prompt increases conscious intention without degrading usability.

---

## 2. Experimental Design

### 2.1 Design
- **Type:** Within-subjects (each participant experiences both conditions)
- **Conditions:**
  - **A (Baseline):** Standard WebAuthn prompt — generic "Touch your security key to continue"
  - **B (Contextual):** Explicit prompt — "Authorize AUTOFILL on github.com for user alice@example.com?"
- **Design:** Within-subjects, counterbalanced (ABBA / BAAB)
- **Participants:** 3-5 internal volunteers (non-authors of the step-up code)
- **Session duration:** ~15 minutes per participant

### 2.2 Independent Variable
| Condition | Prompt shown | Information displayed |
|-----------|--------------|----------------------|
| A (Baseline) | Generic WebAuthn UI | "Touch your security key to continue" |
| B (Contextual) | Extended UI | "Authorize **AUTOFILL** on **github.com** for **alice@example.com**?" |

### 2.3 Dependent Variables

| Metric | Type | Measurement |
|--------|------|-------------|
| **Total time** | Continuous (ms) | `prompt_visible_ts` → `approve_sent_ts` |
| **Hesitation** | Binary (ms > 2000) | Pause > 2s between prompt visible and gesture |
| **Consciousness (self-report)** | Ordinal (1-5) | Likert post-task: "How conscious were you of *what* you were approving?" |
| **Errors (injected)** | Count | Approvals on distractor trials (wrong resource/operation) |
| **Qualitative** | Text | Free-text: "What did you think you were approving?" |

---

## 3. Pilot Implementation

### 3.1 Feature Flag
```typescript
// src/background/config.ts
export const RQ2_PILOT_ENABLED = process.env.RQ2_PILOT === 'true';
export type RQ2Condition = 'baseline' | 'contextual';
```

### 3.2 Condition Assignment
- **Counterbalancing:** ABBA / BAAB sequence per participant
- **Assignment:** Random at session start, stored in `chrome.storage.session`
- **Persistence:** Condition survives worker eviction (session storage)

### 3.3 Extended Prompt UI
**Baseline (A):** Standard WebAuthn UI (browser-controlled)
**Contextual (B):** Custom overlay before `navigator.credentials.get()`:
```
┌─────────────────────────────────────────────┐
│  Authorize AUTOFILL on github.com           │
│  for alice@example.com?                     │
│                                             │
│  [Touch your security key to approve]       │
│                                             │
│  Operation: AUTOFILL                        │
│  Resource: github.com                       │
│  User: alice@example.com                    │
└─────────────────────────────────────────────┘
```

### 3.4 Instrumentation Points
```typescript
interface RQ2Event {
  type: 'rq2:prompt_visible' | 'rq2:gesture_start' | 'rq2:approve_sent' | 'rq2:error';
  condition: 'baseline' | 'contextual';
  trial: number;
  timestamp: number;           // performance.now()
  challengeId: string;
  operation: string;
  resource: string;
  userId: string;
  // For error trials:
  expectedOperation?: string;
  actualOperation?: string;
}
```

---

## 4. Pilot Procedure

### 4.1 Recruitment
- **N:** 3-5 internal volunteers (not authors of step-up code)
- **Inclusion:** Has WebAuthn authenticator registered; uses extension daily
- **Exclusion:** Authors of `step-up-proof.ts`, `auditor.ts`, `popup.ts`
- **Compensation:** None (internal, voluntary, ~15 min)

### 4.2 Session Script
1. **Consent (verbal):** "This is a 15-min usability pilot. You'll approve 6 step-up requests. Your timing and self-reports will be logged. No PII stored. You can stop anytime."
2. **Setup:** Install extension with `RQ2_PILOT=true`, register WebAuthn credential
3. **Calibration:** 1 warm-up trial (discarded)
4. **Trials:** 6 trials (3 per condition, ABBA/BAAB)
   - Each trial: Extension triggers step-up → participant approves → log event
4. **Post-trial:** Likert (1-5) "How conscious were you of *what* you approved?"
5. **Distractor trial (1x):** Inject wrong resource in prompt → measure error
6. **Debrief (2 min):** Free text: "What did you think you were approving?"

### 4.3 Data Collected (per trial)
```json
{
  "participantId": "P01",
  "trial": 3,
  "condition": "contextual",
  "operation": "AUTOFILL",
  "resource": "github.com",
  "userId": "alice@example.com",
  "promptVisibleTs": 1234567890123,
  "gestureStartTs": 1234567892456,
  "approveSentTs": 1234567893001,
  "hesitationMs": 2456,
  "selfReportConsciousness": 4,
  "errorInjected": false
}
```

---

## 5. Analysis Plan

### 5.1 Primary Analysis
- **Paired t-test / Wilcoxon:** Total time (A vs B)
- **McNemar / binomial:** Hesitation rate (A vs B)
- **Paired t-test / Wilcoxon:** Self-report consciousness (A vs B)

### 5.2 Effect Size Thresholds
| Metric | Minimal meaningful difference |
|--------|------------------------------|
| Time | +500ms (cost of reading context) |
| Hesitation | +20% absolute increase |
| Consciousness (1-5) | +0.5 points |

### 5.3 Qualitative Coding
Free-text responses coded for:
- "Knew exactly what I approved" (intention)
- "Just touched the key" (attention)
- "Not sure / confused"

---

## 6. Ethics & Data Handling

| Aspect | Decision |
|--------|----------|
| **IRB** | Not required (internal, <5 participants, no PII, voluntary, no risk) |
| **Consent** | Verbal, recorded in session log |
| **Data stored** | Local JSON in `chrome.storage.session` → exported to `research/rq2-pilot-data/` |
| **Retention** | 90 days, then deleted |
| **Identifiers** | Participant IDs only (P01, P02...), no names/emails |

---

## 5. Go/No-Go Criteria for Full Study

| Criterion | Threshold |
|-----------|-----------|
| **Feasibility** | All 3-5 participants complete 6 trials without technical failure |
| **Signal** | Consciousness rating difference ≥ 0.5 points (paired) |
| **Usability** | Mean time increase < 1.5s per trial |
| **Errors** | 0 distractor errors in contextual condition |

If **all 4 met** → proceed to IRB submission for full study.

---

## 6. Deliverables

| Artifact | Path | Status |
|----------|------|--------|
| Protocol doc | `research/RQ2-PILOT-PROTOCOL.md` | ✅ This file |
| Implementation | `src/background/rq2-pilot.ts`, `src/ui/popup/rq2-pilot.ts` | 🔲 TODO |
| Form HTML | `src/ui/rq2-pilot-form.html` | 🔲 TODO |
| Data export | `research/rq2-pilot-data/` | 🔲 TODO |
| Analysis script | `research/rq2-pilot-analysis.py` | 🔲 TODO |

---

## 6. Flag to Enable

```bash
# In .env or shell
RQ2_PILOT=true npm run build:ext
```

---

## Appendix A: Distractor Trial Design

One trial per participant injects a mismatch:
- Prompt shows: "Authorize AUTOFILL on github.com for alice@example.com"
- Actual operation sent to Plus: `VIEW` on `gitlab.com`
- Measure: Does participant notice? (Self-report + error logged)

---

## 6. Risks & Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|------------|--------|------------|
| Participant fatigue | Medium | Low | Max 6 trials + warmup; <15 min |
| Technical failure (WebAuthn) | Low | Medium | Warmup trial discarded; fallback to passphrase |
| Participant guesses hypothesis | Medium | Medium | Counterbalancing; debrief after |
| WebAuthn not available | Low | High | Skip participant; use passphrase fallback |
| Data loss on worker eviction | Low | Medium | Log to `chrome.storage.session` persistently |

---

## 6. Approval

| Role | Name | Date | Signature |
|------|------|------|-----------|
| PI | | | |
| Security Review | | | |
| Privacy Review | | | |