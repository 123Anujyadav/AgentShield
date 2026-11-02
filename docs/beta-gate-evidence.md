# Beta gate evidence (M3-E E17)

**What this file is.** The record of the three mandatory gates in
[beta-gate-checklist.md](beta-gate-checklist.md).

**How it is filled in.** Only from evidence the operator actually supplies. Nothing here is inferred
from source inspection, automated tests or in-process rendering.

**Current state (2026-11-02): no gate has been executed.** No screenshots, logs, outputs or sign-offs
have been received.

| Gate | Result | Evidence received |
|---|---|---|
| A. Dashboard browser smoke test | **NOT RUN** | None |
| B. Real-installation recovery drill | **NOT RUN** | None |
| C. Storage health CLI | **NOT RUN** | None |

**Current beta decision: NO-GO.**
- **Why:** under the E16 decision rules, any mandatory gate that is FAIL **or NOT RUN** is a NO-GO.
- **What it is not:** this records missing evidence, not a defect found in AgentShield.
- **What stands:** E15's assessment (**CONDITIONAL GO**, conditions not yet met) remains the
  technical baseline.
- **AgentShield is not production-ready.**

## Pre-execution review (2026-11-02)

The checklist was reviewed for unsafe ambiguity before any execution. Corrections were made in
[beta-gate-checklist.md](beta-gate-checklist.md):

| # | Issue | Correction |
|---|---|---|
| R1 | Nothing required re-checking the scratch paths immediately before the scratch API starts (B7). If one variable had been missed, that API would have opened, and written to, the live store. | New step **B6b**: verify all five `path=` lines immediately before B7, with a STOP condition. B7's STOP condition now also covers an `audit-log … path=` outside the scratch folder in its start-up log. |
| R2 | A7 (agent identity) needs `summary-agent` to have a policy. Gate A's setup started the API without one, so A7 would have produced BLOCK, not CONFIRM. | Gate A setup now points to [quick-start.md](quick-start.md) sections 3–4 (`$env:AGENT_POLICY_FILE`), and says to return to the installation's own policy afterwards |
| R3 | B7a started a second web app, which may already be running | "If not still running"; sign in again; only observe on the scratch API |
| R4 | Gate A leaves permanent test records (audit events, approvals, a revoked test credential) in the beta installation; this was not stated | Stated in "Execution order"; record Gate A's time window |
| R5 | No execution order, although A9 can only run inside Gate B | "Execution order": A (without A9), then B (with A9 and C1–C3), then C4 |

**Confirmed safe as written.** These properties of the implementation back the checklist:

| Property | Why it matters |
|---|---|
| A restore never replaces a present, healthy store, and refuses while any store lock is held by a running API | A missed variable in B5 or B6 cannot overwrite live data |
| `npm run ops -- status` is read-only and takes no lock | B2, B9 and C1–C4 are safe while the API runs |
| Values set in the PowerShell session take precedence over `.env` (Node's `process.loadEnvFile` does not overwrite them) | The scratch variables in B5 apply |
| No Gate B step deletes, moves or edits a live file | The drill can always be rolled back |

## What to send back for review

**Never include:** the API token, any key file, `.env`, cookies, or a screenshot of the sign-in field
with the token pasted. AgentShield's own command output never contains these. For screenshots,
check that nothing sensitive is visible.

| Gate | Send |
|---|---|
| **All** | Date and time, machine, Windows version, `git log --oneline -1`, and the operator's name |
| **A** | Browser name, version and window sizes; one line per check A1–A16 (✓ / ✗ / not run, plus anything unexpected); screenshot file names for A1, A2, A5–A11, A14, A15; the terminal output of A7 (`agent-credential list` and the agent's output) and A16; Gate A's time window |
| **B** | The terminal output of B2, B3, B4, B5, B6, B6a, B7 (start-up log), B7b and B8, and of B9 with its exit code (`$LASTEXITCODE` after each `ops` command); the B6b path lines; the B7a screenshot; the backup id; any STOP condition met, and what was done |
| **C** | C1–C4 outputs with their exit codes; for any ATTENTION, the action taken from [operations.md](operations.md) |

**How results will be reviewed.**
- Each item is mapped to its checklist entry and recorded **PASS** (it matches the expected result),
  **FAIL** (it differs, or a STOP condition was met), or **NOT RUN**. A gate is PASS only if every
  required check passed.
- CLI results are judged as the CLI reports them: `ok` / exit 0, or `ATTENTION` / exit 1. They are
  never read as the API's ok, warning, critical or failed levels.
- The CLI cannot detect runtime `write-failed` or `lock-lost` conditions, so those are judged only
  from the API's storage-health output.

## Gate A: dashboard browser smoke test

| Field | Entry |
|---|---|
| Result | **NOT RUN** |
| Date and environment | — |
| Checklist items completed | None |
| Evidence reference | — |
| Findings and corrective actions | — |
| Operator sign-off | — |
| Reviewer sign-off | — |

## Gate B: real-installation recovery drill

| Field | Entry |
|---|---|
| Result | **NOT RUN** |
| Date and environment | — |
| Checklist items completed | None |
| Evidence reference | — |
| Checks: pending approvals became OUTCOME_UNKNOWN; replay fence; idempotency window; audit integrity; live stores untouched | — |
| Findings and corrective actions | — |
| Operator sign-off | — |
| Reviewer sign-off | — |

## Gate C: storage health CLI

| Field | Entry |
|---|---|
| Result | **NOT RUN** |
| Date and environment | — |
| Checklist items completed | None |
| Evidence reference (outputs and exit codes) | — |
| Documented action followed (for any ATTENTION) | — |
| Findings and corrective actions | — |
| Operator sign-off | — |
| Reviewer sign-off | — |

## Open findings and acceptance

Carried from E15 and E16. Each needs a named decision before a GO or CONDITIONAL GO.

| Id | Finding | Blocking | Decision | Acceptance owner |
|---|---|---|---|---|
| M2 | No storage-health panel in the dashboard | Not blocking if Gate C passes and the daily CLI check is adopted | — | — |
| M3 | Dashboard not tested in a browser | **Blocking** until Gate A passes | Closed only by a Gate A PASS | — |
| L4 | No agent or credential view in the dashboard | Not blocking | — | — |
| L5 | The full test suite is sensitive to machine load | Not blocking | — | — |
| — | No real-installation recovery drill | **Blocking** until Gate B passes | Closed only by a Gate B PASS | — |
| — | Residual risks in [beta-readiness.md](beta-readiness.md) | Must be acknowledged | — | — |

## Decision record

| Field | Entry |
|---|---|
| Decision | **NO-GO**: all three gates NOT RUN (2026-11-02) |
| Gate results | A: NOT RUN. B: NOT RUN. C: NOT RUN. |
| Accepted limitations | None recorded |
| Open blocking findings | M3; no real-installation drill |
| Decided by | — (pending the operator's evidence) |
| Reviewed by | — |
