# Beta gate evidence (M3-E E17)

**What this file is.** The record of the three mandatory gates in
[beta-gate-checklist.md](beta-gate-checklist.md).

**How it is filled in.** Only from evidence the operator actually supplies. Nothing here is inferred
from source inspection, automated tests or in-process rendering.

**Current state (2026-11-02).**
- **Gate A's first run on the beta installation failed at A6** (a stale API process, GA-1).
- **The stale API was replaced and Gate A was re-run on the beta installation.** A1–A8 and A10–A16
  pass. A9 runs inside Gate B, and Gate A also needs sign-off.
- **Gates B and C have not been run.**

| Gate | Result | Evidence |
|---|---|---|
| A. Dashboard browser smoke test | **Not yet PASS:** on the beta installation, 15 of 16 checks PASS (A1–A8, A10–A16). A9, which is required, runs inside Gate B (B7a). Operator and reviewer sign-off are pending. The first run's FAIL (A6, GA-1) was corrected and re-run. | Re-run on the beta installation (2026-11-02), see Gate A |
| B. Real-installation recovery drill | **NOT RUN** | None |
| C. Storage health CLI | **NOT RUN** | None |

**Current beta decision: NO-GO.**
- **Why:** Gate A is not complete (A9 runs in Gate B; sign-offs pending), and Gates B and C have not been run.
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
| Result | **FAIL**, on the beta installation (A6). Corrective actions done; a full re-run on the beta installation is required. |
| Date and environment | 2026-11-02. Windows 11; Node.js v22.22.3; npm 10.9.8. The beta installation: API PID 8656 (`node dist/server.js`, started by `npm run start -w @agentshield/api` on 2026-10-29 22:04); Vite PID 32592 on `[::1]:5173`. Commit under test: `28f5cd5`. |
| Checklist items completed | **Operator, beta installation:** sign-in, Model Diagnostics, A5, A6. **Isolated real-browser run:** A1–A8 and A10–A16. A9 is deferred to Gate B. |
| Evidence reference | Operator screenshots (Model Diagnostics, A5, A6), described in the operator's report. The isolated run is in `AgentShield-gate-evidence\2026-11-02-gate-a\`, a folder beside the repository: 36 files, screenshots, terminal output, `gate-a-results.json`, `network.txt`, and the harness `run-gate-a.mjs`. |
| Findings and corrective actions | GA-1 to GA-4 below |
| Operator sign-off | — |
| Reviewer sign-off | — |

### Re-run on the beta installation (2026-11-02, after GA-1 was resolved)

**The environment** (read-only checks before the re-run):
- **Listener:** exactly one on `127.0.0.1:4000`.
- **Process:** API PID 49884 (`node dist/server.js`, started 13:59:44 by `npm run start -w @agentshield/api`,
  commit `894ab12` build). The stale PID 8656 was stopped with operator approval; PID 28160 was replaced
  by the operator.
- **Locks:** all four journal locks are held by PID 49884.
- **`/health`:** 200.
- **Policies:** `/api/policies` shows source `file`, `C:\agentshield-dev\agent-policies.json` (quick-start
  section 3, created 2026-11-02 and validated with the API's own loader):
  - `summary-agent`: `create_summary` only, to `simulated-workspace`;
  - `demo-summarizer`: identical to the built-in demo policy.
- **Model:** `/api/model/status` shows `mock`, live `false`.

**Who ran what:**
- **The operator:** A7 and the approval half of A8.
- **Automated, in a real browser:** the other checks. Headless Edge 156 was driven over the DevTools
  protocol against the operator's own dashboard (`http://localhost:5173`, Vite PID 32592) and API, signed
  in with the operator token. The token was used only inside the automation, never printed or saved.
  - **Run window:** 14:31:55 to 14:32:22 UTC.
  - **Evidence:** `AgentShield-gate-evidence\2026-11-02-gate-a-beta-installation\`, beside the repository.
    It holds 34 files plus `A16-cleanup.txt`, and none contains the token or a credential.

| Check | Result | Exact result | Evidence | By |
|---|---|---|---|---|
| A1 | PASS | Sign-in screen; no dashboard content before sign-in | `A1-unauthenticated.png` | automated, real browser |
| A2 | PASS | "That token was not accepted." | `A2-wrong-token.png` | automated, real browser |
| A3 | PASS | Signed in; Sign out returned to sign-in; Back left the app and showed no data | `A3-signed-in.png`, `A3-after-signout-and-back.png` | automated, real browser |
| A4 | PASS | Loading placeholders observed, then content; no error banner | `A4-loading.png` | automated, real browser |
| A5 | PASS | "No Pending Approvals" with "Open Scenario Lab" | `A5-empty-queue.png` | automated, real browser |
| A6 | PASS | `apr-2`: all card fields; "Requested by: Operator (dashboard) · scenario as demo-summarizer" | `A6-scenario-approval.png` | automated, real browser |
| A7 | PASS | `apr-1`, risk 65: "Requested by: Agent summary-agent · key 20a2038eb7d964f5". `agent-credential list` shows `20a2038eb7d964f5 summary-agent ed25519 active`. `/api/approvals` shows `requestedBy: agent/20a2038eb7d964f5`. No credential displayed. | Operator's report (dashboard and terminal); the list and approvals cross-check were recorded in this review | operator; cross-checked |
| A8 | PASS | **Approve:** `apr-1` EXECUTED (simulated); the agent printed "Approved by the operator (apr-1) and executed." and "Saved summary-1 (69 characters) to the simulated workspace." (operator). **Reject:** `apr-3` REJECTED in the history; the agent printed "The operator rejected apr-3. Nothing was saved." and exited 2 (automated). | Operator's terminal output; `A8-agent-pending.png`, `A8-history.png`, `A8-agent-reject.txt` | operator and automated |
| A9 | NOT RUN | Deferred to Gate B (B7a) | — | — |
| A10 | PASS | Each event shows its id and lifecycle. "Requested by:" reads the agent and key on its CONFIRM events, "Operator (dashboard) · on agent summary-agent's request" on its approve and reject events, and "Operator (dashboard) · scenario as demo-summarizer" on the scenario. The durable-log wording is shown. | `A10-activity-expanded.png`, `A10-events.txt` | automated, real browser |
| A11 | PASS | All six provider fields; MOCK; "Live OFF"; SIMULATED ONLY | `A11-model-diagnostics.png` | automated, real browser |
| A12 | PASS | The operator stopped the API (PID 49884) in its terminal; the dashboard showed the offline state | Operator's report (2026-11-02); no screenshot file named | operator |
| A13 | PASS | The operator restarted the API with `AGENT_POLICY_FILE` unset (PID 50976, 21:45:24); on its next action the dashboard returned to the sign-in screen | Operator's answer (2026-11-02); environment check below | operator |
| A14 | PASS | 1920×1080, all nine views: no overflow or clipped content | `A14-*.png` | automated, real browser (a human look at a real screen is recommended) |
| A15 | PASS | 375×812 mobile emulation: all nine views reachable; no overflow or clipped content; badge rows wrap | `A15-*.png` | automated, real browser (a human look in a narrow window or on a device is recommended) |
| A16 | PASS | `revoke --key 20a2038eb7d964f5` exit 0; `list` shows it revoked at 2026-11-02T14:32:52.646Z; only then `C:\agentshield-dev\summary-agent.key` was removed | `A16-cleanup.txt` | automated, documented CLI |

**After A12 and A13** (read-only check, 2026-11-02 21:48):
- **Listener:** exactly one on `127.0.0.1:4000`.
- **Process:** API PID 50976 (`node dist/server.js`, started 21:45:24 by `npm run start -w @agentshield/api`).
  PID 49884 is gone.
- **Locks:** all four journal locks are held by PID 50976. No restore markers or damaged copies.
- **`/health`:** 200.
- **Policy baseline restored:** `/api/policies` shows source `built-in`, with only `demo-summarizer`
  (sha256 `25d59416…`, the built-in demo policy). That is the configuration with `AGENT_POLICY_FILE` unset;
  `summary-agent` is no longer loaded.
- **Model:** `/api/model/status` shows `mock`, live `false`.
- **Durable state survived both restarts:** `apr-1` EXECUTED, `apr-2` EXPIRED, `apr-3` REJECTED, and six
  audit events (the newest is `evt-6`, the `apr-2` expiry). The test key file stays removed.

**Left on the installation:**
- the scenario approval `apr-2` (it expired and was recorded as EXPIRED, `evt-6`);
- the policy file and the two test notes in `C:\agentshield-dev`;
- all audit events (permanent by design).

### What the operator observed on the beta installation

Operator-supplied, 2026-11-02:

| Check | Observation | Result |
|---|---|---|
| Sign-in | Succeeded | — (A3 was not completed) |
| A11 | "API Online, Provider MOCK, Live Provider LOCKED OFF, SIMULATED ONLY, Key NOT SET, MODEL_LIVE_ENABLED is not true (mock)" | Matches A11; the rest of A11 was not recorded |
| A5 | The empty Approval Queue matched | **PASS** |
| A6 | The scenario created `apr-1`; the card showed **"Requested by: Requester not recorded"** instead of "Operator (dashboard) · scenario as <agent>" | **FAIL** (GA-1) |
| A1–A4, A7–A16 | Not run on the beta installation | NOT RUN |

### Root cause of the A6 failure (GA-1)

**The running API was a stale process.**
- **What was running:** PID 8656 started on **2026-10-29 at 22:04**, from `npm run start -w @agentshield/api`
  (PIDs 2264 → 7912 → 8656). It had kept running the code it loaded then.
- **What it predates:** about 20 commits. These include M3-C/M3-D (2026-10-31), which added `agentId` and
  `requestedBy` to approvals, and E10–E14, the durable audit, replay, idempotency and approval stores.
- **Why the files on disk didn't help:** `apps/api/dist` was rebuilt on 2026-11-01 at 22:22, but the
  process never reloaded it.
- **Why the dashboard disagreed:** the Vite dev server serves the current dashboard source. That source
  shows "Requester not recorded" when an approval carries neither field, and an API older than M3-C
  never sends them.
- **Corroboration:** `%LOCALAPPDATA%\AgentShield` holds only `api-token`. The durable stores the current
  API creates at its first start have never been created on this machine.

**The current source is correct.** `apps/api/src/beta/attribution.test.ts` (new) follows the
dashboard's own path:
1. a session signed in from the web origin;
2. the Scenario Lab request;
3. `GET /api/approvals`;
4. a restart of the durable approval store.

It shows `scenarioId`, `agentId: "demo-summarizer"` and
`requestedBy: { kind: "operator", method: "session" }` on the listed approval. The isolated
real-browser run shows the exact expected label.

**What `apr-1` was.** It existed only in the stale process's memory: that version had no approval
journal. It was not approved, rejected or edited, and is lost when that process stops.

### Real-browser run of the current build (isolated instance)

**What it is.** A real browser (Microsoft Edge 156.0.4314.58, headless, a fresh InPrivate profile)
was driven over the DevTools protocol by Node 22's built-in WebSocket. Nothing was installed.
- **Run window:** 2026-11-02, 04:44:22 to 04:45:21 UTC.
- **Instance:** isolated. The current API build ran on `127.0.0.1:4100`, with every store, its own
  throwaway API token and the quick-start policy in a scratch folder.
- **Forced off:** live model, scanning and bearer credentials, whatever `.env` contains.
- **Dashboard:** a production build of the current source, served on `127.0.0.1:5173`.
- **Credentials:** the test credential was created and revoked with the documented CLI.
- **Untouched:** the operator's processes and `%LOCALAPPDATA%\AgentShield`.

**What it is not.** Not the beta installation, and not a human judgement.

| Check | Result (isolated, real browser) | Exact result | Evidence |
|---|---|---|---|
| A1 | PASS | The sign-in screen; no dashboard content before sign-in | `A1-unauthenticated.png` |
| A2 | PASS | "That token was not accepted." | `A2-wrong-token.png` |
| A3 | PASS | Signed in (API: Online). Sign out returned to sign-in. The dashboard keeps no history entries, so Back left the app (`about:blank`) and showed no data. | `A3-signed-in.png`, `A3-after-signout-and-back.png` |
| A4 | PASS | Loading placeholders observed (with added network latency), then content; no error banner | `A4-loading.png` |
| A5 | PASS | "No Pending Approvals" with "Open Scenario Lab" | `A5-empty-queue.png` |
| A6 | PASS | All card fields; "Requested by: Operator (dashboard) · scenario as demo-summarizer" | `A6-scenario-approval.png` |
| A7 | PASS | CLI `create` exit 0. `list` shows the key id. The card shows "Agent summary-agent · key <keyId>" with the same key id. No credential-shaped value on the page. | `A7-agent-approval.png`, `A7-credential.txt`, `A7-A8-agent-approve.txt` |
| A8 | PASS | Approved: history EXECUTED (green); the agent printed "Approved by the operator (apr-2) and executed." and exited 0. Rejected: history REJECTED (red); the agent printed "The operator rejected apr-3. Nothing was saved." and exited 2. Simulated only. | `A8-history.png`, `A8-after-approve-click.png`, `A8-after-reject-click.png`, `A8-agent-reject.txt` |
| A9 | NOT RUN | Deferred to Gate B (B7a) | — |
| A10 | PASS | Expanded events show the event id, the lifecycle and "Requested by:": the agent and key id on its CONFIRM events; "Operator (dashboard) · on agent summary-agent's request" on its approve and reject events; "Operator (dashboard) · scenario as demo-summarizer" on the scenario | `A10-activity-expanded.png`, `A10-events.txt` |
| A11 | PASS | All six provider fields; mock mode; no key value | `A11-model-diagnostics.png` |
| A12 | PASS | API stopped: "API: Offline", Engine Status OFFLINE; nothing claims success | `A12-api-stopped.png` |
| A13 | PASS | API restarted: the next request returned to the sign-in screen | `A13-after-restart.png` |
| A14 | PASS | 1920×1080: all nine views; no horizontal overflow or clipped content | `A14-*.png` |
| A15 | PASS (after GA-4) | 375×812 mobile emulation: navigation through the screen selector and the bottom bar; no overflow or clipped content; decision buttons within the viewport. Tool Trust's table scrolls inside its own container. | `A15-*.png` |
| A16 | PASS | `revoke` exit 0; `list` shows the key revoked; the test key file removed | `A16-cleanup.txt` |

### Findings from Gate A

| Id | Severity | Finding | Corrective action | Status |
|---|---|---|---|---|
| GA-1 | **High** (it invalidated the gate run) | The beta installation ran an API process started on 2026-10-29, which predates agent identity (M3-C/M3-D) and every durable store (E10–E14). A6 failed, and none of E10–E16's guarantees applied to it. | The operator restarts the API on the current build: Ctrl+C in its terminal, then `npm run start -w @agentshield/api` (the same command; `dist` is current). Regression test `attribution.test.ts`. | **Resolved:** the API was restarted on the current build (PID 49884) and A6 passes on the beta installation |
| GA-2 | Medium | Activity & Audit said "Session Event Timeline (In-Memory) … Events are held in memory and reset when the API restarts": false since E10 | Corrected: events are stored in the audit log and survive restarts. Pinned in `dashboard-accuracy.test.ts`. | Fixed |
| GA-3 | Low | The operator's approve and reject events on an agent's approval were labelled "Operator (dashboard) · scenario as summary-agent", though no scenario was involved (introduced in E15) | `requesterLabel` words scenario runs (which have a `scenarioId`) and decisions apart: "… · on agent X's request". Unit test added. | Fixed |
| GA-4 | Low | At 375 px, badge rows clipped their content with no way to scroll: the Approval Queue card's policy badge, and the decision and outcome rows of Scenario Lab and Threat Investigation. Found by screenshot review; a refined clipping check then failed on the unfixed build. | The rows wrap; pinned in `dashboard-accuracy.test.ts` | Fixed |
| GA-5 | Info | There is no way to tell from outside which build a running API is (no version on `/health`); GA-1 was found from process start times | Recommendation for later; not changed in this gate | Open |
| GA-6 | Info | The sign-in screen's "unreachable" text suggests `npm run start -w @agentshield/api`, while the README uses `npm run dev:api` (noted in E16) | None | Open |

### What remains for a human (updated after A12 and A13)

1. **A9:** runs inside Gate B, step B7a (the `OUTCOME_UNKNOWN` presentation against the drill's scratch API).
2. **Operator and reviewer sign-off** for Gate A, in the table above, once A9 has passed.
3. Optional: a human look at A14 and A15 on a real screen and in a narrow window. The automated run used
   a headless browser, with mobile emulation for A15.

The normal policy configuration is restored. Items 1–4 below were the steps after the first run; all are
done except sign-off.

1. **Restart the beta installation's API on the current build (GA-1).** Stop PID 8656 in its own terminal
   with Ctrl+C, then run `npm run start -w @agentshield/api` there again. This was not done here:
   - the process belongs to the operator's terminal;
   - its environment cannot be read to preserve it;
   - an API started from this session would end with it.

   At this first start of the current build:
   - the durable stores are created in `%LOCALAPPDATA%\AgentShield`;
   - signed agent requests are refused for about 30 seconds (the replay fence);
   - the in-memory `apr-1` is gone.
2. **Re-run Gate A on the beta installation:** A1–A8 and A10–A16, per the checklist, signed in with the
   real API token, which only the operator may use.
3. **Judge the layouts on a real screen** (A14) and in a narrow window or device (A15). The automated run
   used emulation.
4. **Sign off** (operator and reviewer) once the re-run passes.

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
| Decision | **NO-GO**: Gate A not complete (A9 runs in Gate B; sign-offs pending); Gates B and C NOT RUN (2026-11-02) |
| Gate results | A: 15/16 PASS on the beta installation (A1–A8, A10–A16); A9 pending in Gate B; sign-offs pending. B: NOT RUN. C: NOT RUN. |
| Accepted limitations | None recorded |
| Open blocking findings | M3 (closed only by a Gate A PASS on the beta installation); no real-installation drill |
| Decided by | — (pending the operator's evidence) |
| Reviewed by | — |
