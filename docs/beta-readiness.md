# Beta readiness assessment (M3-E E15)

**Date:** 2026-11-01.
**Commit assessed:** `bb768b2`, plus the E15 changes listed below.
**Scope:** the complete AgentShield Sentinel prototype:
- the signed agent protocol and SDK;
- the reference agent;
- the API with its durable stores;
- the operator dashboard;
- the operations tooling.

This is an assessment for a **limited, controlled beta**. It is not a production-readiness
statement. Passing tests show that the behaviour they check holds. They do not show that untested
behaviour is correct.

## Verdict: CONDITIONAL GO

**AgentShield is ready for a limited, controlled beta under the operating conditions below.** It is
**not** production-ready. No Critical or High finding is open.

**What the beta can validate:** the decision and approval workflow, end to end. Every action
AgentShield "executes" is **simulated**; no real tool runs.

**The conditions that make this a conditional GO:**
1. The dashboard has not been tested in a browser.
2. No recovery drill has been run on a real installation.
3. Storage health has no dashboard panel yet.

## What was validated, and how

### Tests actually executed

- **`npm test` (all seven workspaces): 2,347 tests in 79 files, all passed.** Run on Windows 11 (Node 22).

  | Workspace | Tests | Files |
  |---|---|---|
  | agent-protocol | 120 | 2 |
  | agent-sdk | 56 | 3 |
  | reference-agent | 91 | 4 |
  | engine | 728 | 9 |
  | websec | 395 | 13 |
  | API | 929 | 44 |
  | web | 28 | 4 |

  **Flakiness.** In E14, one full run straight after a build had 10 timeouts (5 s limit) from
  machine load. Every affected file passed in isolation, and on every rerun since.
- **`npm run build`, `npm run typecheck`:** pass for all seven workspaces.
- **`npm run security:scan`, `security:self-test` (61 checks), `security:verify`, `git diff --check`:** pass.
- **New in E15:** 23 tests, added only where the audit found a gap.

  | File | Tests | What it checks |
  |---|---|---|
  | `apps/api/src/beta/lifecycle.test.ts` | 8 | The whole beta workflow on the durable stack, wired as `server.ts` wires it, over loopback HTTP, driven by the real SDK and the real credential CLI |
  | `apps/api/src/beta/load.test.ts` | 3 | Bounded concurrency on durable stores, with latency and memory measurements |
  | `apps/api/src/beta/recovery-drill.test.ts` | 1 | The documented recovery procedure through the operator CLI, keeping a transcript |
  | `apps/api/src/beta/windows-paths.test.ts` | 5 | Windows path handling |
  | `apps/api/src/ops/backup.test.ts` | +1 | `ops status` on a lost store |
  | `apps/web/src/approval-display.test.tsx` | 5 | Requester and status display, rendered in process |

- **Not run:** `npm audit`. It needs network access; it last reported 0 vulnerabilities on 2026-10-26.

### End-to-end workflows

Each workflow runs in `lifecycle.test.ts` on durable temporary stores. Existing suites cover the same
behaviour in more depth: E5 SDK integration, E6/E8 reference agent, E11 idempotency, E12 approvals,
E14 operations.

| # | Workflow | Result |
|---|---|---|
| 1 | Agent credential creation with the real CLI | **Pass.** The private key goes only to the restricted `--out` file; the store keeps the public key only; nothing secret is printed |
| 2 | Signed authentication | **Pass.** SDK signatures verify; an unknown key, a missing header and a forged signature get 401 before any evaluation |
| 3 | Successful evaluation | **Pass.** `ALLOW`, executed once |
| 4 | Policy-based blocking | **Pass.** The agent's server-side policy blocks a denied action whatever its intent claims |
| 5 | Approval creation | **Pass.** Suspicious untrusted content gives `CONFIRM` and an approval id |
| 6 | Operator approval and rejection | **Pass.** Only the operator can decide; a decided approval answers 409 if decided again |
| 7 | Credential and policy rechecks | **Pass.** A credential revoked with the CLI, and a policy changed across a restart, both give `BLOCKED_ON_RECHECK` |
| 8 | Simulated execution | **Pass.** The simulator ran exactly once per allowed or approved action, and never otherwise |
| 9 | Durable audit events | **Pass.** Every event is back after a restart, in order, and the chain verifies |
| 10 | Agent approval polling | **Pass.** `getApproval` and `waitForApproval`; another agent reads `null` |
| 11 | Idempotent retry | **Pass.** Replayed, not re-run, including after a restart and a policy change |
| 12 | Restart recovery | **Pass.** Approvals, audit, replay and idempotency state survive; the next id continues |
| 13 | Storage failure | **Pass.** A disk-full approval journal: 503, nothing runs, the health route shows `failed`, and a restart leaves no damage |
| 14 | Backup verification and restore | **Pass.** See the recovery drill below |

**No bypass was found.** In every step, the number of simulated executions matched exactly the
actions that were allowed or operator-approved. Agents could not decide approvals, and unsigned or
forged requests never reached evaluation.

### Dashboard and browser validation

**Not browser-tested.** The repository has no browser test tooling (no jsdom, Testing Library or
Playwright). Adding it would add dependencies, and running the dashboard would mean starting the dev
server; neither was authorised. What was done:

- **Code inspection** of the views and their API use. Every request uses the session cookie. A 401
  returns to the sign-in view. Refresh failures mark the API offline. Approval errors are shown to
  the operator. There is a loading state.
- **In-process rendering** with `react-dom/server` (markup only: no layout and no interaction):
  - the approval queue's pending cards, empty state and decided history;
  - the activity view's event rows.

| Area | Status |
|---|---|
| Approval queue, detail and decision actions | Inspected and rendered in process. **Fixed (M1):** pending approvals now show who requested them (agent and key id, or operator). **Fixed (L2):** `OUTCOME_UNKNOWN` is shown amber with its reason, not as a block. |
| Agent status visibility | **Gap (L4):** there is no agent or credential view; it is CLI only (`agent-credential list`). The requester is now shown on approvals and events. |
| Activity and audit history | Inspected and rendered. Event details now show the requester. |
| Model diagnostics | Inspected; covered by existing source-accuracy tests |
| Storage health | **No panel (M2): deferred**, see below |
| Error and loading states | Inspected only |
| Unauthorised access | Inspected (a 401 returns to sign-in); the API side is fully tested (`security.test.ts`) |
| Mobile and desktop layouts | **Not tested.** Responsive classes exist in most views but not in the website-scans view. |

**Why the storage-health panel is deferred.** E15 is a validation phase. The data is already
available to operators, through `GET /api/storage/health` and `npm run ops -- status`, and the API
logs any level change. A panel would add polling and UI that cannot be browser-tested here. It is a
recommended E16 item, and checking storage health by CLI is a beta condition.

### Windows compatibility

**Where it ran.** All of the following ran on Windows 11, in temporary directories. No live
credential or secret file was opened.

| Area | Status and evidence |
|---|---|
| File permissions and ACLs | **Pass.** Single-entry ACLs on new state files, preserved copies and backups (E13/E14 tests, using icacls). A backup directory uses an inheritable entry (E14 fix). |
| Parent-directory junctions | **Pass.** Junctions above any store are refused (E13). Real symbolic links need a privilege the test account lacks, so junctions were used. |
| Lock ownership and replacement | **Pass.** A live lock refuses start-up; a stale lock is replaced and reported; a lost lock stops writing (E13/E14) |
| Atomic compaction | **Pass.** A crash before the rename leaves the old journal (E13) |
| Backup and restore; interrupted restore | **Pass** (E14 tests and the E15 drill) |
| Special files | **Pass.** A directory at a store path, and the `\\.\` device namespace, are refused. **Fixed (L1):** an NTFS alternate data stream (`file:stream`) is now refused with that reason; before, it was refused as "an interrupted restore". Reserved names (`NUL`, `CON`, `COM1`) and trailing dots become ordinary files: records persist and are never silently discarded. |
| Path handling | **Pass.** Relative paths are refused; `\\?\` prefixes and UNC paths are handled |
| Process restart recovery | **Pass.** A lock left by an exited process, with cut-short records, recovers and is reported without an integrity failure |
| **Not tested** | Multi-account ACL scenarios (only one Windows account was available); antivirus or OneDrive interference with store files (the stores live in `%LOCALAPPDATA%`, which is not synced); Windows editions other than 11 |

### Load and resilience (bounded, local)

Fixed sizes, in process, loopback only. These are observations, not benchmarks.

| Scenario | Result |
|---|---|
| 100 concurrent signed evaluations from 4 agents, on durable stores (every accepted nonce, idempotency record, approval and event fsynced) | All 200 `ALLOW`, executed exactly once each, 100 audit events in order with a verified chain. About 0.6 s wall time (about 170 per second); p50 557 ms, p95 581 ms, max 582 ms; heap +3.4 MB; RSS about 98 MB. |
| 20 concurrent duplicates of one idempotent request | One evaluation, one execution, identical answers; about 90 ms |
| 3 agents filling a shared approval queue concurrently (limit 40, 10 per agent) | Exactly 10 approvals per agent, 2 refused (503) each, nothing executed; intact after a restart |
| Replay-cache, idempotency, audit-log and approval-journal capacity | Covered by existing tests (E8 503 tests, E11 capacity, E10 full log, E12 full journal); not repeated |
| Storage write failures, network timeouts, API failures, interrupted operations | Covered by existing tests (E8 reference-agent failures, E10–E14 fault injection) and lifecycle step 13 |

**Observation.** Writes are synchronous: each request fsyncs before it returns, on one event loop.
Concurrent requests therefore queue, and latency grows with concurrency. This is fine for a handful
of agents, and a limit to watch in the beta.

### Backup and recovery drill (isolated)

**What was run.** `recovery-drill.test.ts` runs the procedure in `docs/operations.md` through the
operator CLI, on temporary stores:
1. status;
2. backup, then verify-backup;
3. activity after the backup (an approval that was pending in the backup is executed);
4. a disaster: three journals lost;
5. status;
6. a restore interrupted by a simulated power loss;
7. the API refuses to start, and status shows `restore=interrupted`;
8. the same restore again;
9. status, then every store restarts.

**Results:**

| Check | Result |
|---|---|
| Complete backup; manifest validation | **Pass** |
| Restore planning | **Pass.** The audit log and credentials are kept (healthy); approvals restored; idempotency gets a recovery window; replay is never restored |
| Interrupted restore | **Pass.** It blocks start-up, and the same restore resumes it |
| Healthy-store preservation | **Pass** |
| Approval quarantine | **Pass.** The approval executed after the backup comes back `OUTCOME_UNKNOWN`, never runnable; ids continue past `apr-4`, which only the audit log knew |
| Replay and idempotency after the restore | **Pass.** The fence is in force; the backed-up key is refused, not replayed |
| Post-restore integrity | **Pass.** The audit chain and the restored journal verify |

**Found by the drill and fixed (M4):** after the disaster, `ops status` reported "ok" with three
stores missing. It now needs attention whenever a store is missing while another holds records.

**A drill on a real installation has not been performed.** It remains an operator activity before
the beta starts (condition 3).

## Findings

| ID | Severity | Finding | Status |
|---|---|---|---|
| — | **Critical** | None | — |
| — | **High** | None | — |
| M1 | Medium | The dashboard never showed which agent (or operator) requested an approval, although the API provides it. An operator could approve without seeing the requester. | **Fixed** (requester on approval cards, history and event details) |
| M2 | Medium | No storage-health panel in the dashboard | **Deferred** to E16; beta condition 4 |
| M3 | Medium | The dashboard has not been tested in a browser, including mobile and desktop layouts | **Open**; beta condition 1 |
| M4 | Medium | `ops status` reported "ok" when stores were lost while others held history | **Fixed** (exit 1 with a note) |
| L1 | Low | An NTFS alternate-data-stream store path was refused with a misleading "interrupted restore" message | **Fixed** (explicit reason) |
| L2 | Low | `OUTCOME_UNKNOWN` approvals were shown red, like a block, without their reason | **Fixed** (amber, reason shown) |
| L3 | Low | Docs and the SDK still said approval ids restart at `apr-1` after a restart (stale since E12) | **Fixed** (architecture, integration guide, SDK README and type docs) |
| L4 | Low | No agent or credential status view in the dashboard (CLI only) | Open; deferred |
| L5 | Low | The full test suite is load-sensitive on Windows: one run of 10 timeouts in E14 | Open; reruns pass. The heaviest suite has longer timeouts. |
| L6 | Low | Four older test files (`load-env`, `policies/store`, `credentials.v2`, the SDK's `credential`) left temporary directories in `%TEMP%` (951 accumulated on the assessment machine, some holding synthetic test credentials) | **Fixed** (every created directory is removed). Existing leftovers were not deleted; remove `%TEMP%\agentshield-*` once no test is running. |
| I1 | Info | On a first-ever start (or after a replay journal is lost) signed requests are refused for the skew window (30 s by default); the SDK reports `ServiceUnavailableError` | By design (replay fence) |
| I2 | Info | Throughput is bounded by synchronous fsync on one event loop (about 170 durable evaluations per second locally) | Acceptable for the beta |
| I3 | Info | Reserved Windows device names are ordinary files under Node; nothing is discarded | Documented |
| I4 | Info | `npm audit` was not re-run (no network) | — |

## Known limitations

- **Simulated execution only.** No real tool, email or file action is performed.
- **Single process, single machine, single Windows account.** No TLS. The API listens on loopback only.
- **The model is a mock by default.** Live model use is separately gated and was not exercised.
- **Backups are offline and manual,** and there is no off-machine copy unless the operator makes one.
- **Website scanning is off by default** and was not part of this assessment.

## Security residual risks

- **Same-account trust.** Anyone controlling the operator's Windows account, or an administrator,
  can read and rewrite the stores, the backups, the credential store and the API token. The
  integrity chains only detect accidental or unsophisticated damage (E13; tamper evidence needs a
  new trust boundary).
- **The API token** keeps the profile's default ACL (E9). **Verified in M3-E E17:** on the assessment
  machine that ACL also grants read access to the local groups `CodexSandboxUsers` and
  `MuseSandboxUsers`. New token files are now created restricted; the existing one needs the operator's
  decision (beta-signoff.md, R2).
- **Restoring an old credential store** undoes later revocations. It needs an explicit flag, and the
  credential list should be reviewed afterwards.
- **Prompt-injection detection** is pattern-based. Novel phrasings may be missed, and the scanner
  benchmark's limits apply. Policy enforcement and operator approval remain the controls that
  matter.
- **The secret-scanning hook** can be bypassed with `--no-verify`, and there is no CI.
- **If both the approval journal and the audit log are lost,** approval ids can restart, and
  idempotency keys from the last 15 minutes are unknown.

## Beta blockers

**None open.** A beta should not start until conditions 1 and 3 below are met.

## Recommended beta operating conditions

Conditions 1 and 3, and the storage CLI check, are turned into mandatory gates with evidence
templates and decision rules in [beta-gate-checklist.md](beta-gate-checklist.md) (M3-E E16; prepared,
not run).


1. **Browser smoke test first.** A person checks the dashboard on the beta machine (sign-in, approval
   queue, decide an approval, activity view, a narrow window) and records the result.
2. **Scope.**
   - One operator machine (Windows 11), loopback only, one Windows account.
   - At most a handful of agents (fewer than 10), each with its own Ed25519 credential and its own
     server-side policy.
   - Synthetic or non-sensitive tasks only.
3. **A real-installation recovery drill before day one.** Follow `docs/operations.md` on the beta
   machine: stop, backup, verify, restore to a scratch copy, restart. Record it.
4. **Daily operations:**
   - `npm run ops -- status` at the start of each day;
   - an offline backup at the end of each day, copied to another disk;
   - read the API's `storage` and `status=integrity-failure` log lines.
5. **Credentials.** Rotate and revoke with the CLI. Never restore an old credential store without
   reviewing the list afterwards.
6. **Exit criteria for the beta.** Record:
   - every `OUTCOME_UNKNOWN`, every integrity warning and every 503;
   - any approval decided without the operator recognising the requester;
   - latency complaints.

   Review them before any wider rollout.
7. **Not production.** No public exposure, no real credentials, no real tool execution.
