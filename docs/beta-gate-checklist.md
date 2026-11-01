# Beta gate checklist (M3-E E16)

**Status: PREPARED, NOT RUN.** This checklist does **not** declare AgentShield ready for a beta.
E15's verdict stands: **CONDITIONAL GO** for a limited, controlled beta, **not production-ready**
([beta-readiness.md](beta-readiness.md)).

**What this checklist does.** It turns E15's conditions into three mandatory gates that a person runs
on the beta machine. It records the evidence and applies the decision rules at the end.

**What E16 did and did not do.** None of these gates was run during E16:
- no browser was opened;
- no service was started;
- no store was read;
- no backup or restore was made.

**Commands.** Every command here comes from [operations.md](operations.md), [quick-start.md](quick-start.md)
or the main [README](../README.md#run-locally). If a step's output differs from what is expected,
**record it as a finding**; do not improvise.

## Before you start

| | |
|---|---|
| **Who** | The beta operator, the Windows account that runs the API. A second person should review the evidence. |
| **Where** | The beta machine (Windows 11). The API listens on loopback only. |
| **Build** | `npm run build` succeeded at the commit under test. Record the commit hash: `git log --oneline -1`. |
| **Evidence folder** | Create one outside the repository and outside `%LOCALAPPDATA%\AgentShield`, for example `D:\AgentShieldGate\<date>\`. Store screenshots and copied terminal output there. |
| **Never record** | The API token, any agent key file, the content of `.env`, cookies, or a screenshot of the sign-in field with the token pasted. Terminal output from AgentShield's own commands never contains these. |

**Ground rules for every gate:**
1. **Use only the documented commands**, exactly as written: `npm run ops -- <command>`, `npm run dev:api`,
   `npm run dev:web`, `npm run agent-credential -w @agentshield/api -- <command>`, and
   `npm run reference-agent -- <options>`.
2. **Never delete, move or edit anything under `%LOCALAPPDATA%\AgentShield`.**
3. **Never use `--replace-damaged` or `--restore-credentials` on the beta installation** during these
   gates.
4. **If a STOP condition is met, stop that gate,** record FAIL with the output, and continue only
   with steps the gate marks as safe.
5. **A gate is PASS only if every one of its required checks passes.** A FAIL is never re-labelled as
   acceptable (see [Decision rules](#decision-rules)).

## Gate A: dashboard browser smoke test

**Why.** E15 rendered the views in process only (markup, no browser). No layout, interaction or
session behaviour has been checked in a real browser (E15 finding M3).

**Setup.** Use the documented commands from [README, Run locally](../README.md#run-locally):
- terminal 1: `npm run dev:api`;
- terminal 2: `npm run dev:web`;
- open **http://localhost:5173**. To sign in, copy the token without displaying it:
  `Get-Content -Raw "$env:LOCALAPPDATA\AgentShield\api-token" | Set-Clipboard`.

**Agent-created approvals** use the quick-start's short-lived test credential (`--days 7`) and the
reference agent:
- [quick-start.md](quick-start.md) section 5 creates the credential;
- section 7 creates a CONFIRM;
- section 11 revokes the credential and removes the key file afterwards.

**Browsers.** Record the browser name and version, and the window sizes used.

| # | Check | How | Expected result | Required |
|---|---|---|---|---|
| A1 | Unauthorised access | Open the app in a private window, before signing in | The "Sign in to AgentShield" screen; no data is shown | Yes |
| A2 | Wrong token | Type an obviously wrong value (not the real token) and sign in | "That token was not accepted." | Yes |
| A3 | Sign-in and sign-out | Sign in with the copied token; then use **Sign out** in the top bar | The dashboard loads; signing out returns to the sign-in screen. Record what the browser's back button shows afterwards. | Yes |
| A4 | Loading state | Watch the first load after sign-in, or reload | Placeholder skeletons, then content; no error banner | Yes |
| A5 | Empty state | **Approval Queue** with nothing pending | "No Pending Approvals", with an **Open Scenario Lab** button | Yes |
| A6 | Approval queue and detail, operator scenario | In **Scenario Lab**, run the prompt-injection scenario; open **Approval Queue** | A pending card with id, status, risk score, policy version, proposed action, escalation reason, and **Requested by: Operator (dashboard) · scenario as <agent>** | Yes |
| A7 | Agent identity and key id | Create a CONFIRM with the reference agent ([quick-start.md](quick-start.md) section 7); open **Approval Queue** | **Requested by: Agent summary-agent · key <keyId>**. The key id matches the one `npm run agent-credential -w @agentshield/api -- list` shows. No credential or secret appears anywhere. | Yes |
| A8 | Decision actions | **Reject Action** on one approval; **Approve & Run (SIMULATED)** on another | Rejected moves to the history as REJECTED (red). Approved moves to the history as EXECUTED (green), or APPROVED_NOT_EXECUTED (amber). The agent reports the outcome. | Yes |
| A9 | `OUTCOME_UNKNOWN` presentation | Run during Gate B, step B7, against the drill's scratch API (it is the only safe way to produce one) | In the history: **OUTCOME_UNKNOWN in amber**, never red, with the reason "This approval was restored from a backup; whether it was decided after the backup was taken is unknown. It will not run." No approve or reject buttons. | Yes |
| A10 | Activity and audit feed | **Activity & Audit**; expand the agent's event and a scenario event | Each event expands to show its explanation, event id and lifecycle, and **Requested by:** with the agent and key id, or the operator | Yes |
| A11 | Model diagnostics | **Model Diagnostics** | The provider configuration (target endpoint base URL, auth header contract, request timeout, retry limit, payload bounds, safety gating). It shows the mock unless live use was separately authorised. No key value is shown. | Yes |
| A12 | Error state | Stop the API in terminal 1 (Ctrl+C), then use the dashboard's refresh | The dashboard marks the API offline or shows "Could not reach the AgentShield API server …". Nothing claims success. Start the API again with `npm run dev:api`. | Yes |
| A13 | Session after an API restart | After A12, use the dashboard again | Sessions are kept in memory only, so it returns to the sign-in screen. Sign in again. | Yes |
| A14 | Desktop layout | A maximised desktop window (record the size) | Every sidebar view opens. Nothing overlaps or is cut off; text is readable. | Yes |
| A15 | Mobile and responsive layout | The browser's responsive or device mode at about 375 px wide, and a narrow desktop window | Navigation is still reachable; the approval cards and decision buttons are usable; no content is hidden without a way to scroll to it. Known risk: **Website Scans** has no responsive styles; record what you see. | Yes |
| A16 | Clean-up | [quick-start.md](quick-start.md) section 11: revoke the test credential and remove its key file | `list` shows the test credential as revoked | Yes |

**STOP conditions for Gate A:**
- Any step shows data before sign-in.
- A credential, token or key value is displayed.
- A decision appears to succeed but the history or the agent disagrees.

**Evidence:** screenshots of A1, A2, A5 to A11, A14 and A15; the terminal output of A7 and A16.

## Gate B: real installation recovery drill

**Why.** E15 rehearsed recovery only in automated tests on temporary stores. Nobody has backed up and
restored this installation (E15 condition 3).

**Procedure.** The drill follows [operations.md](operations.md) (Backup, then Restore), with one
safety change: **the restore goes into an empty scratch folder, never into the live stores.** It
uses the documented store variables (`AUDIT_LOG_FILE`, `APPROVAL_STORE_FILE`,
`IDEMPOTENCY_STORE_FILE`, `REPLAY_STORE_FILE`, `AGENT_CREDENTIAL_FILE`). Values set in the PowerShell
session take precedence over `.env`.

**Why the live stores are safe even if a variable is missed.** A restore never replaces a present,
healthy store, so a forgotten variable cannot overwrite live data. The STOP check in B5 catches it
anyway.

**Before the drill.**
- Pick a time with no pending approvals that matter: the API is stopped for steps B1 to B4.
- Have a second disk or folder for the backup (for example `D:\AgentShieldBackups\<date>`). It must
  not be under `%LOCALAPPDATA%\AgentShield`.
- Pick an empty scratch folder for the restore (for example `D:\AgentShieldDrill\<date>\state`). It
  must not exist yet, and must not be under `%LOCALAPPDATA%\AgentShield`.

| # | Step | Command (exactly) | Expected result | Record |
|---|---|---|---|---|
| B1 | Stop the API | Ctrl+C in its terminal | It exits; nothing else writes the stores | Time |
| B2 | Pre-drill storage status | `npm run ops -- status` | Every store `status=verified`, `lock=free` (or `stale…` after an unclean stop); last line `storage status: ok`; exit code 0 (`$LASTEXITCODE`) | Full output, exit code |
| B3 | Backup | `npm run ops -- backup --out D:\AgentShieldBackups\<date>` | Each store `copied … status=verified` or `not present`; `backup complete: id=<16 hex> directory=…`; exit 0 | Output, backup id |
| B4 | Verify the backup | `npm run ops -- verify-backup --dir D:\AgentShieldBackups\<date>` | Every present store `status=verified`; approvals show `pending=<n>`; `backup verified`; exit 0 | Output; note the `pending` count |
| B4a | Restart the live API | `npm run dev:api` in its usual terminal (no scratch variables set) | It starts normally; no `status=integrity-failure` | Start-up log |
| B5 | Open a **new** PowerShell window and point every store at the scratch folder | `$env:AUDIT_LOG_FILE = "D:\AgentShieldDrill\<date>\state\audit-events.jsonl"`; `$env:APPROVAL_STORE_FILE = "D:\AgentShieldDrill\<date>\state\approvals.journal"`; `$env:IDEMPOTENCY_STORE_FILE = "D:\AgentShieldDrill\<date>\state\idempotency.journal"`; `$env:REPLAY_STORE_FILE = "D:\AgentShieldDrill\<date>\state\replay-nonces.journal"`; `$env:AGENT_CREDENTIAL_FILE = "D:\AgentShieldDrill\<date>\state\agent-credentials.json"`; then `npm run ops -- status` | **Every `path=` line is under the scratch folder.** Every store `status=missing`; `storage status: ok` (no store holds records yet) | Output |
| B6 | Restore into the scratch folder | In the same window: `npm run ops -- restore --dir D:\AgentShieldBackups\<date>` | The plan: `audit-log restore`, `approval-store restore`, `idempotency-store create-recovery-window`, `replay-store keep` (never restored), `credential-store skip` (no `--restore-credentials`); `restore complete from backup <id>`; `Approval ids continue at apr-<n>.`; exit 0 | Output |
| B6a | Scratch status after the restore | `npm run ops -- status` | Audit log and approvals `status=verified`; idempotency `status=verified`; replay and credentials `status=missing`, each with the note "missing while other stores hold records" (expected here); no `restore=interrupted` | Output |
| B7 | Start an API on the scratch stores | Stop the live API (Ctrl+C), then in the **scratch window**: `npm run dev:api` | The start-up log shows: `audit-log status=ready records=<n>` and no `status=integrity-failure`; `approval-store status=recovered restored=<n> effect=pending-approvals-from-backup-marked-OUTCOME_UNKNOWN` (n = B4's `pending`; this line is absent when n is 0); `replay-store status=recovering until=…`; `idempotency-store status=recovering until=… effect=new-idempotency-keys-refused` | Start-up log |
| B7a | `OUTCOME_UNKNOWN` in the dashboard (Gate A9) | `npm run dev:web`, sign in, open **Approval Queue** | Every approval that was pending in the backup is in the history as OUTCOME_UNKNOWN, amber, with the restored-from-backup reason, and cannot be decided | Screenshot |
| B7b | Storage health on the scratch API | In another window: the documented `Invoke-RestMethod http://127.0.0.1:4000/api/storage/health …` command from [operations.md](operations.md) (Watching storage health) | `replay-store` and `idempotency-store` have the `recovering` warning; `approval-store` has `approvals-made-outcome-unknown-at-startup`; no store is `failed`. The response contains no path. | Output |
| B7c | Audit integrity | Read the B7 start-up log | No `audit-log status=integrity-failure`; the record count equals the backup's audit-log `records` (B3) | Comparison |
| B8 | Stop the scratch API; restart the live API | Ctrl+C in the scratch window; **close that window** (its variables end with it); in the usual terminal: `npm run dev:api` | The live API starts with **no** `restored=` line and no `status=recovering` for replay or idempotency: the live stores were not touched | Start-up log |
| B9 | Post-drill status | In a window **without** the scratch variables, at a moment of your choosing: `npm run ops -- status` (safe while the API runs) | The same stores as B2, all `status=verified`, `lock=held-by-pid-<n>` while the API runs, `storage status: ok` | Output |
| B10 | Keep the evidence | Copy the backup folder to the second disk, if it is not already there. Keep the scratch folder for review, or delete **only that scratch folder** after sign-off. | — | Location |

**STOP conditions for Gate B** (record FAIL, keep the output, do not continue the drill):

| When | Condition | What to do |
|---|---|---|
| B2 | Exit code 1, or any store not `verified` | Do not back up a damaged installation as part of the drill. Investigate with [operations.md](operations.md) (Integrity warnings). Restart the API. |
| B3 | Backup refuses, or exits 1 | Read the reason (for example `Stop the AgentShield API first`). If it is not a simple precondition, stop. Restart the API. |
| B4 | `backup verification FAILED` | The backup is not usable. Stop. Restart the API. Delete nothing. |
| B5 | **Any `path=` line is not under the scratch folder** | Close the window, open a new one, set all five variables again. Never run `restore` until all five paths are in the scratch folder. |
| B6 | Restore refuses (`Nothing was restored …`) | Stop. Record the reason. **Do not add `--replace-damaged` or `--restore-credentials`.** |
| B7 | The scratch API refuses to start, or reports `status=integrity-failure` | Stop the scratch API. Record. Go to B8. |
| B8 | The live API reports `restored=`, `recovering`, or an integrity failure | **Serious finding:** the live stores were affected. Stop the API. Do not restore anything. Escalate with [operations.md](operations.md) and record NO-GO. |

**Rollback.** No step changes the live stores. The only live-side actions are stopping and starting
the API (B1, B4a, B7, B8). If anything goes wrong, closing the scratch window and starting the live
API from its usual terminal (B8) is the rollback.

**Never, during this drill:**
- delete, move or edit a file under `%LOCALAPPDATA%\AgentShield`, including `.lock`, `.restoring`
  or `.damaged-…` files;
- run `restore` in a window where B5's check has not passed;
- run `restore` with `--replace-damaged` or `--restore-credentials`;
- delete a backup.

## Gate C: storage health CLI

**Why.** The dashboard has no storage-health panel (E15 finding M2, deferred). During the beta,
operators check storage with the CLI and the API.

**The command:**

```powershell
npm run ops -- status
```

**What it does.**
- It is read-only and takes no lock, so it is safe while the API runs (as implemented in
  `apps/api/src/ops/backup.ts`, `storageStatus`).
- It reads the same store paths as the API: the environment variables, else
  `%LOCALAPPDATA%\AgentShield`.
- A record being appended at that moment may show as `truncated-final-record`.

**Per-store output.** One line per store, then its path:

```text
<store> status=<status> bytes=<n> maxBytes=<n> usedPercent=<n> records=<n> lock=<lock> [restore=interrupted] [permissions=not-restricted] [details=<codes>]
  path=<file>
  note: missing while other stores hold records: it was lost or deleted (see docs/operations.md, Restore)   (only then)
```

`bytes`, `maxBytes`, `usedPercent` and `records` appear only for a present file.

| Field | Values (as implemented) |
|---|---|
| `status` | `verified`, `missing`, `damaged` (the integrity chain fails, or a pre-E13 journal without one), `unsupported-version` (written by a newer AgentShield), `unreadable` (not a regular file, a link, larger than its limit, or unreadable) |
| `lock` | `free`; `held-by-pid-<n>` (a running process: normal while the API runs); `stale-pid-<n>` or `stale` (left by a process that is gone; replaced and reported at the next start) |
| `details` | Counts and codes only, for example `unverified=2`, `truncated-final-record`, `record-version=3` |

**Last line and exit code:**

| Exit code | Last line | Meaning |
|---|---|---|
| **0** | `storage status: ok` | No condition below is present |
| **1** | `storage status: ATTENTION (see docs/operations.md)` | At least one store has any of these: `status=damaged`, `unsupported-version` or `unreadable`; `restore=interrupted`; `permissions=not-restricted`; `usedPercent` of 80 or more; or it is missing while another store holds records |
| **1** | an `error: …` line on stderr | The command itself failed (unexpected) |
| **2** | the usage text | A usage error, for example extra arguments |

### Outcomes and operator action

The CLI has **two** outcomes, ok and ATTENTION. The four levels **ok, warning, critical and failed**
come from the API's view of the running stores:
- `GET /api/storage/health` (operator only);
- the API log line `storage store=<name> level=<level> … warnings=<codes>`, written at start-up and
  whenever a store's level or warnings change.

| Outcome | How it shows | Operator action ([operations.md](operations.md)) |
|---|---|---|
| **Healthy** | CLI exit 0 and `storage status: ok`; API level `ok` | None |
| **Warning** | API level `warning`: at least 80% of a size or entry limit, an integrity failure found at start-up, a recovery window in force, permissions not restricted, or a journal missing at start-up. **The CLI shows exit 1 / ATTENTION** for 80% of a file's size limit, loose permissions, damage, or a lost store. A start-up integrity finding shows in the CLI only while the file still fails its check (the audit log keeps damaged lines; journals are rewritten after recovery). | Plan an audit-log archive (Safe archival); investigate integrity findings (Integrity warnings); restrict permissions; for a lost store, see Restore |
| **Critical** | API level `critical`: at least 95% of a limit, or **full** (`storage-full`: the audit log has no room for another 256 KiB record). **The CLI does not separate critical from warning**: it shows the same exit 1 / ATTENTION from 80%. Entry limits (approvals, idempotency keys, nonces) appear only in the API view. | Act now: Disk-full handling (archive the audit log, or raise `AUDIT_LOG_MAX_BYTES` and restart) |
| **Failed** | API level `failed`: `write-failed` or `lock-lost`; the store accepts no more writes until a restart, and requests answer 503. **The CLI cannot see this:** it reads files, not the running process (it shows the lock as `held-by-pid-<n>`). | Recovery after a crash, and Lock files; free disk space if writes failed; then restart the API |
| **Interrupted restore** | CLI exit 1 with `restore=interrupted`; the API refuses to start | Run the same restore again (An interrupted restore) |
| **Newer format** | CLI `status=unsupported-version`; the API refuses to start | Use the AgentShield version that wrote it |

### Gate C steps

| # | Check | Expected | Required |
|---|---|---|---|
| C1 | Use the scratch window from Gate B (B5, B6a). Before the restore: all `missing`, exit 0. After the restore: exit 1, with the "missing while other stores hold records" note for replay and credentials. | The output matches B5 and B6a | Yes |
| C2 | In the scratch window, after B7 (scratch API running): `npm run ops -- status` | `lock=held-by-pid-<n>` on the scratch stores; still read-only (the scratch API keeps working) | Yes |
| C3 | Compare the scratch API's storage health (B7b) with C2 | Each store's integrity and size agree; the CLI shows no level, as described above | Yes |
| C4 | The operator's routine check on the beta installation (B2 and B9 already ran it) | Exit code and output recorded; any ATTENTION is explained and acted on per the table | Yes |

**STOP conditions for Gate C:**
- The command changes anything: a store's size or lock changes because of it.
- It prints record content, a key or a token.
- The exit code disagrees with the last line.

## Evidence record

Fill in one block per gate. Use PASS only if every required check passed; FAIL if any failed;
NOT RUN if the gate was not attempted.

### Gate A: dashboard browser smoke test

| Field | Entry |
|---|---|
| Result | PASS / FAIL / NOT RUN |
| Date and time | |
| Environment | Machine; Windows version; commit (`git log --oneline -1`); browsers and versions; window sizes |
| Steps performed | A1 … A16 (mark each ✓ / ✗ / not run) |
| Evidence | File names in the evidence folder |
| Findings | Id, severity, description, blocking yes/no |
| Operator sign-off | Name, date |
| Reviewer sign-off | Name, date |

### Gate B: real installation recovery drill

| Field | Entry |
|---|---|
| Result | PASS / FAIL / NOT RUN |
| Date and time | Start and end; how long the API was stopped |
| Environment | Machine; commit; backup folder; scratch folder |
| Steps performed | B1 … B10 (mark each ✓ / ✗ / not run; note any STOP condition met) |
| Evidence | Output files for B2, B3, B4, B5, B6, B6a, B7, B7b, B8, B9; screenshot for B7a; backup id |
| Checks | Pending approvals from the backup became OUTCOME_UNKNOWN (count matches B4); replay fence in force; idempotency recovery window in force; audit record count matches; live stores untouched (B8, B9) |
| Findings | |
| Operator sign-off | |
| Reviewer sign-off | |

### Gate C: storage health CLI

| Field | Entry |
|---|---|
| Result | PASS / FAIL / NOT RUN |
| Date and time | |
| Environment | Machine; commit; which installation (scratch, or beta installation for C4) |
| Steps performed | C1 … C4 |
| Evidence | Outputs with their exit codes (`$LASTEXITCODE`) |
| Findings | |
| Operator sign-off | |
| Reviewer sign-off | |

## Findings carried from E15

**Fixed in E15** (verify them as part of the gates): M1 requester visibility (A6, A7, A10),
M4 lost-store status (C1), L1, L2 (A9), L3, L6.

**Still open:** each needs an explicit decision.

| Id | Finding | Blocking? | Gate that addresses it | Decision (accept as a limitation / must fix) and who decided |
|---|---|---|---|---|
| M2 | No storage-health panel in the dashboard | Not blocking if Gate C passes and the daily CLI check is adopted | C | |
| M3 | Dashboard not tested in a browser | **Blocking until Gate A passes** | A | — (closed only by a Gate A PASS) |
| L4 | No agent or credential view in the dashboard (CLI only) | Not blocking | — | |
| L5 | The full test suite is sensitive to machine load (once, in E14) | Not blocking | — | |
| — | No real-installation recovery drill | **Blocking until Gate B passes** | B | — (closed only by a Gate B PASS) |

**Accepted residual risks** (from [beta-readiness.md](beta-readiness.md) and
[security-assessment.md](security-assessment.md)) must be acknowledged, not just listed:
- same-account trust: whoever controls the Windows account controls the stores and backups;
- the API token's default ACL;
- pattern-based injection detection;
- a bypassable commit hook with no CI;
- simulated execution only;
- single process, loopback only.

## Decision rules

Apply these after the three evidence records are complete. **The decision is made by people, from
the evidence.** Nothing in this repository makes it automatically.

| Decision | Requires |
|---|---|
| **GO** | Gates A, B and C are all **PASS**; no finding from any gate is blocking; every open finding above has a recorded decision; the residual risks are acknowledged |
| **CONDITIONAL GO** | Gates A, B and C are all **PASS**, and what remains is only **explicitly accepted, non-blocking** limitations. Each must be listed by id, with the condition the beta runs under (for example "M2 accepted: daily `npm run ops -- status`") and who accepted it. |
| **NO-GO** | **Any** mandatory gate is FAIL **or NOT RUN**; or a serious security or recovery issue remains. Examples: data shown before sign-in; a credential or token displayed; an approval decided wrongly or decidable when it should not be; a restore that affected live stores; a backup that does not verify; an integrity failure that is not explained. |

**What can never be accepted:**
- **A failed gate is never accepted as a limitation.** Fix the cause, then run that gate again
  completely, with new evidence.
- **A mandatory gate that was not run** is a NO-GO, not a conditional GO.

### Final decision record

| Field | Entry |
|---|---|
| Decision | GO / CONDITIONAL GO / NO-GO |
| Gate results | A: … B: … C: … |
| Accepted limitations (ids and conditions) | |
| Open blocking findings | |
| Beta operating conditions adopted | From [beta-readiness.md](beta-readiness.md), "Recommended beta operating conditions" |
| Decided by | Name, role, date |
| Reviewed by | Name, role, date |
