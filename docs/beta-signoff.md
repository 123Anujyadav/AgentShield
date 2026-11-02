# Beta sign-off packet (M3-E E17)

**What this is.** The human decision package for the controlled beta. It records:
- what the evidence shows;
- every finding, limitation and residual risk that needs a named decision;
- the sign-offs.

**Status (prepared 2026-11-02): technically complete, awaiting human sign-off.**
- Every check in Gates A, B and C passed.
- No blocking finding is open.
- **No decision or signature below has been filled in.** Only the operator and an independent reviewer
  may do that, and nothing in this repository fills them automatically.
- AgentShield is **not production-ready**.

**Sources:**
- [beta-readiness.md](beta-readiness.md): the E15 assessment, findings, limitations and residual risks;
- [beta-gate-checklist.md](beta-gate-checklist.md): the gates and the decision rules (E16);
- [beta-gate-evidence.md](beta-gate-evidence.md): the E17 results, with evidence references.

**Evidence** is in `AgentShield-gate-evidence\` beside the repository:
- `2026-11-02-gate-a\`: the first, isolated real-browser run;
- `2026-11-02-gate-a-beta-installation\`: the Gate A re-run;
- `2026-11-02-gate-b\`: Gates B and C.

**Also retained:** the backup `C:\AgentShieldBackups\2026-11-02` (id `d4b8bf8a76bfdde4`) and the scratch
folder `C:\AgentShieldDrill\2026-11-02\state`.

## 1. How to complete this packet

1. **The operator** reviews the evidence, then signs each gate (section 2). The operator also decides
   every item in section 3 (ACCEPT or REJECT), naming an owner and, for each accepted item, the
   condition the beta runs under.
2. **An independent reviewer** checks the same evidence and signs each gate. That means someone who did
   not run the gates; neither Claude Code nor the operator can act as reviewer.
3. **Fill in section 4** using the E16 decision rules.
4. **REJECT on any item that is not "fixed"** means it must be fixed, and the affected gate re-run, before
   a GO or CONDITIONAL GO.
5. **A failed gate is never accepted as a limitation.** A gate that was not run is a NO-GO.

## 2. Gate sign-offs

| Gate | Technical result (evidence) | Operator sign-off (name, date, "I have reviewed the evidence and confirm the result") | Independent reviewer sign-off (name, date, statement) |
|---|---|---|---|
| **A**: dashboard browser smoke test | **16/16 PASS** on the beta installation (A9 during Gate B) | | |
| **B**: real-installation recovery drill | **B0–B10 PASS** (backup `d4b8bf8a76bfdde4`; GB-2 limitation) | | |
| **C**: storage health CLI | **C1–C4 PASS** | | |

**Gate A, A1–A16:**

| Check | Result | Notes |
|---|---|---|
| A1–A6 | PASS | Automated, real browser (headless Edge 156), against the operator's dashboard and API |
| A7 | PASS | Operator; cross-checked with `agent-credential list` and `/api/approvals` |
| A8 | PASS | Approval by the operator; rejection automated |
| A9 | PASS | B7a: `OUTCOME_UNKNOWN` in amber, with the reason, and no actions |
| A10, A11 | PASS | Automated, real browser |
| A12, A13 | PASS | Operator |
| A14, A15 | PASS | Automated, real browser (A15 in mobile emulation). See item O1. |
| A16 | PASS | Documented CLI |

The first Gate A run failed at A6 (GA-1). The cause was corrected and Gate A was re-run in full.

**Gate B:** every step PASS: B0–B4a, B5–B6b, B7–B7c, B8, B9; B10 PASS with limitation GB-2.

**Gate C:** C1–C3 PASS (inside Gate B); C4 PASS (B2 and B9).

## 3. Residual-risk register

Every item from beta-readiness.md (its findings, known limitations and security residual risks) and
from the E16–E17 gate runs is listed separately. None is merged or downgraded.

**Columns:**
- **Status:** *Fixed* means corrected with evidence (decision: confirm the fix). *Open* means a limitation
  or risk that needs ACCEPT or REJECT.
- **Decision, owner, date:** blank until the operator fills them in.

### 3.1 Findings (beta-readiness.md)

| Id | Severity | Finding | Status | Blocking | Impact | Mitigation / operating condition | Follow-up | Decision (ACCEPT / REJECT / CONFIRM FIX) | Owner | Date |
|---|---|---|---|---|---|---|---|---|---|---|
| M1 | Medium | The dashboard did not show which agent or operator requested an approval | Fixed (E15) | No | An operator could approve without seeing the requester | Requester shown on approval cards, history and events. Verified in Gate A A6, A7 and A10. | — | | | |
| M2 | Medium | No storage-health panel in the dashboard | **Open** | No (Gate C passed) | Storage problems are visible only from the CLI, the API route or the API log | **Condition:** run `npm run ops -- status` at the start of each day and read the API's `storage` log lines | A dashboard panel (later phase) | | | |
| M3 | Medium | The dashboard had not been tested in a browser | Closed technically (Gate A) | Closes with the Gate A sign-off | — | Gate A: 16 checks in a real browser | A human visual check of A14 and A15 (item O1) | | | |
| M4 | Medium | `ops status` said "ok" when stores were lost | Fixed (E15) | No | A lost store could go unnoticed | Exit 1 with a note; verified in Gate B (B6a) and Gate C (C1) | — | | | |
| L1 | Low | Alternate-data-stream path refused with a misleading message | Fixed (E15) | No | Confusing error | Explicit reason | — | | | |
| L2 | Low | `OUTCOME_UNKNOWN` shown red without its reason | Fixed (E15) | No | Could be misread as a block | Amber, with the reason; verified in A9 | — | | | |
| L3 | Low | Docs and SDK said approval ids restart after a restart | Fixed (E15) | No | Misleading integration advice | Corrected | — | | | |
| L4 | Low | No agent or credential status view in the dashboard | **Open** | No | Credential status only through `npm run agent-credential -w @agentshield/api -- list` | **Condition:** check credentials with the CLI; rotate and revoke with the CLI | A dashboard view (later phase) | | | |
| L5 | Low | The full test suite is sensitive to machine load on Windows (E14 timeouts; an `ENOBUFS` socket error in E17) | **Open** | No | A run can fail for environmental reasons | Rerun the affected suite; the heaviest suites have longer timeouts | Make the suites less resource-hungry (later phase) | | | |
| L6 | Low | Older tests left temporary directories, some holding synthetic test credentials | Fixed (E15). **Leftovers not deleted.** | No | Synthetic test keys remain in `%TEMP%\agentshield-*` | No new leftovers are created | **Action:** the operator deletes `%TEMP%\agentshield-*` while no test runs | | | |
| I1 | Info | First start (or a lost replay journal): signed requests refused for 30 s | By design | No | Agents see `ServiceUnavailableError` briefly | Documented replay fence | — | | | |
| I2 | Info | Throughput is bounded by synchronous fsync (about 170 durable evaluations per second locally) | Accepted in E15 | No | Latency grows with concurrency | **Condition:** fewer than 10 agents | Revisit before wider use | | | |
| I3 | Info | Reserved Windows device names are ordinary files | Documented | No | None (nothing discarded) | — | — | | | |
| I4 | Info | `npm audit` not re-run (no network) | **Open** | No | Unknown new advisories since 2026-10-26 | — | **Action:** run `npm audit` with network access before the beta starts | | | |

### 3.2 Known limitations (beta-readiness.md)

| Id | Limitation | Status | Blocking | Impact | Mitigation / operating condition | Follow-up | Decision (ACCEPT / REJECT) | Owner | Date |
|---|---|---|---|---|---|---|---|---|---|
| K1 | Simulated execution only: no real tool, email or file action | **Open** | No | The beta validates decisions and approvals, not real actions | **Condition:** no real tool execution | Real execution is out of scope | | | |
| K2 | Single process, single machine, single Windows account; no TLS; loopback only | **Open** | No | No multi-user or remote access | **Condition:** one Windows 11 machine, loopback only | Out of scope | | | |
| K3 | The model is a mock by default; live model use was not exercised | **Open** | No | Model-assisted analysis is not validated | **Condition:** MOCK mode, live OFF (verified in A11 and `/api/model/status`) | Separate authorization needed | | | |
| K4 | Backups are offline and manual; no off-machine copy unless made by hand | **Open** | No | Data since the last backup can be lost; one disk only (GB-2) | **Condition:** an offline backup daily, copied to another disk | — | | | |
| K5 | Website scanning is off by default and was not assessed | **Open** | No | Not validated | **Condition:** keep scanning off | — | | | |

### 3.3 Security residual risks (beta-readiness.md)

| Id | Risk | Status | Blocking | Impact | Mitigation / operating condition | Follow-up | Decision (ACCEPT / REJECT) | Owner | Date |
|---|---|---|---|---|---|---|---|---|---|
| R1 | Same-account trust: anyone controlling the operator's Windows account, or an administrator, can read and rewrite the stores, backups, credential store and API token; the integrity chains detect only accidental or unsophisticated damage | **Open** | No | A compromised account compromises AgentShield | **Condition:** a dedicated, trusted Windows account; restricted access to the machine | Tamper evidence needs a new trust boundary (E13 report) | | | |
| R2 | The API token keeps the profile's default ACL | **Open** | No | Other processes of the same account can read it | **Condition:** single trusted account | Restrict the token file (later phase) | | | |
| R3 | Restoring an old credential store undoes later revocations | **Open** | No | A revoked credential could become valid again | `--restore-credentials` is never used without review; Gate B did not use it | **Condition:** after any credential restore, review `agent-credential list` and revoke again | | | |
| R4 | Prompt-injection detection is pattern-based; novel phrasings may be missed | **Open** | No | An injection may not escalate to CONFIRM | Policy enforcement and operator approval remain the controlling defences | Track misses during the beta (exit criteria) | | | |
| R5 | The secret-scanning hook can be bypassed (`--no-verify`); there is no CI | **Open** | No | A secret could be committed | **Condition:** never use `--no-verify`; run `npm run security:verify` before any push | CI (later phase) | | | |
| R6 | If both the approval journal and the audit log are lost, approval ids can restart and recent idempotency keys are unknown | **Open** | No | A retried request could be evaluated twice; ids could repeat | **Condition:** daily backups (K4) | — | | | |

### 3.4 Findings from the E16–E17 gate runs

| Id | Severity | Finding | Status | Blocking | Impact | Mitigation / operating condition | Follow-up | Decision (ACCEPT / REJECT / CONFIRM FIX) | Owner | Date |
|---|---|---|---|---|---|---|---|---|---|---|
| GA-1 | High (invalidated the first Gate A run) | The beta API process was three days old and predated agent identity and the durable stores | Resolved | No | A6 failed; durability did not apply | API restarted on the current build; regression test `attribution.test.ts` | See O3 (restart after code changes) | | | |
| GA-2 | Medium | Activity & Audit said events were in memory and reset on restart | Fixed | No | Misled operators about audit persistence | Wording corrected; pinned in a test | — | | | |
| GA-3 | Low | An operator's decision on an agent approval was labelled "scenario as …" | Fixed | No | Misleading attribution | Worded apart; unit test | — | | | |
| GA-4 | Low | Badge rows clipped content at 375 px | Fixed | No | Hidden policy and decision details on narrow screens | Rows wrap; pinned in a test; A15 PASS | — | | | |
| GA-5 | Info | No build or version visible on `/health` | **Open** | No | A stale process is hard to detect from outside (it caused GA-1) | **Condition:** after any code change, run `npm run build` and restart the API (README, "Two ways to start the same API") | Add build information to `/health` (later phase) | | | |
| GA-6 | Info | The sign-in screen suggests `npm run start -w @agentshield/api`, the README and dashboard banner `npm run dev:api` | Fixed (documentation, E17 sign-off preparation) | No | Confusion about how to start the API | The README and troubleshooting.md now document both commands and when to use each. The sign-in text itself is unchanged (a UI change, out of scope). | Optionally align the sign-in text (later phase) | | | |
| GB-1 | Medium | The expiry sweep did not record EXPIRED events durably, so every restart wrote them again | Fixed (`9228d8b`, regression test) | No | Duplicate EXPIRED audit records; nothing ran and no status changed | Live API runs the fix since B8. **One residual duplicate is still to come:** the live journal lacks `expiry-recorded` for `apr-2`. The first approvals listing or decision will write `apr-2`'s EXPIRED event once more, then record it. It will also expire `apr-4` (its first, legitimate EXPIRED event). Status checked read-only on 2026-11-02 at 22:32: not yet occurred. | Note the duplicate when it appears (expected, once); no deletion of audit records | | | |
| GB-2 | Low | One disk only: the backup, scratch folder and live stores share C: | **Open** | No | The drill proves the procedure, not recovery from losing the disk | **Condition:** copy each backup to another disk when one is available | Rerun B3 and B10 with a second disk | | | |
| GB-3 | Info | The replay `recovering` warning lasts only the 30 s skew window | Fixed (checklist B7b) | No | — | — | — | | | |
| GB-4 | Info | A console Ctrl+C does not stop an API started hidden by automation | **Open** | No | Automation must stop such a process directly | Operators' own terminals are unaffected | — | | | |
| O1 | Info | A14 and A15 were judged by automation (headless; A15 in mobile emulation) | **Open** | No | Visual quality not judged by a person | — | **Action:** a person looks at the dashboard on a real screen and in a narrow window or on a device | | | |
| O2 | Info | A7 and the approval half of A8 rest on the operator's text report, without screenshot file names | **Open** | No | Weaker evidence trail for those two checks | Cross-checked with the CLI and the API | Optionally attach screenshots | | | |
| O3 | Info | The live API now runs in a window opened by automation ("AgentShield API (live)", PID 24008) | **Open** | No | It may not outlive the Claude Code session | **Condition:** the operator owns it; if it stops, restart it in their own terminal with `npm run start -w @agentshield/api` and `AGENT_POLICY_FILE` unset | — | | | |

## 4. Final decision

**Decision rules (E16, beta-gate-checklist.md):**

| Decision | Requires |
|---|---|
| **GO** | Gates A, B and C are all PASS; no finding is blocking; every open finding has a recorded decision; the residual risks are acknowledged |
| **CONDITIONAL GO** | Gates A, B and C are all PASS, and only explicitly accepted, non-blocking limitations remain. Each is listed by id, with its condition and who accepted it. |
| **NO-GO** | Any mandatory gate FAIL or NOT RUN, or a serious security or recovery issue remains |

**Preparation recommendation:** CONDITIONAL GO. The gates pass, and the open items above are non-blocking
limitations with defined conditions. **This is a recommendation, not a decision.**

**Before day one** (from beta-readiness.md and the register):
- run `npm audit` with network access (I4);
- a human visual check of the dashboard (O1);
- delete the `%TEMP%\agentshield-*` leftovers (L6);
- set up a second disk for backups if possible (GB-2).

| Field | Entry |
|---|---|
| Decision (GO / CONDITIONAL GO / NO-GO) | |
| Accepted limitations (ids, each with its condition) | |
| Rejected items (ids) and the required fix and re-run | |
| Beta operating conditions adopted (beta-readiness.md, "Recommended beta operating conditions") | |
| Decided by (operator: name, role, date) | |
| Reviewed by (independent reviewer: name, role, date) | |

**E18 must not start until this section and the gate sign-offs in section 2 are completed.**
