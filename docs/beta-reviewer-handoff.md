# Independent reviewer handoff (M3-E E17)

**Who this is for.** The independent reviewer of AgentShield's controlled-beta gates.

**Who may act as reviewer.** Someone who **did not run the gates**. The operator and the automation
(Claude Code) that ran them cannot review them.

**What is asked.** Check that each gate's recorded result is supported by its evidence. Then sign
section 2 and section 4 of [beta-signoff.md](beta-signoff.md), or record why you cannot.

**Read-only.** Nothing here asks you to start, stop or change anything.

## 1. Documents to read

| Document | What it gives you |
|---|---|
| [beta-gate-checklist.md](beta-gate-checklist.md) | Each gate's steps, expected results, stop conditions and the decision rules |
| [beta-gate-evidence.md](beta-gate-evidence.md) | What was run, by whom, the result of every check, the findings and their fixes |
| [beta-signoff.md](beta-signoff.md) | The gate sign-offs, the risk register (section 3), the pre-beta verification (section 5), the operator decision sheet (section 6) and the visual review checklist (section 7) |
| [beta-readiness.md](beta-readiness.md) | The E15 assessment the gates close (findings, limitations, residual risks) |

## 2. Evidence locations

**Evidence folder:** `C:\Users\abhik\OneDrive\Desktop\Muse Ai\AgentShield-gate-evidence\`, beside the
repository.

| Folder | Contents | Supports |
|---|---|---|
| `2026-11-02-gate-a\` | The first real-browser run, on an isolated instance of the current build (36 files) | Gate A findings GA-2 to GA-4 and their fixes |
| `2026-11-02-gate-a-beta-installation\` | The Gate A re-run on the beta installation (35 files: screenshots A1–A15, `A10-events.txt`, `A8-agent-reject.txt`, `A16-cleanup.txt`, `gate-a-live-results.json`) | A1–A8, A10–A16 |
| `2026-11-02-gate-b\` | The recovery drill (16 files: `B0-B1-verification.txt`, `B2-status.txt` to `B9-live-status.txt`, `B6b-recheck.txt`, `B7-scratch-api.*.log`, `B7a-A9-outcome-unknown.png`, `B7a-A9-result.json`, `B7b-storage-health.json`, `B8-live-api.log`, `C2-scratch-status-while-running.txt`) | B0–B10, A9, C1–C4 |
| `2026-11-02-pre-beta\` | Pre-beta verification (41 files: `I4-npm-audit.txt`, `GB-1-*.txt`, `L6-temp-cleanup.txt`, `config-checks.txt`, `file-permissions.txt`, `R2-*.txt`, `R2-folder-acl-*.icacls`, `O3-live-status-after-abrupt-end.txt`, `O1-isolated\`) | I4, GB-1, L6, R2, O1, O3 |

**Retained recovery data** (do not modify):
- the backup `C:\AgentShieldBackups\2026-11-02` (id `d4b8bf8a76bfdde4`, 6 files);
- the drill's scratch copy `C:\AgentShieldDrill\2026-11-02\state` (8 entries).

**Code changes** (local Git history, branch `master`, not pushed), from `git log --oneline 3547d81..HEAD`:
- `129fe5c`: new API token files restricted (R2);
- `9228d8b`: expiry events recorded durably (GB-1);
- `894ab12`: dashboard fixes (GA-2 to GA-4) and the attribution regression test (GA-1);
- the other commits are documentation.

## 3. Suggested checks

1. **Gate A:** compare each row of the Gate A table in beta-gate-evidence.md with its screenshot or file.
   Pay particular attention to:
   - A6 and A7: "Requested by" text;
   - A9: `OUTCOME_UNKNOWN`, in amber, with the reason, and no buttons;
   - A15: the narrow layout.
2. **Gate B:**
   - check that B6's plan never restored replay or idempotency records or credentials;
   - check that B6b and `B6b-recheck.txt` show all five paths inside the scratch folder;
   - check that B8's log shows no `restored=` or `recovering` for the live API;
   - check that B9's store sizes equal B2's.
3. **Gate C:** compare C1–C4 with the outputs they reference, including exit codes; ATTENTION with exit 1
   is expected where noted.
4. **Findings:** check that GA-1 and GB-1 were fixed and re-verified, and that every open item in
   section 3 of beta-signoff.md has a decision before you sign.
5. **Optional:** run `npm test` and `npm run security:verify` in the repository to reproduce the automated
   results (last recorded: 2,352 tests passing).

## 4. Sign-off

Sign in [beta-signoff.md](beta-signoff.md):
- section 2: each gate, reviewer column;
- section 4: "Reviewed by".

If you find a discrepancy, record it there instead of signing; the affected gate is then not PASS until it
is resolved and re-run.
