# Persistent approval lifecycle (M3-E E12)

Since M3-E E12, approvals survive normal API restarts. A pending, approved, rejected or expired
approval keeps its id, timestamps and state, and is never revived, re-run or renumbered by a
restart.

Scope: the single-process local prototype.

## What was there before (E12 audit)

**Storage.** Approvals lived in an in-memory map, at most 500 records.
- Finished records were evicted oldest-first to make room. Pending ones were never evicted.

**Ids.** `apr-N` came from a counter that restarted at 1 with every process. Since E9, agents
bind to `createdAt` to detect reuse.

**State transitions** (`apps/api/src/approvals.ts`). Every transition starts from `PENDING`:
- `REJECTED`: the operator rejects.
- `EXPIRED`: lazily, on a read, approve or reject after 15 minutes.
- `BLOCKED_ON_RECHECK`: the operator approves, and the recheck blocks: credential, policy hash,
  or a full re-evaluation.
- `EXECUTED` or `APPROVED_NOT_EXECUTED`: the operator approves, the recheck passes, and the
  simulator runs (or has no handler).

**Approval and execution** happened together, in one synchronous step.

**After a restart, everything was lost.**
- Pending approvals vanished (agents saw 404).
- An E11 idempotency retry returned an approval reference that no longer existed.
- New approvals reused old ids.

## Design

**One authoritative store.** A dedicated approval journal: `apps/api/src/approval-journal.ts`,
on the E11 journal primitive. The audit log is not used for approval state.

**Location.** `APPROVAL_STORE_FILE`, default `%LOCALAPPDATA%\AgentShield\approvals.journal`.

**File safety.**
- The file is restricted to the current user and fsynced per record.
- Only one process may write it (a lock file).
- Symlinks and non-regular files are refused.

**Records**, one JSON object per line:

```text
{"v":1,"t":"create","r":{...the full server-side approval record...}}
{"v":1,"t":"approving","id":"apr-N"}            write-ahead: recheck passed, about to execute
{"v":1,"t":"to","id":"apr-N","s":"<final status>","e":{...}}
{"v":1,"t":"expiry-recorded","id":"apr-N"}      the EXPIRED audit event was written
{"v":1,"t":"seq","next":N}                      the next approval number
```

**Contents.** The `create` record holds what the recheck needs: the stored intent, the action,
the untrusted content, the policy reference and the requesting credential's key id. The file
is therefore as sensitive as the audit log, or more so; keep its default location.

### Transition semantics

Every change is written and fsynced **before** the in-memory record changes, and **before** any
response is sent.

| Operation | Durable step | If the write fails |
|---|---|---|
| Create, on CONFIRM | `create`, before the id is returned | `503 approval-store-full` or `approval-store-unavailable`: no approval is created, nothing runs, and a `CONFIRM_NOT_QUEUED` event is recorded. The id is skipped for the rest of the process; it was never returned to anyone. |
| Reject | `to REJECTED`, before `200` | `503`: nothing changes |
| Approve, recheck BLOCK | `to BLOCKED_ON_RECHECK`, before `409` | `503`: nothing changes |
| Approve, recheck passes | 1. `approving` (write-ahead); 2. the simulator runs; 3. `to EXECUTED` or `APPROVED_NOT_EXECUTED`, before `200` | Step 1 fails: `503`, nothing runs. Step 3 fails: the action did run, so the answer is **`500 approval-store-write-failed`**, never success. After a restart the approval is `OUTCOME_UNKNOWN`. |
| Expire | `to EXPIRED` | Logged. Expiry follows from `expiresAt`, so the approval is expired regardless and can never be approved. |

**Further rules:**
- **Only one way out of PENDING.** Only `PENDING → final` transitions exist, so a final decision
  can never change. On recovery, a later journal line claiming otherwise is ignored, and counted
  as corrupt.
- **Every check still runs.** The authenticated operator, the active requesting credential, the
  current policy and its hash, and a full re-evaluation are all checked **at decision time**,
  exactly as before. A recovered approval is just a pending approval; nothing is approved or
  executed because of recovery.
- **One decision per approval.** Concurrent decisions are serialised (synchronous handlers), so
  exactly one wins and the rest get `409`.
- **Store failure blocks decisions.** While the store is failed, approve and reject are refused
  up front (`503`). Reads keep working.

### Why approved does not mean executed

An approval is a decision to run, made under the conditions current at that moment. The action
ran only if the status is `EXECUTED` with `executed: true`. Other outcomes of an approve:
- `BLOCKED_ON_RECHECK`: the conditions changed;
- `APPROVED_NOT_EXECUTED`: no handler for the action type;
- `OUTCOME_UNKNOWN`: interrupted, so whether it ran is unknown.

A recovered approval is never executed automatically.

### `OUTCOME_UNKNOWN` (a new final status)

At start-up, an approval becomes `OUTCOME_UNKNOWN` in two cases:
- **interrupted:** its `approving` record has no outcome after it (the API stopped while the
  approved action was running);
- **quarantined:** a damaged journal record may have held its decision.

**What it means:** it never runs, it cannot be approved or rejected (`409`), and it is never
reported as executed (`executed: false`, meaning "not known to have run").
- The SDK accepts the status.
- The reference agent reports it as unconfirmed (`approval-outcome-unknown`) and saves nothing.
- An operator should check what happened.

## Recovery at start-up

| Found | Result |
|---|---|
| Valid records | Rebuilt in order: same ids, timestamps and states. Ids continue after the highest ever used, so they are never reused. |
| A final record cut short by a crash | Ignored. Its write did not complete, so the step it records never took effect: an id never returned, a decision never reported, or an action never started. |
| `approving` with no outcome | `OUTCOME_UNKNOWN` (interrupted) |
| A damaged or invalid line | Counted. Every PENDING approval it names (`apr-N` anywhere in it) becomes `OUTCOME_UNKNOWN`. If it names none, **every** PENDING approval does, because a lost rejection must never be undone by a restart. Ids it names are reserved. |
| A PENDING approval past `expiresAt` | Expired on the next access, as usual, with its `EXPIRED` event written once |
| An `EXPIRED` approval whose event was not recorded | Its event is written on the next sweep |

**After any recovery** the journal is rewritten atomically to the recovered state, so damaged
lines are not read again. Start-up logs a summary (`approval-store status=...`).

**What stops start-up** (`agent-state status=invalid-config`): a store that cannot be opened
safely (symlink, permissions, locked by another API, over the limit).

## Limits and full storage

**The 500-record limit is unchanged.** Pending approvals are never evicted.

**Retention.** Since E12, finished approvals younger than 15 minutes (the idempotency
retention) are also kept. An approval that a live idempotency record refers to therefore stays
readable, and a CONFIRM gets `503 approval-queue-full` instead of evicting it. The in-memory
store used by tests keeps the old behaviour.

**File size.** The journal is compacted to the live records (a snapshot plus `seq`) at 8 MiB,
or twice its last size, and never exceeds 256 MiB. If it is still full after compaction, the
answer is `503 approval-store-full`.

## Integration

**Idempotency (E11).**
- A retry with the same key returns the original approval reference (`id`, `createdAt`), and
  that approval is now still readable after a restart, by its own agent only.
- Another agent gets `404`.
- Another request with the same key gets `409`.
- An expired idempotency record means a new evaluation and a new approval. The old approval
  stays as it was (for example `EXPIRED`); it is never revived.
- If the referenced approval is missing (evicted after its retention) or quarantined, the agent
  sees `404` or `OUTCOME_UNKNOWN`. No approval is created silently.

**Audit (E10).**
- **Events are written after the durable transition.** If the audit write fails, the request
  answers `500 audit-write-failed`, but the decision itself is already durable. An executed
  approval stays `EXECUTED` and cannot run again.
- **The audit readiness check** still runs before any decision.

**Agents and the SDK.**
- The six-field view, the uniform 404 and pagination are unchanged.
- `OUTCOME_UNKNOWN` is a new status value.
- Ids no longer restart, but binding to `createdAt` (E9) remains good practice, for example if
  the store was deleted.

## What still needs an operator

- **`OUTCOME_UNKNOWN` approvals:** find out whether the action took effect.
- **A failed or full store:** fix the cause and restart. While it is failed, approvals cannot be
  created or decided.
- **Deleting or editing the journal while the API runs:** never do either. Deleting it while the
  API is stopped loses every approval. Since M3-E E14, ids continue after every id the audit log
  names (`approval-store status=recovered reason=ids-continue-after-audit-log`). Without the audit
  log, ids restart; agents bound to `createdAt` detect this.
- **Restoring from a backup** (M3-E E14, [operations.md](operations.md)): the restore appends a
  `{"v":1,"t":"restored","next":N}` record. At the next start, every approval that was pending in the
  backup becomes `OUTCOME_UNKNOWN` (it may have been decided after the backup), and ids continue at
  `apr-N`. An older AgentShield reads the record as damage naming no approval, which quarantines
  every pending approval as well.
- **A journal of a newer format** (a record with `"v"` above 1) stops start-up and is left untouched.

## Residual risks

- **No tamper protection.** Since M3-E E13 the journal carries an integrity chain: a modified,
  deleted, inserted or reordered record quarantines the pending approvals it names
  (`OUTCOME_UNKNOWN`, never executable), and the damaged file is preserved ([storage-integrity.md](storage-integrity.md)). A local user who
  recomputes the chain can still forge or remove records undetected.
- **Storage that ignores fsync** can lose the latest transition after a power failure. The
  write-ahead record means an approval that was running then becomes `OUTCOME_UNKNOWN`, not
  `PENDING`.
- **Quarantine is conservative.** A damaged line naming no approval marks every pending approval
  `OUTCOME_UNKNOWN`.
- **Single process.** Several API processes need separate stores, and do not share approvals.
- **Expiry is lazy.** An approval past its expiry is reported `EXPIRED` on the next access, not at
  the exact instant.

## Verification

- `apps/api/src/approval-journal.test.ts`: the store on its own.
- `apps/api/src/agents/approvals-restart.test.ts`: the required scenarios through the real API,
  including interrupted approvals, damaged and truncated records, full and unavailable storage,
  an outcome that ran but could not be stored, and an audit failure during approval.
- Mutation checks: disabling persistence of creation or rejection, the write-ahead record,
  interrupted-approval recovery, final-state protection, quarantine, retention, or the 500 on
  a non-durable outcome, each fails the tests.
