# Durable replay protection and evaluation idempotency (M3-E E11)

Two related guarantees for signed agent requests:

- **Replay protection survives restarts.** A signed request that was accepted once is never
  accepted again, even after the API restarts.
- **Evaluations can be retried safely.** If an evaluation's response is lost, the agent can retry
  it with the same idempotency key. AgentShield returns the original result instead of
  evaluating, and possibly executing, again.

The signed-request protocol and credential formats are unchanged. Scope: the single-process
local prototype.

## What was there before (E11 audit)

**The verification order** (`apps/api/src/agents/signature.ts`):
1. header;
2. start-up fence (`ts < startedAt` refused);
3. ±30 s skew;
4. body, host and canonical request;
5. key;
6. Ed25519 verification;
7. the in-memory replay cache (`expiresAt = ts + skew`; 600 live nonces per key, 100,000 in
   total; never evicting a live nonce);
8. 401, or 429/503 from the cache limits.

**The cross-restart gap** (E9 finding L5). Request R is accepted by the old process at time t0
with `ts > t0`, because the agent's clock is ahead by up to the skew. If the API restarts at
S with `t0 < S ≤ ts`:
- the fence passes (`ts ≥ S`);
- the new process's cache is empty;
- so a replay of R arriving while `ts ≥ now − skew` is accepted once more.

The test suite reproduces this with the old in-memory cache.

**The audit log does not help.** It records events, not nonces. It has a different retention
model, and it cannot be the source of truth for replay decisions. It is not reused.

**Evaluations were not idempotent.** After a timeout or lost response, the agent could not tell
whether its evaluation had run, and a resend could run it twice.

## Replay protection

**Design.** The in-memory cache still decides, with unchanged limits. A dedicated durable
journal (`apps/api/src/agents/durable-nonce-cache.ts`, on `apps/api/src/storage/journal.ts`)
records every accepted nonce:

```text
n1 <keyId> <nonce> <expiresAt ms>
r1 <until ms>                         a recovery window still in force (see below)
```

**Data flow:** signature valid → cache accepts → **append and fsync the record** → only then
does the request continue to the route. At start-up, the live records (`expiresAt ≥ now`)
are loaded back into the cache.

**Guarantees:**
- **Accepted means recorded.** A nonce accepted before a restart is still known after it, until
  its timestamp leaves the skew window.
- **Nothing is evicted.** Live records are never dropped. The cache's limits apply exactly as
  before.
- **A write failure fails closed.** If the record cannot be written (disk full, I/O error, full
  journal), the request is refused with **503** and is not processed. The journal then stops
  accepting writes, so every signed request gets 503 until the API is restarted with working
  storage. Operator routes are unaffected.

**Recovery fallback.** Replay state may be incomplete at start-up in three cases:
- the journal is new, or was deleted;
- a record is unreadable;
- a loaded nonce no longer fits the limits.

In any of these cases, every signed request with a timestamp up to **start-up time + skew**
is refused with **503** (log `reason=replay-recovering`) until that moment passes.
- **Why this is enough:** anything a previous process accepted had a timestamp at most its
  clock + skew, so at most this bound.
- **Agents signing after that moment** are unaffected.
- **The window is recorded** in the journal (`r1`), so a restart inside it keeps it.
- **Unreadable lines are dropped** in the same atomic rewrite, so they do not reopen the window
  at every start.

**Crash safety.**
- **A record cut short by a crash** belongs to a request that never proceeded, because the
  write completes before a request continues. It is kept as a separate, ignored line and
  needs no fallback.
- **Compaction** rewrites the journal to its live records through a restricted temporary file
  that is fsynced and renamed over the old one. It happens when the journal reaches 1 MiB,
  or twice its last compacted size. A crash leaves the old file or the new one.

**Bounds.** The cache limits cap live records at 100,000. The journal never exceeds 32 MiB;
an append that cannot fit is refused (503).

**File safety:**
- the path is absolute;
- a symlink, junction or non-regular file is refused;
- the file is created restricted to the current user;
- one writer only (a lock file holding the process id).

**Location.** `REPLAY_STORE_FILE`, default `%LOCALAPPDATA%\AgentShield\replay-nonces.journal`.
Nonces and key ids are not secrets.

## Evaluation idempotency

### Contract

**The key.** An agent may put `idempotencyKey` in the body of `POST /api/evaluate`:
- 16 to 64 base64url characters;
- the SDK sends a fresh 22-character, 128-bit key with every evaluation;
- because the key is in the body, the request signature covers it, so it cannot be changed in
  transit.

The key is **scoped to the authenticated agent**: records are keyed by agent id and key. It is
**bound to the request's content**: a SHA-256 of the canonical JSON (sorted keys) of `agentId`,
`intent`, `action` and `untrustedContent`.

| Situation | Answer | Evaluated again? |
|---|---|---|
| A new key | Evaluated normally. A "started" record is stored durably **before** the evaluation runs; the result is stored after. | n/a |
| Same agent, key and request; the result is stored | The stored result, with `idempotentReplay: true` (status 200, or the stored 503 `approval-queue-full`). A CONFIRM returns the **original** approval reference (`id`, `createdAt`). | **No** |
| Same key, different request | `409 idempotency-key-reused` | No |
| A duplicate while the first is still running | Waits for the first, and returns its result | No: one evaluation per key |
| Started but never completed (the API stopped mid-evaluation, or the evaluation failed, for example an audit write) | `409 idempotency-outcome-unknown` | **No**, never repeated |
| The same key from another agent | That agent's own, independent record | n/a |
| After the retention period (15 minutes from the start) | The key is new again | Yes, as a new evaluation |

**What a replay contains.** It returns the decision fields (`evaluation`, `executed`,
`execution`, `pendingApproval`). It omits the original `event` and `modelAnalysis`.

**No bypass.** Authentication, the identity check, request validation, the audit readiness
check and rate limits all run first. A revoked credential gets 401 on a retry. Another
credential of the same agent gets the replay. An approval still rechecks the current
credential and policy when it is approved.

**A replay is a report.** It never executes anything. Since M3-E E12 the referenced approval
survives restarts and stays readable by its agent while the idempotency record lives
(finished approvals younger than 15 minutes are not evicted). If it is missing or was
quarantined, the agent sees `404` or `OUTCOME_UNKNOWN` ([approval-persistence.md](approval-persistence.md)).

### Storage

**The journal.** A durable journal (`apps/api/src/idempotency.ts`) holds JSON records:
- "started" (`t:"b"`);
- "completed" (`t:"c"`, with the stored result);
- a recovery marker (`t:"r"`).

**Location.** `IDEMPOTENCY_STORE_FILE`, default
`%LOCALAPPDATA%\AgentShield\idempotency.journal`, restricted to the current user.

**What it holds.** The stored results contain the evaluation, including redacted finding
evidence, so treat the file like the audit log.

**Limits:**
- retention: 15 minutes from the start;
- at most 1,000 live keys per agent and 10,000 in total;
- completed results up to 16 KiB;
- the journal is compacted at 4 MiB (or twice its last size) and never exceeds 192 MiB.

**Never evicted.** Live records are never evicted to make room. At a limit, new keys get
`503 idempotency-capacity` until records expire; existing keys still replay. A result larger
than 16 KiB is not stored, so a retry gets `outcome-unknown`.

**Failures.**
- If the "started" record cannot be written, the request is refused (`503
  idempotency-unavailable`) before evaluating. Later idempotent evaluations are refused too,
  until a restart. Requests without a key are unaffected.
- If the "completed" record cannot be written, the response is still returned (it is
  accurate), and a later retry gets `outcome-unknown`.

**Crash and corruption.**
- **A "started" record cut short by a crash** belongs to an evaluation that never ran: skipped.
- **A crash after "started"** leaves the key outcome-unknown.
- **An unreadable record** could have been a key's "started" record. For the retention period
  after such a start, keys without a record are refused (`503 idempotency-unavailable`)
  rather than possibly run twice. The window is recorded, and unreadable lines are dropped.

### SDK contract (`@agentshield/agent-sdk`)

- **`evaluate(request, { idempotencyKey? })`.** Without a key, the SDK creates a new one for this
  logical evaluation. Pass a key only to retry the **same** evaluation (the same request).
- **The result** carries `idempotencyKey` and `idempotentReplay`.
- **Every evaluate error** carries `details.idempotencyKey`.
- **409 is a `ConflictError`** with the server's `reason`.
- **Unchanged:**
  - every HTTP attempt is freshly signed, with a new timestamp and nonce;
  - GET retries stay bounded;
  - **`evaluate` is still never retried automatically**, so the SDK never sends a second attempt
    on its own, with or without a key.

**What the SDK can determine after a timeout:** nothing about the outcome. The evaluation may
not have arrived, may be running, or may have completed. What it does know is the key it sent.

**The safe way to find out:** retry with `error.details.idempotencyKey` and the same request.
The outcome is then exactly one of:
- the original result (`idempotentReplay: true`);
- a first evaluation, if the first attempt never arrived;
- `409 idempotency-outcome-unknown`, if the first attempt started but its result was lost.

**Never retry with a new key** after an ambiguous failure; that is a new evaluation.

## Residual risks

- **Several processes.** One process per store (lock file). Several API processes using
  different store paths would each have their own replay and idempotency state.
- **Deleting a store while the API is stopped.**
  - For the replay journal, the recovery fence covers it.
  - For the idempotency journal: since M3-E E14, when the audit log has history, the new journal
    applies the 15-minute recovery window, so no key is evaluated as new
    (`idempotency-store status=warning reason=journal-missing-but-audit-log-has-history`). Without
    the audit log, retries within 15 minutes of the deletion may run again. Do not delete it.
- **Backups never restore replay or idempotency state** (M3-E E14): an old copy would forget requests
  accepted since, and could let them run again. See [operations.md](operations.md).
- **A journal of a newer format** stops start-up and is left untouched (M3-E E14).
- **Storage that ignores fsync** can lose the latest records after a power failure. For replay
  protection, the start-up fence still refuses anything signed before the restart; the
  future-dated window is open only for records actually lost.
- **No tamper protection.** Since M3-E E13 the journals carry an integrity chain: damaged or
  edited records trigger the recovery fence (replay) or make their keys outcome-unknown
  (idempotency), see [storage-integrity.md](storage-integrity.md). But a local user who recomputes the chain, or removes whole records
  from the end, is not detected: they can still remove records (allowing a
  replay or a re-run) or add them (refusing requests). The files are restricted to the current
  user, the same trust level as the API token and credential store.
- **Clock changes.** The fallback uses the current skew. Raising
  `AGENT_SIGNATURE_MAX_SKEW_SECONDS` and deleting the replay journal in the same restart could
  leave a short window for requests accepted under the old skew.
- **Idempotency is opt-in for non-SDK clients.** Requests without a key behave as before (not
  idempotent).
- **Availability.**
  - A failed or full store refuses signed requests (replay) or idempotent evaluations (503)
    until an operator acts.
  - A new or recovering replay store refuses agent requests for up to the skew (30 s) after
    start.

## Verification

- `apps/api/src/agents/durable-nonce-cache.test.ts`
- `apps/api/src/agents/replay-restart.test.ts`. The future-dated replay across a restart,
  refused, with a control showing the old in-memory cache accepting it.
- `apps/api/src/idempotency.test.ts`
- `apps/api/src/agents/idempotency.routes.test.ts`. Including the SDK against a live loopback
  server: a lost response is recovered with the error's key, and the evaluation runs once.
- `packages/agent-sdk/src/client.test.ts`: the E11 tests.
- **Mutation checks:** disabling persistence, the recovery fence, write-failure handling, the
  recovery marker, deduplication, the conflict check, concurrency handling, outcome-unknown, or
  persisting "started" before evaluating, each fails the tests.
