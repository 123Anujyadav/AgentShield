# Operating AgentShield: storage, backup and recovery (M3-E E14)

This guide is for the operator of the local, single-process AgentShield API. It covers:
- where state is kept;
- how to watch its capacity and health;
- how to back it up and restore it;
- what to do after a crash, a full disk, or a lost file.

Everything here runs on one machine, as one Windows account. Nothing is replicated or sent anywhere.

> **A normal restart is not a restore.** Restarting the API, after a clean stop or a crash, needs no
> action: every store recovers itself at start-up, fail-safe (see [Recovery after a crash](#recovery-after-a-crash)).
> **Restoring a backup** puts *older* state back. Only do it when a store is lost or unusable, and read
> [What a restore does](#what-a-restore-does) first.

## Storage inventory

**Default location.** Every store defaults to `%LOCALAPPDATA%\AgentShield\`. Each path can be moved
with an environment variable, which must be an absolute path.

**Persistent stores (backed up):**

| Store | Location (default file, variable) | Format and version | Maximum size and limits | Retention |
|---|---|---|---|---|
| Audit log | `audit-events.jsonl`, `AUDIT_LOG_FILE` | JSON Lines, record v2 with an integrity chain; v1 accepted as a legacy prefix | `AUDIT_LOG_MAX_BYTES`: 64 MiB by default, 1 MiB to 1 GiB; at most 256 KiB per record | Everything, until the operator archives the file. Never deleted or rotated automatically. |
| Approval journal | `approvals.journal`, `APPROVAL_STORE_FILE` | Chained journal, JSON records v1 | 256 MiB, compacted at 8 MiB; 500 approvals, 100 pending per agent; 128 KiB per record | Pending and recent approvals. Finished ones are evicted at the 500 limit, never before they are 15 minutes old. |
| Idempotency journal | `idempotency.journal`, `IDEMPOTENCY_STORE_FILE` | Chained journal, JSON records v1 | 192 MiB, compacted at 4 MiB; 10,000 keys, 1,000 per agent; 16 KiB per stored result | 15 minutes per key |
| Replay journal | `replay-nonces.journal`, `REPLAY_STORE_FILE` | Chained journal, text records `n1`/`r1` | 32 MiB, compacted at 1 MiB; 100,000 nonces, 600 per key | Until each signed request's validity window ends (seconds to minutes) |
| Agent credential store | `agent-credentials.json`, `AGENT_CREDENTIAL_FILE` | JSON document, `schemaVersion` 2 (1 is read) | 256 KiB; 1,000 credentials, 4 active per agent | Until revoked or expired; revoked records are kept |

**Integrity, recovery, backup, and what losing each one means:**

| Store | Integrity checks | Recovery | Backup | If the file is lost |
|---|---|---|---|---|
| Audit log | SHA-256 per event, plus the `prev` chain (corruption detection) | Unverified or damaged lines are kept in the file, left out of the view, and reported | **Yes**: restorable | Activity history is gone. New ids start again at `evt-1`. |
| Approval journal | Chain on every record | Damaged or interrupted approvals become `OUTCOME_UNKNOWN`; the damaged file is preserved | **Yes**: restorable | Approvals are gone. Since E14, ids still continue after every id the audit log names. |
| Idempotency journal | Chain | Unverified keys become outcome-unknown, with a 15-minute window | Copied for investigation; **never restored** | Since E14: if the audit log has history, new keys are refused for 15 minutes, so nothing is evaluated twice |
| Replay journal | Chain | Startup fence | Copied for investigation; **never restored** | The next start refuses every signed request dated before it (the fence), so nothing can be replayed |
| Agent credential store | Schema validation; reloaded within 2 s of a change | An invalid file rejects every agent credential (fail closed) | **Yes**: restorable, only when asked | No agent can authenticate until credentials are re-issued or restored |

The store files hold no private keys, raw credentials or tokens. The approval and audit records hold
the redacted request metadata the dashboard shows.

**Configuration and secrets (not backed up by the tool):**

| Item | Location | Notes |
|---|---|---|
| **API token** | `%LOCALAPPDATA%\AgentShield\api-token` | A secret. **Never backed up** by the tool. If it is lost, the API creates a new one at start; sign in to the dashboard with it again. |
| **Policy file** | `AGENT_POLICY_FILE`, optional; only the built-in demo policy when unset | At most 256 KiB and 200 policies. Read once at start-up; an invalid file stops start-up. Keep it with your configuration (for example in version control). |
| **Operator sessions** | Memory only | Lost at every restart: sign in again. |

**Files that appear next to the stores:**

| File | Meaning |
|---|---|
| `<store>.lock` | The single-writer lock (the API's process id). See [Lock files](#lock-files). |
| `<store>.damaged-<time>` | E13: a damaged journal preserved before recovery. Keep it for investigation. |
| `<store>.restoring` | E14: a restore is in progress, or was interrupted. The API refuses to start until it completes. |
| `<store>.before-restore-<time>` | E14: a damaged store copied aside by `restore --replace-damaged`. |

All of these files, and every backup, are created restricted to your Windows account: a single ACL
entry, or mode 0600.

## Watching storage health

**From the terminal, at any time.** This is read-only and safe while the API runs:

```powershell
npm run ops -- status
```

For each store it prints:
- size against its limit;
- lock owner;
- integrity status, with counts only;
- an interrupted-restore marker, and permissions.

It exits with 1 when something needs attention:
- damage, or an unsupported version;
- an interrupted restore;
- loose permissions;
- a store at 80% or more of its limit;
- (M3-E E15) a store missing while another store holds records, which means it was lost or deleted.
  A fresh installation, with no stores yet, is ok. A record being appended at that
moment may show as `truncated-final-record`; that is normal.

**From the API (operator only).** `GET /api/storage/health` returns:
- for each store: bytes, maximum, remaining bytes and percentage used;
- entries against their limit (approvals, idempotency keys, nonces);
- whether the store is writable and still holds its lock;
- what start-up recovery found;
- the overall level.

It contains numbers and fixed codes only, never a path, a file name or a record. Agents get `403`.

```powershell
$token = Get-Content -Raw "$env:LOCALAPPDATA\AgentShield\api-token"
Invoke-RestMethod http://127.0.0.1:4000/api/storage/health -Headers @{ Authorization = "Bearer $($token.Trim())" }
```

**In the API's log.**
- At start-up, every store that is not `ok` is logged.
- After that, a line is logged whenever a store's level or warnings change (checked every minute):
  `storage store=<name> level=<level> bytesUsedPercent=… remainingBytes=… warnings=…`.

**Levels:**

| Level | Meaning | What to do |
|---|---|---|
| `ok` | Nothing to do | Nothing |
| `warning` | At least 80% of a size or entry limit, an integrity failure found at start-up, a recovery window in force, or permissions not restricted | Plan an archive, or investigate the integrity finding |
| `critical` | At least 95% of a limit, or full | Act now: [Disk-full handling](#disk-full-handling) |
| `failed` | A write failed, or the lock was lost: the store accepts no more writes until a restart | [Recovery after a crash](#recovery-after-a-crash) and [Lock files](#lock-files) |

**Warning codes:**

| Code | Meaning |
|---|---|
| `storage-full` | No room for another record (the audit log) |
| `bytes-above-warning`, `bytes-above-critical` | The file is at least 80% or 95% of its size limit |
| `entries-above-warning`, `entries-above-critical` | Live entries are at least 80% or 95% of their limit |
| `write-failed`, `lock-lost` | The store has stopped writing (fail closed) |
| `integrity-failure-at-startup` | Damaged or unverified records were found at start-up ([storage-integrity.md](storage-integrity.md)) |
| `recovering` | A recovery window is in force: replay protection is refusing signed requests dated before it, or idempotency is refusing new keys |
| `permissions-not-restricted` | Other accounts can read the file |
| `journal-missing-at-startup` | The idempotency journal was missing although the audit log has history |

These are informational and do not raise the level: `stale-lock-replaced-at-startup`,
`truncated-record-recovered-at-startup`, `migrated-at-startup`,
`approvals-made-outcome-unknown-at-startup`.

**Monitoring never deletes, rotates, compacts or archives anything.** Only the operator does.

## Backup

### Why backups are offline

The four stores are separate files, each written at its own moment, and AgentShield has no
consistent live snapshot. A copy taken while the API runs could mix moments, for example an
approval decision without its audit event.

So the tool takes a backup **only while the API is stopped**:
- it takes every store's lock for the whole copy, so it refuses if the API (or a credential command)
  is running;
- an API started during the backup refuses to open its stores.

### Procedure

1. Stop the API (Ctrl+C in its terminal).
2. Run the backup. The output directory must not exist yet. Without `--out`, it defaults to
   `%LOCALAPPDATA%\AgentShield\backups\backup-<time>`.

   ```powershell
   npm run ops -- backup --out D:\AgentShieldBackups\2026-11-01
   ```

3. Read the output. Every store is listed as copied or not present, and any store that failed its
   integrity check is listed as not restorable.
4. Start the API again.
5. Verify the backup, now or later. Verification changes nothing:

   ```powershell
   npm run ops -- verify-backup --dir D:\AgentShieldBackups\2026-11-01
   ```

6. Keep a copy **on another disk**. A backup in `%LOCALAPPDATA%` does not survive losing that disk.

### What a backup contains

- The five store files, byte for byte.
- `manifest.json`, written **last**. It holds:
  - the backup's id and time;
  - for each store: whether it was present, its size and SHA-256, its integrity status and record count;
  - whether it can be restored.

  It contains no paths and no record content.

**What it never contains:** the API token, the policy file, lock files, or `.env`.

**Restrictions.** The directory and every file in it are restricted to your Windows account.

**Detecting an incomplete or damaged backup.** `verify-backup` checks, without changing anything:

| Check | What it catches |
|---|---|
| The manifest is present | A backup with no manifest never finished |
| Each file's size and SHA-256 match the manifest | Truncation and modification |
| Each store's integrity chain verifies | Damage inside the copy |
| Record and backup-format versions are supported | A backup from a newer AgentShield |
| A temporary copy of the approval journal opens with the real store | Records the store would reject |

It warns about files that are readable by others, and about unexpected files.

### Retention

- Keep several generations, for example daily for a week and weekly for a month, on a disk other
  than the one the API uses.
- A backup holds the same data the dashboard shows. Protect it like the audit log: only you should
  be able to read it.
- Delete old backups yourself. The tool never deletes a backup.
- **Old backups are useful for history, not for restoring live security state.** Approvals pending
  in an old backup come back as `OUTCOME_UNKNOWN`, and an old credential store would undo later
  revocations (see below).

## Restore

### What a restore does

A restore **only fills in a store that is missing**, or, if you ask with `--replace-damaged`, one
whose integrity check fails. **A present, healthy store is always kept:** it holds newer state than
any backup, so the tool never replaces it, and has no option to.

| Store | When restored | How |
|---|---|---|
| **Audit log** | Missing, or damaged with `--replace-damaged` | Restored as backed up (verified). Events after the backup are not in it. |
| **Approval journal** | Missing, or damaged with `--replace-damaged` | Restored, plus a `restored` record. At the next start, every approval that was **pending** in the backup becomes **`OUTCOME_UNKNOWN`**: it may have been decided, or even executed, after the backup. It can never run. Decided approvals keep their decision. Ids continue after every id the backup, the replaced file and the audit log name, so an id is never reissued. |
| **Idempotency journal** | **Never restored** | An old idempotency record can make a retried request look new, or replay a stale result. If the journal is missing, a new one is created holding only a 15-minute recovery window: no key is evaluated as new until any key used since the backup has expired. |
| **Replay journal** | **Never restored** | An old nonce list would forget requests accepted after the backup, and those could be replayed. A missing journal is left missing; the next start then refuses every signed request dated before it (the fence). |
| **Credential store** | Missing, and only with `--restore-credentials` | An old copy brings back credentials **revoked since the backup**. After restoring, run `npm run agent-credential -w @agentshield/api -- list` and revoke again anything that should not be active. A present credential store is never replaced. |

**Security risks of restoring older replay or idempotency state.** This is why the tool never does it:
- **Replay:** requests accepted after the backup would be forgotten. Any of them still inside their
  validity window could be accepted a second time.
- **Idempotency:** a retried evaluation whose key was used after the backup could be evaluated, and
  executed, again. A stored result from the backup could also be returned for a request that later
  had a different outcome.

### Procedure

1. **Stop the API.**
2. **Verify the backup:** `npm run ops -- verify-backup --dir <backup>`.
3. **Check the current state:** `npm run ops -- status`. Decide whether a restore is needed at all.
   A damaged journal is usually better left to start-up recovery, which keeps every readable newer
   record.
4. **Restore:**

   ```powershell
   npm run ops -- restore --dir D:\AgentShieldBackups\2026-11-01
   # only if needed:  --replace-damaged   --restore-credentials
   ```

   The tool verifies the whole backup, takes every lock, and plans every store. It refuses before
   writing anything if:
   - the backup fails verification;
   - the API is running;
   - a damaged store needs `--replace-damaged`;
   - a store that must be restored has no usable copy.

   It then writes, in order:
   1. a `.restoring` marker next to each store it will write;
   2. copies of damaged stores, set aside (`.before-restore-<time>`);
   3. the stores, each atomically: audit log, approvals, idempotency window, credentials;
   4. after verifying each written file, it removes the markers.
5. **Start the API and read its start-up log.** Expect:
   - `approval-store status=recovered restored=N effect=pending-approvals-from-backup-marked-OUTCOME_UNKNOWN`;
   - `replay-store status=recovering …` (the fence);
   - `idempotency-store status=recovering …` (the 15-minute window);
   - `approval-store status=recovered reason=ids-continue-after-audit-log …` where it applies.
6. **Tell agents** that pending approvals from before the restore are `OUTCOME_UNKNOWN`. They can
   submit a new evaluation.

**When nothing needs restoring,** the tool reports that and writes nothing.

### An interrupted restore

If the restore stops part-way (a crash, power loss, or Ctrl+C), the `.restoring` markers stay. While
they do:
- **the API refuses to start:**
  `… status=invalid-config reason=A restore of the <store> was interrupted …`;
- `backup` refuses too.

**What happens to a store that is not restored yet:** it is never created empty in its place, which
would reuse approval ids.

**To finish, run the same restore again,** with the same backup. Stores already restored are
written again from the same backup.

**A different backup is refused** until the interrupted restore is completed.

## Recovery after a crash

A crash, power loss or forced stop needs **no restore**. Start the API. Each store recovers itself
at start-up and logs what it did:

| What the crash left | What start-up does |
|---|---|
| A lock file from the dead process | Replaced and reported (`status=warning reason=stale-lock-replaced`) |
| A record cut short | Ignored (it never took effect) and the journal rewritten; the audit log keeps it as a marked, skipped line |
| An approval being carried out | `OUTCOME_UNKNOWN`: it never runs again |
| Replay state | Fenced: signed requests dated before start-up + skew are refused (503, with Retry-After) |
| An idempotency key started but not completed | Its outcome is unknown, and it is not evaluated again |
| A compaction interrupted before its rename | The old journal is intact |

If start-up instead **refuses**, the log line says why. See [troubleshooting.md](troubleshooting.md).

## Disk-full handling

**When the disk itself is full.** Every write fails closed:
- requests that need to record something answer **503** (or `500 audit-write-failed` when the action
  already ran);
- the affected store stops writing until a restart;
- nothing is half-written as if it succeeded.

Free space, then restart the API.

**When the audit log is full** (`audit-storage-full`, level `critical`):
- evaluations, approvals and rejections are refused (503) **before anything runs**;
- reads keep working.

Archive the log ([below](#safe-archival-of-the-audit-log)), or raise `AUDIT_LOG_MAX_BYTES`
(up to 1 GiB) and restart.

**When a journal reaches its limit.** The journals compact themselves, so their files stay small.
Their real limits are entries:

| Store | What is refused at the limit | What frees room |
|---|---|---|
| Approvals | New approvals (`approval-store-full`, `CONFIRM_NOT_QUEUED`) | Decide pending approvals |
| Idempotency | New keys (`503 idempotency-capacity`) | Keys expire after 15 minutes |
| Replay | Signed requests from that key (429), or from every key at the global limit (503) | Nonces expire within minutes |

**Never delete a live journal to make room.** Deleting the replay or idempotency journal weakens
protection until the fence or window passes. Deleting the approval journal loses approvals.

## Safe archival of the audit log

1. Stop the API.
2. Take a backup: `npm run ops -- backup --out <dir>`. It includes the audit log, verified.
3. Move `audit-events.jsonl` to an archive location only you can read, or rely on the copy in the
   backup.
4. Start the API. It creates a new, empty audit log, and event ids start again at `evt-1`.

**What carries on.** Approval ids are unaffected: the approval journal keeps its own sequence.

**What to keep.** Archived logs are evidence. Keep them as long as your review needs them. A log with
integrity warnings should be kept unchanged.

## Lock files

**What a lock is.** Each store has `<store>.lock`, holding the process id of the API that writes it.
Only one process may write a store.

**How locks behave:**

| Situation | What happens |
|---|---|
| A lock left by a process that no longer runs | Replaced at the next start, with a warning |
| A lock held by a running process | Start-up stops: `… is in use by another AgentShield API process (pid N)` |
| The lock is removed or replaced while the API runs | The store stops writing (`lock-lost`, 503) until a restart |

**What to do when start-up says the store is in use:**
1. Check whether another AgentShield API is running: `Get-Process -Id N`.
2. If it is, stop it, or use separate store paths for a second instance.
3. If process `N` is something unrelated (a reused process id), delete the `.lock` file and start again.

**The credential CLI** uses its own `agent-credentials.json.lock`, which holds no process id. If it
was left by an interrupted command, delete it.

## Integrity warnings

**`… status=integrity-failure …` at start-up.** A store's integrity chain did not verify.

**What it is.** Corruption detection, not proof of tampering, and no protection against someone who
controls your Windows account (see [storage-integrity.md](storage-integrity.md)).

**What happened automatically.** The store has already recovered fail-safe, and the damaged file was
preserved (`copy=`).

**What to do:**
1. Compare the damaged copy with the current journal.
2. If the damage is unexplained, treat it as possible interference: rotate the API token and the
   agent credentials.
3. **Do not restore a backup over a journal that start-up has already recovered.** You would lose the
   newer records it kept.

## Disaster recovery limitations

- **Everything after the last backup is lost** if the disk is lost: audit events, approvals and
  their decisions. A restore cannot recover decisions made after the backup; that is why restored
  pending approvals become `OUTCOME_UNKNOWN`.
- **No live, off-machine or continuous backup.** Backups are offline, manual, and only as good as the
  copy you keep elsewhere.
- **The API token is not backed up.** A new one is created; operators sign in again.
- **Credentials:**
  - Restoring an old credential store undoes later revocations; review it before starting the API.
  - Re-issuing credentials (agents enrol again) is the safe alternative.
- **Same-account trust.** Anyone controlling your Windows account (or an administrator) can read and
  change the stores and the backups. Integrity chains only detect accidental or unsophisticated damage.
- **Single process, single machine.** Nothing here supports more than one API writing the same stores.
- **Not drilled for real.** These procedures are covered by automated tests on temporary directories.
  **No recovery drill has been performed on a real installation.** Rehearse one on a test machine
  before relying on it.
