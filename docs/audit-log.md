# Durable audit log (M3-E E10)

AgentShield records every decision and approval step as an activity event. Since M3-E E10 the
API stores these events in a local, append-only file, so they survive restarts and are never
dropped to make room.

Scope: the single-process local prototype. This is not distributed storage, and it is not
tamper-proof (see Residual risks). Since M3-E E13 records are chained (v2, a `prev` hash), so
corruption and unsophisticated edits are detected and reported; see [storage-integrity.md](storage-integrity.md).

## What was there before (E10 inspection)

**Producers.** Every event goes through one function, `recordEvent` in `apps/api/src/app.ts`.
Its callers are:

| Lifecycle | Written by |
|---|---|
| `SIMULATED_EXECUTED`, `EVALUATED`, `PENDING_CONFIRMATION`, `BLOCKED` | `POST /api/evaluate`: every decision, agent or operator scenario |
| `CONFIRM_NOT_QUEUED` | evaluate, when the approval store (or the agent's share of it) is full |
| `IDENTITY_MISMATCH` | evaluate, when the body names a different agent than the credential |
| `SIMULATED_EXECUTED`, `APPROVED_NOT_EXECUTED`, `BLOCKED_ON_RECHECK` | `POST /api/approvals/:id/approve` |
| `REJECTED` | `POST /api/approvals/:id/reject` |
| `EXPIRED` | the lazy expiry sweep (listings, approve, reject, agent reads). A failed write keeps a pending marker and is retried. |

**Schema.** The `ActivityEvent` type in `packages/engine/src/types.ts`. Each event has:
- `id` (`evt-N`) and an ISO 8601 `timestamp`, taken when the event was written;
- the request metadata: `scenarioId`, `intentTask`, `actionType`, `tool`, `destination`;
- the decision: `decision`, `riskScore`, `findings`, `explanation`;
- optionally `approvalId` and `lifecycle`;
- the agent fields: `agentId`, `agentPolicy`, `actor`, `claimedAgentId`.

**Redaction.** `recordEvent` replaces secret-shaped values in `intentTask`, `actionType`, `tool`,
`destination`, `agentId` and `claimedAgentId` before an event is stored. Finding evidence is
redacted by the engine.

Events never contain credentials, private keys, Authorization headers, API tokens or untrusted
content.

**Before E10:**
- **Storage:** an in-memory array of the newest `API_MAX_EVENTS` events (default 1,000).
  Older events were silently dropped.
- **Restarts:** everything was lost on restart, and ids started again at `evt-1`.
- **Ordering:** the order of writes, which is safe because writes are synchronous.

**Consumers.**
- `GET /api/events`, operator only: every retained event, newest first, with no paging.
- The dashboard's Activity & Audit and Command Center views.

**Error handling.**
- A failed write threw: evaluate answered 500, and approve or reject went to the generic error
  handler.
- The `EXPIRED` writer catches failures and retries later.

## Design

**Compatibility.** `GET /api/events` and the event schema are unchanged. The API view still holds
the newest `API_MAX_EVENTS` events. The file underneath keeps every event, up to its size limit.

**Write order.** Each event is written to the file first, flushed with fsync, and only then added
to the view. An event the view shows has been stored durably.

**Ids continue across restarts.** At start-up the newest `API_MAX_EVENTS` stored events are
loaded into the view, and numbering continues after the highest stored id.

**Memory-only mode.** `createApp` without an `auditLog` keeps events in memory only, as before.
Tests and demos use this; the server always passes the file.

### File format

**Location.** `AUDIT_LOG_FILE`, an absolute path. The default is
`%LOCALAPPDATA%\AgentShield\audit-events.jsonl`, next to the API token and credential store.

**Lines.** UTF-8 JSON Lines, one record per line, each ending in LF:

```text
{"v":2,"seq":42,"prev":"<64 hex digits>","sha256":"<64 hex digits>","event":{"id":"evt-42","timestamp":"2026-11-01T09:00:00.000Z",...}}
```

Logs written before M3-E E13 hold v1 records (the same without `prev`). They are still read,
but only as a prefix: new records are chained after them, and a v1 record after a v2 one is
unverified.

**Fields.**
- `seq` is 1, 2, 3, ... in write order. It always equals the number in `event.id`.
- `sha256` is the SHA-256 of the exact `event` JSON text. It detects partial and corrupted
  records. It does **not** detect deliberate changes, since anyone who can edit the file can
  recompute it.
- `prev` (M3-E E13) is the SHA-256 of the previous valid record line, or of a fixed genesis
  value for the first record. A record whose `prev` does not match is **unverified**: it stays
  in the file, is left out of the view, and is reported at start-up
  (`audit-log status=integrity-failure`). This detects deleted, inserted and reordered records,
  but not whole records removed from the end, nor a rewrite that recomputes every hash (see
  [storage-integrity.md](storage-integrity.md)).
- JSON escapes every control character, so no field value can end a line or start a forged
  record.

**Limits.**
- **The file never exceeds `AUDIT_LOG_MAX_BYTES`.** It is a whole number of bytes from 1 MiB to
  1 GiB, 64 MiB by default.
- **Readiness.** When less than one maximum-size record (256 KiB) of room remains, the log
  reports itself full.
- **Old events are never deleted or rewritten to make room.**

### File safety

**Creation.** The parent directory is created owner-only where supported. A new file is created
empty and restricted to the current user (a Windows ACL with a single entry, or mode 0600)
before anything is written to it.

**What is refused.**
- A relative path.
- A symbolic link or junction at the path. It is not followed.
- Anything that is not a regular file.
- A file that changes between the check and the open (device and inode compared).
- On POSIX, the file is opened with `O_NOFOLLOW`.

**Existing files.** An existing file whose permissions grant other accounts access is still
used, with a start-up warning (`reason=permissions-not-restricted`).

**Single writer.** A lock file next to the log (`audit-events.jsonl.lock`, holding the process
id) stops a second API process from appending.
- A lock left by a process that no longer runs is replaced, with a warning.
- A lock held by a running process stops start-up.

## Restart and corruption recovery

At start-up the whole file is read. It is at most `AUDIT_LOG_MAX_BYTES`, and a larger file stops
start-up.

| Found | What happens |
|---|---|
| Complete, valid records | Loaded in order |
| A final record without its LF (a crash or power loss during a write) | Kept: an LF is appended so it stays a separate, malformed line, and the next record starts on its own line. Reported as `reason=truncated-final-record`. |
| A malformed line: not JSON, wrong version, checksum mismatch, id not matching `seq`, missing fields | Skipped and counted. Start-up warns with the count and line numbers, never the content. The line stays in the file. |
| A duplicate or out-of-order `seq` | Skipped (the first wins) and counted (`reason=duplicate-records`) |
| A record whose `prev` does not name the previous valid record (E13) | Kept in the file, left out of the view, counted and reported as `status=integrity-failure` with line numbers |
| Any skipped line | New ids continue after the highest `seq` seen anywhere in the file, so an id is never reused |

Nothing in the file is deleted or rewritten during recovery.

## Failure handling: what fails closed

| Situation | Behaviour |
|---|---|
| The log cannot be opened safely: a relative path, a symlink, not a regular file, no write permission, locked by another process, larger than its limit, or an invalid `AUDIT_LOG_MAX_BYTES` | **The API does not start**: `audit-log status=invalid-config reason=...` |
| A write or fsync fails during a request (disk full, I/O error) | The request answers **`500 {"reason":"audit-write-failed"}`**, never success. The event is not added to the view, and the log is marked failed for the rest of the process. |
| The log is failed, or full | `POST /api/evaluate`, `/approve` and `/reject` are refused **before anything is evaluated, executed or changed**: `503` with `reason` set to `audit-unavailable` or `audit-storage-full`. Reads keep working: `GET /api/events`, `/api/approvals`, agent approval reads, policies. |
| A record over 256 KiB | Not written; the request answers `500 audit-write-failed`. The log stays usable. |
| An `EXPIRED` event cannot be written | Unchanged from before: the record keeps its pending marker and the write is retried later. |

**A failed write is not a refused action.** Most writes happen after the decision they record.
- An `ALLOW` whose simulated handler already ran, or an approval that already executed, is
  reported as `500 audit-write-failed`. The outcome is unconfirmed.
- The SDK reports this as `ServerError`, and the reference agent as `unconfirmed`. It is not
  retried.
- After a failure, no further state changes are accepted until the API is restarted with
  working storage.
- Security decisions themselves are never changed by audit failures.

**No duplicates from the store.** It appends each event exactly once per call and never retries
silently. The one existing case of a possible duplicate remains the `EXPIRED` retry path: a write
that succeeds but is reported as failed. This is documented in the main README.

## Operating the log

**Location.** Start-up prints it, with the record count and size:
`audit-log status=ready records=N bytes=B maxBytes=M path=...`.

**Reading.** Use PowerShell. Lines that are not records are skipped:

```powershell
Get-Content "$env:LOCALAPPDATA\AgentShield\audit-events.jsonl" | ForEach-Object { ($_ | ConvertFrom-Json).event } | Select-Object id, timestamp, lifecycle, decision, agentId
```

**When the log is full.**
1. Stop the API.
2. Move the file to an archive location that only you can read.
3. Start the API again; it creates a new, empty file.

Ids then start again at `evt-1` in the new file. Alternatively, raise `AUDIT_LOG_MAX_BYTES`
(up to 1 GiB).

**Never edit the file while the API runs.** Edited lines fail their checksum and are skipped
at the next start.

## Security review and residual risks

| Concern | Handling | Residual risk |
|---|---|---|
| Log injection | JSON escaping of every field. The record shape is matched exactly. A line separator inside a field (U+2028/U+2029, left unescaped by JSON) is handled. | None found |
| Path traversal | The path comes only from operator configuration (`AUDIT_LOG_FILE`), never from requests; it must be absolute | An operator can point it anywhere their account can write |
| Symlink attacks | The final path component may not be a symlink or junction, the file is checked after opening, and `O_NOFOLLOW` is used on POSIX | Since E13 a symlinked or junction **parent** directory is refused too. An administrator can still change the directory tree. |
| Sensitive data | Events are redacted before storage, and the store adds nothing. Tests check that the file has no credential, key, Authorization header or token. | Redaction covers only the documented secret patterns (see the main README) |
| Partial writes | Detected at start-up; kept and skipped. The process stops appending after a failed write. | None found |
| Corrupted records | The checksum detects accidental damage; since E13 the `prev` chain also detects deleted, inserted and reordered records. Unverified events are reported and left out of the view, never deleted. | **No tamper protection.** A local user with write access can change, remove or forge records and recompute checksums. |
| Disk exhaustion | A hard size limit with a fail-closed refusal; old events are never dropped | Other files can still fill the disk; that surfaces as write failures, also fail-closed |
| Event loss in crashes | Each event is fsynced before it is shown or the request completes | A crash between an action and its event write loses that event (the action is in-process memory only). Storage that ignores fsync can lose recent records. |
| Concurrent writers | Synchronous appends in one process; the lock file stops a second process | Two processes on different paths are not detected. A lock taken over from a recycled process id is possible but unlikely. |
| Local user access | Created restricted to the current user; a warning if an existing file is not | Any process running as the same Windows user can read and write the log, as with the API token and credential store |

## Verification

**Tests.** Two files cover this:
- `apps/api/src/audit/file-audit-log.test.ts`. Format and checksum; ordering; restart; a
  truncated final record; malformed and duplicate records; log injection; disk-full,
  partial-write and fsync failures; a read-only file; the storage limit; an oversized record;
  symlinks and junctions; the single-writer lock; configuration.
- `apps/api/src/audit/audit-routes.test.ts`. Through the API: durable order and view
  compatibility; restart with continued ids; redaction in the file; concurrent requests;
  `EXPIRED` events; no storage path in responses; fail-closed behaviour on a write failure and
  on full storage.
