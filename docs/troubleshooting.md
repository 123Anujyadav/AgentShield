# Troubleshooting and error reference

This document covers what the API answers, how the SDK reports it, and what an agent
should do. It describes the behaviour at M3-E E6.

**Exact messages.** Server messages are quoted exactly. SDK error messages are fixed text;
see [`packages/agent-sdk/src/errors.ts`](../packages/agent-sdk/src/errors.ts).

**Background reading.** The model behind these answers is in
[security-model.md](security-model.md), and the request flow in
[architecture.md](architecture.md).

## Four kinds of outcome

Every evaluation ends in exactly one of these four kinds. Handle them differently.

| Kind | How you know | What it means | What to do |
|---|---|---|---|
| **Confirmed** | `evaluate` returned a decision. For a CONFIRM, `waitForApproval` returned a final status. | AgentShield decided. `executed` says whether its simulated handler ran. | Act only on `ALLOW` with `executed: true`, or on an observed `EXECUTED` with `executed: true`. Everything else is "not done". |
| **Refused** | `AuthenticationError` (401), `ForbiddenError` (403), `BadRequestError` (400, 413, 415), `RateLimitedError` (429), or `InvalidArgumentError` (local) | The request was **not processed**. Nothing was evaluated or executed. | Fix the cause. Re-sending is your decision; after a 429, wait at least `details.retryAfterSeconds`. |
| **Pending** | `evaluate` returned `CONFIRM` with an `approvalId`, and the approval is still `PENDING`. `waitForApproval` may throw `WaitTimeoutError`. | An operator has not decided yet. Nothing has run. | Wait, possibly again later. Never proceed without an observed `EXECUTED`. |
| **Unconfirmed** | `evaluate` threw `TimeoutError`, `NetworkError`, `ServiceUnavailableError` (503), `ServerError` (5xx and other statuses), `ResponseFormatError`, or `ConflictError` with `idempotency-outcome-unknown` | **Unknown.** The evaluation may or may not have been processed, and an `ALLOW` may already have executed. | Do not act on it and never resend it as a new evaluation. Retry deliberately with `error.details.idempotencyKey` and the same request to recover the result (see [integration-guide.md](integration-guide.md#7-handle-unconfirmed-outcomes-safely)); if that is outcome-unknown, tell a person. |

**The reference agent's status names** map onto these kinds:
- **Confirmed:** `completed`, `blocked`, `not-executed`, `rejected`, `expired` and
  `blocked-on-recheck`.
- **Refused:** `refused`.
- **Pending:** `pending`. `wait-interrupted` and `approval-missing` are failures while
  following a pending approval.
- **Unconfirmed:** `unconfirmed`.

## HTTP status reference (agent routes)

**Where agents can go.** Agents call only `POST /api/evaluate` and
`GET /api/agent/approvals[/:id]`. Error bodies are JSON:
`{"error": "<message>"}`, sometimes with a `"reason"`.

**What the SDK keeps.** It keeps `details.status` and a well-formed `details.reason`, never
the message.

### 400 Bad Request: `BadRequestError` (refused, not processed)

| Message (and `reason`) | Cause |
|---|---|
| `Malformed JSON body.` / `Malformed request body.` | The body is not valid JSON, or arrived broken (the SDK always sends valid JSON) |
| `JSON object body required.` | The body is not a JSON object |
| `Provide intent {task, and optionally allowedActions, deniedActions, allowedDestinations} and action {type, tool, destination, summary}.` | Missing or invalid `intent` or `action` fields, including a nested or non-flat `action.payload` |
| `untrustedContent.text exceeds 8000 characters.` (and other `untrustedContent...` messages) | Untrusted content too long, or missing `source` or `text` |
| `agentId must be a lowercase identifier: ...` (`invalid-agent-id`) | A malformed `agentId` in the body. The SDK never sends one. |
| `Invalid query. Allowed once each: limit (1-50), before (an approval id), status.` (`invalid-query`) | A bad `listApprovals` query. The SDK validates these locally first and throws `InvalidArgumentError`. |

**Which checks run first.**
- Malformed, oversized or wrongly encoded bodies are refused before authentication.
- The other checks run after the signature is verified, so such a request has already used
  its nonce. That is harmless, because the SDK signs every attempt afresh.

### 401 Unauthorized: `AuthenticationError` (refused, not processed)

**Every authentication failure gets the same answer:**

```text
401 {"error":"Authentication required."}
WWW-Authenticate: Bearer realm="agentshield"
```

The response never says why, on purpose. **The reason is in the API's standard error**, as
`agent-auth status=failed scheme=signature reason=<reason> keyId=<keyId or none>`:

| Log reason | Meaning | Fix |
|---|---|---|
| `unknown-key` | No credential with that key id (or it was deleted) | Check `agent-credential list`; issue a credential |
| `revoked` | The credential was revoked | Use a new credential (`rotate` or `create`) |
| `expired` | Past `expiresAt` (90 days by default) | Issue a new credential |
| `scheme-mismatch` | The key id belongs to a legacy bearer credential | Rotate it to Ed25519 |
| `store-unavailable` | The credential store file is currently invalid, so every agent is refused | Fix the store. The log shows `agent-credentials status=invalid reason=...`. |
| `stale` / `future` | The timestamp is more than the allowed skew (±30 s by default) from the server clock | Fix the clock on the agent or server machine. `AGENT_SIGNATURE_MAX_SKEW_SECONDS` (5 to 300) changes the window but widens replay exposure. |
| `before-startup` | Signed before this API process started (the start-up fence) | Sign again. The SDK does this once automatically for GETs. |
| `bad-signature` | The signature does not verify: wrong key for the key id, or the request was changed after signing | Check that the credential file matches the key id in `list`. Do not modify requests after the SDK signs them. |
| `replay` | That `(keyId, nonce)` was already accepted | Only a replayed or duplicated request causes this; the SDK uses a new nonce every time |
| `bad-header`, `bad-host`, `bad-request`, `content-encoding`, `unreadable-body` | Malformed header, an invalid `Host`, or a body the server would not hash (compressed, or not read as JSON) | Use the SDK unmodified, and do not add `Content-Encoding` |

**Other things that cause a 401:**
- A private key sent as a bearer token. It is logged as
  `reason=private-key-sent-as-bearer ... action=rotate-this-credential`; rotate that
  credential.
- A legacy bearer credential while `AGENT_BEARER_ALLOWED` is not `true`
  (`reason=bearer-disabled`).

**What the SDK does on a 401.**
- `evaluate`: no retry, so you get `AuthenticationError` straight away.
- GETs: one re-signed retry, then `AuthenticationError`.

### 403 Forbidden: `ForbiddenError` (refused, not processed)

| `reason` | Message | Cause |
|---|---|---|
| `operator-required` | `This route requires operator authentication.` | An agent called an operator route: approve, reject, events, policies, and so on. Agents can never approve or reject. |
| `operator-required` | `Seeded scenarios can only be run by the operator.` | An agent sent a `scenarioId` |
| `agent-credential-required` | `Custom evaluations require an agent credential.` / `This route requires an agent credential.` | The operator token or a session was used where an agent credential is needed |
| `agent-identity-mismatch` | `agentId does not match the authenticated agent. Nothing was evaluated.` | The body named a different agent; it was recorded as a security event. The SDK never sends `agentId`. |
| (none) | `Host not allowed.` / `Origin not allowed.` | The `Host` is not `localhost`, `127.0.0.1` or `[::1]`, or a browser origin other than the dashboard was used |

### 404 Not Found (approvals)

`GET /api/agent/approvals/:id` answers `404 {"error":"Approval not found."}` in all of
these cases, with no way to tell them apart:
- the id is unknown or malformed;
- it is another agent's approval;
- it is an operator scenario's approval;
- the approval store was deleted while the API was stopped (approvals survive restarts since
  M3-E E12);
- a final record older than 15 minutes was dropped to make room (at most 500 records are
  kept; pending ones are never dropped).

**In the SDK:**
- `getApproval(id)` returns `null`.
- `waitForApproval(id)` throws `ApprovalNotFoundError`.

**What to do.** Treat it as "not done". If it is your own approval and the API restarted,
it is gone; submit a new evaluation if the task still matters.

### 413 and 415: `BadRequestError` (refused, not processed)

- `413 Request body too large.`: the body is over 32 KB. The SDK refuses such an
  evaluation locally with `InvalidArgumentError`, before sending.
- `415 Unsupported request body encoding.`: an unsupported charset or
  `Content-Encoding`.

### 429 Too Many Requests: `RateLimitedError` (refused, not processed)

**Always** sent with `Retry-After` (seconds), which the SDK exposes as
`details.retryAfterSeconds`:

| Message | Limit |
|---|---|
| `Too many requests. Try again later.` | The general `/api` limit (600 a minute per client address), evaluate (60 a minute, counted per agent; the operator per client address), or the per-agent approval-read limit (120 a minute). Configurable; see `.env.example`. |
| `Too many failed authentication attempts. Try again later.` | More than 20 failed authentications a minute from this client address. Valid credentials are still accepted; only failing attempts get this. |
| `Too many signed requests for this credential. Try again later.` | This key has 600 live nonces in the replay cache: too many signed requests within the skew window |

**What the SDK does.**
- `evaluate`: not retried.
- GETs: retried when `Retry-After` is 5 seconds or less; otherwise the error is reported
  at once.

**Shared limits.** On one machine all local callers share a client address, so another
local process can use up the shared limits.

### 503 Service Unavailable: `ServiceUnavailableError` (treat as unconfirmed)

| Message (and `reason`) | Processed? |
|---|---|
| `Signed requests are temporarily unavailable. Try again later.` (with `Retry-After`) | No. The replay cache holds 100,000 live nonces. |
| `The approval queue is full. ...` (`approval-queue-full`) | **Partly.** The evaluation ran and was recorded as `CONFIRM_NOT_QUEUED`, but no approval was created and nothing executed. The operator must approve, reject or let pending approvals expire. |
| `This agent already has the maximum number of pending approvals. ...` (`approval-queue-full`, M3-E E9) | **Partly**, as above. This agent holds 100 pending approvals; other agents are unaffected. |

**Why it counts as unconfirmed.** Both arrive as `ServiceUnavailableError`, and neither is
retried for `evaluate`, even with a short `Retry-After`. `approval-queue-full` is in
`details.reason`. A client can use it to explain the situation, as the reference agent
does, but a client that treats every 503 from `evaluate` as unconfirmed is never wrong.
GETs are retried after a short `Retry-After`.

### Other statuses

- **5xx**, for example `500 {"error":"Internal error."}`: `ServerError`. Treat an evaluate
  as unconfirmed.
- **409 and 410** come only from the operator's approve and reject routes (already final,
  blocked on recheck, or expired). Agents observe the result through the approval status
  instead.

### Storage integrity and filesystem checks (M3-E E13)

| Log line or answer | Meaning | What to do |
|---|---|---|
| `<store> status=integrity-failure ... copy=<path>` | A state file's integrity chain did not verify (damage or an edit). The store recovered fail-safe: approvals quarantined, replay fenced, idempotency keys unknown, or audit events left out of the view. The original was copied to `<path>`. | Compare the copy; follow [storage-integrity.md](storage-integrity.md) (Operator recovery). If interference is suspected, rotate the API token and agent credentials. |
| `audit-log status=integrity-failure ...` | Unverified audit events are kept in the file but not shown | Archive the audit log once investigated |
| `<store> status=migrated ...` | A pre-E13 journal was rewritten with the integrity chain | Nothing |
| `... status=warning reason=permissions-not-restricted` | Other accounts can read that state file | Restrict it to your account, or let AgentShield recreate it |
| Start-up fails: `... path is not safe: A parent directory of the file is a symbolic link or junction` | A store's directory is reached through a link | Use a real directory (set the store's `*_FILE` variable to a path without links) |
| A request answers 503 after `lock-lost` in the log | A store's lock file was removed or replaced while the API ran, so the API stopped writing | Make sure only one API runs; restart it |
| `git commit` fails with `secret scan FAILED` or `REFUSED <file>` | The pre-commit hook found a credential-shaped value, or a forbidden file, in the staged changes | Unstage it (`git restore --staged <file>`) and remove the secret; never commit `.env` |

### Storage operations, backup and restore (M3-E E14)

| Log line or message | Meaning | What to do |
|---|---|---|
| Start-up fails: `... A restore of the <store> was interrupted` | A restore stopped part-way. Its `.restoring` marker keeps the API from starting on half-restored state. | Run the same `npm run ops -- restore --dir <backup>` again |
| Start-up fails: `... holds records of format version N, written by a newer AgentShield` | The store was written by a newer version (a downgrade, or a file from elsewhere). It was not opened, so nothing was lost. | Use the AgentShield version that wrote it |
| `<store> status=warning reason=stale-lock-replaced` | The previous process did not stop cleanly (a crash or forced stop) | Nothing; check the rest of the start-up log |
| `approval-store status=recovered restored=N` | Pending approvals from a restored backup became `OUTCOME_UNKNOWN` | Tell agents; they can evaluate again |
| `approval-store status=recovered reason=ids-continue-after-audit-log` | The approval journal was lost or restored; ids continue after the audit log's | Nothing |
| `idempotency-store status=warning reason=journal-missing-but-audit-log-has-history` | The idempotency journal was lost: new keys are refused for 15 minutes | Wait; do not delete journals |
| `storage store=<name> level=warning\|critical\|failed ...` | A store is near a limit, full, or stopped writing | See [operations.md](operations.md) (Watching storage health) |
| `ops` says `Stop the AgentShield API first` | Backups and restores run only while the API is stopped | Stop the API, run the command again |
| `ops restore` says `Nothing was restored. ... --replace-damaged` | A present store is damaged. Start-up recovery keeps its newer records. | Usually start the API instead; use `--replace-damaged` only to discard it (it is copied aside) |
| `verify-backup` reports `incomplete` or `does not match the manifest` | The backup never finished, or a file was changed or truncated | Use another backup |

### Approval storage (M3-E E12)

| Answer | Meaning | What to do |
|---|---|---|
| `503 {"reason":"approval-store-full"}` on evaluate (CONFIRM), approve or reject | The approval journal is full, even after compaction. Nothing was created, changed or executed. | Let finished approvals age out, or archive the store while the API is stopped |
| `503 {"reason":"approval-store-unavailable"}` | The approval journal could not be written (disk full, I/O error). Approvals cannot be created or decided until a restart. Nothing changed. | See `approval-store status=...` in the API log; fix and restart |
| `500 {"reason":"approval-store-write-failed"}` on approve | The approved action ran, but its outcome could not be recorded. Never a success. After a restart the approval is `OUTCOME_UNKNOWN`. | Treat as unconfirmed; check the action's effect |
| Approval status `OUTCOME_UNKNOWN` | Recovered after a restart: interrupted while executing, or its record was damaged. It never runs and cannot be decided (`409`). | An operator checks what happened; submit a new evaluation if needed |
| Start-up log `approval-store status=recovered ...` | Interrupted or quarantined approvals were marked `OUTCOME_UNKNOWN` ([approval-persistence.md](approval-persistence.md)) | Review those approvals |

### Replay protection and idempotency (M3-E E11)

| Answer | Meaning | What to do |
|---|---|---|
| `503 Signed requests are temporarily unavailable` with log `reason=replay-recovering` | The replay journal was new, deleted or damaged at start-up, so requests dated up to start-up + skew (30 s) are refused. Not processed. | Wait (at most the skew) and send a freshly signed request. The SDK re-signs every attempt. |
| The same 503 with log `reason=replay-store-unavailable` | The replay journal could not be written (disk full, I/O error). Every signed request is refused until a restart. Not processed. | Fix the cause (see the log), restart the API |
| `400 {"reason":"invalid-idempotency-key"}` | `idempotencyKey` is not 16 to 64 base64url characters, or was sent with an operator scenario | Use the SDK, or a valid key |
| `409 {"reason":"idempotency-key-reused"}` | The key was already used for a different request. Not evaluated. | Use the same request for a retry, or a new key for a new evaluation |
| `409 {"reason":"idempotency-outcome-unknown"}` | An evaluation with this key started, but its result was not recorded (the API stopped, or the evaluation failed). It was not run again. | Unconfirmed: do not act on it; tell a person |
| `503 {"reason":"idempotency-capacity"}` | Too many live keys for this agent (1,000) or the server (10,000). Not evaluated. | Wait for keys to expire (15 minutes), or slow down |
| `503 {"reason":"idempotency-unavailable"}` | The idempotency journal could not be written, or it is recovering from a damaged record. Not evaluated. | See the API log (`idempotency-store status=...`); restart once fixed |
| Start-up fails with `agent-state status=invalid-config reason=...` | A replay, idempotency or approval journal is a symlink or not a regular file, cannot be written, is locked by another running API, or is too large | Fix the cause named in the reason |

### Audit storage (M3-E E10)

| Answer | Meaning | What to do |
|---|---|---|
| `503 {"reason":"audit-unavailable"}` on evaluate, approve or reject | An earlier audit write failed, so the API accepts no more state changes. Nothing was evaluated or executed. | Check the API's standard error for `audit-log status=write-failed code=...` (for example `ENOSPC`). Fix the cause and restart the API. |
| `503 {"reason":"audit-storage-full"}` | The audit log reached `AUDIT_LOG_MAX_BYTES`. Nothing was evaluated or executed. | Archive the file (stop the API and move it), or raise the limit. See [audit-log.md](audit-log.md#operating-the-log). |
| `500 {"reason":"audit-write-failed"}` | The request's audit event could not be stored durably. The action may already have taken effect. | Treat it as unconfirmed, like any 5xx. Do not retry automatically. |
| Start-up fails with `audit-log status=invalid-config reason=...` | The audit log is a symlink or not a regular file, cannot be written, is locked by another running API, is over its limit, or `AUDIT_LOG_MAX_BYTES` is invalid | Fix the cause named in the reason |

To an agent, the two 503s are a `ServiceUnavailableError`, and the reference agent reports
`unconfirmed (unavailable)`. Neither is retried for `evaluate`.

## SDK-only errors

| Error | When | Processed? |
|---|---|---|
| `CredentialError` | Loading a missing, unreadable, too large or malformed credential | Nothing was sent |
| `ConfigurationError` | Bad client options: a non-origin `baseUrl`, a non-loopback host without `allowRemote`, a remote http URL, or an out-of-range timeout or retry count | Nothing was sent |
| `InvalidArgumentError` | A bad method argument: an evaluation over 32 KB, a malformed approval id, bad list options, bad `maxPages` or wait timeout | Nothing was sent |
| `TimeoutError` | No complete answer within `timeoutMs` (default 10 s) | **Unknown** for `evaluate`; GETs are retried first |
| `NetworkError` | AgentShield could not be reached: connection refused, reset, DNS failure, or a redirect (never followed) | **Unknown** for `evaluate`, even though a refused connection usually means it never arrived |
| `ResponseFormatError` | The response was not JSON, had the wrong shape, or was over 1 MB | **Unknown** for `evaluate` |
| `ApprovalNotFoundError` | `waitForApproval` got a 404 | See 404 above |
| `WaitTimeoutError` | `waitForApproval` reached its `timeoutMs` while still `PENDING` | Pending: nothing has run yet |

## Common situations

### Timestamp and signature failures

**Every request gets 401.**
1. Check the API's standard error for the `reason=`.
2. With `stale` or `future`, compare the clocks. Both machines are the same one in local
   development, so look for a skewed system clock or a suspended VM.
3. With `bad-signature`, make sure the key file and the key id belong together:
   `agent-credential list` shows the key id, and the file starts with `asag2_<keyId>.`.
   Never edit the key file.

### Replay or nonce rejection

**A `replay` reason** means the same signed request arrived twice. The SDK never resends a
signature, so look for a proxy, test harness or custom `fetch` that duplicates requests.

**A 429 for too many signed requests, or a 503 for unavailable signed requests,** means the
replay cache's limits were reached. Slow down. Nonces leave the cache once their timestamp
is older than the skew window (30 s by default).

### Expired or revoked credentials

1. `npm run agent-credential -w @agentshield/api -- list` shows each credential's status.
2. Issue a replacement: `rotate --key <old>`, or `create --agent <id>`. Deploy it to the
   agent, then `revoke --key <old>`.
3. A revocation reaches a running API within 2 seconds.

**Pending approvals** created with a revoked or expired credential end in
`BLOCKED_ON_RECHECK` (rule `identity.credential-invalid`) when approved.

**Revoked while the agent waits.** The agent's next poll gets a 401. It is retried once,
then reported as `AuthenticationError`; the reference agent reports `wait-interrupted`.

### Approval expiry

**Approvals expire 15 minutes after creation.**
- The agent sees `EXPIRED`.
- The operator's approve or reject gets `410`.
- Nothing runs.

**Expiry is detected lazily,** on the next read, approve or reject, so the `EXPIRED` event's
timestamp is when it was noticed.

**What to do.** Submit a new evaluation if the task still matters. The SDK's default wait
(16 minutes) is just longer than the approval lifetime.

### Missing approvals

`getApproval` returning `null`, or `ApprovalNotFoundError`, is the uniform 404 above. Since
M3-E E12 a restart does not cause it; for your own approval, look for a deleted approval
store or an old finished approval dropped to make room.

### Network errors and evaluation timeouts

**API not running.** You get `NetworkError` (connection refused). Start it
(`npm run dev:api`) and check the URL. The default is `http://127.0.0.1:4000`; the port comes from
`PORT`.

**Evaluate timed out.** The server may have processed it, and possibly executed an
`ALLOW`. **Do not resend automatically.** Follow
[integration-guide.md](integration-guide.md#7-handle-unconfirmed-outcomes-safely).

**GET timed out.** It was already retried (`getRetries`, default 2). Reading is safe to
repeat: call `getApproval` or `waitForApproval` again later.

### Server restart behaviour

**What the restart loses:**
- **Rate-limit counters and dashboard sessions.** Approvals survive (M3-E E12), and so do the
  replay journal and idempotency records (E11). Activity events are kept:
  they are in the durable audit log, and the event view is restored at start-up (M3-E E10).

**The start-up fence.** A request signed before the restart is refused (`before-startup`).
The SDK re-signs a GET once automatically; an `evaluate` is not retried.

**What survives.** Credentials and policies, which are files. Policy edits take effect
only after a restart.

**While the API is down:**
- polls fail with `NetworkError`, after the SDK's retries;
- the reference agent reports `wait-interrupted`, and `resume(approvalId)` can try again
  once the API is back. The approval is still there, with its state.

**Approval ids.** With the durable store (M3-E E12) ids are never reused. If the store was
deleted, a restarted API numbers approvals from `apr-1` again, so an id from before can name a
new approval. Compare `createdAt` with the evaluate
response's `approvalCreatedAt`. The reference agent reports a mismatch as `approval-missing`
and saves nothing.

**The first evaluation after a restart can fail with `NetworkError`.** It can be sent on a
kept-alive connection to the old process. It is reported as unconfirmed and not retried,
although it never reached the server; check, then run it again.

### The API does not start

| Log line | Fix |
|---|---|
| `agent-policy status=invalid-config reason=...` | Fix `AGENT_POLICY_FILE`; the reason names the position. Use an absolute path. |
| `agent-credentials status=invalid-config reason=...` | Fix or restore the credential store. Check it with `agent-credential list`. |
| `agent-signature status=invalid-config reason=...` | `AGENT_SIGNATURE_MAX_SKEW_SECONDS` must be a whole number from 5 to 300 |
| `agent-state status=invalid-config reason=...` or `audit-log status=invalid-config reason=...` | A store cannot be opened safely: a lock held by another process, an unsafe path, a newer format, or an interrupted restore. The reason says which. See [operations.md](operations.md). |

### The CLI refuses to run

| Message | Fix |
|---|---|
| `Another credential command is running, or one was interrupted. ...` | If none is running, delete the `.lock` file next to the store |
| `The output file already exists; it was not replaced.` | `--out` never overwrites; choose a new path |
| `That agent already has 4 active credentials. ...` | Revoke one first, or use `rotate --revoke-old` |
| `Bearer credentials are disabled. ...` | Use the default Ed25519 scheme |

### The reference agent

**Exit codes.**
- `0`: completed.
- `2`: not done.
- `3`: the outcome is open (`pending`, `wait-interrupted` or `unconfirmed`).
- `1`: refused, or a configuration or usage error.

**Usage problems.**
- Use absolute paths for `--document` and `AGENTSHIELD_AGENT_CREDENTIAL_FILE`: npm runs the
  agent from `apps/reference-agent`.
- A document over 8,000 characters (counted in UTF-16 code units, as the API counts) is
  refused locally with exit code 1, before anything is sent, and is never truncated.
- A full approval queue (`503 approval-queue-full`) is reported as `unconfirmed`
  (`approval-queue-full`) with exit code 3, and is not sent again.
- A document with no readable text (only invisible or control characters) is refused
  locally with exit code 1.
- A request over 32 KB once encoded (many control characters) is reported as `refused`
  (`request-too-large`): the SDK did not send it.
- A `--document` that is not a regular file (a directory, device or pipe) is refused unread
  with exit code 1.

The full status list is in [`apps/reference-agent/README.md`](../apps/reference-agent/README.md#error-handling).
