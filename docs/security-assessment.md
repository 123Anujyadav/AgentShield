# Security and production-readiness assessment (M3-E E9)

**Date:** 2026-11-01.
**Baseline:** `ba1c4ab` (E1–E8).
**Scope:**
- the agent protocol and credentials;
- signature verification, replay protection and rotation;
- authorization;
- policies, approvals and agent approval visibility;
- the SDK and the reference agent;
- audit logging;
- dependencies and repository hygiene.

**Method.**
- Line-by-line review of the source, including three independent read-only reviews:
  1. authentication;
  2. approvals and policy;
  3. the SDK and the reference agent.
- Every finding was traced in the code before being accepted.
- Fixed findings have regression tests, and each test was shown to fail without its fix.

**What was not done:**
- no live services, external calls or dependency changes;
- no `npm audit` (it needs network access);
- `.env`, tokens, keys and credential stores were not inspected.

## Verdict

**Not production-ready. Sound for its stated purpose as a local, single-operator,
single-process prototype with simulated execution.**

**What holds.** The core security properties hold in the code and are covered by tests:
- signed requests are bound to method, host, target and body;
- replays are refused within the window, and across restarts by the start-up fence;
- the agent's identity is taken from its credential, and agents can never approve;
- approval rechecks the credential, the policy hash and the full evaluation;
- an evaluation is never retried automatically.

**What was found.**
- No Critical or High findings.
- Four Medium defects were found and fixed:
  - a replay race at the edge of the window;
  - approval-id reuse after a restart;
  - one agent exhausting shared queues;
  - unbounded reads of special files.
- One Medium was deferred: the in-memory audit log could be flushed. It was addressed in
  M3-E E10 with a durable audit log ([audit-log.md](audit-log.md)).

**What production would require.** These are architectural properties the prototype does not
have:
- persistent, shared state (approvals, replay cache, audit log);
- transport confidentiality (TLS);
- more than one operator identity, with roles;
- deployment hardening beyond loopback.

## Findings

### Critical, High

None found.

### Medium

| # | Finding | Status |
|---|---|---|
| M1 | **A replay at the last millisecond of the window.** The verifier read the clock for the skew check, and the replay cache read it again after verification. A tick between the two, at exactly `ts + skew`, let a captured request through a second time. | **Fixed.** One clock reading per request is passed to the cache (`signature.ts`, `nonce-cache.ts`). Test: `signature.test.ts` "a replay at the last millisecond…". |
| M2 | **Approval ids are reused after an API restart.** Ids restart at `apr-1`. The reference agent followed a pending task by id only, so after a restart another task's new `apr-1`, once approved, completed the stale task and saved a summary nobody had approved. Shown end to end against the real server. | **Fixed.** The SDK returns `approvalCreatedAt` (additive) and refuses a `getApproval` answer about another id. The agent binds each wait to `createdAt` and reports a mismatch as `approval-missing`. Tests in `agent.test.ts`, `client.test.ts` and `reference-agent.integration.test.ts`. |
| M3 | **One agent can exhaust shared resources.** Any agent could fill all 500 approval records with self-supplied suspicious content, giving every other agent and the operator `503`. The evaluate rate limit was per client address, so on one machine an agent used up everyone's allowance. | **Fixed.** At most 100 open approvals per agent (same `503 approval-queue-full`, agent-specific message), and the evaluate limit is counted per agent. Test: `agent-fairness.test.ts`. Several cooperating agents can still exhaust the store (deferred, see D1). |
| M4 | **Special files are read without bound.** The SDK's `AgentCredential.fromFile` and the agent's `--document` checked `stat().size`, then called `readFileSync`. A FIFO or device (size 0) blocked or was read until memory ran out, and a file that grew after the check was read in full. | **Fixed.** Open, check `isFile()` on the descriptor, then a bounded read (non-blocking open where supported). Tests in `credential.test.ts` and `config-cli.test.ts`. |
| M5 | **The audit log can be flushed.** Events are an in-memory list of the newest 1,000. An agent can push its own `IDENTITY_MISMATCH` or `BLOCKED_ON_RECHECK` events out with ordinary BLOCK evaluations: about 17 minutes at 60 a minute. | **Fixed in M3-E E10.** A durable append-only audit log that keeps every event until its size limit and never drops old ones. When full or failing, state changes are refused. The API view still shows the newest 1,000, but older events stay in the file. |

### Low

| # | Finding | Status |
|---|---|---|
| L1 | **The simulator ran Object.prototype members.** Handlers were looked up on a plain object, so an action type such as `toString` "executed", if a policy allowed it. | **Fixed:** own-property lookup. Test: `approvals.test.ts`. |
| L2 | **A backward clock jump stalled several mechanisms.** Credential-store reloading stalled, so a revocation was held back for as long as the jump. The rate-limit windows froze too, returning 429 to everyone. | **Fixed:** a backward jump counts as due, or starts a new window. Tests in `credentials.test.ts` and `security.test.ts`. |
| L3 | **Empty summaries could be saved.** A document of only invisible or control characters produced an empty summary that could be saved. | **Fixed:** refused locally. |
| L4 | **A local refusal was blamed on the server.** The SDK's local refusal of a request over 32 KB was reported as "AgentShield refused the request". | **Fixed:** a `request-too-large` reason saying nothing was sent. |
| L5 | **Future-dated replays across a restart.** A request with a future-dated timestamp, accepted just before a restart, passes the start-up fence (`ts ≥ startedAt`) and an empty cache, so it can be replayed once afterwards. | **Fixed in M3-E E11** (durable replay journal; [replay-and-idempotency.md](replay-and-idempotency.md)). |
| L6 | **A Windows ACL race on `--out`.** `--out` into a directory other users can read leaves a short window: the temporary file has inherited ACLs until `icacls` runs, and a handle opened in that window keeps read access. The default `%LOCALAPPDATA%` location is not affected. | Deferred (D4). |
| L7 | **Approval recheck does not tie key to agent.** The recheck confirms the requesting key id is active, not that it still belongs to the same agent. This only matters if an operator rewrites the store to move a key id to another agent. | Deferred (the operator is trusted). |
| L8 | **Cancellation and wait deadlines are imprecise.** Cancelling does not interrupt an SDK sleep or a request in progress. `waitForApproval` can end up to 30 s early, with no final poll, or overrun by one request. | Deferred. |
| L9 | **Unusable base URLs are accepted.** A trailing-dot host or port 0 is accepted by the constructor, then every request fails. | Deferred. |
| L10 | **The secret scan is not enforced.** It runs only when someone runs `npm run security:verify`; there is no hook or CI. **Addressed in M3-E E13:** a tracked pre-commit hook scans staged changes (`npm run security:hooks`); no CI. | Deferred (D6). |
| L11 | **The global replay cache can be filled.** 100,000 live nonces fit about 167 busy keys, after which every agent gets `503`. | Deferred (D1). |

### Informational

- **The evaluate response shows agents more than the six-field view.** Its `pendingApproval`
  includes the effective intent and the credential id. A test asserts this on purpose.
- **The failed-attempt limiter does not slow guessing.** It verifies credentials before
  limiting, so a correct guess is still accepted. That is safe only because secrets are
  256-bit. Failures are not logged while a client is blocked.
- **A signed request to an operator route uses up a nonce** before its `403`.
- **`AgentCredential.sign` is public,** as documented. The server's route guard is the
  boundary.
- **The credential store's file ACL is not checked when the API loads it.** The CLI writes
  it restricted.
- **`simulator.invocations` grows without bound.** Short strings; test diagnostics only.
- **The first evaluation after an API restart can fail with `NetworkError`.** It is sent on a
  stale keep-alive connection, and reported as unconfirmed, safely.

## Threat model

| # | Threat | Existing protection | Residual risk | Severity | Acceptable for the prototype? | Recommended future mitigation |
|---|---|---|---|---|---|---|
| 1 | Prompt injection and malicious untrusted content | Rule-based scanner escalates to CONFIRM; hard deny and data-leak guard BLOCK; fixed actions in the reference agent | Paraphrased, encoded or non-English attacks evade the rules | Medium | Yes; it is documented as non-comprehensive | Layered detection with an evaluated model; per-tool argument schemas |
| 2 | Stolen agent credential | Ed25519 keys never sent; revocation within 2 s; expiry of 90 days or less; up to 4 keys per agent for rotation | The holder acts as the agent until revocation or expiry | High impact, local access needed | Yes | OS key storage or a hardware key; anomaly detection; shorter expiry |
| 3 | Replay attacks | Signature over the full request; ±30 s window; nonce cache (M1 fixed); start-up fence | Future-dated replay across a restart (L5); several processes | Low | Yes | Persist a nonce high-water mark; a smaller future skew |
| 4 | Unauthorized agent approval or operator actions | One route guard before all handlers (`403 operator-required`); no SDK method | A compromised operator token can approve anything | High impact, local access needed | Yes; single trusted operator | Operator accounts and roles; approvals by more than one person for risky actions |
| 5 | Policy changes while an approval is pending | Policy hash checked on approve, giving `BLOCKED_ON_RECHECK` | None found | Low | Yes | Policy history and versioned audit |
| 6 | Credential revoked during approval polling | Polling gets 401; the approve recheck blocks (`identity.credential-invalid`); the reload works under clock jumps (L2 fixed) | Revocation takes up to 2 s | Low | Yes | Push notification of revocation |
| 7 | Server restart and state loss | Start-up fence; ids bound to `createdAt` (M2 fixed); durable audit events (E10), replay and idempotency (E11), approvals (E12) | Rate-limit counters and sessions are lost; interrupted approvals become `OUTCOME_UNKNOWN` | Low | Yes; documented | Tamper evidence for the local stores |
| 8 | Approval-queue exhaustion | 500-record cap; only finished records evicted; per-agent cap of 100 (M3 fixed); `503` fails safe | Five cooperating agents can still fill it; finished records may be evicted before their agent reads them | Low | Yes | Per-agent quotas with priority; durable final records |
| 9 | Replay-cache exhaustion | 600 per key, 100,000 overall; live nonces never evicted; `429`/`503` fail safe | About 167 busy keys deny service to all (L11) | Low | Yes | A capacity tied to active keys; shorter skew |
| 10 | Malformed or oversized requests | 32 KB body; fixed-text 400, 413 and 415 before authentication; strict schemas; 8,000-character content; local checks in the SDK and agent (M4 fixed) | None found | Low | Yes | Fuzz testing of parsers |
| 11 | Information leakage through errors and logs | Fixed-text errors; enum reasons; key ids only; redacted events; no stack traces | Agents see the effective intent in the evaluate response (informational) | Low | Yes | Return the minimal view to agents |
| 12 | Ambiguous evaluation timeouts | Evaluate never retried; reported as unconfirmed, with nothing saved | A person must reconcile; there is no idempotency key | Medium | Yes; documented | Server idempotency keys; an approval view that names its request |
| 13 | Multi-process inconsistencies | The design assumes one process; this is documented | Separate replay caches, approval stores and events per process | High if deployed that way | Yes; not supported | Shared state (database, shared replay cache) before scaling out |
| 14 | Local HTTP confidentiality | Loopback only; signatures give integrity; the SDK requires https for remote hosts | Local traffic capture reveals bodies and responses | Medium | Yes; documented | TLS, or a Unix socket or named pipe with OS ACLs |
| 15 | Malicious or compromised reference-agent input files | Strict task shape; character limit; regular-file check with a bounded read (M4 fixed); control and bidi characters removed from the display; document never treated as instructions | Content can still be injection text (handled by threat 1) | Low | Yes | Not needed beyond threat 1 |

## Dependencies and repository

**Workspaces.** Seven workspaces. The runtime dependencies are express 4.22.3, cors 2.8.6,
react and react-dom 19.3.1, and the workspace packages. The SDK, protocol package and
reference agent have no third-party runtime dependencies.

**Known advisories.** Every production package is at or past the versions that fixed the
2024 Express-stack advisories:
- body-parser 1.20.9;
- path-to-regexp 0.1.13;
- cookie 0.7.2;
- send 0.19.2;
- serve-static 1.16.3.

`npm audit` was not run (offline). It last reported 0 vulnerabilities on 2026-10-26.

**Lockfile** (v3, 319 packages):
- every entry resolves to `registry.npmjs.org` and has an integrity hash;
- no git, file or http sources;
- `npm ls --package-lock-only` reports only optional peers, and the bundled dependencies of
  an optional `wasm32` Tailwind package for another platform, which is harmless.

**Install scripts.** Three, all development-only: `esbuild` (two copies) and `fsevents`.

**`.npmrc`.** `legacy-peer-deps=true`, with its reason documented. No root-level
`engines` field.

**Repository hygiene:**
- `.env` is ignored and has never been committed. `.env.example` has no secret values.
- `*.pem`, `*.key`, `*.p12`, `*.pfx`, `dist/` and protected dataset paths are ignored.
- No key or credential-store file has ever been tracked.
- The secret scan passes for the working tree and history.

## Test gaps

**Closed in E9.** Each of the fixes above has a regression test that fails without it.

**Still missing, as recommended work:**
- **Persistence:** approvals, events and the replay cache across a restart (needs a
  persistent store first).
- **Multi-process deployment:** not supported, so not tested.
- **Fault timing in the SDK:**
  - a response body that starts and never finishes;
  - cancellation during a real sleep;
  - wait-deadline precision.
- **Platform-specific:**
  - FIFO and device paths on POSIX;
  - the Windows ACL timing around `--out`.
- **Clock behaviour:** the future-skew replay across a restart (L5), which is not fixed.
- **Browser:** the dashboard approval flow for agent-created approvals.
- **Fuzzing:** of the header, the target and the JSON parsers.

## Deferred risks and recommended phases

| # | Risk | Recommendation |
|---|---|---|
| D1 | Shared limits can be exhausted by several agents, or by many keys (L11) | Quotas per agent and per key with fair sharing, when multi-agent use is real |
| D2 | ~~The audit log is in memory and can be flushed (M5)~~ | Done in M3-E E10. Remaining: the log is not tamper-proof, and there is no paging API for history beyond the view ([audit-log.md](audit-log.md#security-review-and-residual-risks)). |
| D3 | ~~Future-dated replay across a restart (L5)~~ | Done in M3-E E11: accepted nonces are persisted before a request proceeds, with a recovery fence when state may be incomplete |
| D4 | Windows ACL race on `--out` to shared directories (L6) | Refuse `--out` to directories other users can access, or write through a restricted subdirectory |
| D5 | ~~No idempotency~~ (done in M3-E E11: per-agent idempotency keys, SDK keys on every evaluation). Remaining: the approval view does not identify its request (threat 12) | Server-side idempotency keys and a request digest in the agent view |
| D6 | ~~The secret scan is not enforced (L10)~~ | Local pre-commit hook done in M3-E E13; CI remains a recommendation |
| D7 | Shared (multi-process) state; TLS; operator roles (threats 4, 13, 14). Persistent local state is done (E10–E12). | Required before any deployment beyond a single local machine |

## M3-E E14: operational readiness and recovery

**Findings before implementation** (each reproduced in a test that fails without the fix):

| # | Finding | Status |
|---|---|---|
| E14-1 | A store written by a newer AgentShield was read as damage: start-up quarantined its approvals and **rewrote the journal, discarding the newer records** | **Fixed:** a record of a newer format version stops start-up; the file is left untouched |
| E14-2 | A lost approval journal restarted ids at `apr-1` although the audit log showed they had been issued | **Fixed:** ids continue after the highest id the audit log names |
| E14-3 | A lost idempotency journal let retries within 15 minutes be evaluated, and executed, again | **Fixed** when the audit log has history: the 15-minute recovery window applies |
| E14-4 | A stale journal lock (a crashed process) was replaced silently; the audit log's lock still followed a link when reading its process id | **Fixed:** one shared lock implementation, reported at start-up |
| E14-5 | No backup, restore, capacity or health tooling: operators could only copy live files, which mixes moments and can restore stale replay or idempotency state | **Added:** offline backup (all locks held), verification, a restore that only fills in missing or damaged stores, status, an operator storage-health route, start-up and change logging |
| E14-6 | A file restricted inside a directory restricted with `restrictToCurrentUser` keeps Windows' default Administrators and SYSTEM entries (they are explicit, so `/inheritance:r` does not remove them) | **Handled** for backups: their directory gets an inheritable entry, so files keep exactly one. The helper itself is unchanged; no other code restricts a directory. |

**Design: what a restore never does.**
- It never replaces a present, healthy store.
- It never restores replay or idempotency records.
- It never makes a restored pending approval executable: those become `OUTCOME_UNKNOWN`.
- It restores the credential store only when it is missing and the operator asks, since an old copy
  undoes later revocations.

See [operations.md](operations.md).

**Residual:**
- Backups are offline and manual.
- Everything after the last backup is lost with the disk.
- Backups have the same same-account trust as the stores.
- No recovery drill has been run on a real installation; only automated tests on temporary
  directories.

## M3-E E13: storage integrity and repository hardening

**Findings before implementation** (all reproduced in code and covered by tests):

| # | Finding | Status |
|---|---|---|
| E13-1 | Parent directories of the state files were never checked: a junction or symbolic link above a journal, the audit log or a credential-store write silently redirected it | **Fixed:** every ancestor directory is checked before and after creating directories |
| E13-2 | The single-writer lock was checked only at open: removed or replaced while the API ran, a second process could write the same journal | **Fixed:** the lock is verified before every write; a lost lock stops writing (503) |
| E13-3 | A record cut short by a crash stayed in the file and was read as damage at the next restart, quarantining the approval it named (an E12 defect) | **Fixed:** stores rewrite the journal after such a crash |
| E13-4 | The journals had no protection against silently modified, deleted or reordered records; a single changed character in an approval could be accepted | **Fixed as corruption detection:** an integrity chain on all four state files, fail-safe recovery, damaged copies preserved |
| E13-5 | The secret scan had no pre-commit enforcement and did not know AgentShield's own credential formats | **Fixed:** a staged scan with a pre-commit hook, refusal of env, credential and state files, and `asag_`/`asag2_` patterns |

**Tamper evidence: reported, not implemented.** Authenticating the journals needs a key outside
the reach of the API's Windows account, which owns the files. The options are a separate signing
service account, a TPM-bound key, or an external anchor, and each brings a key-management model
this prototype does not have. See [storage-integrity.md](storage-integrity.md). The implemented chain is corruption detection, and is
documented as such.

**Residual:** the API's account or an administrator can still rewrite any state file
undetectably; whole records removed from the end of a file are not detected; and the hook can be
skipped with `--no-verify`.
