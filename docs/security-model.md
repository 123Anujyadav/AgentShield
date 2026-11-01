# Security model and threat boundaries

This document states what AgentShield's agent integration protects against, and what it
does not, as implemented at M3-E E6. It is meant to be read before you rely on AgentShield
for anything.

> **Read this first.** AgentShield is a local-first prototype. It is not production-ready.
> - Execution is simulated: the allowlisted handlers have no real side effects.
> - Detection is rule-based and does not catch every attack.
> - The API listens on IPv4 loopback only and serves plain HTTP.
>
> Nothing here has been exercised against real agents, real data or a deployed server. The
> evidence is automated tests, including end-to-end tests of the SDK and the reference agent
> against the real API app on a loopback port.

**How it works:** [architecture.md](architecture.md).
**Credential and signature details:** [agent-identity.md](agent-identity.md).
**Repository secret handling:** [security-baseline.md](security-baseline.md).

## Trust model

| Party | Trust |
|---|---|
| **The operator** (holder of the API token or a dashboard session) | Fully trusted. Issues and revokes credentials, writes policies, approves and rejects. There is one shared operator with no user accounts or roles. |
| **An agent** (holder of an agent private key) | Trusted only to act as itself, within its server-side policy. It cannot approve, reject, read other agents' approvals or use operator routes. |
| **Untrusted content** (documents, web pages, tool output the agent read) | Not trusted at all. Scanned for prompt injection. It can escalate a decision to `CONFIRM`, never relax one. |
| **Other local processes** running as the same Windows user | Effectively trusted. They can read the API token file, an agent's key file and loopback traffic. See the limitations below. |

## What AgentShield protects against

Each item names the mechanism and its limit.

- **Impersonating another agent.** The agent is taken from the credential that signed the
  request, never from the request body, path or query. A mismatching body `agentId` is
  refused (`403`) and recorded.
  - **Limit:** whoever holds an agent's private key *is* that agent.
- **Widening an agent's permissions from the request.** The server-held policy is
  authoritative, and the request can only narrow it. An agent with no policy is always
  blocked.
  - **Limit:** a policy that is too broad is still too broad.
- **An agent approving its own action.** Approve and reject are operator-only routes;
  agent credentials get `403 operator-required`. The SDK has no approve or reject method.
- **Tampering with a signed request in transit.** The signature covers the method, host,
  exact target, timestamp, nonce, key id and the SHA-256 of the exact body bytes. Any
  change makes verification fail (`401`).
- **Replaying a captured signed request.**
  - Timestamps outside ±30 seconds are refused.
  - Each `(keyId, nonce)` is accepted once within that window.
  - Anything signed before the API process started is refused (the start-up fence).
- **Using a stolen bearer secret.** Ed25519 credentials never send the private key. Legacy
  bearer credentials are disabled unless `AGENT_BEARER_ALLOWED=true`.
- **Probing for credentials or approvals.**
  - Every authentication failure gets the same `401`, with a dummy verification for
    unknown key ids.
  - Another agent's approval and an unknown id get the same `404`.
  - Failed attempts are rate limited.
- **Executing a blocked action.** `BLOCK` creates no approval and can never execute.
- **Executing an approved action that is no longer allowed.** Approval re-checks the
  requesting credential, the policy hash and the full evaluation before anything runs.
- **Prompt injection steering an otherwise allowed action.** Suspicious untrusted content
  escalates the action to `CONFIRM`, so a person decides.
  - **Limit:** the scanner is rule-based. Paraphrases, other languages, encodings and novel
    phrasing can evade it.
- **Secrets leaking through action fields.** The data-leak guard hard-blocks documented
  credential patterns and email addresses in outbound action fields.
  - **Limit:** only the documented patterns are detected. AgentShield's own `asag_` and
    `asag2_` formats are not detected yet (proposal U7 in agent-identity.md).
- **Leaking secrets through the SDK.**
  - Credential errors have fixed messages.
  - `AgentCredential` serialises to its key id only.
  - Error messages never contain the key, `Authorization` header or body.
- **DNS rebinding and cross-site requests to the API.** It allows only `localhost`,
  `127.0.0.1` and `[::1]` as `Host`, and only the dashboard as browser origin.

## What AgentShield does not protect against

- **A compromised agent machine or account.** Malware or another process running as the
  agent's user can read its key file or process memory and sign as the agent. This lasts
  until the operator revokes the credential or it expires. The SDK cannot erase the key
  from memory, and does not check file permissions.
- **A compromised operator.** The operator token allows approving any pending action,
  issuing credentials (with the CLI and file access) and reading every event. Any process
  running as the operator's Windows user can read the token file.
- **An agent misbehaving within its policy.** AgentShield judges the actions an agent
  *submits*. It cannot stop an agent from doing something without asking AgentShield first.
  - **Integrations must route every side effect through `evaluate`**, and act only on the
    outcome. AgentShield does not sandbox or monitor the agent process.
- **Confidentiality on the wire.** The API is plain HTTP on loopback. Signatures protect
  authenticity and integrity, not confidentiality, and responses are not signed. A local
  process that can capture loopback traffic can read request bodies (including untrusted
  content) and responses.
- **Every prompt-injection or data-leak technique.** Detection is deterministic and
  pattern-based, with documented gaps (see the main README).
- **Real-world consequences.** Handlers are simulated. "Executed" means AgentShield's
  simulator ran. It does not mean an email was sent or a file was written.
- **Availability.** Most rate limits are per client address. On a single machine that
  address is shared, so a local process can exhaust a shared limit. Since M3-E E9 the
  evaluate limit and the pending-approval share (100 of 500) are per agent, so one agent
  cannot use them up for others, but several misbehaving agents together still can. The
  replay-cache and approval-store limits can also return `429` or `503`. Since M3-E E10
  events are kept in a durable audit log that never drops old events; when it is full or
  failing, evaluations and approvals are refused (`503`) until the operator acts.

## Agent vs operator permissions

| Capability | Operator | Agent |
|---|---|---|
| Custom `POST /api/evaluate` | No (`403 agent-credential-required`) | Yes, as itself |
| Seeded scenarios | Yes | No (`403 operator-required`) |
| Read own approvals (`/api/agent/approvals`) | No (`403 agent-credential-required`); uses `/api/approvals` | Yes, own agent only, six fields |
| Approve or reject | Yes, the only approver | **Never** (`403 operator-required`) |
| Events, approvals, policies, scans, model status | Yes | No (`403 operator-required`) |
| Issue, rotate or revoke credentials | Yes (the CLI, with access to the store file) | No |
| Change policies | Yes (edit `AGENT_POLICY_FILE`, restart the API) | No |

## Private-key handling

**Who holds the key.**
- The CLI generates each Ed25519 key pair. The credential store keeps only the public key.
- The private key is delivered once:
  - in a `--out` file, created restricted to the current Windows user and never
    overwritten;
  - or printed once on standard output, where it can stay in terminal scrollback. Prefer
    `--out`.
- **The agent loads it only through the SDK's explicit loaders.** These are
  `AgentCredential.fromFile` (a file of at most 1 KB), `fromEnv` (a variable you name) and
  `fromString`. No default location or variable is ever read implicitly.

**The key in use.**
- The key never leaves the agent process. It is used to sign and is not sent to
  AgentShield.
- A private key sent as a bearer token is refused, and logged so the operator can rotate
  it.

**Storing it.**
- Keep key files outside the repository and readable only by the agent's account.
- Never put a key in a policy, document, ticket or chat.
- An environment variable is readable by the agent's child processes, and possibly by
  anything that can inspect the process environment. Prefer a file.

## Replay protection limitations

- **The replay cache is per process.** Since M3-E E11 it is persisted, so a restart does not
  reset it, and a lock file stops two processes from sharing one journal. Running more than
  one API process, each with its own journal, against the same credentials would still let
  a request be accepted once by each. See [replay-and-idempotency.md](replay-and-idempotency.md).
- **After a restart, the start-up fence** (not the cache) refuses earlier requests. A
  request signed just before a restart and sent after it is refused; the SDK re-signs a
  GET once in that case.
- **A request that is signed but never delivered** can be sent once by whoever captured
  it, within its skew window (±30 seconds by default).
- **Clock dependence.** A server or agent clock more than the skew away refuses every
  request (`401`). A larger skew setting widens the replay window.
- **Legacy bearer credentials** (only while `AGENT_BEARER_ALLOWED=true`) can be replayed
  until revoked.

## Approval and execution semantics

### Why an approval is not equivalent to successful execution

An operator's **approval is a request to run**, not a guarantee that anything ran:

1. **The recheck can refuse it.** Approving re-checks, in order, the requesting credential,
   the policy hash and the full evaluation. Any failure ends in `BLOCKED_ON_RECHECK`, and
   nothing runs.
2. **There may be no handler.** If the action type has no simulated handler, the approval
   ends in `APPROVED_NOT_EXECUTED`.
3. **Only `EXECUTED` with `executed: true`** means AgentShield's simulator ran the action.
   Even then the effect is simulated.
4. **The agent may never learn the result.** It can stop waiting, lose its connection,
   restart or have its credential revoked before it observes the final status. Final
   records can also be dropped from memory when the approval store is full, and every
   approval is lost on an API restart.
5. **An approval id alone is not proof of identity across restarts.** Ids restart at
   `apr-1` in a new API process, so a later approval can reuse an id. Compare the
   approval's `createdAt` with the `approvalCreatedAt` from the evaluate response before
   acting on it (the reference agent does).

**What an agent should do.** Treat only an observed `EXECUTED` with `executed: true` as a
go-ahead for any follow-up work. Treat every other status, and every failure to observe
one, as "not done". The reference agent does exactly this.

### Evaluations and idempotency (M3-E E11)

**Never resent with a new key.** The SDK still never retries `evaluate` automatically. After a
timeout, network error, `5xx` or malformed response, the evaluation may or may not have been
processed, and an `ALLOW` may already have executed. Resending it **without** idempotency
could run the action twice.

**Retry with the same key instead.** Every SDK evaluation carries an idempotency key, and the
key of a failed attempt is in `error.details.idempotencyKey`. Retrying with that key and the
same request returns the original result if the first attempt completed, and never runs a
second evaluation for the key.
- If the first attempt started but its result was lost (for example the API stopped), the
  answer is `409 idempotency-outcome-unknown`.
- That case is still for a person to reconcile.

**Limits.** Records last 15 minutes, with explicit capacity limits.
- A key reused after that is a new evaluation.
- Requests without a key are not idempotent.

Details: [replay-and-idempotency.md](replay-and-idempotency.md).

## Credential rotation and revocation

- **Rotation without downtime.**
  1. `rotate --key <old>` issues a new credential for the same agent.
  2. Deploy it to the agent.
  3. `revoke --key <old>` once the agent uses the new one.

  Up to 4 active credentials per agent leave room for the overlap. Approvals stay visible
  to the agent across rotation.
- **Revocation** reaches a running API within 2 seconds; it relies on the file system
  updating size, timestamps or file id, which NTFS does. After that:
  - every request with the revoked key gets `401`;
  - its pending approvals end in `BLOCKED_ON_RECHECK` if approved.
- **Expiry** is 90 days by default and 365 at most. An expired credential gets the same
  `401`. The SDK cannot see expiry or revocation locally.
- **Incident response:** see [agent-identity.md](agent-identity.md#incident-response).

## Local HTTP confidentiality limitations

**What any local process can see.** The API is plain HTTP on `127.0.0.1`, so any local
process that can capture loopback traffic can read requests and responses. That includes
untrusted content, decisions and explanations. The signature scheme prevents tampering and
replay; it does not encrypt.

**Remote use.** The SDK refuses a non-loopback `baseUrl` unless `allowRemote` is set, and
then requires https. The API itself only listens on loopback and has not been deployed or
hardened for remote access.

## Multi-process and restart limitations

**An API restart loses:**
- every pending approval: an agent waiting on one then gets `404` (approval missing);
- the replay cache;
- rate-limit counters;
- dashboard sessions.

**It keeps:** credentials and policies, which are files, and (since M3-E E10) every activity
event written to the durable audit log. Policy changes need a restart. The audit log is not
tamper-proof: a local user with write access can change it ([audit-log.md](audit-log.md)).

**One process per credential store.** The design assumes one API process. Several
processes would each have their own replay cache, approval store and events.

**Agent restarts** lose whatever the agent kept in memory. For the reference agent, that is
its saved summaries and the approvals it was following. Design your agent's own
persistence so that a retry after a restart reuses the original idempotency key (keys last 15
minutes on the server).

## Reporting and verification status

**What has been verified:**
- unit, route and end-to-end tests: the SDK and reference agent against the real API app
  on an ephemeral loopback port, with deterministic test keys and temporary stores;
- Windows permission checks on temporary files;
- the repository secret scan.

**What has not:** browser walkthroughs of agent approvals, a separately started server
under load, and any deployment beyond loopback.
