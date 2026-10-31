# Agent identity (M3-D)

Status: implemented and verified with offline unit, CLI and route tests, plus Windows
permission checks on temporary files. Not yet exercised against a running server, a
browser, or a real agent.

M3-C gave each agent a server-side policy, but the agent was whatever id the request
named. With M3-D each agent has its own credential. The server works out the agent from
the credential, never from the request, so a caller can only act as an agent whose
credential it holds.

## Two kinds of caller

| | Operator | Agent |
|---|---|---|
| Authenticates with | the API token (`Authorization: Bearer <token>`) or a dashboard session | its credential (`Authorization: Bearer asag_<keyId>.<secret>`) |
| Can use | every `/api` route except custom evaluations | `POST /api/evaluate` with a custom request, and nothing else |
| Seeded scenarios | yes (the dashboard) | no: `403 operator-required` |
| Custom evaluations | no: `403 agent-credential-required` (no compatibility mode) | yes, as itself |
| Approve or reject | yes: the only approver | no: `403 operator-required`, even for its own request |
| Events, approvals, policies, scans, model status | yes | no: `403 operator-required` |

The operator layer is unchanged from M0. A bearer value that starts with `asag_` is only
ever checked as an agent credential, never against the operator token, and an operator
token may not start with `asag_` (the API refuses to start with one). An agent
credential is not a dashboard sign-in: `GET /api/session` reports it as not signed in
without checking it at all (so that route reveals nothing about any agent credential), and
it cannot be used to log in.

Every route an agent may not use is refused by one rule placed before all route
handlers, so routes added later are operator-only by default.

## Credentials

A credential is `asag_<keyId>.<secret>`, 65 characters:

- `keyId`: 16 lower-case hex digits (8 random bytes), a public identifier like an access
  key id. It appears in `list`, logs and operator events.
- `secret`: 43 base64url characters (32 bytes from `crypto.randomBytes`, 256 bits).

The server stores only `sha256("agentshield-agent-credential-v1\0" + keyId + "\0" + secret)`.
The fixed prefix separates this from any other use of SHA-256, and including the key id
means two records' hashes cannot be swapped. With a 256-bit random secret a fast hash is
enough: guessing a secret from its hash is not feasible, so a slow password hash would
add nothing. Digests are compared with `crypto.timingSafeEqual`. An unknown key id still
costs one comparison against a dummy digest, so response timing does not reveal which
key ids exist.

## The credential store

`%LOCALAPPDATA%\AgentShield\agent-credentials.json` (next to the API token), or the path
in `AGENT_CREDENTIAL_FILE`. It never holds a secret:

```json
{
  "schemaVersion": 1,
  "credentials": [
    {
      "keyId": "3f9a1c2b7d4e6f80",
      "agentId": "report-writer",
      "sha256": "<64 lower-case hex digits>",
      "label": "nightly report job",
      "createdAt": "2026-11-01T09:00:00.000Z",
      "expiresAt": "2027-01-30T09:00:00.000Z",
      "revokedAt": null
    }
  ]
}
```

Validation is strict:

- Every field is required and no other field is allowed.
- `agentId` follows the M3-C pattern.
- Timestamps are ISO 8601 UTC with milliseconds. `expiresAt` is after `createdAt` and at
  most 365 days later.
- Duplicate key ids and duplicate hashes are refused.
- An agent can have at most 4 active credentials (revoked and expired ones do not count).
- The file can be at most 256 KB and hold at most 1,000 credentials.

| Situation | Result |
|---|---|
| No file | No agent credentials. Every agent gets `401`; the dashboard works. |
| Invalid file at start-up | The API does not start: `agent-credentials status=invalid-config reason=...`. |
| File changed and valid | Picked up within 2 seconds. |
| File changed and invalid | Every agent credential is rejected until the file is valid again (`agent-credentials status=invalid ... effect=all-agent-credentials-rejected`). The previous credentials are not kept. The dashboard keeps working. |
| File deleted | No agent credentials. |
| Credential for an agent with no policy | Loads with a warning (`reason=no-policy`). The agent authenticates but gets the M3-C default-deny BLOCK. It never gets an implicit policy. |

**Hot reload.** On use (an agent request or an approval), and at most every 2 seconds,
the server compares the file's size, timestamps and file id. An edit or an atomic
replacement (a new file renamed over the old one) changes at least one of them, and the
file is then read and validated again. A credential revoked in the file stops working at
the latest 2 seconds after the change. Error messages name the position and the expected
field or format, never a value or an unknown field's name from the file.

**Permissions.** The CLI writes the store atomically:

1. It creates an empty temporary file next to the store.
2. It removes inherited permissions and grants only the current Windows user full control
   (`icacls ... /inheritance:r /grant:r *<your SID>:(F)`, using `%SystemRoot%\System32`
   tools by absolute path).
3. Only then does it write and flush the content, and rename the file into place.

The content never exists in a file other accounts can read. If permissions cannot be
set, nothing is written. On other systems the file mode is 0600.

## Provisioning and delivery

```powershell
npm run agent-credential -w @agentshield/api -- create --agent report-writer --label "nightly report job"
npm run agent-credential -w @agentshield/api -- create --agent report-writer --days 30 --out C:\secure\report-writer.credential
npm run agent-credential -w @agentshield/api -- list
npm run agent-credential -w @agentshield/api -- revoke --key 3f9a1c2b7d4e6f80
npm run agent-credential -w @agentshield/api -- rotate --key 3f9a1c2b7d4e6f80 [--revoke-old]
```

Every command takes `--file <store>`. The CLI reads `AGENT_CREDENTIAL_FILE` from `.env`
the same way the server does, so both use the same store.

- **`create`** prints the credential exactly once, on standard output. With `--out` it
  writes the credential to a new file readable only by you and does not print it. It
  never replaces an existing file. The default expiry is 90 days; `--days` accepts 1 to
  365.
- **Delivery.** Move the credential to the agent's secret storage straight away and clear
  your terminal. No command takes a secret as an argument, and none prints one except
  `create` and `rotate` (once).
- **`list`** shows key id, agent, status, label and dates. It never shows a hash or secret.
- The CLI validates the store before every write, refuses to write over an invalid store,
  and keeps revoked records for the audit trail. A lock file stops two commands from
  changing the store at once. If a command was interrupted, delete the `.lock` file next
  to the store.

## Expiry, rotation and revocation

- **Expiry.** Every credential expires after at most 365 days (90 by default). An expired
  credential gets the same `401` as any other invalid one.
- **Rotation without downtime.** Run `rotate --key <old>` and give the new credential to
  the agent. Once the agent uses it, run `revoke --key <old>`. An agent may hold up to 4
  active credentials, which leaves room for the overlap.
- **Revocation.** Run `revoke --key <keyId>`. A running API stops accepting the
  credential within 2 seconds, without a restart.
- **Pending approvals.** An approval made with a credential that has since been revoked,
  expired or removed (or that cannot be checked because the store is invalid) cannot
  execute. Approving it returns `409 BLOCKED_ON_RECHECK` with rule
  `identity.credential-invalid`, and nothing runs. Rotating with `--revoke-old` therefore
  also stops the old credential's pending approvals.

## Identity on each request

For `POST /api/evaluate` with an agent credential:

1. The agent is the credential's. A body `agentId` is optional.
2. A body `agentId` equal to the agent's is accepted. A malformed one is a `400`
   (`invalid-agent-id`).
3. A different, well-formed `agentId` is a `403` (`agent-identity-mismatch`). Nothing is
   evaluated or executed. A security event (`lifecycle: IDENTITY_MISMATCH`, rule
   `identity.agent-mismatch`) records the authenticated agent, the claimed id
   (`claimedAgentId`, shown as `[REDACTED]` if it looks like a secret) and the credential
   key id.
4. The agent's M3-C policy is applied unchanged: the request can only narrow it, an
   agent with no policy is blocked, and hard deny and the data-leak guard override any
   policy. Muse remains advisory only.

## Audit attribution

Events and approvals carry `actor`:

- `{ kind: "agent", credentialId: "<keyId>" }` for an agent's request.
- `{ kind: "operator", method: "session" | "bearer" }` for a seeded scenario, and for
  approve and reject.

Approvals show who asked (`requestedBy`). The key id is the only part of a credential
that is ever shown, and only to the operator. Secrets and hashes never appear in a
response, event, approval, error or log. Token-shaped agent ids and claimed ids are
redacted as described in [agent-policies.md](agent-policies.md).

**Server logs** (standard error) contain no secrets:

- `agent-auth status=failed reason=<malformed|unknown-key|wrong-secret|revoked|expired|store-unavailable> keyId=<keyId or none>`
- `agent-credentials status=reloaded|invalid|warning ...`

## Failed attempts

Every `Authorization` header is verified first. A valid credential or operator token is
always accepted, and a success never counts as a failure. Failed `Authorization`-header
attempts are counted per client address. After 20 in a minute
(`API_AUTH_FAILURE_RATE_LIMIT_PER_MINUTE`), further *failed* attempts get `429` instead
of `401`, and are no longer logged, until the minute ends.

- The API listens on loopback only, so the count is shared by every local caller. A local
  process sending bad credentials can make other callers' bad attempts get `429`, but it
  cannot block a valid credential.
- Dashboard sessions (cookies) are neither counted nor limited here.
- `GET /api/session` never verifies agent credentials, so it offers no way around the
  limit.
- Verifying a credential is one SHA-256 and one comparison, and every `/api` request is
  also under the general request limit (`API_RATE_LIMIT_PER_MINUTE`).

## Incident response

If a credential may have leaked:

1. Revoke it: `revoke --key <keyId>`, or `rotate --key <keyId> --revoke-old` to issue a
   replacement in the same step. It stops working within 2 seconds, and its pending
   approvals can no longer execute.
2. Review the dashboard's events for that `credentialId` and for `IDENTITY_MISMATCH`
   events, and check the API's standard error for `agent-auth status=failed` lines.
3. If the store itself may have been changed, check it with `list`. An invalid store
   rejects every agent until it is fixed.
4. If the operator token leaked, rotate it as well (delete the token file and restart
   the API). Operator access includes approving.

## Limitations

- **Bearer credentials can be replayed.** Anyone who obtains a credential can act as that
  agent until it is revoked or expires. Signed requests, which limit replay, are deferred
  to the M3-E review.
- **The operator is fully trusted.** The operator issues credentials and approves
  actions; there is a single operator with no roles.
- **Agents cannot yet read the status of their own approvals.** This is deferred to M3-E.
- **The API is plain HTTP on loopback**, so a local process able to capture loopback
  traffic could read credentials in transit.
- **The failed-attempt limit is per client address.** Locally that is the whole machine,
  so a local process sending bad credentials can make other callers' *failed* attempts
  get `429` rather than `401` for up to a minute. Valid credentials are not affected. The
  general per-address request limits (all requests, evaluations, approvals) are shared
  the same way.
- **Revocation takes up to 2 seconds to apply.** It also depends on the file system
  updating size, timestamps or file id on every change, which NTFS does.
- **CLI output.** A credential printed by `create` can remain in terminal scrollback.
  Prefer `--out`.
- **Verification so far** is offline tests and Windows permission checks on temporary
  files only.

## Proposed follow-up: detecting leaked agent credentials (U7, not implemented)

The scanner, the data-leak guard and the repository secret scan do not know the `asag_`
format yet. Changing them needs a separate review. The recommendation:

- **Pattern:** `(?<![A-Za-z0-9_])asag_[0-9a-f]{16}\.[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])`.
  The fixed prefix, exact lengths and the `.` separator make false positives unlikely.
- **Data-leak guard** (`packages/engine/src/scanner/scan.ts`, outbound secret detection):
  an action whose type, tool, destination, summary or payload carries an agent
  credential would be a hard BLOCK. This includes an agent trying to send out its own
  credential. Public responses and events would then show the value as `[REDACTED]`
  through the existing redaction.
- **Repository secret scan** (`scripts/secret-scan.mjs`): add the same pattern so a
  credential pasted into a tracked file or commit fails `npm run security:verify`.
- **Tests:** detection inside each action field, at text boundaries, inside JSON and URL
  encoding; no detection for a 64-character variant or upper-case key id; redaction in
  events and approvals; secret-scan fixtures built at runtime so the repository itself
  never contains a credential-shaped literal.
