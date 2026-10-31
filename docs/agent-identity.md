# Agent identity (M3-D, with M3-E E2 credential schemes and E3 signed requests)

Status: implemented and verified with offline unit, CLI and route tests, plus Windows
permission checks on temporary files. Not yet exercised against a running server, a
browser, or a real agent.

**Since M3-E E3, agents authenticate by signing each request** with their Ed25519 key
(see Signed requests below). Legacy bearer credentials are disabled by default
(`AGENT_BEARER_ALLOWED`, below). The agent SDK (E5) and agent approval-status routes (E4)
are not implemented yet.

M3-C gave each agent a server-side policy, but the agent was whatever id the request
named. With M3-D each agent has its own credential. The server works out the agent from
the credential, never from the request, so a caller can only act as an agent whose
credential it holds.

## Two kinds of caller

| | Operator | Agent |
|---|---|---|
| Authenticates with | the API token (`Authorization: Bearer <token>`) or a dashboard session | signed requests with its Ed25519 key (`Authorization: AGENTSHIELD-SIG-V1 ...`); or, only while `AGENT_BEARER_ALLOWED=true`, a legacy bearer credential (`Authorization: Bearer asag_<keyId>.<secret>`) |
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

Every credential has a public `keyId`: 16 lower-case hex digits (8 random bytes), like an
access key id. It appears in `list`, logs and operator events. There are two schemes, and
they are never interchangeable.

### Ed25519 (the default since M3-E E2)

The CLI generates an Ed25519 key pair with `node:crypto`.

- **The store keeps only the public key**: the raw 32 bytes in unpadded base64url.
- **The agent keeps the private key**, as `asag2_<keyId>.<key>` (87 characters). `<key>`
  is the private key's PKCS#8 DER encoding (48 bytes, RFC 8410) in unpadded base64url.
  Node loads it with
  `crypto.createPrivateKey({ key: Buffer.from(key, "base64url"), format: "der", type: "pkcs8" })`.
- **The private key never leaves the agent machine.** It is used to sign requests
  (see Signed requests) and is never sent to the API. A bearer token starting with `asag2_`
  is refused without being compared with anything, and the API logs
  `reason=private-key-sent-as-bearer keyId=<keyId> action=rotate-this-credential` so the
  operator knows to replace that key.

### Legacy bearer (M3-D)

A legacy bearer credential is `asag_<keyId>.<secret>`, 65 characters. The secret is 43
base64url characters (32 bytes from `crypto.randomBytes`, 256 bits), sent with every
request. Bearer credentials authenticate only while `AGENT_BEARER_ALLOWED=true`. The
server stores only `sha256("agentshield-agent-credential-v1\0" + keyId + "\0" + secret)`.
The fixed prefix separates this from any other use of SHA-256, and including the key id
means two records' hashes cannot be swapped. With a 256-bit random secret a fast hash is
enough: guessing a secret from its hash is not feasible, so a slow password hash would
add nothing. Digests are compared with `crypto.timingSafeEqual`. An unknown key id still
costs one comparison against a dummy digest, so response timing does not reveal which
key ids exist.

## The credential store

`%LOCALAPPDATA%\AgentShield\agent-credentials.json` (next to the API token), or the path
in `AGENT_CREDENTIAL_FILE`. It never holds a secret or a private key. Schema 2 (written by
the CLI since M3-E E2) records each credential's scheme:

```json
{
  "schemaVersion": 2,
  "credentials": [
    {
      "scheme": "ed25519",
      "keyId": "3f9a1c2b7d4e6f80",
      "agentId": "report-writer",
      "publicKey": "<43 base64url characters: the raw 32-byte public key>",
      "label": "nightly report job",
      "createdAt": "2026-11-01T09:00:00.000Z",
      "expiresAt": "2027-01-30T09:00:00.000Z",
      "revokedAt": null
    },
    {
      "scheme": "bearer",
      "keyId": "0a1b2c3d4e5f6a7b",
      "agentId": "legacy-agent",
      "sha256": "<64 lower-case hex digits>",
      "label": null,
      "createdAt": "2026-10-01T09:00:00.000Z",
      "expiresAt": "2026-12-30T09:00:00.000Z",
      "revokedAt": null
    }
  ]
}
```

**Schema 1** (M3-D) is still read.
- Its records have no `scheme` field and keep their original meaning: bearer. They are
  never reinterpreted as Ed25519.
- The first CLI change to the file rewrites it as schema 2, with the same records marked
  `"scheme": "bearer"` and every other field unchanged.

Validation is strict:

- `scheme` is exactly `ed25519` or `bearer` (schema 2). An Ed25519 record has `publicKey`
  and no `sha256`; a bearer record has `sha256` and no `publicKey`. A schema 1 record has
  neither `scheme` nor `publicKey`.
- A public key must be canonical unpadded base64url of exactly 32 bytes.
  - Those bytes must be the canonical encoding of a point on the curve (y below p, no
    "negative zero"), decoded as RFC 8032 section 5.1.3 specifies.
  - The point must not be one of the eight small-order points (the same list libsodium
    uses), and Node must accept it as an Ed25519 key.
  - Node alone accepts small-order points. With one of them as a public key, a fixed
    signature verifies for every message, so such a key makes the store invalid.
- Every field is required and no other field is allowed (so, for example, a `privateKey`
  field makes the store invalid).
- `agentId` follows the M3-C pattern.
- Timestamps are ISO 8601 UTC with milliseconds. `expiresAt` is after `createdAt` and at
  most 365 days later.
- Duplicate key ids, duplicate hashes and duplicate public keys are refused.
- An agent can have at most 4 active credentials of either scheme combined (revoked and
  expired ones do not count).
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
npm run agent-credential -w @agentshield/api -- create --agent report-writer --days 30 --out C:\secure\report-writer.key
npm run agent-credential -w @agentshield/api -- list
npm run agent-credential -w @agentshield/api -- revoke --key 3f9a1c2b7d4e6f80
npm run agent-credential -w @agentshield/api -- rotate --key 3f9a1c2b7d4e6f80 [--revoke-old]
```

`create` and `rotate` issue Ed25519 credentials. `--scheme bearer` issues a legacy bearer
credential instead, and is refused unless `AGENT_BEARER_ALLOWED=true` (see migration below).

Every command takes `--file <store>`. The CLI reads `AGENT_CREDENTIAL_FILE` from `.env`
the same way the server does, so both use the same store.

- **`create`** prints the private key (`asag2_...`) exactly once, on standard output.
  - With `--out` it writes the key to a new file and does not print it. The file is
    restricted to you before any key material is written, and an existing file is never
    replaced.
  - The default expiry is 90 days; `--days` accepts 1 to 365.
- **Delivery.** Move the key to the agent machine's secret storage straight away and clear
  your terminal.
  - No command takes a key or secret as an argument.
  - None prints one, except `create` and `rotate` (once).
- **`list`** shows key id, agent, scheme, status, label and dates. It never shows a hash, a
  public key, a private key or a secret.
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

## Legacy bearer migration (`AGENT_BEARER_ALLOWED`)

`AGENT_BEARER_ALLOWED` is off unless it is exactly `true` (so `TRUE`, `1` or ` true` all
leave it off).

**While it is off (the default):**
- Bearer credentials, including every M3-D schema 1 record, still load and stay listed,
  but they do not authenticate. The API returns the usual `401` and logs
  `reason=bearer-disabled`.
- At start-up and on every reload, the API warns how many active bearer credentials
  cannot be used (`reason=bearer-disabled activeBearerCredentials=N`).
- The CLI refuses `--scheme bearer`.

**Ed25519 credentials do not depend on this setting at all.**

To migrate an agent from bearer to Ed25519:

1. If existing bearer agents must keep working in the meantime, set
   `AGENT_BEARER_ALLOWED=true` temporarily and restart the API. It logs
   `reason=bearer-allowed` at start-up as a reminder.
2. For each bearer credential, run `rotate --key <bearer keyId>`. This issues an Ed25519
   key for the same agent. Add `--revoke-old` to revoke the bearer credential in the same
   step, or revoke it once the agent signs its requests.
3. Remove `AGENT_BEARER_ALLOWED` (or set it to anything but `true`) and restart. Bearer
   is then refused again.

Nothing is converted automatically: a bearer record is never turned into an Ed25519 key.

## Signed requests (M3-E E3)

An agent signs each request with its Ed25519 private key and sends one header:

```
Authorization: AGENTSHIELD-SIG-V1 keyId="<keyId>", ts="<Unix ms>", nonce="<16 random bytes, base64url>", sig="<Ed25519 signature, base64url>"
```

The header format and the signed bytes are defined once, in `@agentshield/agent-protocol`
(`packages/agent-protocol/src/canonical.ts`). The server verifies with that same code. The
signature covers:
- the method;
- the `Host` header (lower-cased);
- the exact request target (path and query, as sent, not normalised);
- the timestamp, the nonce and the key id;
- the SHA-256 of the exact raw body bytes.

The server checks, in this order:

1. **Header.** The exact format, at most 512 characters. A header with this scheme is only
   ever checked as a signature: never as a bearer token, never against the operator token,
   and never with a fallback to a dashboard cookie.
2. **Timestamp.** It must not be earlier than the moment this API process started (the
   start-up fence), and must be within the allowed clock skew of the server clock (default
   ±30 seconds). The skew is set with `AGENT_SIGNATURE_MAX_SKEW_SECONDS`: a whole number
   from 5 to 300; unset or empty means 30, and any other value stops the API at start-up.
3. **Body.**
   - The raw bytes are kept as received, before JSON parsing, within the existing 32 KB
     limit (a larger body is refused with `413` before authentication).
   - Other body errors also get fixed text before authentication: malformed JSON or a
     malformed compressed body gets `400`, and an unsupported charset or
     `Content-Encoding` gets `415`. Parser messages are never returned or logged.
   - A body that was not read as JSON, and any `Content-Encoding` other than `identity`,
     are refused.
4. **Canonical request**, built from what was actually received.
5. **Key.** The key id must name an active Ed25519 credential: not unknown, revoked,
   expired, a bearer key, or unverifiable because the store is invalid. One Ed25519
   verification always runs, against a dummy key when the key id is not usable, so
   response time does not reveal which key ids exist.
6. **Signature.** `crypto.verify` (Ed25519) over the canonical bytes. The signature is
   accepted only if its R is not a small-order point and its S is below the group order,
   as libsodium also requires. This is checked in addition to the verification, never
   instead of it.
7. **Replay.** Only now, after a valid signature, is the key id and nonce recorded. A nonce
   already recorded for that key, until its timestamp falls out of the skew window, is a
   replay.

**Responses:**
- Every failure gets the same `401 {"error":"Authentication required."}` as any other
  failed authentication, and counts toward the failed-attempt limit.
- The exceptions come from the replay cache's limits. A key with 600 live nonces gets
  `429`; when 100,000 nonces are live in total, every signed request gets `503`. Both
  carry `Retry-After` and are not counted as failed authentication, since the request was
  signed correctly. Live nonces are never evicted to make room, because that would let
  their requests be replayed.

**What reaches the log:** a line such as
`agent-auth status=failed scheme=signature reason=<reason> keyId=<keyId or none>`. The
reasons are `bad-header`, `before-startup`, `stale`, `future`, `content-encoding`,
`unreadable-body`, `bad-host`, `bad-request`, `unknown-key`, `scheme-mismatch`,
`revoked`, `expired`, `store-unavailable`, `bad-signature`, `replay`, `nonce-key-quota`
and `nonce-capacity`. The header, signature, nonce and any key material are never logged
or echoed.

**Where signed requests are accepted:** only on `POST /api/evaluate`; every other route
answers `403 operator-required` to a signed agent. `GET /api/session` never verifies a
signed header and uses no nonce.

**The replay cache is in memory**, so it is per process and empty after a restart. The
start-up fence closes that gap: any request captured before a restart carries an older
timestamp and is refused. A request signed shortly before a restart and sent after it is
refused too; the agent should sign it again.

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

- **Bearer credentials can be replayed** (only while `AGENT_BEARER_ALLOWED=true`). Anyone
  who obtains one can act as that agent until it is revoked or expires. Signed requests
  never send the private key, and each is accepted once.
- **Signed requests protect authenticity and integrity, not confidentiality.** The API is
  plain HTTP on loopback, so a local process able to capture loopback traffic can read
  request bodies and responses. Responses are not signed.
- **The replay cache is per process and in memory.** It does not span several API
  instances. After a restart the start-up fence, not the cache, refuses earlier requests.
- **A request signed but never delivered** can still be sent by whoever captured it, once,
  within its skew window.
- **An Ed25519 private key is as sensitive as a bearer secret on the agent machine.**
  Whoever holds it can sign as that agent until it is revoked or expires.
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
or `asag2_` formats yet. Changing them needs a separate review. The recommendation:

- **Patterns:**
  - bearer: `(?<![A-Za-z0-9_])asag_[0-9a-f]{16}\.[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])`;
  - Ed25519 private key (M3-E E2): `(?<![A-Za-z0-9_])asag2_[0-9a-f]{16}\.[A-Za-z0-9_-]{64}(?![A-Za-z0-9_-])`.

  The fixed prefixes, exact lengths and the `.` separator make false positives unlikely.
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
