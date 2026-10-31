# @agentshield/agent-sdk

The official TypeScript client for AgentShield agents (M3-E E5).

It signs every request with the agent's Ed25519 key using the AgentShield signed-request
protocol (`AGENTSHIELD-SIG-V1`, from `@agentshield/agent-protocol`), and talks to exactly
three routes:

| Method | Route | Notes |
|---|---|---|
| `evaluate(request)` | `POST /api/evaluate` | Never retried automatically |
| `getApproval(id)` | `GET /api/agent/approvals/:id` | Returns `null` for the server's uniform 404 |
| `listApprovals(options)` | `GET /api/agent/approvals` | Newest first, pages via `before` |

It also provides `iterateApprovals` (follows pages) and `waitForApproval` (polls until a
decision). There is no generic request method, and nothing that approves, rejects or
executes an action: only the operator can do that.

Requirements: Node.js 22 (it uses the built-in `fetch` and `node:crypto`). There are no
third-party runtime dependencies.

## Setup in this workspace

The SDK is a workspace package, so `npm install` at the repository root links it. Build it
after the protocol package:

```powershell
npm run build -w @agentshield/agent-protocol
npm run build -w @agentshield/agent-sdk
```

Then import it from another workspace package that lists `"@agentshield/agent-sdk": "*"`:

```ts
import { AgentCredential, AgentShieldClient } from "@agentshield/agent-sdk";
```

## Credentials

The operator issues an Ed25519 credential for the agent (see `docs/agent-identity.md`):

```powershell
npm run agent-credential -w @agentshield/api -- create --agent report-writer --out C:\secure\report-writer.key
```

The file holds one line, `asag2_<keyId>.<key>`. `<key>` is the agent's private key
(PKCS#8 DER, base64url). Keep the file readable only by the agent's account; `--out`
already restricts it that way. Load it from an explicit source:

```ts
const credential = AgentCredential.fromFile("C:\\secure\\report-writer.key");
// or, from an environment variable you name explicitly:
const fromEnv = AgentCredential.fromEnv("AGENTSHIELD_AGENT_CREDENTIAL");
```

**Where the private key lives.** It is held in a private field of the `AgentCredential`
object and is only used to sign.
- It is never sent to AgentShield.
- It never appears in `JSON.stringify(credential)`, `String(credential)`, `util.inspect`
  or any error message. Those show the public `keyId` only.
- A malformed credential throws `CredentialError` with a fixed message that does not echo
  the input.

**What the SDK cannot check.** Whether a credential has expired or been revoked is known
only to the server. Such a credential fails with `AuthenticationError`.

## Evaluating an action

```ts
const client = new AgentShieldClient({ baseUrl: "http://127.0.0.1:4000", credential });

const result = await client.evaluate({
  intent: { task: "Summarize the quarterly report" },
  action: {
    type: "create_summary",
    tool: "simulated.workspace.createSummary",
    destination: "simulated-workspace",
    summary: "Create a summary of the report",
  },
  untrustedContent: { source: "document", text: documentText },
});

if (result.decision === "ALLOW") {
  // result.executed tells whether AgentShield ran the (simulated) action.
} else if (result.decision === "CONFIRM") {
  // An operator must approve: follow result.approvalId.
} else {
  // BLOCK: result.findings and result.explanation say why.
}
```

**What is sent.** Only `intent`, `action` and `untrustedContent`. The agent's identity
always comes from the credential, never from the request.

**Size limit.** Requests larger than 32 KB (the server's limit) are refused before
sending.

## Following an approval

```ts
if (result.approvalId) {
  const final = await client.waitForApproval(result.approvalId, { timeoutMs: 16 * 60 * 1000 });
  console.log(final.status, final.executed); // e.g. "EXECUTED", true
}

const page = await client.listApprovals({ limit: 20, status: "PENDING" });
for await (const approval of client.iterateApprovals({ limit: 50 })) {
  // every approval of this agent, newest first
}
```

**What an approval contains.** Exactly six fields: `id`, `status`, `createdAt`,
`expiresAt`, `executed` and `pollAfterSeconds`. A response with any other shape is
rejected with `ResponseFormatError`.

**Missing approvals.** `getApproval` returns `null` when the approval does not exist or
belongs to another agent; the server does not say which. `waitForApproval` throws
`ApprovalNotFoundError` in that case, and `WaitTimeoutError` if the approval is still
pending at the end.

## Errors

Every error is an `AgentShieldError` with a `code` and, when the server answered,
`details.status` and the server's fixed-text `details.reason`.

| Error | Meaning |
|---|---|
| `CredentialError` | The local credential is missing or malformed |
| `ConfigurationError` | Invalid client options |
| `InvalidArgumentError` | A bad argument; nothing was sent |
| `AuthenticationError` (401) | Unknown, revoked or expired credential, wrong key, clock too far off, or the request was signed before the server started. Not processed. |
| `ForbiddenError` (403) | Refused, with a reason such as `operator-required` |
| `BadRequestError` (400 / 413 / 415) | An invalid request; not processed |
| `RateLimitedError` (429) | Rate limited (`details.retryAfterSeconds`) |
| `ServiceUnavailableError` (503) | For example, the replay cache or approval queue is full |
| `ServerError` | Any other HTTP error |
| `TimeoutError` | No answer within `timeoutMs` (default 10 s) |
| `NetworkError` | AgentShield could not be reached |
| `ResponseFormatError` | The response was not JSON, had the wrong shape, or was over 1 MB |

```ts
import { AuthenticationError, RateLimitedError, TimeoutError } from "@agentshield/agent-sdk";

try {
  await client.evaluate(request);
} catch (error) {
  if (error instanceof AuthenticationError) {
    // Ask the operator to check or rotate this agent's credential.
  } else if (error instanceof TimeoutError) {
    // The evaluation may or may not have run: check listApprovals before sending it again.
  } else if (error instanceof RateLimitedError) {
    // Wait error.details.retryAfterSeconds before trying again.
  } else {
    throw error;
  }
}
```

## Retries

Every attempt is signed again, with a new timestamp, a new 128-bit nonce and a new
signature. A nonce is never reused.

**`evaluate` is never retried.** The server does not yet deduplicate evaluations, so a
repeated evaluation could run an action twice.
- After a `TimeoutError` or `NetworkError`, the evaluation may or may not have been
  processed: check `listApprovals` before deciding to send it again.
- A `401`, `400`, `403`, `413`, `415` or `429` means it was not processed, so re-sending
  is the caller's decision.

**GET requests** (`getApproval`, `listApprovals`) are retried up to `getRetries` extra
times (default 2, at most 5):
- after a network error or timeout;
- after `429` or `503`, waiting for `Retry-After` if it is at most 5 seconds, otherwise
  reporting the error straight away;
- **once** after a `401`. This covers a request signed just before the server restarted,
  which the server's start-up fence refuses. A second `401` is reported as
  `AuthenticationError`.

`400`, `403` and `404` are never retried.

## Options

```ts
new AgentShieldClient({
  baseUrl: "http://127.0.0.1:4000", // origin only; loopback unless allowRemote
  credential,
  timeoutMs: 10_000,                 // 100 to 120000
  getRetries: 2,                     // 0 to 5
  allowRemote: false,                // true allows a non-loopback host, https only
});
```

**Redirects** are never followed.

**`fetch`, `now` and `sleep`** can be replaced, for tests.

## Security notes and limitations

- **The private key is the agent's identity.** Anyone who can read the credential file or
  the agent process's memory can act as the agent until the operator revokes the
  credential or it expires. The SDK cannot erase the key from memory.
- **The SDK does not check file permissions.** Use `agent-credential create --out`, which
  restricts the file to the current Windows user, and keep it that way.
- **`AgentCredential.sign` is public.** Whoever holds the credential object can sign any
  bytes with it, just as they could with the file itself. The client only ever signs its
  three routes.
- **Signatures protect the request, not the response.** On the default loopback HTTP
  setup, a local process that can capture loopback traffic can read requests and
  responses.
- **A timed-out evaluate is ambiguous.** It may or may not have run. Server-side
  idempotency keys are not implemented yet.
