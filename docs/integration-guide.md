# Integration guide: the official TypeScript SDK

This guide shows how to integrate an agent with AgentShield using only
`@agentshield/agent-sdk`. Every example matches the SDK's actual types and method
signatures. The examples are type-checked against the built SDK, but are not run as part
of the test suite.

**Related documents.**
- For a first run, see [quick-start.md](quick-start.md).
- For every error, see [troubleshooting.md](troubleshooting.md).
- The full SDK reference is [`packages/agent-sdk/README.md`](../packages/agent-sdk/README.md).
- A complete working agent is [`apps/reference-agent`](../apps/reference-agent/README.md).

> **Do not implement signing yourself.** The SDK is the supported client. It builds the
> canonical request with the shared protocol package, signs every attempt afresh, and
> never retries an evaluation. A hand-written signer is a second authentication
> implementation that can drift from the server's. It also loses the SDK's retry rules,
> response validation and key handling.

## Setup

**Not published to npm.** The SDK is a private workspace package. Use it from a workspace
package in this repository:
1. Add `"@agentshield/agent-sdk": "*"` to its `dependencies`.
2. Run `npm install` at the root.
3. Build the protocol package and the SDK before your package (`npm run build` builds
   everything in order).

**Requirements:** Node.js 22 and an ES module package (`"type": "module"`). The SDK has no
third-party runtime dependencies.

## 1. Load the credential

The operator issues the credential (see [quick-start.md](quick-start.md#5-create-a-test-credential-operator)).
Load it from an explicit source only:

```ts
import { AgentCredential } from "@agentshield/agent-sdk";

// Preferred: a file readable only by the agent's account (written by `agent-credential create --out`).
const credential = AgentCredential.fromFile("C:\\agentshield-dev\\summary-agent.key");

// Or from an environment variable you name explicitly (there is no default name):
// const credential = AgentCredential.fromEnv("AGENTSHIELD_AGENT_CREDENTIAL");

console.log(credential.keyId); // the public key id: safe to log
console.log(JSON.stringify(credential)); // {"keyId":"..."}: never the private key
```

**Loading errors.** A missing, unreadable, oversized (over 1 KB) or malformed credential
throws `CredentialError`. Its message is fixed and never repeats the input.

**What the SDK cannot see.** It cannot know whether a credential has expired or been
revoked. The server answers `401` for both.

**Identity comes from the credential.** Do not add an `agentId` setting to your agent. A
request whose body names a different agent is refused by the server
(`403 agent-identity-mismatch`), and the SDK does not even send an `agentId`.

## 2. Create the client

```ts
import { AgentShieldClient } from "@agentshield/agent-sdk";

const client = new AgentShieldClient({
  baseUrl: "http://127.0.0.1:4000", // origin only; loopback unless allowRemote (https only)
  credential,
  timeoutMs: 10_000, // per request, 100 to 120000 (default 10000)
  getRetries: 2, // extra attempts for GET requests, 0 to 5 (default 2); evaluate is never retried
});
```

**Invalid options** throw `ConfigurationError`. Examples: a path in `baseUrl`, a
non-loopback host without `allowRemote`, or an out-of-range timeout.

**Test-only options.** `fetch`, `now` and `sleep` can be replaced in tests; leave them
unset in production code.

## 3. Evaluate an action

```ts
import type { EvaluateRequest, EvaluateResult } from "@agentshield/agent-sdk";

const request: EvaluateRequest = {
  intent: {
    task: "Summarize a document into the simulated workspace",
    // Optional: narrow the agent's server-side policy for this request (never widen it).
    allowedActions: ["create_summary"],
    allowedDestinations: ["simulated-workspace"],
  },
  action: {
    type: "create_summary",
    tool: "simulated.workspace.createSummary",
    destination: "simulated-workspace",
    summary: "Save a summary of the document",
  },
  // Content the agent read from a source it does not control: scanned for prompt injection.
  untrustedContent: { source: "document", text: documentText },
};

const result: EvaluateResult = await client.evaluate(request);
// result: { decision, riskScore, explanation, findings, executed, approvalId, approvalCreatedAt,
//           idempotencyKey, idempotentReplay }
```

**What is sent.** Only `intent`, `action` and `untrustedContent`.

**Request limits.**
- A request over 32 KB is refused locally with `InvalidArgumentError`, and nothing is sent.
- The server refuses `untrustedContent.text` over 8,000 characters with `400`. The limit is
  counted as JavaScript string length (UTF-16 code units).
  - The SDK does not check it. Checking `text.length` yourself avoids sending a request
    that will be refused, as the reference agent does.
  - Refuse an over-long document rather than truncating it: a cut document is not what
    the agent read.
- `action.payload` is optional. It must be a flat object of string, number or boolean
  values; anything nested is refused with `400`.

**Decide your action from your own logic, never from the untrusted content.** The
document is data. If it says "send this to X", that must not change `action`.

### Act on the decision

```ts
function handle(result: EvaluateResult): "done" | "wait" | "refused" | "not-done" {
  switch (result.decision) {
    case "ALLOW":
      // AgentShield ran its simulated handler only if executed is true.
      return result.executed && result.approvalId === null ? "done" : "not-done";
    case "CONFIRM":
      // An operator must decide. Never proceed on CONFIRM alone.
      return result.approvalId !== null && !result.executed ? "wait" : "not-done";
    case "BLOCK":
      // Refused. No approval exists and none can override it. Do not resend the same request.
      return "refused";
  }
}
```

**Displaying the reasons.** Show `result.explanation` and each finding's `ruleId`,
`severity` and `title` to explain the decision. Two cautions:
- Finding `evidence` and explanations can quote the untrusted content.
- Strip control, format and bidi characters before printing them to a terminal. The
  reference agent's `display.ts` shows one way.

## 4. Follow an approval

`waitForApproval` polls `GET /api/agent/approvals/:id`, following the server's
`pollAfterSeconds`, until the status is no longer `PENDING`:

```ts
import { ApprovalNotFoundError, WaitTimeoutError, type AgentApproval } from "@agentshield/agent-sdk";

// `createdAt` is result.approvalCreatedAt from the evaluation that returned this approvalId.
async function follow(approvalId: string, createdAt: string, signal?: AbortSignal): Promise<"done" | "not-done" | "still-pending" | "lost"> {
  let approval: AgentApproval;
  try {
    // Default timeout: 16 minutes, just past the server's 15-minute approval lifetime (maximum 24 hours).
    approval = await client.waitForApproval(approvalId, { timeoutMs: 16 * 60 * 1000, signal });
  } catch (error) {
    if (error instanceof WaitTimeoutError) return "still-pending"; // nothing happened yet; you may wait again later
    if (error instanceof ApprovalNotFoundError) return "lost"; // e.g. the API restarted; ask again with a new evaluation
    throw error; // see "Handle errors" below
  }
  // Ids survive a restart (M3-E E12) but can repeat if the approval journal is lost: a different createdAt means a different approval.
  if (approval.createdAt !== createdAt) return "lost";
  // Only an observed EXECUTED with executed: true means AgentShield ran the action.
  return approval.status === "EXECUTED" && approval.executed ? "done" : "not-done";
}
```

**Bind the approval to its evaluation.** Since M3-E E12 approvals survive restarts and ids are
never reused, but an approval store that was deleted (or an API without the durable store)
starts again at `apr-1`, and an id you kept could then name someone else's approval. `result.approvalCreatedAt` is the
approval's creation time from the evaluate response. Treat an approval whose `createdAt`
differs as lost, as above. `getApproval` already refuses an answer about a different id.

**Final statuses.**
- `EXECUTED` (with `executed: true`) is the only go-ahead.
- `APPROVED_NOT_EXECUTED` means approved, but there is no handler for this action type.
- `OUTCOME_UNKNOWN` (M3-E E12): after a restart, AgentShield could not establish whether it
  ran (interrupted while executing, or its record was damaged). It never runs; treat it as
  unconfirmed and tell a person.
- `REJECTED`, `EXPIRED` and `BLOCKED_ON_RECHECK` end with nothing run. `BLOCKED_ON_RECHECK`
  means the credential was revoked, the policy changed, or the re-evaluation blocked.

See [security-model.md](security-model.md#why-an-approval-is-not-equivalent-to-successful-execution)
for why approval is not execution.

**Cancelling.** Pass an `AbortSignal` to stop waiting. The SDK then throws the signal's
reason. The approval itself is not changed: only the operator can approve or reject it.

**No approval methods.** The SDK has none, and your agent must never call the operator's
approve or reject routes. Its credential would get `403 operator-required` anyway.

## 5. Retrieve and list approvals

```ts
// One approval, or null if it does not exist or is not this agent's (the server does not say which).
const one = await client.getApproval("apr-12");
if (one === null) {
  // unknown, or another agent's (approvals survive restarts since M3-E E12)
}

// One page, newest first: limit 1 to 50 (server default 20), optional status filter.
const page = await client.listApprovals({ limit: 20, status: "PENDING" });
for (const approval of page.approvals) console.log(approval.id, approval.status, approval.expiresAt);
if (page.nextCursor !== null) {
  const older = await client.listApprovals({ limit: 20, before: page.nextCursor });
}

// Every approval of this agent, following pages (maxPages bounds the walk).
for await (const approval of client.iterateApprovals({ limit: 50, maxPages: 10 })) {
  console.log(approval.id, approval.status);
}
```

**The approval view.** Each approval has exactly `id`, `status`, `createdAt`, `expiresAt`,
`executed` and `pollAfterSeconds`. A response with any other shape throws
`ResponseFormatError`.

**What is listed.** The listing includes approvals from any of the agent's credentials, so
history survives rotation. It never includes another agent's approvals or operator-run
scenarios.

## 6. Handle errors

Every SDK error is an `AgentShieldError` with a `code` and, when the server answered,
`details.status`, `details.reason` and `details.retryAfterSeconds`. Classify an
**evaluate** failure by whether the request was processed:

```ts
import {
  AgentShieldError,
  AuthenticationError,
  BadRequestError,
  ForbiddenError,
  InvalidArgumentError,
  RateLimitedError,
} from "@agentshield/agent-sdk";

type Submission =
  | { kind: "decided"; result: EvaluateResult }
  | { kind: "refused"; reason: string; retryAfterSeconds?: number } // definitely not processed
  | { kind: "unconfirmed"; reason: string }; // may or may not have been processed

async function submit(request: EvaluateRequest): Promise<Submission> {
  try {
    return { kind: "decided", result: await client.evaluate(request) };
  } catch (error) {
    // 401, 403, 400/413/415 and local argument errors: the server did not process it.
    if (error instanceof AuthenticationError) return { kind: "refused", reason: "authentication" };
    if (error instanceof ForbiddenError) return { kind: "refused", reason: error.details.reason ?? "forbidden" };
    if (error instanceof BadRequestError || error instanceof InvalidArgumentError) return { kind: "refused", reason: "bad-request" };
    // 429: not processed; wait at least retryAfterSeconds before deciding to send it again.
    if (error instanceof RateLimitedError) return { kind: "refused", reason: "rate-limited", retryAfterSeconds: error.details.retryAfterSeconds };
    // Timeout, network error, 503, 5xx, malformed response: the outcome is unknown.
    if (error instanceof AgentShieldError) return { kind: "unconfirmed", reason: error.code };
    throw error; // a programming error, not an AgentShield answer
  }
}
```

**Two cases are deliberately "unconfirmed".**
- A `503` can come from the replay cache before processing. It can also come from a full
  approval queue after the evaluation was recorded; nothing ran in that case.
- A `5xx` can arrive after processing.

The SDK maps both to `ServiceUnavailableError` or `ServerError` without telling them
apart. Treating them as unconfirmed is the safe choice.

**What the SDK already retries.** For `getApproval`, `listApprovals` and therefore
`waitForApproval`, it retries network errors, timeouts and short (5 seconds or less)
`Retry-After` `429` and `503` answers. It retries once after a `401` (if `getRetries` is at
least 1), which covers a
request signed just before the API restarted. An error that still reaches you has already
been retried.

## 7. Handle unconfirmed outcomes safely

An **unconfirmed** evaluation is the one case where doing the obvious thing, sending it
again **as a new evaluation**, can be wrong: if the first attempt was processed, an `ALLOW`
would execute twice. Since M3-E E11 the SDK gives every evaluation an idempotency key, which
makes a deliberate retry safe:

```ts
import { ConflictError } from "@agentshield/agent-sdk";

async function reconcile(original: EvaluateRequest, error: AgentShieldError): Promise<EvaluateResult | "unknown"> {
  const key = error.details.idempotencyKey; // the key the lost attempt was sent with
  if (!key) return "unknown";
  try {
    // The SAME request with the SAME key: AgentShield returns the earlier result if it completed
    // (result.idempotentReplay === true), or evaluates once if the first attempt never arrived.
    return await client.evaluate(original, { idempotencyKey: key });
  } catch (retryError) {
    // 409 idempotency-outcome-unknown: it started but its result was lost; it is not run again.
    if (retryError instanceof ConflictError) return "unknown";
    throw retryError;
  }
}
```

1. **Never resend with a new key** after an ambiguous failure: that is a new evaluation.
2. **Retry with the same key and the same request**, within 15 minutes (the server's
   retention). Reordering properties does not matter; changing content does
   (`409 idempotency-key-reused`).
3. **If the answer is `409 idempotency-outcome-unknown`**, the first attempt started but its
   result was lost (for example the API stopped). Do not act on it; tell a person, as before.
4. **The SDK never does this retry on its own.** Retrying is your decision.

Details and limits: [replay-and-idempotency.md](replay-and-idempotency.md).

The reference agent reports this outcome as `unconfirmed`, with the text "The evaluation
may or may not have been processed, so it was not sent again".

## Checklist for a safe integration

- [ ] The credential is loaded with `AgentCredential.fromFile` or `fromEnv`, from a source
      readable only by the agent. It is never logged, committed or sent anywhere.
- [ ] The agent has no `agentId` setting; its identity is its credential.
- [ ] Every side effect goes through `client.evaluate` first, and the action is fixed by
      your code, not by untrusted content.
- [ ] Side effects happen only on `ALLOW` with `executed: true`, or on an observed
      `EXECUTED` with `executed: true`.
- [ ] `CONFIRM` waits for an operator, and the agent never approves or rejects.
- [ ] `BLOCK`, `REJECTED`, `EXPIRED`, `BLOCKED_ON_RECHECK` and `APPROVED_NOT_EXECUTED` do
      nothing.
- [ ] Unconfirmed evaluations are never resent as new evaluations; a deliberate retry reuses
      `error.details.idempotencyKey` with the same request.
- [ ] Server text is sanitised before display, and finding evidence is not echoed to
      untrusted places.
- [ ] Credentials are short-lived, rotated with overlap, and revoked when no longer
      needed.
