# @agentshield/reference-agent

A complete, harmless reference agent built on the official AgentShield SDK
(`@agentshield/agent-sdk`). It is part of M3-E E6.

**What it does.** It summarizes a document into a *simulated* workspace: an in-memory list
held by the agent process. It asks AgentShield before saving anything, and saves only once
AgentShield reports the action as executed.

**What it does not do.** It has no real tools: no email, no file writes, no shell, no
network other than AgentShield. It never approves or rejects anything; only an operator can.

Use it as a template for how an agent should handle `ALLOW`, `CONFIRM` and `BLOCK`, approvals
and failures.

## Install and build

It is a workspace package. Install at the repository root once, then build it after the
protocol package and the SDK:

```powershell
npm install
npm run build -w @agentshield/agent-protocol
npm run build -w @agentshield/agent-sdk
npm run build -w @agentshield/reference-agent
```

`npm run build` at the root builds everything in that order.

Its only runtime dependency is `@agentshield/agent-sdk`.

## Configuration

The agent reads three environment variables. Nothing else configures it.

| Variable | Meaning |
|---|---|
| `AGENTSHIELD_URL` | AgentShield's origin. Default `http://127.0.0.1:4000`. Must be loopback (the SDK's default rule). |
| `AGENTSHIELD_AGENT_CREDENTIAL_FILE` | Path of the agent's credential file. **Preferred.** Loaded with `AgentCredential.fromFile`. |
| `AGENTSHIELD_AGENT_CREDENTIAL` | The credential itself, as an alternative. Loaded with `AgentCredential.fromEnv`. |

**Credential source.** Set exactly one of the two credential variables; setting both is an
error.

**No identity setting.** There is no setting for the agent's identity. AgentShield works it
out from the credential. `AGENTSHIELD_AGENT_ID` (or `AGENTSHIELD_AGENT`) is refused if set,
so nobody believes it does something.

**Getting a credential.** The operator issues it with the existing CLI. The example below is
for a throwaway local test only:

```powershell
# Operator, on the AgentShield machine (writes a key file restricted to the current user):
npm run agent-credential -w @agentshield/api -- create --agent report-writer --out C:\secure\report-writer.key

# Agent:
$env:AGENTSHIELD_AGENT_CREDENTIAL_FILE = "C:\secure\report-writer.key"
```

The operator also needs a policy for `report-writer` that allows the action `create_summary`
to the destination `simulated-workspace`.

**Placeholder values.** The values below are placeholders, not a credential:

```text
AGENTSHIELD_URL=http://127.0.0.1:4000
AGENTSHIELD_AGENT_CREDENTIAL_FILE=C:\secure\report-writer.key
# never commit a credential; the file holds one line: asag2_<keyId>.<key>
```

## Running it

```powershell
npm run reference-agent -- --document C:\docs\notes.txt [--title "Notes"] [--wait-minutes 16]
```

- `--document`: a UTF-8 text file of at most 24 KB.
- `--title`: a local label for the saved summary. It defaults to the file name and is never
  sent to AgentShield.
- `--wait-minutes`: how long to wait for an operator (1 to 60; default 16, just past the
  15-minute approval lifetime).

**Output.** It prints the credential's public key id, AgentShield's decision with its
reasons, and what happened. It never prints the key, the document or the summary.

| Exit code | Meaning |
|---|---|
| 0 | Completed: the summary was saved |
| 2 | Not done: blocked, rejected, expired, blocked on recheck, not executed, or the approval was lost |
| 3 | Outcome open: still pending, the wait was interrupted, or the evaluation is unconfirmed |
| 1 | Refused before processing, or a configuration, credential or usage error |

**Using it from code:**

```ts
import { AgentCredential, AgentShieldClient } from "@agentshield/agent-sdk";
import { ReferenceAgent } from "@agentshield/reference-agent";

const credential = AgentCredential.fromFile("C:\\secure\\report-writer.key");
const agent = new ReferenceAgent({ client: new AgentShieldClient({ baseUrl: "http://127.0.0.1:4000", credential }) });
const outcome = await agent.run({ title: "Notes", text: documentText });
// outcome.status: "completed", "blocked", "pending", ...; agent.workspace.list() holds saved summaries.
```

## Workflow

1. **Validate the task.** It must be exactly `{ title, text }`. A task with any other field
   (`agentId`, `action`, `destination`, `credential`, ...) is refused, not ignored.
2. **Summarize locally.** The summary is deterministic: the first three sentences, at most
   500 characters. Hidden characters are removed. Nothing in the document is followed.
3. **Evaluate once.** The agent sends one signed `POST /api/evaluate` through the SDK.
   - The action is fixed: `create_summary` with `simulated.workspace.createSummary` to
     `simulated-workspace`.
   - The intent narrows the agent's policy to that action and destination.
   - The document is sent as `untrustedContent`, so AgentShield scans it for prompt
     injection.
4. **Act on the decision.**
   - **ALLOW** with `executed: true`: AgentShield ran the (simulated) action. The agent
     saves the summary to its workspace (status `completed`). An ALLOW that was not executed
     saves nothing (`not-executed`).
   - **BLOCK**: nothing is saved and no approval is followed (`blocked`).
   - **CONFIRM** with an approval id: the agent waits, see step 5. A CONFIRM without one
     saves nothing.
5. **Follow the approval.** The agent polls only its own approval
   (`GET /api/agent/approvals/:id`, via `waitForApproval`), as often as the server's
   `pollAfterSeconds` says. The operator decides in the AgentShield UI, or through
   `POST /api/approvals/:id/approve` or `/reject` with operator authentication.
   - `EXECUTED` with `executed: true`: the summary is saved (`completed`).
   - `REJECTED`, `EXPIRED`, `BLOCKED_ON_RECHECK` or `APPROVED_NOT_EXECUTED`: nothing is
     saved.
   - Still pending when the wait ends: `pending`. `agent.resume(approvalId)` continues it
     later.

## Error handling

**Evaluate failures.** The agent sends an evaluation at most once. It never repeats it
automatically, because a repeat could run the action twice.

| Failure | Status | Meaning |
|---|---|---|
| 401 (unknown, expired or revoked credential) | `refused` (`authentication`) | Not processed. Ask the operator to check or rotate the credential. |
| 400 / 403 / 413 / 415, or too large to send | `refused` | Not processed. |
| 429 | `refused` (`rate-limited`, with `retryAfterSeconds`) | Not processed. Re-running is your decision. |
| Timeout, network error, 5xx, malformed answer | `unconfirmed` | **May or may not have been processed** (it may even have executed). It was not sent again and nothing was saved. Check the agent's approvals (`listApprovals`) before running the task again. |

**Approval failures.**

| While waiting for an approval | Status | Meaning |
|---|---|---|
| The approval is not found (for example AgentShield restarted: pending approvals live in memory) | `approval-missing` | Nothing saved. Run the task again to ask again. |
| Credential revoked or expired, AgentShield unreachable, or another error | `wait-interrupted` (with a reason) | Nothing saved, and the approval itself is unchanged. `resume` can try again. If the credential was revoked, an operator's later approval is refused at recheck (`BLOCKED_ON_RECHECK`). |
| Cancelled (an `AbortSignal` passed to `run` or `resume`) | `wait-interrupted` (`cancelled`) | Nothing saved. |

**Retries inside the SDK.** The SDK retries approval reads a few times on its own (each
with a new signature), including once after a `401` signed just before a server restart.

**Unexpected errors.** Programming errors (anything that is not an SDK error) are thrown,
not hidden. Nothing is saved and nothing is retried.

## Security boundaries

- **Identity comes from the credential.** The SDK signs every request with the agent's
  Ed25519 key, and the server derives the agent from the key id. The agent never sends an
  agent id. Its task input and configuration cannot name one.
- **Only the SDK talks to AgentShield.** The agent does not call `fetch`, sign, build
  `Authorization` headers or import the protocol package. It accepts only a real
  `AgentShieldClient`. A source test (`boundaries.test.ts`) enforces this.
- **No self-approval.** The SDK has no approve or reject method, and the agent never calls
  an operator route. The end-to-end tests show the server refusing the agent's own
  credential on those routes (`403 operator-required`).
- **Nothing runs because it was asked.** The document is data. It cannot change the action,
  the destination or the identity. The only side effect, saving a summary in memory, happens
  only after AgentShield reports the action as executed.
- **Only its own approvals.** `resume` accepts only approvals this agent instance started,
  so an approval id from anywhere else is refused before any request. The server also hides
  other agents' approvals (uniform 404).
- **Safe display.** Server text (explanations, finding titles) can contain document text,
  so it is printed with control, format and bidi characters replaced, and cut to length.
  Finding evidence, the document and the summary are never printed. Only the credential's
  public key id is shown.
- **No secrets in output.** Credential errors come from the SDK with fixed messages that
  never echo the credential.

## Local development

```powershell
npm run test -w @agentshield/reference-agent        # unit tests (fake AgentShield, real SDK)
npm run typecheck -w @agentshield/reference-agent
npm run test -w @agentshield/api -- reference-agent  # end-to-end against the real API
```

**Unit tests.** They drive the real SDK client against a fake `fetch`. They use a
deterministic test credential derived from a label at run time; no key material is stored.

**End-to-end tests.** `apps/api/src/agents/reference-agent.integration.test.ts` starts the
real API app on a loopback ephemeral port, with:
- a temporary credential file holding deterministic test keys;
- the operator acting through the existing routes and the `agent-credential` CLI
  (revocation).

They cover:
- ALLOW, BLOCK by policy, and CONFIRM with approval, rejection, expiry and resume;
- self-approval refusal and agent isolation;
- rotation, revocation, an expired credential, an unknown credential and a malformed one;
- revocation while polling;
- the API being unavailable;
- an evaluate timeout after the server processed it (not repeated);
- a server restart while waiting;
- leakage and authentication checks.

Nothing needs a real credential, an external service or a running AgentShield.

## Limitations

- **The workspace is in memory.** Saved summaries and the list of approvals being followed
  are lost when the process ends. A restarted agent cannot resume an earlier approval; it
  can only run the task again.
- **An unconfirmed evaluation stays unconfirmed.** The server has no idempotency keys yet,
  and an approval view does not say which request it belongs to. So the agent cannot match
  an `unconfirmed` evaluation to an approval. It reports the situation and leaves the
  decision to a person.
- **AgentShield executes, not the agent.** "Executed" means AgentShield's simulator ran the
  action. The reference agent's own effect is only to record the summary locally.
- **The summary is simple.** It is extractive and deterministic, by design: the point is
  the control flow, not the summarization.
