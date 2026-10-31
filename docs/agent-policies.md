# Agent policies (M3-C)

Status: implemented and verified with offline unit and route tests only (no browser,
no deployed server).

Before M3-C, the permissions used to judge an action came from the request itself
(`intent.allowedActions`, `intent.deniedActions`, `intent.allowedDestinations`), so a
caller could grant itself anything. Now every evaluation names an **agent**, and the
server holds that agent's policy. The request can narrow the policy but never widen it.
Since M3-D the agent is the one whose credential authenticated the request, not an id the
request claims; see [agent-identity.md](agent-identity.md).

## Policy file

Policies are optional configuration. With no `AGENT_POLICY_FILE` set (or set to blank),
the API uses one built-in policy, `demo-summarizer`, which matches the seeded scenarios.
When `AGENT_POLICY_FILE` names a file, that file **replaces** the built-in policy
completely. If the seeded scenarios should keep working, the file must include
`demo-summarizer` (as [`config/agent-policies.example.json`](../config/agent-policies.example.json) does, with the
same fields and therefore the same hash as the built-in one).

```json
{
  "schemaVersion": 1,
  "policies": [
    {
      "agentId": "report-writer",
      "version": 1,
      "description": "Optional, at most 500 characters.",
      "allowedActions": ["read_document", "create_report"],
      "deniedActions": ["send_email"],
      "allowedDestinations": ["simulated-workspace"]
    }
  ]
}
```

Use an absolute path. A relative path resolves from the API process's working directory,
which is `apps/api` under `npm run dev:api`. The file is read once at start-up. Edits take effect on the next API restart. There is
no write endpoint.

Validation is strict, and **any** problem stops the API at start-up with
`agent-policy status=invalid-config reason=...`. The reason names the position and the
expected field or format, never a value or an unknown field's name from the file:

- The file can be at most 256 KB, must be valid JSON (a UTF-8 BOM is tolerated), and must
  contain only `schemaVersion` (exactly `1`) and `policies` (an array of at most 200).
- A policy contains only the six fields shown. Unknown fields are refused, so a misspelled
  `allowedDestination` cannot silently mean "no restriction".
- `agentId` matches `^[a-z0-9][a-z0-9._-]{0,63}$`. Duplicate agent ids are refused.
- `version` is a positive integer.
- All three lists are required (an empty list is allowed). Each holds at most 64 unique,
  non-empty strings of at most 128 characters, with no control characters, no leading or
  trailing whitespace and no `*`. Matching is exact: no wildcards and no case folding.

Each loaded policy is identified by its agent id, declared version and a SHA-256 of its
canonical form (`agentPolicy: { agentId, version, sha256 }`). Any edit, including only
the description or only the version, changes the hash.

## Enforcement

`POST /api/evaluate`:

1. **Seeded scenario** (`scenarioId`, operator only since M3-D): uses the scenario's own
   agent (`demo-summarizer`). An `agentId` in the body is ignored.
2. **Custom request** (an agent credential is required since M3-D): the agent is the
   credential's.
   - A body `agentId` is optional. If present it must equal the authenticated agent: a
     malformed one (wrong type, wrong characters, too long, empty, `null`) is a `400`
     with `reason: "invalid-agent-id"`, and a different well-formed one is a `403`
     `agent-identity-mismatch` recorded as a security event; neither is evaluated.
   - An authenticated agent with no policy (a credential issued for an agent the policy
     file does not list): an audited **BLOCK** (`200`, risk 90, rule
     `policy.unknown-agent`). No approval is created, nothing executes, and the event
     records the agent id with `agentPolicy: null`. Scanner findings are still reported
     first. The server keeps the original agent id for policy lookup and enforcement, but
     public events (the evaluate response's `event` and `GET /api/events`) show a
     token-shaped id, such as one that looks like a GitHub, GitLab, Slack or `sk-` key, as
     `[REDACTED]`, both as the agent id and as a mismatching claimed id. Ordinary ids such
     as `report-writer` are shown unchanged.
3. The effective permissions are the policy narrowed by the request:

   | Field | Request omits it | Request supplies it |
   |---|---|---|
   | `allowedActions` | policy list | policy ∩ request (an empty list grants nothing) |
   | `allowedDestinations` | policy list | policy ∩ request (an empty list grants nothing) |
   | `deniedActions` | policy list | policy ∪ request (a request can add denies, never remove them) |

   Because every stored policy has `allowedDestinations`, destinations are always
   restricted for a known agent.
4. The unchanged engine then evaluates the action. Hard deny, the data-leak guard and the
   scanner run as before and still override any policy: a policy that lists
   `send_payment` as allowed still gets a BLOCK.
5. The evaluation, its event and any pending approval carry `agentId` and `agentPolicy`.
   Muse (model analysis) is unchanged and advisory only. It never sees or changes a policy.

### Approvals and policy changes

A `CONFIRM` stores the agent, the policy reference and the original request (the request
stays server-side and is not shown in approval views). Only the operator can approve
(M3-D). On approve, the server first checks that the agent credential that made the
request is still valid (see [agent-identity.md](agent-identity.md)), then looks up the
agent's **current** policy:

- If the policy was removed, its hash differs from the one recorded at CONFIRM time (any
  edit or version bump), or the record has no agent or policy reference, the recheck is a
  BLOCK (rule `policy.changed-since-approval`, risk 90). The approve call returns `409`
  `BLOCKED_ON_RECHECK`, and nothing executes.
- Otherwise the stored request is narrowed against the current policy again and fully
  re-evaluated, as before M3-C.

Policies only change on restart today, and pending approvals are in memory, so a restart
already discards them. The hash check keeps this safe if policies or approvals ever
outlive a restart.

## Reading policies

`GET /api/policies` (operator only, like every `/api` route except evaluate) returns
`{ source: "built-in" | "file", policies: [{ agentId, version, sha256, description,
allowedActions, deniedActions, allowedDestinations }] }` in file order. A description or
list entry that looks like a secret is shown as `[REDACTED]`. This is display-only, and
enforcement still uses the exact stored value. `POST`, `PUT`, `PATCH` and `DELETE` are not
routed (`404`).

## Limitations

- Since M3-D an agent id is bound to a credential, so a caller can no longer act as an
  agent whose credential it does not hold. The operator, who issues credentials, is
  fully trusted. See [agent-identity.md](agent-identity.md) for the remaining limits.
- Policies are global configuration with no per-user or per-tenant scoping, no history
  and no hot reload. Changing a policy means editing the file and restarting.
- Only exact action and destination strings are supported. There are no patterns,
  parameter constraints, rate or amount limits, or time windows.
- Unknown agents are blocked, but a policy that is too broad is still too broad. Review
  policies as you would code.
- Verified by unit, store and route tests only. The web UI only runs seeded scenarios and
  does not show or choose agents.
