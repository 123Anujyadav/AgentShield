import { POLICY_VERSION } from "./evaluate.js";
import { redactSecretValue, scanUntrustedContent } from "./scanner/scan.js";
import type { AgentPolicy, EvaluationResult, Finding, ProposedAction, RequestedIntent, UntrustedContent, UserIntent } from "./types.js";

/**
 * Server-side agent policies (M3-C).
 *
 * A policy is held by the server and keyed by agent identity. It is the ceiling
 * for what that agent may do. A request can only narrow it:
 * - allowedActions and allowedDestinations: intersection with the policy;
 * - deniedActions: union with the policy (a request can add denies, never remove one);
 * - an omitted list inherits the policy's list; an explicitly empty list grants nothing.
 * Matching is exact (no wildcards, no case folding). The global hard-deny list and
 * the data-leak guard in evaluateAction still apply on top of any policy.
 */

/** The built-in demo agent: exactly the seeded scenarios' intent, so their decisions are unchanged. */
export const DEMO_AGENT_ID = "demo-summarizer";

/** Policy order, without duplicates. */
function unique(values: readonly string[]): string[] {
  return [...new Set(values)];
}

function narrow(policy: readonly string[], requested: readonly string[] | undefined): string[] {
  if (requested === undefined) return unique(policy);
  const asked = new Set(requested);
  return unique(policy.filter((value) => asked.has(value)));
}

/**
 * The intent an evaluation actually uses: the server policy narrowed by the request.
 * Nothing in the request can add an action or a destination the policy does not hold.
 */
export function resolveAgentIntent(policy: AgentPolicy, requested: RequestedIntent): UserIntent {
  return {
    ...(requested.id !== undefined ? { id: requested.id } : {}),
    task: requested.task,
    allowedActions: narrow(policy.allowedActions, requested.allowedActions),
    deniedActions: unique([...policy.deniedActions, ...(requested.deniedActions ?? [])]),
    allowedDestinations: narrow(policy.allowedDestinations, requested.allowedDestinations),
  };
}

export const UNKNOWN_AGENT_RULE_ID = "policy.unknown-agent";
export const POLICY_CHANGED_RULE_ID = "policy.changed-since-approval";
/** M3-D: the agent credential that created an approval is no longer valid (revoked, expired, removed or unavailable). */
export const CREDENTIAL_INVALID_RULE_ID = "identity.credential-invalid";
export const POLICY_BLOCK_RISK = 90;

type PolicyBlockKind = "unknown-agent" | "policy-changed" | "credential-invalid";

/**
 * A BLOCK decided by the policy layer itself: no server-side policy for the agent
 * (default deny), or, on an approval recheck, a policy that changed since the
 * approval was created or (M3-D) a creating agent credential that is no longer valid. Scanner findings are still reported, first, as in every
 * evaluation; nothing here can be overridden by an approval or the advisory model.
 */
export function policyBlockEvaluation(
  kind: PolicyBlockKind,
  agentId: string | null,
  action: ProposedAction,
  untrustedContent?: UntrustedContent,
): EvaluationResult {
  const scan = untrustedContent ? scanUntrustedContent(untrustedContent.text) : null;
  const scannerFindings: Finding[] = scan?.findings ?? [];
  const shownAgent = agentId === null ? "(none)" : redactSecretValue(agentId);
  const shownType = redactSecretValue(action.type);
  const finding: Finding =
    kind === "credential-invalid"
      ? {
          ruleId: CREDENTIAL_INVALID_RULE_ID,
          category: "policy",
          severity: "high",
          title: "Agent credential no longer valid",
          explanation: "The agent credential that requested this action was revoked, expired, removed or cannot be checked, so the approval cannot execute.",
          evidence: `agentId=${shownAgent}; action.type=${shownType}`,
        }
      : kind === "unknown-agent"
      ? {
          ruleId: UNKNOWN_AGENT_RULE_ID,
          category: "policy",
          severity: "high",
          title: "Unknown agent",
          explanation: "No server-side policy exists for this agent, so no action can be authorised. Unknown agents are denied by default.",
          evidence: `agentId=${shownAgent}; action.type=${shownType}`,
        }
      : {
          ruleId: POLICY_CHANGED_RULE_ID,
          category: "policy",
          severity: "high",
          title: "Policy changed since approval",
          explanation: "The agent's server-side policy changed or was removed after this approval was created, so the stale approval cannot execute.",
          evidence: `agentId=${shownAgent}; action.type=${shownType}`,
        };
  return {
    decision: "BLOCK",
    policyVersion: POLICY_VERSION,
    riskScore: POLICY_BLOCK_RISK,
    findings: [...scannerFindings, finding],
    scannerFindings,
    scannerStatus: scan ? scan.status : "not-scanned",
    explanation:
      kind === "credential-invalid"
        ? `Blocked: the credential agent ${shownAgent} used to request this action is no longer valid. Nothing was executed.`
        : kind === "unknown-agent"
        ? `Blocked: no server-side policy exists for agent ${shownAgent}. Unknown agents are denied by default and nothing was executed.`
        : `Blocked: the policy for agent ${shownAgent} changed since this approval was created. Nothing was executed; evaluate the action again under the current policy.`,
    actionType: shownType,
  };
}
