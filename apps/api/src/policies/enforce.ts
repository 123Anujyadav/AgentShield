import {
  evaluateAction,
  policyBlockEvaluation,
  resolveAgentIntent,
  type EvaluationResult,
  type ProposedAction,
  type RequestedIntent,
  type UntrustedContent,
  type UserIntent,
} from "@agentshield/engine";
import type { ApprovalRecord } from "../approvals.js";
import { AGENT_ID_PATTERN, type PolicyStore } from "./store.js";

/**
 * Policy enforcement for the API (M3-C). Pure functions, so every rule here is
 * testable without a server. The server-held policy is authoritative: a request
 * can only narrow it, an unknown agent is denied, and an approval is rechecked
 * against the policy as it is now, not as it was when the approval was created.
 */

export type AgentIdParse = { ok: true; agentId: string | null } | { ok: false };

/** Absent: no agent (denied as unknown). Present: must be a well-formed agent id, or the request is malformed. */
export function parseAgentId(value: unknown): AgentIdParse {
  if (value === undefined) return { ok: true, agentId: null };
  if (typeof value === "string" && AGENT_ID_PATTERN.test(value)) return { ok: true, agentId: value };
  return { ok: false };
}

export interface AgentEvaluation {
  evaluation: EvaluationResult;
  /** The intent the decision used: the policy narrowed by the request; null for an unknown agent. */
  effectiveIntent: UserIntent | null;
}

/** Evaluates an action for an agent under its server-side policy. No policy: an audited default-deny BLOCK. */
export function evaluateForAgent(
  store: PolicyStore,
  agentId: string | null,
  requested: RequestedIntent,
  action: ProposedAction,
  untrustedContent?: UntrustedContent,
): AgentEvaluation {
  const loaded = agentId === null ? undefined : store.get(agentId);
  if (!loaded) {
    return { evaluation: { ...policyBlockEvaluation("unknown-agent", agentId, action, untrustedContent), agentPolicy: null }, effectiveIntent: null };
  }
  const effectiveIntent = resolveAgentIntent(loaded.policy, requested);
  return {
    evaluation: { ...evaluateAction({ intent: effectiveIntent, action, untrustedContent }), agentPolicy: { ...loaded.ref } },
    effectiveIntent,
  };
}

/**
 * The approval recheck. The agent's policy must still exist and be the exact
 * policy (same content hash) the CONFIRM was decided under; any change or removal
 * blocks the stale approval. If it is unchanged, the stored request is narrowed
 * against the current policy again and evaluated in full (hard deny, data-leak
 * guard, intent checks).
 */
export function recheckApproval(store: PolicyStore, record: ApprovalRecord): EvaluationResult {
  const agentId = record.agentId ?? null;
  const current = agentId === null ? undefined : store.get(agentId);
  if (!current || !record.agentPolicy || current.ref.sha256 !== record.agentPolicy.sha256) {
    return { ...policyBlockEvaluation("policy-changed", agentId, record.action, record.untrustedContent), agentPolicy: current ? { ...current.ref } : null };
  }
  const requested: RequestedIntent = record.requestedIntent ?? record.intent;
  const intent = resolveAgentIntent(current.policy, requested);
  return { ...evaluateAction({ intent, action: record.action, untrustedContent: record.untrustedContent }), agentPolicy: { ...current.ref } };
}
