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
import type { CredentialStatus } from "../agents/credentials.js";
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

/** M3-D: the finding recorded when a request names a different agent than its credential's. */
export const IDENTITY_MISMATCH_RULE_ID = "identity.agent-mismatch";

/**
 * The approval recheck.
 *
 * 1. M3-D identity: an action an agent requested runs only while the credential
 *    it used is still active (not revoked, expired, removed, or unverifiable
 *    because the credential store is invalid). Only an operator-run seeded
 *    scenario has no credential to check; any other record without one is blocked.
 * 2. M3-C policy: the agent's policy must still exist and be the exact policy
 *    (same content hash) the CONFIRM was decided under.
 * 3. The stored request is narrowed against the current policy again and
 *    evaluated in full (hard deny, data-leak guard, intent checks).
 */
export function recheckApproval(
  store: PolicyStore,
  record: ApprovalRecord,
  credentialStatus: (keyId: string) => CredentialStatus,
): EvaluationResult {
  const agentId = record.agentId ?? null;
  const current = agentId === null ? undefined : store.get(agentId);
  const operatorScenario = record.requestedBy?.kind === "operator" && record.scenarioId !== null;
  if (!operatorScenario && (!record.credentialKeyId || credentialStatus(record.credentialKeyId) !== "active")) {
    return { ...policyBlockEvaluation("credential-invalid", agentId, record.action, record.untrustedContent), agentPolicy: current ? { ...current.ref } : null };
  }
  if (!current || !record.agentPolicy || current.ref.sha256 !== record.agentPolicy.sha256) {
    return { ...policyBlockEvaluation("policy-changed", agentId, record.action, record.untrustedContent), agentPolicy: current ? { ...current.ref } : null };
  }
  const requested: RequestedIntent = record.requestedIntent ?? record.intent;
  const intent = resolveAgentIntent(current.policy, requested);
  return { ...evaluateAction({ intent, action: record.action, untrustedContent: record.untrustedContent }), agentPolicy: { ...current.ref } };
}
