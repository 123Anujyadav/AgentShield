import type {
  EvaluationResult,
  PendingApproval,
  ProposedAction,
  SimulatedExecution,
  UntrustedContent,
  UserIntent,
} from "@agentshield/engine";
import type { Simulator } from "./simulator.js";

export const APPROVAL_TTL_MS = 15 * 60 * 1000;

export interface ApprovalStore {
  records: Map<string, PendingApproval & { untrustedContent?: UntrustedContent }>;
  nextId: number;
}

export function createApprovalStore(): ApprovalStore {
  return { records: new Map(), nextId: 1 };
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

export function createPendingApproval(
  store: ApprovalStore,
  input: {
    scenarioId: string | null;
    intent: UserIntent;
    action: ProposedAction;
    untrustedContent?: UntrustedContent;
    evaluation: EvaluationResult;
  },
  now = new Date(),
): PendingApproval {
  const record: PendingApproval & { untrustedContent?: UntrustedContent } = {
    id: `apr-${store.nextId++}`,
    status: "PENDING",
    createdAt: now.toISOString(),
    expiresAt: new Date(now.getTime() + APPROVAL_TTL_MS).toISOString(),
    scenarioId: input.scenarioId,
    intent: clone(input.intent),
    action: clone(input.action),
    decision: input.evaluation.decision,
    policyVersion: input.evaluation.policyVersion,
    riskScore: input.evaluation.riskScore,
    findings: clone(input.evaluation.findings),
    explanation: input.evaluation.explanation,
    execution: null,
    untrustedContent: input.untrustedContent ? clone(input.untrustedContent) : undefined,
  };
  store.records.set(record.id, record);
  return toPublicApproval(record);
}

/** Public view never echoes the raw untrusted content back. */
export function toPublicApproval(
  record: PendingApproval & { untrustedContent?: UntrustedContent },
): PendingApproval {
  const { untrustedContent: _ignored, ...rest } = record;
  return clone(rest);
}

export type ApproveOutcome =
  | { kind: "not-found" }
  | { kind: "already-final"; status: number; approval: PendingApproval }
  | { kind: "expired"; approval: PendingApproval }
  | { kind: "blocked-on-recheck"; approval: PendingApproval; recheck: EvaluationResult }
  | { kind: "executed"; approval: PendingApproval; execution: SimulatedExecution; recheck: EvaluationResult };

export function processApproval(
  store: ApprovalStore,
  id: string,
  reevaluate: (record: PendingApproval & { untrustedContent?: UntrustedContent }) => EvaluationResult,
  simulator: Simulator,
  now = new Date(),
): ApproveOutcome {
  const record = store.records.get(id);
  if (!record) return { kind: "not-found" };
  if (record.status !== "PENDING") {
    return { kind: "already-final", status: 409, approval: toPublicApproval(record) };
  }
  if (now.getTime() > new Date(record.expiresAt).getTime()) {
    record.status = "EXPIRED";
    return { kind: "expired", approval: toPublicApproval(record) };
  }
  // Policy recheck against the exact stored intent/action/content. Client input plays no part.
  const recheck = reevaluate(record);
  if (recheck.decision === "BLOCK") {
    record.status = "BLOCKED_ON_RECHECK";
    record.execution = { executed: false, handler: null, result: null, reason: "Policy recheck returned BLOCK." };
    return { kind: "blocked-on-recheck", approval: toPublicApproval(record), recheck };
  }
  const execution = simulator.execute(clone(record.action), "ALLOW");
  record.execution = execution;
  record.status = execution.executed ? "EXECUTED" : "BLOCKED_ON_RECHECK";
  return { kind: "executed", approval: toPublicApproval(record), execution, recheck };
}

export type RejectOutcome =
  | { kind: "not-found" }
  | { kind: "already-final"; approval: PendingApproval }
  | { kind: "rejected"; approval: PendingApproval };

export function processRejection(store: ApprovalStore, id: string): RejectOutcome {
  const record = store.records.get(id);
  if (!record) return { kind: "not-found" };
  if (record.status !== "PENDING") return { kind: "already-final", approval: toPublicApproval(record) };
  record.status = "REJECTED";
  record.execution = { executed: false, handler: null, result: null, reason: "Rejected by user. No handler invoked." };
  return { kind: "rejected", approval: toPublicApproval(record) };
}
