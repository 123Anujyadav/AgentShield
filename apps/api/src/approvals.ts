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

/** Internal record: public approval fields plus server-only bookkeeping. */
export interface ApprovalRecord extends PendingApproval {
  untrustedContent?: UntrustedContent;
  /** True while the EXPIRED lifecycle event still has to be written successfully. */
  expiryEventPending?: boolean;
}

export interface ApprovalStore {
  records: Map<string, ApprovalRecord>;
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
  const record: ApprovalRecord = {
    id: `apr-${store.nextId++}`,
    status: "PENDING",
    expiryEventPending: false,
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

function isExpired(record: ApprovalRecord, now: Date): boolean {
  return now.getTime() > new Date(record.expiresAt).getTime();
}

/**
 * Transitions stale PENDING records to EXPIRED so listings reflect the
 * documented 15-minute TTL without waiting for an approve/reject attempt.
 * Already-final records are never touched.
 *
 * Event delivery is retry-based, not strict exactly-once: `onExpired` is
 * retried on a later listing, approve, or reject while the record's pending
 * marker is set, but approvals and markers live only in memory, so a process
 * restart loses both. If a write succeeds in the event store but then
 * reports an error, the retry may record a duplicate event. Returns how
 * many records transitioned in this call.
 */
export function expirePendingApprovals(
  store: ApprovalStore,
  now = new Date(),
  onExpired?: (approval: PendingApproval) => void,
): number {
  let changed = 0;
  for (const record of store.records.values()) {
    if (record.status === "PENDING" && isExpired(record, now)) {
      record.status = "EXPIRED";
      record.expiryEventPending = true;
      changed += 1;
    }
    if (record.status === "EXPIRED" && record.expiryEventPending && onExpired) {
      // Isolate failures per record: a throwing event write keeps the record
      // pending for the next retry and never blocks later stale records.
      try {
        onExpired(toPublicApproval(record));
        record.expiryEventPending = false;
      } catch {
        // Pending marker stays set; a later sweep or approve/reject retries.
        console.warn(`approval-expiry-event status=write-failed approvalId=${record.id} retry=pending`);
      }
    }
  }
  return changed;
}

/** Marks the EXPIRED event as written. Returns false when nothing was pending. */
export function markExpiryEventRecorded(store: ApprovalStore, id: string): boolean {
  const record = store.records.get(id);
  if (!record || record.status !== "EXPIRED" || !record.expiryEventPending) return false;
  record.expiryEventPending = false;
  return true;
}

/** Public view never echoes the raw untrusted content or internal bookkeeping back. */
export function toPublicApproval(record: ApprovalRecord): PendingApproval {
  const { untrustedContent: _ignored, expiryEventPending: _pending, ...rest } = record;
  return clone(rest);
}

export type ApproveOutcome =
  | { kind: "not-found" }
  | { kind: "already-final"; status: number; approval: PendingApproval }
  | { kind: "expired"; approval: PendingApproval; expiryEventPending: boolean }
  | { kind: "blocked-on-recheck"; approval: PendingApproval; recheck: EvaluationResult }
  | { kind: "executed"; approval: PendingApproval; execution: SimulatedExecution; recheck: EvaluationResult };

export function processApproval(
  store: ApprovalStore,
  id: string,
  reevaluate: (record: ApprovalRecord) => EvaluationResult,
  simulator: Simulator,
  now = new Date(),
): ApproveOutcome {
  const record = store.records.get(id);
  if (!record) return { kind: "not-found" };
  if (record.status === "EXPIRED") {
    return { kind: "expired", approval: toPublicApproval(record), expiryEventPending: record.expiryEventPending === true };
  }
  if (record.status !== "PENDING") {
    return { kind: "already-final", status: 409, approval: toPublicApproval(record) };
  }
  if (isExpired(record, now)) {
    record.status = "EXPIRED";
    record.expiryEventPending = true;
    return { kind: "expired", approval: toPublicApproval(record), expiryEventPending: true };
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
  | { kind: "expired"; approval: PendingApproval; expiryEventPending: boolean }
  | { kind: "rejected"; approval: PendingApproval };

export function processRejection(store: ApprovalStore, id: string, now = new Date()): RejectOutcome {
  const record = store.records.get(id);
  if (!record) return { kind: "not-found" };
  if (record.status === "EXPIRED") {
    return { kind: "expired", approval: toPublicApproval(record), expiryEventPending: record.expiryEventPending === true };
  }
  if (record.status !== "PENDING") return { kind: "already-final", approval: toPublicApproval(record) };
  if (isExpired(record, now)) {
    record.status = "EXPIRED";
    record.expiryEventPending = true;
    return { kind: "expired", approval: toPublicApproval(record), expiryEventPending: true };
  }
  record.status = "REJECTED";
  record.execution = { executed: false, handler: null, result: null, reason: "Rejected by user. No handler invoked." };
  return { kind: "rejected", approval: toPublicApproval(record) };
}
