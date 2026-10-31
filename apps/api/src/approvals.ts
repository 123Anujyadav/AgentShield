import type {
  AgentPolicyRef,
  EvaluationResult,
  PendingApproval,
  RequestActor,
  RequestedIntent,
  ProposedAction,
  SimulatedExecution,
  UntrustedContent,
  UserIntent,
} from "@agentshield/engine";
import { detectOutboundSecret, payloadAssignment, redactSecretValue } from "@agentshield/engine";
import type { Simulator } from "./simulator.js";

export const APPROVAL_TTL_MS = 15 * 60 * 1000;

/** M3-B: most approval records kept in memory. Only finished records are ever evicted to stay under it. */
export const MAX_APPROVAL_RECORDS = 500;

/** Thrown when every stored approval is still open, so a new one cannot be stored without dropping one. */
export class ApprovalCapacityError extends Error {
  constructor() {
    super("approval-queue-full");
  }
}

/** Internal record: public approval fields plus server-only bookkeeping. */
export interface ApprovalRecord extends PendingApproval {
  untrustedContent?: UntrustedContent;
  /** M3-C, server-only: what the request asked for, re-narrowed against the CURRENT policy on recheck. */
  requestedIntent?: RequestedIntent;
  /** M3-D, server-only: the key id of the agent credential that requested the action; rechecked on approve. */
  credentialKeyId?: string;
  /** True while the EXPIRED lifecycle event still has to be written successfully. */
  expiryEventPending?: boolean;
}

export interface ApprovalStore {
  records: Map<string, ApprovalRecord>;
  nextId: number;
  /** Most records kept (M3-B). */
  limit: number;
}

export function createApprovalStore(limit: number = MAX_APPROVAL_RECORDS): ApprovalStore {
  if (!Number.isInteger(limit) || limit < 1) throw new RangeError("The approval store limit must be a positive integer.");
  return { records: new Map(), nextId: 1, limit };
}

/**
 * A record that may be dropped to make room: a final decision whose lifecycle
 * event has already been written. PENDING records are never evicted, and an
 * EXPIRED record is kept until its expiry event has been recorded.
 */
function isEvictable(record: ApprovalRecord): boolean {
  switch (record.status) {
    case "EXECUTED":
    case "REJECTED":
    case "BLOCKED_ON_RECHECK":
    case "APPROVED_NOT_EXECUTED":
      return true;
    case "EXPIRED":
      return record.expiryEventPending !== true;
    default:
      return false;
  }
}

/** Evicts the oldest finished records until one more fits; false when only open records remain. */
function makeRoom(store: ApprovalStore): boolean {
  for (const [id, record] of store.records) {
    if (store.records.size < store.limit) break;
    if (isEvictable(record)) store.records.delete(id);
  }
  return store.records.size < store.limit;
}

/** True when a new approval would not fit even after evicting every finished record. */
export function approvalStoreFull(store: ApprovalStore): boolean {
  if (store.records.size < store.limit) return false;
  let evictable = 0;
  for (const record of store.records.values()) if (isEvictable(record)) evictable += 1;
  return evictable === 0;
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
    /** M3-C: the agent, what the request asked for, and the policy the CONFIRM was decided under. */
    agentId?: string | null;
    requestedIntent?: RequestedIntent;
    agentPolicy?: AgentPolicyRef | null;
    /** M3-D: who requested the action, and (for an agent) the credential it used. */
    requestedBy?: RequestActor;
    credentialKeyId?: string;
  },
  now = new Date(),
): PendingApproval {
  // Bounded (M3-B): drop the oldest finished records; never an open one.
  if (!makeRoom(store)) throw new ApprovalCapacityError();
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
    ...(input.agentId !== undefined ? { agentId: input.agentId } : {}),
    ...(input.agentPolicy !== undefined ? { agentPolicy: input.agentPolicy === null ? null : { ...input.agentPolicy } } : {}),
    ...(input.requestedIntent !== undefined ? { requestedIntent: clone(input.requestedIntent) } : {}),
    ...(input.requestedBy !== undefined ? { requestedBy: { ...input.requestedBy } } : {}),
    ...(input.credentialKeyId !== undefined ? { credentialKeyId: input.credentialKeyId } : {}),
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

/**
 * Public copy of a simulated execution. The simulator's reason can quote the
 * action type, so a secret-shaped type is replaced wherever it appears
 * (Phase I, display only: the stored record and the decision are untouched).
 */
export function publicExecution(execution: SimulatedExecution, actionType: string): SimulatedExecution {
  const shown = redactSecretValue(actionType);
  if (shown === actionType) return execution;
  const hide = (text: string | null) => (text === null ? null : text.split(actionType).join(shown));
  return { ...execution, handler: hide(execution.handler), result: hide(execution.result), reason: hide(execution.reason) };
}

/** Public view never echoes the raw untrusted content or internal bookkeeping back. */
export function toPublicApproval(record: ApprovalRecord): PendingApproval {
  // Server-only fields never reach clients (M3-C adds the requested intent, M3-D the credential key id;
  // the public requestedBy carries the key id only for operator views, per U5).
  const { untrustedContent: _ignored, expiryEventPending: _pending, requestedIntent: _requested, credentialKeyId: _key, ...rest } = record;
  const pub = clone(rest);
  // Phase I: secret-shaped request metadata is shown as [REDACTED].
  if (pub.execution) pub.execution = publicExecution(pub.execution, record.action.type);
  pub.action.type = redactSecretValue(pub.action.type);
  pub.action.tool = redactSecretValue(pub.action.tool);
  pub.intent.task = redactSecretValue(pub.intent.task);
  if (pub.intent.id !== undefined) pub.intent.id = redactSecretValue(pub.intent.id);
  pub.intent.allowedActions = pub.intent.allowedActions.map(redactSecretValue);
  pub.intent.deniedActions = pub.intent.deniedActions.map(redactSecretValue);
  // Defense in depth: never echo a secret-shaped outbound value back to a
  // client. The stored record is untouched and still governs policy recheck.
  if (detectOutboundSecret("action.summary", pub.action.summary)) {
    pub.action.summary = "[REDACTED]";
  }
  if (detectOutboundSecret("action.destination", pub.action.destination)) {
    pub.action.destination = "[REDACTED]";
  }
  if (pub.intent.allowedDestinations) {
    pub.intent.allowedDestinations = pub.intent.allowedDestinations.map((destination) =>
      detectOutboundSecret("action.destination", destination) ? "[REDACTED]" : destination,
    );
  }
  if (pub.action.payload) {
    const sanitized: NonNullable<typeof pub.action.payload> = {};
    const entries = Object.entries(pub.action.payload);
    for (let index = 0; index < entries.length; index += 1) {
      const [key, value] = entries[index] as [string, string | number | boolean];
      const field = `action.payload.value[${index}]`;
      // A secret-shaped key is renamed to a fixed safe label; a secret-shaped
      // value is replaced. Raw attacker-controlled keys never reach clients.
      const safeKey = detectOutboundSecret(field, key) ? `[REDACTED] field-${index}` : key;
      const secretValue =
        detectOutboundSecret(field, payloadAssignment(key, String(value))) ?? detectOutboundSecret(field, String(value));
      sanitized[safeKey] = secretValue ? "[REDACTED]" : value;
    }
    pub.action.payload = sanitized;
  }
  return pub;
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
  // The recheck passed; if no handler ran, that is not a policy block (M3-B).
  record.status = execution.executed ? "EXECUTED" : "APPROVED_NOT_EXECUTED";
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
