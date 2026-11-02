import type {
  AgentPolicyRef,
  ApprovalStatus,
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

/**
 * M3-E E9: most open (PENDING, unexpired) approvals one agent can hold, so a single agent cannot
 * fill the whole store and starve every other agent and the operator's scenarios.
 */
export const MAX_PENDING_APPROVALS_PER_AGENT = 100;

/**
 * Thrown when a new approval cannot be stored: every stored approval is still open ("store"), or
 * the requesting agent already holds its maximum of open approvals ("agent", M3-E E9).
 */
export class ApprovalCapacityError extends Error {
  constructor(readonly scope: "store" | "agent" = "store") {
    super("approval-queue-full");
  }
}

/**
 * M3-E E12: the approval store could not durably record a creation or a transition, so it did not
 * happen (nothing changed, nothing ran).
 */
export class ApprovalStoreError extends Error {
  constructor(readonly reason: "approval-store-full" | "approval-store-unavailable") {
    super(reason);
    this.name = "ApprovalStoreError";
  }
}

/**
 * M3-E E12: durable approval storage. Each method records one change durably BEFORE the in-memory record
 * changes and throws ApprovalStoreError if it cannot. Without it (tests, demos) approvals live in memory.
 */
export interface ApprovalPersistence {
  readiness(): { ok: true } | { ok: false; reason: "approval-store-full" | "approval-store-unavailable" };
  created(record: ApprovalRecord, nextId: number): void;
  /** Write-ahead: the recheck passed and the simulated action is about to run. */
  approving(id: string): void;
  transitioned(id: string, status: ApprovalStatus, execution: SimulatedExecution | null): void;
  expiryRecorded(id: string): void;
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
  /** Most open approvals per agent (M3-E E9). */
  perAgentPendingLimit: number;
  /**
   * M3-E E12: finished records younger than this are never evicted to make room, so an approval that a
   * live idempotency record refers to stays readable. 0 (the in-memory default) keeps the M3-B behaviour.
   */
  finishedRetentionMs: number;
  /** M3-E E12: durable storage; absent for in-memory stores. */
  persistence?: ApprovalPersistence;
}

export function createApprovalStore(
  limit: number = MAX_APPROVAL_RECORDS,
  perAgentPendingLimit: number = MAX_PENDING_APPROVALS_PER_AGENT,
  options: { finishedRetentionMs?: number; persistence?: ApprovalPersistence } = {},
): ApprovalStore {
  if (!Number.isInteger(limit) || limit < 1) throw new RangeError("The approval store limit must be a positive integer.");
  if (!Number.isInteger(perAgentPendingLimit) || perAgentPendingLimit < 1) throw new RangeError("The per-agent approval limit must be a positive integer.");
  const finishedRetentionMs = options.finishedRetentionMs ?? 0;
  if (!Number.isSafeInteger(finishedRetentionMs) || finishedRetentionMs < 0) throw new RangeError("The finished-approval retention must be a non-negative integer.");
  return { records: new Map(), nextId: 1, limit, perAgentPendingLimit, finishedRetentionMs, ...(options.persistence ? { persistence: options.persistence } : {}) };
}

/** Open approvals (PENDING and not yet past their expiry) that one agent's credentials requested. */
export function openApprovalsFor(store: ApprovalStore, agentId: string, now: Date = new Date()): number {
  let open = 0;
  for (const record of store.records.values()) {
    if (record.status === "PENDING" && !isExpired(record, now) && isOwnAgentApproval(record, agentId)) open += 1;
  }
  return open;
}

/**
 * A record that may be dropped to make room: a final decision whose lifecycle
 * event has already been written. PENDING records are never evicted, and an
 * EXPIRED record is kept until its expiry event has been recorded.
 */
function isEvictable(record: ApprovalRecord, store?: ApprovalStore, now: Date = new Date()): boolean {
  // M3-E E12: a recently created record may still be referenced by an idempotency record.
  if (store && store.finishedRetentionMs > 0 && now.getTime() - new Date(record.createdAt).getTime() < store.finishedRetentionMs) return false;
  switch (record.status) {
    case "EXECUTED":
    case "REJECTED":
    case "BLOCKED_ON_RECHECK":
    case "APPROVED_NOT_EXECUTED":
    case "OUTCOME_UNKNOWN":
      return true;
    case "EXPIRED":
      return record.expiryEventPending !== true;
    default:
      return false;
  }
}

/** Evicts the oldest finished records until one more fits; false when only open records remain. */
export function makeRoom(store: ApprovalStore, now: Date = new Date()): boolean {
  for (const [id, record] of store.records) {
    if (store.records.size < store.limit) break;
    if (isEvictable(record, store, now)) store.records.delete(id);
  }
  return store.records.size < store.limit;
}

/** True when a new approval would not fit even after evicting every finished record. */
export function approvalStoreFull(store: ApprovalStore): boolean {
  if (store.records.size < store.limit) return false;
  let evictable = 0;
  for (const record of store.records.values()) if (isEvictable(record, store)) evictable += 1;
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
  // M3-E E9: one agent cannot hold more than its share of open approvals (operator scenarios are not counted).
  if (input.requestedBy?.kind === "agent" && typeof input.agentId === "string" && openApprovalsFor(store, input.agentId, now) >= store.perAgentPendingLimit) {
    throw new ApprovalCapacityError("agent");
  }
  // Bounded (M3-B): drop the oldest finished records; never an open one.
  if (!makeRoom(store, now)) throw new ApprovalCapacityError();
  const record: ApprovalRecord = {
    id: `apr-${store.nextId}`,
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
  // M3-E E12: durably recorded before the id is returned. On failure nothing is stored, and the id is
  // still consumed (it may be in the journal), so it is never handed out twice.
  store.nextId += 1;
  store.persistence?.created(record, store.nextId);
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
      recordExpiry(store, record);
      changed += 1;
    }
    if (record.status === "EXPIRED" && record.expiryEventPending && onExpired) {
      // Isolate failures per record: a throwing event write keeps the record
      // pending for the next retry and never blocks later stale records.
      try {
        onExpired(toPublicApproval(record));
        // M3-E E17 (Gate B, GB-1): record durably that the event was written (as approve and reject already
        // did). Clearing only the in-memory marker made every restart write the EXPIRED event again.
        markExpiryEventRecorded(store, record.id);
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
  try {
    store.persistence?.expiryRecorded(id);
  } catch {
    // Not recorded durably: after a restart the EXPIRED event may be written once more (delivery is not
    // exactly-once, as documented).
  }
  return true;
}

/**
 * M3-E E12: PENDING -> EXPIRED. Expiry follows from expiresAt, so even when the transition cannot be
 * recorded durably the record is treated as expired (after a restart it is derived again) and can never be
 * approved. The failure is logged; nothing is reported as a success.
 */
function recordExpiry(store: ApprovalStore, record: ApprovalRecord): void {
  try {
    store.persistence?.transitioned(record.id, "EXPIRED", null);
  } catch {
    console.warn(`approval-store status=write-failed transition=EXPIRED approvalId=${record.id} effect=derived-from-expiresAt`);
  }
  record.status = "EXPIRED";
  record.expiryEventPending = true;
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

/**
 * M3-E E4: everything an agent may see about one of its own approvals. Built field by
 * field, so nothing else in the record (intent, action, findings, untrusted content,
 * policy, actor or credential details) can reach an agent.
 */
export interface AgentApprovalView {
  id: string;
  status: ApprovalStatus;
  createdAt: string;
  expiresAt: string;
  executed: boolean;
  /** Seconds to wait before asking again while the approval is pending; null once it is final. */
  pollAfterSeconds: number | null;
}

export const AGENT_APPROVAL_POLL_SECONDS = 2;
export const AGENT_APPROVAL_PAGE_DEFAULT = 20;
export const AGENT_APPROVAL_PAGE_MAX = 50;

/**
 * Whether an agent may see a record: one that an agent credential requested, for this
 * agent. Any of the agent's credentials qualifies, so history survives rotation. An
 * operator-run seeded scenario is never visible to an agent, even one with the same id.
 */
export function isOwnAgentApproval(record: ApprovalRecord, agentId: string): boolean {
  return record.requestedBy?.kind === "agent" && record.agentId === agentId;
}

export function toAgentApprovalView(record: ApprovalRecord): AgentApprovalView {
  return {
    id: record.id,
    status: record.status,
    createdAt: record.createdAt,
    expiresAt: record.expiresAt,
    executed: record.execution?.executed === true,
    pollAfterSeconds: record.status === "PENDING" ? AGENT_APPROVAL_POLL_SECONDS : null,
  };
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
  /** `durable: false` (M3-E E12): it ran, but the outcome could not be recorded durably (report as unconfirmed). */
  | { kind: "executed"; approval: PendingApproval; execution: SimulatedExecution; recheck: EvaluationResult; durable: boolean };

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
    recordExpiry(store, record);
    return { kind: "expired", approval: toPublicApproval(record), expiryEventPending: true };
  }
  // Policy recheck against the exact stored intent/action/content. Client input plays no part.
  const recheck = reevaluate(record);
  if (recheck.decision === "BLOCK") {
    const blocked: SimulatedExecution = { executed: false, handler: null, result: null, reason: "Policy recheck returned BLOCK." };
    store.persistence?.transitioned(id, "BLOCKED_ON_RECHECK", blocked); // throws: nothing changed
    record.status = "BLOCKED_ON_RECHECK";
    record.execution = blocked;
    return { kind: "blocked-on-recheck", approval: toPublicApproval(record), recheck };
  }
  // M3-E E12: write-ahead. If the API stops after this and before the outcome is recorded, recovery marks
  // the approval OUTCOME_UNKNOWN: it is never run again and never reported as executed.
  store.persistence?.approving(id); // throws: nothing changed, nothing ran
  const execution = simulator.execute(clone(record.action), "ALLOW");
  // The recheck passed; if no handler ran, that is not a policy block (M3-B).
  const status: ApprovalStatus = execution.executed ? "EXECUTED" : "APPROVED_NOT_EXECUTED";
  record.execution = execution;
  record.status = status;
  let durable = true;
  try {
    store.persistence?.transitioned(id, status, execution);
  } catch {
    // It ran, but the outcome is not durable: the store refuses further changes, and after a restart the
    // write-ahead record makes this approval OUTCOME_UNKNOWN. The caller reports it as unconfirmed.
    durable = false;
  }
  return { kind: "executed", approval: toPublicApproval(record), execution, recheck, durable };
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
    recordExpiry(store, record);
    return { kind: "expired", approval: toPublicApproval(record), expiryEventPending: true };
  }
  const rejected: SimulatedExecution = { executed: false, handler: null, result: null, reason: "Rejected by user. No handler invoked." };
  store.persistence?.transitioned(id, "REJECTED", rejected); // M3-E E12: throws before anything changes
  record.status = "REJECTED";
  record.execution = rejected;
  return { kind: "rejected", approval: toPublicApproval(record) };
}
