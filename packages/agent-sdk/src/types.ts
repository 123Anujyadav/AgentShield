import { ResponseFormatError } from "./errors.js";

/** What the agent wants to do and why (M3-C: it can only narrow the agent's server-side policy). */
export interface EvaluateRequest {
  intent: {
    task: string;
    id?: string;
    allowedActions?: string[];
    deniedActions?: string[];
    allowedDestinations?: string[];
  };
  action: {
    type: string;
    tool: string;
    destination: string;
    summary: string;
    payload?: Record<string, unknown>;
  };
  /** Content the agent read from somewhere it does not control (scanned for injection). */
  untrustedContent?: { source: string; text: string };
}

export type Decision = "ALLOW" | "CONFIRM" | "BLOCK";

export interface Finding {
  ruleId: string;
  category: string;
  severity: string;
  title: string;
  explanation: string;
  evidence: string;
}

/** The decision for an evaluated action. */
export interface EvaluateResult {
  decision: Decision;
  riskScore: number;
  explanation: string;
  findings: Finding[];
  /** Whether AgentShield ran the (simulated) action. */
  executed: boolean;
  /** For CONFIRM: the approval to follow with getApproval / waitForApproval. Otherwise null. */
  approvalId: string | null;
}

export type ApprovalStatus = "PENDING" | "EXECUTED" | "APPROVED_NOT_EXECUTED" | "REJECTED" | "EXPIRED" | "BLOCKED_ON_RECHECK";

/** The server's six-field view of one of this agent's approvals (M3-E E4). */
export interface AgentApproval {
  id: string;
  status: ApprovalStatus;
  createdAt: string;
  expiresAt: string;
  executed: boolean;
  /** Seconds to wait before asking again while pending; null once final. */
  pollAfterSeconds: number | null;
}

export interface ApprovalPage {
  approvals: AgentApproval[];
  /** Pass as `before` for the next (older) page; null on the last page. */
  nextCursor: string | null;
}

export interface ListApprovalsOptions {
  /** 1 to 50 (server default 20). */
  limit?: number;
  /** Only approvals older than this id. */
  before?: string;
  status?: ApprovalStatus;
}

export const APPROVAL_STATUSES: readonly ApprovalStatus[] = ["PENDING", "EXECUTED", "APPROVED_NOT_EXECUTED", "REJECTED", "EXPIRED", "BLOCKED_ON_RECHECK"];
export const APPROVAL_ID = /^apr-[1-9][0-9]{0,8}$/;
const APPROVAL_KEYS = ["createdAt", "executed", "expiresAt", "id", "pollAfterSeconds", "status"];

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Exactly the six-field contract; anything else is a protocol error. */
export function parseApproval(value: unknown): AgentApproval {
  if (!isRecord(value) || Object.keys(value).sort().join(",") !== APPROVAL_KEYS.join(",")) throw new ResponseFormatError();
  const { id, status, createdAt, expiresAt, executed, pollAfterSeconds } = value;
  if (typeof id !== "string" || !APPROVAL_ID.test(id)) throw new ResponseFormatError();
  if (typeof status !== "string" || !(APPROVAL_STATUSES as readonly string[]).includes(status)) throw new ResponseFormatError();
  if (typeof createdAt !== "string" || typeof expiresAt !== "string" || typeof executed !== "boolean") throw new ResponseFormatError();
  if (pollAfterSeconds !== null && (typeof pollAfterSeconds !== "number" || !Number.isFinite(pollAfterSeconds) || pollAfterSeconds < 0)) throw new ResponseFormatError();
  return { id, status: status as ApprovalStatus, createdAt, expiresAt, executed, pollAfterSeconds };
}

export function parseApprovalPage(value: unknown): ApprovalPage {
  if (!isRecord(value) || !Array.isArray(value.approvals)) throw new ResponseFormatError();
  const nextCursor = value.nextCursor;
  if (nextCursor !== null && (typeof nextCursor !== "string" || !APPROVAL_ID.test(nextCursor))) throw new ResponseFormatError();
  return { approvals: value.approvals.map(parseApproval), nextCursor };
}

function parseFinding(value: unknown): Finding {
  if (!isRecord(value)) throw new ResponseFormatError();
  const fields = ["ruleId", "category", "severity", "title", "explanation", "evidence"] as const;
  for (const field of fields) if (typeof value[field] !== "string") throw new ResponseFormatError();
  return { ruleId: value.ruleId as string, category: value.category as string, severity: value.severity as string, title: value.title as string, explanation: value.explanation as string, evidence: value.evidence as string };
}

/** The decision fields of an evaluate response; the rest of the server's response is not exposed. */
export function parseEvaluateResult(value: unknown): EvaluateResult {
  if (!isRecord(value) || !isRecord(value.evaluation)) throw new ResponseFormatError();
  const { decision, riskScore, explanation, findings } = value.evaluation;
  if (decision !== "ALLOW" && decision !== "CONFIRM" && decision !== "BLOCK") throw new ResponseFormatError();
  if (typeof riskScore !== "number" || typeof explanation !== "string" || !Array.isArray(findings) || typeof value.executed !== "boolean") throw new ResponseFormatError();
  const pending = value.pendingApproval;
  let approvalId: string | null = null;
  if (pending !== null && pending !== undefined) {
    if (!isRecord(pending) || typeof pending.id !== "string" || !APPROVAL_ID.test(pending.id)) throw new ResponseFormatError();
    approvalId = pending.id;
  }
  return { decision, riskScore, explanation, findings: findings.map(parseFinding), executed: value.executed, approvalId };
}
