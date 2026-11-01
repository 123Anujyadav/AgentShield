import {
  AgentShieldError,
  AgentShieldClient,
  ApprovalNotFoundError,
  AuthenticationError,
  BadRequestError,
  ForbiddenError,
  InvalidArgumentError,
  NetworkError,
  RateLimitedError,
  ResponseFormatError,
  ServiceUnavailableError,
  TimeoutError,
  WaitTimeoutError,
  type AgentApproval,
  type Decision,
  type EvaluateRequest,
  type EvaluateResult,
} from "@agentshield/agent-sdk";
import { summarize } from "./summarize.js";
import { parseSummaryTask, TaskInputError, type SummaryTask } from "./task.js";
import { SimulatedWorkspace, type SavedSummary } from "./workspace.js";

/**
 * The reference agent (M3-E E6): summarizes a document into a simulated workspace, asking
 * AgentShield first through the official SDK.
 *
 * - The summary is computed locally; saving it is the only side effect, and it happens
 *   only when AgentShield reports the action as executed (an ALLOW, or an approval that
 *   reached EXECUTED). Every other outcome saves nothing.
 * - The action is fixed. The document is sent as untrusted content and never changes what
 *   the agent does.
 * - The agent's identity is its credential, held by the SDK client. Nothing here names an
 *   agent, signs a request or talks to AgentShield other than through the client.
 * - An evaluation is sent once. If its outcome is unknown (a timeout, a network error, a
 *   server error) the agent reports that and does not send it again.
 * - The agent can only read its approvals. Approving or rejecting is the operator's.
 */

/** The one action the agent ever requests. */
export const SUMMARY_ACTION = Object.freeze({ type: "create_summary", tool: "simulated.workspace.createSummary", destination: "simulated-workspace" });
const TASK_DESCRIPTION = "Summarize a document into the simulated workspace";

/** Default wait for an operator decision: just past the server's 15-minute approval lifetime. */
export const DEFAULT_APPROVAL_WAIT_MS = 16 * 60 * 1000;
export const MAX_APPROVAL_WAIT_MS = 24 * 60 * 60 * 1000;

/** Why a request did not complete. Fixed codes, safe to display. */
export type FailureReason =
  | "authentication"
  | "forbidden"
  | "bad-request"
  | "rate-limited"
  | "unavailable"
  | "timeout"
  | "network"
  | "server-error"
  | "response-format"
  | "cancelled"
  /** Refused by the SDK before sending: the encoded request is over AgentShield's 32 KB limit. */
  | "request-too-large"
  /** 503 approval-queue-full: CONFIRM was needed, but no approval was created and nothing executed. */
  | "approval-queue-full";

/** What AgentShield decided. Finding evidence is left out: it can quote the document. */
export interface EvaluationSummary {
  decision: Decision;
  riskScore: number;
  explanation: string;
  findings: Array<{ ruleId: string; severity: string; title: string }>;
}

export type TaskOutcome =
  /** AgentShield executed the action; the summary was saved. */
  | { status: "completed"; evaluation: EvaluationSummary; approvalId: string | null; saved: SavedSummary }
  /** AgentShield refused the action. */
  | { status: "blocked"; evaluation: EvaluationSummary }
  /** Allowed or approved, but AgentShield did not execute it, so nothing was saved. */
  | { status: "not-executed"; evaluation: EvaluationSummary; approvalId: string | null }
  /** The operator rejected it, it expired, or it failed the check made at approval time. */
  | { status: "rejected" | "expired" | "blocked-on-recheck"; evaluation: EvaluationSummary; approvalId: string }
  /** Still waiting for the operator when the wait ended. `resume` continues it. */
  | { status: "pending"; evaluation: EvaluationSummary; approvalId: string }
  /** The approval could not be read (for example the credential was revoked, or AgentShield went away). `resume` can try again. */
  | { status: "wait-interrupted"; evaluation: EvaluationSummary; approvalId: string; reason: FailureReason }
  /** AgentShield no longer knows the approval (for example it restarted and lost pending approvals). */
  | { status: "approval-missing"; evaluation: EvaluationSummary; approvalId: string }
  /** The evaluation may or may not have been processed. It was not sent again. */
  | { status: "unconfirmed"; reason: FailureReason }
  /** AgentShield refused the request before processing it. */
  | { status: "refused"; reason: FailureReason; retryAfterSeconds: number | null };

export class UnknownApprovalError extends Error {
  constructor() {
    super("This agent did not start that approval, or has already finished it.");
    this.name = "UnknownApprovalError";
  }
}

export interface ReferenceAgentOptions {
  /** The official SDK client. It holds the credential, so it decides who the agent is. */
  client: AgentShieldClient;
  workspace?: SimulatedWorkspace;
  /** How long to wait for an operator decision (default 16 minutes). */
  approvalWaitMs?: number;
}

interface PendingTask {
  title: string;
  summary: string;
  evaluation: EvaluationSummary;
  /**
   * When the server created this task's approval (from the evaluate response). Approval ids start
   * again at apr-1 after an API restart, so the id alone can later name a different approval; an
   * approval whose createdAt differs is not this task's (M3-E E9).
   */
  createdAt: string;
  waiting: boolean;
}

export class ReferenceAgent {
  readonly workspace: SimulatedWorkspace;
  readonly #client: AgentShieldClient;
  readonly #approvalWaitMs: number;
  /** Approvals this agent started and has not finished. Only these can be resumed. */
  readonly #pending = new Map<string, PendingTask>();

  constructor(options: ReferenceAgentOptions) {
    if (!(options.client instanceof AgentShieldClient)) throw new TypeError("The reference agent talks to AgentShield only through the official SDK client.");
    this.#client = options.client;
    this.workspace = options.workspace ?? new SimulatedWorkspace();
    const wait = options.approvalWaitMs ?? DEFAULT_APPROVAL_WAIT_MS;
    if (!Number.isSafeInteger(wait) || wait < 1 || wait > MAX_APPROVAL_WAIT_MS) throw new RangeError("approvalWaitMs must be a whole number of ms from 1 to 24 hours.");
    this.#approvalWaitMs = wait;
  }

  /** The exact request sent for a task: a fixed action, with the document as untrusted content. */
  static evaluationRequest(task: SummaryTask, summary: string): EvaluateRequest {
    return {
      intent: { task: TASK_DESCRIPTION, allowedActions: [SUMMARY_ACTION.type], allowedDestinations: [SUMMARY_ACTION.destination] },
      action: { ...SUMMARY_ACTION, summary: `Save a ${summary.length}-character summary of a document to the simulated workspace` },
      untrustedContent: { source: "document", text: task.text },
    };
  }

  /** Summarizes a document, asks AgentShield, and saves the summary only if AgentShield executed the action. */
  async run(input: unknown, options: { signal?: AbortSignal } = {}): Promise<TaskOutcome> {
    const task = parseSummaryTask(input);
    const summary = summarize(task.text);
    // Only invisible or control characters: there is nothing to summarize, so nothing is asked or saved (M3-E E9).
    if (summary.length === 0) throw new TaskInputError("The document has no readable text.");

    let result: EvaluateResult;
    try {
      // Sent exactly once, whatever happens.
      result = await this.#client.evaluate(ReferenceAgent.evaluationRequest(task, summary));
    } catch (error) {
      return evaluateFailure(error);
    }
    const evaluation = summarizeEvaluation(result);

    if (result.decision === "BLOCK") return { status: "blocked", evaluation };
    if (result.decision === "ALLOW") {
      if (result.executed && result.approvalId === null) return this.#complete(task.title, summary, evaluation, null);
      return { status: "not-executed", evaluation, approvalId: null };
    }
    // CONFIRM: only an operator can let it go ahead.
    if (result.approvalId === null || result.approvalCreatedAt === null || result.executed) return { status: "not-executed", evaluation, approvalId: result.approvalId };
    // If this id is already being followed, it belonged to an approval from before an API restart: that
    // approval is gone, and its follower will find the entry replaced and report it missing (M3-E E9).
    this.#pending.set(result.approvalId, { title: task.title, summary, evaluation, createdAt: result.approvalCreatedAt, waiting: false });
    return this.#follow(result.approvalId, options.signal);
  }

  /** Continues waiting for an approval this agent started (after "pending" or "wait-interrupted"). */
  async resume(approvalId: string, options: { signal?: AbortSignal } = {}): Promise<TaskOutcome> {
    if (typeof approvalId !== "string" || !this.#pending.has(approvalId)) throw new UnknownApprovalError();
    return this.#follow(approvalId, options.signal);
  }

  /** The approvals this agent is still following. */
  pendingApprovals(): string[] {
    return [...this.#pending.keys()];
  }

  async #follow(approvalId: string, signal: AbortSignal | undefined): Promise<TaskOutcome> {
    const task = this.#pending.get(approvalId)!;
    if (task.waiting) throw new Error("This approval is already being followed.");
    task.waiting = true;
    let approval: AgentApproval;
    try {
      approval = await this.#client.waitForApproval(approvalId, { timeoutMs: this.#approvalWaitMs, signal });
    } catch (error) {
      task.waiting = false;
      const { evaluation } = task;
      if (error instanceof WaitTimeoutError) return { status: "pending", evaluation, approvalId };
      if (error instanceof ApprovalNotFoundError) {
        this.#forget(approvalId, task);
        return { status: "approval-missing", evaluation, approvalId };
      }
      if (signal?.aborted) return { status: "wait-interrupted", evaluation, approvalId, reason: "cancelled" };
      if (error instanceof AgentShieldError) return { status: "wait-interrupted", evaluation, approvalId, reason: failureReason(error) };
      throw error;
    }
    const { evaluation } = task;
    // Not this task's approval: replaced by a newer task with the same id, or the same id reissued after an
    // API restart (a different createdAt). Its outcome says nothing about this task, so nothing is saved.
    if (this.#pending.get(approvalId) !== task || approval.createdAt !== task.createdAt) {
      this.#forget(approvalId, task);
      return { status: "approval-missing", evaluation, approvalId };
    }
    this.#pending.delete(approvalId);
    switch (approval.status) {
      case "EXECUTED":
        // Saved only when the server says the approved action ran.
        if (approval.executed) return this.#complete(task.title, task.summary, evaluation, approvalId);
        return { status: "not-executed", evaluation, approvalId };
      case "APPROVED_NOT_EXECUTED":
        return { status: "not-executed", evaluation, approvalId };
      case "REJECTED":
        return { status: "rejected", evaluation, approvalId };
      case "EXPIRED":
        return { status: "expired", evaluation, approvalId };
      case "BLOCKED_ON_RECHECK":
        return { status: "blocked-on-recheck", evaluation, approvalId };
      default:
        // waitForApproval never returns PENDING; anything else is not a go-ahead.
        return { status: "not-executed", evaluation, approvalId };
    }
  }

  /** Stops following an approval, unless a newer task has taken over its id. */
  #forget(approvalId: string, task: PendingTask): void {
    if (this.#pending.get(approvalId) === task) this.#pending.delete(approvalId);
  }

  #complete(title: string, summary: string, evaluation: EvaluationSummary, approvalId: string | null): TaskOutcome {
    const saved = this.workspace.save({ title, summary, approvalId });
    return { status: "completed", evaluation, approvalId, saved };
  }
}

function summarizeEvaluation(result: EvaluateResult): EvaluationSummary {
  return {
    decision: result.decision,
    riskScore: result.riskScore,
    explanation: result.explanation,
    findings: result.findings.map((f) => ({ ruleId: f.ruleId, severity: f.severity, title: f.title })),
  };
}

/**
 * Errors that prove the evaluation was not processed; anything else leaves it unknown and
 * is never sent again. A 503 is always unconfirmed, whatever its reason: the replay cache
 * refuses before processing, while a full approval queue answers after the evaluation was
 * recorded (nothing executed). Neither is a success, and neither is retried.
 */
function evaluateFailure(error: unknown): TaskOutcome {
  if (error instanceof AuthenticationError || error instanceof ForbiddenError || error instanceof BadRequestError || error instanceof InvalidArgumentError) {
    return { status: "refused", reason: failureReason(error), retryAfterSeconds: null };
  }
  if (error instanceof RateLimitedError) return { status: "refused", reason: "rate-limited", retryAfterSeconds: error.details.retryAfterSeconds ?? null };
  if (error instanceof AgentShieldError) return { status: "unconfirmed", reason: failureReason(error) };
  throw error;
}

function failureReason(error: AgentShieldError): FailureReason {
  if (error instanceof AuthenticationError) return "authentication";
  if (error instanceof ForbiddenError) return "forbidden";
  // InvalidArgumentError is the SDK refusing locally; for this agent's fixed request that only happens when the
  // encoded request is over 32 KB. Nothing was sent, so it is not reported as AgentShield's refusal (M3-E E9).
  if (error instanceof InvalidArgumentError) return "request-too-large";
  if (error instanceof BadRequestError) return "bad-request";
  if (error instanceof RateLimitedError) return "rate-limited";
  if (error instanceof ServiceUnavailableError) return error.details.reason === "approval-queue-full" ? "approval-queue-full" : "unavailable";
  if (error instanceof TimeoutError) return "timeout";
  if (error instanceof NetworkError) return "network";
  if (error instanceof ResponseFormatError) return "response-format";
  return "server-error";
}
