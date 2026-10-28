import cors from "cors";
import express from "express";
import type { ActivityEvent, PendingApproval, ProposedAction, SimulatedExecution, UntrustedContent, UserIntent } from "@agentshield/engine";
import { evaluateAction, getScenario, MAX_SCAN_LENGTH, SCENARIOS } from "@agentshield/engine";
import {
  createApprovalStore,
  expirePendingApprovals,
  markExpiryEventRecorded,
  processApproval,
  processRejection,
  createPendingApproval,
  publicExecution,
  toPublicApproval,
  type ApprovalStore,
} from "./approvals.js";
import { createSimulator, type Simulator } from "./simulator.js";
import { ModelAnalysisService } from "./model/analyze.js";
import { loadModelConfig, type ModelConfig } from "./model/config.js";
import { selectModelProvider } from "./model/live.js";
import { failedAnalysis, redactSecretValue } from "@agentshield/engine";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function parseIntent(value: unknown): UserIntent | null {
  if (!isRecord(value)) return null;
  if (typeof value.task !== "string" || !value.task.trim()) return null;
  if (!Array.isArray(value.allowedActions) || !value.allowedActions.every((v) => typeof v === "string")) return null;
  if (!Array.isArray(value.deniedActions) || !value.deniedActions.every((v) => typeof v === "string")) return null;
  if (value.id !== undefined && typeof value.id !== "string") return null;
  if (
    value.allowedDestinations !== undefined &&
    (!Array.isArray(value.allowedDestinations) || !value.allowedDestinations.every((v) => typeof v === "string"))
  ) {
    return null;
  }
  return {
    id: typeof value.id === "string" ? value.id : undefined,
    task: value.task,
    allowedActions: value.allowedActions,
    deniedActions: value.deniedActions,
    allowedDestinations: Array.isArray(value.allowedDestinations) ? value.allowedDestinations : undefined,
  };
}

function parsePayload(value: unknown): ProposedAction["payload"] | null {
  if (value === undefined) return undefined;
  if (!isRecord(value) || Array.isArray(value)) return null;
  // Flat contract only: string, number, or boolean values. Nested objects,
  // arrays, null, and other types are rejected before evaluation so they can
  // never be stringified into a guard bypass or crash downstream code.
  for (const entry of Object.values(value)) {
    if (typeof entry !== "string" && typeof entry !== "number" && typeof entry !== "boolean") {
      return null;
    }
  }
  return value as ProposedAction["payload"];
}

function parseAction(value: unknown): ProposedAction | null {
  if (!isRecord(value)) return null;
  if (typeof value.type !== "string" || typeof value.tool !== "string") return null;
  if (typeof value.destination !== "string" || typeof value.summary !== "string") return null;
  const payload = parsePayload(value.payload);
  if (payload === null) return null;
  return {
    type: value.type,
    tool: value.tool,
    destination: value.destination,
    summary: value.summary,
    payload,
  };
}

type ParseResult = { ok: true; value?: UntrustedContent } | { ok: false; error: string };

/** Client-supplied findings/scores are never accepted; only raw content is parsed and re-scanned server-side. */
function parseUntrustedContent(value: unknown): ParseResult {
  if (value === undefined) return { ok: true, value: undefined };
  if (!isRecord(value)) return { ok: false, error: "untrustedContent must be an object {source, text}." };
  if (typeof value.source !== "string" || !value.source.trim()) return { ok: false, error: "untrustedContent.source must be a non-empty string." };
  if (typeof value.text !== "string") return { ok: false, error: "untrustedContent.text must be a string." };
  if (value.text.length > MAX_SCAN_LENGTH) return { ok: false, error: `untrustedContent.text exceeds ${MAX_SCAN_LENGTH} characters.` };
  return { ok: true, value: { source: value.source, text: value.text } };
}

export interface AppDeps {
  simulator?: Simulator;
  approvalStore?: ApprovalStore;
  modelService?: ModelAnalysisService;
  modelConfig?: ModelConfig;
  /** Injectable so tests can fault-inject event writes. Defaults to a fresh in-memory list. */
  events?: ActivityEvent[];
}

export function createApp(deps: AppDeps = {}) {
  const app = express();
  const events: ActivityEvent[] = deps.events ?? [];
  const simulator = deps.simulator ?? createSimulator();
  const approvalStore = deps.approvalStore ?? createApprovalStore();
  const modelConfig = deps.modelConfig ?? loadModelConfig();
  const modelService =
    deps.modelService ?? new ModelAnalysisService(selectModelProvider(modelConfig), modelConfig);
  let nextId = 1;

  function recordEvent(
    partial: Omit<ActivityEvent, "id" | "timestamp">,
  ): ActivityEvent {
    // Secret-shaped request metadata (destination, and since Phase I the
    // action type, tool, and intent task) is never stored in the public event log.
    const safePartial = {
      ...partial,
      intentTask: redactSecretValue(partial.intentTask),
      actionType: redactSecretValue(partial.actionType),
      tool: redactSecretValue(partial.tool),
      destination: redactSecretValue(partial.destination),
    };
    const event: ActivityEvent = {
      id: `evt-${nextId++}`,
      timestamp: new Date().toISOString(),
      ...safePartial,
    };
    events.push(event);
    return event;
  }

  app.use(cors({ origin: ["http://localhost:5173", "http://127.0.0.1:5173"] }));
  app.use(express.json({ limit: "32kb" }));

  app.get("/health", (_req, res) => {
    res.json({ status: "ok", service: "agentshield-api" });
  });

  app.get("/api/scenarios", (_req, res) => {
    res.json({ scenarios: SCENARIOS });
  });

  app.get("/api/model/status", (_req, res) => {
    // Presence flag only. The key value is never returned, logged, or sent to the frontend.
    res.json({
      mode: modelConfig.effectiveMode,
      requestedMode: modelConfig.requestedMode,
      provider: modelConfig.provider,
      model: modelConfig.model,
      baseUrl: modelConfig.baseUrl,
      apiKeyConfigured: modelConfig.apiKeyConfigured,
      liveFlagSet: modelConfig.liveFlagSet,
      liveEnabled: modelConfig.liveEnabled,
      isMock: modelConfig.effectiveMode === "mock",
      note: modelConfig.liveEnabled
        ? "Live provider is gated on by server flag and key presence."
        : "Mock provider. Live is disabled by default (MODEL_LIVE_ENABLED is not true, or no key is configured).",
    });
  });

  app.get("/api/events", (_req, res) => {
    res.json({ events: [...events].reverse() });
  });

  app.post("/api/evaluate", async (req, res, next) => {
    try {
    const body: unknown = req.body;
    if (!isRecord(body)) {
      res.status(400).json({ error: "JSON object body required." });
      return;
    }

    let scenarioId: string | null = null;
    let intent: UserIntent | null = null;
    let action: ProposedAction | null = null;
    let untrustedContent: UntrustedContent | undefined;

    if (typeof body.scenarioId === "string") {
      const scenario = getScenario(body.scenarioId);
      if (!scenario) {
        res.status(404).json({ error: `Unknown scenario: ${redactSecretValue(body.scenarioId)}` });
        return;
      }
      scenarioId = scenario.id;
      intent = scenario.intent;
      action = scenario.action;
      untrustedContent = scenario.untrustedContent;
    } else {
      intent = parseIntent(body.intent);
      action = parseAction(body.action);
      if (!intent || !action) {
        res.status(400).json({ error: "Provide scenarioId, or intent {task, allowedActions, deniedActions} and action {type, tool, destination, summary}." });
        return;
      }
      const parsed = parseUntrustedContent(body.untrustedContent);
      if (!parsed.ok) {
        res.status(400).json({ error: parsed.error });
        return;
      }
      untrustedContent = parsed.value;
    }

    // userApproved in the evaluate body is ignored for execution: approval only
    // happens through the approval endpoints against a server-created record.
    const evaluation = evaluateAction({ intent, action, untrustedContent });

    let execution: SimulatedExecution = {
      executed: false,
      handler: null,
      result: null,
      reason:
        evaluation.decision === "BLOCK"
          ? "Decision is BLOCK. No handler invoked."
          : "Decision is CONFIRM. Awaiting approval; no handler invoked.",
    };
    let pendingApproval = null as ReturnType<typeof createPendingApproval> | null;

    if (evaluation.decision === "ALLOW") {
      execution = publicExecution(simulator.execute(action, evaluation.decision), action.type);
    } else if (evaluation.decision === "CONFIRM") {
      pendingApproval = createPendingApproval(approvalStore, {
        scenarioId,
        intent,
        action,
        untrustedContent,
        evaluation,
      });
    }

    const event = recordEvent({
      scenarioId,
      intentTask: intent.task,
      actionType: action.type,
      tool: action.tool,
      destination: action.destination,
      decision: evaluation.decision,
      riskScore: evaluation.riskScore,
      findings: evaluation.findings,
      explanation: evaluation.explanation,
      approvalId: pendingApproval?.id,
      lifecycle: evaluation.decision === "ALLOW" ? (execution.executed ? "SIMULATED_EXECUTED" : "EVALUATED") : evaluation.decision === "CONFIRM" ? "PENDING_CONFIRMATION" : "BLOCKED",
    });
    // Advisory only: model analysis runs after the deterministic decision and
    // can never change decision, riskScore, execution, or approval state.
    const modelAnalysis = untrustedContent
      ? await modelService.analyze(untrustedContent.text)
      : failedAnalysis("mock", "mock (deterministic, offline)", "not-scanned", "unavailable");

    res.json({ evaluation, event, executed: execution.executed, execution, pendingApproval, modelAnalysis });
    } catch (error) {
      next(error);
    }
  });

  /**
   * Writes the single EXPIRED lifecycle event for an expiry transition.
   * The event timestamp is when expiry was detected (listing, approve or
   * reject), not the exact instant the TTL elapsed. A failed write is
   * swallowed on purpose: the record keeps its pending marker, so a later
   * listing, approve or reject retries it. Delivery is retry-based and
   * in-memory only, not strict exactly-once (see README).
   */
  function recordExpiryEvent(approval: PendingApproval): void {
    recordEvent({
      scenarioId: approval.scenarioId,
      intentTask: approval.intent.task,
      actionType: approval.action.type,
      tool: approval.action.tool,
      destination: approval.action.destination,
      decision: approval.decision,
      riskScore: approval.riskScore,
      findings: approval.findings,
      explanation:
        "Approval expiry detected on review: the record passed its 15-minute expiry and no handler was invoked. Event time is detection time, not the exact expiry instant.",
      approvalId: approval.id,
      lifecycle: "EXPIRED",
    });
  }

  /** Retries a pending expiry event; a failed write keeps the pending marker. */
  function tryRecordExpiryEvent(approval: PendingApproval): void {
    try {
      recordExpiryEvent(approval);
      markExpiryEventRecorded(approvalStore, approval.id);
    } catch {
      // Pending marker remains set; the next operation retries the write.
      console.warn(`approval-expiry-event status=write-failed approvalId=${approval.id} retry=pending`);
    }
  }

  app.get("/api/approvals", (_req, res) => {
    // Surface the documented TTL in listings: stale PENDING records are
    // reported as EXPIRED instead of pending forever.
    expirePendingApprovals(approvalStore, new Date(), recordExpiryEvent);
    const approvals = [...approvalStore.records.values()].map(toPublicApproval).reverse();
    res.json({ approvals });
  });

  function approvalIdParam(req: express.Request, res: express.Response): string | null {
    const id = req.params.id;
    if (typeof id !== "string" || !/^apr-\d+$/.test(id)) {
      res.status(400).json({ error: "Invalid approval id." });
      return null;
    }
    return id;
  }

  function hasValidBody(req: express.Request, res: express.Response): boolean {
    if (req.body !== undefined && req.body !== null && !isRecord(req.body)) {
      res.status(400).json({ error: "JSON object body required." });
      return false;
    }
    return true;
  }

  app.post("/api/approvals/:id/approve", (req, res) => {
    const id = approvalIdParam(req, res);
    if (!id || !hasValidBody(req, res)) return;
    // Any client-supplied action/findings/score in the body is ignored on purpose.
    const storedType = approvalStore.records.get(id)?.action.type ?? "";
    const outcome = processApproval(approvalStore, id, (record) =>
      evaluateAction({ intent: record.intent, action: record.action, untrustedContent: record.untrustedContent }),
      simulator,
    );
    if (outcome.kind === "not-found") {
      res.status(404).json({ error: `Unknown approval: ${id}`, executed: false });
      return;
    }
    if (outcome.kind === "already-final") {
      res.status(409).json({ error: `Approval ${id} is already ${outcome.approval.status}.`, approval: outcome.approval, executed: false });
      return;
    }
    if (outcome.kind === "expired") {
      if (outcome.expiryEventPending) tryRecordExpiryEvent(outcome.approval);
      res.status(410).json({ error: `Approval ${id} has expired.`, approval: outcome.approval, executed: false });
      return;
    }
    if (outcome.kind === "blocked-on-recheck") {
      recordEvent({
        scenarioId: outcome.approval.scenarioId,
        intentTask: outcome.approval.intent.task,
        actionType: outcome.approval.action.type,
        tool: outcome.approval.action.tool,
        destination: outcome.approval.action.destination,
        decision: "BLOCK",
        riskScore: outcome.recheck.riskScore,
        findings: outcome.recheck.findings,
        explanation: "Approval rejected by policy recheck: current policy returns BLOCK. Nothing executed.",
        approvalId: id,
        lifecycle: "BLOCKED_ON_RECHECK",
      });
      res.status(409).json({ error: "Policy recheck returned BLOCK. Approval rejected; nothing executed.", approval: outcome.approval, executed: false });
      return;
    }
    const execution = publicExecution(outcome.execution, storedType);
    recordEvent({
      scenarioId: outcome.approval.scenarioId,
      intentTask: outcome.approval.intent.task,
      actionType: outcome.approval.action.type,
      tool: outcome.approval.action.tool,
      destination: outcome.approval.action.destination,
      decision: outcome.approval.decision,
      riskScore: outcome.approval.riskScore,
      findings: outcome.approval.findings,
      explanation: execution.executed
        ? "Approved after policy recheck. Simulated handler executed exactly once."
        : `Approved, but simulated execution did not run: ${execution.reason}`,
      approvalId: id,
      lifecycle: outcome.execution.executed ? "SIMULATED_EXECUTED" : "APPROVED_NOT_EXECUTED",
    });
    res.json({ approval: outcome.approval, execution, executed: execution.executed });
  });

  app.post("/api/approvals/:id/reject", (req, res) => {
    const id = approvalIdParam(req, res);
    if (!id || !hasValidBody(req, res)) return;
    const outcome = processRejection(approvalStore, id);
    if (outcome.kind === "not-found") {
      res.status(404).json({ error: `Unknown approval: ${id}`, executed: false });
      return;
    }
    if (outcome.kind === "already-final") {
      res.status(409).json({ error: `Approval ${id} is already ${outcome.approval.status}.`, approval: outcome.approval, executed: false });
      return;
    }
    if (outcome.kind === "expired") {
      if (outcome.expiryEventPending) tryRecordExpiryEvent(outcome.approval);
      res.status(410).json({ error: `Approval ${id} has expired.`, approval: outcome.approval, executed: false });
      return;
    }
    recordEvent({
      scenarioId: outcome.approval.scenarioId,
      intentTask: outcome.approval.intent.task,
      actionType: outcome.approval.action.type,
      tool: outcome.approval.action.tool,
      destination: outcome.approval.action.destination,
      decision: outcome.approval.decision,
      riskScore: outcome.approval.riskScore,
      findings: outcome.approval.findings,
      explanation: "Rejected by user. No handler invoked.",
      approvalId: id,
      lifecycle: "REJECTED",
    });
    res.json({ approval: outcome.approval, executed: false });
  });

  // Controlled error surface: no stack traces, request bodies, or secret
  // values. Only a sanitized category is logged.
  app.use((error: unknown, _req: express.Request, res: express.Response, next: express.NextFunction) => {
    if (res.headersSent) {
      next(error);
      return;
    }
    const isParseError =
      error instanceof SyntaxError ||
      (isRecord(error) && (error.type === "entity.parse.failed" || error.type === "entity.too.large"));
    if (isParseError) {
      console.warn("api-request status=bad-request category=malformed-json");
      res.status(400).json({ error: "Malformed JSON body." });
      return;
    }
    console.warn("api-request status=internal-error category=unhandled");
    res.status(500).json({ error: "Internal error." });
  });

  return app;
}
