import cors from "cors";
import express from "express";
import type { ActivityEvent, PendingApproval, ProposedAction, RequestedIntent, SimulatedExecution, UntrustedContent, UserIntent } from "@agentshield/engine";
import { getScenario, MAX_SCAN_LENGTH, SCENARIOS } from "@agentshield/engine";
import { evaluateForAgent, parseAgentId, recheckApproval } from "./policies/enforce.js";
import { builtInPolicyStore, type PolicyStore } from "./policies/store.js";
import {
  ApprovalCapacityError,
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
import { randomBytes } from "node:crypto";
import { createApiAuth, createSessionStore, MIN_TOKEN_LENGTH, registerSessionRoutes } from "./security/auth.js";
import { loadSecurityConfig, type SecurityConfig } from "./security/config.js";
import { createRateLimiter } from "./security/rate-limit.js";
import { hostCheck, originCheck } from "./security/request-guards.js";
import { loadScanConfig } from "./scans/config.js";
import { registerScanRoutes } from "./scans/routes.js";
import { ScanService } from "./scans/service.js";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

/**
 * What a request asks for (M3-C). Every list is optional: an omitted list inherits
 * the agent's server-side policy; a present list can only narrow it, and an empty
 * list grants nothing in that category.
 */
function parseIntent(value: unknown): RequestedIntent | null {
  if (!isRecord(value)) return null;
  if (typeof value.task !== "string" || !value.task.trim()) return null;
  if (value.id !== undefined && typeof value.id !== "string") return null;
  const list = (field: unknown): string[] | undefined | null =>
    field === undefined ? undefined : Array.isArray(field) && field.every((v) => typeof v === "string") ? (field as string[]) : null;
  const allowedActions = list(value.allowedActions);
  const deniedActions = list(value.deniedActions);
  const allowedDestinations = list(value.allowedDestinations);
  if (allowedActions === null || deniedActions === null || allowedDestinations === null) return null;
  return {
    ...(typeof value.id === "string" ? { id: value.id } : {}),
    task: value.task,
    ...(allowedActions !== undefined ? { allowedActions } : {}),
    ...(deniedActions !== undefined ? { deniedActions } : {}),
    ...(allowedDestinations !== undefined ? { allowedDestinations } : {}),
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
  /** M3-C: server-side agent policies. Defaults to the built-in demo agent only. */
  policyStore?: PolicyStore;
  modelService?: ModelAnalysisService;
  modelConfig?: ModelConfig;
  /** Injectable so tests can fault-inject event writes. Defaults to a fresh in-memory list. */
  events?: ActivityEvent[];
  /**
   * The local API token (see security/token.ts). Without one, a random token
   * that nobody knows is used, so every protected route refuses access
   * (fail closed) instead of running unauthenticated.
   */
  apiToken?: string;
  /** Overrides for API safety settings; the rest come from the environment. */
  security?: Partial<SecurityConfig>;
  /** Clock for sessions and rate limits (milliseconds). Injectable for tests. */
  now?: () => number;
  /** Website scanning (M1). Defaults to environment settings, which leave scanning off. */
  scanService?: ScanService;
}

export function createApp(deps: AppDeps = {}) {
  const app = express();
  const events: ActivityEvent[] = deps.events ?? [];
  const simulator = deps.simulator ?? createSimulator();
  const approvalStore = deps.approvalStore ?? createApprovalStore();
  const policyStore = deps.policyStore ?? builtInPolicyStore();
  const modelConfig = deps.modelConfig ?? loadModelConfig();
  const modelService =
    deps.modelService ?? new ModelAnalysisService(selectModelProvider(modelConfig), modelConfig);
  const security: SecurityConfig = { ...loadSecurityConfig(), ...deps.security };
  if (deps.apiToken !== undefined && deps.apiToken.length < MIN_TOKEN_LENGTH) {
    throw new Error(`The API token must be at least ${MIN_TOKEN_LENGTH} characters.`);
  }
  const apiToken = deps.apiToken ?? randomBytes(32).toString("base64url");
  const now = deps.now ?? Date.now;
  const sessions = createSessionStore({
    absoluteMs: security.sessionAbsoluteMs,
    idleMs: security.sessionIdleMs,
    maxSessions: security.maxSessions,
    now,
  });
  const auth = createApiAuth(apiToken, sessions, security);
  const limit = createRateLimiter({ windowMs: security.rateLimitWindowMs, now });
  const scanService = deps.scanService ?? new ScanService({ config: loadScanConfig() });
  let nextId = 1;

  function recordEvent(
    partial: Omit<ActivityEvent, "id" | "timestamp">,
  ): ActivityEvent {
    // Secret-shaped request metadata (destination, and since Phase I the
    // action type, tool, and intent task; since M3-C the agent id) is never stored in the public event log.
    // Display only: policy lookup and enforcement use the original agent id.
    const safePartial = {
      ...partial,
      intentTask: redactSecretValue(partial.intentTask),
      actionType: redactSecretValue(partial.actionType),
      tool: redactSecretValue(partial.tool),
      destination: redactSecretValue(partial.destination),
      ...(typeof partial.agentId === "string" ? { agentId: redactSecretValue(partial.agentId) } : {}),
    };
    const event: ActivityEvent = {
      id: `evt-${nextId++}`,
      timestamp: new Date().toISOString(),
      ...safePartial,
    };
    events.push(event);
    // Bounded retention: keep only the newest events, so the log cannot grow without limit.
    if (events.length > security.maxEvents) events.splice(0, events.length - security.maxEvents);
    return event;
  }

  // Order matters: Host and Origin checks first, then CORS, body parsing, the
  // global rate limit, sign-in routes, and authentication for the rest of /api.
  app.disable("x-powered-by");
  app.use(hostCheck(security.allowedHostnames));
  app.use(originCheck(security.allowedOrigins));
  app.use(cors({ origin: [...security.allowedOrigins], credentials: true }));
  app.use(express.json({ limit: "32kb" }));

  app.get("/health", (_req, res) => {
    res.json({ status: "ok", service: "agentshield-api" });
  });

  app.use("/api", limit("api", security.rateLimits.api));
  registerSessionRoutes(app, { apiToken, auth, sessions, limit, config: security });
  // Every /api route registered below, including future ones, requires authentication.
  app.use("/api", auth.requireAuth);
  registerScanRoutes(app, { service: scanService, limit });

  // M3-C: read-only view of the server-side agent policies. There is no write endpoint;
  // policies change only by editing the policy file and restarting the server.
  app.get("/api/policies", (_req, res) => {
    const shown = (values: readonly string[]) => values.map(redactSecretValue);
    res.json({
      source: policyStore.source,
      policies: policyStore.list().map(({ policy, ref }) => ({
        agentId: ref.agentId,
        version: ref.version,
        sha256: ref.sha256,
        description: policy.description === undefined ? null : redactSecretValue(policy.description),
        allowedActions: shown(policy.allowedActions),
        deniedActions: shown(policy.deniedActions),
        allowedDestinations: shown(policy.allowedDestinations),
      })),
    });
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

  app.post("/api/evaluate", limit("evaluate", security.rateLimits.evaluate), async (req, res, next) => {
    try {
    const body: unknown = req.body;
    if (!isRecord(body)) {
      res.status(400).json({ error: "JSON object body required." });
      return;
    }

    let scenarioId: string | null = null;
    let agentId: string | null = null;
    let requested: RequestedIntent | null = null;
    let action: ProposedAction | null = null;
    let untrustedContent: UntrustedContent | undefined;

    if (typeof body.scenarioId === "string") {
      const scenario = getScenario(body.scenarioId);
      if (!scenario) {
        res.status(404).json({ error: `Unknown scenario: ${redactSecretValue(body.scenarioId)}` });
        return;
      }
      scenarioId = scenario.id;
      agentId = scenario.agentId;
      requested = scenario.intent;
      action = scenario.action;
      untrustedContent = scenario.untrustedContent;
    } else {
      // M3-C: an absent agentId is an unknown agent (denied below); a malformed one is a bad request.
      const parsedAgent = parseAgentId(body.agentId);
      if (!parsedAgent.ok) {
        res.status(400).json({
          error: "agentId must be a lowercase identifier: a-z or 0-9 first, then a-z, 0-9, '.', '_' or '-', at most 64 characters.",
          reason: "invalid-agent-id",
        });
        return;
      }
      agentId = parsedAgent.agentId;
      requested = parseIntent(body.intent);
      action = parseAction(body.action);
      if (!requested || !action) {
        res.status(400).json({
          error:
            "Provide scenarioId, or agentId, intent {task, and optionally allowedActions, deniedActions, allowedDestinations} and action {type, tool, destination, summary}.",
        });
        return;
      }
      const parsed = parseUntrustedContent(body.untrustedContent);
      if (!parsed.ok) {
        res.status(400).json({ error: parsed.error });
        return;
      }
      untrustedContent = parsed.value;
    }

    // The agent's server-side policy is authoritative (M3-C): the request can only
    // narrow it, and an unknown agent is an audited default-deny BLOCK.
    // userApproved in the evaluate body is ignored for execution: approval only
    // happens through the approval endpoints against a server-created record.
    const { evaluation, effectiveIntent } = evaluateForAgent(policyStore, agentId, requested, action, untrustedContent);
    const intent: UserIntent = effectiveIntent ?? { task: requested.task, allowedActions: [], deniedActions: [], allowedDestinations: [] };
    const agentFields = { agentId, agentPolicy: evaluation.agentPolicy ?? null };

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
      // Stale PENDING records become EXPIRED (with their event written) so they can make room.
      if (approvalStore.records.size >= approvalStore.limit) expirePendingApprovals(approvalStore, new Date(), recordExpiryEvent);
      try {
        pendingApproval = createPendingApproval(approvalStore, {
          scenarioId,
          intent,
          action,
          untrustedContent,
          evaluation,
          agentId,
          requestedIntent: requested,
          agentPolicy: evaluation.agentPolicy ?? null,
        });
      } catch (error) {
        if (!(error instanceof ApprovalCapacityError)) throw error;
        // Nothing runs without an approval record. The decision stays CONFIRM and is recorded.
        const event = recordEvent({
          scenarioId,
          intentTask: intent.task,
          actionType: action.type,
          tool: action.tool,
          destination: action.destination,
          decision: evaluation.decision,
          riskScore: evaluation.riskScore,
          findings: evaluation.findings,
          explanation: "Confirmation required, but the approval queue is full. Nothing was executed and no approval was created.",
          lifecycle: "CONFIRM_NOT_QUEUED",
          ...agentFields,
        });
        res.status(503).json({
          error: "The approval queue is full. Approve, reject or let pending approvals expire, then try again. Nothing was executed.",
          reason: "approval-queue-full",
          evaluation,
          event,
          executed: false,
          pendingApproval: null,
        });
        return;
      }
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
      ...agentFields,
    });
    // Advisory only: model analysis runs after the deterministic decision and
    // can never change decision, riskScore, execution, or approval state.
    const modelAnalysis = untrustedContent
      ? await modelService.analyze(untrustedContent.text)
      : failedAnalysis("mock", "mock (deterministic, offline)", "not-scanned", "unavailable");

    // The effective intent is not echoed: it can carry raw request metadata (Phase I redaction applies to events and approvals).
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
      agentId: approval.agentId ?? null,
      agentPolicy: approval.agentPolicy ?? null,
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

  app.post("/api/approvals/:id/approve", limit("approval-action", security.rateLimits.approvalAction), (req, res) => {
    const id = approvalIdParam(req, res);
    if (!id || !hasValidBody(req, res)) return;
    // Any client-supplied action/findings/score in the body is ignored on purpose.
    const storedType = approvalStore.records.get(id)?.action.type ?? "";
    const outcome = processApproval(approvalStore, id, (record) => recheckApproval(policyStore, record),
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
        agentId: outcome.approval.agentId ?? null,
        agentPolicy: outcome.recheck.agentPolicy ?? null,
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
      agentId: outcome.approval.agentId ?? null,
      agentPolicy: outcome.recheck.agentPolicy ?? null,
    });
    res.json({ approval: outcome.approval, execution, executed: execution.executed });
  });

  app.post("/api/approvals/:id/reject", limit("approval-action", security.rateLimits.approvalAction), (req, res) => {
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
      agentId: outcome.approval.agentId ?? null,
      agentPolicy: outcome.approval.agentPolicy ?? null,
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
