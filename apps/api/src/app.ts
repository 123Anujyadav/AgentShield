import cors from "cors";
import express from "express";
import type { ActivityEvent, PendingApproval, ProposedAction, RequestActor, RequestedIntent, SimulatedExecution, UntrustedContent, UserIntent } from "@agentshield/engine";
import { getScenario, MAX_SCAN_LENGTH, POLICY_BLOCK_RISK, SCENARIOS } from "@agentshield/engine";
import { CREDENTIAL_PREFIX, emptyCredentialStore, SIGNING_CREDENTIAL_PREFIX, type CredentialStore } from "./agents/credentials.js";
import { createNonceCache, type NonceCache } from "./agents/nonce-cache.js";
import { captureRawBody, createSignatureVerifier, DEFAULT_SIGNATURE_SKEW_SECONDS } from "./agents/signature.js";
import { evaluateForAgent, IDENTITY_MISMATCH_RULE_ID, parseAgentId, recheckApproval } from "./policies/enforce.js";
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
import { createApiAuth, createSessionStore, isOperator, MIN_TOKEN_LENGTH, registerSessionRoutes, type Authentication } from "./security/auth.js";
import { loadSecurityConfig, type SecurityConfig } from "./security/config.js";
import { createFailureLimiter, createRateLimiter } from "./security/rate-limit.js";
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

/**
 * Request-body errors raised by express.json (body-parser), mapped to a safe client
 * response (M3-E audit L2). Only body-parser's own errors qualify: a known `type`, or an
 * http-errors error marked `expose` with a 4xx status (how a malformed gzip/deflate body
 * arrives). Anything else is an internal error. Messages are fixed text: the parser's
 * message, the body and any stack are never returned or logged.
 */
function bodyParserClientError(error: unknown): { status: 400 | 413 | 415; category: string; message: string } | null {
  if (!isRecord(error)) return null;
  switch (error.type) {
    case "entity.parse.failed":
      return { status: 400, category: "malformed-json", message: "Malformed JSON body." };
    case "entity.too.large":
      return { status: 413, category: "body-too-large", message: "Request body too large." };
    case "charset.unsupported":
    case "encoding.unsupported":
      return { status: 415, category: "unsupported-body-encoding", message: "Unsupported request body encoding." };
    case "request.aborted":
    case "request.size.invalid":
      return { status: 400, category: "malformed-body", message: "Malformed request body." };
  }
  const status = typeof error.status === "number" ? error.status : null;
  if (error.expose === true && status !== null && status >= 400 && status < 500) {
    if (status === 413) return { status: 413, category: "body-too-large", message: "Request body too large." };
    if (status === 415) return { status: 415, category: "unsupported-body-encoding", message: "Unsupported request body encoding." };
    return { status: 400, category: "malformed-body", message: "Malformed request body." };
  }
  return null;
}

export interface AppDeps {
  simulator?: Simulator;
  approvalStore?: ApprovalStore;
  /** M3-C: server-side agent policies. Defaults to the built-in demo agent only. */
  policyStore?: PolicyStore;
  /** M3-D: agent credentials (hashes and public keys only). Defaults to none, so no agent can authenticate. */
  credentialStore?: CredentialStore;
  /** M3-E E3: replay protection for signed requests. Defaults to a fresh in-memory cache (600 per key, 100,000 total). */
  nonceCache?: NonceCache;
  /** M3-E E3: allowed clock skew for signed requests, in ms (server: AGENT_SIGNATURE_MAX_SKEW_SECONDS). Default 30 s. */
  signatureSkewMs?: number;
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
  // M3-D/M3-E: an operator token must never look like an agent credential of either scheme.
  if (apiToken.startsWith(CREDENTIAL_PREFIX) || apiToken.startsWith(SIGNING_CREDENTIAL_PREFIX)) {
    throw new Error(`The API token must not start with "${CREDENTIAL_PREFIX}" or "${SIGNING_CREDENTIAL_PREFIX}".`);
  }
  const credentialStore = deps.credentialStore ?? emptyCredentialStore();
  const now = deps.now ?? Date.now;
  const sessions = createSessionStore({
    absoluteMs: security.sessionAbsoluteMs,
    idleMs: security.sessionIdleMs,
    maxSessions: security.maxSessions,
    now,
  });
  const failures = createFailureLimiter({ windowMs: security.rateLimitWindowMs, now, limit: security.rateLimits.authFailure });
  // M3-E E3: signed agent requests. The start-up fence refuses timestamps from before this point.
  const signatureSkewMs = deps.signatureSkewMs ?? DEFAULT_SIGNATURE_SKEW_SECONDS * 1000;
  const verifySigned = createSignatureVerifier({
    credentials: credentialStore,
    nonces: deps.nonceCache ?? createNonceCache({ now }),
    now,
    skewMs: signatureSkewMs,
    startedAt: now(),
  });
  const auth = createApiAuth(apiToken, sessions, security, {
    credentials: credentialStore,
    failures,
    verifySigned,
    signedRetryAfterSeconds: Math.ceil(signatureSkewMs / 1000),
  });
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
      ...(typeof partial.claimedAgentId === "string" ? { claimedAgentId: redactSecretValue(partial.claimedAgentId) } : {}),
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
  // The exact body bytes are kept for signed-request verification (M3-E E3); the 32 KB limit applies to both.
  app.use(express.json({ limit: "32kb", verify: captureRawBody }));

  app.get("/health", (_req, res) => {
    res.json({ status: "ok", service: "agentshield-api" });
  });

  app.use("/api", limit("api", security.rateLimits.api));
  registerSessionRoutes(app, { apiToken, auth, sessions, limit, config: security });
  // Every /api route registered below, including future ones, requires authentication.
  app.use("/api", auth.requireAuth);
  // M3-D: operator and agent separation. An agent credential is accepted on exactly one
  // route, POST /api/evaluate (custom evaluations); every other route, including future
  // ones and approve/reject, is operator-only. Agents can never approve their own actions.
  // /api/session requests skip authentication, so they may arrive here with no caller; they are
  // not agents and fall through to the normal 404 (M3-D audit L1).
  app.use("/api", (req, res, next) => {
    const caller = res.locals.auth as Authentication | undefined;
    if (caller?.kind !== "agent" || (req.method === "POST" && req.path === "/evaluate")) {
      next();
      return;
    }
    res.status(403).json({ error: "This route requires operator authentication.", reason: "operator-required" });
  });
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

    const caller = res.locals.auth as Authentication;
    let scenarioId: string | null = null;
    let agentId: string | null = null;
    let requested: RequestedIntent | null = null;
    let action: ProposedAction | null = null;
    let untrustedContent: UntrustedContent | undefined;
    let actor: RequestActor;
    let credentialKeyId: string | undefined;

    if (typeof body.scenarioId === "string") {
      // M3-D: seeded scenarios are operator demos, run under the built-in demo agent.
      if (!isOperator(caller)) {
        res.status(403).json({ error: "Seeded scenarios can only be run by the operator.", reason: "operator-required" });
        return;
      }
      actor = { kind: "operator", method: caller.kind };
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
      // M3-D (U2): custom evaluations are for agents only. There is no operator or legacy path.
      if (caller.kind !== "agent") {
        res.status(403).json({ error: "Custom evaluations require an agent credential.", reason: "agent-credential-required" });
        return;
      }
      // The agent is the credential's. A body agentId may repeat it; a malformed one is a bad
      // request; a different one is refused, recorded, and never evaluated (U3).
      const parsedAgent = parseAgentId(body.agentId);
      if (!parsedAgent.ok) {
        res.status(400).json({
          error: "agentId must be a lowercase identifier: a-z or 0-9 first, then a-z, 0-9, '.', '_' or '-', at most 64 characters.",
          reason: "invalid-agent-id",
        });
        return;
      }
      if (parsedAgent.agentId !== null && parsedAgent.agentId !== caller.agentId) {
        recordIdentityMismatch(caller, parsedAgent.agentId, body);
        res.status(403).json({ error: "agentId does not match the authenticated agent. Nothing was evaluated.", reason: "agent-identity-mismatch" });
        return;
      }
      agentId = caller.agentId;
      actor = { kind: "agent", credentialId: caller.keyId };
      credentialKeyId = caller.keyId;
      requested = parseIntent(body.intent);
      action = parseAction(body.action);
      if (!requested || !action) {
        res.status(400).json({
          error:
            "Provide intent {task, and optionally allowedActions, deniedActions, allowedDestinations} and action {type, tool, destination, summary}.",
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
    const agentFields = { agentId, agentPolicy: evaluation.agentPolicy ?? null, actor };

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
          requestedBy: actor,
          ...(credentialKeyId !== undefined ? { credentialKeyId } : {}),
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
   * M3-D (U3): a request named a different agent than its credential's. Recorded as a
   * security event with the authenticated agent and the claimed id (redacted when
   * secret-shaped); nothing was evaluated or executed.
   */
  function recordIdentityMismatch(caller: Extract<Authentication, { kind: "agent" }>, claimed: string, body: Record<string, unknown>): ActivityEvent {
    const claimedAction = parseAction(body.action);
    return recordEvent({
      scenarioId: null,
      intentTask: parseIntent(body.intent)?.task ?? "",
      actionType: claimedAction?.type ?? "",
      tool: claimedAction?.tool ?? "",
      destination: claimedAction?.destination ?? "",
      decision: "BLOCK",
      riskScore: POLICY_BLOCK_RISK,
      findings: [
        {
          ruleId: IDENTITY_MISMATCH_RULE_ID,
          category: "policy",
          severity: "high",
          title: "Agent identity mismatch",
          explanation: "The request named a different agent than the one its credential belongs to. It was refused and not evaluated.",
          evidence: `authenticated=${redactSecretValue(caller.agentId)}; claimed=${redactSecretValue(claimed)}`,
        },
      ],
      explanation: "Refused: the request's agentId does not match the authenticated agent. Nothing was evaluated or executed.",
      lifecycle: "IDENTITY_MISMATCH",
      agentId: caller.agentId,
      agentPolicy: null,
      claimedAgentId: claimed,
      actor: { kind: "agent", credentialId: caller.keyId },
    });
  }

  /** The operator acting on an approval (approve and reject are operator-only routes). */
  function operatorActor(res: express.Response): RequestActor {
    const caller = res.locals.auth as Authentication;
    return { kind: "operator", method: caller.kind === "session" ? "session" : "bearer" };
  }

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
    const outcome = processApproval(approvalStore, id, (record) => recheckApproval(policyStore, record, (keyId) => credentialStore.status(keyId)),
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
        actor: operatorActor(res),
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
      actor: operatorActor(res),
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
      actor: operatorActor(res),
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
    const client = bodyParserClientError(error);
    if (client) {
      console.warn(`api-request status=${client.status} category=${client.category}`);
      res.status(client.status).json({ error: client.message });
      return;
    }
    console.warn("api-request status=internal-error category=unhandled");
    res.status(500).json({ error: "Internal error." });
  });

  return app;
}
