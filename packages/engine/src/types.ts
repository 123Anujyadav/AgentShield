export type Decision = "ALLOW" | "CONFIRM" | "BLOCK";
export type FindingSeverity = "low" | "medium" | "high" | "critical";
export type FindingCategory = "hard-deny" | "intent" | "policy" | "injection";

export interface UntrustedContent {
  /** Where the content came from, e.g. "document", "webpage", "tool-output". Always untrusted. */
  source: string;
  text: string;
}

export interface UserIntent {
  /** Stable identifier for the intent this evaluation is bound to. */
  id?: string;
  task: string;
  allowedActions: string[];
  deniedActions: string[];
  /** If present, the action destination must be listed here. Missing/empty is treated conservatively. */
  allowedDestinations?: string[];
}

/**
 * Server-side policy for one agent (M3-C). The server holds it; a request can only
 * narrow it. See resolveAgentIntent in policy.ts for the exact rules.
 */
export interface AgentPolicy {
  /** Exact identity of the agent this policy is for. */
  agentId: string;
  /** Positive integer, declared by the policy author. */
  version: number;
  description?: string;
  allowedActions: string[];
  deniedActions: string[];
  /** Always present: [] means no destination is allowed. */
  allowedDestinations: string[];
}

/** Which policy an evaluation used: the declared version and a canonical content hash. */
export interface AgentPolicyRef {
  agentId: string;
  version: number;
  sha256: string;
}

/** What a request may ask for. Each list is optional; a present list can only narrow the agent's policy. */
export interface RequestedIntent {
  id?: string;
  task: string;
  allowedActions?: string[];
  deniedActions?: string[];
  allowedDestinations?: string[];
}

export interface ProposedAction {
  type: string;
  tool: string;
  destination: string;
  summary: string;
  payload?: Record<string, string | number | boolean>;
}

export interface Finding {
  ruleId: string;
  category: FindingCategory;
  severity: FindingSeverity;
  title: string;
  explanation: string;
  evidence: string;
}

export interface EvaluationInput {
  intent: UserIntent;
  action: ProposedAction;
  /** Explicitly labelled untrusted content to scan. Treated as data, never as policy. */
  untrustedContent?: UntrustedContent;
  /** User approval may support a future CONFIRM flow. It never overrides a hard deny. */
  userApproved?: boolean;
}

export interface EvaluationResult {
  decision: Decision;
  policyVersion: string;
  riskScore: number;
  /** All findings: scanner findings first, then intent/policy findings. */
  findings: Finding[];
  /** Findings from the rule-based Injection Scanner only. */
  scannerFindings: Finding[];
  scannerStatus: "clean" | "suspicious" | "empty" | "not-scanned";
  explanation: string;
  actionType: string;
  /** M3-C: the server-side policy the decision was made under; null when the agent is unknown. Set by the API. */
  agentPolicy?: AgentPolicyRef | null;
}

export interface ActivityEvent {
  id: string;
  timestamp: string;
  scenarioId: string | null;
  intentTask: string;
  actionType: string;
  tool: string;
  destination: string;
  decision: Decision;
  riskScore: number;
  findings: Finding[];
  explanation: string;
  approvalId?: string;
  lifecycle?: string;
  /** M3-C: the agent the request was made for (null when none was given). */
  agentId?: string | null;
  /** M3-C: the policy the decision was made under (null for an unknown agent). */
  agentPolicy?: AgentPolicyRef | null;
}

export type ApprovalStatus =
  | "PENDING"
  | "EXECUTED"
  | "REJECTED"
  | "EXPIRED"
  | "BLOCKED_ON_RECHECK"
  /** M3-B: the recheck passed, but no simulated handler is registered for the action type. Nothing ran. */
  | "APPROVED_NOT_EXECUTED";

export interface SimulatedExecution {
  executed: boolean;
  handler: string | null;
  result: string | null;
  reason: string | null;
}

/** A pending approval binds the exact intent, action and evaluation that produced CONFIRM. */
export interface PendingApproval {
  id: string;
  status: ApprovalStatus;
  createdAt: string;
  expiresAt: string;
  scenarioId: string | null;
  intent: UserIntent;
  action: ProposedAction;
  decision: Decision;
  policyVersion: string;
  riskScore: number;
  findings: Finding[];
  explanation: string;
  execution: SimulatedExecution | null;
  /** M3-C: the agent and the policy version the CONFIRM was decided under. */
  agentId?: string | null;
  agentPolicy?: AgentPolicyRef | null;
}

export interface Scenario {
  id: string;
  label: string;
  description: string;
  /** M3-C: the agent whose server-side policy the scenario is evaluated under. */
  agentId: string;
  intent: UserIntent;
  action: ProposedAction;
  untrustedContent?: UntrustedContent;
}
