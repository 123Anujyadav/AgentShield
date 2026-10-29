import type {
  ActivityEvent,
  EvaluationResult,
  ModelAnalysis,
  PendingApproval,
  Scenario,
  SimulatedExecution,
} from "@agentshield/engine";

export type { ActivityEvent, EvaluationResult, ModelAnalysis, PendingApproval, Scenario, SimulatedExecution };

export type View =
  | "command"
  | "scenarios"
  | "investigation"
  | "policy"
  | "approvals"
  | "diagnostics"
  | "tool-trust"
  | "scans"
  | "activity";

export interface ModelStatus {
  mode: string;
  provider: string;
  model: string;
  apiKeyConfigured: boolean;
  liveEnabled: boolean;
  isMock: boolean;
  note: string;
}

export interface EvaluateResponse {
  evaluation: EvaluationResult;
  event: ActivityEvent;
  executed: boolean;
  execution: SimulatedExecution;
  pendingApproval: PendingApproval | null;
  modelAnalysis: ModelAnalysis;
}

export interface ApprovalResponse {
  approval: PendingApproval;
  execution?: SimulatedExecution;
  executed: boolean;
  error?: string;
}
