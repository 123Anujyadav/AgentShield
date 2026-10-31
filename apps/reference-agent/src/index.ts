/**
 * @agentshield/reference-agent (M3-E E6): a complete, harmless agent built on the official
 * AgentShield SDK. It summarizes a document into an in-memory simulated workspace, and only
 * after AgentShield allows (or an operator approves) the action.
 */
export {
  DEFAULT_APPROVAL_WAIT_MS,
  MAX_APPROVAL_WAIT_MS,
  ReferenceAgent,
  SUMMARY_ACTION,
  UnknownApprovalError,
  type EvaluationSummary,
  type FailureReason,
  type ReferenceAgentOptions,
  type TaskOutcome,
} from "./agent.js";
export { exitCode, runReferenceAgent, type CliIo } from "./cli.js";
export { AgentConfigError, CREDENTIAL_FILE_VARIABLE, CREDENTIAL_VARIABLE, DEFAULT_BASE_URL, URL_VARIABLE, loadAgentConfig, type AgentConfig } from "./config.js";
export { describeOutcome, inert } from "./display.js";
export { MAX_SUMMARY_LENGTH, summarize } from "./summarize.js";
export { DocumentTooLongError, MAX_DOCUMENT_BYTES, MAX_DOCUMENT_CHARACTERS, TaskInputError, parseSummaryTask, type SummaryTask } from "./task.js";
export { SimulatedWorkspace, type SavedSummary } from "./workspace.js";
