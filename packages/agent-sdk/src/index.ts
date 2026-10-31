/**
 * @agentshield/agent-sdk (M3-E E5): sign and send AgentShield agent requests.
 *
 *   const credential = AgentCredential.fromFile("C:\\secure\\report-writer.key");
 *   const client = new AgentShieldClient({ baseUrl: "http://127.0.0.1:4000", credential });
 *   const result = await client.evaluate({ intent: { task: "Summarize" }, action: { ... } });
 *
 * The request signer is internal: the client signs only its own fixed routes.
 */
export { AgentCredential, MAX_CREDENTIAL_FILE_BYTES } from "./credential.js";
export {
  AgentShieldClient,
  DEFAULT_GET_RETRIES,
  DEFAULT_TIMEOUT_MS,
  MAX_EVALUATE_BODY_BYTES,
  MAX_GET_RETRIES,
  MAX_TIMEOUT_MS,
  MIN_TIMEOUT_MS,
  type AgentShieldClientOptions,
  type WaitOptions,
} from "./client.js";
export {
  AgentShieldError,
  ApprovalNotFoundError,
  AuthenticationError,
  BadRequestError,
  ConfigurationError,
  CredentialError,
  ForbiddenError,
  InvalidArgumentError,
  NetworkError,
  RateLimitedError,
  ResponseFormatError,
  ServerError,
  ServiceUnavailableError,
  TimeoutError,
  WaitTimeoutError,
  type AgentShieldErrorCode,
} from "./errors.js";
export {
  APPROVAL_STATUSES,
  type AgentApproval,
  type ApprovalPage,
  type ApprovalStatus,
  type Decision,
  type EvaluateRequest,
  type EvaluateResult,
  type Finding,
  type ListApprovalsOptions,
} from "./types.js";
