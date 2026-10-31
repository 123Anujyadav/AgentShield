/**
 * Typed errors (M3-E E5). Messages are fixed text: they never contain a credential,
 * private key, Authorization header, request body or approval content. Where the
 * server answered, `status` and the server's own fixed-text `reason` are kept.
 */

export type AgentShieldErrorCode =
  | "credential"
  | "configuration"
  | "invalid-argument"
  | "authentication"
  | "forbidden"
  | "bad-request"
  | "rate-limited"
  | "service-unavailable"
  | "server"
  | "timeout"
  | "network"
  | "response-format"
  | "approval-not-found"
  | "wait-timeout";

export class AgentShieldError extends Error {
  constructor(
    readonly code: AgentShieldErrorCode,
    message: string,
    readonly details: { status?: number; reason?: string; retryAfterSeconds?: number } = {},
  ) {
    super(message);
    this.name = "AgentShieldError";
  }
}

/** The local credential is missing, malformed or not an Ed25519 signing credential. */
export class CredentialError extends AgentShieldError {
  constructor(message: string) {
    super("credential", message);
    this.name = "CredentialError";
  }
}

/** The client options are invalid (base URL, timeout, retries). */
export class ConfigurationError extends AgentShieldError {
  constructor(message: string) {
    super("configuration", message);
    this.name = "ConfigurationError";
  }
}

/** An argument to an SDK method is invalid; nothing was sent. */
export class InvalidArgumentError extends AgentShieldError {
  constructor(message: string) {
    super("invalid-argument", message);
    this.name = "InvalidArgumentError";
  }
}

/**
 * HTTP 401. The server does not say why: the credential may be unknown, revoked or
 * expired, the key may not match, the clock may be too far off, or the request was
 * signed before the server started. The request was not processed.
 */
export class AuthenticationError extends AgentShieldError {
  constructor(status: number) {
    super("authentication", "AgentShield refused the request's authentication (401). The credential may be unknown, revoked or expired, or the clock may be off.", { status });
    this.name = "AuthenticationError";
  }
}

/** HTTP 403, for example `operator-required` or `agent-identity-mismatch`. */
export class ForbiddenError extends AgentShieldError {
  constructor(status: number, reason?: string) {
    super("forbidden", `AgentShield refused the request (403${reason ? `, ${reason}` : ""}).`, { status, reason });
    this.name = "ForbiddenError";
  }
}

/** HTTP 400, 413 or 415: the request was invalid and was not processed. */
export class BadRequestError extends AgentShieldError {
  constructor(status: number, reason?: string) {
    super("bad-request", `AgentShield rejected the request as invalid (${status}${reason ? `, ${reason}` : ""}).`, { status, reason });
    this.name = "BadRequestError";
  }
}

/** HTTP 429. `retryAfterSeconds` is the server's hint, when it gave one. */
export class RateLimitedError extends AgentShieldError {
  constructor(status: number, retryAfterSeconds?: number, reason?: string) {
    super("rate-limited", "AgentShield is rate limiting this client (429).", { status, retryAfterSeconds, reason });
    this.name = "RateLimitedError";
  }
}

/** HTTP 503 (for example, the replay cache or the approval queue is full; see `details.reason`). */
export class ServiceUnavailableError extends AgentShieldError {
  constructor(status: number, retryAfterSeconds?: number, reason?: string) {
    super("service-unavailable", "AgentShield is temporarily unavailable (503).", { status, retryAfterSeconds, reason });
    this.name = "ServiceUnavailableError";
  }
}

/** Any other HTTP error status. */
export class ServerError extends AgentShieldError {
  constructor(status: number) {
    super("server", `AgentShield returned an error (${status}).`, { status });
    this.name = "ServerError";
  }
}

/** No response within the configured timeout. For evaluate, the action may or may not have been processed. */
export class TimeoutError extends AgentShieldError {
  constructor() {
    super("timeout", "AgentShield did not respond within the timeout.");
    this.name = "TimeoutError";
  }
}

/** The request could not be sent or the connection failed. */
export class NetworkError extends AgentShieldError {
  constructor() {
    super("network", "Could not reach AgentShield.");
    this.name = "NetworkError";
  }
}

/** The response was not what the protocol defines (not JSON, wrong shape or too large). */
export class ResponseFormatError extends AgentShieldError {
  constructor(message = "AgentShield returned a response in an unexpected format.") {
    super("response-format", message);
    this.name = "ResponseFormatError";
  }
}

/** waitForApproval: the approval does not exist or is not this agent's (the server's uniform 404). */
export class ApprovalNotFoundError extends AgentShieldError {
  constructor() {
    super("approval-not-found", "No such approval for this agent.");
    this.name = "ApprovalNotFoundError";
  }
}

/** waitForApproval: the approval was still pending when the wait ended. */
export class WaitTimeoutError extends AgentShieldError {
  constructor() {
    super("wait-timeout", "The approval was still pending when the wait ended.");
    this.name = "WaitTimeoutError";
  }
}
