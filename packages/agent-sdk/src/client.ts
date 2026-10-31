import { inspect } from "node:util";
import { AgentCredential } from "./credential.js";
import {
  ApprovalNotFoundError,
  AuthenticationError,
  BadRequestError,
  ConfigurationError,
  ForbiddenError,
  InvalidArgumentError,
  NetworkError,
  RateLimitedError,
  ResponseFormatError,
  ServerError,
  ServiceUnavailableError,
  TimeoutError,
  WaitTimeoutError,
  type AgentShieldError,
} from "./errors.js";
import { signRequest } from "./signing.js";
import {
  APPROVAL_ID,
  APPROVAL_STATUSES,
  parseApproval,
  parseApprovalPage,
  parseEvaluateResult,
  type AgentApproval,
  type ApprovalPage,
  type EvaluateRequest,
  type EvaluateResult,
  type ListApprovalsOptions,
} from "./types.js";

/**
 * The AgentShield agent client (M3-E E5). It talks to exactly three routes, each signed
 * with the agent's Ed25519 key (E1-E3 protocol):
 *
 *   evaluate(request)          POST /api/evaluate          never retried automatically
 *   getApproval(id)            GET  /api/agent/approvals/:id
 *   listApprovals(options)     GET  /api/agent/approvals
 *
 * plus helpers built on them (iterateApprovals, waitForApproval). There is no generic
 * request method, and no way to approve, reject or execute anything.
 *
 * Retries (GET only, bounded by `getRetries`): network errors and timeouts, 429/503
 * (waiting for Retry-After when it is short), and one retry after a 401, which covers a
 * request signed just before the server restarted. Every attempt is signed afresh: new
 * timestamp, new nonce, new signature. evaluate is never retried, because the server
 * does not yet deduplicate evaluations: a timed-out evaluate may already have run.
 */

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]"]);
export const DEFAULT_TIMEOUT_MS = 10_000;
export const MIN_TIMEOUT_MS = 100;
export const MAX_TIMEOUT_MS = 120_000;
export const DEFAULT_GET_RETRIES = 2;
export const MAX_GET_RETRIES = 5;
/** The server's request-body limit: larger evaluations are refused here, before sending. */
export const MAX_EVALUATE_BODY_BYTES = 32 * 1024;
const MAX_RESPONSE_BYTES = 1024 * 1024;
const MAX_RETRY_WAIT_MS = 5_000;
const DEFAULT_WAIT_TIMEOUT_MS = 16 * 60 * 1000;
const MAX_WAIT_TIMEOUT_MS = 24 * 60 * 60 * 1000;
const NOT_FOUND = Symbol("not-found");

export interface AgentShieldClientOptions {
  /** The API origin, for example http://127.0.0.1:4000. Loopback only, unless allowRemote is set (https only). */
  baseUrl: string;
  credential: AgentCredential;
  /** Per-request timeout in ms (100 to 120000, default 10000). */
  timeoutMs?: number;
  /** Extra attempts for GET requests (0 to 5, default 2). evaluate is never retried. */
  getRetries?: number;
  /** Allow a non-loopback host. Only https is ever accepted for one. */
  allowRemote?: boolean;
  /** A fetch implementation (default: the global fetch). For tests or custom transports. */
  fetch?: typeof fetch;
  /** Clock in ms (default Date.now). For tests. */
  now?: () => number;
  /** Delay function (default setTimeout). For tests. */
  sleep?: (ms: number) => Promise<void>;
}

export interface WaitOptions {
  /** How long to wait for a decision, in ms (default 16 minutes, just past the server's 15-minute expiry). */
  timeoutMs?: number;
  signal?: AbortSignal;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function boundedInteger(value: number | undefined, fallback: number, min: number, max: number, name: string): number {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || value < min || value > max) throw new ConfigurationError(`${name} must be a whole number from ${min} to ${max}.`);
  return value;
}

function parseBaseUrl(baseUrl: unknown, allowRemote: boolean): URL {
  let url: URL;
  try {
    url = new URL(String(baseUrl));
  } catch {
    throw new ConfigurationError("baseUrl must be an absolute URL such as http://127.0.0.1:4000.");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") throw new ConfigurationError("baseUrl must use http or https.");
  if (url.username || url.password) throw new ConfigurationError("baseUrl must not contain user information.");
  if ((url.pathname !== "/" && url.pathname !== "") || url.search || url.hash) throw new ConfigurationError("baseUrl must be an origin only (no path, query or fragment).");
  if (!LOOPBACK_HOSTS.has(url.hostname)) {
    if (!allowRemote) throw new ConfigurationError("baseUrl must be a loopback address (127.0.0.1, localhost or [::1]); set allowRemote for a remote https server.");
    if (url.protocol !== "https:") throw new ConfigurationError("A remote baseUrl must use https.");
  }
  return url;
}

function retryAfterSeconds(header: string | null): number | undefined {
  if (header === null || !/^\d{1,6}$/.test(header.trim())) return undefined;
  return Number(header.trim());
}

function isAbort(error: unknown): boolean {
  return isRecord(error) && (error.name === "TimeoutError" || error.name === "AbortError");
}

/** Reads at most MAX_RESPONSE_BYTES of a response body. */
async function readBody(response: Response): Promise<string> {
  const declared = Number(response.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > MAX_RESPONSE_BYTES) throw new ResponseFormatError("AgentShield's response is too large.");
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > MAX_RESPONSE_BYTES) {
      await reader.cancel().catch(() => {});
      throw new ResponseFormatError("AgentShield's response is too large.");
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

async function readJson(response: Response): Promise<unknown> {
  const text = await readBody(response);
  try {
    return JSON.parse(text);
  } catch {
    throw new ResponseFormatError();
  }
}

function errorFor(status: number, reason: string | undefined, retryAfter: number | undefined): AgentShieldError {
  if (status === 401) return new AuthenticationError(status);
  if (status === 403) return new ForbiddenError(status, reason);
  if (status === 400 || status === 413 || status === 415) return new BadRequestError(status, reason);
  if (status === 429) return new RateLimitedError(status, retryAfter, reason);
  if (status === 503) return new ServiceUnavailableError(status, retryAfter, reason);
  return new ServerError(status);
}

function requireString(value: unknown, name: string): string {
  if (typeof value !== "string" || value.length === 0) throw new InvalidArgumentError(`${name} must be a non-empty string.`);
  return value;
}

export class AgentShieldClient {
  readonly #base: URL;
  readonly #credential: AgentCredential;
  readonly #timeoutMs: number;
  readonly #getRetries: number;
  readonly #fetch: typeof fetch;
  readonly #now: () => number;
  readonly #sleep: (ms: number) => Promise<void>;

  constructor(options: AgentShieldClientOptions) {
    if (!isRecord(options)) throw new ConfigurationError("Client options are required.");
    if (!(options.credential instanceof AgentCredential)) throw new ConfigurationError("credential must be an AgentCredential (AgentCredential.fromFile, fromEnv or fromString).");
    this.#base = parseBaseUrl(options.baseUrl, options.allowRemote === true);
    this.#credential = options.credential;
    this.#timeoutMs = boundedInteger(options.timeoutMs, DEFAULT_TIMEOUT_MS, MIN_TIMEOUT_MS, MAX_TIMEOUT_MS, "timeoutMs");
    this.#getRetries = boundedInteger(options.getRetries, DEFAULT_GET_RETRIES, 0, MAX_GET_RETRIES, "getRetries");
    this.#fetch = options.fetch ?? globalThis.fetch;
    this.#now = options.now ?? Date.now;
    this.#sleep = options.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
  }

  /** The credential's public key id. */
  get keyId(): string {
    return this.#credential.keyId;
  }

  /**
   * Asks AgentShield to evaluate an action for this agent. Sent once, never retried
   * automatically. If it times out, it may or may not have been processed: check
   * listApprovals before sending it again.
   */
  async evaluate(request: EvaluateRequest): Promise<EvaluateResult> {
    if (!isRecord(request) || !isRecord(request.intent) || !isRecord(request.action)) throw new InvalidArgumentError("evaluate needs an intent and an action.");
    requireString(request.intent.task, "intent.task");
    for (const field of ["type", "tool", "destination", "summary"] as const) requireString(request.action[field], `action.${field}`);
    // Only the documented fields are sent. The agent's identity comes from the credential.
    const payload = { intent: request.intent, action: request.action, ...(request.untrustedContent !== undefined ? { untrustedContent: request.untrustedContent } : {}) };
    let text: string;
    try {
      text = JSON.stringify(payload);
    } catch {
      throw new InvalidArgumentError("The evaluation cannot be converted to JSON.");
    }
    const body = Buffer.from(text, "utf8");
    if (body.length > MAX_EVALUATE_BODY_BYTES) throw new InvalidArgumentError(`The evaluation is larger than ${MAX_EVALUATE_BODY_BYTES} bytes.`);
    return parseEvaluateResult(await this.#send("POST", "/api/evaluate", body, { retry: false }));
  }

  /** One of this agent's approvals, or null if it does not exist or is not this agent's (the server does not say which). */
  async getApproval(id: string): Promise<AgentApproval | null> {
    if (typeof id !== "string" || !APPROVAL_ID.test(id)) throw new InvalidArgumentError("The approval id must look like apr-<number>.");
    const result = await this.#send("GET", `/api/agent/approvals/${id}`, undefined, { retry: true, notFoundIsNull: true });
    if (result === NOT_FOUND) return null;
    if (!isRecord(result) || Object.keys(result).join(",") !== "approval") throw new ResponseFormatError();
    return parseApproval(result.approval);
  }

  /** One page of this agent's approvals, newest first. */
  async listApprovals(options: ListApprovalsOptions = {}): Promise<ApprovalPage> {
    if (!isRecord(options)) throw new InvalidArgumentError("listApprovals options must be an object.");
    for (const key of Object.keys(options)) if (key !== "limit" && key !== "before" && key !== "status") throw new InvalidArgumentError("listApprovals accepts only limit, before and status.");
    const { limit, before, status } = options as Record<string, unknown>;
    const params = new URLSearchParams();
    if (limit !== undefined) {
      if (typeof limit !== "number" || !Number.isSafeInteger(limit) || limit < 1 || limit > 50) throw new InvalidArgumentError("limit must be a whole number from 1 to 50.");
      params.set("limit", String(limit));
    }
    if (before !== undefined) {
      if (typeof before !== "string" || !APPROVAL_ID.test(before)) throw new InvalidArgumentError("before must be an approval id (apr-<number>).");
      params.set("before", before);
    }
    if (status !== undefined) {
      if (typeof status !== "string" || !(APPROVAL_STATUSES as readonly string[]).includes(status)) throw new InvalidArgumentError("status is not an approval status.");
      params.set("status", status);
    }
    const query = params.toString();
    return parseApprovalPage(await this.#send("GET", query ? `/api/agent/approvals?${query}` : "/api/agent/approvals", undefined, { retry: true }));
  }

  /** Every page of this agent's approvals, newest first, following nextCursor (at most `maxPages` pages, default 100). */
  async *iterateApprovals(options: Omit<ListApprovalsOptions, "before"> & { maxPages?: number } = {}): AsyncGenerator<AgentApproval> {
    const { maxPages = 100, ...filters } = options;
    if (!Number.isSafeInteger(maxPages) || maxPages < 1 || maxPages > 1000) throw new InvalidArgumentError("maxPages must be a whole number from 1 to 1000.");
    let before: string | undefined;
    for (let page = 0; page < maxPages; page += 1) {
      const result: ApprovalPage = await this.listApprovals({ ...filters, ...(before ? { before } : {}) });
      for (const approval of result.approvals) yield approval;
      if (!result.nextCursor) return;
      before = result.nextCursor;
    }
  }

  /**
   * Polls one of this agent's approvals until it is no longer pending, following the
   * server's pollAfterSeconds hint. Throws ApprovalNotFoundError if the approval does not
   * exist or is not this agent's, and WaitTimeoutError if it is still pending at the end.
   */
  async waitForApproval(id: string, options: WaitOptions = {}): Promise<AgentApproval> {
    const timeoutMs = options.timeoutMs ?? DEFAULT_WAIT_TIMEOUT_MS;
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_WAIT_TIMEOUT_MS) throw new InvalidArgumentError("timeoutMs must be a whole number of ms up to 24 hours.");
    const deadline = this.#now() + timeoutMs;
    for (;;) {
      if (options.signal?.aborted) throw options.signal.reason ?? new Error("Aborted");
      const approval = await this.getApproval(id);
      if (approval === null) throw new ApprovalNotFoundError();
      if (approval.status !== "PENDING") return approval;
      const wait = Math.min(Math.max((approval.pollAfterSeconds ?? 2) * 1000, 500), 30_000);
      if (this.#now() + wait > deadline) throw new WaitTimeoutError();
      await this.#sleep(wait);
      if (options.signal?.aborted) throw options.signal.reason ?? new Error("Aborted");
    }
  }

  toJSON(): { baseUrl: string; keyId: string } {
    return { baseUrl: this.#base.origin, keyId: this.#credential.keyId };
  }

  [inspect.custom](): string {
    return `AgentShieldClient { baseUrl: '${this.#base.origin}', keyId: '${this.#credential.keyId}' }`;
  }

  /** Signs and sends one request to a fixed SDK route; retries GETs as described above. */
  async #send(method: "GET" | "POST", path: string, body: Buffer | undefined, policy: { retry: boolean; notFoundIsNull?: boolean }): Promise<unknown> {
    const url = new URL(path, this.#base);
    const attempts = policy.retry ? 1 + this.#getRetries : 1;
    let authRetried = false;
    for (let attempt = 1; ; attempt += 1) {
      // Fresh timestamp, nonce and signature for every attempt.
      const { authorization } = signRequest({ credential: this.#credential, method, url, body, now: this.#now });
      const headers: Record<string, string> = { Authorization: authorization, Accept: "application/json" };
      if (body !== undefined) headers["Content-Type"] = "application/json";
      const canRetry = policy.retry && attempt < attempts;

      let response: Response;
      try {
        response = await this.#fetch(url, { method, headers, body, redirect: "error", signal: AbortSignal.timeout(this.#timeoutMs) });
      } catch (error) {
        if (canRetry) {
          await this.#sleep(this.#backoff(attempt));
          continue;
        }
        throw isAbort(error) ? new TimeoutError() : new NetworkError();
      }

      try {
        if (response.status >= 200 && response.status < 300) return await readJson(response);
        if (response.status === 404 && policy.notFoundIsNull) {
          await response.body?.cancel().catch(() => {});
          return NOT_FOUND;
        }
        const payload = await readJson(response).catch(() => null);
        const reason = isRecord(payload) && typeof payload.reason === "string" && /^[a-z0-9-]{1,64}$/.test(payload.reason) ? payload.reason : undefined;
        const retryAfter = retryAfterSeconds(response.headers.get("retry-after"));
        if (response.status === 401 && canRetry && !authRetried) {
          authRetried = true;
          continue;
        }
        if ((response.status === 429 || response.status === 503) && canRetry) {
          const wait = retryAfter === undefined ? this.#backoff(attempt) : retryAfter * 1000;
          if (wait <= MAX_RETRY_WAIT_MS) {
            await this.#sleep(wait);
            continue;
          }
        }
        throw errorFor(response.status, reason, retryAfter);
      } catch (error) {
        if (isAbort(error)) throw new TimeoutError();
        throw error;
      }
    }
  }

  #backoff(attempt: number): number {
    return Math.min(250 * 2 ** (attempt - 1) + Math.floor(Math.random() * 100), 2_000);
  }
}
