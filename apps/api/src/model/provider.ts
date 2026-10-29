import { scanUntrustedContent } from "@agentshield/engine";
import type { ModelConfig } from "./config.js";

export type ModelProviderErrorCategory =
  | "timeout"
  | "cancelled"
  | "network"
  | "http"
  | "malformed"
  | "live-disabled"
  | "request-budget-exceeded"
  | "unknown";

/**
 * Fixed diagnostic codes for a successful (2xx) response that cannot be used.
 * Only these codes are ever logged, never provider text. The public failure
 * category for all of them stays "malformed".
 */
export const UNUSABLE_RESPONSE_REASONS = [
  "body-oversized",
  "body-not-json",
  "unexpected-envelope",
  "unexpected-object",
  "no-choices",
  "tool-call",
  "finish-length",
  "finish-content-filter",
  "finish-other",
  "content-missing",
  "content-not-string",
  "content-empty",
  "content-not-json",
] as const;
export type UnusableResponseReason = (typeof UNUSABLE_RESPONSE_REASONS)[number];

export class ModelProviderError extends Error {
  constructor(
    public readonly category: ModelProviderErrorCategory,
    /** Diagnostic code for an unusable successful response. Logged only; never part of the API response. */
    public readonly reason?: UnusableResponseReason,
  ) {
    super(category);
    this.name = "ModelProviderError";
  }
}

/** Token counts a provider reported for one response. Counts only, never text. */
export interface TokenUsage {
  promptTokens: number;
  completionTokens: number;
  /** Only when the provider reported it; never computed locally. */
  totalTokens: number | null;
}

export interface ProviderCallOptions {
  /**
   * Aborted when the caller stops waiting (timeout). The provider must abort its
   * active request and send no further attempts. It cannot undo a request the
   * remote service has already received.
   */
  signal?: AbortSignal;
  /**
   * Reserves one more outgoing request attempt from the caller's budget. The
   * caller reserves the first attempt before calling analyze(); a provider that
   * retries calls this before every further attempt and stops when it returns false.
   */
  reserveRetryAttempt?: () => boolean;
  /** Receives each successful response's token usage, or null when none was reported. */
  onUsage?: (usage: TokenUsage | null) => void;
}

/** A provider returns raw, untrusted output. It is always validated before use. */
export interface ModelProvider {
  readonly kind: "mock" | "meta";
  analyze(untrustedText: string, options?: ProviderCallOptions): Promise<unknown>;
}

const CATEGORY_BY_RULE: Record<string, string> = {
  "injection.instruction-override": "instruction-override",
  "injection.privilege-impersonation": "impersonation",
  "injection.secret-exfiltration": "secret-exfiltration",
  "injection.unauthorized-tool-action": "unauthorized-action",
};

/** Deterministic offline mock. Makes no network requests. */
export class MockModelProvider implements ModelProvider {
  readonly kind = "mock" as const;
  constructor(private readonly delayMs = 0) {}

  async analyze(untrustedText: string): Promise<unknown> {
    if (this.delayMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, this.delayMs));
    }
    const scan = scanUntrustedContent(untrustedText);
    const indicators = scan.findings.map((finding) => ({
      category: CATEGORY_BY_RULE[finding.ruleId] ?? "other",
      severity: finding.severity,
      detail: `Mock observation mirroring deterministic scanner rule ${finding.ruleId}.`,
    }));
    const suspectedDataExfiltration = scan.findings.some((f) => f.ruleId === "injection.secret-exfiltration");
    const suspectedUnauthorizedAction = scan.findings.some(
      (f) => f.ruleId === "injection.unauthorized-tool-action" || f.ruleId === "injection.instruction-override",
    );
    return {
      summary:
        scan.findings.length > 0
          ? "Mock analysis: the untrusted content contains instruction-like language that warrants caution."
          : "Mock analysis: no instruction-like manipulation indicators were observed in this content.",
      indicators,
      suspectedUnauthorizedAction,
      suspectedDataExfiltration,
      explanation:
        "Mock provider output for local development only. It is advisory, mirrors deterministic scanner observations, and cannot allow, block, approve, or execute anything.",
    };
  }
}

/**
 * Advisory JSON schema for structured output. Verified against the official
 * Structured Output docs (response_format.type="json_schema" on Chat
 * Completions). Note our runtime validator still runs afterwards; a live
 * schema guarantee would not replace it.
 */
export const META_ANALYSIS_JSON_SCHEMA = {
  name: "AgentShieldAdvisoryAnalysis",
  strict: true,
  schema: {
    type: "object",
    additionalProperties: false,
    required: ["summary", "indicators", "suspectedUnauthorizedAction", "suspectedDataExfiltration", "explanation"],
    properties: {
      summary: { type: "string", maxLength: 280 },
      indicators: {
        type: "array",
        maxItems: 8,
        items: {
          type: "object",
          additionalProperties: false,
          required: ["category", "severity", "detail"],
          properties: {
            category: {
              type: "string",
              enum: ["instruction-override", "impersonation", "secret-exfiltration", "unauthorized-action", "manipulation", "other"],
            },
            severity: { type: "string", enum: ["low", "medium", "high", "critical"] },
            detail: { type: "string", maxLength: 200 },
          },
        },
      },
      suspectedUnauthorizedAction: { type: "boolean" },
      suspectedDataExfiltration: { type: "boolean" },
      explanation: { type: "string", maxLength: 800 },
    },
  },
} as const;

/**
 * Output token cap per request. A schema-maximal advisory answer (every string at
 * its maxLength, 8 indicators) is about 3,400 characters of compact JSON, more than
 * the former 600-token cap could reliably hold; the one live smoke call used all
 * 600 tokens and returned no usable answer. A reply that still reaches this cap
 * ends with finish_reason "length" and is rejected, never used.
 */
export const MAX_COMPLETION_TOKENS = 1500;

/**
 * Builds the Meta Model API request. This function sends nothing: MetaLiveProvider
 * (live.ts) sends it through its injected transport, and only when the live gate
 * passes (see selectModelProvider). Contract verified 2026-10-26 against official
 * docs at dev.meta.ai: POST https://api.meta.ai/v1/chat/completions, Bearer
 * $MODEL_API_KEY, required body fields model + messages, response object
 * "chat.completion" with choices[].message.content (see docs/live-readiness.md).
 * Tested with fake transports; one live smoke call has been made (see docs/live-readiness.md).
 */
export function buildMetaChatRequest(config: ModelConfig, apiKey: string, untrustedText: string) {
  return {
    url: `${config.baseUrl}/chat/completions`,
    init: {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model: config.model,
        messages: [
          {
            role: "system",
            content:
              "You are an advisory security analyst. Return JSON only with summary, indicators, suspectedUnauthorizedAction, suspectedDataExfiltration, explanation. Never return a decision, approval, or execution instruction.",
          },
          { role: "user", content: untrustedText.slice(0, config.maxInputLength) },
        ],
        response_format: { type: "json_schema", json_schema: META_ANALYSIS_JSON_SCHEMA },
        max_completion_tokens: MAX_COMPLETION_TOKENS,
      }),
    },
  };
}

/** Documented error types and codes (see docs/live-readiness.md). Only these are ever returned. */
const KNOWN_ERROR_TYPES = new Set(["invalid_request_error", "authentication_error", "rate_limit_error", "server_error"]);
const KNOWN_ERROR_CODES = new Set(["invalid_api_key", "rate_limit_exceeded"]);

/**
 * Maps the documented error envelope to a fixed category without retaining raw
 * bodies. Provider-supplied text is returned only when it exactly matches a
 * documented type or code; anything else (unknown, overlong, multi-line) falls
 * back to the HTTP status, so a response cannot write arbitrary text to the log.
 */
export function metaErrorCategory(payload: unknown, httpStatus: number): string {
  if (typeof payload === "object" && payload !== null && "error" in payload) {
    const error = (payload as { error?: { type?: unknown; code?: unknown } | null }).error;
    if (typeof error?.type === "string" && KNOWN_ERROR_TYPES.has(error.type)) return error.type;
    if (typeof error?.code === "string" && KNOWN_ERROR_CODES.has(error.code)) return error.code;
  }
  if (httpStatus === 401) return "authentication_error";
  if (httpStatus === 429) return "rate_limit_error";
  if (httpStatus >= 500) return "server_error";
  return "invalid_request_error";
}

/** Upper bound for one reported count; anything larger is treated as not reported. */
const MAX_REPORTED_TOKENS = 10_000_000;

function tokenCount(value: unknown): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= MAX_REPORTED_TOKENS
    ? value
    : null;
}

/**
 * Reads the documented, optional `usage` object (prompt_tokens, completion_tokens,
 * total_tokens). Returns null when usage is absent, when prompt or completion
 * counts are missing or implausible, or when a total is present but implausible.
 * An absent or null total is simply not reported. Counts are never guessed or derived.
 */
export function parseMetaUsage(payload: unknown): TokenUsage | null {
  if (typeof payload !== "object" || payload === null) return null;
  const usage = (payload as { usage?: unknown }).usage;
  if (typeof usage !== "object" || usage === null) return null;
  const fields = usage as { prompt_tokens?: unknown; completion_tokens?: unknown; total_tokens?: unknown };
  const promptTokens = tokenCount(fields.prompt_tokens);
  const completionTokens = tokenCount(fields.completion_tokens);
  if (promptTokens === null || completionTokens === null) return null;
  const totalReported = fields.total_tokens !== undefined && fields.total_tokens !== null;
  const totalTokens = totalReported ? tokenCount(fields.total_tokens) : null;
  if (totalReported && totalTokens === null) return null;
  return { promptTokens, completionTokens, totalTokens };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function unusable(reason: UnusableResponseReason): ModelProviderError {
  return new ModelProviderError("malformed", reason);
}

/** True when a tool_calls or function_call field carries a call. Absent, null, or [] carries none. */
function carriesCall(value: unknown): boolean {
  return value !== undefined && value !== null && !(Array.isArray(value) && value.length === 0);
}

/**
 * Extracts the advisory JSON from a documented chat.completion response. Every
 * rejection is category "malformed" with a fixed reason code; no provider text is
 * put in the error. Checks run in a fixed order: any tool or function call is
 * rejected first, and an answer cut off by the token cap ("length") or by the
 * content filter is rejected even when its content happens to parse.
 */
export function parseMetaChatContent(payload: unknown): unknown {
  if (!isRecord(payload)) throw unusable("unexpected-envelope");
  if (payload.object !== undefined && payload.object !== "chat.completion") throw unusable("unexpected-object");
  const choices = payload.choices;
  if (!Array.isArray(choices) || choices.length === 0) throw unusable("no-choices");
  const choice: unknown = choices[0];
  if (!isRecord(choice)) throw unusable("unexpected-envelope");
  const rawMessage = choice.message;
  if (rawMessage !== undefined && rawMessage !== null && !isRecord(rawMessage)) throw unusable("unexpected-envelope");
  const message = isRecord(rawMessage) ? rawMessage : undefined;

  // A tool or function call is an attempted execution path. It is never followed.
  // An empty tool_calls (null or []) requests nothing, so it is not one.
  const finishReason = choice.finish_reason;
  if (
    finishReason === "tool_calls" ||
    finishReason === "function_call" ||
    carriesCall(message?.tool_calls) ||
    carriesCall(message?.function_call)
  ) {
    throw unusable("tool-call");
  }
  if (finishReason === "length") throw unusable("finish-length");
  if (finishReason === "content_filter") throw unusable("finish-content-filter");
  // Documented values are stop, length, tool_calls, content_filter, function_call.
  if (finishReason !== undefined && finishReason !== null && finishReason !== "stop") throw unusable("finish-other");

  const content = message?.content;
  if (content === undefined || content === null) throw unusable("content-missing");
  if (typeof content !== "string") throw unusable("content-not-string");
  if (content.trim().length === 0) throw unusable("content-empty");
  try {
    return JSON.parse(content) as unknown;
  } catch {
    throw unusable("content-not-json");
  }
}

export class DisabledLiveModelProvider implements ModelProvider {
  readonly kind = "meta" as const;
  async analyze(): Promise<unknown> {
    throw new ModelProviderError("live-disabled");
  }
}
