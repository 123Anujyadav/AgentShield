import { scanUntrustedContent } from "@agentshield/engine";
import type { ModelConfig } from "./config.js";

export class ModelProviderError extends Error {
  constructor(public readonly category: "timeout" | "network" | "http" | "malformed" | "live-disabled" | "unknown") {
    super(category);
    this.name = "ModelProviderError";
  }
}

/** A provider returns raw, untrusted output. It is always validated before use. */
export interface ModelProvider {
  readonly kind: "mock" | "meta";
  analyze(untrustedText: string): Promise<unknown>;
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
 * Live Meta transport is intentionally not implemented.
 * Verified 2026-10-26 against official docs at dev.meta.ai:
 * POST https://api.meta.ai/v1/chat/completions, Bearer $MODEL_API_KEY,
 * required body fields model + messages, response object "chat.completion"
 * with choices[].message.content (see docs/live-readiness.md).
 * No request is ever sent by this function; it only builds the shape.
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
        max_completion_tokens: 600,
      }),
    },
  };
}

/** Parse the documented error envelope without retaining raw bodies. */
export function metaErrorCategory(payload: unknown, httpStatus: number): string {
  if (typeof payload === "object" && payload !== null && "error" in payload) {
    const error = (payload as { error?: { type?: unknown; code?: unknown } }).error;
    if (typeof error?.type === "string" && error.type) return error.type;
    if (typeof error?.code === "string" && error.code) return error.code;
  }
  if (httpStatus === 401) return "authentication_error";
  if (httpStatus === 429) return "rate_limit_error";
  if (httpStatus >= 500) return "server_error";
  return "invalid_request_error";
}

export function parseMetaChatContent(payload: unknown): unknown {
  if (typeof payload !== "object" || payload === null) {
    throw new ModelProviderError("malformed");
  }
  const record = payload as {
    object?: unknown;
    choices?: unknown;
  };
  if (record.object !== undefined && record.object !== "chat.completion") {
    throw new ModelProviderError("malformed");
  }
  const choices = record.choices;
  if (!Array.isArray(choices) || choices.length === 0) throw new ModelProviderError("malformed");
  const choice = choices[0] as {
    finish_reason?: unknown;
    message?: { content?: unknown; tool_calls?: unknown };
  };
  // A tool-call response is an attempted execution path. It is never followed.
  if (choice.finish_reason === "tool_calls" || choice.message?.tool_calls !== undefined) {
    throw new ModelProviderError("malformed");
  }
  const content = choice.message?.content;
  if (typeof content !== "string" || content.length === 0) throw new ModelProviderError("malformed");
  try {
    return JSON.parse(content) as unknown;
  } catch {
    throw new ModelProviderError("malformed");
  }
}

export class DisabledLiveModelProvider implements ModelProvider {
  readonly kind = "meta" as const;
  async analyze(): Promise<unknown> {
    throw new ModelProviderError("live-disabled");
  }
}
