import { MAX_SCAN_LENGTH } from "./scanner/scan.js";
import type { FindingSeverity } from "./types.js";

/**
 * Advisory model-assisted contextual analysis.
 * This is NOT a policy finding and never carries a decision.
 */
export const MODEL_ANALYSIS_LIMITS = {
  /** M3-B: the same limit evaluation accepts for untrusted content, so analysis can see everything the scanner sees. */
  maxInputLength: MAX_SCAN_LENGTH,
  maxSummaryLength: 280,
  maxExplanationLength: 800,
  maxIndicators: 8,
  maxIndicatorDetailLength: 200,
} as const;

export type ModelAnalysisStatus = "success" | "failed" | "unavailable";
export type ModelIndicatorCategory =
  | "instruction-override"
  | "impersonation"
  | "secret-exfiltration"
  | "unauthorized-action"
  | "manipulation"
  | "other";

export interface ModelIndicator {
  category: ModelIndicatorCategory;
  severity: FindingSeverity;
  detail: string;
}

export interface ModelAnalysis {
  status: ModelAnalysisStatus;
  /** "mock" in Phase 4. "meta" is reserved for a future separately-authorized live mode. */
  provider: "mock" | "meta";
  model: string;
  isMock: boolean;
  authority: "advisory-only";
  summary: string;
  indicators: ModelIndicator[];
  suspectedUnauthorizedAction: boolean;
  suspectedDataExfiltration: boolean;
  explanation: string;
  /** Sanitized failure category only (e.g. "timeout"). Never raw provider bodies. */
  failureReason: string | null;
}

const INDICATOR_CATEGORIES = new Set<string>([
  "instruction-override",
  "impersonation",
  "secret-exfiltration",
  "unauthorized-action",
  "manipulation",
  "other",
]);
const SEVERITIES = new Set<string>(["low", "medium", "high", "critical"]);

/** Keys that would make model output an attempted authorization/execution decision. */
const FORBIDDEN_KEYS = new Set([
  "decision",
  "actiondecision",
  "allow",
  "allowed",
  "block",
  "blocked",
  "approve",
  "approved",
  "approval",
  "execute",
  "execution",
  "executenow",
  "toolcall",
  "tool_call",
  "toolcalls",
  "riskoverride",
  "finaldecision",
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function boundedString(value: unknown, max: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= max;
}

export type ModelValidationResult =
  | { ok: true; value: Omit<ModelAnalysis, "status" | "provider" | "model" | "isMock" | "authority" | "failureReason"> }
  | { ok: false; error: string };

/**
 * Strict runtime validation of provider output. Any attempted decision,
 * approval, or execution field makes the whole output invalid.
 */
export function validateModelOutput(raw: unknown): ModelValidationResult {
  if (!isRecord(raw)) return { ok: false, error: "model output is not an object" };

  for (const key of Object.keys(raw)) {
    if (FORBIDDEN_KEYS.has(key.toLowerCase())) {
      return { ok: false, error: `model output contains forbidden authorization field: ${key}` };
    }
  }

  if (!boundedString(raw.summary, MODEL_ANALYSIS_LIMITS.maxSummaryLength)) {
    return { ok: false, error: "summary missing or oversized" };
  }
  if (!boundedString(raw.explanation, MODEL_ANALYSIS_LIMITS.maxExplanationLength)) {
    return { ok: false, error: "explanation missing or oversized" };
  }
  if (typeof raw.suspectedUnauthorizedAction !== "boolean") {
    return { ok: false, error: "suspectedUnauthorizedAction must be boolean" };
  }
  if (typeof raw.suspectedDataExfiltration !== "boolean") {
    return { ok: false, error: "suspectedDataExfiltration must be boolean" };
  }
  if (!Array.isArray(raw.indicators) || raw.indicators.length > MODEL_ANALYSIS_LIMITS.maxIndicators) {
    return { ok: false, error: "indicators missing or too many" };
  }

  const indicators: ModelIndicator[] = [];
  for (const item of raw.indicators) {
    if (!isRecord(item)) return { ok: false, error: "indicator is not an object" };
    if (typeof item.category !== "string" || !INDICATOR_CATEGORIES.has(item.category)) {
      return { ok: false, error: "indicator category invalid" };
    }
    if (typeof item.severity !== "string" || !SEVERITIES.has(item.severity)) {
      return { ok: false, error: "indicator severity invalid" };
    }
    if (!boundedString(item.detail, MODEL_ANALYSIS_LIMITS.maxIndicatorDetailLength)) {
      return { ok: false, error: "indicator detail missing or oversized" };
    }
    indicators.push({
      category: item.category as ModelIndicatorCategory,
      severity: item.severity as FindingSeverity,
      detail: item.detail,
    });
  }

  return {
    ok: true,
    value: {
      summary: raw.summary,
      indicators,
      suspectedUnauthorizedAction: raw.suspectedUnauthorizedAction,
      suspectedDataExfiltration: raw.suspectedDataExfiltration,
      explanation: raw.explanation,
    },
  };
}

export function failedAnalysis(
  provider: ModelAnalysis["provider"],
  model: string,
  failureReason: string,
  status: ModelAnalysisStatus = "failed",
): ModelAnalysis {
  return {
    status,
    provider,
    model,
    isMock: provider === "mock",
    authority: "advisory-only",
    summary: "Model-assisted analysis did not produce a usable result.",
    indicators: [],
    suspectedUnauthorizedAction: false,
    suspectedDataExfiltration: false,
    explanation:
      "Model analysis failed or is unavailable. This is not evidence that the content is safe; deterministic policy and scanner results above remain authoritative.",
    failureReason,
  };
}
