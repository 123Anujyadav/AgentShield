export interface ModelConfig {
  /**
   * Effective runtime mode. "live" is only possible when MODEL_LIVE_ENABLED
   * is exactly "true" AND MODEL_API_KEY is present. Otherwise mock (fail closed).
   */
  effectiveMode: "mock" | "live";
  requestedMode: string;
  provider: "mock" | "meta";
  baseUrl: string;
  model: string;
  /** Presence only. The value is never read into responses, logs, or the frontend. */
  apiKeyConfigured: boolean;
  /** Explicit server-side feature flag. Defaults to false. */
  liveFlagSet: boolean;
  liveEnabled: boolean;
  timeoutMs: number;
  maxInputLength: number;
  /** Upper bound, in characters, for a successful provider response body and for the answer inside it. */
  maxOutputLength: number;
  maxRequests: number;
  maxRetries: number;
}

function parseBoundedInt(value: string | undefined, fallback: number, min: number, max: number): number {
  const parsed = Number.parseInt(value ?? "", 10);
  if (Number.isNaN(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

export function loadModelConfig(env: NodeJS.ProcessEnv = process.env): ModelConfig {
  const apiKeyConfigured = Boolean(env.MODEL_API_KEY);
  const liveFlagSet = env.MODEL_LIVE_ENABLED === "true";
  const liveEnabled = liveFlagSet && apiKeyConfigured;
  return {
    effectiveMode: liveEnabled ? "live" : "mock",
    requestedMode: env.MODEL_PROVIDER_MODE ?? "mock",
    provider: liveEnabled ? "meta" : "mock",
    baseUrl: env.MODEL_BASE_URL ?? "https://api.meta.ai/v1",
    model: env.MODEL_NAME ?? "muse-spark-1.3",
    apiKeyConfigured,
    liveFlagSet,
    liveEnabled,
    timeoutMs: parseBoundedInt(env.MODEL_TIMEOUT_MS, 5000, 100, 30000),
    maxInputLength: parseBoundedInt(env.MODEL_MAX_INPUT_CHARS, 4000, 100, 20000),
    // Bounds the provider's whole response body, not only the answer. A
    // schema-maximal answer in a full chat.completion envelope measures 4,017
    // characters as compact ASCII JSON and up to about 18,000 when quotes or
    // non-ASCII text are escaped; the former 4,000 default rejected all of them.
    // 20,000 (the existing maximum) fits every such case (see live.test.ts).
    maxOutputLength: parseBoundedInt(env.MODEL_MAX_OUTPUT_CHARS, 20000, 100, 20000),
    maxRequests: parseBoundedInt(env.MODEL_MAX_REQUESTS, 50, 1, 1000),
    maxRetries: parseBoundedInt(env.MODEL_MAX_RETRIES, 2, 0, 3),
  };
}
