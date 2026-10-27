import type { ModelConfig } from "./config.js";
import {
  MockModelProvider,
  ModelProviderError,
  buildMetaChatRequest,
  metaErrorCategory,
  parseMetaChatContent,
  type ModelProvider,
} from "./provider.js";

export interface HttpResponseLike {
  status: number;
  headers: { get(name: string): string | null };
  text(): Promise<string>;
}

export interface HttpInitLike {
  method: string;
  headers: Record<string, string>;
  body: string;
  signal?: AbortSignal;
}

/** Injected transport. Production default wraps fetch; tests inject fakes. */
export type HttpTransport = (url: string, init: HttpInitLike) => Promise<HttpResponseLike>;

export const defaultHttpTransport: HttpTransport = async (url, init) => {
  const response = await fetch(url, init);
  return {
    status: response.status,
    headers: response.headers,
    text: () => response.text(),
  };
};

export interface LiveProviderOptions {
  transport?: HttpTransport;
  sleep?: (ms: number) => Promise<void>;
  /** Hard cap on any Retry-After wait so a hostile/buggy header cannot stall us. */
  maxRetryAfterMs?: number;
}

const defaultSleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/**
 * Real Meta Model API provider. Constructing it performs no network I/O and
 * no startup health check. It is only selected when the config gate passes
 * (MODEL_LIVE_ENABLED=true and MODEL_API_KEY present). See selectModelProvider.
 */
export class MetaLiveProvider implements ModelProvider {
  readonly kind = "meta" as const;
  private readonly transport: HttpTransport;
  private readonly sleep: (ms: number) => Promise<void>;
  private readonly maxRetryAfterMs: number;

  constructor(
    private readonly config: ModelConfig,
    private readonly apiKey: string,
    options: LiveProviderOptions = {},
  ) {
    if (!apiKey) throw new ModelProviderError("live-disabled");
    this.transport = options.transport ?? defaultHttpTransport;
    this.sleep = options.sleep ?? defaultSleep;
    this.maxRetryAfterMs = options.maxRetryAfterMs ?? 5000;
  }

  async analyze(untrustedText: string): Promise<unknown> {
    if (untrustedText.length > this.config.maxInputLength) {
      throw new ModelProviderError("malformed");
    }
    const { url, init } = buildMetaChatRequest(this.config, this.apiKey, untrustedText);
    const maxAttempts = 1 + this.config.maxRetries;

    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), this.config.timeoutMs);
      let response: HttpResponseLike;
      try {
        response = await this.transport(url, { ...init, signal: controller.signal });
      } catch {
        // Abort => timeout. Other transport failures => network. No retry either way
        // beyond this point except explicit 429/5xx handling below.
        if (controller.signal.aborted) throw new ModelProviderError("timeout");
        throw new ModelProviderError("network");
      } finally {
        clearTimeout(timer);
      }

      if (response.status >= 200 && response.status < 300) {
        const bodyText = await response.text();
        if (bodyText.length > this.config.maxOutputLength) {
          throw new ModelProviderError("malformed");
        }
        let payload: unknown;
        try {
          payload = JSON.parse(bodyText) as unknown;
        } catch {
          throw new ModelProviderError("malformed");
        }
        // Rejects tool calls and non-chat.completion shapes. The result is raw
        // untrusted advisory JSON; analyze.ts validates it strictly afterwards.
        return parseMetaChatContent(payload);
      }

      const retryable = response.status === 429 || response.status >= 500;
      if (retryable && attempt < maxAttempts) {
        await this.sleep(this.retryDelayMs(response, attempt));
        continue;
      }

      // Sanitized logging only: status + documented category. Never headers or bodies.
      const category = metaErrorCategory(await safeJson(response), response.status);
      console.warn(`model-live status=http-error httpStatus=${response.status} category=${category}`);
      throw new ModelProviderError(response.status === 401 ? "http" : "http");
    }
    throw new ModelProviderError("http");
  }

  private retryDelayMs(response: HttpResponseLike, attempt: number): number {
    const retryAfter = response.headers.get("retry-after");
    const seconds = retryAfter ? Number.parseFloat(retryAfter) : Number.NaN;
    if (!Number.isNaN(seconds) && seconds >= 0) {
      return Math.min(seconds * 1000, this.maxRetryAfterMs);
    }
    return Math.min(250 * 2 ** (attempt - 1), this.maxRetryAfterMs);
  }
}

async function safeJson(response: HttpResponseLike): Promise<unknown> {
  try {
    const text = await response.text();
    return JSON.parse(text) as unknown;
  } catch {
    return null;
  }
}

/**
 * Provider selection gate.
 * - Flag off (default): mock, regardless of key.
 * - Flag on but key missing: mock (fail closed). No live attempt is possible.
 * - Flag on and key present: live.
 * The key is read here from the server process environment only.
 */
export function selectModelProvider(
  config: ModelConfig,
  env: NodeJS.ProcessEnv = process.env,
  liveOptions: LiveProviderOptions = {},
): ModelProvider {
  if (!config.liveEnabled) return new MockModelProvider();
  const apiKey = env.MODEL_API_KEY;
  if (!apiKey) return new MockModelProvider();
  return new MetaLiveProvider(config, apiKey, liveOptions);
}
