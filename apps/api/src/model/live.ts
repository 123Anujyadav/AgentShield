import type { ModelConfig } from "./config.js";
import {
  MockModelProvider,
  ModelProviderError,
  buildMetaChatRequest,
  metaErrorCategory,
  parseMetaChatContent,
  parseMetaUsage,
  UNUSABLE_RESPONSE_REASONS,
  type ModelProvider,
  type ProviderCallOptions,
  type UnusableResponseReason,
} from "./provider.js";

export interface HttpResponseLike {
  status: number;
  headers: { get(name: string): string | null };
  text(): Promise<string>;
  /** Optional streamed body. When present it is read in bounded chunks and cancelled on abort or overflow. */
  body?: ReadableStream<Uint8Array> | null;
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
    body: response.body,
  };
};

export interface LiveProviderOptions {
  transport?: HttpTransport;
  /** Waits between retries; should resolve early when the signal aborts. */
  sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
  /** Hard cap on any Retry-After wait so a hostile/buggy header cannot stall us. */
  maxRetryAfterMs?: number;
}

/** Resolves after ms, or as soon as the signal aborts. Always removes its timer and listener. */
const defaultSleep = (ms: number, signal?: AbortSignal) =>
  new Promise<void>((resolve) => {
    if (signal?.aborted) {
      resolve();
      return;
    }
    const done = () => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", done);
      resolve();
    };
    const timer = setTimeout(done, ms);
    signal?.addEventListener("abort", done, { once: true });
  });

/** A failed response's body is only parsed for its documented error envelope, which is small. */
const MAX_ERROR_BODY_CHARS = 4096;

type AttemptResult =
  /** bodyText is null when the body exceeded the output limit; the rest was cancelled unread. */
  | { ok: true; bodyText: string | null }
  | { ok: false; status: number; retryAfter: string | null; errorCategory: string };

/** Settles with the promise, or rejects as soon as the signal aborts. Always removes its listener. */
function untilAborted<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) {
    // The abandoned promise may still settle later; its outcome is ignored.
    promise.catch(() => {});
    return Promise.reject(new Error("aborted"));
  }
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(new Error("aborted"));
    signal.addEventListener("abort", onAbort, { once: true });
    promise.then(
      (value) => {
        signal.removeEventListener("abort", onAbort);
        resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener("abort", onAbort);
        reject(error);
      },
    );
  });
}

/**
 * Reads at most maxChars characters of a body while the signal is live, and
 * returns null when the body is larger. A streamed body is read in chunks, never
 * buffered past the bound, and cancelled on overflow or abort. A text()-only body
 * (test fakes) is raced against the signal instead.
 */
async function readBoundedText(response: HttpResponseLike, maxChars: number, signal: AbortSignal): Promise<string | null> {
  const stream = response.body;
  if (!stream) {
    const text = await untilAborted(response.text(), signal);
    return text.length > maxChars ? null : text;
  }
  // A UTF-16 code unit takes at most 3 UTF-8 bytes, so more bytes than this
  // always means more than maxChars characters.
  const maxBytes = maxChars * 3;
  const reader = stream.getReader();
  const cancel = () => {
    reader.cancel().catch(() => {});
  };
  signal.addEventListener("abort", cancel, { once: true });
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  let finished = false;
  try {
    for (;;) {
      if (signal.aborted) throw new Error("aborted");
      const { done, value } = await reader.read();
      // A cancelled read reports done; the abort check keeps it from passing as a complete body.
      if (signal.aborted) throw new Error("aborted");
      if (done) break;
      bytes += value.byteLength;
      if (bytes > maxBytes) return null;
      chunks.push(value);
    }
    finished = true;
  } finally {
    signal.removeEventListener("abort", cancel);
    if (!finished) cancel();
  }
  const text = Buffer.concat(chunks).toString("utf8");
  return text.length > maxChars ? null : text;
}

const KNOWN_UNUSABLE_REASONS: ReadonlySet<string> = new Set(UNUSABLE_RESPONSE_REASONS);

/**
 * Logs why a successful response could not be used and returns the error to
 * throw. The log line holds one fixed code, re-checked against the allowlist, and
 * never any part of the response, prompt, headers, or key. The public failure
 * category stays "malformed".
 */
function unusableResponse(reason: UnusableResponseReason | undefined): ModelProviderError {
  const shown: UnusableResponseReason = reason !== undefined && KNOWN_UNUSABLE_REASONS.has(reason) ? reason : "unexpected-envelope";
  console.warn(`model-live status=unusable-response reason=${shown}`);
  return new ModelProviderError("malformed", shown);
}

function parseJsonOrNull(text: string | null): unknown {
  if (text === null) return null;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return null;
  }
}

/**
 * Real Meta Model API provider. Constructing it performs no network I/O and
 * no startup health check. It is only selected when the config gate passes
 * (MODEL_LIVE_ENABLED=true and MODEL_API_KEY present). See selectModelProvider.
 */
export class MetaLiveProvider implements ModelProvider {
  readonly kind = "meta" as const;
  private readonly transport: HttpTransport;
  private readonly sleep: (ms: number, signal?: AbortSignal) => Promise<void>;
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

  async analyze(untrustedText: string, options: ProviderCallOptions = {}): Promise<unknown> {
    const { signal } = options;
    if (untrustedText.length > this.config.maxInputLength) {
      throw new ModelProviderError("malformed");
    }
    const { url, init } = buildMetaChatRequest(this.config, this.apiKey, untrustedText);
    const maxAttempts = 1 + this.config.maxRetries;

    for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
      // The caller stopped waiting: send nothing more.
      if (signal?.aborted) throw new ModelProviderError("cancelled");
      // The caller reserved the first attempt; every retry needs its own reservation.
      if (attempt > 1 && options.reserveRetryAttempt && !options.reserveRetryAttempt()) {
        throw new ModelProviderError("request-budget-exceeded");
      }

      const result = await this.send(url, init, signal);
      // A response that completes after cancellation is discarded unread.
      if (signal?.aborted) throw new ModelProviderError("cancelled");

      if (result.ok) {
        // Tokens were spent even when the body is unusable, so usage is reported
        // on every successful response: "none" when it cannot be read.
        const { bodyText } = result;
        if (bodyText === null) {
          options.onUsage?.(null);
          throw unusableResponse("body-oversized");
        }
        let payload: unknown;
        try {
          payload = JSON.parse(bodyText) as unknown;
        } catch {
          options.onUsage?.(null);
          throw unusableResponse("body-not-json");
        }
        options.onUsage?.(parseMetaUsage(payload));
        // Rejects tool calls, cut-off or filtered answers, and unexpected shapes.
        // The result is raw untrusted advisory JSON; analyze.ts validates it
        // strictly afterwards. Nothing here is retried.
        try {
          return parseMetaChatContent(payload);
        } catch (error) {
          throw unusableResponse(error instanceof ModelProviderError ? error.reason : undefined);
        }
      }

      const retryable = result.status === 429 || result.status >= 500;
      if (retryable && attempt < maxAttempts) {
        await this.sleep(this.retryDelayMs(result.retryAfter, attempt), signal);
        continue;
      }

      // Sanitized logging only: integer status + a fixed documented category. Never headers or bodies.
      const shownStatus = Number.isInteger(result.status) ? result.status : "invalid";
      console.warn(`model-live status=http-error httpStatus=${shownStatus} category=${result.errorCategory}`);
      throw new ModelProviderError("http");
    }
    throw new ModelProviderError("http");
  }

  /**
   * One attempt: sends the request and reads its body (bounded) under one
   * AbortController that fires on this attempt's timeout or on the caller's
   * signal. Failed responses are read here too, so a slow or endless error body
   * is cancelled like the request and the body is consumed or cancelled before
   * any retry. The timer and the listener are always removed before returning.
   */
  private async send(url: string, init: HttpInitLike, signal?: AbortSignal): Promise<AttemptResult> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.config.timeoutMs);
    const cancel = () => controller.abort();
    signal?.addEventListener("abort", cancel, { once: true });
    try {
      const response = await untilAborted(this.transport(url, { ...init, signal: controller.signal }), controller.signal);
      if (response.status >= 200 && response.status < 300) {
        return { ok: true, bodyText: await readBoundedText(response, this.config.maxOutputLength, controller.signal) };
      }
      let errorBody: string | null = null;
      try {
        errorBody = await readBoundedText(response, MAX_ERROR_BODY_CHARS, controller.signal);
      } catch (error) {
        // Abort or timeout ends the attempt. Any other unreadable error body
        // just leaves the status-derived category, keeping the retry policy unchanged.
        if (controller.signal.aborted) throw error;
      }
      return {
        ok: false,
        status: response.status,
        retryAfter: response.headers.get("retry-after"),
        errorCategory: metaErrorCategory(parseJsonOrNull(errorBody), response.status),
      };
    } catch {
      // Caller abort => cancelled; own timer => timeout; anything else => network.
      // None of these is retried.
      if (signal?.aborted) throw new ModelProviderError("cancelled");
      if (controller.signal.aborted) throw new ModelProviderError("timeout");
      throw new ModelProviderError("network");
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener("abort", cancel);
    }
  }

  private retryDelayMs(retryAfter: string | null, attempt: number): number {
    const seconds = retryAfter ? Number.parseFloat(retryAfter) : Number.NaN;
    if (!Number.isNaN(seconds) && seconds >= 0) {
      return Math.min(seconds * 1000, this.maxRetryAfterMs);
    }
    return Math.min(250 * 2 ** (attempt - 1), this.maxRetryAfterMs);
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
