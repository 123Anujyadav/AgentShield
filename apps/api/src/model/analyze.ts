import {
  failedAnalysis,
  validateModelOutput,
  type ModelAnalysis,
} from "@agentshield/engine";
import type { ModelConfig } from "./config.js";
import { ModelProviderError, type ModelProvider, type TokenUsage } from "./provider.js";

/** In-memory token accounting for this API process. Counts only; resets on restart. */
export interface ModelUsageTotals {
  responsesWithUsage: number;
  responsesWithoutUsage: number;
  promptTokens: number;
  completionTokens: number;
  /** Sum of provider-reported totals only; a response without a reported total adds nothing. */
  reportedTotalTokens: number;
}

/** On timeout, aborts the controller (stopping the provider's request and retries), then rejects. */
function withTimeout<T>(promise: Promise<T>, timeoutMs: number, controller: AbortController): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => {
      controller.abort();
      reject(new ModelProviderError("timeout"));
    }, timeoutMs);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timer);
        reject(error);
      },
    );
  });
}

export class ModelAnalysisService {
  /** Outgoing provider request attempts, including retries. MODEL_MAX_REQUESTS caps this. */
  private attemptsUsed = 0;
  private readonly usageTotals: ModelUsageTotals = {
    responsesWithUsage: 0,
    responsesWithoutUsage: 0,
    promptTokens: 0,
    completionTokens: 0,
    reportedTotalTokens: 0,
  };

  constructor(
    private readonly provider: ModelProvider,
    private readonly config: ModelConfig,
  ) {}

  get requestsUsed(): number {
    return this.attemptsUsed;
  }

  get usage(): ModelUsageTotals {
    return { ...this.usageTotals };
  }

  /**
   * Check and reserve in one synchronous step: with no await in between,
   * concurrent analyses cannot reserve more attempts than the budget allows.
   */
  private reserveAttempt(): boolean {
    if (this.attemptsUsed >= this.config.maxRequests) return false;
    this.attemptsUsed += 1;
    return true;
  }

  /** Logs counts only: never the key, prompt, response, or untrusted content. */
  private recordUsage(usage: TokenUsage | null): void {
    if (!usage) {
      this.usageTotals.responsesWithoutUsage += 1;
      console.info("model-usage status=not-reported");
      return;
    }
    this.usageTotals.responsesWithUsage += 1;
    this.usageTotals.promptTokens += usage.promptTokens;
    this.usageTotals.completionTokens += usage.completionTokens;
    if (usage.totalTokens !== null) this.usageTotals.reportedTotalTokens += usage.totalTokens;
    console.info(
      `model-usage status=reported promptTokens=${usage.promptTokens} completionTokens=${usage.completionTokens} totalTokens=${usage.totalTokens ?? "not-reported"}`,
    );
  }

  async analyze(untrustedText: string): Promise<ModelAnalysis> {
    const providerName = this.provider.kind;
    const modelName = providerName === "mock" ? "mock (deterministic, offline)" : this.config.model;

    if (untrustedText.length > this.config.maxInputLength) {
      return failedAnalysis(providerName, modelName, "oversized-input");
    }
    // Reserves the first attempt; the provider must reserve each retry itself.
    if (!this.reserveAttempt()) {
      return failedAnalysis(providerName, modelName, "request-budget-exceeded", "unavailable");
    }

    const controller = new AbortController();
    let raw: unknown;
    try {
      raw = await withTimeout(
        this.provider.analyze(untrustedText, {
          signal: controller.signal,
          reserveRetryAttempt: () => this.reserveAttempt(),
          onUsage: (usage) => this.recordUsage(usage),
        }),
        this.config.timeoutMs,
        controller,
      );
    } catch (error) {
      const category = error instanceof ModelProviderError ? error.category : "unknown";
      const status = category === "live-disabled" || category === "request-budget-exceeded" ? "unavailable" : "failed";
      // Only the sanitized category is surfaced. Never log raw content or bodies.
      console.warn(`model-analysis status=failed category=${category}`);
      return failedAnalysis(providerName, modelName, category, status);
    }

    if (typeof raw === "string") {
      if (raw.length > this.config.maxOutputLength) {
        return failedAnalysis(providerName, modelName, "oversized-output");
      }
      try {
        raw = JSON.parse(raw) as unknown;
      } catch {
        return failedAnalysis(providerName, modelName, "malformed-json");
      }
    } else if (JSON.stringify(raw)?.length > this.config.maxOutputLength) {
      return failedAnalysis(providerName, modelName, "oversized-output");
    }

    const validation = validateModelOutput(raw);
    if (!validation.ok) {
      console.warn("model-analysis status=failed category=invalid-model-output");
      return failedAnalysis(providerName, modelName, "invalid-model-output");
    }

    return {
      status: "success",
      provider: providerName,
      model: modelName,
      isMock: providerName === "mock",
      authority: "advisory-only",
      ...validation.value,
      failureReason: null,
    };
  }
}
