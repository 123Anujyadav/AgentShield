import {
  failedAnalysis,
  validateModelOutput,
  type ModelAnalysis,
} from "@agentshield/engine";
import type { ModelConfig } from "./config.js";
import { ModelProviderError, type ModelProvider } from "./provider.js";

function withTimeout<T>(promise: Promise<T>, timeoutMs: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new ModelProviderError("timeout")), timeoutMs);
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
  private requestCount = 0;

  constructor(
    private readonly provider: ModelProvider,
    private readonly config: ModelConfig,
  ) {}

  get requestsUsed(): number {
    return this.requestCount;
  }

  async analyze(untrustedText: string): Promise<ModelAnalysis> {
    const providerName = this.provider.kind;
    const modelName = providerName === "mock" ? "mock (deterministic, offline)" : this.config.model;

    if (untrustedText.length > this.config.maxInputLength) {
      return failedAnalysis(providerName, modelName, "oversized-input");
    }
    if (this.requestCount >= this.config.maxRequests) {
      return failedAnalysis(providerName, modelName, "request-budget-exceeded", "unavailable");
    }
    this.requestCount += 1;

    let raw: unknown;
    try {
      raw = await withTimeout(this.provider.analyze(untrustedText), this.config.timeoutMs);
    } catch (error) {
      const category = error instanceof ModelProviderError ? error.category : "unknown";
      const status = category === "live-disabled" ? "unavailable" : "failed";
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
