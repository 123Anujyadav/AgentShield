import { describe, expect, it, vi } from "vitest";
import { createTestApp as createApp, request } from "../test-support.js";
import { loadModelConfig } from "./config.js";
import { MetaLiveProvider, selectModelProvider, type HttpTransport } from "./live.js";
import { MockModelProvider } from "./provider.js";

const TEST_KEY = "TEST_KEY_NOT_REAL";

describe("provider-selection gate (Phase 7 audit, offline)", () => {
  it("default config and key-alone both select mock", () => {
    expect(selectModelProvider(loadModelConfig({}))).toBeInstanceOf(MockModelProvider);
    expect(selectModelProvider(loadModelConfig({ MODEL_API_KEY: TEST_KEY }), { MODEL_API_KEY: TEST_KEY }))
      .toBeInstanceOf(MockModelProvider);
  });

  it("flag without key fails closed to mock and cannot call transport", async () => {
    const transport: HttpTransport = vi.fn(async () => {
      throw new Error("transport must not be called");
    });
    const provider = selectModelProvider(loadModelConfig({ MODEL_LIVE_ENABLED: "true" }), {}, { transport });
    expect(provider).toBeInstanceOf(MockModelProvider);
    const result = await provider.analyze("hello");
    expect(result).toBeTruthy();
    expect(transport).not.toHaveBeenCalled();
  });

  it("live is selected only with flag AND key; construction makes no request", () => {
    const transport: HttpTransport = vi.fn(async () => {
      throw new Error("transport must not be called during construction");
    });
    const config = loadModelConfig({ MODEL_LIVE_ENABLED: "true", MODEL_API_KEY: TEST_KEY });
    const provider = selectModelProvider(config, { MODEL_API_KEY: TEST_KEY }, { transport });
    expect(provider).toBeInstanceOf(MetaLiveProvider);
    expect(transport).not.toHaveBeenCalled();
  });

  it("/api/model/status performs no outbound request and exposes no secret material", async () => {
    const transport: HttpTransport = vi.fn(async () => {
      throw new Error("transport must not be called by status");
    });
    const app = createApp();
    const res = await request(app).get("/api/model/status");
    expect(res.status).toBe(200);
    expect(res.body.mode).toBe("mock");
    expect(res.body.liveEnabled).toBe(false);
    expect(res.body.isMock).toBe(true);
    const serialized = JSON.stringify(res.body);
    expect(serialized).not.toContain(TEST_KEY);
    expect(serialized.toLowerCase()).not.toContain("bearer");
    expect(serialized).not.toContain("Authorization");
    expect(transport).not.toHaveBeenCalled();
  });

  it("frontend/request-body fields cannot activate live mode or change the provider", async () => {
    const app = createApp();
    const res = await request(app)
      .post("/api/evaluate")
      .send({
        scenarioId: "benign-summary",
        provider: "meta",
        MODEL_LIVE_ENABLED: "true",
        MODEL_API_KEY: TEST_KEY,
        liveEnabled: true,
        mode: "live",
      });
    expect(res.status).toBe(200);
    expect(res.body.modelAnalysis.isMock).toBe(true);
    expect(res.body.modelAnalysis.provider).toBe("mock");
    const status = await request(app).get("/api/model/status");
    expect(status.body.mode).toBe("mock");
    expect(JSON.stringify(res.body)).not.toContain(TEST_KEY);
  });
});
