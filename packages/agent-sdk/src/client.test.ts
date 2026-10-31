import { inspect } from "node:util";
import { describe, expect, it } from "vitest";
import { AgentShieldClient, MAX_EVALUATE_BODY_BYTES } from "./client.js";
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
} from "./errors.js";
import { testKey, verifySignedRequest } from "./test-fixtures.js";
import type { EvaluateRequest } from "./types.js";

/** M3-E E5: the client, against a fake fetch that records every request. */

const key = testKey("client-tests");
const credential = AgentCredential.fromString(key.credential);
const BASE = "http://127.0.0.1:4000";
const T0 = 1_793_523_600_000;

interface Call {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: Buffer | undefined;
  redirect: string | undefined;
}

type Responder = (call: Call, index: number, signal: AbortSignal) => Response | Promise<Response>;

function harness(responder: Responder, options: { getRetries?: number; timeoutMs?: number } = {}) {
  const calls: Call[] = [];
  const sleeps: number[] = [];
  let clock = T0;
  const fetchImpl = (async (input: URL | string, init: RequestInit) => {
    const call: Call = {
      url: String(input),
      method: String(init.method),
      headers: init.headers as Record<string, string>,
      body: init.body === undefined || init.body === null ? undefined : Buffer.from(init.body as Uint8Array),
      redirect: init.redirect,
    };
    calls.push(call);
    clock += 7; // each request moves the clock, so timestamps differ
    return responder(call, calls.length - 1, init.signal as AbortSignal);
  }) as typeof fetch;
  const client = new AgentShieldClient({
    baseUrl: BASE,
    credential,
    fetch: fetchImpl,
    now: () => clock,
    sleep: async (ms) => {
      sleeps.push(ms);
      clock += ms;
    },
    ...options,
  });
  return { client, calls, sleeps };
}

const json = (status: number, body: unknown, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
const approval = (id: string, status = "PENDING") => ({
  id,
  status,
  createdAt: "2026-11-01T09:00:00.000Z",
  expiresAt: "2026-11-01T09:15:00.000Z",
  executed: status === "EXECUTED",
  pollAfterSeconds: status === "PENDING" ? 2 : null,
});
const request: EvaluateRequest = {
  intent: { task: "Summarize the quarterly report" },
  action: { type: "create_summary", tool: "simulated.workspace.createSummary", destination: "simulated-workspace", summary: "Create a summary" },
  untrustedContent: { source: "document", text: "Quarterly figures." },
};
const evaluateResponse = {
  evaluation: { decision: "CONFIRM", riskScore: 80, explanation: "Needs confirmation.", findings: [{ ruleId: "r", category: "injection", severity: "high", title: "t", explanation: "e", evidence: "x" }], scannerStatus: "suspicious" },
  executed: false,
  pendingApproval: { id: "apr-7", status: "PENDING", intent: { task: "Summarize" } },
  event: { id: "evt-1" },
  modelAnalysis: { authority: "advisory-only" },
};
const verified = (call: Call) => verifySignedRequest({ method: call.method, url: call.url, authorization: call.headers.Authorization!, body: call.body }, key.publicKey);
const caught = async (promise: Promise<unknown>) => {
  try {
    await promise;
  } catch (error) {
    return error as Error;
  }
  throw new Error("expected a rejection");
};

describe("M3-E E5: evaluate", () => {
  it("sends exactly the documented fields, signed over the exact body bytes, and returns the decision", async () => {
    const h = harness(() => json(200, evaluateResponse));
    const result = await h.client.evaluate({ ...request, agentId: "someone-else" } as EvaluateRequest);
    expect(result).toEqual({ decision: "CONFIRM", riskScore: 80, explanation: "Needs confirmation.", findings: evaluateResponse.evaluation.findings, executed: false, approvalId: "apr-7" });
    const [call] = h.calls;
    expect([call!.method, call!.url, call!.headers["Content-Type"], call!.redirect]).toEqual(["POST", `${BASE}/api/evaluate`, "application/json", "error"]);
    expect(JSON.parse(call!.body!.toString())).toEqual({ intent: request.intent, action: request.action, untrustedContent: request.untrustedContent });
    expect(verified(call!)).toBe(true);
  });

  it.each([
    ["401", () => json(401, { error: "Authentication required." }), AuthenticationError],
    ["429 with a short Retry-After", () => json(429, { error: "x" }, { "retry-after": "1" }), RateLimitedError],
    ["503 approval queue full", () => json(503, { error: "x", reason: "approval-queue-full" }), ServiceUnavailableError],
    ["500", () => json(500, { error: "Internal error." }), ServerError],
    ["a network failure", () => Promise.reject(new TypeError("fetch failed")), NetworkError],
  ])("is never retried automatically (%s)", async (_label, responder, ErrorType) => {
    const h = harness(responder as Responder, { getRetries: 5 });
    const error = await caught(h.client.evaluate(request));
    expect(error).toBeInstanceOf(ErrorType);
    expect([h.calls.length, h.sleeps]).toEqual([1, []]);
  });

  it("is not retried after a timeout either (it may already have run)", async () => {
    const h = harness((_c, _i, signal) => new Promise((_resolve, reject) => signal.addEventListener("abort", () => reject(signal.reason))), { timeoutMs: 100, getRetries: 5 });
    const started = Date.now();
    expect(await caught(h.client.evaluate(request))).toBeInstanceOf(TimeoutError);
    expect(Date.now() - started).toBeLessThan(5000);
    expect(h.calls).toHaveLength(1);
  });

  it("refuses invalid or oversized evaluations before sending anything", async () => {
    const h = harness(() => json(200, evaluateResponse));
    const big = { ...request, untrustedContent: { source: "doc", text: "x".repeat(MAX_EVALUATE_BODY_BYTES) } };
    const unserialisable = { ...request, action: { ...request.action, payload: { count: 1n } } };
    for (const bad of [big, { intent: {}, action: request.action }, { intent: request.intent }, null, unserialisable]) {
      expect(await caught(h.client.evaluate(bad as EvaluateRequest))).toBeInstanceOf(InvalidArgumentError);
    }
    expect(h.calls).toHaveLength(0);
  });

  it("maps 400 and 403 to typed errors with the server's reason, and rejects an unexpected response shape", async () => {
    const forbidden = await caught(harness(() => json(403, { error: "x", reason: "agent-identity-mismatch" })).client.evaluate(request));
    expect(forbidden).toBeInstanceOf(ForbiddenError);
    expect((forbidden as ForbiddenError).details).toEqual({ status: 403, reason: "agent-identity-mismatch" });
    expect(await caught(harness(() => json(400, { error: "x", reason: "invalid-agent-id" })).client.evaluate(request))).toBeInstanceOf(BadRequestError);
    expect(await caught(harness(() => json(200, { evaluation: { decision: "MAYBE" } })).client.evaluate(request))).toBeInstanceOf(ResponseFormatError);
    expect(await caught(harness(() => new Response("not json", { status: 200 })).client.evaluate(request))).toBeInstanceOf(ResponseFormatError);
  });
});

describe("M3-E E5: approvals", () => {
  it("reads one approval (exactly six fields) and returns null for the server's uniform 404", async () => {
    const h = harness((call) => (call.url.endsWith("apr-3") ? json(200, { approval: approval("apr-3") }) : json(404, { error: "Approval not found." })));
    expect(await h.client.getApproval("apr-3")).toEqual(approval("apr-3"));
    expect(await h.client.getApproval("apr-4")).toBeNull();
    expect(h.calls.map((c) => [c.method, c.url, c.body])).toEqual([
      ["GET", `${BASE}/api/agent/approvals/apr-3`, undefined],
      ["GET", `${BASE}/api/agent/approvals/apr-4`, undefined],
    ]);
    expect(h.calls.every(verified)).toBe(true);
  });

  it("rejects malformed ids locally and responses that break the six-field contract", async () => {
    const h = harness(() => json(200, { approval: approval("apr-3") }));
    for (const id of ["apr-0", "APR-1", "1", "apr-1/approve", "../approvals"]) expect(await caught(h.client.getApproval(id))).toBeInstanceOf(InvalidArgumentError);
    expect(h.calls).toHaveLength(0);
    for (const body of [{ approval: { ...approval("apr-3"), agentId: "writer" } }, { approval: { ...approval("apr-3"), status: "DONE" } }, { approval: approval("apr-3"), extra: 1 }, { approval: { id: "apr-3" } }]) {
      expect(await caught(harness(() => json(200, body)).client.getApproval("apr-3"))).toBeInstanceOf(ResponseFormatError);
    }
  });

  it("lists with limit, before and status; pages with iterateApprovals; validates options locally", async () => {
    const pages: Record<string, unknown> = {
      [`${BASE}/api/agent/approvals?limit=2&status=PENDING`]: { approvals: [approval("apr-9"), approval("apr-8")], nextCursor: "apr-8" },
      [`${BASE}/api/agent/approvals?limit=2&before=apr-8&status=PENDING`]: { approvals: [approval("apr-5")], nextCursor: null },
    };
    const h = harness((call) => (call.url in pages ? json(200, pages[call.url]) : json(400, { error: "x", reason: "invalid-query" })));
    expect(await h.client.listApprovals({ limit: 2, status: "PENDING" })).toEqual(pages[`${BASE}/api/agent/approvals?limit=2&status=PENDING`]);
    const seen: string[] = [];
    for await (const a of h.client.iterateApprovals({ limit: 2, status: "PENDING" })) seen.push(a.id);
    expect(seen).toEqual(["apr-9", "apr-8", "apr-5"]);
    expect(h.calls.every(verified)).toBe(true);
    const before = h.calls.length;
    for (const bad of [{ limit: 0 }, { limit: 51 }, { limit: 1.5 }, { before: "x" }, { status: "DONE" }, { agentId: "reader" }]) {
      expect(await caught(h.client.listApprovals(bad as never))).toBeInstanceOf(InvalidArgumentError);
    }
    expect(h.calls.length).toBe(before);
  });

  it("waitForApproval follows pollAfterSeconds until a decision, and reports not-found and time-outs", async () => {
    const statuses = ["PENDING", "PENDING", "EXECUTED"];
    const h = harness((_c, i) => json(200, { approval: approval("apr-3", statuses[Math.min(i, 2)]) }));
    expect(await h.client.waitForApproval("apr-3")).toMatchObject({ status: "EXECUTED", executed: true });
    expect(h.sleeps).toEqual([2000, 2000]);
    expect(await caught(harness(() => json(404, { error: "Approval not found." })).client.waitForApproval("apr-3"))).toBeInstanceOf(ApprovalNotFoundError);
    const stuck = harness(() => json(200, { approval: approval("apr-3") }));
    expect(await caught(stuck.client.waitForApproval("apr-3", { timeoutMs: 5000 }))).toBeInstanceOf(WaitTimeoutError);
    expect(stuck.calls.length).toBeLessThanOrEqual(4);
    const controller = new AbortController();
    controller.abort(new Error("stop"));
    expect((await caught(stuck.client.waitForApproval("apr-3", { signal: controller.signal }))).message).toBe("stop");
    // Aborted during the wait between polls: stops without polling again.
    const later = new AbortController();
    let polls = 0;
    const waiting = new AgentShieldClient({
      baseUrl: BASE,
      credential,
      fetch: (async () => {
        polls += 1;
        return json(200, { approval: approval("apr-3") });
      }) as typeof fetch,
      sleep: async () => {
        later.abort(new Error("stopped while waiting"));
      },
    });
    expect((await caught(waiting.waitForApproval("apr-3", { signal: later.signal }))).message).toBe("stopped while waiting");
    expect(polls).toBe(1);
  });
});

describe("M3-E E5: GET retries", () => {
  const headersOf = (h: ReturnType<typeof harness>) => h.calls.map((c) => c.headers.Authorization!);

  it("retries 503 and 429 (honouring a short Retry-After), each attempt freshly signed", async () => {
    const h = harness((_c, i) => (i === 0 ? json(503, { error: "x" }, { "retry-after": "1" }) : i === 1 ? json(429, { error: "x" }, { "retry-after": "2" }) : json(200, { approval: approval("apr-3") })));
    expect(await h.client.getApproval("apr-3")).toEqual(approval("apr-3"));
    expect([h.calls.length, h.sleeps]).toEqual([3, [1000, 2000]]);
    const auth = headersOf(h);
    expect(new Set(auth).size).toBe(3);
    const nonces = auth.map((a) => /nonce="([^"]+)"/.exec(a)![1]);
    const timestamps = auth.map((a) => /ts="(\d+)"/.exec(a)![1]);
    expect(new Set(nonces).size).toBe(3);
    expect(new Set(timestamps).size).toBe(3);
    expect(h.calls.every(verified)).toBe(true);
  });

  it("retries a network failure, and re-signs once after a 401 (a request signed just before a restart)", async () => {
    const net = harness((_c, i) => (i === 0 ? Promise.reject(new TypeError("fetch failed")) : json(200, { approval: approval("apr-3") })));
    expect(await net.client.getApproval("apr-3")).not.toBeNull();
    expect(net.calls).toHaveLength(2);
    const once = harness((_c, i) => (i === 0 ? json(401, { error: "x" }) : json(200, { approval: approval("apr-3") })));
    expect(await once.client.getApproval("apr-3")).not.toBeNull();
    expect(once.calls).toHaveLength(2);
    expect(new Set(headersOf(once)).size).toBe(2);
  });

  it("never retries a 401 more than once, never retries 400/403, and stops at the retry limit", async () => {
    const auth = harness(() => json(401, { error: "x" }), { getRetries: 5 });
    expect(await caught(auth.client.getApproval("apr-3"))).toBeInstanceOf(AuthenticationError);
    expect(auth.calls).toHaveLength(2);
    for (const status of [400, 403]) {
      const h = harness(() => json(status, { error: "x" }), { getRetries: 5 });
      await caught(h.client.listApprovals());
      expect(h.calls, String(status)).toHaveLength(1);
    }
    const capped = harness(() => json(503, { error: "x" }));
    expect(await caught(capped.client.getApproval("apr-3"))).toBeInstanceOf(ServiceUnavailableError);
    expect(capped.calls).toHaveLength(3); // 1 + default getRetries (2)
    const zero = harness(() => json(503, { error: "x" }), { getRetries: 0 });
    await caught(zero.client.getApproval("apr-3"));
    expect(zero.calls).toHaveLength(1);
  });

  it("does not wait for a long Retry-After: it reports the rate limit at once", async () => {
    const h = harness(() => json(429, { error: "x" }, { "retry-after": "60" }));
    const error = await caught(h.client.getApproval("apr-3"));
    expect([error instanceof RateLimitedError, (error as RateLimitedError).details.retryAfterSeconds, h.calls.length, h.sleeps]).toEqual([true, 60, 1, []]);
  });

  it("times out a GET that never answers, retrying within the limit", async () => {
    const h = harness((_c, _i, signal) => new Promise((_resolve, reject) => signal.addEventListener("abort", () => reject(signal.reason))), { timeoutMs: 100, getRetries: 1 });
    expect(await caught(h.client.getApproval("apr-3"))).toBeInstanceOf(TimeoutError);
    expect(h.calls).toHaveLength(2);
  });
});

describe("M3-E E5: configuration and exposure", () => {
  it("accepts loopback origins; refuses remote, plain-http-remote, paths, queries, user info and other schemes", () => {
    for (const baseUrl of ["http://127.0.0.1:4000", "http://localhost:4000/", "http://[::1]:4000"]) expect(() => new AgentShieldClient({ baseUrl, credential })).not.toThrow();
    expect(() => new AgentShieldClient({ baseUrl: "https://agentshield.example", credential, allowRemote: true })).not.toThrow();
    for (const [baseUrl, allowRemote] of [
      ["https://agentshield.example", false],
      ["http://agentshield.example", true],
      ["http://127.0.0.1:4000/api", false],
      ["http://127.0.0.1:4000/?x=1", false],
      ["http://user:pass@127.0.0.1:4000", false],
      ["ftp://127.0.0.1", false],
      ["not a url", false],
    ] as const) {
      expect(() => new AgentShieldClient({ baseUrl, credential, allowRemote }), baseUrl).toThrowError(ConfigurationError);
    }
    expect(() => new AgentShieldClient({ baseUrl: BASE, credential, timeoutMs: 50 })).toThrowError(ConfigurationError);
    expect(() => new AgentShieldClient({ baseUrl: BASE, credential, getRetries: 6 })).toThrowError(ConfigurationError);
    expect(() => new AgentShieldClient({ baseUrl: BASE, credential: { keyId: key.keyId } as unknown as AgentCredential })).toThrowError(ConfigurationError);
  });

  it("offers only the agent operations: no generic request, approve, reject or execute method", () => {
    const methods = Object.getOwnPropertyNames(AgentShieldClient.prototype).sort();
    expect(methods).toEqual(["constructor", "evaluate", "getApproval", "iterateApprovals", "keyId", "listApprovals", "toJSON", "waitForApproval"]);
  });

  it("the private key is never sent, logged or exposed: requests, errors, JSON and inspect", async () => {
    const responses = [json(200, evaluateResponse), json(401, { error: "x" }), json(401, { error: "x" }), json(200, { approval: approval("apr-3") })];
    const h = harness((_c, i) => responses[i] ?? json(500, {}));
    const errors: Error[] = [];
    await h.client.evaluate(request);
    errors.push(await caught(h.client.getApproval("apr-3")));
    errors.push(await caught(harness(() => Promise.reject(new TypeError("fetch failed"))).client.evaluate(request)));
    const everything = [
      ...h.calls.map((c) => `${c.url} ${JSON.stringify(c.headers)} ${c.body?.toString() ?? ""}`),
      ...errors.map((e) => `${e.message} ${JSON.stringify(e)} ${inspect(e)}`),
      JSON.stringify(h.client),
      inspect(h.client, { showHidden: true, depth: 10 }),
      String(h.client),
    ].join("\n");
    expect(everything).not.toContain(key.secretPart);
    expect(everything).not.toContain(key.secretPart.slice(-43));
    expect(everything).not.toContain("asag2_");
    expect(JSON.parse(JSON.stringify(h.client))).toEqual({ baseUrl: BASE, keyId: key.keyId });
  });
});
