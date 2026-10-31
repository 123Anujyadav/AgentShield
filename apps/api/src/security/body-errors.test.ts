import { request as httpRequest } from "node:http";
import type { AddressInfo } from "node:net";
import { gzipSync } from "node:zlib";
import supertest from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AppDeps } from "../app.js";
import { createTestApp, request, TEST_API_TOKEN } from "../test-support.js";

/**
 * M3-E audit L2: request-body errors from express.json (body-parser) get a safe 4xx
 * response with fixed text; genuine internal errors stay 500. Nothing from the parser,
 * the body or a stack is returned or logged.
 */

let warnings: string[] = [];
beforeEach(() => {
  warnings = [];
  vi.spyOn(console, "warn").mockImplementation((line: unknown) => {
    warnings.push(String(line));
  });
});
afterEach(() => vi.restoreAllMocks());

/** Parser messages, request values and stack fragments that must never be echoed. */
const LEAKS = ["incorrect header check", "latin1", "x-unknown", "unsupported charset", "Unexpected", "SyntaxError", "    at ", "secret-body-marker"];

describe("M3-E audit L2: request-body errors (unauthenticated POST /api/evaluate)", () => {
  it.each([
    ["an unsupported charset", (r: supertest.Test) => r.set("Content-Type", "application/json; charset=latin1").send('{"m":"secret-body-marker"}'), 415, "Unsupported request body encoding.", "unsupported-body-encoding"],
    ["an unsupported Content-Encoding", (r: supertest.Test) => r.set("Content-Type", "application/json").set("Content-Encoding", "x-unknown").send('{"m":"secret-body-marker"}'), 415, "Unsupported request body encoding.", "unsupported-body-encoding"],
    ["malformed JSON", (r: supertest.Test) => r.set("Content-Type", "application/json").send('{"m":"secret-body-marker"'), 400, "Malformed JSON body.", "malformed-json"],
    ["a malformed gzip body", (r: supertest.Test) => r.set("Content-Type", "application/json").set("Content-Encoding", "gzip").send("secret-body-marker, not gzip"), 400, "Malformed request body.", "malformed-body"],
    ["a body over 32 KB", (r: supertest.Test) => r.set("Content-Type", "application/json").send(JSON.stringify({ m: "secret-body-marker".repeat(2000) })), 413, "Request body too large.", "body-too-large"],
  ])("%s gets a fixed 4xx response before authentication and leaks nothing", async (_label, build, status, message, category) => {
    const app = createTestApp();
    const res = await build(supertest(app).post("/api/evaluate"));
    expect([res.status, res.body]).toEqual([status, { error: message }]);
    expect(warnings).toEqual([`api-request status=${status} category=${category}`]);
    const everything = res.text + warnings.join("\n");
    for (const leak of LEAKS) expect(everything, leak).not.toContain(leak);
  });

  it("the same errors apply to an authenticated operator (parsing happens before authentication)", async () => {
    const app = createTestApp();
    const res = await request(app).post("/api/evaluate").set("Content-Type", "application/json; charset=latin1").send("{}");
    expect(res.status).toBe(415);
  });

  it("a valid gzip-compressed JSON body is still accepted", async () => {
    const app = createTestApp();
    const server = app.listen(0, "127.0.0.1");
    await new Promise<void>((resolve) => server.once("listening", () => resolve()));
    try {
      const { port } = server.address() as AddressInfo;
      const body = gzipSync(Buffer.from(JSON.stringify({ scenarioId: "benign-summary" })));
      const status = await new Promise<number>((resolve, reject) => {
        const req = httpRequest(
          { host: "127.0.0.1", port, method: "POST", path: "/api/evaluate", headers: { Authorization: `Bearer ${TEST_API_TOKEN}`, "Content-Type": "application/json", "Content-Encoding": "gzip", "Content-Length": body.length } },
          (res) => {
            res.resume();
            res.on("end", () => resolve(res.statusCode ?? 0));
          },
        );
        req.on("error", reject);
        req.end(body);
      });
      expect(status).toBe(200);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});

describe("M3-E audit L2: genuine internal errors are never reported as client errors", () => {
  const failing = (error: unknown) => ({ analyze: async () => Promise.reject(error) }) as unknown as AppDeps["modelService"];

  it.each([
    ["a plain Error", new Error("internal detail")],
    ["a SyntaxError raised inside the server", new SyntaxError("internal JSON detail")],
    ["an error that only claims a 4xx status (not exposed)", Object.assign(new Error("internal detail"), { status: 400 })],
    ["an error with a client-error type but nothing else", Object.assign(new Error("internal detail"), { type: "something.else" })],
  ])("%s stays 500 with fixed text", async (_label, error) => {
    const app = createTestApp({ modelService: failing(error) });
    const res = await request(app).post("/api/evaluate").send({ scenarioId: "benign-summary" });
    expect([res.status, res.body]).toEqual([500, { error: "Internal error." }]);
    expect(warnings).toEqual(["api-request status=internal-error category=unhandled"]);
    expect(res.text + warnings.join("\n")).not.toMatch(/internal (JSON )?detail/);
  });
});
