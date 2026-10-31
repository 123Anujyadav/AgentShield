import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import supertest from "supertest";
import { afterEach, beforeEach, describe, expect, it, vi, type MockInstance } from "vitest";
import type { ActivityEvent } from "@agentshield/engine";
import { createApp, type AppDeps } from "../app.js";
import { createTestApp, request, TEST_AGENT_ID, TEST_API_TOKEN } from "../test-support.js";
import { SESSION_COOKIE } from "./auth.js";
import { loadSecurityConfig, WEB_ORIGINS } from "./config.js";
import { hostnameOf } from "./request-guards.js";
import { API_TOKEN_FILE_NAME, defaultTokenDirectory, loadOrCreateApiToken } from "./token.js";

const WEB_ORIGIN = WEB_ORIGINS[0];
const BEARER = `Bearer ${TEST_API_TOKEN}`;
const MINUTE = 60_000;

/** A controllable clock for sessions and rate limits. */
function clock(start = 1_800_000_000_000) {
  let current = start;
  return { now: () => current, advance: (ms: number) => (current += ms) };
}

/** Every route registered on the app, as [method, path] pairs. */
function registeredRoutes(app: ReturnType<typeof createApp>): Array<[string, string]> {
  const stack = (app as unknown as { _router: { stack: Array<{ route?: { path: string; methods: Record<string, boolean> } }> } })._router.stack;
  return stack.flatMap((layer) =>
    layer.route ? Object.keys(layer.route.methods).map((method): [string, string] => [method, layer.route!.path]) : [],
  );
}

/** Signs in and returns the session cookie pair ("name=value"). */
async function login(app: ReturnType<typeof createApp>): Promise<string> {
  const res = await supertest(app).post("/api/session").set("Origin", WEB_ORIGIN).send({ token: TEST_API_TOKEN });
  expect(res.status).toBe(200);
  const cookie = String(res.headers["set-cookie"]?.[0] ?? "");
  return cookie.split(";")[0]!;
}

const benignEvaluate = { scenarioId: "benign-summary" };

describe("M0: Host header validation", () => {
  it("parses host names and ports strictly", () => {
    expect(hostnameOf("localhost:4000")).toBe("localhost");
    expect(hostnameOf("LOCALHOST")).toBe("localhost");
    expect(hostnameOf("127.0.0.1:4000")).toBe("127.0.0.1");
    expect(hostnameOf("[::1]:4000")).toBe("[::1]");
    for (const bad of [undefined, "", "localhost:", "localhost:abc", "localhost:123456", "[::1", "user@localhost", "local host", "localhost/x"]) {
      expect(hostnameOf(bad)).toBeNull();
    }
  });

  it("accepts the loopback names and refuses every other Host, including on /health", async () => {
    const app = createTestApp();
    for (const host of ["localhost:4000", "127.0.0.1:4000", "[::1]:4000", "localhost"]) {
      expect((await request(app).get("/api/events").set("Host", host)).status, host).toBe(200);
    }
    const hostile = ["evil.example", "evil.example:4000", "localhost.evil.example", "127.0.0.1.nip.io", "0.0.0.0:4000", "localhost:abc", "rebind.attacker.test:4000"];
    for (const host of hostile) {
      for (const path of ["/health", "/api/events", "/api/session"]) {
        const res = await request(app).get(path).set("Host", host);
        expect([res.status, res.body], `${host} ${path}`).toEqual([403, { error: "Host not allowed." }]);
        expect(JSON.stringify(res.body)).not.toContain(host.split(":")[0]);
      }
    }
    // A rebinding page cannot reach a write route either, even with a valid token.
    const write = await request(app).post("/api/evaluate").set("Host", "rebind.attacker.test").send({ agentId: TEST_AGENT_ID, ...benignEvaluate });
    expect(write.status).toBe(403);
  });
});

describe("M0: Origin and CORS", () => {
  it("refuses a foreign Origin on reads and writes; the web app's origins pass with credentialed CORS", async () => {
    const app = createTestApp();
    for (const origin of ["https://evil.example", "http://localhost:5174", "null"]) {
      expect((await request(app).get("/api/events").set("Origin", origin)).status, origin).toBe(403);
      expect((await request(app).post("/api/evaluate").set("Origin", origin).send({ agentId: TEST_AGENT_ID, ...benignEvaluate })).status, origin).toBe(403);
    }
    for (const origin of WEB_ORIGINS) {
      const res = await request(app).get("/api/events").set("Origin", origin);
      expect(res.status).toBe(200);
      expect(res.headers["access-control-allow-origin"]).toBe(origin);
      expect(res.headers["access-control-allow-credentials"]).toBe("true");
    }
    const preflight = await supertest(app)
      .options("/api/evaluate")
      .set("Origin", WEB_ORIGIN)
      .set("Access-Control-Request-Method", "POST")
      .set("Access-Control-Request-Headers", "content-type");
    expect(preflight.status).toBe(204);
    expect(preflight.headers["access-control-allow-credentials"]).toBe("true");
  });
});

describe("M0: authentication on every /api route", () => {
  it("every registered /api route except /api/session refuses missing or wrong credentials", async () => {
    const app = createTestApp();
    const protectedRoutes = registeredRoutes(app).filter(([, path]) => path.startsWith("/api/") && path !== "/api/session");
    // Guards against a vacuous pass: the routes that exist today are all listed.
    expect(protectedRoutes).toEqual(
      expect.arrayContaining([
        ["get", "/api/scenarios"],
        ["get", "/api/model/status"],
        ["get", "/api/events"],
        ["post", "/api/evaluate"],
        ["get", "/api/approvals"],
        ["post", "/api/approvals/:id/approve"],
        ["post", "/api/approvals/:id/reject"],
      ]),
    );
    const badCredentials: Array<Record<string, string>> = [
      {},
      { Authorization: "Bearer " },
      // Built at runtime so the source holds no credential-shaped literal for the secret scan.
      { Authorization: `Bearer ${"wrong-token-".repeat(4)}` },
      { Authorization: `Bearer ${TEST_API_TOKEN}x` },
      { Authorization: `Bearer ${TEST_API_TOKEN.slice(0, -1)}` },
      { Authorization: `bearer ${TEST_API_TOKEN}` },
      { Authorization: `Basic ${TEST_API_TOKEN}` },
      { Authorization: `Bearer ${TEST_API_TOKEN} extra` },
      { Cookie: `${SESSION_COOKIE}=forged-session-id` },
      // A wrong Authorization header does not fall back to a cookie.
      { Authorization: "Bearer wrong", Cookie: `${SESSION_COOKIE}=forged` },
    ];
    for (const [method, path] of protectedRoutes) {
      const url = path.replace(":id", "apr-1");
      for (const headers of badCredentials) {
        const test = (supertest(app) as unknown as Record<string, (u: string) => supertest.Test>)[method]!(url).set(headers);
        const res = await (method === "post" ? test.send({}) : test);
        expect([res.status, res.body], `${method} ${url} ${JSON.stringify(headers)}`).toEqual([401, { error: "Authentication required." }]);
        expect(res.headers["www-authenticate"]).toBe('Bearer realm="agentshield"');
        expect(JSON.stringify(res.body) + JSON.stringify(res.headers)).not.toContain(TEST_API_TOKEN);
      }
      const ok = (supertest(app) as unknown as Record<string, (u: string) => supertest.Test>)[method]!(url).set("Authorization", BEARER);
      expect((await (method === "post" ? ok.send(url.includes("approvals") ? {} : benignEvaluate) : ok)).status, `${method} ${url}`).not.toBe(401);
    }
  });

  it("future and unknown /api routes are protected by default; /health stays public", async () => {
    const app = createTestApp();
    expect((await supertest(app).get("/api/scans")).status).toBe(401);
    expect((await supertest(app).post("/api/scans").send({ url: "https://example.com" })).status).toBe(401);
    expect((await supertest(app).get("/health")).status).toBe(200);
  });

  it("without a configured token the API fails closed: nothing authenticates", async () => {
    const app = createApp();
    expect((await supertest(app).get("/api/events").set("Authorization", BEARER)).status).toBe(401);
    expect((await supertest(app).post("/api/session").send({ token: TEST_API_TOKEN })).status).toBe(401);
    expect(() => createApp({ apiToken: "too-short" })).toThrow(/at least 32 characters/);
  });
});

describe("M0: login and session cookie", () => {
  let warn: MockInstance;
  beforeEach(() => {
    warn = vi.spyOn(console, "warn").mockImplementation(() => {});
  });
  afterEach(() => {
    vi.restoreAllMocks();
  });

  function sessionApp(extra: AppDeps = {}) {
    const time = clock();
    return { app: createTestApp({ now: time.now, ...extra }), time };
  }

  it("a wrong or malformed token is refused with fixed messages and logged without the attempt", async () => {
    const { app } = sessionApp();
    const attempt = "WRONG_TOKEN_MARKER_7f3a-0123456789-0123456789";
    const wrong = await supertest(app).post("/api/session").send({ token: attempt });
    expect([wrong.status, wrong.body]).toEqual([401, { error: "Invalid token." }]);
    expect(wrong.headers["set-cookie"]).toBeUndefined();
    for (const body of [{}, { token: 42 }, { token: "" }, { token: "x".repeat(513) }, { token: ["a"] }]) {
      expect((await supertest(app).post("/api/session").send(body)).status, JSON.stringify(body).slice(0, 40)).toBe(400);
    }
    const logged = warn.mock.calls.flat().map(String).join("\n");
    expect(logged).toContain("api-auth status=login-failed");
    expect(logged).not.toContain(attempt);
  });

  it("a correct token sets an HttpOnly, SameSite=Strict, /api-scoped session cookie that never contains the token", async () => {
    const { app } = sessionApp();
    const res = await supertest(app).post("/api/session").set("Origin", WEB_ORIGIN).send({ token: TEST_API_TOKEN });
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ authenticated: true, method: "session" });
    const cookie = String(res.headers["set-cookie"]?.[0]);
    expect(cookie).toMatch(new RegExp(`^${SESSION_COOKIE}=[A-Za-z0-9_-]{43}; Path=/api; HttpOnly; SameSite=Strict; Max-Age=28800$`));
    expect(cookie + JSON.stringify(res.body)).not.toContain(TEST_API_TOKEN);

    const status = await supertest(app).get("/api/session").set("Cookie", cookie.split(";")[0]!);
    expect(status.body).toMatchObject({ authenticated: true, method: "session" });
    expect(JSON.stringify(status.body)).not.toContain(TEST_API_TOKEN);
    expect((await supertest(app).get("/api/session")).body).toEqual({ authenticated: false, method: null, expiresAt: null });
  });

  it("cookie-authenticated reads work; cookie-authenticated writes need the web app's Origin (CSRF)", async () => {
    const { app } = sessionApp();
    const cookie = await login(app);
    expect((await supertest(app).get("/api/events").set("Cookie", cookie)).status).toBe(200);
    expect((await supertest(app).post("/api/evaluate").set("Cookie", cookie).set("Origin", WEB_ORIGIN).send({ agentId: TEST_AGENT_ID, ...benignEvaluate })).status).toBe(200);
    const noOrigin = await supertest(app).post("/api/evaluate").set("Cookie", cookie).send({ agentId: TEST_AGENT_ID, ...benignEvaluate });
    expect([noOrigin.status, noOrigin.body]).toEqual([403, { error: "Origin not allowed." }]);
    expect((await supertest(app).post("/api/evaluate").set("Cookie", cookie).set("Origin", "https://evil.example").send({ agentId: TEST_AGENT_ID, ...benignEvaluate })).status).toBe(403);
    // Bearer clients (scripts, tests) do not need an Origin.
    expect((await supertest(app).post("/api/evaluate").set("Authorization", BEARER).send({ agentId: TEST_AGENT_ID, ...benignEvaluate })).status).toBe(200);
  });

  it("a session ends after 30 idle minutes, and after 8 hours however active it is", async () => {
    const { app, time } = sessionApp();
    const idle = await login(app);
    time.advance(29 * MINUTE);
    expect((await supertest(app).get("/api/events").set("Cookie", idle)).status).toBe(200);
    time.advance(30 * MINUTE);
    expect((await supertest(app).get("/api/events").set("Cookie", idle)).status).toBe(401);

    const active = await login(app);
    for (let elapsed = 0; elapsed < 8 * 60 - 10; elapsed += 10) {
      time.advance(10 * MINUTE);
      expect((await supertest(app).get("/api/session").set("Cookie", active)).body.authenticated).toBe(true);
    }
    time.advance(20 * MINUTE);
    expect((await supertest(app).get("/api/events").set("Cookie", active)).status).toBe(401);
  });

  it("logout ends the session and clears the cookie; a new login rotates the session id", async () => {
    const { app } = sessionApp();
    const first = await login(app);
    const second = await supertest(app).post("/api/session").set("Cookie", first).set("Origin", WEB_ORIGIN).send({ token: TEST_API_TOKEN });
    const rotated = String(second.headers["set-cookie"]?.[0]).split(";")[0]!;
    expect(rotated).not.toBe(first);
    expect((await supertest(app).get("/api/events").set("Cookie", first)).status).toBe(401);
    expect((await supertest(app).get("/api/events").set("Cookie", rotated)).status).toBe(200);

    const out = await supertest(app).delete("/api/session").set("Cookie", rotated).set("Origin", WEB_ORIGIN);
    expect(out.status).toBe(200);
    expect(String(out.headers["set-cookie"]?.[0])).toBe(`${SESSION_COOKIE}=; Path=/api; HttpOnly; SameSite=Strict; Max-Age=0`);
    expect((await supertest(app).get("/api/events").set("Cookie", rotated)).status).toBe(401);
  });

  it("at most 10 sessions exist; an 11th login ends the oldest", async () => {
    // A higher login limit, so the 10-per-minute default does not stop the 11th login first.
    const { app } = sessionApp({ security: { rateLimits: { ...loadSecurityConfig({}).rateLimits, session: 20 } } });
    const cookies: string[] = [];
    for (let i = 0; i < 11; i += 1) cookies.push(await login(app));
    expect((await supertest(app).get("/api/events").set("Cookie", cookies[0]!)).status).toBe(401);
    for (const cookie of cookies.slice(1)) expect((await supertest(app).get("/api/events").set("Cookie", cookie)).status).toBe(200);
  });
});

describe("M0: rate limits", () => {
  it("limits login attempts per minute, with Retry-After, and resets after the window", async () => {
    const time = clock();
    const app = createTestApp({ now: time.now });
    vi.spyOn(console, "warn").mockImplementation(() => {});
    for (let i = 0; i < 10; i += 1) expect((await supertest(app).post("/api/session").send({ token: `wrong-${i}` })).status).toBe(401);
    const limited = await supertest(app).post("/api/session").send({ token: TEST_API_TOKEN });
    expect([limited.status, limited.body]).toEqual([429, { error: "Too many requests. Try again later." }]);
    expect(Number(limited.headers["retry-after"])).toBeGreaterThanOrEqual(1);
    time.advance(MINUTE);
    expect((await supertest(app).post("/api/session").send({ token: TEST_API_TOKEN })).status).toBe(200);
    vi.restoreAllMocks();
  });

  it("limits evaluations and approval actions separately, and every /api request globally", async () => {
    const time = clock();
    const app = createTestApp({
      now: time.now,
      security: { rateLimits: { api: 1000, session: 10, evaluate: 3, approvalAction: 2 } },
    });
    for (let i = 0; i < 3; i += 1) expect((await request(app).post("/api/evaluate").send({ agentId: TEST_AGENT_ID, ...benignEvaluate })).status).toBe(200);
    expect((await request(app).post("/api/evaluate").send({ agentId: TEST_AGENT_ID, ...benignEvaluate })).status).toBe(429);
    // Reads are not affected by the evaluate limit.
    expect((await request(app).get("/api/events")).status).toBe(200);
    // approve and reject share one bucket.
    expect((await request(app).post("/api/approvals/apr-1/approve").send({})).status).toBe(404);
    expect((await request(app).post("/api/approvals/apr-1/reject").send({})).status).toBe(404);
    expect((await request(app).post("/api/approvals/apr-1/approve").send({})).status).toBe(429);
    time.advance(MINUTE);
    expect((await request(app).post("/api/evaluate").send({ agentId: TEST_AGENT_ID, ...benignEvaluate })).status).toBe(200);

    const global = createTestApp({ now: time.now, security: { rateLimits: { api: 5, session: 10, evaluate: 60, approvalAction: 60 } } });
    // Unauthenticated floods count too, before authentication runs.
    for (let i = 0; i < 5; i += 1) expect((await supertest(global).get("/api/events")).status).toBe(401);
    expect((await request(global).get("/api/events")).status).toBe(429);
    expect((await supertest(global).get("/health")).status).toBe(200);
  });

  it("settings are bounded and default safely", () => {
    const defaults = loadSecurityConfig({});
    expect(defaults).toMatchObject({
      maxEvents: 1000,
      rateLimits: { api: 600, session: 10, evaluate: 60, approvalAction: 60 },
      sessionAbsoluteMs: 8 * 60 * MINUTE,
      sessionIdleMs: 30 * MINUTE,
      maxSessions: 10,
    });
    const odd = loadSecurityConfig({
      API_MAX_EVENTS: "5",
      API_RATE_LIMIT_PER_MINUTE: "999999",
      API_LOGIN_RATE_LIMIT_PER_MINUTE: "ten",
      API_SESSION_IDLE_MINUTES: "",
      API_SESSION_MAX_MINUTES: "0",
    });
    expect(odd).toMatchObject({ maxEvents: 100, rateLimits: { api: 10_000, session: 10 }, sessionIdleMs: 30 * MINUTE, sessionAbsoluteMs: 5 * MINUTE });
  });
});

describe("M0: bounded event storage", () => {
  it("keeps only the newest events, newest first, and still redacts secret-shaped values", async () => {
    const events: ActivityEvent[] = [];
    const app = createTestApp({ events, security: { maxEvents: 5 } });
    for (let i = 0; i < 7; i += 1) await request(app).post("/api/evaluate").send({ agentId: TEST_AGENT_ID, ...benignEvaluate });
    const marker = "fakeBenchmarkDestEvent123456";
    await request(app)
      .post("/api/evaluate")
      .send({ agentId: TEST_AGENT_ID,
        intent: { task: "Summarize", allowedActions: ["create_summary"], deniedActions: ["create_summary"], allowedDestinations: [] },
        action: { type: "create_summary", tool: "simulated.workspace.createSummary", destination: `api_key=${marker}`, summary: "Create" },
      });
    expect(events).toHaveLength(5);
    const listed = (await request(app).get("/api/events")).body.events as ActivityEvent[];
    expect(listed.map((event) => event.id)).toEqual(["evt-8", "evt-7", "evt-6", "evt-5", "evt-4"]);
    expect(JSON.stringify(listed)).not.toContain(marker);
    expect(listed[0]?.destination).toContain("[REDACTED]");
  });
});

describe("M0: API token file", () => {
  let directory: string;
  beforeEach(() => {
    directory = mkdtempSync(join(tmpdir(), "agentshield-token-test-"));
  });
  afterEach(() => {
    rmSync(directory, { recursive: true, force: true });
  });

  it("creates a 256-bit base64url token once and then reuses it", () => {
    const tokenDir = join(directory, "AgentShield");
    const first = loadOrCreateApiToken(tokenDir);
    expect(first.created).toBe(true);
    expect(first.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(first.path).toBe(join(tokenDir, API_TOKEN_FILE_NAME));
    expect(readFileSync(first.path, "utf8")).toBe(first.token);
    const second = loadOrCreateApiToken(tokenDir);
    expect(second).toEqual({ token: first.token, path: first.path, created: false });
    expect(loadOrCreateApiToken(join(directory, "Other")).token).not.toBe(first.token);
  });

  it("refuses an invalid token file without overwriting it or echoing its content", () => {
    const path = join(directory, API_TOKEN_FILE_NAME);
    writeFileSync(path, "short CONTENT_MARKER_19c2");
    expect(() => loadOrCreateApiToken(directory)).toThrow(/does not hold a valid token/);
    try {
      loadOrCreateApiToken(directory);
    } catch (error) {
      expect(String(error)).not.toContain("CONTENT_MARKER_19c2");
    }
    expect(readFileSync(path, "utf8")).toBe("short CONTENT_MARKER_19c2");
  });

  it("defaults to the user's local application data folder, outside the repository", () => {
    expect(defaultTokenDirectory({ LOCALAPPDATA: join("C:", "Users", "someone", "AppData", "Local") })).toBe(
      join("C:", "Users", "someone", "AppData", "Local", "AgentShield"),
    );
    expect(defaultTokenDirectory({})).toContain("AgentShield");
  });
});
