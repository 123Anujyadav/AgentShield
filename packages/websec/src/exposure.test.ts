import { describe, expect, it, vi } from "vitest";
import {
  BASELINE_CHECK_ID,
  baselinePath,
  classifyBaseline,
  classifyExposureResponse,
  createExposureProbes,
  EXPOSURE_CHECK_IDS,
  EXPOSURE_PATHS,
  EXPOSURE_SUMMARIES,
  type BaselineState,
  type ExposurePath,
} from "./checks/exposure.js";
import { GuardedFetcher, PREFIX_RANGE_HEADER, RequestBudget, type FetchResult, type Resolver, type Transport, type TransportRequest } from "./fetcher.js";
import type { CheckResult } from "./findings.js";
import { PASSIVE_CHECKS, runPassiveScan, ScanStopped } from "./scan.js";
import { NOT_CHECKED_SUMMARIES, runProbeStage } from "./stages.js";
import { parseLabOrigin, type DnsTarget } from "./target.js";

/**
 * Exposure checks (M2-C). Every response comes from a fake transport serving
 * generated in-memory bodies; nothing touches the network. Credential-shaped
 * fixtures are assembled at runtime so no such literal is committed.
 */

const cryptoCalls = vi.hoisted(() => ({ randomBytes: [] as number[] }));
vi.mock("node:crypto", async (importOriginal) => {
  const actual = await importOriginal<typeof import("node:crypto")>();
  return {
    ...actual,
    randomBytes: (size: number) => {
      cryptoCalls.randomBytes.push(size);
      return actual.randomBytes(size);
    },
  };
});

const target: DnsTarget = { kind: "dns", hostname: "example.com", displayHostname: "example.com" };
const PUBLIC = [{ address: "93.184.215.14", family: 4 }];
const T0 = Date.parse("2026-10-30T00:00:00Z");
const BASELINE = "BASELINE";

// --- Fixtures --------------------------------------------------------------

const AWS_KEY = ["AKIA", "Z7Q4K2M9", "R5T8W3X6"].join("");
const DB_PASSWORD = ["Zx9Qw7", "Lm3Vb5", "Tr8Np2"].join("");
const GIT_CRED = ["deploy", ":", "Pw7", "Kq2", "Zr9"].join("");
const ENV_PLAIN = "APP_NAME=shopfront\nAPP_ENV=production\n# comment\nLOG_LEVEL=info\n";
const ENV_SECRETS = `APP_NAME=shopfront\nAWS_ACCESS_KEY_ID=${AWS_KEY}\nDB_PASSWORD=${DB_PASSWORD}\nMAIL_FROM=ops@shopfront.example\n`;
const GIT_CONFIG = `[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n[remote "origin"]\n\turl = https://${GIT_CRED}@git.example.net/acme/private-site.git\n`;
const APACHE_STATUS = [
  '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">',
  "<html><head>",
  "<title>Apache Status</title>",
  "</head><body>",
  "<h1>Apache Server Status for shop.example (via 10.20.30.40)</h1>",
  "<dl><dt>Server Version: Apache/2.4.58 (Ubuntu)</dt>",
  "<dt>Server MPM: event</dt></dl>",
  "<table><tr><td>203.0.113.77</td><td>GET /admin/payroll-export?id=42 HTTP/1.1</td></tr></table>",
  "</body></html>",
].join("\n");
const NGINX_STATUS = "Active connections: 291 \nserver accepts handled requests\n 16630948 16630948 31070465 \nReading: 6 Writing: 179 Waiting: 106 \n";
const DS_STORE = Buffer.concat([Buffer.from([0, 0, 0, 1, 0x42, 0x75, 0x64, 0x31]), Buffer.alloc(16), Buffer.from("payroll-2026.xlsx", "utf16le")]);
const ZIP = Buffer.concat([Buffer.from([0x50, 0x4b, 0x03, 0x04, 0x14, 0, 0, 0]), Buffer.from("customer-list.csv")]);
const EMPTY_ZIP = Buffer.concat([Buffer.from([0x50, 0x4b, 0x05, 0x06]), Buffer.alloc(18)]);
const GZIP = Buffer.concat([Buffer.from([0x1f, 0x8b, 0x08, 0x00, 0, 0, 0, 0, 0, 0x03]), Buffer.from("tarball-inner-name")]);
const MYSQL_DUMP = "-- MySQL dump 10.13  Distrib 8.0.36, for Linux (x86_64)\n--\n-- Host: localhost    Database: shopdb\nCREATE TABLE `customers` (`email` varchar(255));\nINSERT INTO `customers` VALUES ('alice@shop.example');\n";
const MARIADB_DUMP = "-- MariaDB dump 10.19  Distrib 10.11.6-MariaDB, for debian-linux-gnu (x86_64)\n--\n-- Host: db    Database: shopdb\n";
const POSTGRES_DUMP = "--\n-- PostgreSQL database dump\n--\n\n-- Dumped from database version 16.2\nSET statement_timeout = 0;\n";
const SQL_COMBO = "CREATE TABLE orders (id int, card_last4 char(4));\nINSERT INTO orders VALUES (1, '4242');\n";
const HTML_PAGE = (marker: string) => `<!DOCTYPE html><html><head><title>Shop</title></head><body><main>${marker}</main></body></html>`;

/** Every fixed path exposed, with a not-found baseline. */
const ALL_EXPOSED: Record<string, Reply> = {
  [BASELINE]: { status: 404, body: HTML_PAGE("Not found") },
  "/.git/HEAD": { status: 200, body: "ref: refs/heads/main\n" },
  "/.git/config": { status: 200, body: GIT_CONFIG },
  "/.env": { status: 200, body: ENV_SECRETS },
  "/.DS_Store": { status: 200, body: DS_STORE },
  "/server-status": { status: 200, body: APACHE_STATUS },
  "/backup.zip": { status: 200, body: ZIP },
  "/backup.tar.gz": { status: 200, body: GZIP },
  "/database.sql": { status: 200, body: MYSQL_DUMP },
  "/dump.sql": { status: 200, body: POSTGRES_DUMP },
};

/** Strings from the fixtures that must never appear in any result. */
const NEVER_IN_OUTPUT = [
  AWS_KEY,
  DB_PASSWORD,
  "AWS_ACCESS_KEY_ID",
  "DB_PASSWORD",
  "APP_NAME",
  "shopfront",
  "MAIL_FROM",
  GIT_CRED,
  "git.example.net",
  "private-site",
  "refs/heads/main",
  "10.20.30.40",
  "203.0.113.77",
  "payroll-export",
  "payroll-2026",
  "customer-list",
  "tarball-inner",
  "customers",
  "alice@shop.example",
  "shopdb",
  "statement_timeout",
  "16630948",
];

// --- Harness -----------------------------------------------------------------

type Reply =
  | { status: number; headers?: Record<string, string | string[]>; body?: string | Buffer; chunkSize?: number }
  | "hang"
  | "reset";

function body(content: string | Buffer | undefined, chunkSize = 1024): AsyncIterable<Uint8Array> | null {
  if (content === undefined) return null;
  const bytes = Buffer.isBuffer(content) ? content : Buffer.from(content);
  return (async function* () {
    for (let i = 0; i < bytes.length; i += chunkSize) yield new Uint8Array(bytes.subarray(i, i + chunkSize));
  })();
}

function site(routes: Record<string, Reply>, requests: TransportRequest[], onRequest?: (request: TransportRequest) => void): Transport {
  return async (request) => {
    requests.push(request);
    onRequest?.(request);
    const path = request.url.pathname;
    const reply = routes[path.startsWith("/agentshield-baseline-") ? BASELINE : path] ?? { status: 404, body: HTML_PAGE("Not found") };
    if (reply === "reset") throw new Error("connection reset");
    if (reply === "hang") {
      return new Promise((_resolve, reject) => request.signal.addEventListener("abort", () => reject(new Error("aborted")), { once: true }));
    }
    return { status: reply.status, headers: reply.headers ?? {}, body: body(reply.body, reply.chunkSize), tls: null, close: () => {} };
  };
}

async function runExposure(
  routes: Record<string, Reply>,
  options: { budget?: number; deadline?: number; resolver?: Resolver; signal?: AbortSignal; onRequest?: (r: TransportRequest) => void; clock?: { ms: number } } = {},
) {
  const requests: TransportRequest[] = [];
  const fetcher = new GuardedFetcher({ resolver: options.resolver ?? (async () => PUBLIC), transport: site(routes, requests, options.onRequest), timeoutMs: 40 });
  const budget = new RequestBudget(options.budget ?? 30);
  const clock = options.clock ?? { ms: T0 };
  const stage = await runProbeStage({
    probes: createExposureProbes(),
    deadline: options.deadline ?? T0 + 120_000,
    context: { target, fetcher, budget, signal: options.signal },
    now: () => clock.ms,
  });
  const byId = Object.fromEntries(stage.checks.map((c) => [c.checkId, c])) as Record<string, CheckResult>;
  const byPath = Object.fromEntries(EXPOSURE_PATHS.map((p, i) => [p, byId[EXPOSURE_CHECK_IDS[i]!]!])) as Record<ExposurePath, CheckResult>;
  return { stage, byId, byPath, requests, budget };
}

/** A successful prefix-mode fetch result, for direct classification. */
function fetched(status: number, content: string | Buffer, truncated = false, headers: Record<string, string[]> = {}): FetchResult {
  const bytes = Buffer.isBuffer(content) ? content : Buffer.from(content);
  return { ok: true, url: new URL("https://example.com/"), status, headers, body: null, tls: null, hops: [], prefix: { kind: "read", bytes, truncated } };
}
const NOT_FOUND: BaselineState = { kind: "not-found" };
const classify = (path: ExposurePath, content: string | Buffer, baseline: BaselineState = NOT_FOUND, truncated = false) =>
  classifyExposureResponse(path, fetched(200, content, truncated), baseline);
const isFinding = (check: CheckResult) => check.status === "fail" && check.findings.length === 1;

// --- A. Fixed path allowlist -----------------------------------------------------

describe("A. the fixed path allowlist", () => {
  it("is exactly the nine approved paths, in order, and frozen", () => {
    expect(EXPOSURE_PATHS).toEqual([
      "/.git/HEAD",
      "/.git/config",
      "/.env",
      "/.DS_Store",
      "/server-status",
      "/backup.zip",
      "/backup.tar.gz",
      "/database.sql",
      "/dump.sql",
    ]);
    expect(Object.isFrozen(EXPOSURE_PATHS)).toBe(true);
    expect(() => (EXPOSURE_PATHS as string[]).push("/admin")).toThrow();
  });

  it("takes no caller paths: the stage requests only the baseline and the nine paths, each once", async () => {
    expect(createExposureProbes.length).toBe(0);
    const { requests } = await runExposure({});
    const paths = requests.map((r) => r.url.pathname);
    expect(paths).toHaveLength(10);
    expect(paths[0]).toMatch(/^\/agentshield-baseline-[0-9a-f]{64}$/);
    expect(paths.slice(1)).toEqual([...EXPOSURE_PATHS]);
    expect(requests.every((r) => r.url.host === "example.com" && r.url.search === "" && r.method === "GET")).toBe(true);
  });

  it("the baseline path is separate from the allowlist, random and drawn from 32 CSPRNG bytes", () => {
    cryptoCalls.randomBytes.length = 0;
    const paths = Array.from({ length: 50 }, () => baselinePath());
    expect(new Set(paths).size).toBe(50);
    expect(paths.every((p) => /^\/agentshield-baseline-[0-9a-f]{64}$/.test(p) && !(EXPOSURE_PATHS as readonly string[]).includes(p))).toBe(true);
    expect(cryptoCalls.randomBytes).toEqual(Array(50).fill(32));
  });

  it("lab targets get the same fixed paths on the exact lab origin", async () => {
    const requests: TransportRequest[] = [];
    const fetcher = new GuardedFetcher({ resolver: async () => PUBLIC, transport: site({}, requests) });
    const lab = parseLabOrigin("http://127.0.0.1:8081")!;
    await runProbeStage({ probes: createExposureProbes(), deadline: T0 + 120_000, context: { target: lab, fetcher, budget: new RequestBudget(30) }, now: () => T0 });
    expect(requests.map((r) => r.url.origin)).toEqual(Array(10).fill("http://127.0.0.1:8081"));
    expect(requests.slice(1).map((r) => r.url.pathname)).toEqual([...EXPOSURE_PATHS]);
  });
});

// --- B. Positive signatures -------------------------------------------------------

describe("B. positive signatures (not-found baseline)", () => {
  it.each([
    ["/.git/HEAD", "ref: refs/heads/main\n", "high", "high"],
    ["/.git/HEAD", "ref: refs/heads/release/2026.10\n", "high", "high"],
    ["/.git/HEAD", "3f786850e387550fdab836ed7e6dc881de23001b\n", "high", "high"],
    ["/.git/HEAD", `${"0a1b2c3d".repeat(8)}\n`, "high", "high"],
    ["/.git/config", GIT_CONFIG, "high", "high"],
    ["/.env", ENV_PLAIN, "high", "medium"],
    ["/.env", ENV_SECRETS, "high", "high"],
    ["/.DS_Store", DS_STORE, "low", "high"],
    ["/server-status", APACHE_STATUS, "medium", "high"],
    ["/server-status", NGINX_STATUS, "medium", "high"],
    ["/backup.zip", ZIP, "high", "high"],
    ["/backup.zip", EMPTY_ZIP, "high", "high"],
    ["/backup.tar.gz", GZIP, "high", "high"],
    ["/database.sql", MYSQL_DUMP, "high", "high"],
    ["/dump.sql", MARIADB_DUMP, "high", "high"],
    ["/database.sql", POSTGRES_DUMP, "high", "high"],
    ["/dump.sql", SQL_COMBO, "high", "medium"],
  ] as Array<[ExposurePath, string | Buffer, string, string]>)("%s is reported for a matching body (case %#)", (path, content, severity, confidence) => {
    const check = classify(path, content);
    expect(isFinding(check)).toBe(true);
    expect(check.findings[0]).toMatchObject({ severity, confidence, checkId: check.checkId });
    expect(check.findings[0]!.evidence.startsWith(`${path}: `)).toBe(true);
  });

  it(".env is high, never critical, and reports secret kinds and counts only", () => {
    const plain = classify("/.env", ENV_PLAIN).findings[0]!;
    expect(plain.evidence).toBe("/.env: 3 assignments; no secret-shaped value recognized");
    const secret = classify("/.env", ENV_SECRETS).findings[0]!;
    expect(secret.severity).toBe("high");
    // The email address is not counted as a secret.
    expect(secret.evidence).toBe("/.env: 4 assignments; 2 secret-shaped (aws-access-key-id x1, labelled-secret-assignment x1)");
  });

  it("lists at most three secret kinds by name and counts the rest", () => {
    const gh = ["ghp", "_", "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"].join("");
    const google = ["AIza", "SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q"].join("");
    // Neutral names, so each value is judged by its own format: four different kinds.
    const lines = [`K1=${AWS_KEY}`, `K2=${gh}`, `K3=${google}`, `DB_PASSWORD=${DB_PASSWORD}`, `K5=${AWS_KEY}`];
    const evidence = classify("/.env", `${lines.join("\n")}\n`).findings[0]!.evidence;
    expect(evidence).toBe("/.env: 5 assignments; 5 secret-shaped (aws-access-key-id x2, github-token x1, google-api-key x1 +1 more)");
  });
});

// --- C. Negative signatures -------------------------------------------------------

describe("C. negative signatures", () => {
  it.each([
    ["/.git/HEAD", HTML_PAGE("ref: refs/heads/main")],
    ["/.git/HEAD", "ref: refs/heads/../../etc/passwd\n"],
    ["/.git/HEAD", "ref: heads/main\n"],
    ["/.git/HEAD", "ref: refs/heads/main\nextra line\n"],
    ["/.git/HEAD", "ref: refs/heads/.hidden\n"],
    ["/.git/HEAD", "ref: refs/heads/main.lock\n"],
    ["/.git/HEAD", "3f786850e387550fdab836ed7e6dc881de23001\n"],
    ["/.git/HEAD", "3F786850E387550FDAB836ED7E6DC881DE23001B\n"],
    ["/.git/config", "[core]\n\tfilemode = true\n"],
    ["/.git/config", "repositoryformatversion = 0\n"],
    ["/.git/config", HTML_PAGE("[core]\nrepositoryformatversion = 0")],
    ["/.git/config", "Set [core] repositoryformatversion = 0 in your config.\n"],
    ["/.env", HTML_PAGE("APP_NAME=shop\nAPP_ENV=prod")],
    // Mostly assignments, so only the HTML rule rejects these.
    ["/.env", "<!doctype html>\nA=1\nB=2\nC=3\nD=4\nE=5\n"],
    ["/.git/config", "<html>\n[core]\nrepositoryformatversion = 0\n</html>\n"],
    ["/database.sql", "<html>\n-- MySQL dump 10.13  Distrib 8.0.36\n</html>\n"],
    ["/.env", "Hello world\nThis is a readme.\nKEY=value\n"],
    ["/.env", "Install guide\nRun the app\nThen edit files\nSet A=1\nB=2\nC=3\n"],
    ["/.env", "KEY=value\n"],
    ["/.DS_Store", Buffer.from([0, 0, 0, 1, 0x42, 0x75, 0x64])],
    ["/.DS_Store", Buffer.from([0, 0, 0, 1, 0x42, 0x75, 0x64, 0x32, 0, 0])],
    ["/.DS_Store", "Bud1 is the .DS_Store magic\n"],
    ["/server-status", HTML_PAGE("Server Status: all systems operational. Active connections: 12")],
    ["/server-status", "Active connections: 5\n"],
    ["/server-status", `${NGINX_STATUS}extra: 1\n`],
    ["/server-status", "<html><head><title>Apache Status</title></head><body>Server Version: unknown</body></html>"],
    ["/backup.zip", Buffer.from([0x50, 0x4b, 0x01, 0x02, 0, 0])],
    ["/backup.zip", "PK is a word, not an archive\n"],
    ["/backup.tar.gz", Buffer.from([0x1f, 0x8b, 0x07, 0])],
    ["/backup.tar.gz", "plain text backup notes\n"],
    ["/database.sql", "-- MySQL\nselect 1;\n"],
    ["/database.sql", "-- MySQL dump\n"],
    ["/database.sql", "CREATE TABLE only_schema (id int);\n"],
    ["/dump.sql", "INSERT INTO t VALUES (1);\n"],
    ["/dump.sql", HTML_PAGE("Tutorial: CREATE TABLE t (id int); INSERT INTO t VALUES (1);")],
    ["/dump.sql", Buffer.concat([Buffer.from("-- MySQL dump 10.13\n"), Buffer.from([0, 1, 2])])],
  ] as Array<[ExposurePath, string | Buffer]>)("%s is not reported for a non-matching body (case %#)", (path, content) => {
    const check = classify(path, content);
    expect([check.status, check.summary, check.findings]).toEqual(["pass", EXPOSURE_SUMMARIES.noSignature, []]);
  });

  it("an empty 200 body is not exposure", () => {
    for (const path of EXPOSURE_PATHS) expect(classify(path, "").status).toBe("pass");
  });

  it("a catch-all site serving one HTML page everywhere produces no finding at all", async () => {
    const page = { status: 200, body: HTML_PAGE("Welcome to the shop") };
    const routes = Object.fromEntries([BASELINE, ...EXPOSURE_PATHS].map((p) => [p, page]));
    const { byId, byPath } = await runExposure(routes);
    expect(byId[BASELINE_CHECK_ID]).toMatchObject({ status: "pass", summary: EXPOSURE_SUMMARIES.baselineCatchAll });
    for (const path of EXPOSURE_PATHS) expect(byPath[path]).toMatchObject({ status: "pass", summary: EXPOSURE_SUMMARIES.likeBaseline, findings: [] });
  });

  it("soft-404 baseline matches: a near-identical catch-all page is not exposure", () => {
    const base = HTML_PAGE(`${"x".repeat(900)} request-id=1111`);
    const probe = HTML_PAGE(`${"x".repeat(900)} request-id=2222`);
    const check = classifyExposureResponse("/.env", fetched(200, probe), { kind: "catch-all", bytes: Buffer.from(base) });
    expect(check).toMatchObject({ status: "pass", summary: EXPOSURE_SUMMARIES.likeBaseline });
  });

  it("when a random path also matches the signature, the match is inconclusive, never a finding", () => {
    const baseline: BaselineState = { kind: "catch-all", bytes: Buffer.from("A=1\nB=2\nC=3\n") };
    const check = classifyExposureResponse("/.env", fetched(200, ENV_PLAIN), baseline);
    expect(check).toMatchObject({ status: "error", summary: EXPOSURE_SUMMARIES.baselineMatches, findings: [] });
  });

  it("a real file differing from a catch-all baseline is still reported", () => {
    const baseline: BaselineState = { kind: "catch-all", bytes: Buffer.from(HTML_PAGE("Welcome")) };
    expect(isFinding(classifyExposureResponse("/backup.zip", fetched(200, ZIP), baseline))).toBe(true);
  });
});

// --- D. Outcome handling ------------------------------------------------------------

describe("D. outcome handling", () => {
  const expectRow = (check: CheckResult, status: string, summary: string) => expect([check.status, check.summary, check.findings]).toEqual([status, summary, []]);

  it("404 and 410 are not exposed; 401 and 403 are not exposed (denied)", async () => {
    const { byPath } = await runExposure({
      "/.git/HEAD": { status: 404 },
      "/.git/config": { status: 410 },
      "/.env": { status: 401, body: ENV_SECRETS },
      "/.DS_Store": { status: 403, body: DS_STORE },
    });
    expectRow(byPath["/.git/HEAD"], "pass", EXPOSURE_SUMMARIES.notFound);
    expectRow(byPath["/.git/config"], "pass", EXPOSURE_SUMMARIES.notFound);
    expectRow(byPath["/.env"], "pass", EXPOSURE_SUMMARIES.denied);
    expectRow(byPath["/.DS_Store"], "pass", EXPOSURE_SUMMARIES.denied);
  });

  it("3xx (including 304) is inconclusive and never followed; 416 and 5xx are inconclusive", async () => {
    const { byPath, requests } = await runExposure({
      "/.git/HEAD": { status: 301, headers: { location: "/.git/HEAD/" }, body: "ref: refs/heads/main\n" },
      "/.git/config": { status: 302, headers: { location: "https://example.com/login" } },
      "/.env": { status: 304 },
      "/.DS_Store": { status: 307, headers: { location: "/" } },
      "/server-status": { status: 416, headers: { "content-range": "bytes */0" } },
      "/backup.zip": { status: 500, body: ZIP },
      "/backup.tar.gz": { status: 503, body: GZIP },
    });
    for (const path of ["/.git/HEAD", "/.git/config", "/.env", "/.DS_Store"] as const) expectRow(byPath[path], "error", EXPOSURE_SUMMARIES.redirect);
    expectRow(byPath["/server-status"], "error", EXPOSURE_SUMMARIES.rangeNotSatisfiable);
    expectRow(byPath["/backup.zip"], "error", EXPOSURE_SUMMARIES.serverError);
    expectRow(byPath["/backup.tar.gz"], "error", EXPOSURE_SUMMARIES.serverError);
    expect(requests).toHaveLength(10); // no redirect hop was requested
    expect(requests.some((r) => r.url.pathname === "/login" || r.url.pathname === "/.git/HEAD/")).toBe(false);
  });

  it("other statuses (204, 400, 429) are inconclusive", () => {
    for (const status of [204, 400, 429]) {
      expect(classifyExposureResponse("/.env", fetched(status, ENV_PLAIN), NOT_FOUND)).toMatchObject({ status: "error", summary: EXPOSURE_SUMMARIES.unexpectedStatus });
    }
  });

  it("a timeout and a connection error are inconclusive, and later probes still run", async () => {
    const { byPath, requests } = await runExposure({ "/.git/HEAD": "hang", "/.git/config": "reset", "/.env": { status: 200, body: ENV_PLAIN } });
    expectRow(byPath["/.git/HEAD"], "error", EXPOSURE_SUMMARIES.timeout);
    expectRow(byPath["/.git/config"], "error", EXPOSURE_SUMMARIES.failed);
    expect(isFinding(byPath["/.env"])).toBe(true);
    expect(requests).toHaveLength(10);
  });

  it("an encoded (compressed) response is inconclusive even when its bytes match", async () => {
    const { byPath } = await runExposure({
      "/backup.tar.gz": { status: 200, headers: { "content-encoding": "gzip" }, body: GZIP },
      "/.env": { status: 200, headers: { "content-encoding": "br" }, body: ENV_SECRETS },
    });
    expectRow(byPath["/backup.tar.gz"], "error", EXPOSURE_SUMMARIES.encoded);
    expectRow(byPath["/.env"], "error", EXPOSURE_SUMMARIES.encoded);
  });

  it.each([
    ["a timed-out baseline", "hang" as Reply, EXPOSURE_SUMMARIES.baselineUnavailable],
    ["a failed baseline", "reset" as Reply, EXPOSURE_SUMMARIES.baselineUnavailable],
    ["a redirecting baseline", { status: 302, headers: { location: "/" } } as Reply, EXPOSURE_SUMMARIES.baselineUnavailable],
    ["a server-error baseline", { status: 500 } as Reply, EXPOSURE_SUMMARIES.baselineUnavailable],
    ["an encoded baseline", { status: 200, headers: { "content-encoding": "gzip" }, body: "x" } as Reply, EXPOSURE_SUMMARIES.baselineUnavailable],
    ["a 416 baseline", { status: 416 } as Reply, EXPOSURE_SUMMARIES.baselineUnavailable],
    ["a forbidden baseline", { status: 403, body: HTML_PAGE("Forbidden") } as Reply, EXPOSURE_SUMMARIES.baselineAmbiguous],
    ["an unauthorized baseline", { status: 401 } as Reply, EXPOSURE_SUMMARIES.baselineAmbiguous],
    ["an empty 200 baseline", { status: 200, body: "" } as Reply, EXPOSURE_SUMMARIES.baselineAmbiguous],
  ])("with %s, signature matches are inconclusive, not findings; misses and 404s still pass", async (_label, baselineReply, baselineSummary) => {
    const { byId, byPath } = await runExposure({ ...ALL_EXPOSED, [BASELINE]: baselineReply, "/dump.sql": { status: 404 }, "/database.sql": { status: 200, body: "hello\n" } });
    expect(byId[BASELINE_CHECK_ID]).toMatchObject({ status: "error", summary: baselineSummary, findings: [] });
    for (const path of EXPOSURE_PATHS.slice(0, 7)) expectRow(byPath[path], "error", EXPOSURE_SUMMARIES.baselineUnknown);
    expectRow(byPath["/database.sql"], "pass", EXPOSURE_SUMMARIES.noSignature);
    expectRow(byPath["/dump.sql"], "pass", EXPOSURE_SUMMARIES.notFound);
  });

  it("truncated responses: whole-file signatures are not established; leading signatures still are", async () => {
    const pad = "x".repeat(6000);
    const { byPath } = await runExposure({
      "/.git/HEAD": { status: 200, body: `ref: refs/heads/main\n${pad}` },
      "/server-status": { status: 200, body: `${NGINX_STATUS}${pad}` },
      "/backup.zip": { status: 200, body: Buffer.concat([ZIP, Buffer.alloc(100_000, 7)]) },
      // The secret sits on the line cut off at 4 KB, so it is not counted.
      "/.env": { status: 200, body: `A=1\nB=2\nPAD=${"C".repeat(4066)}\nTOKEN=${AWS_KEY}\n` },
    });
    expectRow(byPath["/.git/HEAD"], "pass", EXPOSURE_SUMMARIES.noSignature);
    expectRow(byPath["/server-status"], "pass", EXPOSURE_SUMMARIES.noSignature);
    expect(isFinding(byPath["/backup.zip"])).toBe(true);
    expect(byPath["/.env"].findings[0]?.evidence).toBe("/.env: 3 assignments; no secret-shaped value recognized");
  });

  it("a whole-file signature whose first 4 KB match exactly is still not trusted when the body goes on", async () => {
    // Everything after the signature within 4 KB is whitespace (removed by trimming); what follows is unknown.
    const tail = `${" ".repeat(6000)}<html>catch-all</html>`;
    const { byPath } = await runExposure({
      "/.git/HEAD": { status: 200, body: `ref: refs/heads/main\n${tail}` },
      "/server-status": { status: 200, body: `${NGINX_STATUS}${tail}` },
    });
    expectRow(byPath["/.git/HEAD"], "pass", EXPOSURE_SUMMARIES.noSignature);
    expectRow(byPath["/server-status"], "pass", EXPOSURE_SUMMARIES.noSignature);
  });

  it("classifyBaseline maps every outcome to a fixed state and summary", () => {
    expect(classifyBaseline(fetched(404, "nope")).state).toEqual({ kind: "not-found" });
    expect(classifyBaseline(fetched(410, "")).state).toEqual({ kind: "not-found" });
    expect(classifyBaseline(fetched(206, "page")).state.kind).toBe("catch-all");
    expect(classifyBaseline({ ok: false, reason: "timeout", url: new URL("https://example.com/"), hops: [] }).state).toEqual({ kind: "unavailable" });
    expect(classifyBaseline({ ok: false, reason: "request-budget-exceeded", url: new URL("https://example.com/"), hops: [] }).check.summary).toBe(
      NOT_CHECKED_SUMMARIES["request-budget"],
    );
  });
});

// --- E. Safety and redaction ------------------------------------------------------------

const FIXED_SUMMARIES = new Set<string>([...Object.values(EXPOSURE_SUMMARIES), ...Object.values(NOT_CHECKED_SUMMARIES), "1 finding(s)"]);

describe("E. safety and redaction", () => {
  it("findings for a fully exposed site carry no names, values, URLs, addresses, SQL, archive or file contents", async () => {
    const { stage, byPath } = await runExposure(ALL_EXPOSED);
    for (const path of EXPOSURE_PATHS) expect(isFinding(byPath[path]), path).toBe(true);
    const serialized = JSON.stringify(stage);
    for (const secret of NEVER_IN_OUTPUT) expect(serialized, secret).not.toContain(secret);
  });

  it("every summary is fixed text and every evidence string is a fixed template", async () => {
    const runs = [
      await runExposure(ALL_EXPOSED),
      await runExposure({ ...ALL_EXPOSED, [BASELINE]: { status: 200, body: HTML_PAGE("<b>target-controlled</b>") } }),
      await runExposure({ "/.env": "hang", "/.git/HEAD": { status: 302, headers: { location: "/<script>" } } }),
    ];
    for (const { stage } of runs) {
      for (const check of stage.checks) {
        expect(FIXED_SUMMARIES.has(check.summary), check.summary).toBe(true);
        for (const finding of check.findings) {
          expect(finding.evidence).not.toMatch(/[<>"'`]|https?:/);
          expect(finding.evidence.length).toBeLessThanOrEqual(160);
        }
      }
      expect(JSON.stringify(stage)).not.toContain("target-controlled");
    }
  });

  it("secret evidence is kinds and counts only", () => {
    const evidence = classify("/.env", ENV_SECRETS).findings[0]!.evidence;
    expect(evidence).toMatch(/^\/\.env: \d+ assignments; \d+ secret-shaped \([a-z0-9-]+ x\d+(, [a-z0-9-]+ x\d+)*\)$/);
  });

  it("the Git remote URL and its credentials never appear", () => {
    const serialized = JSON.stringify(classify("/.git/config", GIT_CONFIG));
    // ("remote" itself appears in the fixed explanation text; the file's own lines never do.)
    for (const fragment of [GIT_CRED, "git.example.net", "acme", "[remote", "origin", "url =", "filemode"]) expect(serialized).not.toContain(fragment);
  });

  it("server-status addresses and request URLs never appear", () => {
    const serialized = JSON.stringify([classify("/server-status", APACHE_STATUS), classify("/server-status", NGINX_STATUS)]);
    for (const fragment of ["203.0.113.77", "10.20.30.40", "/admin", "payroll", "Apache/2.4", "291", "31070465"]) expect(serialized).not.toContain(fragment);
  });

  it("baseline bytes are never in any result, including when the baseline is a catch-all", async () => {
    const sentinel = "BASELINE-SENTINEL-7f3a";
    const { stage } = await runExposure({ ...ALL_EXPOSED, [BASELINE]: { status: 200, body: HTML_PAGE(sentinel) } });
    expect(JSON.stringify(stage)).not.toContain(sentinel);
    expect(stage.checks.filter(isFinding)).toHaveLength(9);
  });
});

// --- F. Scheduler integration -----------------------------------------------------------

describe("F. scheduler integration", () => {
  it("plans the baseline plus nine probes, each allowed exactly one request", () => {
    const probes = createExposureProbes();
    expect(probes.map((p) => p.checkId)).toEqual([BASELINE_CHECK_ID, ...EXPOSURE_CHECK_IDS]);
    expect(probes.map((p) => p.maxRequests)).toEqual(Array(10).fill(1));
  });

  it("the baseline request counts against the budget: 10 requests in all, every one in prefix mode", async () => {
    const { budget, requests } = await runExposure({});
    expect(budget.spent).toBe(10);
    expect(requests.map((r) => r.headers.range)).toEqual(Array(10).fill(PREFIX_RANGE_HEADER));
  });

  it("budget exhaustion stops later probes, which are not checked (never pass)", async () => {
    const { byId, byPath, requests, stage } = await runExposure(ALL_EXPOSED, { budget: 4 });
    expect(requests).toHaveLength(4);
    expect(byId[BASELINE_CHECK_ID]!.status).toBe("pass");
    for (const path of EXPOSURE_PATHS.slice(0, 3)) expect(isFinding(byPath[path])).toBe(true);
    for (const path of EXPOSURE_PATHS.slice(3)) expect(byPath[path]).toMatchObject({ status: "error", summary: NOT_CHECKED_SUMMARIES["request-budget"] });
    expect(stage.stoppedEarly).toBe("request-budget");
  });

  it("time exhaustion stops later probes; finished results are kept", async () => {
    const clock = { ms: T0 };
    // 15 s per request; 85 s available; a probe needs 20 s left to start.
    const { requests, byPath, stage } = await runExposure(ALL_EXPOSED, { clock, deadline: T0 + 85_000, onRequest: () => (clock.ms += 15_000) });
    expect(requests).toHaveLength(5); // baseline + 4 probes (the fifth would start with 10 s left)
    for (const path of EXPOSURE_PATHS.slice(0, 4)) expect(isFinding(byPath[path])).toBe(true);
    for (const path of EXPOSURE_PATHS.slice(4)) expect(byPath[path]).toMatchObject({ status: "error", summary: NOT_CHECKED_SUMMARIES["time-limit"] });
    expect(stage.stoppedEarly).toBe("time-limit");
  });

  it("a probe interrupted by the time limit is never trusted, even when its body matched", async () => {
    const controller = new AbortController();
    const { byPath } = await runExposure(ALL_EXPOSED, {
      signal: controller.signal,
      onRequest: (r) => {
        if (r.url.pathname === "/.env") controller.abort(new DOMException("The scan reached its time limit.", "TimeoutError"));
      },
    });
    expect(isFinding(byPath["/.git/config"])).toBe(true);
    for (const path of EXPOSURE_PATHS.slice(2)) expect(byPath[path]).toMatchObject({ status: "error", summary: NOT_CHECKED_SUMMARIES["time-limit"], findings: [] });
  });

  it("an interrupted baseline leaves every probe not checked", async () => {
    const controller = new AbortController();
    const { byId, requests } = await runExposure(ALL_EXPOSED, { signal: controller.signal, onRequest: () => controller.abort() });
    expect(requests).toHaveLength(1);
    expect(Object.values(byId).every((c) => c.status === "error" && c.summary === NOT_CHECKED_SUMMARIES.stopped)).toBe(true);
  });

  it("a safety refusal mid-stage still stops the whole scan (M1 policy)", async () => {
    let lookups = 0;
    const resolver: Resolver = async () => (++lookups <= 3 ? PUBLIC : [{ address: "169.254.169.254", family: 4 }]);
    await expect(runExposure(ALL_EXPOSED, { resolver })).rejects.toBeInstanceOf(ScanStopped);
  });

  it("with the passive scan: M1 results first and without Range, then the exposure rows; 13 requests", async () => {
    const requests: TransportRequest[] = [];
    const fetcher = new GuardedFetcher({ resolver: async () => PUBLIC, transport: site(ALL_EXPOSED, requests) });
    const scan = await runPassiveScan({
      target,
      fetcher,
      budget: new RequestBudget(30),
      now: () => new Date(T0),
      probeStage: { probes: createExposureProbes(), deadline: T0 + 120_000 },
    });
    expect(scan.checks.slice(0, PASSIVE_CHECKS.length).map((c) => c.checkId)).not.toContain(BASELINE_CHECK_ID);
    expect(scan.checks.slice(PASSIVE_CHECKS.length).map((c) => c.checkId)).toEqual([BASELINE_CHECK_ID, ...EXPOSURE_CHECK_IDS]);
    expect([scan.requestsUsed, scan.probesStoppedEarly]).toEqual([13, null]);
    expect(requests.slice(0, 3).every((r) => r.headers.range === undefined)).toBe(true);
    expect(requests.slice(3).every((r) => r.headers.range === PREFIX_RANGE_HEADER)).toBe(true);
  });
});
