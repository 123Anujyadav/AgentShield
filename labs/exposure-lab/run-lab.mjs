#!/usr/bin/env node
/**
 * AgentShield exposure-check lab (M2-F): isolated, loopback only.
 *
 * Run from the repository root after `npm run build`:
 *   node labs/exposure-lab/run-lab.mjs [path/to/results.json]
 *
 * What it does, all inside this one process:
 * - installs guards first: listen() may bind only 127.0.0.1, every outgoing
 *   socket must go to 127.0.0.1, and every DNS call is refused and recorded;
 * - starts three fixture servers on 127.0.0.1:8081-8083 (good, bad, variants);
 * - builds isolated API instances from the compiled app with a synthetic
 *   configuration object (lab mode, and SCAN_EXPOSURE_ENABLED only where a
 *   scenario needs it). It never reads .env and never changes process.env;
 * - runs the scenarios over loopback HTTP, then stops every server.
 *
 * Output is check names with PASS/FAIL and counts only; no fixture body,
 * finding evidence or token is printed. Exit code 0 only when every check passes.
 */
import dns from "node:dns";
import http from "node:http";
import net from "node:net";
import { randomBytes } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { gzipSync } from "node:zlib";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = join(HERE, "..", "..");
const LOOPBACK = "127.0.0.1";
const PORTS = { good: 8081, bad: 8082, variants: 8083 };
const ORIGIN = Object.fromEntries(Object.entries(PORTS).map(([name, port]) => [name, `http://${LOOPBACK}:${port}`]));
const LAB_PORTS = new Set(Object.values(PORTS));

// ---------------------------------------------------------------------------
// Guards, installed before any application module is loaded.

const violations = [];
const bindings = [];
const outbound = [];
const dnsCalls = [];

const realListen = net.Server.prototype.listen;
net.Server.prototype.listen = function guardedListen(...args) {
  const options = typeof args[0] === "object" && args[0] !== null ? args[0] : { port: args[0], host: typeof args[1] === "string" ? args[1] : undefined };
  if (options.host !== LOOPBACK || options.path !== undefined) {
    violations.push(`refused bind to ${String(options.host ?? "all interfaces")}`);
    throw new Error("lab guard: services may bind 127.0.0.1 only");
  }
  return realListen.apply(this, args);
};

const realConnect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function guardedConnect(...args) {
  const first = Array.isArray(args[0]) ? args[0][0] : args[0];
  const isObject = typeof first === "object" && first !== null;
  const host = isObject ? first.host : typeof args[1] === "string" ? args[1] : undefined;
  const port = isObject ? first.port : first;
  // An IPC pipe has a path and no port (HTTP requests also carry their URL path here).
  const ipc = isObject && first.path !== undefined && (first.port === undefined || first.port === null);
  outbound.push({ host: String(host), port: Number(port) });
  if (ipc || host !== LOOPBACK) {
    violations.push(`refused connection to ${String(host)}:${String(port)}`);
    throw new Error("lab guard: connections may go to 127.0.0.1 only");
  }
  return realConnect.apply(this, args);
};

// Node's listen() passes even an IP literal through dns.lookup; resolving the literal
// 127.0.0.1 is answered locally (no DNS query), so exactly that one value is let through.
const literalLookups = [];
const realLookup = dns.lookup;
for (const name of ["lookup", "resolve", "resolve4", "resolve6", "resolveTxt", "resolveAny", "resolveCname"]) {
  dns[name] = (...args) => {
    if (name === "lookup" && args[0] === LOOPBACK) {
      literalLookups.push(args[0]);
      return realLookup.apply(dns, args);
    }
    dnsCalls.push(name);
    const callback = args.at(-1);
    if (typeof callback === "function") process.nextTick(callback, Object.assign(new Error("lab guard: DNS refused"), { code: "EREFUSED" }));
  };
  dns.promises[name] = async () => {
    dnsCalls.push(`promises.${name}`);
    throw Object.assign(new Error("lab guard: DNS refused"), { code: "EREFUSED" });
  };
}

// ---------------------------------------------------------------------------
// Checks and output (names and counts only).

const results = [];
function check(name, ok, detail = "") {
  results.push({ name, ok: Boolean(ok), detail });
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? `  [${detail}]` : ""}`);
}
const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/** Every response body the API returned, kept in memory for the redaction search. */
const apiOutputs = [];

// The process environment must not carry scanner or model switches.
const switchNames = () => Object.keys(process.env).filter((key) => /^(SCAN_|MODEL_)/i.test(key));
check("process environment has no SCAN_* or MODEL_* variables before the run", switchNames().length === 0, `${switchNames().length} found`);

const imp = (relative) => import(pathToFileURL(join(ROOT, relative)).href);
const websec = await imp("packages/websec/dist/index.js");
const { createApp } = await imp("apps/api/dist/app.js");
const { ScanService } = await imp("apps/api/dist/scans/service.js");
const { loadScanConfig } = await imp("apps/api/dist/scans/config.js");
const { loadModelConfig } = await imp("apps/api/dist/model/config.js");

// ---------------------------------------------------------------------------
// Fixtures.

const FIX = (path) => readFileSync(join(HERE, "fixtures", path));
const M1_SITE = readFileSync(join(ROOT, "labs", "passive-scan", "site", "index.html"));
const M1_SECURITY_TXT = readFileSync(join(ROOT, "labs", "passive-scan", "security", "security.txt"));
const BAD = {
  "/.git/HEAD": [FIX("bad/git-HEAD"), "text/plain"],
  "/.git/config": [FIX("bad/git-config"), "text/plain"],
  "/.env": [FIX("bad/env"), "text/plain"],
  "/.DS_Store": [FIX("bad/DS_Store.bin"), "application/octet-stream"],
  "/server-status": [FIX("bad/apache-status.html"), "text/html"],
  "/backup.zip": [FIX("bad/backup.zip"), "application/zip"],
  "/backup.tar.gz": [FIX("bad/backup.tar.gz"), "application/gzip"],
  "/database.sql": [FIX("bad/database.sql"), "application/sql"],
  "/dump.sql": [FIX("bad/dump.sql"), "application/sql"],
};
check("binary fixtures carry the exact signatures", FIX("bad/DS_Store.bin").subarray(0, 8).equals(Buffer.from([0, 0, 0, 1, 0x42, 0x75, 0x64, 0x31])) && FIX("bad/backup.zip").subarray(0, 4).equals(Buffer.from("PK\x05\x06", "latin1")) && FIX("bad/backup.tar.gz").subarray(0, 3).equals(Buffer.from([0x1f, 0x8b, 0x08])));

// Header sets copied from labs/passive-scan/nginx/good.conf and bad.conf.
const GOOD_HEADERS = {
  server: "nginx",
  "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
  "x-content-type-options": "nosniff",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "camera=(), microphone=(), geolocation=()",
  "set-cookie": "lab_session=demo; Path=/; HttpOnly; SameSite=Lax",
};
const BAD_HEADERS = {
  server: "nginx/1.27.0",
  "x-powered-by": "PHP/7.4.3",
  "content-security-policy": "default-src * 'unsafe-inline'",
  "x-frame-options": "ALLOW-FROM https://example.com",
  "referrer-policy": "unsafe-url",
  "permissions-policy": "camera 'none'",
  "access-control-allow-origin": "*",
  "access-control-allow-credentials": "true",
  "set-cookie": "lab_session=demo; Path=/",
};
const NOT_FOUND_PAGE = Buffer.from("<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center></body></html>\n");

// ---------------------------------------------------------------------------
// Fixture servers.

const serverLog = [];

function send(req, res, entry, status, body = Buffer.alloc(0), headers = {}, honorRange = true) {
  const range = honorRange && status === 200 ? /^bytes=(\d+)-(\d*)$/.exec(req.headers.range ?? "") : null;
  if (range && body.length > 0) {
    const start = Number(range[1]);
    const end = Math.min(range[2] === "" ? body.length - 1 : Number(range[2]), body.length - 1);
    if (start >= body.length) {
      entry.status = 416;
      res.writeHead(416, { ...headers, "content-range": `bytes */${body.length}` });
      res.end();
      return;
    }
    entry.status = 206;
    res.writeHead(206, { ...headers, "content-range": `bytes ${start}-${end}/${body.length}`, "content-length": end - start + 1 });
    res.end(body.subarray(start, end + 1));
    return;
  }
  entry.status = status;
  res.writeHead(status, { ...headers, "content-length": body.length });
  res.end(body);
}

/** A large body that ignores Range; records how much was queued and whether the client hung up first. */
function stream(res, entry, head, total, headers) {
  entry.status = 200;
  entry.streamTotal = total;
  let sent = 0;
  res.writeHead(200, { ...headers, "content-length": total });
  res.on("close", () => {
    entry.bytesQueued = sent;
    entry.closedEarly = !res.writableFinished;
  });
  const filler = Buffer.alloc(16_384, 0x41);
  const pump = () => {
    while (sent < total && !res.destroyed) {
      const chunk = sent === 0 ? Buffer.concat([head, filler]).subarray(0, 16_384) : filler;
      const ok = res.write(chunk.subarray(0, Math.min(chunk.length, total - sent)));
      sent += Math.min(chunk.length, total - sent);
      if (!ok) {
        res.once("drain", pump);
        return;
      }
    }
    if (!res.destroyed) res.end();
  };
  pump();
}

const pathOf = (req) => new URL(req.url, "http://lab.invalid").pathname;
const isBaselinePath = (path) => path.startsWith("/agentshield-baseline-");

function goodRoute(req, res, entry) {
  const path = entry.path;
  const h = GOOD_HEADERS;
  if (path === "/") return send(req, res, entry, 200, M1_SITE, { ...h, "content-type": "text/html" });
  if (path === "/.well-known/security.txt") return send(req, res, entry, 200, M1_SECURITY_TXT, { ...h, "content-type": "text/plain" });
  if (path === "/server-status") return send(req, res, entry, 200, FIX("good/status.html"), { ...h, "content-type": "text/html" });
  if (path === "/.env") return send(req, res, entry, 200, FIX("good/env-readme.txt"), { ...h, "content-type": "text/plain" });
  if (path === "/backup.zip") return send(req, res, entry, 410, Buffer.from("Gone\n"), { ...h, "content-type": "text/plain" });
  if (path === "/.git/config") return send(req, res, entry, 403, Buffer.from("Forbidden\n"), { ...h, "content-type": "text/plain" });
  return send(req, res, entry, 404, NOT_FOUND_PAGE, { ...h, "content-type": "text/html" });
}

function badRoute(req, res, entry) {
  const path = entry.path;
  const h = BAD_HEADERS;
  if (path === "/") return send(req, res, entry, 200, M1_SITE, { ...h, "content-type": "text/html" });
  const file = BAD[path];
  if (file) return send(req, res, entry, 200, file[0], { ...h, "content-type": file[1] });
  return send(req, res, entry, 404, NOT_FOUND_PAGE, { ...h, "content-type": "text/html" });
}

let scenario = "nginx";
const MB2 = 2 * 1024 * 1024;
function variantsRoute(req, res, entry) {
  entry.scenario = scenario;
  const path = entry.path;
  const html = { "content-type": "text/html" };
  const text = { "content-type": "text/plain" };
  const catchAll = () => send(req, res, entry, 200, FIX("variants/catch-all.html"), html);
  const notFound = () => send(req, res, entry, 404, NOT_FOUND_PAGE, html);
  const root = () => send(req, res, entry, 200, M1_SITE, html);
  switch (scenario) {
    case "nginx":
      if (path === "/") return root();
      if (path === "/server-status") return send(req, res, entry, 200, FIX("variants/nginx-stub-status.txt"), text);
      return notFound();
    case "generic-active":
      if (path === "/") return root();
      if (path === "/server-status") return send(req, res, entry, 200, FIX("variants/generic-active-connections.txt"), text);
      return notFound();
    case "catch-all":
      return catchAll();
    case "catch-all-real-env":
      if (path === "/.env") return send(req, res, entry, 200, BAD["/.env"][0], text);
      return catchAll();
    case "ambiguous":
      if (path === "/") return root();
      if (BAD[path]) return send(req, res, entry, 200, BAD[path][0], { "content-type": BAD[path][1] });
      return send(req, res, entry, 403, Buffer.from("Forbidden\n"), text);
    case "transport":
      if (path === "/") return root();
      if (path === "/backup.zip") return stream(res, entry, Buffer.from([0x50, 0x4b, 0x03, 0x04]), MB2, { "content-type": "application/zip" });
      if (path === "/database.sql") return stream(res, entry, Buffer.from("-- MySQL dump 10.13  Distrib 8.0.0, for lab\n"), MB2, { "content-type": "application/sql" });
      if (path === "/.env") return send(req, res, entry, 200, gzipSync(BAD["/.env"][0]), { ...text, "content-encoding": "gzip" }, false);
      if (path === "/.git/HEAD") return send(req, res, entry, 302, Buffer.alloc(0), { location: "/lab-redirect-target" });
      if (path === "/.git/config") return send(req, res, entry, 301, Buffer.alloc(0), { location: "http://192.0.2.1/lab-external-redirect" });
      if (path === "/server-status") return send(req, res, entry, 500, Buffer.from("error\n"), text);
      if (path === "/backup.tar.gz") return send(req, res, entry, 304);
      if (path === "/.DS_Store") return send(req, res, entry, 416, Buffer.alloc(0), { "content-range": "bytes */0" });
      return notFound();
    case "slow":
      return void setTimeout(() => (path === "/" ? root() : notFound()), 400);
    default:
      return notFound();
  }
}

const servers = [];
function startFixture(name, port, route) {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      const entry = {
        server: name,
        method: req.method,
        path: pathOf(req),
        hasQuery: req.url.includes("?"),
        range: req.headers.range ?? null,
        acceptEncoding: req.headers["accept-encoding"] ?? null,
        remote: req.socket.remoteAddress,
      };
      serverLog.push(entry);
      route(req, res, entry);
    });
    server.once("error", (error) => reject(new Error(`${name} could not listen on ${LOOPBACK}:${port} (${error.code ?? "error"})`)));
    server.listen(port, LOOPBACK, () => {
      const address = server.address();
      bindings.push({ name, address: address.address, port: address.port });
      servers.push(server);
      resolve(server);
    });
  });
}

// ---------------------------------------------------------------------------
// Isolated API instances.

const RESERVED = new Set([4000, 5173]);
const transportCalls = [];
const guardedTransport = (request) => {
  transportCalls.push({ address: request.address, port: request.port, range: request.headers.range ?? null });
  if (request.address !== LOOPBACK || !LAB_PORTS.has(request.port)) {
    violations.push(`transport asked for ${request.address}:${request.port}`);
    return Promise.reject(new Error("lab guard: transport refused"));
  }
  return websec.nodeTransport(request);
};
const refuseDns = (kind) => async () => {
  dnsCalls.push(kind);
  throw Object.assign(new Error("lab guard: DNS refused"), { code: "EREFUSED" });
};

function labScanConfig(exposureOn, overrides = {}) {
  // A synthetic environment object: never process.env, never .env.
  const env = { SCAN_LAB_MODE: "true", SCAN_LAB_ORIGINS: Object.values(ORIGIN).join(","), ...(exposureOn ? { SCAN_EXPOSURE_ENABLED: "true" } : {}) };
  // Lab-only: room for the scenario matrix under the start-scan rate limit.
  return { ...loadScanConfig(env), rateLimits: { registerTarget: 100, verify: 100, startScan: 100 }, ...overrides };
}

async function startApi(name, config) {
  const token = randomBytes(32).toString("base64url");
  const service = new ScanService({ config, transport: guardedTransport, resolver: refuseDns("resolver"), txtResolver: refuseDns("txt-resolver") });
  const app = createApp({ apiToken: token, scanService: service, modelConfig: loadModelConfig({}) });
  const server = http.createServer(app);
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, LOOPBACK, resolve);
  });
  const port = server.address().port;
  bindings.push({ name: `api:${name}`, address: server.address().address, port });
  servers.push(server);
  const agent = new http.Agent({ keepAlive: false });
  const call = (method, path, body) =>
    new Promise((resolve, reject) => {
      const payload = body === undefined ? null : Buffer.from(JSON.stringify(body));
      const req = http.request(
        {
          host: LOOPBACK,
          port,
          method,
          path,
          agent,
          headers: { authorization: `Bearer ${token}`, ...(payload ? { "content-type": "application/json", "content-length": payload.length } : {}) },
        },
        (res) => {
          const chunks = [];
          res.on("data", (c) => chunks.push(c));
          res.on("end", () => {
            const text = Buffer.concat(chunks).toString("utf8");
            apiOutputs.push(text);
            let json = null;
            try {
              json = JSON.parse(text);
            } catch {}
            resolve({ status: res.statusCode, text, json });
          });
        },
      );
      req.on("error", reject);
      if (payload) req.write(payload);
      req.end();
    });
  return { name, service, call };
}

async function targetId(api, origin) {
  const created = await api.call("POST", "/api/targets", { url: origin });
  const id = created.status === 201 ? created.json.target.id : (await api.call("GET", "/api/targets")).json.targets.find((t) => t.hostname === origin)?.id;
  const verified = await api.call("POST", `/api/targets/${id}/verify`, {});
  if (verified.json?.target?.verification?.status !== "verified") throw new Error(`lab target ${origin} did not verify`);
  return id;
}

const scans = [];
/** Starts one scan, waits for it to finish, and returns the scan, its reports and the fixture requests it caused. */
async function runScan(label, api, origin, body) {
  const id = await targetId(api, origin);
  const logStart = serverLog.length;
  const start = await api.call("POST", "/api/scans", { targetId: id, ...body });
  let scan = start.json?.scan ?? null;
  if (start.status === 202) {
    for (let i = 0; i < 600; i += 1) {
      const got = await api.call("GET", `/api/scans/${scan.id}`);
      scan = got.json.scan;
      if (["completed", "failed", "rejected"].includes(scan.status)) break;
      await sleep(25);
    }
  }
  const reportJson = scan ? (await api.call("GET", `/api/scans/${scan.id}/report.json`)).text : null;
  const reportHtml = scan ? (await api.call("GET", `/api/scans/${scan.id}/report.html`)).text : null;
  const requests = serverLog.slice(logStart);
  const record = { label, api, origin, body, start, scan, reportJson, reportHtml, requests };
  scans.push(record);
  return record;
}

const EXPOSURE_SET = new Set(websec.EXPOSURE_PATHS);
const exposureRequests = (requests) => requests.filter((r) => EXPOSURE_SET.has(r.path) || isBaselinePath(r.path));
const outcomes = (scan) => Object.fromEntries((scan.exposure?.paths ?? []).map((p) => [p.path, p.outcome]));
const topSeverity = (row) => [...row.findings].sort((a, b) => websec.SEVERITY_ORDER.indexOf(a.severity) - websec.SEVERITY_ORDER.indexOf(b.severity))[0]?.severity ?? null;
const sum = (counts) => Object.values(counts ?? {}).reduce((a, b) => a + b, 0);
const describe = (map) => Object.entries(map).map(([k, v]) => `${k}=${v}`).join(", ");

// ---------------------------------------------------------------------------
// Run.

let fatal = null;
try {
  await startFixture("good", PORTS.good, goodRoute);
  await startFixture("bad", PORTS.bad, badRoute);
  await startFixture("variants", PORTS.variants, variantsRoute);
  const apiOff = await startApi("exposure-off", labScanConfig(false));
  const apiOn = await startApi("exposure-on", labScanConfig(true));
  const apiBudget = await startApi("budget-7", labScanConfig(true, { requestBudget: 7 }));
  const apiTimed = await startApi("deadline", labScanConfig(true, { scanTimeoutMs: 3000, probeReserveMs: 700 }));
  check("every service is bound to 127.0.0.1 only", bindings.length === 7 && bindings.every((b) => b.address === LOOPBACK), `${bindings.length} bindings`);
  check("the server switch is on only in the lab API instances that need it", apiOff.service.config.exposureEnabled === false && apiOn.service.config.exposureEnabled === true && switchNames().length === 0);

  // ---- G. Global and per-scan controls (bad site) ----
  const offFalse = await runScan("G1 switch off, not requested", apiOff, ORIGIN.bad, {});
  check("G1 switch off + not requested: completed, no exposure request", offFalse.scan.status === "completed" && exposureRequests(offFalse.requests).length === 0 && offFalse.scan.options.exposureChecks === false, `requests=${offFalse.requests.length}`);
  const offTrue = await runScan("G2 switch off, requested", apiOff, ORIGIN.bad, { includeExposureChecks: true });
  check("G2 switch off + requested: 409 exposure-checks-disabled and nothing sent to the site", offTrue.start.status === 409 && offTrue.start.json.reason === "exposure-checks-disabled" && offTrue.requests.length === 0, `status=${offTrue.start.status} requests=${offTrue.requests.length}`);
  const onFalse = await runScan("G3 switch on, not requested", apiOn, ORIGIN.bad, { includeExposureChecks: false });
  check("G3 switch on + not requested: completed, no exposure request", onFalse.scan.status === "completed" && exposureRequests(onFalse.requests).length === 0, `requests=${onFalse.requests.length}`);
  const bad = await runScan("G4/B switch on, requested (bad site)", apiOn, ORIGIN.bad, { includeExposureChecks: true });
  const badPaths = bad.requests.map((r) => r.path);
  check("G4 switch on + requested: exactly the 2 passive requests, one random baseline, then the nine fixed paths", badPaths.length === 12 && badPaths[0] === "/" && badPaths[1] === "/.well-known/security.txt" && /^\/agentshield-baseline-[0-9a-f]{64}$/.test(badPaths[2]) && badPaths.slice(3).join(",") === websec.EXPOSURE_PATHS.join(","), `${badPaths.length} requests`);
  check("G4 every request was a GET from 127.0.0.1 with no query string", bad.requests.every((r) => r.method === "GET" && r.remote === LOOPBACK && !r.hasQuery));

  // ---- B. Bad site: nine paths ----
  const EXPECTED_SEVERITY = { "/.git/HEAD": "high", "/.git/config": "high", "/.env": "high", "/.DS_Store": "low", "/server-status": "medium", "/backup.zip": "high", "/backup.tar.gz": "high", "/database.sql": "high", "/dump.sql": "high" };
  const badRows = bad.scan.exposure.paths;
  check("B all nine paths are reported exposed", badRows.length === 9 && badRows.every((r) => r.outcome === "exposed"), describe(outcomes(bad.scan)));
  check("B each path has the approved severity", badRows.every((r) => topSeverity(r) === EXPECTED_SEVERITY[r.path]), badRows.map((r) => `${r.path}=${topSeverity(r)}`).join(", "));
  check("B .env is high (never critical) and reports secret kinds and counts only", /^\/\.env: \d+ assignments; \d+ secret-shaped \([a-z0-9-]+ x\d+(, [a-z0-9-]+ x\d+)*( \+\d+ more)?\)$/.test(badRows.find((r) => r.path === "/.env").findings[0].evidence), badRows.find((r) => r.path === "/.env").findings[0].evidence.replace(/^\/\.env: /, ""));
  check("B baseline is a not-found diagnostic and is not counted", bad.scan.exposure.baseline.outcome === "not-found" && sum(bad.scan.exposure.findings) === 9 && bad.scan.checks.filter((c) => c.group === "exposure-baseline").every((c) => c.findings.length === 0));
  const badPassiveIds = bad.scan.checks.filter((c) => !c.group).flatMap((c) => c.findings.map((f) => f.findingId)).sort();
  const M1_BAD_TABLE = ["cookies.httponly-missing", "cookies.samesite-missing", "cors.wildcard-with-credentials", "header.csp.unsafe-script-sources", "header.framing.invalid-x-frame-options", "header.permissions-policy.malformed", "header.referrer-policy.leaky", "header.version-disclosure.server", "header.version-disclosure.x-powered-by", "header.x-content-type-options.missing", "security-txt.missing"];
  check("B passive (M1) findings on the bad site match the M1 lab table", JSON.stringify(badPassiveIds) === JSON.stringify(M1_BAD_TABLE), `${badPassiveIds.length} findings`);
  check("B total findings = passive + nine exposure (baseline never counted)", sum(bad.scan.summary) === badPassiveIds.length + 9, `summary=${sum(bad.scan.summary)}`);

  // ---- A. Good site ----
  const good = await runScan("A good site, requested", apiOn, ORIGIN.good, { includeExposureChecks: true });
  check("A good site: no exposure finding, every path not exposed", good.scan.status === "completed" && good.scan.exposure.counts.exposed === 0 && good.scan.exposure.paths.every((r) => r.outcome === "not-exposed"), describe(outcomes(good.scan)));
  const goodSummary = Object.fromEntries(good.scan.exposure.paths.map((r) => [r.path, r.summary.replace(/^Not exposed: /, "")]));
  check("A good site: 404, 410 and 403 are not exposed; generic HTML status page and ordinary text have no signature", /not found/.test(goodSummary["/.git/HEAD"]) && /not found/.test(goodSummary["/backup.zip"]) && /denied/.test(goodSummary["/.git/config"]) && /signature/.test(goodSummary["/server-status"]) && /signature/.test(goodSummary["/.env"]));
  check("A good site: baseline is not-found", good.scan.exposure.baseline.outcome === "not-found");
  const goodPassive = good.scan.checks.filter((c) => !c.group).flatMap((c) => c.findings);
  check("A good site: passive (M1) checks report no finding", goodPassive.length === 0, `${goodPassive.length} findings`);

  // ---- C. Apache ----
  check("C Apache mod_status fixture detected by its strict signature", /Apache mod_status page signature/.test(badRows.find((r) => r.path === "/server-status").findings[0].evidence));
  check("C generic HTML status page (good site) not detected", good.scan.exposure.paths.find((r) => r.path === "/server-status").outcome === "not-exposed");

  // ---- D. nginx ----
  scenario = "nginx";
  const nginx = await runScan("D nginx stub_status", apiOn, ORIGIN.variants, { includeExposureChecks: true });
  const nginxRow = nginx.scan.exposure.paths.find((r) => r.path === "/server-status");
  check("D nginx stub_status fixture detected (medium)", nginxRow.outcome === "exposed" && topSeverity(nginxRow) === "medium" && /nginx stub_status format/.test(nginxRow.findings[0].evidence));
  scenario = "generic-active";
  const generic = await runScan("D generic 'Active connections' text", apiOn, ORIGIN.variants, { includeExposureChecks: true });
  check("D 'Active connections' text alone not detected", generic.scan.exposure.paths.find((r) => r.path === "/server-status").outcome === "not-exposed");

  // ---- E. Prefix, Range, cancellation, compression, redirects ----
  const rangeOk = bad.requests.every((r) => (EXPOSURE_SET.has(r.path) || isBaselinePath(r.path) ? r.range === "bytes=0-4095" : r.range === null));
  check("E the fixture server received Range: bytes=0-4095 on the 10 exposure requests and no Range on passive requests", rangeOk);
  check("E every request asked for an identity (uncompressed) response", bad.requests.every((r) => r.acceptEncoding === "identity"));
  scenario = "transport";
  const transport = await runScan("E transport behaviours", apiOn, ORIGIN.variants, { includeExposureChecks: true });
  const t = outcomes(transport.scan);
  check("E a server ignoring Range with a 2 MB body: signature still found in the first 4 KB", t["/backup.zip"] === "exposed" && t["/database.sql"] === "exposed");
  const streamed = transport.requests.filter((r) => r.streamTotal);
  await sleep(200); // let the server see the client close
  check("E the scanner hung up early on both 2 MB streams", streamed.length === 2 && streamed.every((r) => r.closedEarly === true && r.bytesQueued < r.streamTotal), streamed.map((r) => `${r.path} queued ${r.bytesQueued} of ${r.streamTotal}`).join("; "));
  check("E compressed response is inconclusive", t["/.env"] === "inconclusive" && /compressed/.test(transport.scan.exposure.paths.find((r) => r.path === "/.env").summary));
  check("E redirects (302, and 301 to an outside address) are inconclusive and never followed", t["/.git/HEAD"] === "inconclusive" && t["/.git/config"] === "inconclusive" && !transport.requests.some((r) => r.path === "/lab-redirect-target") && !outbound.some((o) => o.host !== LOOPBACK));
  check("E 500, 304 and 416 are inconclusive, never a pass", t["/server-status"] === "inconclusive" && t["/backup.tar.gz"] === "inconclusive" && t["/.DS_Store"] === "inconclusive", `${t["/server-status"]}, ${t["/backup.tar.gz"]}, ${t["/.DS_Store"]}`);

  // Direct use of the guarded fetcher with the real Node transport, to measure what is kept.
  const lab = websec.parseLabOrigin(ORIGIN.variants, RESERVED);
  const fetcher = new websec.GuardedFetcher({ resolver: refuseDns("resolver"), transport: guardedTransport });
  const before = serverLog.length;
  const prefix = await fetcher.fetch(lab, new URL(`${ORIGIN.variants}/backup.zip`), { budget: new websec.RequestBudget(5), readPrefix: true });
  const full = await fetcher.fetch(lab, new URL(`${ORIGIN.variants}/backup.zip`), { budget: new websec.RequestBudget(5), readBodyBytes: 32 * 1024 });
  await sleep(200);
  const direct = serverLog.slice(before);
  check("E prefix mode keeps exactly 4,096 bytes of a 2 MB body that ignores Range, and marks it truncated", prefix.ok && prefix.prefix?.kind === "read" && prefix.prefix.bytes.length === 4096 && prefix.prefix.truncated === true);
  check("E Range is sent only in prefix mode; the normal read sends none and stops at its limit", direct.length === 2 && direct[0].range === "bytes=0-4095" && direct[1].range === null && full.ok === false && full.reason === "body-too-large");
  check("E both direct reads were cancelled long before the end of the stream", direct.every((r) => r.closedEarly === true && r.bytesQueued < r.streamTotal), direct.map((r) => `queued ${r.bytesQueued}`).join("; "));

  // ---- F. Soft-404 ----
  scenario = "catch-all";
  const catchAll = await runScan("F catch-all site", apiOn, ORIGIN.variants, { includeExposureChecks: true });
  check("F catch-all baseline: no false exposure finding, every path matches the baseline", catchAll.scan.exposure.baseline.outcome === "catch-all" && catchAll.scan.exposure.counts.exposed === 0 && catchAll.scan.exposure.paths.every((r) => /random missing path/.test(r.summary)));
  scenario = "catch-all-real-env";
  const catchReal = await runScan("F catch-all site with a real .env", apiOn, ORIGIN.variants, { includeExposureChecks: true });
  check("F a real file on a catch-all site is still found", outcomes(catchReal.scan)["/.env"] === "exposed" && catchReal.scan.exposure.counts.exposed === 1);
  scenario = "ambiguous";
  const ambiguous = await runScan("F ambiguous (403) baseline", apiOn, ORIGIN.variants, { includeExposureChecks: true });
  check("F ambiguous baseline: matching signatures are inconclusive, never findings", ambiguous.scan.exposure.baseline.outcome === "inconclusive" && ambiguous.scan.exposure.counts.exposed === 0 && ambiguous.scan.exposure.counts.inconclusive === 9);

  // ---- M2-A: budget and deadline ----
  const budget = await runScan("M2-A request budget 7", apiBudget, ORIGIN.bad, { includeExposureChecks: true });
  const b = budget.scan.exposure.paths;
  check("M2-A budget: 7 requests used, first four paths checked, last five not checked (never pass)", budget.scan.requestsUsed === 7 && budget.requests.length === 7 && b.slice(0, 4).every((r) => r.outcome === "exposed") && b.slice(4).every((r) => r.outcome === "not-checked" && /request budget/.test(r.summary)), describe(budget.scan.exposure.counts));
  scenario = "slow";
  const timed = await runScan("M2-A deadline", apiTimed, ORIGIN.variants, { includeExposureChecks: true });
  const tc = timed.scan.exposure.counts;
  check("M2-A deadline: completed with the passive results kept; later paths not checked for time", timed.scan.status === "completed" && timed.scan.checks.filter((c) => !c.group).length === 12 && tc["not-checked"] >= 1 && tc["not-exposed"] >= 1 && timed.scan.exposure.paths.filter((r) => r.outcome === "not-checked").every((r) => /time limit/.test(r.summary)), describe(tc));

  // ---- H. Reports and audit ----
  const completedRequested = scans.filter((s) => s.scan?.status === "completed" && s.body.includeExposureChecks === true);
  const completedNot = scans.filter((s) => s.scan?.status === "completed" && s.body.includeExposureChecks !== true);
  check("H JSON reports state requested / not requested from the recorded option", scans.filter((s) => s.reportJson).every((s) => {
    const r = JSON.parse(s.reportJson);
    return r.options.exposureChecks === (s.body.includeExposureChecks === true) && r.exposure.requested === (s.body.includeExposureChecks === true);
  }));
  check("H JSON reports list only passive checks under checks; exposure rows and baseline sit under exposure", completedRequested.every((s) => {
    const r = JSON.parse(s.reportJson);
    return r.checks.every((c) => !c.group) && r.checks.length === 12 && r.exposure.paths.length === 9;
  }));
  check("H HTML reports show nine path rows when requested and the not-requested state otherwise", completedRequested.every((s) => (s.reportHtml.match(/<tr><td><code>\//g) ?? []).length === 9 && s.reportHtml.includes("<tr><th>Exposure checks</th><td>Requested</td></tr>")) && completedNot.every((s) => s.reportHtml.includes("<tr><th>Exposure checks</th><td>Not requested</td></tr>") && !s.reportHtml.includes("exposure-table")));
  check("H the baseline is never an HTML table row", completedRequested.every((s) => !/<tr><td><code>[^<]*baseline/i.test(s.reportHtml)));
  for (const api of [apiOff, apiOn, apiBudget, apiTimed]) {
    const audit = (await api.call("GET", "/api/scans")).json.audit;
    const mine = scans.filter((s) => s.api === api && s.scan);
    const ok = mine.every((s) => {
      const tagged = audit.filter((e) => e.scanId === s.scan.id && e.exposureChecks);
      const requested = s.body.includeExposureChecks === true;
      return tagged.length === 1 && tagged[0].exposureChecks.requested === requested && tagged[0].exposureChecks.allowed === (requested ? api.service.config.exposureEnabled : null);
    });
    check(`H audit (${api.name}): the opt-in is recorded exactly once per scan, with the switch's answer`, ok, `${mine.length} scans`);
  }
  const rejected = (await apiOff.call("GET", "/api/scans")).json.audit.filter((e) => e.scanId === offTrue.scan.id);
  check("H a refused opt-in is one scan-rejected entry and never a queued or completed scan", rejected.length === 1 && rejected[0].event === "scan-rejected" && rejected[0].reason === "exposure-checks-disabled");

  // Redaction: every API output (scan details, lists, audit, both report formats) searched for every sentinel.
  const SENTINELS = [
    "FAKE_AGENTSHIELD_TEST_SECRET_DO_NOT_USE_12345",
    "FAKE_AGENTSHIELD_TEST_SECRET_DO_NOT_USE_67890",
    "FAKE_AGENTSHIELD",
    "DB_PASSWORD",
    "LAB_SECRET_TOKEN",
    "LAB_APP_NAME",
    "agentshield-lab",
    "lab-user",
    "git.lab.invalid",
    "refs/heads/lab-main",
    "192.0.2.10",
    "192.0.2.77",
    "192.0.2.1",
    "lab-sentinel-request-path",
    "lab-external-redirect",
    "lab-redirect-target",
    "LAB_SQL_SENTINEL",
    "LAB_DSSTORE",
    "LAB_ZIP_SENTINEL",
    "LAB_TAR_SENTINEL",
    "LAB_BASELINE_SENTINEL",
    "agentshield-baseline-",
  ];
  const corpus = apiOutputs.join("\n");
  const hits = SENTINELS.filter((s) => corpus.includes(s));
  check(`H no sentinel appears in any API output, report or audit entry (${SENTINELS.length} sentinels, ${apiOutputs.length} outputs)`, hits.length === 0, hits.length ? `${hits.length} sentinel(s) found` : "");
} catch (error) {
  fatal = error;
  check("lab run completed without an unexpected error", false, error instanceof Error ? error.message : "unknown error");
} finally {
  // ---- I. Safety and cleanup ----
  await Promise.all(
    servers.map(
      (server) =>
        new Promise((resolve) => {
          server.closeAllConnections?.();
          server.close(() => resolve());
        }),
    ),
  );
  check("I every service was stopped", servers.every((server) => !server.listening), `${servers.length} stopped`);
  check("I no DNS call was made (resolver, TXT or system lookup)", dnsCalls.length === 0, `${dnsCalls.length} calls; ${literalLookups.length} local resolutions of the literal 127.0.0.1 by listen()`);
  check("I every outgoing connection went to 127.0.0.1", outbound.length > 0 && outbound.every((o) => o.host === LOOPBACK), `${outbound.length} connections`);
  check("I the scanner's transport only ever targeted the lab ports on 127.0.0.1", transportCalls.length > 0 && transportCalls.every((c) => c.address === LOOPBACK && LAB_PORTS.has(c.port)), `${transportCalls.length} requests`);
  check("I no guard violation (bind, connect or transport)", violations.length === 0, `${violations.length} violations`);
  check("I process environment still has no SCAN_* or MODEL_* variables", switchNames().length === 0);
}

const failed = results.filter((r) => !r.ok);
const summary = {
  run: "AgentShield M2-F exposure lab",
  loopback: LOOPBACK,
  fixturePorts: PORTS,
  bindings: bindings.map((b) => `${b.name} ${b.address}:${b.port}`),
  scans: scans.map((s) => ({ label: s.label, status: s.scan?.status ?? `http ${s.start.status}`, requestsUsed: s.scan?.requestsUsed ?? 0, fixtureRequests: s.requests.length, exposure: s.scan?.exposure?.requested ? s.scan.exposure.counts : "not requested" })),
  checks: results,
  passed: results.length - failed.length,
  failed: failed.length,
};
if (process.argv[2]) writeFileSync(process.argv[2], JSON.stringify(summary, null, 2));
console.log(`\n${summary.passed} passed, ${summary.failed} failed`);
process.exitCode = failed.length === 0 && !fatal ? 0 : 1;
