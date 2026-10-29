import { execFileSync } from "node:child_process";
import dns from "node:dns";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:https";
import { connect, isIP, type Socket } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { TLSSocket } from "node:tls";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { checkTls } from "./checks/transport-security.js";
import { GuardedFetcher, RequestBudget, type FetchResult, type Transport, type TransportRequest, type TransportResponse } from "./fetcher.js";
import { CORS_PROBE_ORIGIN } from "./scan.js";
import { createNodeTransport, nodeTransport } from "./node-transport.js";
import type { DnsTarget } from "./target.js";

/**
 * Loopback-only validation of the REAL network transport (M1): TLS, SNI, the Host
 * header, connection pinning, DNS-rebinding resistance and cancellation.
 *
 * Scope and safety:
 * - Every server binds to 127.0.0.1 or ::1 only, on ephemeral ports (and, for the
 *   blocked-resolution decoy, port 443 on loopback when it is free).
 * - The test host name is under .example (RFC 2606) and is never resolved: Node's
 *   dns.lookup is replaced for this file by a spy that records every call and
 *   answers ::1 (the "rebound" address). A pinned connection never calls it.
 * - Certificates are throwaway, generated with the local OpenSSL into a temp folder
 *   that is deleted afterwards; keys are never printed or stored in the repository.
 * - No public address, DNS server or external service is contacted.
 */

const HOST = "agentshield-pin-test.example";
const OTHER_HOST = "other-host.example";
const target: DnsTarget = { kind: "dns", hostname: HOST, displayHostname: HOST };

function findOpenssl(): string | null {
  for (const candidate of ["openssl", "C:\\Program Files\\Git\\mingw64\\bin\\openssl.exe", "C:\\Program Files\\Git\\usr\\bin\\openssl.exe"]) {
    try {
      execFileSync(candidate, ["version"], { stdio: "pipe" });
      return candidate;
    } catch {
      // try the next location
    }
  }
  return null;
}

const OPENSSL = findOpenssl();

interface Certs {
  ca: string;
  good: { key: string; cert: string };
  mismatch: { key: string; cert: string };
  selfSigned: { key: string; cert: string };
}

/** Generates a throwaway test CA and three leaf certificates (EC P-256, 400 days). */
function generateCerts(openssl: string, dir: string): Certs {
  const run = (args: string[]) => execFileSync(openssl, args, { cwd: dir, stdio: "pipe" });
  const ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes"];
  run(["req", "-x509", ...ec, "-keyout", "ca.key", "-out", "ca.crt", "-days", "400", "-subj", "/CN=AgentShield Loopback Test CA",
    "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign"]);
  const leaf = (name: string, san: string, serial: string) => {
    writeFileSync(join(dir, `${name}.ext`), `subjectAltName=DNS:${san}\nbasicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n`);
    run(["req", ...ec, "-keyout", `${name}.key`, "-out", `${name}.csr`, "-subj", `/CN=${san}`]);
    run(["x509", "-req", "-in", `${name}.csr`, "-CA", "ca.crt", "-CAkey", "ca.key", "-set_serial", serial, "-days", "400", "-out", `${name}.crt`, "-extfile", `${name}.ext`]);
  };
  leaf("good", HOST, "0x1001");
  leaf("mismatch", OTHER_HOST, "0x1002");
  run(["req", "-x509", ...ec, "-keyout", "self.key", "-out", "self.crt", "-days", "400", "-subj", `/CN=${HOST}`, "-addext", `subjectAltName=DNS:${HOST}`]);
  const read = (file: string) => readFileSync(join(dir, file), "utf8");
  return {
    ca: read("ca.crt"),
    good: { key: read("good.key"), cert: read("good.crt") },
    mismatch: { key: read("mismatch.key"), cert: read("mismatch.crt") },
    selfSigned: { key: read("self.key"), cert: read("self.crt") },
  };
}

interface Seen {
  host: string | undefined;
  servername: string | false | null | undefined;
  localAddress: string | undefined;
  path: string | undefined;
}

interface TestServer {
  server: Server;
  port: number;
  seen: Seen[];
  connections: number;
  closedSockets: number;
}

const servers: TestServer[] = [];
const sockets = new Set<Socket>();

/** An in-process HTTPS server on one loopback address that records every request it receives. */
function startServer(tls: { key: string; cert: string }, address: "127.0.0.1" | "::1", port = 0, respond = true): Promise<TestServer> {
  return new Promise((resolve, reject) => {
    const record: TestServer = { server: undefined as unknown as Server, port: 0, seen: [], connections: 0, closedSockets: 0 };
    const server = createServer({ key: tls.key, cert: tls.cert }, (req, res) => {
      record.seen.push({
        host: req.headers.host,
        servername: (req.socket as TLSSocket).servername,
        localAddress: req.socket.localAddress,
        path: req.url,
      });
      if (!respond) return; // hangs until the client gives up
      res.writeHead(200, { "content-type": "text/plain", "x-pin-test": "fixed" });
      res.end("pinned-ok");
    });
    server.on("connection", (socket: Socket) => {
      record.connections += 1;
      sockets.add(socket);
      socket.on("close", () => {
        record.closedSockets += 1;
        sockets.delete(socket);
      });
    });
    server.on("error", reject);
    server.listen(port, address, () => {
      record.server = server;
      record.port = (server.address() as { port: number }).port;
      servers.push(record);
      resolve(record);
    });
  });
}

/** Builds the request the guarded fetcher would hand to the transport after validating `address`. */
function pinnedRequest(url: string, address: string, family: 4 | 6, signal = new AbortController().signal): TransportRequest {
  const parsed = new URL(url);
  return {
    url: parsed,
    address,
    family,
    port: Number(parsed.port || 443),
    servername: parsed.hostname,
    method: "GET",
    headers: { host: parsed.host, "user-agent": "AgentShield-PassiveScanner/0.1 (loopback test)", accept: "*/*", "accept-encoding": "identity", connection: "close" },
    signal,
  };
}

async function readBody(response: TransportResponse): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of response.body ?? []) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString("utf8");
}

function observationFor(result: FetchResult) {
  return { target, https: result, http: null, securityTxt: null, probeOrigin: CORS_PROBE_ORIGIN, now: new Date() };
}

function asFetchResult(url: string, response: TransportResponse): FetchResult {
  return { ok: true, url: new URL(url), status: response.status, headers: {}, body: null, tls: response.tls, hops: [] };
}

describe.skipIf(OPENSSL === null)("real transport over loopback HTTPS (no public network, no real DNS)", () => {
  let dir = "";
  let certs: Certs;
  let goodV4: TestServer;
  let goodV6: TestServer;
  let selfSigned: TestServer;
  let mismatch: TestServer;
  const dnsCalls: string[] = [];
  const realLookup = dns.lookup;

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), "agentshield-loopback-tls-"));
    certs = generateCerts(OPENSSL!, dir);
    // Every uncontrolled host-name lookup is recorded and answered with ::1 (the "rebound"
    // address). IP literals (used by server.listen) go to Node's own lookup, which answers
    // them locally without any DNS query.
    (dns as { lookup: unknown }).lookup = (hostname: string, options: unknown, callback?: unknown) => {
      if (isIP(hostname) !== 0) return (realLookup as (...args: unknown[]) => void).call(dns, hostname, options, callback);
      dnsCalls.push(hostname);
      const cb = (typeof options === "function" ? options : callback) as (...args: unknown[]) => void;
      const all = typeof options === "object" && options !== null && (options as { all?: boolean }).all;
      process.nextTick(() => (all ? cb(null, [{ address: "::1", family: 6 }]) : cb(null, "::1", 6)));
    };
    // Two servers on the SAME port: 127.0.0.1 (the validated address) and ::1, where a
    // connection lands only if DNS, not the pin, decides. Ephemeral ports are chosen per
    // address family, so a port free on one may be busy on the other: retry on collision.
    for (let attempt = 0; attempt < 10 && !goodV4; attempt += 1) {
      const v6 = await startServer(certs.good, "::1");
      try {
        goodV4 = await startServer(certs.good, "127.0.0.1", v6.port);
        goodV6 = v6;
      } catch {
        await new Promise<void>((resolve) => v6.server.close(() => resolve()));
        servers.splice(servers.indexOf(v6), 1);
      }
    }
    if (!goodV4) throw new Error("could not bind the same loopback port on 127.0.0.1 and ::1");
    selfSigned = await startServer(certs.selfSigned, "127.0.0.1");
    mismatch = await startServer(certs.mismatch, "127.0.0.1");
  }, 30_000);

  afterAll(async () => {
    (dns as { lookup: unknown }).lookup = realLookup;
    for (const socket of sockets) socket.destroy();
    await Promise.all(servers.map((s) => new Promise<void>((resolve) => s.server.close(() => resolve()))));
    if (dir && existsSync(dir)) rmSync(dir, { recursive: true, force: true });
  });

  it("the DNS spy intercepts Node's own lookups (canary, using localhost)", async () => {
    const before = goodV6.connections;
    await new Promise<void>((resolve, reject) => {
      const socket = connect({ host: "localhost", port: goodV6.port }, () => {
        socket.destroy();
        resolve();
      });
      socket.on("error", reject);
    });
    expect(dnsCalls).toEqual(["localhost"]);
    expect(goodV6.connections).toBe(before + 1);
    dnsCalls.length = 0;
  });

  it("trusted certificate: the pinned connection reaches the checked 127.0.0.1, keeping Host and SNI", async () => {
    const transport = createNodeTransport({ ca: certs.ca });
    const url = `https://${HOST}:${goodV4.port}/`;
    // The canary above connected to the ::1 server once on purpose; count from here.
    const v6Before = goodV6.connections;
    const response = await transport(pinnedRequest(url, "127.0.0.1", 4));
    const body = await readBody(response);
    response.close();

    expect([response.status, body, response.headers["x-pin-test"]]).toEqual([200, "pinned-ok", "fixed"]);
    expect(response.tls).toMatchObject({ authorized: true, authorizationError: null, hostnameMatches: true });
    expect(response.tls?.protocol).toMatch(/^TLSv1\.[23]$/);
    expect(response.tls?.certificate).toMatchObject({ subjectCN: HOST, issuerCN: "AgentShield Loopback Test CA" });
    expect(goodV4.seen.at(-1)).toEqual({ host: `${HOST}:${goodV4.port}`, servername: HOST, localAddress: "127.0.0.1", path: "/" });
    // Pinned: no DNS lookup at all, and nothing reached the ::1 server on the same port.
    expect(dnsCalls).toEqual([]);
    expect(goodV6.connections).toBe(v6Before);
    // The scanner's TLS check passes this connection.
    expect(checkTls(observationFor(asFetchResult(url, response)))).toMatchObject({ status: "pass", findings: [] });
  });

  it("rebinding: DNS answers ::1, yet the destination is always the pinned, validated address", async () => {
    const transport = createNodeTransport({ ca: certs.ca });
    const url = `https://${HOST}:${goodV4.port}/`;
    const v4Before = goodV4.seen.length;
    const v6Before = goodV6.connections;
    for (let i = 0; i < 3; i += 1) {
      const response = await transport(pinnedRequest(url, "127.0.0.1", 4));
      await readBody(response);
      response.close();
    }
    expect(goodV4.seen.length - v4Before).toBe(3);
    expect(goodV6.connections).toBe(v6Before);
    expect(dnsCalls).toEqual([]);

    // The pin, not DNS, chooses the socket: pinning ::1 reaches the ::1 server instead.
    const viaV6 = await transport(pinnedRequest(url, "::1", 6));
    await readBody(viaV6);
    viaV6.close();
    expect(goodV6.seen.at(-1)).toMatchObject({ servername: HOST, localAddress: "::1" });
    expect(goodV4.seen.length - v4Before).toBe(3);
    expect(dnsCalls).toEqual([]);
  });

  it("untrusted (self-signed) certificate: the production transport reports it, and the TLS check fails it", async () => {
    const url = `https://${HOST}:${selfSigned.port}/`;
    const response = await nodeTransport(pinnedRequest(url, "127.0.0.1", 4));
    response.close();
    expect(response.tls).toMatchObject({ authorized: false, authorizationError: "DEPTH_ZERO_SELF_SIGNED_CERT", hostnameMatches: true });
    const check = checkTls(observationFor(asFetchResult(url, response)));
    expect(check.status).toBe("fail");
    expect(check.findings.map((f) => f.findingId)).toEqual(["tls.certificate-untrusted"]);
    expect(selfSigned.seen.at(-1)?.servername).toBe(HOST);
    expect(dnsCalls).toEqual([]);
  });

  it("the test CA is not trusted by the production transport (default trust store)", async () => {
    const url = `https://${HOST}:${goodV4.port}/`;
    const response = await nodeTransport(pinnedRequest(url, "127.0.0.1", 4));
    response.close();
    expect(response.tls?.authorized).toBe(false);
    expect(response.tls?.authorizationError).toMatch(/^(UNABLE_TO_VERIFY_LEAF_SIGNATURE|UNABLE_TO_GET_ISSUER_CERT_LOCALLY|SELF_SIGNED_CERT_IN_CHAIN)$/);
    expect(checkTls(observationFor(asFetchResult(url, response))).findings.map((f) => f.findingId)).toEqual(["tls.certificate-untrusted"]);
  });

  it("hostname mismatch: Node reports ERR_TLS_CERT_ALTNAME_INVALID and the check reports it exactly once", async () => {
    const transport = createNodeTransport({ ca: certs.ca });
    const url = `https://${HOST}:${mismatch.port}/`;
    const response = await transport(pinnedRequest(url, "127.0.0.1", 4));
    response.close();
    expect(response.tls).toMatchObject({ authorized: false, authorizationError: "ERR_TLS_CERT_ALTNAME_INVALID", hostnameMatches: false });
    expect(response.tls?.certificate?.subjectAltNames).toEqual([`DNS:${OTHER_HOST}`]);
    const check = checkTls(observationFor(asFetchResult(url, response)));
    expect(check.status).toBe("fail");
    expect(check.findings.map((f) => f.findingId)).toEqual(["tls.hostname-mismatch"]);
    expect(mismatch.seen.at(-1)?.servername).toBe(HOST);
  });

  it("cancellation closes the real socket, with no request completed", async () => {
    const hanging = await startServer(certs.good, "127.0.0.1", 0, false);
    const controller = new AbortController();
    const transport = createNodeTransport({ ca: certs.ca });
    const pending = transport(pinnedRequest(`https://${HOST}:${hanging.port}/`, "127.0.0.1", 4, controller.signal));
    setTimeout(() => controller.abort(), 150);
    await expect(pending).rejects.toBeTruthy();
    const deadline = Date.now() + 3000;
    while (hanging.closedSockets < hanging.connections && Date.now() < deadline) await new Promise((r) => setTimeout(r, 20));
    expect(hanging.connections).toBe(1);
    expect(hanging.closedSockets).toBe(1);
  });

  it("blocked resolution through the real guarded fetcher: the transport is never called and no server sees a request", async () => {
    // Decoys where a broken guard would connect: loopback port 443, when it is free.
    const decoys: TestServer[] = [];
    for (const address of ["127.0.0.1", "::1"] as const) {
      try {
        decoys.push(await startServer(certs.good, address, 443));
      } catch {
        // Port 443 in use or not bindable: the transport-call count below still applies.
      }
    }
    let transportCalls = 0;
    const realTransport = createNodeTransport({ ca: certs.ca });
    const counting: Transport = (request) => {
      transportCalls += 1;
      return realTransport(request);
    };
    const answers = [
      [{ address: "127.0.0.1", family: 4 }],
      [{ address: "127.0.0.2", family: 4 }],
      [{ address: "::1", family: 6 }],
      [{ address: "::ffff:127.0.0.1", family: 6 }],
      [{ address: "127.0.0.1", family: 4 }, { address: "::1", family: 6 }],
    ];
    for (const answer of answers) {
      const fetcher = new GuardedFetcher({ resolver: async () => answer, transport: counting, timeoutMs: 2000 });
      const result = await fetcher.fetch(target, new URL(`https://${HOST}/`), { budget: new RequestBudget(30) });
      expect(result, JSON.stringify(answer)).toMatchObject({ ok: false, reason: "blocked-address" });
    }
    expect(transportCalls).toBe(0);
    for (const decoy of decoys) expect([decoy.connections, decoy.seen.length]).toEqual([0, 0]);
    expect(dnsCalls).toEqual([]);
    console.info(`loopback-tls: blocked-resolution decoys bound on port 443: ${decoys.length} of 2`);
  });

  it("no uncontrolled DNS lookup happened in any test after the canary", () => {
    expect(dnsCalls).toEqual([]);
  });
});
