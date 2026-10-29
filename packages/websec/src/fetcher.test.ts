import { brotliCompressSync, gzipSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import {
  GuardedFetcher,
  HostGate,
  RequestBudget,
  type Resolver,
  type TlsDetails,
  type Transport,
  type TransportRequest,
  type TransportResponse,
} from "./fetcher.js";
import { parseLabOrigin, type DnsTarget } from "./target.js";

/**
 * Every test here uses a fake resolver and a fake transport. Nothing touches the
 * network: the transport records what it was asked to do and answers from fixtures.
 */

const target: DnsTarget = { kind: "dns", hostname: "example.com", displayHostname: "example.com" };
const PUBLIC = [{ address: "93.184.215.14", family: 4 }];

interface FakeSpec {
  status: number;
  headers?: Record<string, string | string[]>;
  body?: string | Buffer | Array<string | Buffer>;
  tls?: TlsDetails | null;
}

function fakeResponse(spec: FakeSpec, stats: { closed: number; chunksRead: number }): TransportResponse {
  const chunks = spec.body === undefined ? [] : (Array.isArray(spec.body) ? spec.body : [spec.body]).map((c) => Buffer.from(c));
  return {
    status: spec.status,
    headers: spec.headers ?? {},
    body: {
      async *[Symbol.asyncIterator]() {
        for (const chunk of chunks) {
          stats.chunksRead += 1;
          yield new Uint8Array(chunk);
        }
      },
    },
    tls: spec.tls ?? null,
    close: () => {
      stats.closed += 1;
    },
  };
}

function setup(
  respond: (request: TransportRequest, call: number) => FakeSpec | Promise<FakeSpec>,
  resolve: Resolver = async () => PUBLIC,
  options: Partial<ConstructorParameters<typeof GuardedFetcher>[0]> = {},
) {
  const requests: TransportRequest[] = [];
  const stats = { closed: 0, chunksRead: 0 };
  const resolverCalls: string[] = [];
  const transport: Transport = async (request) => {
    requests.push(request);
    return fakeResponse(await respond(request, requests.length), stats);
  };
  const resolver: Resolver = (hostname, signal) => {
    resolverCalls.push(hostname);
    return resolve(hostname, signal);
  };
  const fetcher = new GuardedFetcher({ resolver, transport, ...options });
  return { fetcher, requests, stats, resolverCalls };
}

const budget = (limit = 30) => new RequestBudget(limit);

describe("guarded fetcher: resolution, pinning and headers", () => {
  it("connects only to the validated address, keeping the host name for Host and TLS SNI", async () => {
    const { fetcher, requests } = setup(() => ({ status: 200 }));
    const result = await fetcher.fetch(target, new URL("https://example.com/"), { budget: budget() });
    expect(result.ok).toBe(true);
    expect(requests).toHaveLength(1);
    const [request] = requests;
    expect(request).toMatchObject({ address: "93.184.215.14", family: 4, port: 443, servername: "example.com", method: "GET" });
    expect(request!.url.hostname).toBe("example.com");
    expect(request!.headers).toEqual({
      host: "example.com",
      "user-agent": expect.stringContaining("AgentShield"),
      accept: "*/*",
      "accept-encoding": "identity",
      connection: "close",
    });
  });

  it("never sends cookies or credentials, and only a well-formed probe Origin", async () => {
    const { fetcher, requests } = setup(() => ({ status: 200 }));
    await fetcher.fetch(target, new URL("https://example.com/"), { budget: budget(), probeOrigin: "https://agentshield-cors-probe.invalid" });
    await fetcher.fetch(target, new URL("http://example.com/"), { budget: budget(), probeOrigin: "https://evil.example\r\nCookie: a=b" });
    expect(requests[0]!.headers.origin).toBe("https://agentshield-cors-probe.invalid");
    expect(requests[1]!.headers.origin).toBeUndefined();
    expect(requests[1]!.servername).toBeNull();
    expect(requests[1]!.port).toBe(80);
    for (const request of requests) {
      const names = Object.keys(request.headers);
      expect(names).not.toContain("cookie");
      expect(names).not.toContain("authorization");
    }
  });

  it.each([
    ["a private address", [{ address: "10.0.0.5", family: 4 }], "blocked-address", "private"],
    ["cloud metadata", [{ address: "169.254.169.254", family: 4 }], "blocked-address", "cloud-metadata"],
    ["loopback IPv6", [{ address: "::1", family: 6 }], "blocked-address", "loopback"],
    ["one private among public", [...PUBLIC, { address: "192.168.1.1", family: 4 }], "blocked-address", "private"],
    ["an IPv4-mapped address", [{ address: "::ffff:127.0.0.1", family: 6 }], "blocked-address", "ipv4-mapped"],
    ["an empty answer", [], "malformed-resolution", "empty"],
    ["a malformed answer", [{ address: "2130706433", family: 4 }], "malformed-resolution", "malformed"],
  ])("refuses %s without calling the transport", async (_label, answers, reason, blockReason) => {
    const { fetcher, requests } = setup(() => ({ status: 200 }), async () => answers);
    const result = await fetcher.fetch(target, new URL("https://example.com/"), { budget: budget() });
    expect(result).toMatchObject({ ok: false, reason, blockReason });
    expect(requests).toHaveLength(0);
  });

  it("treats a resolver error as a DNS failure, with no request sent", async () => {
    const { fetcher, requests } = setup(
      () => ({ status: 200 }),
      async () => {
        throw new Error("ENOTFOUND");
      },
    );
    expect(await fetcher.fetch(target, new URL("https://example.com/"), { budget: budget() })).toMatchObject({ ok: false, reason: "dns-failure" });
    expect(requests).toHaveLength(0);
  });

  it("refuses an out-of-scope start URL before resolving anything", async () => {
    const { fetcher, requests, resolverCalls } = setup(() => ({ status: 200 }));
    for (const url of ["https://evil.example/", "https://www.example.com/", "https://example.com:8443/", "http://127.0.0.1/"]) {
      expect(await fetcher.fetch(target, new URL(url), { budget: budget() }), url).toMatchObject({ ok: false, reason: "out-of-scope" });
    }
    expect([requests.length, resolverCalls.length]).toEqual([0, 0]);
  });
});

describe("guarded fetcher: DNS rebinding and redirects", () => {
  it("re-resolves every redirect hop and stops when the name rebinds to a private address", async () => {
    let lookups = 0;
    const { fetcher, requests } = setup(
      () => ({ status: 302, headers: { location: "/next" } }),
      async () => (++lookups === 1 ? PUBLIC : [{ address: "127.0.0.1", family: 4 }]),
    );
    const result = await fetcher.fetch(target, new URL("https://example.com/"), { budget: budget() });
    expect(result).toMatchObject({ ok: false, reason: "blocked-address", blockReason: "loopback" });
    expect(requests.map((r) => r.address)).toEqual(["93.184.215.14"]);
    expect(lookups).toBe(2);
  });

  it("follows same-host redirects and records each hop", async () => {
    const { fetcher, requests } = setup((_request, call) =>
      call === 1 ? { status: 301, headers: { location: "https://example.com/home" } } : call === 2 ? { status: 302, headers: { location: "/final" } } : { status: 200 },
    );
    const result = await fetcher.fetch(target, new URL("http://example.com/"), { budget: budget() });
    expect(result).toMatchObject({ ok: true, status: 200 });
    if (result.ok) {
      expect(result.url.href).toBe("https://example.com/final");
      expect(result.hops.map((h) => h.status)).toEqual([301, 302]);
    }
    expect(requests.map((r) => r.url.href)).toEqual(["http://example.com/", "https://example.com/home", "https://example.com/final"]);
  });

  it.each([
    "https://evil.example/",
    "https://www.example.com/",
    "https://example.com:8443/",
    "http://127.0.0.1/",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]/",
    "https://user:pass@example.com/",
    "ftp://example.com/",
    "//evil.example/",
  ])("refuses a redirect to %s without following it", async (location) => {
    const { fetcher, requests } = setup(() => ({ status: 302, headers: { location } }));
    const result = await fetcher.fetch(target, new URL("https://example.com/"), { budget: budget() });
    expect(result).toMatchObject({ ok: false, reason: "redirect-out-of-scope" });
    expect(requests).toHaveLength(1);
  });

  it("stops after five redirects", async () => {
    const { fetcher, requests } = setup((_request, call) => ({ status: 302, headers: { location: `/hop-${call}` } }));
    const result = await fetcher.fetch(target, new URL("https://example.com/"), { budget: budget() });
    expect(result).toMatchObject({ ok: false, reason: "too-many-redirects" });
    expect(requests).toHaveLength(6);
  });

  it("refuses an unparseable redirect location", async () => {
    const { fetcher } = setup(() => ({ status: 302, headers: { location: "https://exa mple.com/" } }));
    expect(await fetcher.fetch(target, new URL("https://example.com/"), { budget: budget() })).toMatchObject({ ok: false, reason: "invalid-redirect" });
  });

  it("returns a redirect unfollowed when asked to", async () => {
    const { fetcher, requests } = setup(() => ({ status: 301, headers: { location: "https://evil.example/" } }));
    const result = await fetcher.fetch(target, new URL("http://example.com/"), { budget: budget(), followRedirects: false });
    expect(result).toMatchObject({ ok: true, status: 301, headers: { location: ["https://evil.example/"] } });
    expect(requests).toHaveLength(1);
  });
});

describe("guarded fetcher: budgets, timeouts and bodies", () => {
  it("each attempt, including redirect hops, uses the shared request budget", async () => {
    const { fetcher, requests } = setup((_request, call) => ({ status: 302, headers: { location: `/hop-${call}` } }));
    const shared = budget(3);
    expect(await fetcher.fetch(target, new URL("https://example.com/"), { budget: shared })).toMatchObject({ ok: false, reason: "request-budget-exceeded" });
    expect(requests).toHaveLength(3);
    expect(await fetcher.fetch(target, new URL("https://example.com/"), { budget: shared })).toMatchObject({ ok: false, reason: "request-budget-exceeded" });
    expect([requests.length, shared.spent]).toEqual([3, 3]);
  });

  it("times out a hanging transport, aborts its signal, and closes a response that arrives late", async () => {
    let seen: AbortSignal | null = null;
    let late: TransportResponse | null = null;
    let lateClosed = false;
    const transport: Transport = (request) => {
      seen = request.signal;
      return new Promise((resolve) =>
        setTimeout(() => {
          late = { status: 200, headers: {}, body: null, tls: null, close: () => (lateClosed = true) };
          resolve(late);
        }, 60),
      );
    };
    const fetcher = new GuardedFetcher({ resolver: async () => PUBLIC, transport, timeoutMs: 20 });
    expect(await fetcher.fetch(target, new URL("https://example.com/"), { budget: budget() })).toMatchObject({ ok: false, reason: "timeout" });
    expect(seen!.aborted).toBe(true);
    await new Promise((resolve) => setTimeout(resolve, 80));
    expect([late !== null, lateClosed]).toEqual([true, true]);
  });

  it("times out a hanging resolver without sending a request", async () => {
    const { fetcher, requests } = setup(() => ({ status: 200 }), () => new Promise(() => {}), { timeoutMs: 20 });
    expect(await fetcher.fetch(target, new URL("https://example.com/"), { budget: budget() })).toMatchObject({ ok: false, reason: "timeout" });
    expect(requests).toHaveLength(0);
  });

  it("stops when the caller cancels", async () => {
    const controller = new AbortController();
    const { fetcher } = setup(() => new Promise<FakeSpec>(() => {}));
    const pending = fetcher.fetch(target, new URL("https://example.com/"), { budget: budget(), signal: controller.signal });
    setTimeout(() => controller.abort(), 10);
    expect(await pending).toMatchObject({ ok: false, reason: "cancelled" });
    expect(await fetcher.fetch(target, new URL("https://example.com/"), { budget: budget(), signal: controller.signal })).toMatchObject({
      ok: false,
      reason: "cancelled",
    });
  });

  it("discards the body unread unless asked, and always closes the response", async () => {
    const { fetcher, stats } = setup(() => ({ status: 200, body: ["aaa", "bbb"] }));
    const result = await fetcher.fetch(target, new URL("https://example.com/"), { budget: budget() });
    expect(result).toMatchObject({ ok: true, body: null });
    expect([stats.chunksRead, stats.closed]).toEqual([0, 1]);
  });

  it("reads a bounded body and refuses one over the limit", async () => {
    const small = setup(() => ({ status: 200, body: ["Contact: ", "x"] }));
    const ok = await small.fetcher.fetch(target, new URL("https://example.com/"), { budget: budget(), readBodyBytes: 32 });
    expect(ok.ok && ok.body?.toString()).toBe("Contact: x");
    const large = setup(() => ({ status: 200, body: ["0123456789", "x"] }));
    expect(await large.fetcher.fetch(target, new URL("https://example.com/"), { budget: budget(), readBodyBytes: 10 })).toMatchObject({
      ok: false,
      reason: "body-too-large",
    });
    expect(large.stats.closed).toBe(1);
  });

  it("never reads more than the fetcher's 1 MB-style hard cap, whatever the caller asks", async () => {
    const { fetcher } = setup(() => ({ status: 200, body: "y".repeat(101) }), undefined, { maxBodyBytes: 100 });
    expect(await fetcher.fetch(target, new URL("https://example.com/"), { budget: budget(), readBodyBytes: 10_000_000 })).toMatchObject({
      ok: false,
      reason: "body-too-large",
    });
  });

  it("decodes compressed bodies within the limit and refuses decompression bombs", async () => {
    const text = "Contact: mailto:security@example.com\n";
    const gzip = setup(() => ({ status: 200, headers: { "content-encoding": "gzip" }, body: gzipSync(text) }));
    const decoded = await gzip.fetcher.fetch(target, new URL("https://example.com/"), { budget: budget(), readBodyBytes: 1000 });
    expect(decoded.ok && decoded.body?.toString()).toBe(text);
    const br = setup(() => ({ status: 200, headers: { "content-encoding": "br" }, body: brotliCompressSync(text) }));
    const brDecoded = await br.fetcher.fetch(target, new URL("https://example.com/"), { budget: budget(), readBodyBytes: 1000 });
    expect(brDecoded.ok && brDecoded.body?.toString()).toBe(text);

    const bomb = gzipSync(Buffer.alloc(200_000));
    expect(bomb.length).toBeLessThan(1000);
    const bombed = setup(() => ({ status: 200, headers: { "content-encoding": "gzip" }, body: bomb }));
    expect(await bombed.fetcher.fetch(target, new URL("https://example.com/"), { budget: budget(), readBodyBytes: 1000 })).toMatchObject({
      ok: false,
      reason: "decompressed-too-large",
    });
    const unknown = setup(() => ({ status: 200, headers: { "content-encoding": "zstd" }, body: "x" }));
    expect(await unknown.fetcher.fetch(target, new URL("https://example.com/"), { budget: budget(), readBodyBytes: 100 })).toMatchObject({
      ok: false,
      reason: "unsupported-encoding",
    });
    const corrupt = setup(() => ({ status: 200, headers: { "content-encoding": "gzip" }, body: "not gzip" }));
    expect(await corrupt.fetcher.fetch(target, new URL("https://example.com/"), { budget: budget(), readBodyBytes: 100 })).toMatchObject({
      ok: false,
      reason: "invalid-encoding",
    });
  });

  it("allows at most one active request per host", async () => {
    let active = 0;
    let peak = 0;
    const transport: Transport = async () => {
      active += 1;
      peak = Math.max(peak, active);
      await new Promise((resolve) => setTimeout(resolve, 10));
      active -= 1;
      return { status: 200, headers: {}, body: null, tls: null, close: () => {} };
    };
    const gate = new HostGate();
    const fetcher = new GuardedFetcher({ resolver: async () => PUBLIC, transport, hostGate: gate });
    const results = await Promise.all(Array.from({ length: 4 }, () => fetcher.fetch(target, new URL("https://example.com/"), { budget: budget() })));
    expect(results.every((r) => r.ok)).toBe(true);
    expect(peak).toBe(1);
    expect(gate.activeFor("example.com")).toBe(0);
  });
});

describe("guarded fetcher: lab targets", () => {
  it("connects to the configured loopback address without DNS, and only within the exact lab origin", async () => {
    const lab = parseLabOrigin("http://127.0.0.1:8081")!;
    const { fetcher, requests, resolverCalls } = setup((_request, call) => (call === 1 ? { status: 302, headers: { location: "http://127.0.0.1:8082/" } } : { status: 200 }));
    expect(await fetcher.fetch(lab, new URL("http://127.0.0.1:8081/"), { budget: budget() })).toMatchObject({ ok: false, reason: "redirect-out-of-scope" });
    expect(requests).toHaveLength(1);
    expect(requests[0]).toMatchObject({ address: "127.0.0.1", port: 8081, servername: null });
    expect(resolverCalls).toEqual([]);
    for (const url of ["http://127.0.0.1:9999/", "http://169.254.169.254/", "http://localhost:8081/"]) {
      expect(await fetcher.fetch(lab, new URL(url), { budget: budget() }), url).toMatchObject({ ok: false, reason: "out-of-scope" });
    }
    expect(requests).toHaveLength(1);
  });
});
