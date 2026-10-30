import { gzipSync } from "node:zlib";
import { describe, expect, it } from "vitest";
import {
  GuardedFetcher,
  PREFIX_RANGE_HEADER,
  PREFIX_READ_BYTES,
  RequestBudget,
  type FetchOptions,
  type FetchResult,
  type PrefixRead,
  type Transport,
  type TransportRequest,
} from "./fetcher.js";
import { runPassiveScan } from "./scan.js";
import type { DnsTarget } from "./target.js";

/**
 * Prefix mode (M2-B). Every body here is a generated in-memory stream behind a
 * fake transport; nothing touches the network.
 */

const target: DnsTarget = { kind: "dns", hostname: "example.com", displayHostname: "example.com" };
const PUBLIC = [{ address: "93.184.215.14", family: 4 }];
const URL_ = new URL("https://example.com/probe");

/** Deterministic content: byte i of the body is (i * 7 + 3) & 0xff. */
const patternByte = (i: number) => (i * 7 + 3) & 0xff;

interface StreamStats {
  pulled: number;
  bytesYielded: number;
  returned: boolean;
  closed: number;
}

/**
 * A generated body stream. `total` bytes in `chunkSize` chunks (Infinity: never ends);
 * `hangAfter` chunks, then it waits forever; `failAfter` chunks, then it throws.
 */
function generated(stats: StreamStats, spec: { total?: number; chunkSize?: number; hangAfter?: number; failAfter?: number }) {
  const total = spec.total ?? Infinity;
  const chunkSize = spec.chunkSize ?? 1000;
  return {
    async *[Symbol.asyncIterator]() {
      try {
        for (let offset = 0; offset < total; offset += chunkSize) {
          if (spec.hangAfter !== undefined && stats.pulled >= spec.hangAfter) await new Promise(() => {});
          if (spec.failAfter !== undefined && stats.pulled >= spec.failAfter) throw new Error("connection reset");
          const size = Math.min(chunkSize, total - offset);
          const chunk = new Uint8Array(size);
          for (let i = 0; i < size; i += 1) chunk[i] = patternByte(offset + i);
          stats.pulled += 1;
          stats.bytesYielded += size;
          yield chunk;
        }
      } finally {
        stats.returned = true;
      }
    },
  };
}

function setup(
  respond: (request: TransportRequest, stats: StreamStats) => { status: number; headers?: Record<string, string | string[]>; body: AsyncIterable<Uint8Array> | null },
  options: { timeoutMs?: number; maxBodyBytes?: number } = {},
) {
  const requests: TransportRequest[] = [];
  const stats: StreamStats = { pulled: 0, bytesYielded: 0, returned: false, closed: 0 };
  const transport: Transport = async (request) => {
    requests.push(request);
    const { status, headers, body } = respond(request, stats);
    return { status, headers: headers ?? {}, body, tls: null, close: () => (stats.closed += 1) };
  };
  const fetcher = new GuardedFetcher({ resolver: async () => PUBLIC, transport, ...options });
  return { fetcher, requests, stats };
}

const prefixOf = (result: FetchResult): PrefixRead => {
  if (!result.ok || !result.prefix) throw new Error(`expected a prefix read, got ${JSON.stringify(result)}`);
  return result.prefix;
};
const expectedBytes = (n: number) => Buffer.from(Array.from({ length: n }, (_, i) => patternByte(i)));

describe("guarded fetcher: prefix mode reads at most 4,096 bytes", () => {
  it("reads exactly 4,096 bytes from a larger generated stream and marks it truncated", async () => {
    const { fetcher, stats } = setup((_r, s) => ({ status: 200, body: generated(s, { total: 50_000, chunkSize: 1000 }) }));
    const result = await fetcher.fetch(target, URL_, { budget: new RequestBudget(30), readPrefix: true });
    const prefix = prefixOf(result);
    expect(prefix.kind).toBe("read");
    if (prefix.kind !== "read") return;
    expect(prefix.bytes.length).toBe(PREFIX_READ_BYTES);
    expect(prefix.bytes.equals(expectedBytes(PREFIX_READ_BYTES))).toBe(true);
    expect(prefix.truncated).toBe(true);
    expect(result.ok && result.body).toBeNull(); // the bytes live only in result.prefix
  });

  it("stops pulling from the stream at the cap, releases it and closes the response", async () => {
    const { fetcher, stats } = setup((_r, s) => ({ status: 200, body: generated(s, { chunkSize: 1000 }) })); // never ends
    const prefix = prefixOf(await fetcher.fetch(target, URL_, { budget: new RequestBudget(30), readPrefix: true }));
    expect(prefix.kind === "read" && prefix.bytes.length).toBe(PREFIX_READ_BYTES);
    // 4 full chunks + 96 bytes of the fifth; the sixth is never requested.
    expect([stats.pulled, stats.returned, stats.closed]).toEqual([5, true, 1]);
  });

  it("returns the bytes actually read when the body is shorter, not truncated", async () => {
    const { fetcher, stats } = setup((_r, s) => ({ status: 200, body: generated(s, { total: 1500, chunkSize: 1000 }) }));
    const prefix = prefixOf(await fetcher.fetch(target, URL_, { budget: new RequestBudget(30), readPrefix: true }));
    expect(prefix).toEqual({ kind: "read", bytes: expectedBytes(1500), truncated: false });
    expect(stats.closed).toBe(1);
    const empty = setup(() => ({ status: 200, body: null }));
    expect(prefixOf(await empty.fetcher.fetch(target, URL_, { budget: new RequestBudget(30), readPrefix: true }))).toEqual({
      kind: "read",
      bytes: Buffer.alloc(0),
      truncated: false,
    });
  });

  it("copies only the kept bytes when one chunk is far larger than the cap", async () => {
    const { fetcher, stats } = setup((_r, s) => ({ status: 200, body: generated(s, { total: 1_000_000, chunkSize: 1_000_000 }) }));
    const prefix = prefixOf(await fetcher.fetch(target, URL_, { budget: new RequestBudget(30), readPrefix: true }));
    if (prefix.kind !== "read") throw new Error("expected bytes");
    expect([prefix.bytes.length, prefix.bytes.buffer.byteLength <= 8192, prefix.truncated]).toEqual([PREFIX_READ_BYTES, true, true]);
    expect(stats.pulled).toBe(1);
  });

  it("never reads more than the fetcher's hard body cap, if that is smaller", async () => {
    const { fetcher } = setup((_r, s) => ({ status: 200, body: generated(s, { chunkSize: 64 }) }), { maxBodyBytes: 100 });
    const prefix = prefixOf(await fetcher.fetch(target, URL_, { budget: new RequestBudget(30), readPrefix: true }));
    expect(prefix.kind === "read" && [prefix.bytes.length, prefix.truncated]).toEqual([100, true]);
  });
});

describe("guarded fetcher: the fixed Range header", () => {
  it("sends Range: bytes=0-4095 in prefix mode only, and never in normal (M1) fetches", async () => {
    const { fetcher, requests } = setup((_r, s) => ({ status: 200, body: generated(s, { total: 10 }) }));
    await fetcher.fetch(target, URL_, { budget: new RequestBudget(30), readPrefix: true });
    await fetcher.fetch(target, URL_, { budget: new RequestBudget(30) });
    await fetcher.fetch(target, URL_, { budget: new RequestBudget(30), readBodyBytes: 32 * 1024 });
    await fetcher.fetch(target, URL_, { budget: new RequestBudget(30), readPrefix: false });
    expect(PREFIX_RANGE_HEADER).toBe("bytes=0-4095");
    expect(requests.map((r) => r.headers.range)).toEqual(["bytes=0-4095", undefined, undefined, undefined]);
    // Prefix mode changes nothing else about the request.
    const { range, ...rest } = requests[0]!.headers;
    expect(range).toBeDefined();
    expect(rest).toEqual(requests[1]!.headers);
    expect(rest["accept-encoding"]).toBe("identity");
  });

  it("only the exact value true enables prefix mode", async () => {
    const { fetcher, requests } = setup((_r, s) => ({ status: 200, body: generated(s, { total: 10 }) }));
    for (const value of ["true", 1, "yes", {}] as unknown[]) {
      const result = await fetcher.fetch(target, URL_, { budget: new RequestBudget(30), readPrefix: value } as FetchOptions);
      expect(result.ok && result.prefix).toBeUndefined();
    }
    expect(requests.every((r) => r.headers.range === undefined)).toBe(true);
  });

  it("a caller cannot set or override the Range value, the size or any header", async () => {
    const { fetcher, requests } = setup((_r, s) => ({ status: 200, body: generated(s, { chunkSize: 1000 }) }));
    const hostile = {
      budget: new RequestBudget(30),
      readPrefix: true,
      readBodyBytes: 1_000_000,
      range: "bytes=0-999999",
      headers: { range: "bytes=100-200", Range: "bytes=5-", cookie: "sid=1", authorization: "Basic eA==" },
      prefixBytes: 1_000_000,
    } as unknown as FetchOptions;
    const prefix = prefixOf(await fetcher.fetch(target, URL_, hostile));
    expect(prefix.kind === "read" && prefix.bytes.length).toBe(PREFIX_READ_BYTES);
    expect(requests[0]!.headers.range).toBe("bytes=0-4095");
    expect(Object.keys(requests[0]!.headers).sort()).toEqual(["accept", "accept-encoding", "connection", "host", "range", "user-agent"]);
    // A caller-chosen Range never appears in a normal fetch either.
    await fetcher.fetch(target, URL_, { ...hostile, readPrefix: undefined } as unknown as FetchOptions);
    expect(requests[1]!.headers.range).toBeUndefined();
  });

  it("a server that ignores Range and sends a large 200 still yields at most 4,096 bytes", async () => {
    const { fetcher, stats } = setup((request, s) => {
      expect(request.headers.range).toBe("bytes=0-4095");
      return { status: 200, headers: { "content-length": "10000000" }, body: generated(s, { total: 10_000_000, chunkSize: 16_384 }) };
    });
    const prefix = prefixOf(await fetcher.fetch(target, URL_, { budget: new RequestBudget(30), readPrefix: true }));
    expect(prefix.kind === "read" && [prefix.bytes.length, prefix.truncated]).toEqual([PREFIX_READ_BYTES, true]);
    expect([stats.pulled, stats.bytesYielded, stats.returned, stats.closed]).toEqual([1, 16_384, true, 1]);
  });

  it("handles 206 Partial Content: reads the range, and caps a server that sends more than asked", async () => {
    const honest = setup((_r, s) => ({
      status: 206,
      headers: { "content-range": "bytes 0-4095/90000" },
      body: generated(s, { total: 4096, chunkSize: 512 }),
    }));
    const result = await honest.fetcher.fetch(target, URL_, { budget: new RequestBudget(30), readPrefix: true });
    expect(result.ok && [result.status, result.headers["content-range"]]).toEqual([206, ["bytes 0-4095/90000"]]);
    expect(prefixOf(result)).toEqual({ kind: "read", bytes: expectedBytes(4096), truncated: true });
    const short = setup((_r, s) => ({ status: 206, headers: { "content-range": "bytes 0-99/100" }, body: generated(s, { total: 100 }) }));
    expect(prefixOf(await short.fetcher.fetch(target, URL_, { budget: new RequestBudget(30), readPrefix: true }))).toEqual({
      kind: "read",
      bytes: expectedBytes(100),
      truncated: false,
    });
    const overlong = setup((_r, s) => ({ status: 206, body: generated(s, { chunkSize: 4000 }) }));
    const capped = prefixOf(await overlong.fetcher.fetch(target, URL_, { budget: new RequestBudget(30), readPrefix: true }));
    expect(capped.kind === "read" && capped.bytes.length).toBe(PREFIX_READ_BYTES);
    expect([overlong.stats.pulled, overlong.stats.closed]).toEqual([2, 1]);
  });

  it("handles 416 safely: the body is not read and the response is closed", async () => {
    const { fetcher, stats } = setup((_r, s) => ({ status: 416, headers: { "content-range": "bytes */0" }, body: generated(s, { total: 5000 }) }));
    const result = await fetcher.fetch(target, URL_, { budget: new RequestBudget(30), readPrefix: true });
    expect(result.ok && result.status).toBe(416);
    expect(prefixOf(result)).toEqual({ kind: "not-read", reason: "range-not-satisfiable" });
    expect([stats.pulled, stats.closed]).toEqual([0, 1]);
  });

  it("never follows a redirect in prefix mode, even when asked to, and does not read its body", async () => {
    const { fetcher, requests, stats } = setup((_r, s) => ({ status: 302, headers: { location: "/elsewhere" }, body: generated(s, { total: 100 }) }));
    const budget = new RequestBudget(30);
    const result = await fetcher.fetch(target, URL_, { budget, readPrefix: true, followRedirects: true });
    expect(result.ok && [result.status, result.hops]).toEqual([302, []]);
    expect(prefixOf(result)).toEqual({ kind: "not-read", reason: "redirect" });
    expect([requests.length, budget.spent, stats.pulled, stats.closed]).toEqual([1, 1, 0, 1]);
  });
});

describe("guarded fetcher: encoded bodies are never decoded in prefix mode", () => {
  it.each([
    [{ "content-encoding": "gzip" }, "gzip"],
    [{ "content-encoding": "BR" }, "br"],
    [{ "content-encoding": ["deflate", "gzip"] }, "deflate, gzip"],
    [{ "content-encoding": "identity, zstd" }, "zstd"],
    [{ "transfer-encoding": "gzip, chunked" }, "gzip"],
    [{ "content-encoding": "x<script>" }, "unrecognized"],
  ])("%j is marked unsuitable (%s) and its body is left unread", async (headers, encoding) => {
    const { fetcher, stats } = setup(() => ({ status: 200, headers, body: (async function* () { stats.pulled += 1; yield new Uint8Array(gzipSync("secret-looking body")); })() }));
    const result = await fetcher.fetch(target, URL_, { budget: new RequestBudget(30), readPrefix: true });
    expect(prefixOf(result)).toEqual({ kind: "encoded", encoding });
    expect(result.ok && result.body).toBeNull();
    expect([stats.pulled, stats.closed]).toEqual([0, 1]);
    expect(JSON.stringify(result)).not.toContain("secret-looking");
  });

  it("identity and chunked alone are not encodings", async () => {
    const { fetcher } = setup((_r, s) => ({ status: 200, headers: { "content-encoding": "identity", "transfer-encoding": "chunked" }, body: generated(s, { total: 10 }) }));
    expect(prefixOf(await fetcher.fetch(target, URL_, { budget: new RequestBudget(30), readPrefix: true })).kind).toBe("read");
  });

  it("M1 reads still decode compressed bodies exactly as before", async () => {
    const text = "Contact: mailto:security@example.com\n";
    const { fetcher } = setup(() => ({ status: 200, headers: { "content-encoding": "gzip" }, body: (async function* () { yield new Uint8Array(gzipSync(text)); })() }));
    const result = await fetcher.fetch(target, URL_, { budget: new RequestBudget(30), readBodyBytes: 1000 });
    expect(result.ok && [result.body?.toString(), result.prefix]).toEqual([text, undefined]);
  });
});

describe("guarded fetcher: prefix reads end cleanly on timeout, abort and error", () => {
  it("times out while the body stalls mid-prefix, then releases the stream and closes the response", async () => {
    const { fetcher, stats } = setup((_r, s) => ({ status: 200, body: generated(s, { chunkSize: 1000, hangAfter: 2 }) }), { timeoutMs: 30 });
    const result = await fetcher.fetch(target, URL_, { budget: new RequestBudget(30), readPrefix: true });
    expect(result).toMatchObject({ ok: false, reason: "timeout" });
    expect([stats.pulled, stats.closed]).toEqual([2, 1]);
  });

  it("stops when the caller aborts mid-prefix, then closes the response", async () => {
    const controller = new AbortController();
    const { fetcher, stats } = setup((_r, s) => ({ status: 200, body: generated(s, { chunkSize: 1000, hangAfter: 1 }) }));
    const pending = fetcher.fetch(target, URL_, { budget: new RequestBudget(30), readPrefix: true, signal: controller.signal });
    setTimeout(() => controller.abort(), 10);
    expect(await pending).toMatchObject({ ok: false, reason: "cancelled" });
    expect([stats.pulled, stats.closed]).toEqual([1, 1]);
  });

  it("a stream error mid-prefix is a connection failure; the stream is released and the response closed", async () => {
    const { fetcher, stats } = setup((_r, s) => ({ status: 200, body: generated(s, { chunkSize: 1000, failAfter: 2 }) }));
    const result = await fetcher.fetch(target, URL_, { budget: new RequestBudget(30), readPrefix: true });
    expect(result).toMatchObject({ ok: false, reason: "connection-failed" });
    expect([stats.pulled, stats.returned, stats.closed]).toEqual([2, true, 1]);
  });
});

describe("M1 requests are unchanged by prefix mode", () => {
  it("the passive scan never sends Range and never gets a prefix result", async () => {
    const requests: TransportRequest[] = [];
    const transport: Transport = async (request) => {
      requests.push(request);
      return { status: 200, headers: {}, body: null, tls: null, close: () => {} };
    };
    const fetcher = new GuardedFetcher({ resolver: async () => PUBLIC, transport });
    await runPassiveScan({ target, fetcher, budget: new RequestBudget(30) });
    expect(requests).toHaveLength(3);
    expect(requests.every((r) => !("range" in r.headers))).toBe(true);
  });
});
