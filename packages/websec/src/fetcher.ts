import { brotliDecompressSync, gunzipSync, inflateSync } from "node:zlib";
import { classifyResolution, type AddressFamily, type BlockReason } from "./address.js";
import { isInScope, type ScanTarget } from "./target.js";

/**
 * Guarded fetcher (M1): the single boundary through which a scan touches the
 * network. For every request, including every redirect hop, it:
 *
 *  1. checks the URL is inside the target's exact scope;
 *  2. resolves the host name and refuses the request if any address is blocked;
 *  3. takes one unit from the scan's request budget (requests actually sent);
 *  4. hands the transport one validated address to connect to (pinning), so the
 *     transport never resolves the name again (no DNS-rebinding window);
 *  5. sends only fixed headers (never cookies or credentials), with a timeout,
 *     one active request per host, and bounded, optionally decoded bodies.
 *
 * The resolver and transport are injected; tests use fakes and never touch the network.
 */

export type Resolver = (hostname: string, signal: AbortSignal) => Promise<unknown>;

export interface TransportRequest {
  url: URL;
  /** The validated address to connect to. A transport must not resolve the host name itself. */
  address: string;
  family: AddressFamily;
  port: number;
  /** TLS server name for SNI and certificate checks (https only); always the original host name. */
  servername: string | null;
  method: "GET";
  headers: Readonly<Record<string, string>>;
  signal: AbortSignal;
}

export interface CertificateSummary {
  subjectCN: string | null;
  issuerCN: string | null;
  subjectAltNames: string[];
  validFrom: string | null;
  validTo: string | null;
}

export interface TlsDetails {
  protocol: string | null;
  /**
   * Node's verdict for the connection: false when the chain does not validate
   * against the trusted roots, and also when the certificate does not match the
   * requested host name (Node then sets authorizationError to
   * ERR_TLS_CERT_ALTNAME_INVALID). The connection is not refused either way;
   * the TLS check reports the problem.
   */
  authorized: boolean;
  /** Verification error code such as CERT_HAS_EXPIRED; never free text. */
  authorizationError: string | null;
  /** True when the certificate is valid for the requested host name. */
  hostnameMatches: boolean;
  certificate: CertificateSummary | null;
}

export interface TransportResponse {
  status: number;
  headers: Record<string, string | string[] | undefined>;
  body: AsyncIterable<Uint8Array> | null;
  tls: TlsDetails | null;
  /** Releases the connection and discards any unread body. Must be safe to call twice. */
  close(): void;
}

export type Transport = (request: TransportRequest) => Promise<TransportResponse>;

/** Per-scan request budget. Every attempt, including each redirect hop, uses one unit. */
export class RequestBudget {
  private used = 0;
  constructor(readonly limit: number) {}
  take(): boolean {
    if (this.used >= this.limit) return false;
    this.used += 1;
    return true;
  }
  get spent(): number {
    return this.used;
  }
  get remaining(): number {
    return this.limit - this.used;
  }
}

/** Serializes requests per host: at most one active request to a host at any time. */
export class HostGate {
  private readonly tails = new Map<string, Promise<void>>();
  private readonly active = new Map<string, number>();

  async run<T>(host: string, task: () => Promise<T>): Promise<T> {
    const previous = this.tails.get(host) ?? Promise.resolve();
    let release!: () => void;
    const current = new Promise<void>((resolve) => {
      release = resolve;
    });
    const tail = previous.then(() => current);
    this.tails.set(host, tail);
    await previous;
    this.active.set(host, (this.active.get(host) ?? 0) + 1);
    try {
      return await task();
    } finally {
      const remaining = (this.active.get(host) ?? 1) - 1;
      if (remaining === 0) this.active.delete(host);
      else this.active.set(host, remaining);
      release();
      if (this.tails.get(host) === tail) this.tails.delete(host);
    }
  }

  /** Requests currently in flight for a host (0 or 1). */
  activeFor(host: string): number {
    return this.active.get(host) ?? 0;
  }
}

export type FetchFailureReason =
  | "out-of-scope"
  | "redirect-out-of-scope"
  | "invalid-redirect"
  | "too-many-redirects"
  | "request-budget-exceeded"
  | "dns-failure"
  | "blocked-address"
  | "malformed-resolution"
  | "timeout"
  | "cancelled"
  | "connection-failed"
  | "body-too-large"
  | "decompressed-too-large"
  | "unsupported-encoding"
  | "invalid-encoding";

export interface FetchHop {
  url: string;
  status: number;
}

export type NormalizedHeaders = Record<string, string[]>;

export type FetchResult =
  | {
      ok: true;
      url: URL;
      status: number;
      headers: NormalizedHeaders;
      body: Buffer | null;
      tls: TlsDetails | null;
      hops: FetchHop[];
      /** Present only when the fetch was made in prefix mode (readPrefix: true). */
      prefix?: PrefixRead;
    }
  | { ok: false; reason: FetchFailureReason; url: URL; hops: FetchHop[]; blockReason?: BlockReason | "empty" };

export interface FetcherOptions {
  resolver: Resolver;
  transport: Transport;
  timeoutMs?: number;
  maxRedirects?: number;
  maxBodyBytes?: number;
  hostGate?: HostGate;
  userAgent?: string;
}

export interface FetchOptions {
  budget: RequestBudget;
  /** Follow same-host redirects (default true). When false, a 3xx response is returned as is. */
  followRedirects?: boolean;
  /** Bytes of body to read (capped at maxBodyBytes); 0 or absent discards the body unread. */
  readBodyBytes?: number;
  /** A fixed Origin to send (CORS probe). Must be an https origin. */
  probeOrigin?: string;
  signal?: AbortSignal;
  /**
   * Prefix mode (M2): send the fixed header Range: bytes=0-4095, never follow a
   * redirect, never decode, and read at most the first PREFIX_READ_BYTES of the
   * body into result.prefix. Only the exact value true enables it; it replaces
   * readBodyBytes and followRedirects for that fetch.
   */
  readPrefix?: boolean;
}

/** The fixed prefix size. Callers can switch prefix mode on, but never choose a size or a range. */
export const PREFIX_READ_BYTES = 4096;
export const PREFIX_RANGE_HEADER = `bytes=0-${PREFIX_READ_BYTES - 1}`;

/**
 * What prefix mode read. Bodies are inspected only as sent with no encoding: an
 * encoded body is left unread (never decoded, never kept), so a later stage can
 * treat it as inconclusive.
 */
export type PrefixRead =
  | {
      kind: "read";
      /** The bytes actually read: at most PREFIX_READ_BYTES. */
      bytes: Buffer;
      /** True when reading stopped at the limit: the body was at least PREFIX_READ_BYTES long and anything after was never read. */
      truncated: boolean;
    }
  | {
      kind: "encoded";
      /** The declared codings, normalized (lower-case tokens; anything malformed becomes "unrecognized"). */
      encoding: string;
    }
  | {
      kind: "not-read";
      /** A 3xx response (never followed in prefix mode) or a 416 (no satisfiable range). */
      reason: "redirect" | "range-not-satisfiable";
    };

export const DEFAULT_TIMEOUT_MS = 10_000;
export const DEFAULT_MAX_REDIRECTS = 5;
export const DEFAULT_MAX_BODY_BYTES = 1_048_576;
export const DEFAULT_USER_AGENT = "AgentShield-PassiveScanner/0.1 (owner-verified passive checks)";
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

class FetchAbort extends Error {
  constructor(readonly reason: FetchFailureReason) {
    super(reason);
  }
}

/** Lower-cases header names and turns every value into a list of strings. */
export function normalizeHeaders(headers: TransportResponse["headers"]): NormalizedHeaders {
  const out: NormalizedHeaders = {};
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined) continue;
    const key = name.toLowerCase();
    out[key] = [...(out[key] ?? []), ...(Array.isArray(value) ? value : [value]).map(String)];
  }
  return out;
}

/** Settles with the promise, or rejects as soon as the signal aborts. Always removes its listener. */
function untilAborted<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) {
    promise.catch(() => {});
    return Promise.reject(new Error("aborted"));
  }
  return new Promise<T>((resolve, reject) => {
    const onAbort = () => reject(new Error("aborted"));
    signal.addEventListener("abort", onAbort, { once: true });
    promise.then(
      (value) => {
        signal.removeEventListener("abort", onAbort);
        resolve(value);
      },
      (error: unknown) => {
        signal.removeEventListener("abort", onAbort);
        reject(error);
      },
    );
  });
}

async function readCapped(body: AsyncIterable<Uint8Array> | null, cap: number, signal: AbortSignal): Promise<Buffer> {
  if (!body) return Buffer.alloc(0);
  const chunks: Buffer[] = [];
  let total = 0;
  const iterator = body[Symbol.asyncIterator]();
  try {
    for (;;) {
      if (signal.aborted) throw new Error("aborted");
      const { done, value } = await untilAborted(iterator.next(), signal);
      if (done) break;
      total += value.byteLength;
      if (total > cap) throw new FetchAbort("body-too-large");
      chunks.push(Buffer.from(value));
    }
  } finally {
    // Stops the underlying stream on early exit; harmless when it already ended.
    void iterator.return?.()?.catch?.(() => {});
  }
  return Buffer.concat(chunks);
}

const PASS_THROUGH_CODINGS = new Set(["identity", "chunked"]);

/**
 * The codings that would have to be undone before a body could be inspected:
 * every Content-Encoding coding, plus any Transfer-Encoding coding other than
 * chunked (Node removes chunking but nothing else). Returns null when there are none.
 */
function bodyEncoding(headers: NormalizedHeaders): string | null {
  const codings = [...(headers["content-encoding"] ?? []), ...(headers["transfer-encoding"] ?? [])]
    .flatMap((value) => value.split(","))
    .map((token) => token.trim().toLowerCase())
    .filter((token) => token !== "" && !PASS_THROUGH_CODINGS.has(token))
    .map((token) => (/^[a-z0-9._+-]{1,32}$/.test(token) ? token : "unrecognized"));
  const unique = [...new Set(codings)];
  return unique.length === 0 ? null : unique.slice(0, 4).join(", ");
}

/**
 * Reads at most `cap` bytes. Stops pulling from the stream as soon as the cap is
 * reached; only the bytes kept are copied, and the stream is released on every
 * exit (the caller also closes the response).
 */
async function readPrefixBytes(body: AsyncIterable<Uint8Array> | null, cap: number, signal: AbortSignal): Promise<PrefixRead> {
  if (!body) return { kind: "read", bytes: Buffer.alloc(0), truncated: false };
  const chunks: Buffer[] = [];
  let total = 0;
  const iterator = body[Symbol.asyncIterator]();
  try {
    while (total < cap) {
      if (signal.aborted) throw new Error("aborted");
      const { done, value } = await untilAborted(iterator.next(), signal);
      if (done) break;
      const take = Math.min(value.byteLength, cap - total);
      chunks.push(Buffer.from(value.subarray(0, take)));
      total += take;
    }
  } finally {
    void iterator.return?.()?.catch?.(() => {});
  }
  return { kind: "read", bytes: Buffer.concat(chunks, total), truncated: total >= cap };
}

async function readPrefix(response: TransportResponse, headers: NormalizedHeaders, cap: number, signal: AbortSignal): Promise<PrefixRead> {
  // 3xx bodies are never inspected, and 416 means the server had no bytes for the range.
  if (response.status >= 300 && response.status < 400) return { kind: "not-read", reason: "redirect" };
  if (response.status === 416) return { kind: "not-read", reason: "range-not-satisfiable" };
  const encoding = bodyEncoding(headers);
  if (encoding !== null) return { kind: "encoded", encoding };
  return readPrefixBytes(response.body, cap, signal);
}

/** Decodes a bounded body. The decoded size is capped too (decompression bombs). */
export function decodeBody(body: Buffer, contentEncoding: string | undefined, cap: number): Buffer {
  const encoding = (contentEncoding ?? "").trim().toLowerCase();
  try {
    if (encoding === "" || encoding === "identity") return body;
    if (encoding === "gzip" || encoding === "x-gzip") return gunzipSync(body, { maxOutputLength: cap });
    if (encoding === "deflate") return inflateSync(body, { maxOutputLength: cap });
    if (encoding === "br") return brotliDecompressSync(body, { maxOutputLength: cap });
  } catch (error) {
    if (error instanceof RangeError || (error as { code?: string }).code === "ERR_BUFFER_TOO_LARGE") {
      throw new FetchAbort("decompressed-too-large");
    }
    throw new FetchAbort("invalid-encoding");
  }
  throw new FetchAbort("unsupported-encoding");
}

export class GuardedFetcher {
  private readonly timeoutMs: number;
  private readonly maxRedirects: number;
  private readonly maxBodyBytes: number;
  private readonly hostGate: HostGate;
  private readonly userAgent: string;

  constructor(private readonly options: FetcherOptions) {
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.maxRedirects = options.maxRedirects ?? DEFAULT_MAX_REDIRECTS;
    this.maxBodyBytes = options.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
    this.hostGate = options.hostGate ?? new HostGate();
    this.userAgent = options.userAgent ?? DEFAULT_USER_AGENT;
  }

  async fetch(target: ScanTarget, start: URL, options: FetchOptions): Promise<FetchResult> {
    const hops: FetchHop[] = [];
    let url = start;
    for (let redirects = 0; ; ) {
      const fail = (reason: FetchFailureReason, blockReason?: BlockReason | "empty"): FetchResult => ({
        ok: false,
        reason,
        url,
        hops,
        ...(blockReason ? { blockReason } : {}),
      });
      if (!isInScope(url, target)) return fail(redirects === 0 ? "out-of-scope" : "redirect-out-of-scope");
      if (options.signal?.aborted) return fail("cancelled");

      const pinned = await this.resolve(target, options.signal);
      if (!pinned.ok) return fail(pinned.reason, pinned.blockReason);
      // The budget counts requests actually sent, so a refused address uses none.
      if (!options.budget.take()) return fail("request-budget-exceeded");

      let result: Awaited<ReturnType<GuardedFetcher["send"]>>;
      try {
        result = await this.hostGate.run(target.hostname, () => this.send(target, url, pinned, options));
      } catch (error) {
        return fail(error instanceof FetchAbort ? error.reason : "connection-failed");
      }

      const location = result.headers.location?.[0];
      const follow = options.readPrefix !== true && options.followRedirects !== false;
      if (follow && REDIRECT_STATUSES.has(result.status) && location !== undefined) {
        hops.push({ url: url.href, status: result.status });
        if (redirects >= this.maxRedirects) return fail("too-many-redirects");
        let next: URL;
        try {
          next = new URL(location, url);
        } catch {
          return fail("invalid-redirect");
        }
        redirects += 1;
        url = next;
        continue; // Re-checks scope, budget and DNS for the next hop.
      }
      return {
        ok: true,
        url,
        status: result.status,
        headers: result.headers,
        body: result.body,
        tls: result.tls,
        hops,
        ...(result.prefix ? { prefix: result.prefix } : {}),
      };
    }
  }

  /** Resolves and validates the target's addresses; lab targets use their configured loopback address only. */
  private async resolve(
    target: ScanTarget,
    signal: AbortSignal | undefined,
  ): Promise<
    | { ok: true; address: string; family: AddressFamily }
    | { ok: false; reason: FetchFailureReason; blockReason?: BlockReason | "empty" }
  > {
    if (target.kind === "lab") return { ok: true, address: target.address, family: target.family };
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    const onAbort = () => controller.abort();
    signal?.addEventListener("abort", onAbort, { once: true });
    let answers: unknown;
    try {
      answers = await untilAborted(this.options.resolver(target.hostname, controller.signal), controller.signal);
    } catch {
      return { ok: false, reason: signal?.aborted ? "cancelled" : controller.signal.aborted ? "timeout" : "dns-failure" };
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
    }
    const verdict = classifyResolution(answers);
    if (!verdict.ok) {
      const malformed = verdict.reason === "malformed" || verdict.reason === "empty";
      return { ok: false, reason: malformed ? "malformed-resolution" : "blocked-address", blockReason: verdict.reason };
    }
    const first = verdict.addresses[0]!;
    return { ok: true, address: first.address, family: first.family };
  }

  private async send(
    target: ScanTarget,
    url: URL,
    pinned: { address: string; family: AddressFamily },
    options: FetchOptions,
  ): Promise<{ status: number; headers: NormalizedHeaders; body: Buffer | null; tls: TlsDetails | null; prefix?: PrefixRead }> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    const onAbort = () => controller.abort();
    options.signal?.addEventListener("abort", onAbort, { once: true });
    const headers: Record<string, string> = {
      host: url.host,
      "user-agent": this.userAgent,
      accept: "*/*",
      "accept-encoding": "identity",
      connection: "close",
    };
    if (options.probeOrigin !== undefined && /^https:\/\/[a-z0-9.-]+$/.test(options.probeOrigin)) {
      headers.origin = options.probeOrigin;
    }
    const prefixMode = options.readPrefix === true;
    if (prefixMode) headers.range = PREFIX_RANGE_HEADER;
    const https = url.protocol === "https:";
    let response: TransportResponse | null = null;
    const pending = this.options.transport({
      url,
      address: pinned.address,
      family: pinned.family,
      port: url.port === "" ? (https ? 443 : 80) : Number(url.port),
      servername: https && target.kind === "dns" ? target.hostname : null,
      method: "GET",
      headers,
      signal: controller.signal,
    });
    try {
      response = await untilAborted(pending, controller.signal);
      const normalized = normalizeHeaders(response.headers);
      if (prefixMode) {
        const prefix = await readPrefix(response, normalized, Math.min(PREFIX_READ_BYTES, this.maxBodyBytes), controller.signal);
        return { status: response.status, headers: normalized, body: null, tls: response.tls, prefix };
      }
      const wanted = Math.min(options.readBodyBytes ?? 0, this.maxBodyBytes);
      let body: Buffer | null = null;
      if (wanted > 0 && !REDIRECT_STATUSES.has(response.status)) {
        const raw = await readCapped(response.body, wanted, controller.signal);
        body = decodeBody(raw, normalized["content-encoding"]?.at(-1), wanted);
      }
      return { status: response.status, headers: normalized, body, tls: response.tls };
    } catch (error) {
      if (error instanceof FetchAbort) throw error;
      if (options.signal?.aborted) throw new FetchAbort("cancelled");
      if (controller.signal.aborted) throw new FetchAbort("timeout");
      throw new FetchAbort("connection-failed");
    } finally {
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", onAbort);
      if (response) response.close();
      // A response that arrives after a timeout or cancellation is closed unread.
      else pending.then((late) => late.close(), () => {});
    }
  }
}
