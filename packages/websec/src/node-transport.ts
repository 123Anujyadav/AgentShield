import { Resolver as DnsResolver, lookup } from "node:dns/promises";
import type { LookupAddress } from "node:dns";
import { request as httpRequest, type IncomingMessage, type RequestOptions } from "node:http";
import { request as httpsRequest } from "node:https";
import { checkServerIdentity, type PeerCertificate, type TLSSocket } from "node:tls";
import type { AddressFamily } from "./address.js";
import type { CertificateSummary, Resolver, TlsDetails, Transport, TransportRequest } from "./fetcher.js";

/**
 * Real network implementations (M1). They are only used when outbound scanning
 * (or lab mode) is explicitly enabled; every automated test uses fakes. Node's
 * http and https modules do not read HTTP_PROXY/HTTPS_PROXY, and no agent or
 * proxy is configured here, so ambient proxy settings cannot redirect a request.
 */

type LookupCallback = (error: NodeJS.ErrnoException | null, address: string | LookupAddress[], family?: number) => void;

/**
 * A lookup function that ignores the host name and always answers with the one
 * address the guard already validated. This is the connection pin: the socket
 * cannot reach any other address, whatever DNS says at connect time.
 */
export function pinnedLookup(address: string, family: AddressFamily) {
  return (_hostname: string, options: { all?: boolean } | number | undefined, callback?: LookupCallback): void => {
    const cb = (typeof options === "function" ? options : callback) as LookupCallback;
    if (typeof options === "object" && options?.all) cb(null, [{ address, family }]);
    else cb(null, address, family);
  };
}

export interface NodeTransportOptions {
  /**
   * Trust anchors replacing Node's default CA store, for private or test roots.
   * Omitted in production, where the default store applies.
   */
  ca?: string | string[];
}

/** Request options for one pinned request. Pure, so it can be tested without a network. */
export function buildRequestOptions(
  request: TransportRequest,
  options: NodeTransportOptions = {},
): RequestOptions & { servername?: string; rejectUnauthorized?: boolean; ca?: string | string[] } {
  const https = request.url.protocol === "https:";
  const host = request.url.hostname.replace(/^\[|\]$/g, "");
  return {
    protocol: request.url.protocol,
    host,
    port: request.port,
    path: `${request.url.pathname}${request.url.search}`,
    method: request.method,
    headers: { ...request.headers },
    lookup: pinnedLookup(request.address, request.family) as unknown as RequestOptions["lookup"],
    agent: false,
    signal: request.signal,
    ...(https
      ? {
          servername: request.servername ?? undefined,
          // The certificate is evaluated (and reported) below instead of failing the
          // connection, so an invalid certificate becomes a finding, not a blind error.
          rejectUnauthorized: false,
          ...(options.ca !== undefined ? { ca: options.ca } : {}),
        }
      : {}),
  };
}

/** True when the certificate is valid for the host name (Node's own identity rules). */
export function certificateMatchesHostname(hostname: string, certificate: Partial<PeerCertificate>): boolean {
  try {
    return checkServerIdentity(hostname, certificate as PeerCertificate) === undefined;
  } catch {
    return false;
  }
}

/** Keeps only a fixed-format error code, never free text from the peer. */
export function sanitizeAuthorizationError(error: unknown): string | null {
  if (error === null || error === undefined) return null;
  const raw = typeof error === "string" ? error : ((error as { code?: unknown }).code ?? (error as Error).message);
  return typeof raw === "string" && /^[A-Z0-9_]{1,64}$/.test(raw) ? raw : "UNKNOWN";
}

export function summarizeCertificate(certificate: Partial<PeerCertificate>): CertificateSummary {
  const cn = (value: unknown) => (typeof value === "string" ? value.slice(0, 255) : null);
  const altNames = typeof certificate.subjectaltname === "string"
    ? certificate.subjectaltname.split(",").map((entry) => entry.trim()).filter(Boolean).slice(0, 20)
    : [];
  return {
    subjectCN: cn((certificate.subject as { CN?: unknown } | undefined)?.CN),
    issuerCN: cn((certificate.issuer as { CN?: unknown } | undefined)?.CN),
    subjectAltNames: altNames,
    validFrom: typeof certificate.valid_from === "string" ? certificate.valid_from : null,
    validTo: typeof certificate.valid_to === "string" ? certificate.valid_to : null,
  };
}

function describeTls(socket: TLSSocket, servername: string | null): TlsDetails {
  const certificate = socket.getPeerCertificate();
  const present = certificate !== null && Object.keys(certificate).length > 0;
  return {
    protocol: socket.getProtocol() ?? null,
    authorized: socket.authorized,
    authorizationError: sanitizeAuthorizationError(socket.authorizationError),
    hostnameMatches: present && servername !== null ? certificateMatchesHostname(servername, certificate) : false,
    certificate: present ? summarizeCertificate(certificate) : null,
  };
}

/** The real transport. Only the trust store can be changed; pinning and TLS reporting are fixed. */
export function createNodeTransport(options: NodeTransportOptions = {}): Transport {
  return (request) =>
    new Promise((resolve, reject) => {
      const https = request.url.protocol === "https:";
      const send = https ? httpsRequest : httpRequest;
      const outgoing = send(buildRequestOptions(request, options), (response: IncomingMessage) => {
        const tls = https ? describeTls(response.socket as TLSSocket, request.servername) : null;
        let closed = false;
        resolve({
          status: response.statusCode ?? 0,
          headers: response.headers,
          body: response,
          tls,
          close: () => {
            if (closed) return;
            closed = true;
            response.destroy();
          },
        });
      });
      outgoing.on("error", reject);
      outgoing.end();
    });
}

/** The production transport: Node's default trust store. */
export const nodeTransport: Transport = createNodeTransport();

/** System resolver (getaddrinfo): every address for the name, in the order returned. */
export const systemResolver: Resolver = (hostname) => lookup(hostname, { all: true, verbatim: true });

export type TxtResolver = (name: string, signal: AbortSignal) => Promise<string[][]>;

/** DNS TXT lookup with a short timeout; cancelled when the signal aborts. */
export const systemTxtResolver: TxtResolver = async (name, signal) => {
  const resolver = new DnsResolver({ timeout: 5000, tries: 2 });
  const cancel = () => resolver.cancel();
  signal.addEventListener("abort", cancel, { once: true });
  try {
    return await resolver.resolveTxt(name);
  } finally {
    signal.removeEventListener("abort", cancel);
  }
};
