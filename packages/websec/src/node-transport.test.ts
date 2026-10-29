import { describe, expect, it } from "vitest";
import type { TransportRequest } from "./fetcher.js";
import { buildRequestOptions, certificateMatchesHostname, pinnedLookup, sanitizeAuthorizationError, summarizeCertificate } from "./node-transport.js";

/** Offline tests of the real transport's pure parts. No socket is opened. */

function request(url: string, address = "93.184.215.14", family: 4 | 6 = 4): TransportRequest {
  const parsed = new URL(url);
  return {
    url: parsed,
    address,
    family,
    port: parsed.protocol === "https:" ? 443 : 80,
    servername: parsed.protocol === "https:" ? parsed.hostname : null,
    method: "GET",
    headers: { host: parsed.host, accept: "*/*" },
    signal: new AbortController().signal,
  };
}

describe("connection pinning", () => {
  it("the lookup answers with the validated address whatever name it is asked for", () => {
    const lookup = pinnedLookup("93.184.215.14", 4);
    const single: unknown[] = [];
    lookup("example.com", { all: false }, (...args) => single.push(args));
    lookup("rebound.attacker.example", {}, (...args) => single.push(args));
    expect(single).toEqual([
      [null, "93.184.215.14", 4],
      [null, "93.184.215.14", 4],
    ]);
    const all: unknown[] = [];
    lookup("example.com", { all: true }, (...args) => all.push(args));
    expect(all).toEqual([[null, [{ address: "93.184.215.14", family: 4 }]]]);
  });

  it("request options pin the address, keep the host name for Host and SNI, and use no agent or proxy", () => {
    const options = buildRequestOptions(request("https://example.com/.well-known/security.txt?x=1"));
    expect(options).toMatchObject({
      protocol: "https:",
      host: "example.com",
      port: 443,
      path: "/.well-known/security.txt?x=1",
      method: "GET",
      agent: false,
      servername: "example.com",
      rejectUnauthorized: false,
      headers: { host: "example.com", accept: "*/*" },
    });
    const answers: unknown[] = [];
    (options.lookup as unknown as ReturnType<typeof pinnedLookup>)("example.com", {}, (...args) => answers.push(args));
    expect(answers).toEqual([[null, "93.184.215.14", 4]]);

    const plain = buildRequestOptions(request("http://[::1]:8081/", "::1", 6));
    expect(plain).toMatchObject({ host: "::1", port: 80, protocol: "http:" });
    expect(plain).not.toHaveProperty("servername");
  });
});

describe("certificate checks", () => {
  const cert = (cn: string, san?: string) => ({ subject: { CN: cn }, subjectaltname: san } as never);

  it("matches the host name against SAN entries, including wildcards", () => {
    expect(certificateMatchesHostname("example.com", cert("example.com", "DNS:example.com, DNS:www.example.com"))).toBe(true);
    expect(certificateMatchesHostname("www.example.com", cert("example.com", "DNS:example.com, DNS:www.example.com"))).toBe(true);
    expect(certificateMatchesHostname("shop.example.com", cert("*.example.com", "DNS:*.example.com"))).toBe(true);
  });

  it("rejects mismatches, wildcard overreach and look-alike names", () => {
    expect(certificateMatchesHostname("example.com", cert("other.example", "DNS:other.example"))).toBe(false);
    expect(certificateMatchesHostname("a.b.example.com", cert("*.example.com", "DNS:*.example.com"))).toBe(false);
    expect(certificateMatchesHostname("example.com", cert("*.example.com", "DNS:*.example.com"))).toBe(false);
    expect(certificateMatchesHostname("example.com.evil.example", cert("example.com", "DNS:example.com"))).toBe(false);
    expect(certificateMatchesHostname("example.com", {} as never)).toBe(false);
  });

  it("keeps only fixed-format verification codes", () => {
    expect(sanitizeAuthorizationError(null)).toBeNull();
    expect(sanitizeAuthorizationError("CERT_HAS_EXPIRED")).toBe("CERT_HAS_EXPIRED");
    expect(sanitizeAuthorizationError(Object.assign(new Error("x"), { code: "DEPTH_ZERO_SELF_SIGNED_CERT" }))).toBe("DEPTH_ZERO_SELF_SIGNED_CERT");
    expect(sanitizeAuthorizationError(new Error("<script>alert(1)</script>"))).toBe("UNKNOWN");
  });

  it("summarizes a certificate to names and dates only", () => {
    expect(
      summarizeCertificate({
        subject: { CN: "example.com" },
        issuer: { CN: "Example CA" },
        subjectaltname: "DNS:example.com, DNS:www.example.com",
        valid_from: "Jan  1 00:00:00 2026 GMT",
        valid_to: "Jan  1 00:00:00 2027 GMT",
      } as never),
    ).toEqual({
      subjectCN: "example.com",
      issuerCN: "Example CA",
      subjectAltNames: ["DNS:example.com", "DNS:www.example.com"],
      validFrom: "Jan  1 00:00:00 2026 GMT",
      validTo: "Jan  1 00:00:00 2027 GMT",
    });
  });
});
