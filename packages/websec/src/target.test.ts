import { describe, expect, it } from "vitest";
import { isInDnsScope, isInLabScope, LAB_PORT_MAX, LAB_PORT_MIN, normalizeTarget, parseLabOrigin, type DnsTarget } from "./target.js";

describe("target normalization", () => {
  it.each([
    ["example.com", "example.com"],
    ["https://example.com", "example.com"],
    ["https://example.com/", "example.com"],
    ["http://example.com", "example.com"],
    ["HTTPS://WWW.Example.COM/", "www.example.com"],
    ["https://example.com:443/", "example.com"],
    ["http://example.com:80", "example.com"],
    ["  shop.example.org  ", "shop.example.org"],
    ["https://bücher.example", "xn--bcher-kva.example"],
    ["xn--bcher-kva.example", "xn--bcher-kva.example"],
  ])("accepts %j as %s", (input, hostname) => {
    const verdict = normalizeTarget(input);
    expect(verdict).toMatchObject({ ok: true, target: { kind: "dns", hostname } });
  });

  it("keeps a Unicode display name for internationalized hosts", () => {
    expect(normalizeTarget("bücher.example")).toMatchObject({ ok: true, target: { displayHostname: "bücher.example" } });
  });

  it.each([
    [42, "invalid-input"],
    ["", "invalid-input"],
    ["a".repeat(2049), "invalid-input"],
    ["https://exa mple.com", "invalid-characters"],
    ["https://example.com\\@evil.com", "invalid-characters"],
    // A tab inside the host: the URL parser would silently drop it, so it is refused first.
    ["https://exam\tple.com", "invalid-characters"],
    ["ftp://example.com", "unsupported-scheme"],
    ["javascript:alert(1)", "unsupported-scheme"],
    ["file:///etc/passwd", "unsupported-scheme"],
    ["gopher://example.com", "unsupported-scheme"],
    ["https://user:pass@example.com", "credentials-not-allowed"],
    ["https://example.com@evil.com", "credentials-not-allowed"],
    ["https://example.com/path", "path-not-allowed"],
    ["https://example.com/?q=1", "path-not-allowed"],
    ["https://example.com/#x", "path-not-allowed"],
    ["https://example.com:8443", "port-not-allowed"],
    ["http://example.com:443", "port-not-allowed"],
    ["https://example.com:80", "port-not-allowed"],
    ["https://127.0.0.1", "ip-literal-not-allowed"],
    ["https://2130706433", "ip-literal-not-allowed"],
    ["https://0x7f.0.0.1", "ip-literal-not-allowed"],
    ["https://0177.0.0.1", "ip-literal-not-allowed"],
    ["https://127.1", "ip-literal-not-allowed"],
    ["https://8.8.8.8", "ip-literal-not-allowed"],
    ["https://[::1]", "ip-literal-not-allowed"],
    ["https://[::ffff:127.0.0.1]", "ip-literal-not-allowed"],
    ["https://example.com.", "trailing-dot"],
    ["https://localhost", "invalid-hostname"],
    ["https://intranet", "invalid-hostname"],
    ["https://under_score.example.com", "invalid-hostname"],
    ["https://-lead.example.com", "invalid-hostname"],
    ["https://ab--cd.example.com", "invalid-hostname"],
    ["https://xn--zz.example.com", "invalid-url"],
    [`https://${"a".repeat(64)}.example.com`, "invalid-hostname"],
    ["https://app.localhost", "special-use-hostname"],
    ["https://printer.local", "special-use-hostname"],
    ["https://db.internal", "special-use-hostname"],
    ["https://router.home.arpa", "special-use-hostname"],
    ["https://1.0.0.127.in-addr.arpa", "special-use-hostname"],
    ["https://site.test", "special-use-hostname"],
    ["https://nas.lan", "special-use-hostname"],
  ])("refuses %j (%s)", (input, reason) => {
    expect(normalizeTarget(input)).toEqual({ ok: false, reason });
  });

  it("scope is the exact host on default ports only", () => {
    const target: DnsTarget = { kind: "dns", hostname: "example.com", displayHostname: "example.com" };
    expect(isInDnsScope(new URL("https://example.com/a?b"), target)).toBe(true);
    expect(isInDnsScope(new URL("http://example.com/"), target)).toBe(true);
    for (const url of [
      "https://www.example.com/",
      "https://example.com.evil.com/",
      "https://example.com:8443/",
      "https://u:p@example.com/",
      "ftp://example.com/",
      "https://evil.com/?example.com",
    ]) {
      expect(isInDnsScope(new URL(url), target), url).toBe(false);
    }
  });
});

describe("lab origins", () => {
  it("accept only exact plain-HTTP loopback origins on ports 8080-8099", () => {
    expect(LAB_PORT_MIN).toBe(8080);
    expect(LAB_PORT_MAX).toBe(8099);
    expect(parseLabOrigin("http://127.0.0.1:8081")).toMatchObject({ kind: "lab", origin: "http://127.0.0.1:8081", address: "127.0.0.1", family: 4, port: 8081 });
    expect(parseLabOrigin("http://[::1]:8082")).toMatchObject({ address: "::1", family: 6, port: 8082 });
    for (const good of ["http://127.0.0.1:8080", "http://127.0.0.1:8082", "http://127.0.0.1:8099", " http://127.0.0.1:8090 "]) {
      expect(parseLabOrigin(good), good).not.toBeNull();
    }
    for (const bad of [
      // Outside the lab range, including common local services and AgentShield's own ports.
      "http://127.0.0.1:8079",
      "http://127.0.0.1:8100",
      "http://127.0.0.1:1024",
      "http://127.0.0.1:3000",
      "http://127.0.0.1:4000",
      "http://127.0.0.1:5173",
      "http://127.0.0.1:5432",
      "http://127.0.0.1:6379",
      "http://127.0.0.1:9229",
      "http://127.0.0.1:65535",
      "http://127.0.0.1:080",
      "http://127.0.0.1:08081",
      "http://127.0.0.1:80",
      "http://127.0.0.1",
      // Not loopback IP literals, or not the exact form.
      "http://localhost:8081",
      "http://127.0.0.2:8081",
      "http://10.0.0.5:8081",
      "http://169.254.169.254:8081",
      "http://[::ffff:127.0.0.1]:8081",
      "http://example.com:8081",
      "https://127.0.0.1:8081",
      "http://127.0.0.1:8081/",
      "http://user@127.0.0.1:8081",
    ]) {
      expect(parseLabOrigin(bad), bad).toBeNull();
    }
  });

  it("refuses a configured reserved port even inside the lab range", () => {
    expect(parseLabOrigin("http://127.0.0.1:8085", new Set([8085]))).toBeNull();
    expect(parseLabOrigin("http://127.0.0.1:8086", new Set([8085]))).not.toBeNull();
  });

  it("lab scope is exactly the configured origin", () => {
    const lab = parseLabOrigin("http://127.0.0.1:8081")!;
    expect(isInLabScope(new URL("http://127.0.0.1:8081/.well-known/security.txt"), lab)).toBe(true);
    for (const url of ["http://127.0.0.1:8082/", "http://localhost:8081/", "https://127.0.0.1:8081/", "http://169.254.169.254/"]) {
      expect(isInLabScope(new URL(url), lab), url).toBe(false);
    }
  });
});
