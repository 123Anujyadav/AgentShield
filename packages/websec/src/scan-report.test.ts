import { describe, expect, it } from "vitest";
import { GuardedFetcher, RequestBudget, type Transport, type TransportRequest } from "./fetcher.js";
import { escapeHtml, renderHtmlReport, renderJsonReport, type ScanReport } from "./report.js";
import { CORS_PROBE_ORIGIN, PASSIVE_CHECKS, runPassiveScan, ScanStopped } from "./scan.js";
import { parseLabOrigin, type DnsTarget } from "./target.js";

const target: DnsTarget = { kind: "dns", hostname: "example.com", displayHostname: "example.com" };
const PUBLIC = [{ address: "93.184.215.14", family: 4 }];

function siteTransport(requests: TransportRequest[]): Transport {
  return async (request) => {
    requests.push(request);
    const path = request.url.pathname;
    const headers: Record<string, string | string[]> =
      request.url.protocol === "http:"
        ? { location: `https://example.com${path}` }
        : path === "/.well-known/security.txt"
          ? { "content-type": "text/plain" }
          : { "strict-transport-security": "max-age=31536000", "set-cookie": "sid=SESSION_SECRET_VALUE_123456; Secure; HttpOnly; SameSite=Lax" };
    const body = path === "/.well-known/security.txt" ? "Contact: mailto:security@example.com\nExpires: 2027-06-01T00:00:00Z\n" : "<html>page body</html>";
    return {
      status: request.url.protocol === "http:" ? 301 : 200,
      headers,
      body: (async function* () {
        yield new Uint8Array(Buffer.from(body));
      })(),
      tls: request.url.protocol === "https:"
        ? {
            protocol: "TLSv1.3",
            authorized: true,
            authorizationError: null,
            hostnameMatches: true,
            certificate: { subjectCN: "example.com", issuerCN: "CA", subjectAltNames: ["DNS:example.com"], validFrom: "2026-01-01T00:00:00Z", validTo: "2027-06-01T00:00:00Z" },
          }
        : null,
      close: () => {},
    };
  };
}

describe("passive scan orchestration", () => {
  it("makes exactly three requests (HTTPS root, HTTP root, security.txt) and runs every check", async () => {
    const requests: TransportRequest[] = [];
    const fetcher = new GuardedFetcher({ resolver: async () => PUBLIC, transport: siteTransport(requests) });
    const budget = new RequestBudget(30);
    const scan = await runPassiveScan({ target, fetcher, budget, now: () => new Date("2026-10-29T00:00:00Z") });
    expect(requests.map((r) => r.url.href)).toEqual([
      "https://example.com/",
      "http://example.com/",
      "https://example.com/.well-known/security.txt",
    ]);
    expect(requests[0]!.headers.origin).toBe(CORS_PROBE_ORIGIN);
    expect(scan.checks.map((c) => c.checkId)).toHaveLength(PASSIVE_CHECKS.length);
    expect([scan.requestsUsed, scan.requestBudget]).toEqual([3, 30]);
    expect(scan.checks.find((c) => c.checkId === "tls")?.status).toBe("pass");
    expect(scan.checks.find((c) => c.checkId === "https-redirect")?.status).toBe("pass");
    expect(scan.checks.find((c) => c.checkId === "security-txt")?.status).toBe("pass");
    // No body or cookie value from the site ends up in results.
    const serialized = JSON.stringify(scan);
    expect(serialized).not.toContain("SESSION_SECRET_VALUE_123456");
    expect(serialized).not.toContain("page body");
    expect(serialized).not.toContain("security@example.com");
  });

  it("stops the whole scan, without findings, when the name resolves to a blocked address", async () => {
    const requests: TransportRequest[] = [];
    const fetcher = new GuardedFetcher({ resolver: async () => [{ address: "192.168.0.10", family: 4 }], transport: siteTransport(requests) });
    await expect(runPassiveScan({ target, fetcher, budget: new RequestBudget(30) })).rejects.toBeInstanceOf(ScanStopped);
    expect(requests).toHaveLength(0);
  });

  it("scans a lab origin over plain HTTP with two requests and no DNS", async () => {
    const requests: TransportRequest[] = [];
    let lookups = 0;
    const fetcher = new GuardedFetcher({
      resolver: async () => {
        lookups += 1;
        return PUBLIC;
      },
      transport: siteTransport(requests),
    });
    const lab = parseLabOrigin("http://127.0.0.1:8081")!;
    // This fake answers plain HTTP with a redirect to another host, which the lab scope refuses to follow.
    const scan = await runPassiveScan({ target: lab, fetcher, budget: new RequestBudget(30) });
    expect(lookups).toBe(0);
    expect(requests.map((r) => r.url.href)).toEqual(["http://127.0.0.1:8081/", "http://127.0.0.1:8081/.well-known/security.txt"]);
    expect(requests.every((r) => r.address === "127.0.0.1" && r.port === 8081)).toBe(true);
    expect(scan.checks.find((c) => c.checkId === "tls")?.status).toBe("not-applicable");
  });
});

describe("reports", () => {
  const hostile = `<img src=x onerror=alert(1)>"'\``;
  const report: ScanReport = {
    scanId: "scan-1",
    target: { hostname: "example.com", displayHostname: `example.com${hostile}`, kind: "dns" },
    status: "completed",
    reason: null,
    requestedAt: "2026-10-29T00:00:00.000Z",
    startedAt: "2026-10-29T00:00:01.000Z",
    finishedAt: "2026-10-29T00:00:02.000Z",
    requestsUsed: 3,
    requestBudget: 30,
    options: { exposureChecks: false },
    checks: [
      {
        checkId: "header.version-disclosure",
        title: `Disclosure ${hostile}`,
        status: "fail",
        summary: `<script>alert("summary")</script>`,
        findings: [
          {
            findingId: "header.version-disclosure.server",
            checkId: "header.version-disclosure",
            severity: "low",
            confidence: "high",
            title: `Server ${hostile}`,
            explanation: "</p><script>alert(2)</script>",
            evidence: `server: <svg onload=alert(3)>`,
            remediation: "javascript:alert(4)",
            references: ["CWE-497", `<b>${hostile}</b>`],
          },
        ],
      },
    ],
  };

  it("escapes every untrusted value in the HTML report", () => {
    const html = renderHtmlReport(report);
    expect(html).not.toMatch(/<script>alert/);
    expect(html).not.toMatch(/<img src=x/);
    expect(html).not.toMatch(/<svg onload/);
    expect(html).not.toContain("<b><img");
    expect(html).toContain("&lt;img src=x onerror=alert(1)&gt;&quot;&#39;&#96;");
    expect(html).toContain("&lt;/p&gt;&lt;script&gt;");
    expect(escapeHtml(`<>&"'\``)).toBe("&lt;&gt;&amp;&quot;&#39;&#96;");
  });

  it("states that a non-completed scan ran no checks", () => {
    const html = renderHtmlReport({ ...report, status: "rejected", reason: "outbound-scanning-disabled", checks: [] });
    expect(html).toContain("No checks ran for this scan.");
    expect(html).toContain("outbound-scanning-disabled");
  });

  it("the JSON report carries the disclaimer, summary and data, and nothing else", () => {
    const json = JSON.parse(renderJsonReport(report)) as Record<string, unknown>;
    expect(Object.keys(json).sort()).toEqual(
      // "options" and "exposure" were added in M2-E (the recorded opt-in and the exposure section).
      ["checks", "disclaimer", "exposure", "finishedAt", "generator", "options", "reason", "requestBudget", "requestedAt", "requestsUsed", "scanId", "startedAt", "status", "summary", "target"].sort(),
    );
    expect(json.summary).toEqual({ critical: 0, high: 0, medium: 0, low: 1, info: 0 });
  });
});
