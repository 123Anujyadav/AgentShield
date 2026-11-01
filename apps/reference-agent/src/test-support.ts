import { createHash } from "node:crypto";
import { AgentCredential, AgentShieldClient, type AgentShieldClientOptions } from "@agentshield/agent-sdk";

/**
 * Test fixtures only (M3-E E6). The credential is derived at runtime from a label, so no
 * key material is stored in the repository; it is never a real credential. The fake
 * AgentShield answers the SDK's fetch with canned responses and records every request.
 */

const ED25519_PKCS8_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export function testCredential(label: string): { credential: string; keyId: string; secretPart: string } {
  const seed = createHash("sha256").update(`agentshield-reference-agent-test-key\0${label}`).digest();
  const keyId = createHash("sha256").update(`agentshield-reference-agent-test-key-id\0${label}`).digest("hex").slice(0, 16);
  const secretPart = Buffer.concat([ED25519_PKCS8_PREFIX, seed]).toString("base64url");
  return { credential: `asag2_${keyId}.${secretPart}`, keyId, secretPart };
}

export interface RecordedRequest {
  method: string;
  path: string;
  body: string | null;
  authorization: string;
}

/** A reply: a Response, an Error to throw (a network failure), or "hang" to wait until the client gives up. */
export type Reply = Response | Error | "hang";

export function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", ...headers } });
}

export const NOW = "2026-10-31T12:00:00.000Z";
export const LATER = "2026-10-31T12:15:00.000Z";

export function evaluation(decision: "ALLOW" | "CONFIRM" | "BLOCK", options: { executed?: boolean; approvalId?: string | null; createdAt?: string; explanation?: string; evidence?: string } = {}): Response {
  return json(200, {
    evaluation: {
      decision,
      riskScore: decision === "ALLOW" ? 5 : decision === "CONFIRM" ? 55 : 95,
      explanation: options.explanation ?? `Decision ${decision}.`,
      findings:
        decision === "ALLOW"
          ? []
          : [{ ruleId: "injection.instruction-override", category: "prompt-injection", severity: "high", title: "Instruction override in content", explanation: "The document tells the agent to ignore its instructions.", evidence: options.evidence ?? "Ignore all previous instructions." }],
    },
    executed: options.executed ?? decision === "ALLOW",
    pendingApproval: options.approvalId ? { id: options.approvalId, status: "PENDING", createdAt: options.createdAt ?? NOW } : null,
  });
}

export function approval(id: string, status: string, executed = status === "EXECUTED", createdAt = NOW): Response {
  return json(200, { approval: { id, status, createdAt, expiresAt: LATER, executed, pollAfterSeconds: status === "PENDING" ? 2 : null } });
}

export function fakeAgentShield(routes: { evaluate?: () => Reply; approval?: (id: string, call: number) => Reply }) {
  const requests: RecordedRequest[] = [];
  let approvalCalls = 0;
  const reply = async (r: Reply, signal: AbortSignal | null | undefined): Promise<Response> => {
    if (r === "hang") {
      return new Promise<Response>((_, reject) => signal?.addEventListener("abort", () => reject(signal.reason), { once: true }));
    }
    if (r instanceof Error) throw r;
    return r;
  };
  const fetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = new URL(String(input));
    const headers = new Headers(init?.headers);
    const body = init?.body ? Buffer.from(init.body as Uint8Array).toString("utf8") : null;
    requests.push({ method: init?.method ?? "GET", path: `${url.pathname}${url.search}`, body, authorization: headers.get("authorization") ?? "" });
    if (init?.method === "POST" && url.pathname === "/api/evaluate" && routes.evaluate) return reply(routes.evaluate(), init.signal);
    const match = /^\/api\/agent\/approvals\/(apr-\d+)$/.exec(url.pathname);
    if ((init?.method ?? "GET") === "GET" && match && routes.approval) return reply(routes.approval(match[1]!, (approvalCalls += 1)), init?.signal);
    return json(404, { error: "Not found" });
  }) as typeof globalThis.fetch;
  return { fetch, requests };
}

export function testClient(fetch: typeof globalThis.fetch, extra: Partial<AgentShieldClientOptions> = {}, label = "reference-agent"): AgentShieldClient {
  return new AgentShieldClient({
    baseUrl: "http://127.0.0.1:4000",
    credential: AgentCredential.fromString(testCredential(label).credential),
    fetch,
    sleep: async () => {},
    ...extra,
  });
}
