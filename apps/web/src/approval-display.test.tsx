import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import type { ActivityEvent, PendingApproval } from "./types.js";
import { requesterLabel, statusTone } from "./approval-display.js";
import ApprovalQueueView from "./components/views/ApprovalQueueView.js";
import ActivityAuditView from "./components/views/ActivityAuditView.js";

/**
 * M3-E E15: the operator sees who asked for an action before deciding it, and an OUTCOME_UNKNOWN approval is
 * shown as unknown (amber, with its reason), never as a block. Rendered in process with react-dom/server:
 * markup only, not a browser test (no layout, no interaction).
 */

const approval = (over: Partial<PendingApproval>): PendingApproval => ({
  id: "apr-1",
  status: "PENDING",
  createdAt: "2026-11-01T09:00:00.000Z",
  expiresAt: "2026-11-01T09:15:00.000Z",
  scenarioId: null,
  intent: { task: "Summarize the notes", allowedActions: [], deniedActions: [], allowedDestinations: [] } as unknown as PendingApproval["intent"],
  action: { type: "create_summary", tool: "simulated.workspace.createSummary", destination: "simulated-workspace", summary: "s" },
  decision: "CONFIRM",
  policyVersion: "v1",
  riskScore: 70,
  findings: [],
  explanation: "Untrusted content asked to ignore instructions.",
  execution: null,
  agentId: "writer",
  requestedBy: { kind: "agent", credentialId: "0123456789abcdef" },
  ...over,
});

describe("M3-E E15: requester and status display", () => {
  it("names the agent and its key id, or the operator, and says when it was not recorded", () => {
    expect(requesterLabel({ agentId: "writer", requestedBy: { kind: "agent", credentialId: "0123456789abcdef" } })).toBe("Agent writer · key 0123456789abcdef");
    expect(requesterLabel({ agentId: "demo-agent", requestedBy: { kind: "operator", method: "session" } })).toBe("Operator (dashboard) · scenario as demo-agent");
    expect(requesterLabel({ agentId: null, actor: { kind: "operator", method: "bearer" } })).toBe("Operator (API token)");
    expect(requesterLabel({})).toBe("Requester not recorded");
  });

  it("colours OUTCOME_UNKNOWN and approved-without-handler amber, refusals red, executions green", () => {
    expect(["EXECUTED", "APPROVED_NOT_EXECUTED", "OUTCOME_UNKNOWN", "REJECTED", "BLOCKED_ON_RECHECK", "EXPIRED"].map((s) => statusTone(s as PendingApproval["status"]))).toEqual([
      "allow",
      "confirm",
      "confirm",
      "block",
      "block",
      "block",
    ]);
  });

  it("the approval queue shows the requester on pending cards and the reason of an OUTCOME_UNKNOWN approval", () => {
    const html = renderToStaticMarkup(
      <ApprovalQueueView
        approvals={[
          approval({}),
          approval({
            id: "apr-2",
            status: "OUTCOME_UNKNOWN",
            execution: { executed: false, handler: null, result: null, reason: "This approval was restored from a backup; it will not run." },
          }),
        ]}
        actingId={null}
        onApprovalAction={async () => {}}
        onNavigate={() => {}}
      />,
    );
    expect(html).toContain("Requested by: <span");
    expect(html).toContain("Agent writer · key 0123456789abcdef");
    expect(html).toContain("This approval was restored from a backup; it will not run.");
    expect(html).toMatch(/color:var\(--confirm\)[^>]*>OUTCOME_UNKNOWN/);
  });

  it("the approval queue renders its empty state", () => {
    const html = renderToStaticMarkup(<ApprovalQueueView approvals={[]} actingId={null} onApprovalAction={async () => {}} onNavigate={() => {}} />);
    expect(html).toContain("No Pending Approvals");
  });

  it("the activity view renders an event row (the requester is in its expanded details, which need a click)", () => {
    const event: ActivityEvent = {
      id: "evt-1",
      timestamp: "2026-11-01T09:00:00.000Z",
      scenarioId: null,
      intentTask: "Summarize",
      actionType: "create_summary",
      tool: "t",
      destination: "simulated-workspace",
      decision: "ALLOW",
      riskScore: 10,
      findings: [],
      explanation: "e",
      agentId: "writer",
      actor: { kind: "agent", credentialId: "0123456789abcdef" },
    };
    const html = renderToStaticMarkup(<ActivityAuditView events={[event]} onNavigate={() => {}} />);
    expect(html).toContain("create_summary");
    expect(html).not.toContain("Requested by"); // collapsed until the operator expands it
  });
});
