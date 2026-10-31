import type { PendingApproval, View } from "../../types.js";
import {
  AlertOctagonIcon,
  AlertTriangleIcon,
  CheckBadgeIcon,
  CheckCircleIcon,
  ChevronIcon,
  FlaskIcon,
  InfoIcon,
  LockIcon,
  TerminalIcon,
} from "../icons.js";

interface ApprovalQueueViewProps {
  approvals: PendingApproval[];
  actingId: string | null;
  onApprovalAction: (approval: PendingApproval, verb: "approve" | "reject") => Promise<void>;
  onNavigate: (view: View) => void;
}

export default function ApprovalQueueView({
  approvals,
  actingId,
  onApprovalAction,
  onNavigate,
}: ApprovalQueueViewProps) {
  const pendingApprovals = approvals.filter((a) => a.status === "PENDING");
  const resolvedApprovals = approvals.filter((a) => a.status !== "PENDING");

  return (
    <div className="space-y-4">
      {/* Header */}
      <div
        className="panel p-4 flex flex-wrap items-center justify-between gap-3"
        style={{
          background: "linear-gradient(90deg, rgba(16, 35, 41, 0.85) 0%, rgba(9, 17, 22, 0.95) 100%)",
        }}
      >
        <div className="flex items-center gap-3">
          <div
            className="flex h-10 w-10 items-center justify-center rounded-lg"
            style={{
              background: "rgba(251, 191, 36, 0.15)",
              border: "1px solid var(--confirm)",
              color: "var(--confirm)",
            }}
          >
            <CheckBadgeIcon className="h-5 w-5" />
          </div>
          <div>
            <h2 className="text-base font-bold" style={{ color: "var(--text-bright)" }}>
              Approval Queue · Human-in-the-Loop Gate
            </h2>
            <p className="text-xs" style={{ color: "var(--muted)" }}>
              Server-side pending authorizations created when untrusted content escalates permitted actions to CONFIRM
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span
            className="badge font-mono"
            style={{
              borderColor: pendingApprovals.length > 0 ? "var(--confirm)" : "var(--border)",
              color: pendingApprovals.length > 0 ? "var(--confirm)" : "var(--muted)",
            }}
          >
            {pendingApprovals.length} Pending
          </span>
          <span className="badge text-[10px]">TTL: 15 Minutes</span>
        </div>
      </div>

      {/* Security Architecture Guarantee Callout */}
      <div
        className="panel p-3.5 text-xs flex items-start gap-3 border"
        style={{ background: "#060e12", borderColor: "rgba(251, 191, 36, 0.3)" }}
      >
        <InfoIcon className="h-4 w-4 text-amber-400 shrink-0 mt-0.5" />
        <div className="text-[11px] leading-relaxed" style={{ color: "var(--muted)" }}>
          <strong className="text-slate-100">Zero Silent Execution Guarantee:</strong> When an action is placed in the Approval Queue, execution is halted immediately on the server. Approving re-checks current policy against the stored action before any simulated handler runs. If an attack is classified as hard-deny BLOCK, it cannot be overridden or approved. Duplicate approvals return HTTP 409 Conflict.
        </div>
      </div>

      {/* Pending Approvals Section */}
      <section className="space-y-3" aria-labelledby="pending-heading">
        <h3 id="pending-heading" className="panel-title flex items-center gap-2">
          <AlertTriangleIcon className="h-4 w-4 text-amber-400" />
          Active Pending Approvals ({pendingApprovals.length})
        </h3>

        {pendingApprovals.length === 0 ? (
          <div className="panel p-8 text-center space-y-3">
            <CheckCircleIcon className="h-8 w-8 text-emerald-400 mx-auto" />
            <h4 className="text-sm font-bold text-slate-100">No Pending Approvals</h4>
            <p className="text-xs text-muted max-w-md mx-auto">
              All agent actions have been processed or resolved. To generate an approval record for testing, run the prompt injection scenario in Scenario Lab.
            </p>
            <button
              type="button"
              onClick={() => onNavigate("scenarios")}
              className="btn-primary text-xs mx-auto flex items-center gap-1.5"
            >
              <FlaskIcon className="h-3.5 w-3.5" /> Open Scenario Lab
            </button>
          </div>
        ) : (
          <div className="space-y-3">
            {pendingApprovals.map((approval) => {
              const isActing = actingId === approval.id;
              return (
                <div
                  key={approval.id}
                  className="panel p-4 border"
                  style={{
                    borderColor: "rgba(251, 191, 36, 0.5)",
                    background: "linear-gradient(180deg, rgba(251, 191, 36, 0.05) 0%, rgba(11, 23, 28, 0.98) 100%)",
                  }}
                >
                  <div className="flex flex-wrap items-center justify-between gap-2 pb-2.5 mb-3 border-b" style={{ borderColor: "var(--border-subtle)" }}>
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-bold text-sm text-amber-400">{approval.id}</span>
                      <span className="badge text-[10px] text-amber-300 border-amber-900 bg-amber-950/40">
                        {approval.status}
                      </span>
                      <span className="badge text-[10px]">Risk Score: {approval.riskScore}/100</span>
                      <span className="badge text-[10px] font-mono">Policy: {approval.policyVersion}</span>
                    </div>
                    <span className="text-[10px] font-mono text-muted">
                      Created: {new Date(approval.createdAt).toLocaleTimeString()}
                    </span>
                  </div>

                  <div className="grid gap-3 md:grid-cols-2 mb-3 text-xs">
                    <div>
                      <span className="text-[10px] font-mono uppercase text-muted block mb-1">Proposed Action:</span>
                      <div className="p-2.5 rounded border" style={{ background: "#05090d", borderColor: "var(--border)" }}>
                        <div className="font-bold text-slate-100">{approval.action.type}</div>
                        <div className="text-[11px] text-muted">Tool: <span className="font-mono text-cyan-300">{approval.action.tool}</span></div>
                        <div className="text-[11px] text-muted">Target: <span className="font-mono text-slate-200">{approval.action.destination}</span></div>
                      </div>
                    </div>
                    <div>
                      <span className="text-[10px] font-mono uppercase text-muted block mb-1">Escalation Reason:</span>
                      <div className="p-2.5 rounded border" style={{ background: "#05090d", borderColor: "var(--border)" }}>
                        <p className="text-slate-200 text-[11px] leading-relaxed">{approval.explanation}</p>
                      </div>
                    </div>
                  </div>

                  {/* Action Controls */}
                  <div className="flex flex-wrap items-center justify-between gap-3 pt-3 border-t" style={{ borderColor: "var(--border-subtle)" }}>
                    <span className="text-[11px] text-muted">
                      Execution Mode: <strong className="text-cyan-300 font-mono">SIMULATED</strong> (No real tool executes)
                    </span>
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={() => void onApprovalAction(approval, "reject")}
                        disabled={isActing}
                        className="btn-danger"
                      >
                        {isActing ? "Working…" : "Reject Action"}
                      </button>
                      <button
                        type="button"
                        onClick={() => void onApprovalAction(approval, "approve")}
                        disabled={isActing}
                        className="btn-primary"
                      >
                        {isActing ? "Re-checking Policy…" : "Approve & Run (SIMULATED)"}
                      </button>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </section>

      {/* Historical Resolved Approvals */}
      {resolvedApprovals.length > 0 && (
        <section className="panel p-4 space-y-3" aria-labelledby="history-heading">
          <h3 id="history-heading" className="panel-title text-muted">
            Resolved Approval History ({resolvedApprovals.length})
          </h3>
          <div className="space-y-2">
            {resolvedApprovals.map((item) => (
              <div
                key={item.id}
                className="p-3 rounded-lg text-xs border flex flex-wrap items-center justify-between gap-2"
                style={{ background: "#060d11", borderColor: "var(--border-subtle)" }}
              >
                <div className="flex items-center gap-2">
                  <span className="font-mono font-bold text-slate-200">{item.id}</span>
                  <span
                    className="badge text-[9px] font-bold"
                    style={{
                      // M3-B: approved but with no registered handler is not a block; shown amber.
                      borderColor: item.status === "EXECUTED" ? "var(--allow)" : item.status === "APPROVED_NOT_EXECUTED" ? "var(--confirm)" : "var(--block)",
                      color: item.status === "EXECUTED" ? "var(--allow)" : item.status === "APPROVED_NOT_EXECUTED" ? "var(--confirm)" : "var(--block)",
                    }}
                  >
                    {item.status}
                  </span>
                  <span className="font-mono text-muted">{item.action.type} → {item.action.destination}</span>
                </div>
                {item.execution?.result && (
                  <span className="text-[11px] text-emerald-400 font-mono">
                    Result: {item.execution.result}
                  </span>
                )}
              </div>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
