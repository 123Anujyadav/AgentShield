import type { Scenario, View } from "../../types.js";
import {
  AlertOctagonIcon,
  AlertTriangleIcon,
  CheckCircleIcon,
  LockIcon,
  ScaleIcon,
  ShieldIcon,
  TerminalIcon,
} from "../icons.js";

interface PolicyActionsViewProps {
  scenarios: Scenario[];
  selectedScenarioId: string;
  onNavigate: (view: View) => void;
}

export default function PolicyActionsView({
  scenarios,
  selectedScenarioId,
  onNavigate,
}: PolicyActionsViewProps) {
  const selected = scenarios.find((s) => s.id === selectedScenarioId);

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
              background: "rgba(52, 211, 153, 0.15)",
              border: "1px solid var(--allow)",
              color: "var(--allow)",
            }}
          >
            <ScaleIcon className="h-5 w-5" />
          </div>
          <div>
            <h2 className="text-base font-bold" style={{ color: "var(--text-bright)" }}>
              Policy & Actions · Deterministic Rulebook
            </h2>
            <p className="text-xs" style={{ color: "var(--muted)" }}>
              Formal Intent Firewall, 3-tier action gate enforcement, and simulated handler allowlist
            </p>
          </div>
        </div>
        <span className="badge font-mono text-[10px]">Policy: agentshield-policy-v1</span>
      </div>

      {/* 3-Tier Action Gate Architecture */}
      <div className="grid gap-3 md:grid-cols-3">
        {/* Tier 1: ALLOW */}
        <div
          className="panel p-4 border flex flex-col justify-between"
          style={{
            borderColor: "rgba(52, 211, 153, 0.4)",
            background: "linear-gradient(180deg, rgba(52, 211, 153, 0.05) 0%, rgba(11, 23, 28, 0.95) 100%)",
          }}
        >
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="font-mono font-bold text-sm text-emerald-400 flex items-center gap-1.5">
                <CheckCircleIcon className="h-4 w-4" /> 1 · ALLOW
              </span>
              <span className="badge text-[9px] text-emerald-300 border-emerald-900 bg-emerald-950/40">RISK &lt; 30</span>
            </div>
            <p className="text-xs text-slate-200 mb-2 font-medium">
              Permitted to execute immediately.
            </p>
            <ul className="text-[11px] text-muted space-y-1.5">
              <li>• Action type matches explicit user intent contract.</li>
              <li>• Destination matches allowed destination criteria.</li>
              <li>• Zero injection scanner or hard-deny flags.</li>
              <li>• Invokes registered SIMULATED handler.</li>
            </ul>
          </div>
          <div className="mt-4 pt-2 border-t text-[10px] font-mono text-emerald-400" style={{ borderColor: "var(--border-subtle)" }}>
            Outcome: Automated Simulated Run
          </div>
        </div>

        {/* Tier 2: CONFIRM */}
        <div
          className="panel p-4 border flex flex-col justify-between"
          style={{
            borderColor: "rgba(251, 191, 36, 0.4)",
            background: "linear-gradient(180deg, rgba(251, 191, 36, 0.05) 0%, rgba(11, 23, 28, 0.95) 100%)",
          }}
        >
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="font-mono font-bold text-sm text-amber-400 flex items-center gap-1.5">
                <AlertTriangleIcon className="h-4 w-4" /> 2 · CONFIRM
              </span>
              <span className="badge text-[9px] text-amber-300 border-amber-900 bg-amber-950/40">HUMAN IN LOOP</span>
            </div>
            <p className="text-xs text-slate-200 mb-2 font-medium">
              Requires explicit confirmation before running.
            </p>
            <ul className="text-[11px] text-muted space-y-1.5">
              <li>• Triggered when untrusted content contains suspicious instructions.</li>
              <li>• Creates server-side pending approval record (15-min TTL).</li>
              <li>• Action is temporarily paused; nothing has executed.</li>
              <li>• On approval, server re-checks policy before running.</li>
            </ul>
          </div>
          <div className="mt-4 pt-2 border-t text-[10px] font-mono text-amber-400" style={{ borderColor: "var(--border-subtle)" }}>
            Outcome: Server Approval Required
          </div>
        </div>

        {/* Tier 3: BLOCK */}
        <div
          className="panel p-4 border flex flex-col justify-between"
          style={{
            borderColor: "rgba(248, 113, 113, 0.4)",
            background: "linear-gradient(180deg, rgba(248, 113, 113, 0.05) 0%, rgba(11, 23, 28, 0.95) 100%)",
          }}
        >
          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="font-mono font-bold text-sm text-red-400 flex items-center gap-1.5">
                <AlertOctagonIcon className="h-4 w-4" /> 3 · BLOCK
              </span>
              <span className="badge text-[9px] text-red-300 border-red-900 bg-red-950/40">HARD DENY</span>
            </div>
            <p className="text-xs text-slate-200 mb-2 font-medium">
              Prohibited; zero execution allowed.
            </p>
            <ul className="text-[11px] text-muted space-y-1.5">
              <li>• Action type forbidden or outside user intent bounds.</li>
              <li>• Unauthorized destination (e.g. external payment, egress).</li>
              <li>• Hard-deny rule wins over risk score and approvals.</li>
              <li>• Cannot be overridden by user confirmation.</li>
            </ul>
          </div>
          <div className="mt-4 pt-2 border-t text-[10px] font-mono text-red-400" style={{ borderColor: "var(--border-subtle)" }}>
            Outcome: Hard Terminal Block
          </div>
        </div>
      </div>

      {/* Intent Firewall Specification & Allowlist */}
      <div className="grid gap-4 lg:grid-cols-2">
        {/* Intent Firewall Rules */}
        <section className="panel p-4" aria-labelledby="intent-firewall-heading">
          <h3 id="intent-firewall-heading" className="panel-title mb-3">
            <LockIcon className="h-4 w-4 text-accent" />
            Intent Firewall Verification Mechanics
          </h3>
          <div className="space-y-2.5 text-xs">
            <div className="p-2.5 rounded border" style={{ background: "#060d11", borderColor: "var(--border)" }}>
              <span className="font-bold text-slate-100 block mb-0.5">1. Strict Explicit Permissions</span>
              <p className="text-muted text-[11px]">
                No action permissions are inferred from vague intent strings. If the user asked to "summarize an email", permissions only grant read and summary tools—never money movement or messaging.
              </p>
            </div>
            <div className="p-2.5 rounded border" style={{ background: "#060d11", borderColor: "var(--border)" }}>
              <span className="font-bold text-slate-100 block mb-0.5">2. Conflicting Rules Resolution</span>
              <p className="text-muted text-[11px]">
                Whenever an allow rule and a deny rule conflict, the deny rule strictly wins. Hard-deny decisions always result in BLOCK.
              </p>
            </div>
            <div className="p-2.5 rounded border" style={{ background: "#060d11", borderColor: "var(--border)" }}>
              <span className="font-bold text-slate-100 block mb-0.5">3. Destination Confinement</span>
              <p className="text-muted text-[11px]">
                Destinations must match configured allowedDestinations. Any action proposing an unverified external network address or storage bucket is blocked.
              </p>
            </div>
          </div>
        </section>

        {/* Simulated Handlers Allowlist */}
        <section className="panel p-4" aria-labelledby="handlers-allowlist-heading">
          <h3 id="handlers-allowlist-heading" className="panel-title mb-3">
            <TerminalIcon className="h-4 w-4 text-accent-blue" />
            Simulated Handlers Allowlist (In-Memory Only)
          </h3>
          <p className="text-xs text-muted mb-3">
            Only explicit allowlisted handler routines can be invoked. All execution is simulated; no external APIs are contacted.
          </p>

          <div className="space-y-2 text-xs">
            <div className="p-2.5 rounded border flex items-center justify-between" style={{ background: "#060d11", borderColor: "var(--border)" }}>
              <div>
                <span className="font-mono font-bold text-cyan-300">create_summary</span>
                <p className="text-[11px] text-muted">Generates a concise synthetic text summary of verified input document.</p>
              </div>
              <span className="badge text-[9px] text-emerald-300">READ-ONLY</span>
            </div>

            <div className="p-2.5 rounded border flex items-center justify-between" style={{ background: "#060d11", borderColor: "var(--border)" }}>
              <div>
                <span className="font-mono font-bold text-cyan-300">read_document</span>
                <p className="text-[11px] text-muted">Fetches mock synthetic file contents into the local scanner context.</p>
              </div>
              <span className="badge text-[9px] text-emerald-300">READ-ONLY</span>
            </div>

            <div className="p-2.5 rounded border flex items-center justify-between" style={{ background: "#060d11", borderColor: "var(--border)" }}>
              <div>
                <span className="font-mono font-bold text-cyan-300">create_report</span>
                <p className="text-[11px] text-muted">Compiles structured synthetic Markdown audit digest in local memory.</p>
              </div>
              <span className="badge text-[9px] text-emerald-300">LOCAL MEMORY</span>
            </div>
          </div>

          <div className="mt-4 pt-2 border-t text-[10px] flex items-center justify-between text-muted" style={{ borderColor: "var(--border-subtle)" }}>
            <span>Unlisted Tools:</span>
            <span className="text-red-400 font-bold font-mono">AUTOMATIC HARD BLOCK</span>
          </div>
        </section>
      </div>

      {/* Active Selected Scenario Policy Match */}
      {selected && (
        <div className="panel p-4">
          <h3 className="panel-title mb-2">Selected Scenario Policy Binding</h3>
          <div className="grid gap-2 sm:grid-cols-2 text-xs">
            <div>
              <span className="text-muted block text-[10px] uppercase">Active Task Contract:</span>
              <span className="font-semibold text-slate-100">{selected.intent.task}</span>
            </div>
            <div>
              <span className="text-muted block text-[10px] uppercase">Authorized Action Set:</span>
              <span className="font-mono text-cyan-300">
                {selected.intent.allowedActions.length > 0 ? selected.intent.allowedActions.join(", ") : "None (Conservative Deny)"}
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
