import type { ActivityEvent, EvaluateResponse, PendingApproval, Scenario, View } from "../../types.js";
import Topology from "../Topology.js";
import { DecisionBadge, MetricCard, decisionColor } from "../common.js";
import {
  ActivityIcon,
  AlertOctagonIcon,
  CheckBadgeIcon,
  ChevronIcon,
  FlaskIcon,
  ScaleIcon,
  ShieldIcon,
} from "../icons.js";

interface CommandCenterViewProps {
  scenarios: Scenario[];
  selectedScenarioId: string;
  onSelectScenarioId: (id: string) => void;
  result: EvaluateResponse | null;
  events: ActivityEvent[];
  approvals: PendingApproval[];
  onEvaluate: () => Promise<void>;
  isBusy: boolean;
  onNavigate: (view: View) => void;
}

export default function CommandCenterView({
  scenarios,
  selectedScenarioId,
  onSelectScenarioId,
  result,
  events,
  approvals,
  onEvaluate,
  isBusy,
  onNavigate,
}: CommandCenterViewProps) {
  const pendingCount = approvals.filter((a) => a.status === "PENDING").length;

  const tally = { ALLOW: 0, CONFIRM: 0, BLOCK: 0 };
  for (const e of events) {
    if (e.decision in tally) tally[e.decision as keyof typeof tally] += 1;
  }
  const totalDecisions = tally.ALLOW + tally.CONFIRM + tally.BLOCK;

  const selected = scenarios.find((s) => s.id === selectedScenarioId);

  return (
    <div className="space-y-4">
      {/* KPI Stats Strip */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <MetricCard
          title="Shield Status"
          value="ENFORCING"
          subtitle="Deterministic Intent Firewall"
          badge="LOCAL"
          color="var(--accent)"
          icon={<ShieldIcon className="h-4 w-4" />}
        />
        <MetricCard
          title="Session Decisions"
          value={totalDecisions}
          subtitle={`ALLOW ${tally.ALLOW} · CONFIRM ${tally.CONFIRM} · BLOCK ${tally.BLOCK}`}
          badge="TIMELINE"
          color="var(--accent-blue)"
          icon={<ScaleIcon className="h-4 w-4" />}
        />
        <MetricCard
          title="Pending Approvals"
          value={pendingCount}
          subtitle={pendingCount === 0 ? "Queue clear · no action paused" : `${pendingCount} action(s) require confirm`}
          badge={pendingCount > 0 ? "ACTION REQUIRED" : "CLEAR"}
          color={pendingCount > 0 ? "var(--confirm)" : "var(--muted)"}
          icon={<CheckBadgeIcon className="h-4 w-4" />}
        />
        <MetricCard
          title="Recent Outcome"
          value={result ? result.evaluation.decision : "IDLE"}
          subtitle={result ? `Risk score: ${result.evaluation.riskScore}/100` : "Run evaluation to trace"}
          badge={result ? `v${result.evaluation.policyVersion.slice(-2)}` : "READY"}
          color={result ? decisionColor(result.evaluation.decision) : "var(--muted)"}
          icon={<AlertOctagonIcon className="h-4 w-4" />}
        />
      </div>

      {/* Main Grid: Policy Topology & Scenario Quick-Fire */}
      <div className="grid gap-4 xl:grid-cols-[1fr_360px]">
        {/* Left Column: Topology & Quick Test */}
        <div className="space-y-4">
          {/* Interactive Topology Graph */}
          <section className="panel p-4" aria-labelledby="topo-heading">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b pb-3 mb-3" style={{ borderColor: "var(--border)" }}>
              <div>
                <h2 id="topo-heading" className="panel-title">
                  <ShieldIcon className="h-3.5 w-3.5 text-accent" />
                  Policy Topology · Deterministic Runtime Cascade
                </h2>
                <p className="text-[11px] mt-0.5" style={{ color: "var(--muted)" }}>
                  Actions flow through Fast Filters → Injection Scanner → Intent Firewall → Decision Gate
                </p>
              </div>
              {result && <DecisionBadge decision={result.evaluation.decision} />}
            </div>

            <Topology result={result} />
          </section>

          {/* Quick-Action Evaluation Launcher */}
          <section className="panel p-4" aria-labelledby="quick-launcher-heading">
            <div className="flex items-center justify-between mb-3">
              <h2 id="quick-launcher-heading" className="panel-title">
                <FlaskIcon className="h-3.5 w-3.5 text-accent" />
                Quick-Fire Evaluation · Seeded Scenarios
              </h2>
              <button
                type="button"
                onClick={() => onNavigate("scenarios")}
                className="text-xs text-accent hover:underline flex items-center gap-1"
              >
                Open Full Scenario Lab <ChevronIcon className="h-3 w-3" />
              </button>
            </div>

            <div className="grid gap-2 sm:grid-cols-3 mb-3">
              {scenarios.map((sc) => {
                const isSelected = sc.id === selectedScenarioId;
                return (
                  <button
                    key={sc.id}
                    type="button"
                    onClick={() => onSelectScenarioId(sc.id)}
                    className="p-2.5 rounded-lg text-left transition-all border flex flex-col justify-between"
                    style={
                      isSelected
                        ? {
                            background: "rgba(53, 230, 208, 0.12)",
                            borderColor: "var(--accent)",
                            boxShadow: "0 0 10px rgba(53, 230, 208, 0.15)",
                          }
                        : {
                            background: "#071014",
                            borderColor: "var(--border)",
                          }
                    }
                  >
                    <div>
                      <span className="text-xs font-semibold block truncate" style={{ color: isSelected ? "var(--text-bright)" : "var(--text)" }}>
                        {sc.label}
                      </span>
                      <span className="text-[10px] block line-clamp-2 mt-1" style={{ color: "var(--muted)" }}>
                        {sc.description}
                      </span>
                    </div>
                    <span className="text-[9px] font-mono mt-2 uppercase" style={{ color: "var(--accent-blue)" }}>
                      Tool: {sc.action.tool}
                    </span>
                  </button>
                );
              })}
            </div>

            <div className="flex flex-wrap items-center justify-between gap-3 pt-2 border-t" style={{ borderColor: "var(--border-subtle)" }}>
              <div className="text-xs" style={{ color: "var(--muted)" }}>
                Selected: <strong style={{ color: "var(--text)" }}>{selected?.label ?? "None"}</strong> · Mode: <span className="font-mono text-cyan-400">SIMULATED</span>
              </div>
              <button
                type="button"
                onClick={() => void onEvaluate()}
                disabled={isBusy || !selectedScenarioId}
                className="btn-primary"
              >
                {isBusy ? "Evaluating Action…" : "Evaluate Action Now"}
              </button>
            </div>
          </section>
        </div>

        {/* Right Column: Security Posture & Recent Activity */}
        <div className="space-y-4">
          {/* Security Posture Panel */}
          <section className="panel p-4" aria-labelledby="posture-heading">
            <h2 id="posture-heading" className="panel-title">
              <ScaleIcon className="h-3.5 w-3.5 text-accent" />
              Session Posture Distribution
            </h2>
            <p className="text-[11px] mt-1 mb-3" style={{ color: "var(--muted)" }}>
              Distribution of real evaluated events in this local API session
            </p>

            <div className="space-y-2 mb-3">
              {(["ALLOW", "CONFIRM", "BLOCK"] as const).map((d) => (
                <div key={d} className="flex items-center justify-between text-xs">
                  <span className="flex items-center gap-1.5 font-semibold" style={{ color: decisionColor(d) }}>
                    <span
                      aria-hidden="true"
                      style={{ width: 6, height: 6, borderRadius: 99, background: decisionColor(d) }}
                    />
                    {d}
                  </span>
                  <span className="font-mono">{tally[d]}</span>
                </div>
              ))}
            </div>

            {totalDecisions === 0 ? (
              <p className="text-xs py-2 text-center rounded border" style={{ borderColor: "var(--border)", color: "var(--muted)" }}>
                No evaluations recorded yet. Run a scenario above.
              </p>
            ) : (
              <div className="flex h-2.5 overflow-hidden rounded-md border" style={{ borderColor: "var(--border)" }}>
                <span style={{ width: `${(tally.ALLOW / totalDecisions) * 100}%`, background: "var(--allow)" }} title={`ALLOW: ${tally.ALLOW}`} />
                <span style={{ width: `${(tally.CONFIRM / totalDecisions) * 100}%`, background: "var(--confirm)" }} title={`CONFIRM: ${tally.CONFIRM}`} />
                <span style={{ width: `${(tally.BLOCK / totalDecisions) * 100}%`, background: "var(--block)" }} title={`BLOCK: ${tally.BLOCK}`} />
              </div>
            )}

            <div className="mt-3 pt-3 border-t text-[11px] space-y-1" style={{ borderColor: "var(--border-subtle)", color: "var(--muted)" }}>
              <p>• <strong>ALLOW:</strong> Allowlisted simulated handler executes immediately.</p>
              <p>• <strong>CONFIRM:</strong> Enters Approval Queue; requires human sign-off.</p>
              <p>• <strong>BLOCK:</strong> Hard deny; non-negotiable rejection.</p>
            </div>
          </section>

          {/* Quick Recent Activity Feed */}
          <section className="panel p-4 flex flex-col" aria-labelledby="activity-preview-heading">
            <div className="flex items-center justify-between mb-2">
              <h2 id="activity-preview-heading" className="panel-title">
                <ActivityIcon className="h-3.5 w-3.5 text-accent" />
                Recent Timeline
              </h2>
              <button
                type="button"
                onClick={() => onNavigate("activity")}
                className="text-xs text-accent hover:underline flex items-center gap-1"
              >
                View Audit <ChevronIcon className="h-3 w-3" />
              </button>
            </div>

            {events.length === 0 ? (
              <p className="text-xs py-4 text-center" style={{ color: "var(--muted)" }}>
                No events recorded yet.
              </p>
            ) : (
              <ul className="space-y-2 mt-1">
                {events.slice(0, 5).map((e) => (
                  <li
                    key={e.id}
                    className="p-2 rounded-lg text-xs flex items-center justify-between border"
                    style={{ background: "#060e12", borderColor: "var(--border-subtle)" }}
                  >
                    <div className="flex items-center gap-2 min-w-0">
                      <DecisionBadge decision={e.decision} size="sm" />
                      <span className="truncate font-mono text-[11px]">{e.actionType}</span>
                    </div>
                    <span className="text-[10px] font-mono shrink-0" style={{ color: "var(--muted)" }}>
                      {new Date(e.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </div>
      </div>
    </div>
  );
}
