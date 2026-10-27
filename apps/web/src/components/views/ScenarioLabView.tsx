import { useState } from "react";
import type { EvaluateResponse, Scenario, View } from "../../types.js";
import { DecisionBadge, decisionColor } from "../common.js";
import {
  AlertTriangleIcon,
  CheckCircleIcon,
  ChevronIcon,
  CopyIcon,
  FlaskIcon,
  InfoIcon,
  LockIcon,
  SearchIcon,
  TerminalIcon,
} from "../icons.js";

interface ScenarioLabViewProps {
  scenarios: Scenario[];
  selectedScenarioId: string;
  onSelectScenarioId: (id: string) => void;
  result: EvaluateResponse | null;
  onEvaluate: () => Promise<void>;
  isBusy: boolean;
  onNavigate: (view: View) => void;
}

export default function ScenarioLabView({
  scenarios,
  selectedScenarioId,
  onSelectScenarioId,
  result,
  onEvaluate,
  isBusy,
  onNavigate,
}: ScenarioLabViewProps) {
  const [copied, setCopied] = useState(false);
  const selected = scenarios.find((s) => s.id === selectedScenarioId);

  const handleCopyContent = () => {
    if (selected?.untrustedContent?.text) {
      void navigator.clipboard.writeText(selected.untrustedContent.text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="space-y-4">
      {/* Header Info Banner */}
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
              background: "rgba(53, 230, 208, 0.15)",
              border: "1px solid var(--accent)",
              color: "var(--accent)",
            }}
          >
            <FlaskIcon className="h-5 w-5" />
          </div>
          <div>
            <h2 className="text-base font-bold" style={{ color: "var(--text-bright)" }}>
              Scenario Lab · Seeded Attack Harness
            </h2>
            <p className="text-xs" style={{ color: "var(--muted)" }}>
              Deterministic test scenarios simulating prompt injection attacks, benign tasks, and hard-deny actions
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className="badge">Total Seeded: {scenarios.length}</span>
          <span className="badge" style={{ borderColor: "var(--accent)", color: "var(--accent)" }}>
            SIMULATED ONLY
          </span>
        </div>
      </div>

      {/* Scenario Selector Cards */}
      <div className="grid gap-3 sm:grid-cols-3">
        {scenarios.map((sc) => {
          const isSelected = sc.id === selectedScenarioId;
          const isInjection = sc.id.includes("injection");
          const isForbidden = sc.id.includes("forbidden");
          const isBenign = sc.id.includes("benign");

          const categoryColor = isInjection
            ? "var(--confirm)"
            : isForbidden
            ? "var(--block)"
            : "var(--allow)";

          return (
            <button
              key={sc.id}
              type="button"
              onClick={() => onSelectScenarioId(sc.id)}
              className="panel p-3.5 text-left transition-all relative flex flex-col justify-between"
              style={
                isSelected
                  ? {
                      borderColor: categoryColor,
                      boxShadow: `0 0 15px ${categoryColor}25`,
                      background: "rgba(16, 35, 41, 0.9)",
                    }
                  : {
                      background: "#071014",
                    }
              }
            >
              <div>
                <div className="flex items-center justify-between gap-1 mb-1.5">
                  <span
                    className="text-[9px] font-mono font-bold uppercase px-1.5 py-0.2 rounded"
                    style={{
                      background: `${categoryColor}18`,
                      color: categoryColor,
                      border: `1px solid ${categoryColor}40`,
                    }}
                  >
                    {isInjection ? "INJECTION TEST" : isForbidden ? "HARD DENY TEST" : "BENIGN TASK"}
                  </span>
                  {isSelected && (
                    <span className="text-[10px] font-mono text-cyan-400 flex items-center gap-1 font-semibold">
                      <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 inline-block" /> ACTIVE
                    </span>
                  )}
                </div>
                <h3 className="text-xs sm:text-sm font-bold text-slate-100 line-clamp-1">{sc.label}</h3>
                <p className="text-[11px] mt-1 line-clamp-2" style={{ color: "var(--muted)" }}>
                  {sc.description}
                </p>
              </div>

              <div className="mt-3 pt-2 border-t flex items-center justify-between text-[10px] font-mono" style={{ borderColor: "var(--border-subtle)", color: "var(--muted)" }}>
                <span>Tool: {sc.action.tool}</span>
                <span className="truncate max-w-[120px]">{sc.action.destination}</span>
              </div>
            </button>
          );
        })}
      </div>

      {/* Deep Scenario Inspector */}
      {selected ? (
        <div className="grid gap-4 lg:grid-cols-3">
          {/* Panel 1: User Intent Contract */}
          <div className="panel p-4 flex flex-col justify-between">
            <div>
              <div className="flex items-center gap-1.5 mb-2 text-xs font-bold uppercase tracking-wider text-muted">
                <LockIcon className="h-3.5 w-3.5 text-accent" /> User Intent Contract
              </div>
              <p className="text-xs mb-3" style={{ color: "var(--muted)" }}>
                Explicit user authorization boundaries captured before agent tool execution.
              </p>
              <div className="space-y-3 text-xs">
                <div>
                  <span className="font-semibold block text-slate-200">Specified Task:</span>
                  <div className="p-2 rounded mt-1 font-mono text-[11px] border" style={{ background: "#05090d", borderColor: "var(--border-subtle)", color: "var(--accent)" }}>
                    "{selected.intent.task}"
                  </div>
                </div>
                <div>
                  <span className="font-semibold block text-slate-200">Allowed Action Types:</span>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {selected.intent.allowedActions.length > 0 ? (
                      selected.intent.allowedActions.map((act) => (
                        <span key={act} className="badge text-[10px] text-emerald-400 border-emerald-900 bg-emerald-950/40">
                          {act}
                        </span>
                      ))
                    ) : (
                      <span className="text-[11px] text-amber-400 italic">None specified (Blocks conservatively)</span>
                    )}
                  </div>
                </div>
                {selected.intent.allowedDestinations && (
                  <div>
                    <span className="font-semibold block text-slate-200">Allowed Destinations:</span>
                    <div className="flex flex-wrap gap-1 mt-1">
                      {selected.intent.allowedDestinations.map((dest) => (
                        <span key={dest} className="badge text-[10px] text-blue-400 border-blue-900 bg-blue-950/40">
                          {dest}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>
            <div className="mt-4 pt-2 border-t text-[10px]" style={{ borderColor: "var(--border-subtle)", color: "var(--muted)" }}>
              Intent Firewall enforces strict explicit matching; missing permissions block conservatively.
            </div>
          </div>

          {/* Panel 2: Proposed Agent Action */}
          <div className="panel p-4 flex flex-col justify-between">
            <div>
              <div className="flex items-center gap-1.5 mb-2 text-xs font-bold uppercase tracking-wider text-muted">
                <TerminalIcon className="h-3.5 w-3.5 text-accent-blue" /> Proposed Agent Action
              </div>
              <p className="text-xs mb-3" style={{ color: "var(--muted)" }}>
                Action intercept proposed by the AI agent before execution is allowed.
              </p>
              <div className="space-y-3 text-xs">
                <div>
                  <span className="font-semibold block text-slate-200">Action Type:</span>
                  <div className="p-2 rounded mt-1 font-mono text-[11px] font-bold border" style={{ background: "#05090d", borderColor: "var(--border-subtle)", color: "var(--text-bright)" }}>
                    {selected.action.type}
                  </div>
                </div>
                <div>
                  <span className="font-semibold block text-slate-200">Target Tool:</span>
                  <div className="p-2 rounded mt-1 font-mono text-[11px] border" style={{ background: "#05090d", borderColor: "var(--border-subtle)", color: "var(--accent-blue)" }}>
                    {selected.action.tool}
                  </div>
                </div>
                <div>
                  <span className="font-semibold block text-slate-200">Target Destination:</span>
                  <div className="p-2 rounded mt-1 font-mono text-[11px] border truncate" style={{ background: "#05090d", borderColor: "var(--border-subtle)", color: "var(--text)" }}>
                    {selected.action.destination}
                  </div>
                </div>
              </div>
            </div>
            <div className="mt-4 pt-2 border-t text-[10px] flex items-center justify-between" style={{ borderColor: "var(--border-subtle)", color: "var(--muted)" }}>
              <span>Handler Mode:</span>
              <span className="badge text-[9px] text-cyan-300">SIMULATED EXECUTION</span>
            </div>
          </div>

          {/* Panel 3: Untrusted Content Inspector */}
          <div className="panel p-4 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-1.5 text-xs font-bold uppercase tracking-wider text-muted">
                  <AlertTriangleIcon className="h-3.5 w-3.5 text-amber-400" /> Untrusted Content
                </div>
                {selected.untrustedContent && (
                  <button
                    type="button"
                    onClick={handleCopyContent}
                    className="text-[10px] text-accent hover:underline flex items-center gap-1"
                  >
                    <CopyIcon className="h-3 w-3" /> {copied ? "Copied" : "Copy Payload"}
                  </button>
                )}
              </div>
              <p className="text-xs mb-2" style={{ color: "var(--muted)" }}>
                External document or web payload scanned strictly as data (never executed).
              </p>

              {selected.untrustedContent ? (
                <div>
                  <div className="flex items-center justify-between text-[10px] font-mono mb-1 text-slate-400">
                    <span>Source: {selected.untrustedContent.source}</span>
                    <span>Length: {selected.untrustedContent.text.length} chars</span>
                  </div>
                  <div
                    className="p-2.5 rounded font-mono text-[11px] leading-relaxed max-h-44 overflow-y-auto whitespace-pre-wrap border"
                    style={{
                      background: "#04080b",
                      borderColor: "var(--border)",
                      color: selected.id.includes("injection") ? "#fca5a5" : "#a5d8d3",
                    }}
                  >
                    {selected.untrustedContent.text}
                  </div>
                </div>
              ) : (
                <div className="p-4 text-center text-xs text-muted">
                  No untrusted external content attached to this scenario.
                </div>
              )}
            </div>
            <div className="mt-4 pt-2 border-t text-[10px]" style={{ borderColor: "var(--border-subtle)", color: "var(--muted)" }}>
              Redaction active: raw evidence is masked before exiting the evaluation engine.
            </div>
          </div>
        </div>
      ) : null}

      {/* Evaluate Trigger Bar */}
      <div className="panel p-4 flex flex-wrap items-center justify-between gap-3">
        <div className="text-xs" style={{ color: "var(--muted)" }}>
          Click <strong style={{ color: "var(--text)" }}>Evaluate Action</strong> to run the deterministic engine cascade. No real network call or file mutation occurs.
        </div>
        <button
          type="button"
          onClick={() => void onEvaluate()}
          disabled={isBusy || !selectedScenarioId}
          className="btn-primary px-6 py-2.5 text-sm"
        >
          {isBusy ? "Evaluating Action Cascade…" : "Evaluate Action Now"}
        </button>
      </div>

      {/* Instant Result Inspection Banner */}
      {result && (
        <div
          className="panel p-4 border"
          style={{
            borderColor: decisionColor(result.evaluation.decision),
            boxShadow: `0 0 20px ${decisionColor(result.evaluation.decision)}1a`,
          }}
        >
          <div className="flex flex-wrap items-center justify-between gap-3 mb-2">
            <div className="flex items-center gap-2">
              <span className="text-xs font-bold uppercase tracking-wider text-muted">Evaluation Decision:</span>
              <DecisionBadge decision={result.evaluation.decision} />
              <span className="badge text-[10px]">Risk: {result.evaluation.riskScore}/100</span>
              <span className="badge text-[10px]">Scanner: {result.evaluation.scannerStatus}</span>
            </div>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={() => onNavigate("investigation")}
                className="btn-ghost text-xs"
              >
                <SearchIcon className="h-3.5 w-3.5 text-accent" /> Inspect in Threat Investigation
              </button>
              {result.evaluation.decision === "CONFIRM" && (
                <button
                  type="button"
                  onClick={() => onNavigate("approvals")}
                  className="btn-primary text-xs"
                >
                  <CheckCircleIcon className="h-3.5 w-3.5" /> Review in Approval Queue
                </button>
              )}
            </div>
          </div>

          <p className="text-sm font-medium mb-3 text-slate-100">{result.evaluation.explanation}</p>

          <div className="grid gap-2 sm:grid-cols-3 text-xs pt-3 border-t" style={{ borderColor: "var(--border-subtle)" }}>
            <div>
              <span className="text-muted block text-[10px] uppercase">Simulated Execution:</span>
              <span className="font-semibold text-cyan-300">
                {result.executed ? `Executed (${result.execution.result})` : `Not executed (${result.execution.reason ?? "Blocked/Pending"})`}
              </span>
            </div>
            <div>
              <span className="text-muted block text-[10px] uppercase">Scanner Findings:</span>
              <span className="font-semibold">
                {result.evaluation.scannerFindings.length === 0 ? "0 rules matched" : `${result.evaluation.scannerFindings.length} rule(s) flagged`}
              </span>
            </div>
            <div>
              <span className="text-muted block text-[10px] uppercase">Model Advisory Analysis:</span>
              <span className="font-semibold text-purple-300">
                {result.modelAnalysis.status} ({result.modelAnalysis.isMock ? "Mock" : result.modelAnalysis.provider})
              </span>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
