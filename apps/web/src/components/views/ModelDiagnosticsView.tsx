import { useState } from "react";
import type { EvaluateResponse, ModelStatus } from "../../types.js";
import { MetricCard } from "../common.js";
import {
  AlertTriangleIcon,
  CheckCircleIcon,
  CpuIcon,
  InfoIcon,
  LockIcon,
  RefreshIcon,
  ShieldIcon,
  TerminalIcon,
} from "../icons.js";

interface ModelDiagnosticsViewProps {
  modelStatus: ModelStatus | null;
  result: EvaluateResponse | null;
  onRefreshStatus: () => Promise<void>;
}

export default function ModelDiagnosticsView({
  modelStatus,
  result,
  onRefreshStatus,
}: ModelDiagnosticsViewProps) {
  const [checking, setChecking] = useState(false);

  const handleTestPing = async () => {
    setChecking(true);
    try {
      await onRefreshStatus();
    } finally {
      setChecking(false);
    }
  };

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
              background: "rgba(167, 139, 250, 0.15)",
              border: "1px solid var(--advisory)",
              color: "var(--advisory)",
            }}
          >
            <CpuIcon className="h-5 w-5" />
          </div>
          <div>
            <h2 className="text-base font-bold" style={{ color: "var(--text-bright)" }}>
              Model Diagnostics · Advisory Layer Telemetry
            </h2>
            <p className="text-xs" style={{ color: "var(--muted)" }}>
              Runtime configuration, health checks, guardrails, and validation contracts for LLM-assisted analysis
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={handleTestPing}
            disabled={checking}
            className="btn-ghost text-xs"
          >
            <RefreshIcon className={`h-3.5 w-3.5 ${checking ? "animate-spin" : ""}`} />
            {checking ? "Checking…" : "Run Status Ping"}
          </button>
          <span className="badge font-mono" style={{ borderColor: "var(--advisory)", color: "var(--advisory)" }}>
            ADVISORY ONLY
          </span>
        </div>
      </div>

      {/* Status KPI Cards */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <MetricCard
          title="Provider Mode"
          value={modelStatus?.mode.toUpperCase() ?? "UNKNOWN"}
          subtitle="Offline synthetic provider"
          badge="LOCAL"
          color="var(--advisory)"
          icon={<CpuIcon className="h-4 w-4" />}
        />
        <MetricCard
          title="Live Provider Gating"
          value={modelStatus?.liveEnabled ? "LIVE ON" : "LOCKED OFF"}
          subtitle={modelStatus?.liveEnabled ? "Real API calls enabled" : "Zero live credits consumed"}
          badge={modelStatus?.liveEnabled ? "ACTIVE" : "PROTECTED"}
          color={modelStatus?.liveEnabled ? "var(--confirm)" : "var(--allow)"}
          icon={<LockIcon className="h-4 w-4" />}
        />
        <MetricCard
          title="Target Model"
          value={modelStatus?.model ?? "muse-spark-1.3"}
          subtitle="Meta AI / Muse Spark v1.3"
          badge="ADVISORY"
          color="var(--accent-blue)"
          icon={<TerminalIcon className="h-4 w-4" />}
        />
        <MetricCard
          title="Key Security"
          value={modelStatus?.apiKeyConfigured ? "CONFIGURED" : "NOT SET"}
          subtitle="Value masked · never exposed"
          badge="PROTECTED"
          color={modelStatus?.apiKeyConfigured ? "var(--allow)" : "var(--muted)"}
          icon={<ShieldIcon className="h-4 w-4" />}
        />
      </div>

      {/* Main Technical Specs & Guardrails */}
      <div className="grid gap-4 lg:grid-cols-2">
        {/* Specification & Environment Settings */}
        <section className="panel p-4" aria-labelledby="specs-heading">
          <h3 id="specs-heading" className="panel-title mb-3">
            <TerminalIcon className="h-4 w-4 text-accent" />
            Provider Configuration Parameters
          </h3>
          <div className="space-y-2 text-xs">
            <div className="p-2.5 rounded border flex items-center justify-between" style={{ background: "#060d11", borderColor: "var(--border)" }}>
              <span className="text-muted">Target Endpoint Base URL:</span>
              <span className="font-mono text-cyan-300">https://api.meta.ai/v1</span>
            </div>
            <div className="p-2.5 rounded border flex items-center justify-between" style={{ background: "#060d11", borderColor: "var(--border)" }}>
              <span className="text-muted">Auth Header Contract:</span>
              <span className="font-mono text-slate-200">Bearer &lt;MODEL_API_KEY&gt;</span>
            </div>
            <div className="p-2.5 rounded border flex items-center justify-between" style={{ background: "#060d11", borderColor: "var(--border)" }}>
              <span className="text-muted">Request Timeout:</span>
              <span className="font-mono text-slate-200">5,000 ms</span>
            </div>
            <div className="p-2.5 rounded border flex items-center justify-between" style={{ background: "#060d11", borderColor: "var(--border)" }}>
              <span className="text-muted">Bounded Retry Limit:</span>
              <span className="font-mono text-slate-200">2 attempts (exponential backoff)</span>
            </div>
            <div className="p-2.5 rounded border flex items-center justify-between" style={{ background: "#060d11", borderColor: "var(--border)" }}>
              <span className="text-muted">Payload Bounds:</span>
              <span className="font-mono text-slate-200">4,000 chars max input / output</span>
            </div>
            <div className="p-2.5 rounded border flex items-center justify-between" style={{ background: "#060d11", borderColor: "var(--border)" }}>
              <span className="text-muted">Safety Gating Guard:</span>
              <span className="font-mono text-emerald-400">MODEL_LIVE_ENABLED=false (Enforced)</span>
            </div>
          </div>
          <p className="text-[10px] mt-3 text-muted">
            {modelStatus?.note ?? "Status loaded from GET /api/model/status"}
          </p>
        </section>

        {/* Strict Guardrails & Anti-Hijacking Protections */}
        <section className="panel p-4" aria-labelledby="guardrails-heading">
          <h3 id="guardrails-heading" className="panel-title mb-3">
            <ShieldIcon className="h-4 w-4 text-purple-400" />
            Advisory Layer Architecture & Guardrails
          </h3>
          <div className="space-y-2.5 text-xs">
            <div className="p-2.5 rounded border" style={{ background: "#060d11", borderColor: "var(--border)" }}>
              <span className="font-bold text-slate-100 flex items-center gap-1.5 mb-1">
                <CheckCircleIcon className="h-3.5 w-3.5 text-emerald-400" />
                1. Authoritative Determinism
              </span>
              <p className="text-[11px] text-muted">
                The AI model is purely an observer. The decision to ALLOW, CONFIRM, or BLOCK is calculated exclusively by the deterministic rule engine (Fast Filters, Regex Scanner, Intent Firewall).
              </p>
            </div>

            <div className="p-2.5 rounded border" style={{ background: "#060d11", borderColor: "var(--border)" }}>
              <span className="font-bold text-slate-100 flex items-center gap-1.5 mb-1">
                <LockIcon className="h-3.5 w-3.5 text-cyan-400" />
                2. Output Schema Validation
              </span>
              <p className="text-[11px] text-muted">
                Provider responses are strictly validated in the engine (`validateModelOutput`). Any decision field, approval tag, or attempted tool execution inside model output triggers immediate validation failure.
              </p>
            </div>

            <div className="p-2.5 rounded border" style={{ background: "#060d11", borderColor: "var(--border)" }}>
              <span className="font-bold text-slate-100 flex items-center gap-1.5 mb-1">
                <AlertTriangleIcon className="h-3.5 w-3.5 text-amber-400" />
                3. Fail-Safe Principle
              </span>
              <p className="text-[11px] text-muted">
                Network drops, provider outages, timeouts, or budget exhaustion are flagged as failures and never interpreted as evidence that the untrusted content is safe.
              </p>
            </div>
          </div>
        </section>
      </div>

      {/* Last Evaluation Model Analysis Telemetry */}
      {result && (
        <section className="panel p-4">
          <h3 className="panel-title mb-2">Last Advisory Observation Telemetry</h3>
          <div className="p-3 rounded border text-xs space-y-1.5 font-mono" style={{ background: "#04090c", borderColor: "var(--border)" }}>
            <div className="text-purple-300">Observation Status: {result.modelAnalysis.status}</div>
            <div className="text-slate-200">Summary: {result.modelAnalysis.summary}</div>
            <div className="text-muted text-[11px]">Explanation: {result.modelAnalysis.explanation}</div>
            <div className="text-muted text-[11px]">
              Indicators Flagged: {result.modelAnalysis.indicators.length}
            </div>
          </div>
        </section>
      )}
    </div>
  );
}
