import type { ModelStatus, View } from "../types.js";
import { NAVIGATION_ITEMS } from "./Sidebar.js";
import { RefreshIcon, ShieldIcon } from "./icons.js";

interface TopBarProps {
  currentView: View;
  onSelectView: (view: View) => void;
  apiOnline: boolean | null;
  modelStatus: ModelStatus | null;
  onRefresh: () => void;
  isRefreshing: boolean;
}

export default function TopBar({
  currentView,
  onSelectView,
  apiOnline,
  modelStatus,
  onRefresh,
  isRefreshing,
}: TopBarProps) {
  const currentItem = NAVIGATION_ITEMS.find((n) => n.id === currentView) ?? NAVIGATION_ITEMS[0];

  return (
    <header
      className="sticky top-0 z-30 flex flex-wrap items-center justify-between gap-3 px-4 py-3"
      style={{
        background: "rgba(5, 9, 13, 0.92)",
        borderBottom: "1px solid var(--border)",
        backdropFilter: "blur(12px)",
      }}
    >
      {/* Title & Screen Badge */}
      <div className="flex items-center gap-3">
        <div className="flex items-center gap-2 lg:hidden" style={{ color: "var(--accent)" }}>
          <ShieldIcon className="h-6 w-6" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-base sm:text-lg font-bold tracking-tight" style={{ color: "var(--text-bright)" }}>
              {currentItem.label}
            </h1>
            <span
              className="hidden sm:inline-flex text-[10px] font-mono px-2 py-0.5 rounded"
              style={{
                background: "rgba(16, 35, 41, 0.9)",
                border: "1px solid var(--border)",
                color: "var(--muted)",
              }}
              title={`Stitch Screen ID: ${currentItem.stitchScreenId}`}
            >
              Stitch Screen: {currentItem.stitchScreenId.slice(0, 8)}…
            </span>
          </div>
          <p className="text-[11px] hidden sm:block" style={{ color: "var(--muted)" }}>
            Deterministic AI Runtime Firewall · Zero Live Side Effects
          </p>
        </div>
      </div>

      {/* System Status Indicators */}
      <div className="flex flex-wrap items-center gap-2">
        {/* API Status */}
        <span
          className="badge"
          style={{
            borderColor: apiOnline ? "rgba(52, 211, 153, 0.3)" : "rgba(248, 113, 113, 0.3)",
            color: apiOnline ? "var(--allow)" : "var(--block)",
          }}
        >
          <span
            aria-hidden="true"
            style={{
              width: 6,
              height: 6,
              borderRadius: 99,
              background: apiOnline ? "var(--allow)" : "var(--block)",
            }}
          />
          {apiOnline === null ? "API: checking…" : apiOnline ? "API: Online" : "API: Offline"}
        </span>

        {/* Model Layer Status */}
        <span
          className="badge hidden md:inline-flex"
          style={{
            borderColor: "rgba(167, 139, 250, 0.35)",
            color: "var(--advisory)",
          }}
        >
          {modelStatus
            ? `Advisory Model: ${modelStatus.mode.toUpperCase()} (Live ${modelStatus.liveEnabled ? "ON" : "OFF"})`
            : "Advisory Model: Loading…"}
        </span>

        {/* Execution Mode */}
        <span
          className="badge"
          style={{
            borderColor: "rgba(53, 230, 208, 0.35)",
            color: "var(--accent)",
          }}
        >
          SIMULATED ONLY
        </span>

        {/* Refresh Button */}
        <button
          type="button"
          onClick={onRefresh}
          disabled={isRefreshing}
          className="btn-ghost"
          title="Refresh server state (events & approvals)"
        >
          <RefreshIcon className={`h-3.5 w-3.5 ${isRefreshing ? "animate-spin" : ""}`} />
          <span className="hidden sm:inline">Refresh</span>
        </button>
      </div>

      {/* Mobile Screen Selector (dropdown for smaller screens) */}
      <div className="w-full lg:hidden pt-2 border-t mt-1" style={{ borderColor: "var(--border-subtle)" }}>
        <select
          value={currentView}
          onChange={(e) => onSelectView(e.target.value as View)}
          className="field text-xs py-1.5"
          aria-label="Select screen"
        >
          {NAVIGATION_ITEMS.map((item) => (
            <option key={item.id} value={item.id}>
              {item.label}
            </option>
          ))}
        </select>
      </div>
    </header>
  );
}
