import type { View } from "../types.js";
import {
  ActivityIcon,
  CheckBadgeIcon,
  CpuIcon,
  FlaskIcon,
  GlobeIcon,
  GridIcon,
  ScaleIcon,
  SearchIcon,
  ShieldIcon,
  ToolIcon,
} from "./icons.js";

interface SidebarProps {
  currentView: View;
  onSelectView: (view: View) => void;
  pendingCount: number;
  totalEvents: number;
  apiOnline: boolean | null;
}

export const NAVIGATION_ITEMS: Array<{
  id: View;
  label: string;
  /** Design reference; screens added after the original design have none. */
  stitchScreenId?: string;
  Icon: typeof GridIcon;
  badge?: string;
}> = [
  { id: "command", label: "Command Center", stitchScreenId: "c5569a062fec4d51b85e84cc2f74fb79", Icon: GridIcon },
  { id: "scenarios", label: "Scenario Lab", stitchScreenId: "e0563c3911df4a5a8acba6825bd19479", Icon: FlaskIcon },
  { id: "investigation", label: "Threat Investigation", stitchScreenId: "1bb0e42734b540c3a4f1d662c19bc9ac", Icon: SearchIcon },
  { id: "policy", label: "Policy & Actions", stitchScreenId: "089cde18e1684c08b955c1df23fa2f36", Icon: ScaleIcon },
  { id: "approvals", label: "Approval Queue", stitchScreenId: "bf85f313e08147968891d5ffc7e7b6b7", Icon: CheckBadgeIcon },
  { id: "diagnostics", label: "Model Diagnostics", stitchScreenId: "74d6cc7c6579466dba28cb67b6594e5b", Icon: CpuIcon },
  { id: "tool-trust", label: "Tool Trust Preview", stitchScreenId: "d5a7bc8590c0475fb84f026dd46329e6", Icon: ToolIcon, badge: "PREVIEW" },
  { id: "scans", label: "Website Scans", Icon: GlobeIcon },
  { id: "activity", label: "Activity & Audit", stitchScreenId: "09d4c88ac5274d37b0943f4192216a0c", Icon: ActivityIcon },
];

export default function Sidebar({
  currentView,
  onSelectView,
  pendingCount,
  totalEvents,
  apiOnline,
}: SidebarProps) {
  return (
    <aside
      className="sticky top-0 hidden h-screen w-64 shrink-0 flex-col py-4 px-3 lg:flex"
      style={{
        background: "linear-gradient(180deg, rgba(8, 16, 22, 0.98) 0%, rgba(5, 9, 13, 0.99) 100%)",
        borderRight: "1px solid var(--border)",
      }}
      aria-label="AgentShield Primary Navigation"
    >
      {/* Brand Header */}
      <div className="flex items-center gap-3 px-2 pb-4 mb-3 border-b" style={{ borderColor: "var(--border)" }}>
        <div
          className="flex h-10 w-10 items-center justify-center rounded-lg"
          style={{
            background: "linear-gradient(135deg, rgba(53, 230, 208, 0.2) 0%, rgba(72, 169, 255, 0.1) 100%)",
            border: "1px solid var(--accent)",
            boxShadow: "0 0 15px rgba(53, 230, 208, 0.25)",
            color: "var(--accent)",
          }}
        >
          <ShieldIcon className="h-6 w-6" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <span className="text-sm font-bold tracking-wide" style={{ color: "var(--text-bright)" }}>
              AgentShield
            </span>
            <span
              className="text-[10px] font-mono px-1.5 py-0.2 rounded"
              style={{ background: "rgba(53, 230, 208, 0.15)", color: "var(--accent)", border: "1px solid rgba(53, 230, 208, 0.3)" }}
            >
              v1.0
            </span>
          </div>
          <p className="text-[11px] truncate" style={{ color: "var(--muted)" }}>
            AI Security Command Center
          </p>
        </div>
      </div>

      {/* Navigation List */}
      <div className="text-[10px] font-bold uppercase tracking-wider px-2 mb-1.5" style={{ color: "var(--muted-dark)" }}>
        Navigation · 8 Stitch Views
      </div>
      <nav className="flex-1 space-y-1 overflow-y-auto pr-1" aria-label="Views">
        {NAVIGATION_ITEMS.map(({ id, label, Icon, badge }) => {
          const isActive = currentView === id;
          return (
            <button
              key={id}
              type="button"
              onClick={() => onSelectView(id)}
              className="group flex w-full items-center gap-2.5 rounded-lg px-2.5 py-2 text-left text-xs font-medium transition-all"
              style={
                isActive
                  ? {
                      background: "linear-gradient(90deg, rgba(53, 230, 208, 0.15) 0%, rgba(16, 35, 41, 0.8) 100%)",
                      color: "var(--accent)",
                      border: "1px solid rgba(53, 230, 208, 0.4)",
                      boxShadow: "0 0 12px rgba(53, 230, 208, 0.15)",
                    }
                  : {
                      color: "var(--muted)",
                      background: "transparent",
                      border: "1px solid transparent",
                    }
              }
            >
              <span
                className="transition-colors group-hover:text-accent"
                style={{ color: isActive ? "var(--accent)" : "inherit" }}
              >
                <Icon className="h-4 w-4 shrink-0" />
              </span>
              <span className="truncate flex-1 font-semibold">{label}</span>

              {/* Dynamic Badges */}
              {id === "approvals" && pendingCount > 0 && (
                <span
                  className="rounded-full px-1.5 py-0.5 text-[10px] font-mono font-bold"
                  style={{
                    background: "rgba(251, 191, 36, 0.2)",
                    color: "var(--confirm)",
                    border: "1px solid var(--confirm)",
                  }}
                >
                  {pendingCount}
                </span>
              )}
              {id === "activity" && totalEvents > 0 && (
                <span
                  className="rounded px-1.5 py-0.5 text-[10px] font-mono"
                  style={{
                    background: "rgba(16, 35, 41, 0.8)",
                    color: "var(--muted)",
                    border: "1px solid var(--border)",
                  }}
                >
                  {totalEvents}
                </span>
              )}
              {badge && (
                <span
                  className="rounded px-1.5 py-0.2 text-[9px] font-mono uppercase"
                  style={{
                    background: "rgba(167, 139, 250, 0.15)",
                    color: "var(--advisory)",
                    border: "1px solid rgba(167, 139, 250, 0.3)",
                  }}
                >
                  {badge}
                </span>
              )}
            </button>
          );
        })}
      </nav>

      {/* Footer System Status */}
      <div
        className="mt-auto rounded-lg p-2.5 text-xs border"
        style={{ background: "#060e12", borderColor: "var(--border)" }}
      >
        <div className="flex items-center justify-between mb-1.5">
          <span className="text-[11px] font-semibold" style={{ color: "var(--muted)" }}>
            Engine Status
          </span>
          <span className="flex items-center gap-1.5 text-[10px] font-mono font-semibold">
            <span
              aria-hidden="true"
              style={{
                width: 7,
                height: 7,
                borderRadius: 99,
                background: apiOnline ? "var(--allow)" : "var(--block)",
                boxShadow: apiOnline ? "0 0 6px var(--allow)" : "none",
              }}
            />
            {apiOnline === null ? "CHECKING" : apiOnline ? "CONNECTED" : "OFFLINE"}
          </span>
        </div>
        <div className="text-[10px] space-y-0.5" style={{ color: "var(--muted)" }}>
          <p className="flex justify-between">
            <span>Enforcement:</span>
            <span className="font-semibold text-emerald-400">Authoritative</span>
          </p>
          <p className="flex justify-between">
            <span>Execution:</span>
            <span className="font-mono text-cyan-400">SIMULATED</span>
          </p>
        </div>
      </div>
    </aside>
  );
}
