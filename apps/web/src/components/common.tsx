import type { ReactNode } from "react";

export function decisionColor(decision: string): string {
  if (decision === "ALLOW") return "var(--allow)";
  if (decision === "BLOCK") return "var(--block)";
  return "var(--confirm)";
}

export function DecisionBadge({ decision, size = "md" }: { decision: string; size?: "sm" | "md" }) {
  const color = decisionColor(decision);
  const isSm = size === "sm";
  return (
    <span
      className="badge font-mono"
      style={{
        borderColor: color,
        color,
        background: `rgba(16, 35, 41, 0.9)`,
        boxShadow: `0 0 8px ${color}22`,
        padding: isSm ? "0.1rem 0.45rem" : "0.15rem 0.6rem",
        fontSize: isSm ? "0.62rem" : "0.68rem",
      }}
    >
      <span
        aria-hidden="true"
        style={{
          width: isSm ? 5 : 7,
          height: isSm ? 5 : 7,
          borderRadius: 99,
          background: color,
          display: "inline-block",
        }}
      />
      {decision}
    </span>
  );
}

export function TruncateText({ text, max = 320 }: { text: string; max?: number }) {
  const isLong = text.length > max;
  return <span>{isLong ? `${text.slice(0, max)}… (${text.length} chars)` : text}</span>;
}

export function MetricCard({
  title,
  value,
  subtitle,
  badge,
  color = "var(--accent)",
  icon,
}: {
  title: string;
  value: string | number;
  subtitle?: string;
  badge?: string;
  color?: string;
  icon?: ReactNode;
}) {
  return (
    <div
      className="panel p-3.5 flex flex-col justify-between"
      style={{
        borderLeft: `3px solid ${color}`,
      }}
    >
      <div className="flex items-center justify-between text-xs mb-1" style={{ color: "var(--muted)" }}>
        <span className="font-semibold uppercase tracking-wider text-[10px]">{title}</span>
        {icon && <span style={{ color }}>{icon}</span>}
        {badge && (
          <span
            className="text-[9px] font-mono px-1.5 py-0.2 rounded"
            style={{ background: `${color}15`, color, border: `1px solid ${color}40` }}
          >
            {badge}
          </span>
        )}
      </div>
      <div className="text-xl sm:text-2xl font-bold font-mono tracking-tight my-1" style={{ color: "var(--text-bright)" }}>
        {value}
      </div>
      {subtitle && <div className="text-[11px]" style={{ color: "var(--muted)" }}>{subtitle}</div>}
    </div>
  );
}
