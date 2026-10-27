import type { EvaluateResponse } from "../types.js";

const OUTCOMES = [
  { key: "ALLOW", label: "ALLOW", color: "#34d399", y: 34 },
  { key: "CONFIRM", label: "CONFIRM", color: "#fbbf24", y: 112 },
  { key: "BLOCK", label: "BLOCK", color: "#f87171", y: 190 },
] as const;

const STAGES = [
  { x: 78, label: "Request", sub: "Proposed action" },
  { x: 238, label: "Scanner", sub: "Untrusted content" },
  { x: 398, label: "Intent Firewall", sub: "Explicit permissions" },
  { x: 558, label: "Decision Gate", sub: "Policy · v1" },
] as const;

/**
 * AgentShield policy topology. A stage is only highlighted when a real
 * evaluation response exists; otherwise the graph is in a neutral idle state.
 */
export default function Topology({ result }: { result: EvaluateResponse | null }) {
  const decision = result?.evaluation.decision ?? null;
  const activeColor = OUTCOMES.find((o) => o.key === decision)?.color ?? "#35e6d0";
  const evaluated = result !== null;

  return (
    <div>
      <svg viewBox="0 0 800 260" className="hidden w-full md:block" role="img" aria-label="AgentShield policy flow: request, scanner, intent firewall, decision gate, then allow, confirm, or block">
        {STAGES.slice(0, -1).map((stage, i) => (
          <path key={stage.label} className="topo-path" d={`M ${stage.x + 52} 130 L ${STAGES[i + 1].x - 52} 130`} stroke={evaluated ? activeColor : "#193941"} strokeWidth={evaluated ? 2 : 1.5} fill="none" opacity={evaluated ? 0.85 : 0.7} />
        ))}
        {OUTCOMES.map((outcome) => {
          const active = decision === outcome.key;
          return (
            <g key={outcome.key}>
              <path className="topo-path" d={`M 610 130 C 660 ${130}, 650 ${outcome.y + 16}, 676 ${outcome.y + 16}`} stroke={active ? outcome.color : "#193941"} strokeWidth={active ? 2.5 : 1.5} fill="none" opacity={active ? 1 : 0.55} />
              <rect x="678" y={outcome.y} width="104" height="32" rx="6" fill={active ? "#102329" : "#0b171c"} stroke={active ? outcome.color : "#193941"} strokeWidth={active ? 1.8 : 1} />
              <text x="730" y={outcome.y + 20} textAnchor="middle" fontSize="11" fontWeight="700" fill={active ? outcome.color : "#8aa3ad"}>{outcome.label}</text>
            </g>
          );
        })}
        {STAGES.map((stage, i) => {
          const active = evaluated;
          return (
            <g key={stage.label}>
              <circle cx={stage.x} cy="130" r="30" fill="#0b171c" stroke={active ? activeColor : "#2a4a52"} strokeWidth={active ? 1.8 : 1.2} />
              <text x={stage.x} y="126" textAnchor="middle" fontSize="10.5" fontWeight="700" fill="#e6f2f2">{stage.label.split(" ")[0]}</text>
              <text x={stage.x} y="140" textAnchor="middle" fontSize="8.5" fill="#8aa3ad">{stage.label.split(" ").slice(1).join(" ") || `Stage ${i + 1}`}</text>
              <text x={stage.x} y="182" textAnchor="middle" fontSize="9" fill="#8aa3ad">{stage.sub}</text>
            </g>
          );
        })}
        <text x="400" y="238" textAnchor="middle" fontSize="10" fill="#8aa3ad">
          {evaluated ? `Evaluated path highlighted from the actual API response · decision ${decision}` : "Idle — run a seeded scenario to trace the evaluated path"}
        </text>
      </svg>

      {/* Simplified flow for small screens */}
      <ol className="flex flex-wrap items-center gap-1.5 text-xs md:hidden" aria-label="Policy flow stages">
        {["Request", "Scanner", "Intent Firewall", "Decision Gate", decision ?? "ALLOW / CONFIRM / BLOCK"].map((label, i, arr) => (
          <li key={label} className="flex items-center gap-1.5">
            <span className="badge" style={evaluated && i === arr.length - 1 ? { borderColor: activeColor, color: activeColor } : undefined}>{label}</span>
            {i < arr.length - 1 && <span aria-hidden="true" style={{ color: "#35e6d0" }}>→</span>}
          </li>
        ))}
      </ol>
      <p className="mt-2 text-xs" style={{ color: "var(--muted)" }}>
        Deterministic policy topology only. This is not live network activity and does not depict external infrastructure.
      </p>
    </div>
  );
}
