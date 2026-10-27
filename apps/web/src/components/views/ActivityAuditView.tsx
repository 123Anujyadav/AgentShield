import { useMemo, useState } from "react";
import type { ActivityEvent, View } from "../../types.js";
import { DecisionBadge, decisionColor } from "../common.js";
import {
  ActivityIcon,
  ChevronIcon,
  CopyIcon,
  FlaskIcon,
  InfoIcon,
  SearchIcon,
  TerminalIcon,
} from "../icons.js";

interface ActivityAuditViewProps {
  events: ActivityEvent[];
  onNavigate: (view: View) => void;
}

export default function ActivityAuditView({
  events,
  onNavigate,
}: ActivityAuditViewProps) {
  const [filterDecision, setFilterDecision] = useState<string>("ALL");
  const [searchQuery, setSearchQuery] = useState("");
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const filteredEvents = useMemo(() => {
    return events.filter((e) => {
      const matchDecision = filterDecision === "ALL" || e.decision === filterDecision;
      const q = searchQuery.toLowerCase().trim();
      const matchSearch =
        !q ||
        e.actionType.toLowerCase().includes(q) ||
        e.destination.toLowerCase().includes(q) ||
        e.explanation.toLowerCase().includes(q) ||
        e.id.toLowerCase().includes(q);
      return matchDecision && matchSearch;
    });
  }, [events, filterDecision, searchQuery]);

  const handleExportJSON = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(events, null, 2));
    const downloadAnchor = document.createElement("a");
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `agentshield-audit-${new Date().toISOString().slice(0, 10)}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
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
              background: "rgba(53, 230, 208, 0.15)",
              border: "1px solid var(--accent)",
              color: "var(--accent)",
            }}
          >
            <ActivityIcon className="h-5 w-5" />
          </div>
          <div>
            <h2 className="text-base font-bold" style={{ color: "var(--text-bright)" }}>
              Activity & Audit · Session Event Timeline (In-Memory)
            </h2>
            <p className="text-xs" style={{ color: "var(--muted)" }}>
              Session record of agent action proposals, scanner checks, human authorizations, and engine decisions. Events are held in memory and reset when the API restarts.
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={handleExportJSON}
            disabled={events.length === 0}
            className="btn-ghost text-xs"
          >
            Export Session JSON
          </button>
          <span className="badge font-mono text-[10px]">
            {events.length} Recorded Event{events.length === 1 ? "" : "s"}
          </span>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="panel p-3 flex flex-wrap items-center justify-between gap-3">
        {/* Decision Filters */}
        <div className="flex items-center gap-1.5 overflow-x-auto text-xs">
          <span className="text-[10px] font-mono uppercase text-muted mr-1">Filter:</span>
          {["ALL", "ALLOW", "CONFIRM", "BLOCK"].map((type) => {
            const isSelected = filterDecision === type;
            const count =
              type === "ALL"
                ? events.length
                : events.filter((e) => e.decision === type).length;
            return (
              <button
                key={type}
                type="button"
                onClick={() => setFilterDecision(type)}
                className="px-2.5 py-1 rounded-md font-mono text-[11px] font-semibold transition-all border"
                style={
                  isSelected
                    ? {
                        background:
                          type === "ALLOW"
                            ? "rgba(52, 211, 153, 0.2)"
                            : type === "CONFIRM"
                            ? "rgba(251, 191, 36, 0.2)"
                            : type === "BLOCK"
                            ? "rgba(248, 113, 113, 0.2)"
                            : "rgba(53, 230, 208, 0.2)",
                        borderColor:
                          type === "ALLOW"
                            ? "var(--allow)"
                            : type === "CONFIRM"
                            ? "var(--confirm)"
                            : type === "BLOCK"
                            ? "var(--block)"
                            : "var(--accent)",
                        color:
                          type === "ALLOW"
                            ? "var(--allow)"
                            : type === "CONFIRM"
                            ? "var(--confirm)"
                            : type === "BLOCK"
                            ? "var(--block)"
                            : "var(--accent)",
                      }
                    : {
                        background: "#060d11",
                        borderColor: "var(--border)",
                        color: "var(--muted)",
                      }
                }
              >
                {type} ({count})
              </button>
            );
          })}
        </div>

        {/* Search Input */}
        <div className="flex items-center gap-2 w-full sm:w-64">
          <div className="relative w-full">
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search action, tool, destination…"
              className="field text-xs py-1.5 pl-7"
            />
            <SearchIcon className="h-3.5 w-3.5 text-muted absolute left-2 top-2.5 pointer-events-none" />
          </div>
          {searchQuery && (
            <button
              type="button"
              onClick={() => setSearchQuery("")}
              className="text-xs text-muted hover:text-white"
            >
              Clear
            </button>
          )}
        </div>
      </div>

      {/* Event Stream List */}
      <section className="space-y-2.5" aria-labelledby="timeline-events-heading">
        <h3 id="timeline-events-heading" className="sr-only">
          Timeline Events
        </h3>

        {filteredEvents.length === 0 ? (
          <div className="panel p-8 text-center space-y-3">
            <ActivityIcon className="h-8 w-8 text-muted mx-auto" />
            <h4 className="text-sm font-bold text-slate-100">
              {events.length === 0 ? "No Timeline Events Yet" : "No Events Match Current Filter"}
            </h4>
            <p className="text-xs text-muted max-w-md mx-auto">
              {events.length === 0
                ? "Actions evaluated in the Scenario Lab or Command Center will automatically be cataloged into this in-memory session timeline."
                : "Try resetting your decision filter or search keyword to view all recorded timeline events."}
            </p>
            {events.length === 0 && (
              <button
                type="button"
                onClick={() => onNavigate("scenarios")}
                className="btn-primary text-xs mx-auto flex items-center gap-1.5"
              >
                <FlaskIcon className="h-3.5 w-3.5" /> Launch Scenario Lab
              </button>
            )}
          </div>
        ) : (
          <div className="space-y-2">
            {filteredEvents.map((evt) => {
              const isExpanded = expandedId === evt.id;
              const col = decisionColor(evt.decision);
              return (
                <div
                  key={evt.id}
                  className="panel p-3.5 transition-all border"
                  style={{
                    borderColor: isExpanded ? col : "var(--border)",
                    background: isExpanded
                      ? "linear-gradient(180deg, rgba(16, 35, 41, 0.95), rgba(7, 16, 20, 0.98))"
                      : "#071014",
                  }}
                >
                  <button
                    type="button"
                    onClick={() => setExpandedId(isExpanded ? null : evt.id)}
                    className="w-full text-left flex flex-wrap items-center justify-between gap-2"
                  >
                    <div className="flex items-center gap-2.5 min-w-0">
                      <span
                        aria-hidden="true"
                        style={{
                          width: 8,
                          height: 8,
                          borderRadius: 99,
                          background: col,
                          boxShadow: `0 0 8px ${col}66`,
                          flexShrink: 0,
                        }}
                      />
                      <DecisionBadge decision={evt.decision} size="sm" />
                      <span className="font-mono font-bold text-xs text-slate-100 truncate">
                        {evt.actionType}
                      </span>
                      <span className="text-muted text-xs truncate hidden sm:inline">
                        → {evt.destination}
                      </span>
                    </div>

                    <div className="flex items-center gap-3 text-xs font-mono text-muted">
                      <span className="text-[10px]">Risk: {evt.riskScore}</span>
                      <span className="text-[10px]">
                        {new Date(evt.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
                      </span>
                      <ChevronIcon
                        className={`h-4 w-4 text-muted transition-transform ${isExpanded ? "rotate-90 text-accent" : ""}`}
                      />
                    </div>
                  </button>

                  {/* Expanded Accordion Details */}
                  {isExpanded && (
                    <div className="mt-3 pt-3 border-t text-xs space-y-2" style={{ borderColor: "var(--border-subtle)" }}>
                      <div>
                        <span className="text-muted block text-[10px] uppercase font-mono">Engine Explanation:</span>
                        <p className="text-slate-200 mt-0.5 leading-relaxed">{evt.explanation}</p>
                      </div>

                      <div className="grid gap-2 sm:grid-cols-3 pt-2 text-[11px] font-mono" style={{ color: "var(--muted)" }}>
                        <div>
                          Event ID: <span className="text-slate-200">{evt.id}</span>
                        </div>
                        <div>
                          Lifecycle State: <span className="text-cyan-300 font-bold">{evt.lifecycle ?? "evaluated"}</span>
                        </div>
                        <div>
                          Execution: <span className="text-slate-200 font-bold">SIMULATED</span>
                        </div>
                      </div>

                      {evt.findings && evt.findings.filter((f) => f.category === "injection").length > 0 && (
                        <div className="pt-2">
                          <span className="text-muted block text-[10px] uppercase font-mono mb-1">
                            Flagged Scanner Rules ({evt.findings.filter((f) => f.category === "injection").length}):
                          </span>
                          <div className="space-y-1">
                            {evt.findings
                              .filter((f) => f.category === "injection")
                              .map((f, i) => (
                              <div
                                key={i}
                                className="p-1.5 rounded font-mono text-[10px] border flex items-center justify-between"
                                style={{ background: "#04090c", borderColor: "var(--border)" }}
                              >
                                <span className="text-amber-400 font-semibold">{f.ruleId} · {f.severity}</span>
                                <span className="text-slate-300 truncate max-w-[280px]">{f.explanation}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </section>

      {/* Footer Informational Callout */}
      <div
        className="panel p-3 text-xs text-muted flex items-center justify-between"
        style={{ background: "#05090d" }}
      >
        <span className="text-[11px]">
          Session memory audit timeline · Resets on API restart · In-memory evaluation records only
        </span>
        <span className="badge text-[9px] text-emerald-300">DETERMINISTIC VERIFICATION</span>
      </div>
    </div>
  );
}
