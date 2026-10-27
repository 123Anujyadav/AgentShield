import {
  AlertTriangleIcon,
  CheckCircleIcon,
  InfoIcon,
  LockIcon,
  ShieldIcon,
  TerminalIcon,
  ToolIcon,
} from "../icons.js";

const PREVIEW_TOOLS = [
  {
    name: "read_document",
    source: "Local Interception SDK",
    type: "Built-in Core Tool",
    status: "TRUSTED",
    riskRating: "LOW",
    manifestHash: "sha256:8f43b2a8c190... (Verified)",
    description: "Reads local synthetic documents into scanner context without executing commands.",
    permissions: ["file.read (isolated sandbox)"],
  },
  {
    name: "create_summary",
    source: "Local Interception SDK",
    type: "Built-in Core Tool",
    status: "TRUSTED",
    riskRating: "LOW",
    manifestHash: "sha256:d19e0481bb23... (Verified)",
    description: "In-memory string transformation creating concise bullet-point digests.",
    permissions: ["memory.write (ephemeral)"],
  },
  {
    name: "create_report",
    source: "Local Interception SDK",
    type: "Built-in Core Tool",
    status: "TRUSTED",
    riskRating: "LOW",
    manifestHash: "sha256:5a76c8d20e49... (Verified)",
    description: "Compiles formatted Markdown security summaries in session memory.",
    permissions: ["memory.write (ephemeral)"],
  },
  {
    name: "send_payment",
    source: "External Financial Plugin",
    type: "MCP External Connector",
    status: "HARD DENIED",
    riskRating: "CRITICAL",
    manifestHash: "sha256:99cf3a1b02de... (Blocked)",
    description: "Initiates monetary transfer to third-party cryptocurrency or bank account.",
    permissions: ["payment.execute", "network.egress (external)"],
  },
  {
    name: "agentic_browser_proxy",
    source: "Browser Extension Bridge",
    type: "Network Interceptor",
    status: "MONITORED",
    riskRating: "HIGH",
    manifestHash: "sha256:1a84f509c27b... (Pending Audit)",
    description: "Fetches and renders external HTML pages for agent browsing tasks.",
    permissions: ["network.ingress", "dom.read"],
  },
];

export default function ToolTrustView() {
  return (
    <div className="space-y-4">
      {/* Prominent Preview Banner */}
      <div
        className="panel p-4 flex flex-wrap items-center justify-between gap-3 border"
        style={{
          borderColor: "rgba(167, 139, 250, 0.4)",
          background: "linear-gradient(90deg, rgba(167, 139, 250, 0.1) 0%, rgba(9, 17, 22, 0.95) 100%)",
        }}
      >
        <div className="flex items-center gap-3">
          <div
            className="flex h-10 w-10 items-center justify-center rounded-lg"
            style={{
              background: "rgba(167, 139, 250, 0.2)",
              border: "1px solid var(--advisory)",
              color: "var(--advisory)",
            }}
          >
            <ToolIcon className="h-5 w-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-base font-bold" style={{ color: "var(--text-bright)" }}>
                Tool Trust Preview · Connector Integrity
              </h2>
              <span
                className="badge text-[9px] font-mono font-bold"
                style={{
                  background: "rgba(167, 139, 250, 0.2)",
                  color: "var(--advisory)",
                  borderColor: "var(--advisory)",
                }}
              >
                PREVIEW — NOT IMPLEMENTED
              </span>
            </div>
            <p className="text-xs" style={{ color: "var(--muted)" }}>
              Design specification for agent tool inventory, signed manifests, and MCP connector drift defense
            </p>
          </div>
        </div>
        <span className="badge text-[10px] text-purple-300">Phase 1-2 Roadmap</span>
      </div>

      {/* Architecture Concept Callout */}
      <div className="grid gap-4 lg:grid-cols-3">
        <div className="panel p-3.5 space-y-1.5 border" style={{ borderColor: "var(--border)" }}>
          <div className="flex items-center gap-1.5 text-xs font-bold text-accent">
            <LockIcon className="h-4 w-4" /> Signed Manifests
          </div>
          <p className="text-[11px] text-muted">
            Every tool declaration (including schema, description, and parameter types) is hashed and signed at install time via TUF cryptographic keys.
          </p>
        </div>

        <div className="panel p-3.5 space-y-1.5 border" style={{ borderColor: "var(--border)" }}>
          <div className="flex items-center gap-1.5 text-xs font-bold text-amber-400">
            <AlertTriangleIcon className="h-4 w-4" /> Description Drift Alerts
          </div>
          <p className="text-[11px] text-muted">
            If a tool or MCP connector silently alters its description or docstrings after initial user approval, AgentShield immediately revokes authorization.
          </p>
        </div>

        <div className="panel p-3.5 space-y-1.5 border" style={{ borderColor: "var(--border)" }}>
          <div className="flex items-center gap-1.5 text-xs font-bold text-emerald-400">
            <ShieldIcon className="h-4 w-4" /> Least-Privilege Scoping
          </div>
          <p className="text-[11px] text-muted">
            Tools operate in capability sandboxes. An email summarizer tool cannot request file-system writing or arbitrary network egress.
          </p>
        </div>
      </div>

      {/* Tool Inventory Preview Table */}
      <section className="panel p-4" aria-labelledby="inventory-heading">
        <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
          <h3 id="inventory-heading" className="panel-title">
            <TerminalIcon className="h-4 w-4 text-accent" />
            Registered Tools & Connectors Inventory (Specification Preview)
          </h3>
          <span className="badge text-[10px] text-purple-300">
            PREVIEW ONLY · NO LIVE REGISTRY
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead>
              <tr className="border-b text-[10px] uppercase font-mono text-muted" style={{ borderColor: "var(--border)" }}>
                <th className="py-2 pr-3">Tool Identifier</th>
                <th className="py-2 pr-3">Category</th>
                <th className="py-2 pr-3">Trust Status</th>
                <th className="py-2 pr-3">Risk Level</th>
                <th className="py-2 pr-3">Cryptographic Manifest</th>
                <th className="py-2">Permission Boundary</th>
              </tr>
            </thead>
            <tbody className="divide-y" style={{ borderColor: "var(--border-subtle)" }}>
              {PREVIEW_TOOLS.map((tool) => (
                <tr key={tool.name} className="hover:bg-white/[0.02]">
                  <td className="py-3 pr-3 font-mono font-bold text-slate-100">{tool.name}</td>
                  <td className="py-3 pr-3 text-muted text-[11px]">{tool.type}</td>
                  <td className="py-3 pr-3">
                    <span
                      className="text-[9px] font-mono font-bold px-1.5 py-0.2 rounded"
                      style={{
                        background:
                          tool.status === "TRUSTED"
                            ? "rgba(52, 211, 153, 0.15)"
                            : tool.status === "HARD DENIED"
                            ? "rgba(248, 113, 113, 0.2)"
                            : "rgba(251, 191, 36, 0.15)",
                        color:
                          tool.status === "TRUSTED"
                            ? "var(--allow)"
                            : tool.status === "HARD DENIED"
                            ? "var(--block)"
                            : "var(--confirm)",
                      }}
                    >
                      {tool.status}
                    </span>
                  </td>
                  <td className="py-3 pr-3">
                    <span
                      className="font-mono text-[10px] font-bold"
                      style={{
                        color:
                          tool.riskRating === "CRITICAL"
                            ? "var(--block)"
                            : tool.riskRating === "HIGH"
                            ? "var(--confirm)"
                            : "var(--allow)",
                      }}
                    >
                      {tool.riskRating}
                    </span>
                  </td>
                  <td className="py-3 pr-3 font-mono text-[10px] text-muted">{tool.manifestHash}</td>
                  <td className="py-3">
                    <div className="flex flex-wrap gap-1">
                      {tool.permissions.map((perm) => (
                        <span key={perm} className="badge text-[9px] text-slate-300">
                          {perm}
                        </span>
                      ))}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Proposal Reference Box */}
      <div
        className="panel p-3.5 text-xs text-muted flex items-start gap-2.5"
        style={{ background: "#05090d" }}
      >
        <InfoIcon className="h-4 w-4 text-accent shrink-0 mt-0.5" />
        <p className="text-[11px] leading-relaxed">
          From the <strong className="text-slate-200">AgentShield Proposal</strong>: "Mobile operating systems sandbox apps, so AgentShield enters through the Agent SDK, MCP proxy, and Egress guard. In Phase 0-4, deterministic action gating and scanner rules are fully active; live signed manifest verification for third-party MCP servers is scheduled for Phase 1-2 development."
        </p>
      </div>
    </div>
  );
}
