import { useCallback, useEffect, useState, type FormEvent } from "react";
import { apiFetch, UnauthorizedError } from "../../api.js";
import { AlertTriangleIcon, CopyIcon, GlobeIcon, InfoIcon, LockIcon, RefreshIcon } from "../icons.js";

/**
 * Website Scans (M1). Every list and result shown here comes from the API; this
 * screen never shows sample or mock findings. A scan only appears as completed
 * when the server ran it.
 */

type Severity = "critical" | "high" | "medium" | "low" | "info";

interface Finding {
  findingId: string;
  severity: Severity;
  confidence: "low" | "medium" | "high";
  title: string;
  explanation: string;
  evidence: string;
  remediation: string;
  references: string[];
}

interface CheckResult {
  checkId: string;
  title: string;
  status: "pass" | "fail" | "error" | "not-applicable";
  summary: string;
  findings: Finding[];
}

interface Target {
  id: string;
  kind: "dns" | "lab";
  hostname: string;
  displayHostname: string;
  verification: {
    method: "dns-txt" | "lab-config";
    status: "pending" | "verified" | "failed" | "expired";
    verifiedAt: string | null;
    expiresAt: string | null;
    lastFailureMessage: string | null;
  };
  dnsRecord: { type: "TXT"; name: string; value: string } | null;
}

interface Scan {
  id: string;
  targetId: string;
  displayHostname: string;
  status: "queued" | "running" | "completed" | "failed" | "rejected";
  reason: string | null;
  message: string | null;
  requestedAt: string;
  finishedAt: string | null;
  requestsUsed: number;
  requestBudget: number;
  summary: Record<Severity, number>;
  checks?: CheckResult[];
}

interface Settings {
  outboundScanningEnabled: boolean;
  labModeEnabled: boolean;
  labOrigins: string[];
  verificationValidityDays: number;
  requestBudget: number;
}

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
const SEVERITY_COLOR: Record<Severity, string> = {
  critical: "var(--block)",
  high: "var(--block)",
  medium: "var(--confirm)",
  low: "var(--accent-blue)",
  info: "var(--muted)",
};
const STATUS_COLOR: Record<string, string> = {
  verified: "var(--allow)",
  completed: "var(--allow)",
  pass: "var(--allow)",
  pending: "var(--muted)",
  queued: "var(--muted)",
  running: "var(--accent)",
  "not-applicable": "var(--muted)",
  failed: "var(--block)",
  fail: "var(--block)",
  error: "var(--confirm)",
  rejected: "var(--confirm)",
  expired: "var(--confirm)",
};

function Badge({ label, color }: { label: string; color: string }) {
  return (
    <span className="badge font-mono text-[10px] uppercase" style={{ borderColor: color, color }}>
      {label}
    </span>
  );
}

function when(value: string | null): string {
  return value ? new Date(value).toLocaleString() : "—";
}

async function readJson<T>(res: Response): Promise<T> {
  return (await res.json()) as T;
}

export default function WebsiteScansView({ onUnauthorized }: { onUnauthorized: () => void }) {
  const [targets, setTargets] = useState<Target[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [selected, setSelected] = useState<Scan | null>(null);
  const [url, setUrl] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState<{ tone: "error" | "info"; text: string } | null>(null);

  const handle = useCallback(
    (error: unknown, fallback: string) => {
      if (error instanceof UnauthorizedError) onUnauthorized();
      else setNotice({ tone: "error", text: fallback });
    },
    [onUnauthorized],
  );

  const load = useCallback(async () => {
    try {
      const [targetsRes, scansRes] = await Promise.all([apiFetch("/api/targets"), apiFetch("/api/scans")]);
      const targetsBody = await readJson<{ targets: Target[]; settings: Settings }>(targetsRes);
      const scansBody = await readJson<{ scans: Scan[] }>(scansRes);
      setTargets(targetsBody.targets);
      setSettings(targetsBody.settings);
      setScans(scansBody.scans);
    } catch (error) {
      handle(error, "Could not load targets and scans from the API.");
    }
  }, [handle]);

  const loadScan = useCallback(
    async (id: string) => {
      try {
        const res = await apiFetch(`/api/scans/${id}`);
        if (res.ok) setSelected((await readJson<{ scan: Scan }>(res)).scan);
      } catch (error) {
        handle(error, "Could not load the scan.");
      }
    },
    [handle],
  );

  useEffect(() => {
    void load();
  }, [load]);

  // Poll while a scan is queued or running.
  const active = scans.some((s) => s.status === "queued" || s.status === "running");
  useEffect(() => {
    if (!active) return;
    const timer = setInterval(() => {
      void load();
      if (selected) void loadScan(selected.id);
    }, 2000);
    return () => clearInterval(timer);
  }, [active, load, loadScan, selected]);

  async function post(path: string, body: unknown, key: string): Promise<void> {
    setBusy(key);
    setNotice(null);
    try {
      const res = await apiFetch(path, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await readJson<{ error?: string; scan?: Scan }>(res);
      if (!res.ok) setNotice({ tone: "error", text: data.error ?? `Request failed (${res.status}).` });
      else if (data.scan) {
        setNotice({ tone: "info", text: `Scan ${data.scan.id} accepted (${data.scan.status}). Results appear when it finishes.` });
        void loadScan(data.scan.id);
      }
      await load();
    } catch (error) {
      handle(error, "The request failed. Check that the API is running.");
    } finally {
      setBusy(null);
    }
  }

  async function onRegister(event: FormEvent) {
    event.preventDefault();
    if (!url.trim()) return;
    await post("/api/targets", { url: url.trim() }, "register");
    setUrl("");
  }

  async function onDelete(target: Target) {
    setBusy(`delete-${target.id}`);
    try {
      await apiFetch(`/api/targets/${target.id}`, { method: "DELETE" });
      await load();
    } catch (error) {
      handle(error, "Could not delete the target.");
    } finally {
      setBusy(null);
    }
  }

  async function download(scan: Scan, format: "json" | "html") {
    try {
      const res = await apiFetch(`/api/scans/${scan.id}/report.${format}`);
      if (!res.ok) throw new Error(String(res.status));
      const href = URL.createObjectURL(await res.blob());
      const anchor = document.createElement("a");
      anchor.href = href;
      anchor.download = `agentshield-${scan.id}.${format}`;
      anchor.click();
      URL.revokeObjectURL(href);
    } catch (error) {
      handle(error, "Could not download the report.");
    }
  }

  const canScan = (target: Target) =>
    target.verification.status === "verified" &&
    (target.kind === "dns" ? settings?.outboundScanningEnabled === true : settings?.labModeEnabled === true);

  return (
    <div className="space-y-4">
      <div className="panel p-4 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <GlobeIcon className="h-6 w-6" />
          <div>
            <h2 className="text-base font-bold" style={{ color: "var(--text-bright)" }}>
              Website Scans
            </h2>
            <p className="text-xs" style={{ color: "var(--muted)" }}>
              Passive checks of sites you own: TLS, HTTPS redirect, security headers, CORS, cookie flags and security.txt.
              Three requests per scan, no crawling, no attack payloads.
            </p>
          </div>
        </div>
        <button type="button" className="btn-ghost text-xs" onClick={() => void load()}>
          <RefreshIcon className="h-3.5 w-3.5" /> Refresh
        </button>
      </div>

      {settings && !settings.outboundScanningEnabled && (
        <div role="status" className="panel p-3 text-xs flex gap-2 items-start" style={{ borderColor: "var(--confirm)", color: "var(--text)" }}>
          <LockIcon className="h-4 w-4 shrink-0" />
          <span>
            <strong>Outbound scanning is disabled.</strong> No request is sent to any website and ownership cannot be verified.
            To enable it, set <code>SCAN_NETWORK_ENABLED=true</code> in the API's environment and restart the API.
            {settings.labModeEnabled && settings.labOrigins.length > 0 && (
              <> Lab mode is on for: {settings.labOrigins.join(", ")}.</>
            )}
          </span>
        </div>
      )}

      {notice && (
        <div
          role={notice.tone === "error" ? "alert" : "status"}
          className="panel p-3 text-xs flex items-center justify-between gap-2"
          style={{ borderColor: notice.tone === "error" ? "var(--block)" : "var(--accent)" }}
        >
          <span>{notice.text}</span>
          <button type="button" className="text-xs hover:underline" onClick={() => setNotice(null)}>
            Dismiss
          </button>
        </div>
      )}

      <form onSubmit={(event) => void onRegister(event)} className="panel p-4 flex flex-wrap gap-2 items-end">
        <label className="flex-1 min-w-[220px] text-xs flex flex-col gap-1" style={{ color: "var(--muted)" }}>
          Site you own (exact host name, e.g. https://www.example.com)
          <input value={url} onChange={(event) => setUrl(event.target.value)} className="field text-sm" placeholder="https://www.example.com" />
        </label>
        <button type="submit" className="btn-primary text-xs" disabled={busy === "register" || !url.trim()}>
          Add target
        </button>
      </form>

      <section className="panel p-4 space-y-3" aria-labelledby="targets-title">
        <h3 id="targets-title" className="panel-title">
          Targets
        </h3>
        {targets.length === 0 && (
          <p className="text-xs" style={{ color: "var(--muted)" }}>
            No targets yet. Add a site you own, then prove ownership with a DNS TXT record.
          </p>
        )}
        {targets.map((target) => (
          <div key={target.id} className="border rounded-lg p-3 space-y-2" style={{ borderColor: "var(--border)" }}>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2">
                <span className="font-mono text-sm" style={{ color: "var(--text-bright)" }}>
                  {target.displayHostname}
                </span>
                <Badge label={target.verification.status} color={STATUS_COLOR[target.verification.status] ?? "var(--muted)"} />
                {target.kind === "lab" && <Badge label="lab" color="var(--accent-blue)" />}
              </div>
              <div className="flex gap-2">
                <button type="button" className="btn-ghost text-xs" disabled={busy !== null} onClick={() => void post(`/api/targets/${target.id}/verify`, {}, `verify-${target.id}`)}>
                  Verify ownership
                </button>
                <button
                  type="button"
                  className="btn-primary text-xs"
                  disabled={busy !== null || !canScan(target)}
                  title={canScan(target) ? "Start a passive scan" : "Requires verified ownership and scanning enabled"}
                  onClick={() => void post("/api/scans", { targetId: target.id }, `scan-${target.id}`)}
                >
                  Start scan
                </button>
                <button type="button" className="btn-ghost text-xs" disabled={busy !== null} onClick={() => void onDelete(target)}>
                  Delete
                </button>
              </div>
            </div>
            <p className="text-[11px]" style={{ color: "var(--muted)" }}>
              {target.verification.status === "verified"
                ? `Verified ${when(target.verification.verifiedAt)}; expires ${when(target.verification.expiresAt)}. The DNS record is checked again before every scan.`
                : target.verification.lastFailureMessage ?? "Not verified yet."}
            </p>
            {target.dnsRecord && (
              <div className="rounded-md p-2 text-[11px] space-y-1" style={{ background: "rgba(16, 35, 41, 0.9)" }}>
                <p className="flex items-center gap-1" style={{ color: "var(--muted)" }}>
                  <InfoIcon className="h-3.5 w-3.5" /> Publish this DNS TXT record at your DNS provider, then click Verify ownership:
                </p>
                {(["name", "value"] as const).map((field) => (
                  <div key={field} className="flex items-center gap-2 font-mono break-all">
                    <span style={{ color: "var(--muted)" }}>{field === "name" ? "Name " : "Value"}</span>
                    <span style={{ color: "var(--text-bright)" }}>{target.dnsRecord![field]}</span>
                    <button
                      type="button"
                      className="btn-ghost text-[10px] py-0.5 px-1.5"
                      aria-label={`Copy ${field}`}
                      onClick={() => void navigator.clipboard.writeText(target.dnsRecord![field])}
                    >
                      <CopyIcon className="h-3 w-3" />
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>
        ))}
      </section>

      <section className="panel p-4 space-y-3" aria-labelledby="scans-title">
        <h3 id="scans-title" className="panel-title">
          Scan history (this API session only)
        </h3>
        {scans.length === 0 && (
          <p className="text-xs" style={{ color: "var(--muted)" }}>
            No scans yet. History is kept in memory and is cleared when the API restarts.
          </p>
        )}
        {scans.map((scan) => (
          <button
            type="button"
            key={scan.id}
            onClick={() => void loadScan(scan.id)}
            className="w-full text-left border rounded-lg p-2.5 flex flex-wrap items-center justify-between gap-2"
            style={{ borderColor: selected?.id === scan.id ? "var(--accent)" : "var(--border)" }}
          >
            <span className="flex items-center gap-2 text-xs">
              <span className="font-mono" style={{ color: "var(--text-bright)" }}>
                {scan.id}
              </span>
              <span>{scan.displayHostname}</span>
              <Badge label={scan.status} color={STATUS_COLOR[scan.status] ?? "var(--muted)"} />
            </span>
            <span className="text-[11px] font-mono" style={{ color: "var(--muted)" }}>
              {scan.status === "completed"
                ? SEVERITIES.filter((s) => scan.summary[s] > 0).map((s) => `${s} ${scan.summary[s]}`).join(" · ") || "no findings"
                : scan.message ?? scan.status}
            </span>
          </button>
        ))}
      </section>

      {selected && (
        <section className="panel p-4 space-y-3" aria-labelledby="scan-detail-title">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h3 id="scan-detail-title" className="panel-title">
              {selected.id} · {selected.displayHostname} · {selected.status}
            </h3>
            <div className="flex gap-2">
              <button type="button" className="btn-ghost text-xs" onClick={() => void download(selected, "json")}>
                Download JSON
              </button>
              <button type="button" className="btn-ghost text-xs" onClick={() => void download(selected, "html")}>
                Download HTML
              </button>
            </div>
          </div>
          <p className="text-[11px]" style={{ color: "var(--muted)" }}>
            Requested {when(selected.requestedAt)} · finished {when(selected.finishedAt)} · {selected.requestsUsed} of {selected.requestBudget} requests used.
            {selected.message ? ` ${selected.message}` : ""}
          </p>
          {selected.status !== "completed" ? (
            <p className="text-xs flex items-center gap-1" style={{ color: "var(--confirm)" }}>
              <AlertTriangleIcon className="h-4 w-4" /> No checks ran for this scan.
            </p>
          ) : (
            (selected.checks ?? []).map((check) => (
              <div key={check.checkId} className="border rounded-lg p-3 space-y-2" style={{ borderColor: "var(--border)" }}>
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm font-semibold" style={{ color: "var(--text-bright)" }}>
                    {check.title}
                  </span>
                  <Badge label={check.status} color={STATUS_COLOR[check.status] ?? "var(--muted)"} />
                </div>
                <p className="text-[11px]" style={{ color: "var(--muted)" }}>
                  {check.summary}
                </p>
                {check.findings.map((finding) => (
                  <div key={finding.findingId} className="pl-3 border-l-2 space-y-1 text-xs" style={{ borderColor: SEVERITY_COLOR[finding.severity] }}>
                    <p className="flex flex-wrap items-center gap-2">
                      <Badge label={finding.severity} color={SEVERITY_COLOR[finding.severity]} />
                      <strong style={{ color: "var(--text-bright)" }}>{finding.title}</strong>
                      <span className="text-[10px]" style={{ color: "var(--muted)" }}>
                        confidence {finding.confidence}
                      </span>
                    </p>
                    <p>{finding.explanation}</p>
                    <p>
                      <span style={{ color: "var(--muted)" }}>Evidence: </span>
                      <code className="break-all">{finding.evidence}</code>
                    </p>
                    <p>
                      <span style={{ color: "var(--muted)" }}>Remediation: </span>
                      {finding.remediation}
                    </p>
                    {finding.references.length > 0 && (
                      <p className="text-[10px]" style={{ color: "var(--muted)" }}>
                        {finding.references.join(" · ")}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            ))
          )}
          <p className="text-[10px]" style={{ color: "var(--muted)" }}>
            Findings are evidence of weaker configuration, not proof of exploitability. A clean result is not a certification.
          </p>
        </section>
      )}
    </div>
  );
}
