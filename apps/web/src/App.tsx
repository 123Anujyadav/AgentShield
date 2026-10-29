import { useCallback, useEffect, useMemo, useState } from "react";
import type {
  ActivityEvent,
  ApprovalResponse,
  EvaluateResponse,
  ModelStatus,
  PendingApproval,
  Scenario,
  View,
} from "./types.js";
import Sidebar, { NAVIGATION_ITEMS } from "./components/Sidebar.js";
import TopBar from "./components/TopBar.js";
import CommandCenterView from "./components/views/CommandCenterView.js";
import ScenarioLabView from "./components/views/ScenarioLabView.js";
import ThreatInvestigationView from "./components/views/ThreatInvestigationView.js";
import PolicyActionsView from "./components/views/PolicyActionsView.js";
import ApprovalQueueView from "./components/views/ApprovalQueueView.js";
import ModelDiagnosticsView from "./components/views/ModelDiagnosticsView.js";
import ToolTrustView from "./components/views/ToolTrustView.js";
import ActivityAuditView from "./components/views/ActivityAuditView.js";
import WebsiteScansView from "./components/views/WebsiteScansView.js";
import LoginView from "./components/LoginView.js";
import { apiFetch, hasSession, logout, UnauthorizedError } from "./api.js";
import type { ScanSwitches } from "./scan-state.js";

type AuthState = "checking" | "signed-out" | "signed-in";

function getInitialView(): View {
  if (typeof window !== "undefined" && window.location.hash) {
    const hash = window.location.hash.replace("#", "") as View;
    if (NAVIGATION_ITEMS.some((n) => n.id === hash)) {
      return hash;
    }
  }
  return "command";
}

export default function App() {
  const [view, setViewState] = useState<View>(getInitialView);
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [selectedId, setSelectedId] = useState("");
  const [result, setResult] = useState<EvaluateResponse | null>(null);
  const [events, setEvents] = useState<ActivityEvent[]>([]);
  const [approvals, setApprovals] = useState<PendingApproval[]>([]);
  const [modelStatus, setModelStatus] = useState<ModelStatus | null>(null);
  const [scanSwitches, setScanSwitches] = useState<ScanSwitches | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [actingId, setActingId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [apiOnline, setApiOnline] = useState<boolean | null>(null);
  const [auth, setAuth] = useState<AuthState>("checking");
  const [authNotice, setAuthNotice] = useState<string | null>(null);

  // A 401 from any call means the session ended: return to the sign-in screen.
  const onUnauthorized = useCallback(() => {
    setAuth("signed-out");
    setAuthNotice("Your session ended. Sign in again.");
  }, []);

  // Sync view with browser location hash
  const setView = useCallback((newView: View) => {
    setViewState(newView);
    if (typeof window !== "undefined") {
      window.location.hash = newView;
    }
  }, []);

  useEffect(() => {
    const handleHashChange = () => {
      const hash = window.location.hash.replace("#", "") as View;
      if (NAVIGATION_ITEMS.some((n) => n.id === hash)) {
        setViewState(hash);
      }
    };
    window.addEventListener("hashchange", handleHashChange);
    return () => window.removeEventListener("hashchange", handleHashChange);
  }, []);

  // Fetch events & approvals
  const refresh = useCallback(async () => {
    setIsRefreshing(true);
    try {
      const [eventsRes, approvalsRes] = await Promise.all([
        apiFetch("/api/events"),
        apiFetch("/api/approvals"),
      ]);
      if (!eventsRes.ok || !approvalsRes.ok) throw new Error("API refresh failed");
      const eventsData = (await eventsRes.json()) as { events: ActivityEvent[] };
      const approvalsData = (await approvalsRes.json()) as { approvals: PendingApproval[] };
      setEvents(eventsData.events);
      setApprovals(approvalsData.approvals);
      setApiOnline(true);
    } catch (error) {
      if (error instanceof UnauthorizedError) onUnauthorized();
      else setApiOnline(false);
    } finally {
      setIsRefreshing(false);
    }
  }, [onUnauthorized]);

  // Fetch model status independently
  const refreshModelStatus = useCallback(async () => {
    try {
      const statusRes = await apiFetch("/api/model/status");
      if (statusRes.ok) {
        setModelStatus((await statusRes.json()) as ModelStatus);
      }
    } catch (error) {
      // Model status fetch failure is non-destructive
      if (error instanceof UnauthorizedError) onUnauthorized();
    }
  }, [onUnauthorized]);

  // The server's website-scanning switches, for the top bar. Unknown (null) on any failure.
  const refreshScanSwitches = useCallback(async () => {
    try {
      const res = await apiFetch("/api/targets");
      const body = res.ok ? ((await res.json()) as { settings?: ScanSwitches }) : null;
      setScanSwitches(body?.settings ?? null);
    } catch (error) {
      setScanSwitches(null);
      if (error instanceof UnauthorizedError) onUnauthorized();
    }
  }, [onUnauthorized]);

  // Load initial app data
  const loadAll = useCallback(async () => {
    setLoading(true);
    try {
      const res = await apiFetch("/api/scenarios");
      if (!res.ok) throw new Error(`API ${res.status}`);
      const data = (await res.json()) as { scenarios: Scenario[] };
      setScenarios(data.scenarios);
      setSelectedId((current) => current || data.scenarios[0]?.id || "");
      await Promise.all([refreshModelStatus(), refresh(), refreshScanSwitches()]);
      setApiOnline(true);
      setError(null);
    } catch (error) {
      if (error instanceof UnauthorizedError) {
        onUnauthorized();
        return;
      }
      setApiOnline(false);
      setError("Could not reach the AgentShield API server. Please ensure it is running on http://localhost:4000 (npm run dev:api)");
    } finally {
      setLoading(false);
    }
  }, [refresh, refreshModelStatus, refreshScanSwitches, onUnauthorized]);

  // On startup, check for an existing session before loading any data.
  useEffect(() => {
    let cancelled = false;
    hasSession()
      .then((signedIn) => {
        if (!cancelled) setAuth(signedIn ? "signed-in" : "signed-out");
      })
      .catch(() => {
        if (cancelled) return;
        setApiOnline(false);
        setAuth("signed-out");
        setAuthNotice("Could not reach the AgentShield API on http://localhost:4000.");
      });
    return () => {
      cancelled = true;
    };
  }, []);

  useEffect(() => {
    if (auth === "signed-in") void loadAll();
  }, [auth, loadAll]);

  const pendingCount = useMemo(() => approvals.filter((a) => a.status === "PENDING").length, [approvals]);

  // Execute Action Evaluation against backend engine
  async function onEvaluate() {
    if (!selectedId) return;
    setBusy(true);
    setError(null);
    try {
      const res = await apiFetch("/api/evaluate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ scenarioId: selectedId }),
      });
      if (!res.ok) throw new Error(`API ${res.status}`);
      const evalData = (await res.json()) as EvaluateResponse;
      setResult(evalData);
      await refresh();
    } catch (error) {
      if (error instanceof UnauthorizedError) {
        onUnauthorized();
        return;
      }
      setError("Evaluation failed. Please verify that the API is running on http://localhost:4000.");
    } finally {
      setBusy(false);
    }
  }

  // Handle human-in-the-loop approval or rejection
  async function onApprovalAction(approval: PendingApproval, verb: "approve" | "reject") {
    setActingId(approval.id);
    setError(null);
    try {
      const res = await apiFetch(`/api/approvals/${approval.id}/${verb}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
      const data = (await res.json()) as ApprovalResponse;
      if (!res.ok) {
        setError(data.error ?? `Approval action failed with status ${res.status}. Session state refreshed.`);
      }
      await refresh();
    } catch (error) {
      if (error instanceof UnauthorizedError) {
        onUnauthorized();
        return;
      }
      setError("Approval request failed. Please check backend connection.");
    } finally {
      setActingId(null);
    }
  }

  async function onSignOut() {
    await logout();
    setResult(null);
    setEvents([]);
    setApprovals([]);
    setAuthNotice(null);
    setAuth("signed-out");
  }

  if (auth !== "signed-in") {
    return auth === "checking" ? (
      <div className="flex min-h-screen items-center justify-center" style={{ backgroundColor: "var(--bg)" }} aria-label="Checking session">
        <div className="skeleton w-64" />
      </div>
    ) : (
      <LoginView
        notice={authNotice}
        onSignedIn={() => {
          setAuthNotice(null);
          setAuth("signed-in");
        }}
      />
    );
  }

  return (
    <div className="flex min-h-screen" style={{ backgroundColor: "var(--bg)" }}>
      {/* Primary Sidebar (All 8 Screens) */}
      <Sidebar
        currentView={view}
        onSelectView={setView}
        pendingCount={pendingCount}
        totalEvents={events.length}
        apiOnline={apiOnline}
      />

      {/* Main Content Area */}
      <div className="min-w-0 flex-1 flex flex-col pb-24 lg:pb-6">
        <TopBar
          currentView={view}
          onSelectView={setView}
          apiOnline={apiOnline}
          modelStatus={modelStatus}
          onRefresh={() => void refresh()}
          isRefreshing={isRefreshing}
          onSignOut={() => void onSignOut()}
          scanSwitches={scanSwitches}
        />

        <main className="mx-auto w-full max-w-[1540px] p-3 sm:p-5 flex-1">
          {/* Global Alert Notification */}
          {error && (
            <div
              role="alert"
              className="mb-4 rounded-lg p-3 text-xs flex items-center justify-between border"
              style={{
                background: "rgba(248, 113, 113, 0.12)",
                color: "#fca5a5",
                borderColor: "var(--block)",
              }}
            >
              <span>{error}</span>
              <button
                type="button"
                onClick={() => setError(null)}
                className="text-xs hover:underline ml-2"
              >
                Dismiss
              </button>
            </div>
          )}

          {/* Initial Loading Skeletons */}
          {loading ? (
            <div className="grid gap-3 lg:grid-cols-3" aria-label="Loading view">
              <div className="skeleton" />
              <div className="skeleton" />
              <div className="skeleton" />
            </div>
          ) : view === "command" ? (
            /* Screen 1: Command Center */
            <CommandCenterView
              scenarios={scenarios}
              selectedScenarioId={selectedId}
              onSelectScenarioId={(id) => {
                setSelectedId(id);
                setResult(null);
              }}
              result={result}
              events={events}
              approvals={approvals}
              onEvaluate={onEvaluate}
              isBusy={busy}
              onNavigate={setView}
            />
          ) : view === "scenarios" ? (
            /* Screen 2: Scenario Lab */
            <ScenarioLabView
              scenarios={scenarios}
              selectedScenarioId={selectedId}
              onSelectScenarioId={(id) => {
                setSelectedId(id);
                setResult(null);
              }}
              result={result}
              onEvaluate={onEvaluate}
              isBusy={busy}
              onNavigate={setView}
            />
          ) : view === "investigation" ? (
            /* Screen 3: Threat Investigation */
            <ThreatInvestigationView
              result={result}
              onNavigate={setView}
            />
          ) : view === "policy" ? (
            /* Screen 4: Policy & Actions */
            <PolicyActionsView
              scenarios={scenarios}
              selectedScenarioId={selectedId}
              onNavigate={setView}
            />
          ) : view === "approvals" ? (
            /* Screen 5: Approval Queue */
            <ApprovalQueueView
              approvals={approvals}
              actingId={actingId}
              onApprovalAction={onApprovalAction}
              onNavigate={setView}
            />
          ) : view === "diagnostics" ? (
            /* Screen 6: Model Diagnostics */
            <ModelDiagnosticsView
              modelStatus={modelStatus}
              result={result}
              onRefreshStatus={refreshModelStatus}
            />
          ) : view === "tool-trust" ? (
            /* Screen 7: Tool Trust Preview */
            <ToolTrustView />
          ) : view === "scans" ? (
            /* Website Scans (M1) */
            <WebsiteScansView onUnauthorized={onUnauthorized} />
          ) : (
            /* Screen 8: Activity & Audit */
            <ActivityAuditView
              events={events}
              onNavigate={setView}
            />
          )}
        </main>
      </div>

      {/* Mobile Bottom Navigation Rail */}
      <nav
        className="fixed inset-x-0 bottom-0 z-40 flex justify-around py-2 px-1 lg:hidden border-t"
        style={{
          background: "rgba(6, 12, 16, 0.98)",
          borderColor: "var(--border)",
          backdropFilter: "blur(12px)",
        }}
        aria-label="Mobile Navigation"
      >
        {NAVIGATION_ITEMS.map(({ id, label, Icon }) => {
          const isActive = view === id;
          return (
            <button
              key={id}
              type="button"
              aria-label={label}
              title={label}
              onClick={() => setView(id)}
              className="p-2 rounded-lg transition-colors flex flex-col items-center gap-1 relative"
              style={{
                color: isActive ? "var(--accent)" : "var(--muted)",
                background: isActive ? "rgba(53, 230, 208, 0.15)" : "transparent",
              }}
            >
              <Icon className="h-4 w-4" />
              {id === "approvals" && pendingCount > 0 && (
                <span
                  className="absolute top-1 right-1 w-2 h-2 rounded-full"
                  style={{ background: "var(--confirm)" }}
                />
              )}
            </button>
          );
        })}
      </nav>
    </div>
  );
}
