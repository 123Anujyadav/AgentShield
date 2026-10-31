import { describe, expect, it } from "vitest";
import approvalQueue from "./components/views/ApprovalQueueView.tsx?raw";
import modelDiagnostics from "./components/views/ModelDiagnosticsView.tsx?raw";
import policy from "./components/views/PolicyActionsView.tsx?raw";
import toolTrust from "./components/views/ToolTrustView.tsx?raw";

/** M3-B (G10): dashboard text must match what the engine and API actually do. No browser: the views' source. */

describe("M3-B (G10): dashboard text matches the engine", () => {
  it("Policy: ALLOW scores 10 to 30 and may carry lower-severity scanner findings; unregistered types are not executed, not blocked", () => {
    expect(policy).not.toContain("RISK &lt; 30");
    expect(policy).toContain("RISK 10&ndash;30");
    expect(policy).not.toContain("Zero injection scanner or hard-deny flags.");
    expect(policy).toContain("lower-severity findings raise the score to 30");
    expect(policy).toContain("an action type with no handler is allowed but not executed");
    expect(policy).not.toContain("AUTOMATIC HARD BLOCK");
    expect(policy).toContain("NOT EXECUTED (DECISION UNCHANGED)");
  });

  it("Tool Trust: stays a labelled preview and claims no SDK or verified manifests", () => {
    expect(toolTrust).toContain("PREVIEW — NOT IMPLEMENTED");
    expect(toolTrust).not.toContain('source: "Local Interception SDK"');
    expect(toolTrust).not.toMatch(/\((?:Verified|Blocked|Pending Audit)\)/);
    expect((toolTrust.match(/"example only \\u2014 not verified"/g) ?? []).length).toBe(5);
  });

  it("Model diagnostics: shows the server's base URL and live state, and accurate default limits", () => {
    expect(modelDiagnostics).not.toContain("https://api.meta.ai/v1</span>");
    expect(modelDiagnostics).toContain('{modelStatus?.baseUrl ?? "unknown"}');
    expect(modelDiagnostics).not.toContain("4,000 chars max input / output");
    expect(modelDiagnostics).toContain("8,000 chars input · 20,000 chars response (server defaults)");
    expect(modelDiagnostics).not.toContain("2 attempts (exponential backoff)");
    expect(modelDiagnostics).toContain("Up to 2 retries by default");
    expect(modelDiagnostics).not.toContain("MODEL_LIVE_ENABLED=false (Enforced)");
    expect(modelDiagnostics).toContain('modelStatus?.isMock === false ? "Live provider (advisory only)" : "Offline synthetic provider"');
  });

  it("Approval queue: an approved action with no handler is shown amber, not as a block", () => {
    expect(approvalQueue).toContain('item.status === "APPROVED_NOT_EXECUTED" ? "var(--confirm)"');
  });
});
