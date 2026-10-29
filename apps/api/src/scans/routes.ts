import type { Express, Response } from "express";
import { renderHtmlReport, renderJsonReport } from "@agentshield/websec";
import type { RateLimitFactory } from "../security/rate-limit.js";
import { refusalMessage, type Outcome, type ScanService } from "./service.js";

/**
 * Website-scan routes (M1). They are registered after the /api authentication
 * middleware in app.ts, so every one of them requires the API token or a
 * session; none is public.
 */

const TARGET_ID = /^tgt-\d{1,9}$/;
const SCAN_ID = /^scan-\d{1,9}$/;

function send<T>(res: Response, outcome: Outcome<T>, key: string): void {
  if (outcome.ok) {
    res.status(outcome.status).json({ [key]: outcome.value });
    return;
  }
  res.status(outcome.status).json({
    error: refusalMessage(outcome.reason),
    reason: outcome.reason,
    ...(outcome.value !== undefined ? { [key]: outcome.value } : {}),
  });
}

export function registerScanRoutes(app: Express, deps: { service: ScanService; limit: RateLimitFactory }): void {
  const { service, limit } = deps;
  const limits = service.config.rateLimits;

  app.get("/api/targets", (_req, res) => {
    res.json({ targets: service.listTargets(), settings: service.settings() });
  });

  app.post("/api/targets", limit("scan-target-register", limits.registerTarget), (req, res) => {
    const url: unknown = (req.body as { url?: unknown } | undefined)?.url;
    send(res, service.registerTarget(url), "target");
  });

  app.delete("/api/targets/:id", (req, res) => {
    if (!TARGET_ID.test(req.params.id)) {
      res.status(400).json({ error: "Invalid target id.", reason: "invalid-id" });
      return;
    }
    send(res, service.deleteTarget(req.params.id), "result");
  });

  app.post("/api/targets/:id/verify", limit("scan-verify", limits.verify), async (req, res, next) => {
    try {
      if (!TARGET_ID.test(req.params.id)) {
        res.status(400).json({ error: "Invalid target id.", reason: "invalid-id" });
        return;
      }
      send(res, await service.verifyTarget(req.params.id), "target");
    } catch (error) {
      next(error);
    }
  });

  app.post("/api/scans", limit("scan-start", limits.startScan), (req, res) => {
    const targetId: unknown = (req.body as { targetId?: unknown } | undefined)?.targetId;
    if (typeof targetId !== "string" || !TARGET_ID.test(targetId)) {
      res.status(400).json({ error: "A targetId such as tgt-1 is required.", reason: "invalid-id" });
      return;
    }
    send(res, service.startScan(targetId), "scan");
  });

  app.get("/api/scans", (_req, res) => {
    res.json({ scans: service.listScans(), audit: service.auditLog(), settings: service.settings() });
  });

  app.get("/api/scans/:id", (req, res) => {
    const scan = SCAN_ID.test(req.params.id) ? service.getScan(req.params.id) : null;
    if (!scan) {
      res.status(404).json({ error: "Scan not found.", reason: "scan-not-found" });
      return;
    }
    res.json({ scan });
  });

  app.get("/api/scans/:id/report.json", (req, res) => {
    const report = SCAN_ID.test(req.params.id) ? service.report(req.params.id) : null;
    if (!report) {
      res.status(404).json({ error: "Scan not found.", reason: "scan-not-found" });
      return;
    }
    res.setHeader("Content-Disposition", `attachment; filename="agentshield-${report.scanId}.json"`);
    res.type("application/json").send(renderJsonReport(report));
  });

  app.get("/api/scans/:id/report.html", (req, res) => {
    const report = SCAN_ID.test(req.params.id) ? service.report(req.params.id) : null;
    if (!report) {
      res.status(404).json({ error: "Scan not found.", reason: "scan-not-found" });
      return;
    }
    // Downloaded, not rendered in the app; if opened, it can run no script and load nothing.
    res.setHeader("Content-Disposition", `attachment; filename="agentshield-${report.scanId}.html"`);
    res.setHeader("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.type("text/html").send(renderHtmlReport(report));
  });
}
