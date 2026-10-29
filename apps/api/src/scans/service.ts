import {
  GuardedFetcher,
  HostGate,
  RequestBudget,
  ScanStopped,
  nodeTransport,
  normalizeTarget,
  runPassiveScan,
  summarizeFindings,
  systemResolver,
  systemTxtResolver,
  type CheckResult,
  type Resolver,
  type ScanReport,
  type ScanStatus,
  type ScanTarget,
  type Transport,
  type TxtResolver,
} from "@agentshield/websec";
import type { ScanConfig } from "./config.js";
import { checkDnsProof, createChallenge, verificationRecordName, verificationRecordValue } from "./verification.js";

/**
 * Website-scan service (M1): targets, ownership verification, a small job
 * queue, and in-memory, size-capped storage. Everything is lost when the API
 * restarts. No target is ever contacted unless:
 *   - the relevant switch is on (SCAN_NETWORK_ENABLED for real targets,
 *     SCAN_LAB_MODE for configured lab origins),
 *   - ownership is verified and not expired, and for real targets the DNS TXT
 *     proof is checked again when the scan starts,
 *   - and every resolved address passes the SSRF guard (inside the fetcher).
 */

export type VerificationStatus = "pending" | "verified" | "failed" | "expired";

interface TargetRecord {
  id: string;
  target: ScanTarget;
  createdAt: number;
  /** DNS targets only. Never included in reports, audit entries or logs. */
  challenge: string | null;
  verifiedAt: number | null;
  expiresAt: number | null;
  lastCheckedAt: number | null;
  lastFailure: string | null;
}

interface ScanRecord {
  id: string;
  targetId: string;
  target: ScanTarget;
  status: ScanStatus;
  reason: string | null;
  requestedAt: number;
  startedAt: number | null;
  finishedAt: number | null;
  requestsUsed: number;
  requestBudget: number;
  checks: CheckResult[];
  controller: AbortController | null;
  /** Why an in-flight scan was stopped from outside (deletion, timeout). */
  stopReason: string | null;
}

export type AuditEvent =
  | "target-registered"
  | "target-deleted"
  | "verification-succeeded"
  | "verification-failed"
  | "verification-refused"
  | "scan-queued"
  | "scan-rejected"
  | "scan-started"
  | "scan-completed"
  | "scan-failed";

export interface AuditEntry {
  id: number;
  at: string;
  event: AuditEvent;
  targetId: string;
  scanId: string | null;
  hostname: string;
  reason: string | null;
}

/**
 * Messages for the target-validation reasons returned by normalizeTarget. They
 * describe why an address was refused when it was added; no scan is involved.
 */
export const TARGET_REJECTION_MESSAGES: Record<string, string> = {
  "invalid-input": "Enter a host name or an http(s) address, such as https://www.example.com.",
  "invalid-characters": "The address contains spaces, control characters or backslashes.",
  "unsupported-scheme": "Only http:// and https:// addresses can be added.",
  "invalid-url": "The address could not be read as a URL.",
  "credentials-not-allowed": "Addresses with a user name or password are not accepted.",
  "path-not-allowed": "Enter only the site's address, without a path, query or fragment.",
  "port-not-allowed":
    "Only the default ports are accepted (443 for https, 80 for http). A local lab origin is accepted only when lab mode is on and it is listed in SCAN_LAB_ORIGINS.",
  "ip-literal-not-allowed": "IP addresses cannot be added: ownership is proved through DNS, so enter a host name.",
  "trailing-dot": "Remove the trailing dot from the host name.",
  "invalid-hostname": "That is not a valid public host name.",
  "special-use-hostname": "Local, internal and reserved names (such as localhost, .local or .internal) cannot be added.",
};

/** Fixed messages for every reason code the API can return. */
export const REASON_MESSAGES: Record<string, string> = {
  ...TARGET_REJECTION_MESSAGES,
  "outbound-scanning-disabled": "Outbound scanning is disabled (SCAN_NETWORK_ENABLED is not true). Nothing was sent.",
  "lab-mode-disabled": "Lab mode is off, or this lab origin is not configured. Nothing was sent.",
  "target-not-verified": "Ownership of this target is not verified. Nothing was sent to it.",
  "verification-expired": "Ownership verification has expired. Verify again before scanning. Nothing was sent to the target.",
  "verification-failed": "The last ownership verification failed. Verify again before scanning. Nothing was sent to the target.",
  "scan-already-active": "A scan of this target is already queued or running.",
  "too-many-active-scans": "The maximum number of concurrent scans is already running. Try again when one finishes.",
  "ownership-proof-failed": "The DNS TXT ownership record could not be confirmed when the scan started. Nothing was sent to the target.",
  "target-deleted": "The target was deleted.",
  "target-not-found": "Target not found.",
  "target-already-registered": "This target is already registered.",
  "target-limit-reached": "The maximum number of targets is registered. Delete one first.",
  "record-missing": "No TXT record was found at the verification name.",
  "record-mismatch": "A TXT record exists, but none matches the expected value.",
  "resolver-error": "The DNS lookup failed.",
  timeout: "The DNS lookup timed out.",
  "blocked-address": "The host name resolves to a blocked (private, loopback, link-local, metadata or reserved) address. Nothing was sent.",
  "malformed-resolution": "The host name's DNS answer was empty or malformed. Nothing was sent.",
  "dns-failure": "The host name could not be resolved. Nothing was sent.",
  "out-of-scope": "The request was outside the target's scope.",
  cancelled: "The scan was cancelled.",
  "scan-timeout": "The scan exceeded its overall time limit.",
  "internal-error": "The scan failed because of an internal error.",
};

/** The known message for a reason code, or null when there is none. */
export function messageFor(reason: string | null): string | null {
  if (reason === null) return null;
  return REASON_MESSAGES[reason] ?? null;
}

/** Message for a refused request (any route). Never describes the refusal as a scan. */
export function refusalMessage(reason: string): string {
  return messageFor(reason) ?? "Request refused.";
}

/** Message for a scan that ended without completing. */
export function scanMessage(reason: string | null): string | null {
  return reason === null ? null : (messageFor(reason) ?? "The scan did not complete.");
}

/**
 * Why a target may not be scanned, from its verification state, or null when it
 * may. Shared by the start-of-request check and the check when a queued scan
 * starts, so both report the same distinct reasons.
 */
export function verificationRefusal(status: VerificationStatus): string | null {
  switch (status) {
    case "verified":
      return null;
    case "expired":
      return "verification-expired";
    case "failed":
      return "verification-failed";
    case "pending":
      return "target-not-verified";
  }
}

export type Outcome<T> = { ok: true; status: number; value: T } | { ok: false; status: number; reason: string; value?: unknown };

export interface ScanServiceDeps {
  config: ScanConfig;
  resolver?: Resolver;
  txtResolver?: TxtResolver;
  transport?: Transport;
  now?: () => number;
}

const iso = (ms: number | null) => (ms === null ? null : new Date(ms).toISOString());

export class ScanService {
  readonly config: ScanConfig;
  private readonly txtResolver: TxtResolver;
  private readonly fetcher: GuardedFetcher;
  private readonly now: () => number;
  private readonly targets = new Map<string, TargetRecord>();
  private readonly scans: ScanRecord[] = [];
  private readonly audit: AuditEntry[] = [];
  private readonly jobs = new Set<Promise<void>>();
  private nextTargetId = 1;
  private nextScanId = 1;
  private nextAuditId = 1;

  constructor(deps: ScanServiceDeps) {
    this.config = deps.config;
    this.txtResolver = deps.txtResolver ?? systemTxtResolver;
    this.now = deps.now ?? Date.now;
    this.fetcher = new GuardedFetcher({
      resolver: deps.resolver ?? systemResolver,
      transport: deps.transport ?? nodeTransport,
      hostGate: new HostGate(),
    });
  }

  settings() {
    return {
      outboundScanningEnabled: this.config.networkEnabled,
      labModeEnabled: this.config.lab.enabled,
      labOrigins: [...this.config.lab.origins.keys()],
      verificationValidityDays: Math.round(this.config.verificationTtlMs / 86_400_000),
      requestBudget: this.config.requestBudget,
      maxConcurrentScans: this.config.maxConcurrentScans,
    };
  }

  // ---- targets ----

  private verificationStatus(record: TargetRecord): VerificationStatus {
    if (record.verifiedAt !== null && record.expiresAt !== null) return this.now() < record.expiresAt ? "verified" : "expired";
    return record.lastFailure ? "failed" : "pending";
  }

  publicTarget(record: TargetRecord) {
    const status = this.verificationStatus(record);
    const dns = record.target.kind === "dns";
    return {
      id: record.id,
      kind: record.target.kind,
      hostname: record.target.kind === "dns" ? record.target.hostname : record.target.origin,
      displayHostname: record.target.displayHostname,
      createdAt: iso(record.createdAt),
      verification: {
        method: dns ? "dns-txt" : "lab-config",
        status,
        verifiedAt: status === "verified" ? iso(record.verifiedAt) : null,
        expiresAt: status === "verified" ? iso(record.expiresAt) : null,
        lastCheckedAt: iso(record.lastCheckedAt),
        lastFailure: record.lastFailure,
        lastFailureMessage: record.lastFailure === null ? null : refusalMessage(record.lastFailure),
      },
      // Shown only while the owner still needs it to set up or restore the record.
      dnsRecord:
        dns && record.challenge && status !== "verified"
          ? { type: "TXT", name: verificationRecordName(record.target.hostname), value: verificationRecordValue(record.challenge) }
          : null,
    };
  }

  listTargets() {
    return [...this.targets.values()].map((record) => this.publicTarget(record));
  }

  registerTarget(input: unknown): Outcome<ReturnType<ScanService["publicTarget"]>> {
    let target: ScanTarget | null = null;
    if (this.config.lab.enabled && typeof input === "string") {
      target = this.config.lab.origins.get(input.trim().replace(/\/$/, "")) ?? null;
    }
    if (!target) {
      const verdict = normalizeTarget(input);
      if (!verdict.ok) return { ok: false, status: 400, reason: verdict.reason };
      target = verdict.target;
    }
    const key = target.kind === "dns" ? target.hostname : target.origin;
    for (const existing of this.targets.values()) {
      const existingKey = existing.target.kind === "dns" ? existing.target.hostname : existing.target.origin;
      if (existingKey === key) return { ok: false, status: 409, reason: "target-already-registered", value: { targetId: existing.id } };
    }
    if (this.targets.size >= this.config.maxTargets) return { ok: false, status: 409, reason: "target-limit-reached" };
    const record: TargetRecord = {
      id: `tgt-${this.nextTargetId++}`,
      target,
      createdAt: this.now(),
      challenge: target.kind === "dns" ? createChallenge() : null,
      verifiedAt: null,
      expiresAt: null,
      lastCheckedAt: null,
      lastFailure: null,
    };
    this.targets.set(record.id, record);
    this.record("target-registered", record, null, null);
    return { ok: true, status: 201, value: this.publicTarget(record) };
  }

  deleteTarget(id: string): Outcome<{ deleted: true }> {
    const record = this.targets.get(id);
    if (!record) return { ok: false, status: 404, reason: "target-not-found" };
    this.targets.delete(id);
    for (const scan of this.scans) {
      if (scan.targetId === id && (scan.status === "queued" || scan.status === "running")) {
        scan.stopReason = "target-deleted";
        scan.controller?.abort();
      }
    }
    this.record("target-deleted", record, null, null);
    return { ok: true, status: 200, value: { deleted: true } };
  }

  async verifyTarget(id: string): Promise<Outcome<ReturnType<ScanService["publicTarget"]>>> {
    const record = this.targets.get(id);
    if (!record) return { ok: false, status: 404, reason: "target-not-found" };
    const refusal = this.switchRefusal(record.target);
    if (refusal) {
      this.record("verification-refused", record, null, refusal);
      return { ok: false, status: 409, reason: refusal, value: this.publicTarget(record) };
    }
    record.lastCheckedAt = this.now();
    if (record.target.kind === "lab") {
      // Lab targets are proved by the server's own configuration, never by DNS.
      this.markVerified(record);
      this.record("verification-succeeded", record, null, "lab-config");
      return { ok: true, status: 200, value: this.publicTarget(record) };
    }
    const proof = await checkDnsProof(this.txtResolver, record.target.hostname, record.challenge!);
    if (!this.targets.has(id)) return { ok: false, status: 404, reason: "target-not-found" };
    if (!proof.ok) {
      this.markFailed(record, proof.reason);
      this.record("verification-failed", record, null, proof.reason);
      return { ok: false, status: 409, reason: proof.reason, value: this.publicTarget(record) };
    }
    this.markVerified(record);
    this.record("verification-succeeded", record, null, "dns-txt");
    return { ok: true, status: 200, value: this.publicTarget(record) };
  }

  private markVerified(record: TargetRecord): void {
    record.verifiedAt = this.now();
    record.expiresAt = record.verifiedAt + this.config.verificationTtlMs;
    record.lastFailure = null;
  }

  private markFailed(record: TargetRecord, reason: string): void {
    record.verifiedAt = null;
    record.expiresAt = null;
    record.lastFailure = reason;
  }

  /** The switch that must be on for this kind of target, or null when it is. Evaluated server-side only. */
  private switchRefusal(target: ScanTarget): string | null {
    if (target.kind === "dns") return this.config.networkEnabled ? null : "outbound-scanning-disabled";
    return this.config.lab.enabled && this.config.lab.origins.has(target.origin) ? null : "lab-mode-disabled";
  }

  // ---- scans ----

  private isActive(scan: ScanRecord): boolean {
    return scan.status === "queued" || scan.status === "running";
  }

  startScan(targetId: string): Outcome<ReturnType<ScanService["publicScan"]>> {
    const target = this.targets.get(targetId);
    if (!target) return { ok: false, status: 404, reason: "target-not-found" };
    // Judged before the new record exists, so it never counts itself as active.
    const active = this.scans.filter((s) => this.isActive(s));
    const verification = this.verificationStatus(target);
    const [status, reason] =
      ((): [number, string] | [null, null] => {
        const refusal = this.switchRefusal(target.target);
        if (refusal) return [409, refusal];
        const notVerified = verificationRefusal(verification);
        if (notVerified) return [409, notVerified];
        if (active.some((s) => s.targetId === targetId)) return [409, "scan-already-active"];
        if (active.length >= this.config.maxConcurrentScans) return [429, "too-many-active-scans"];
        return [null, null];
      })();
    const scan = this.newScan(target);
    if (status !== null) {
      // Recorded as rejected so the history shows the attempt; nothing was sent.
      this.finish(scan, "rejected", reason);
      return { ok: false, status, reason, value: this.publicScan(scan) };
    }

    this.record("scan-queued", target, scan.id, null);
    const job = Promise.resolve()
      .then(() => this.run(scan))
      .finally(() => this.jobs.delete(job));
    this.jobs.add(job);
    return { ok: true, status: 202, value: this.publicScan(scan) };
  }

  private newScan(target: TargetRecord): ScanRecord {
    const scan: ScanRecord = {
      id: `scan-${this.nextScanId++}`,
      targetId: target.id,
      target: target.target,
      status: "queued",
      reason: null,
      requestedAt: this.now(),
      startedAt: null,
      finishedAt: null,
      requestsUsed: 0,
      requestBudget: this.config.requestBudget,
      checks: [],
      controller: null,
      stopReason: null,
    };
    this.scans.push(scan);
    // Bounded retention: drop the oldest finished scans; active scans are never dropped.
    while (this.scans.length > this.config.maxScans) {
      const index = this.scans.findIndex((s) => !this.isActive(s) && s !== scan);
      if (index === -1) break;
      this.scans.splice(index, 1);
    }
    return scan;
  }

  private finish(scan: ScanRecord, status: "completed" | "failed" | "rejected", reason: string | null): void {
    scan.status = status;
    scan.reason = reason;
    scan.finishedAt = this.now();
    const event: AuditEvent = status === "completed" ? "scan-completed" : status === "failed" ? "scan-failed" : "scan-rejected";
    this.recordFor(event, scan.targetId, scan.target, scan.id, reason);
  }

  /** Runs one accepted scan. Never throws; every outcome ends in a final state. */
  private async run(scan: ScanRecord): Promise<void> {
    const controller = new AbortController();
    scan.controller = controller;
    const timer = setTimeout(() => {
      scan.stopReason = "scan-timeout";
      controller.abort();
    }, this.config.scanTimeoutMs);
    const budget = new RequestBudget(this.config.requestBudget);
    try {
      const target = this.targets.get(scan.targetId);
      if (!target || scan.stopReason) return this.finish(scan, "rejected", scan.stopReason ?? "target-deleted");
      scan.status = "running";
      scan.startedAt = this.now();
      this.record("scan-started", target, scan.id, null);

      // Re-check everything at start: the switches, expiry, and the DNS proof itself.
      const refusal = this.switchRefusal(target.target);
      if (refusal) return this.finish(scan, "rejected", refusal);
      // The state may have changed while the scan was queued: report which state it is now in.
      const notVerified = verificationRefusal(this.verificationStatus(target));
      if (notVerified) return this.finish(scan, "rejected", notVerified);
      if (target.target.kind === "dns") {
        target.lastCheckedAt = this.now();
        const proof = await checkDnsProof(this.txtResolver, target.target.hostname, target.challenge!);
        if (scan.stopReason) return this.finish(scan, "rejected", scan.stopReason);
        if (!proof.ok) {
          this.markFailed(target, proof.reason);
          this.record("verification-failed", target, scan.id, proof.reason);
          return this.finish(scan, "rejected", "ownership-proof-failed");
        }
      }

      const result = await runPassiveScan({ target: target.target, fetcher: this.fetcher, budget, signal: controller.signal, now: () => new Date(this.now()) });
      scan.checks = result.checks;
      scan.requestsUsed = result.requestsUsed;
      this.finish(scan, "completed", null);
    } catch (error) {
      scan.requestsUsed = budget.spent;
      const reason = scan.stopReason ?? (error instanceof ScanStopped ? error.reason : "internal-error");
      // Refused before any request reached the target: rejected, not failed.
      this.finish(scan, budget.spent === 0 && error instanceof ScanStopped && !scan.stopReason ? "rejected" : "failed", reason);
    } finally {
      clearTimeout(timer);
      scan.controller = null;
    }
  }

  publicScan(scan: ScanRecord) {
    return {
      id: scan.id,
      targetId: scan.targetId,
      kind: scan.target.kind,
      hostname: scan.target.kind === "dns" ? scan.target.hostname : scan.target.origin,
      displayHostname: scan.target.displayHostname,
      status: scan.status,
      reason: scan.reason,
      message: scanMessage(scan.reason),
      requestedAt: iso(scan.requestedAt),
      startedAt: iso(scan.startedAt),
      finishedAt: iso(scan.finishedAt),
      requestsUsed: scan.requestsUsed,
      requestBudget: scan.requestBudget,
      summary: summarizeFindings(scan.checks),
    };
  }

  listScans() {
    return [...this.scans].reverse().map((scan) => this.publicScan(scan));
  }

  getScan(id: string) {
    const scan = this.scans.find((s) => s.id === id);
    return scan ? { ...this.publicScan(scan), checks: scan.checks } : null;
  }

  report(id: string): ScanReport | null {
    const scan = this.scans.find((s) => s.id === id);
    if (!scan) return null;
    return {
      scanId: scan.id,
      target: {
        hostname: scan.target.kind === "dns" ? scan.target.hostname : scan.target.origin,
        displayHostname: scan.target.displayHostname,
        kind: scan.target.kind,
      },
      status: scan.status,
      reason: scan.reason,
      requestedAt: iso(scan.requestedAt)!,
      startedAt: iso(scan.startedAt),
      finishedAt: iso(scan.finishedAt),
      requestsUsed: scan.requestsUsed,
      requestBudget: scan.requestBudget,
      checks: scan.checks,
    };
  }

  // ---- audit ----

  auditLog(limit = 100): AuditEntry[] {
    return this.audit.slice(-limit).reverse();
  }

  private record(event: AuditEvent, target: TargetRecord, scanId: string | null, reason: string | null): void {
    this.recordFor(event, target.id, target.target, scanId, reason);
  }

  private recordFor(event: AuditEvent, targetId: string, target: ScanTarget, scanId: string | null, reason: string | null): void {
    this.audit.push({
      id: this.nextAuditId++,
      at: new Date(this.now()).toISOString(),
      event,
      targetId,
      scanId,
      hostname: target.kind === "dns" ? target.hostname : target.origin,
      reason,
    });
    if (this.audit.length > this.config.maxAuditEntries) this.audit.splice(0, this.audit.length - this.config.maxAuditEntries);
  }

  /** Resolves when no scan job is running (tests and orderly shutdown). */
  async whenIdle(): Promise<void> {
    while (this.jobs.size > 0) await Promise.allSettled([...this.jobs]);
  }
}
