import { DEFAULT_TIMEOUT_MS, RequestBudget, type GuardedFetcher } from "./fetcher.js";
import { errored, type CheckGroup, type CheckResult } from "./findings.js";
import type { ScanTarget } from "./target.js";

/**
 * Deadline-aware probe scheduling (M2-A foundation). Optional probes run one at a
 * time, only after the passive checks have produced their results. Before each
 * probe the scheduler confirms that the scan is still running and that enough time
 * and request budget remain for the probe's worst case. Otherwise it stops
 * scheduling and reports that probe and every later one as not checked.
 * Results already produced are always kept.
 */

/** Worst case for one guarded request without redirects: DNS resolution and the request each have their own timeout. */
export const PROBE_TIME_RESERVE_MS = 2 * DEFAULT_TIMEOUT_MS;

export type NotCheckedReason = "time-limit" | "request-budget" | "stopped";

/** Fixed summaries: nothing from the target or the error is ever echoed into a not-checked result. */
export const NOT_CHECKED_SUMMARIES: Readonly<Record<NotCheckedReason, string>> = {
  "time-limit": "Not checked: the scan reached its time limit before this check could finish.",
  "request-budget": "Not checked: the scan's request budget ran out before this check could run.",
  stopped: "Not checked: the scan was stopped before this check could finish.",
};

export interface ProbeContext {
  target: ScanTarget;
  fetcher: GuardedFetcher;
  /** Limited to the probe's declared maxRequests and drawn from the scan's shared budget. */
  budget: RequestBudget;
  signal?: AbortSignal;
}

export interface PlannedProbe {
  checkId: string;
  title: string;
  /** Upper bound on the requests this probe may send; the scheduler enforces it. */
  maxRequests: number;
  /** Stamped on every row this probe produces, including not-checked rows. */
  group?: CheckGroup;
  run(context: ProbeContext): Promise<CheckResult>;
}

export interface ProbeStagePlan {
  probes: readonly PlannedProbe[];
  /** Absolute time (ms since the epoch, on the scan's clock) after which no probe may still be running. */
  deadline: number;
  /** Time that must remain before a probe starts. Defaults to PROBE_TIME_RESERVE_MS. */
  reserveMs?: number;
}

export interface ProbeStageResult {
  /** One result per planned probe, in plan order. */
  checks: CheckResult[];
  /** Why scheduling stopped early, or null when every probe ran to completion. */
  stoppedEarly: NotCheckedReason | null;
}

/** A probe's own allowance: it can never send more than its declared requests, nor more than the scan has left. */
class ProbeBudget extends RequestBudget {
  constructor(
    private readonly shared: RequestBudget,
    limit: number,
  ) {
    super(limit);
  }
  override take(): boolean {
    return this.shared.remaining > 0 && super.take() && this.shared.take();
  }
}

export function notChecked(probe: Pick<PlannedProbe, "checkId" | "title" | "group">, reason: NotCheckedReason): CheckResult {
  return withGroup(errored(probe.checkId, probe.title, NOT_CHECKED_SUMMARIES[reason]), probe.group);
}

function withGroup(check: CheckResult, group: CheckGroup | undefined): CheckResult {
  return group === undefined ? check : { ...check, group };
}

/** A timeout abort (AbortSignal.timeout, or a scan's own time limit) or a passed deadline counts as the time limit. */
function abortReason(signal: AbortSignal | undefined, deadline: number, now: number): NotCheckedReason {
  const reason: unknown = signal?.reason;
  const timedOut = typeof reason === "object" && reason !== null && (reason as { name?: unknown }).name === "TimeoutError";
  return timedOut || now >= deadline ? "time-limit" : "stopped";
}

export async function runProbeStage(options: ProbeStagePlan & { context: ProbeContext; now: () => number }): Promise<ProbeStageResult> {
  const { probes, deadline, context, now } = options;
  const reserveMs = options.reserveMs ?? PROBE_TIME_RESERVE_MS;
  const checks: CheckResult[] = [];
  let stop: NotCheckedReason | null = null;

  for (const probe of probes) {
    if (stop === null) {
      if (context.signal?.aborted) stop = abortReason(context.signal, deadline, now());
      else if (deadline - now() < reserveMs) stop = "time-limit";
      else if (context.budget.remaining < probe.maxRequests) stop = "request-budget";
    }
    if (stop !== null) {
      checks.push(notChecked(probe, stop));
      continue;
    }

    const probeContext: ProbeContext = { ...context, budget: new ProbeBudget(context.budget, probe.maxRequests) };
    let check: CheckResult;
    try {
      check = await probe.run(probeContext);
    } catch (error) {
      // Interrupted mid-flight: report the probe as not checked and keep everything else.
      // Any other failure, including a safety refusal (ScanStopped), still stops the scan.
      if (!context.signal?.aborted) throw error;
      stop = abortReason(context.signal, deadline, now());
      checks.push(notChecked(probe, stop));
      continue;
    }
    if (context.signal?.aborted) {
      // A result built from a cancelled request is not trustworthy, whatever it says.
      stop = abortReason(context.signal, deadline, now());
      checks.push(notChecked(probe, stop));
      continue;
    }
    checks.push(withGroup(check, probe.group));
  }
  return { checks, stoppedEarly: stop };
}
