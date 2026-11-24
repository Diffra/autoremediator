import type { AutonomySummary } from "../autonomy/types.js";
import { resolveConstraints } from "../remediate/context.js";
import type { RemediateOptions, RemediationReport } from "../remediate/types.js";
import type { RepairAgent, RepairBudget } from "../repair/repair-agent.js";
import type { CheckName, VerificationResult } from "../verify/types.js";
import { fingerprintRepo } from "./fingerprint.js";
import type { StepEvent } from "./ledger.js";
import {
  buildPlan,
  type PlanItem,
  type PlanOptions,
  type PlanSkip,
  type RemediationPlan,
} from "./plan.js";
import { RunStore, type AttemptRecord, type RunRecord, type RunStatus } from "./run-store.js";

export { applyPlan, resumeRun } from "./apply.js";
export { rollbackRun } from "./rollback.js";
export {
  readAttemptArtifact,
  verifyRun,
  type AttemptArtifact,
  type RunVerification,
} from "./verify-run.js";

export type { AttemptRecord, AttemptStatus, RunRecord, RunStatus } from "./run-store.js";
export type { RunDeps } from "./deps.js";
export type { PlanItem, PlanSkip, RemediationPlan } from "./plan.js";
export type { CheckName, CheckResult, VerificationResult } from "../verify/types.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface RunQuery {
  /** Project directory (default: process.cwd()). */
  cwd?: string;
  runId: string;
}

export interface ApplyPlanOptions {
  cwd?: string;
  /** The run that holds the plan. */
  runId?: string;
  /** Alternative to `runId`: the content id of the plan. */
  planId?: string;
  /** Apply only these plan items (default: every item not yet applied). */
  itemIds?: string[];
  /**
   * Verify each item after applying it, and take it back out if verification fails (default:
   * true). Runs the cheap checks (scope, policy, supply-chain, vuln-gone); tests and type checks
   * already ran inside the apply step when requested.
   */
  verify?: boolean;
  /**
   * When an upgrade breaks the project's type check or tests, have an agent repair the project's
   * source in an isolated checkout, and keep the result only if the verifier accepts it. Default:
   * on when a model is configured (`model` or `AUTOREMEDIATOR_MODEL`), off otherwise. `true`
   * without a model is an error; `false` never spends tokens.
   */
  repair?: boolean;
  /** Language model for repair, as `<provider>:<model-id>` (default: `AUTOREMEDIATOR_MODEL`). */
  model?: string;
  /** SDK only: supply the agent yourself instead of configuring a model. */
  repairAgent?: RepairAgent;
  /** Limits for one repair attempt (defaults: 40 steps, 10 minutes, 12 commands, 3 rounds). */
  repairBudget?: Partial<RepairBudget>;
  /** SDK only: cancel in-flight repairs. */
  signal?: AbortSignal;
}

export interface VerifyRunOptions extends RunQuery {
  /** Run only these checks (default: all, in order). */
  checks?: CheckName[];
  /** Skip checks that need the network. */
  offline?: boolean;
}

export interface RollbackRunOptions extends RunQuery {
  /** Roll back even though the project changed since the run's last step. */
  force?: boolean;
  /**
   * Reinstall dependencies from the restored lockfile so `node_modules` matches again (default:
   * true). Without it the restored manifests and the installed packages disagree.
   */
  reinstall?: boolean;
}

export interface ListRunsOptions {
  cwd?: string;
  status?: RunStatus;
  limit?: number;
}

export interface ItemOutcome {
  itemId: string;
  packageName: string;
  fromVersion: string;
  toVersion: string;
  strategy: PlanItem["strategy"];
  status: "applied" | "failed";
  message: string;
  unresolvedReason?: string;
  /** Set when verification ran for this item; a failed one is why the item was taken back out. */
  verification?: VerificationResult;
  /** Set when an agent was asked to repair this item. */
  repair?: { attemptId: string; status: string; rounds: number; reason: string };
}

export interface RunReport {
  runId: string;
  planId?: string;
  status: RunStatus;
  cwd: string;
  /** Outcomes of the items this call attempted. */
  items: ItemOutcome[];
  /** Plan items that were not attempted by this call. */
  pending: string[];
  skipped: PlanSkip[];
  message: string;
  /** Set when the policy configures earned autonomy: the level in force and what it says about this run. */
  autonomy?: AutonomySummary;
}

export interface RunDetails {
  run: RunRecord;
  plan?: RemediationPlan;
  /** Outcome of every plan item that has been attempted, from the ledger. */
  items: ItemOutcome[];
  /** Agent repair attempts, oldest first. */
  attempts: AttemptRecord[];
  ledger: { ok: boolean; reason?: string; events: StepEvent[] };
}

export interface RollbackReport {
  runId: string;
  status: "rolled-back";
  restoredFiles: number;
  /** Manifests and lockfiles match the state the plan was made against again. */
  matchesBase: boolean;
  /** Whether dependencies were reinstalled from the restored lockfile. */
  reinstalled: boolean;
  /** Why the reinstall did not happen or failed. */
  reinstallNote?: string;
  message: string;
}

// ---------------------------------------------------------------------------
// Planning
// ---------------------------------------------------------------------------

function planOptionsFrom(options: RemediateOptions, cwd: string): PlanOptions {
  const constraints = resolveConstraints(options, cwd);
  return {
    ...(options.packageManager ? { packageManager: options.packageManager } : {}),
    ...(options.policy ? { policy: options.policy } : {}),
    ...(options.runTests === undefined ? {} : { runTests: options.runTests }),
    ...(constraints.typecheck === undefined ? {} : { typecheck: constraints.typecheck }),
    ...(options.patchesDir ? { patchesDir: options.patchesDir } : {}),
    ...(options.proofOfFix === undefined ? {} : { proofOfFix: options.proofOfFix }),
    ...(constraints.requireProofOfFix === undefined
      ? {}
      : { requireProofOfFix: constraints.requireProofOfFix }),
    ...(options.reproductionTest ? { reproductionTest: options.reproductionTest } : {}),
    ...(options.ignoreMemory ? { ignoreMemory: true } : {}),
    ...(constraints.enableBreakingChangeRefactor === undefined
      ? {}
      : { breakingChangeRefactor: constraints.enableBreakingChangeRefactor }),
    constraints,
  };
}

/**
 * Record a preview as a run with a plan that can be applied later. Returns the ids to put on the
 * report. Nothing in the project is touched.
 */
export async function persistPlan(
  report: RemediationReport,
  options: RemediateOptions,
  cwd: string,
): Promise<{ runId: string; planId: string }> {
  const store = new RunStore(cwd);
  const planOptions = planOptionsFrom(options, cwd);
  const base = await fingerprintRepo(cwd, options.policy);
  const run = store.create({
    cwd,
    cveIds: [report.cveId],
    source: options.source,
    base,
    status: "planned",
  });
  const plan = buildPlan({ runId: run.runId, cwd, report, base, options: planOptions });

  store.writeJson(run.runId, "plan.json", plan);
  store.writeJson(run.runId, "report.json", report);
  store.update(run.runId, { planId: plan.planId });
  store.ledger(run.runId).append("plan.created", {
    planId: plan.planId,
    cveId: report.cveId,
    items: plan.items.length,
    skipped: plan.skipped.length,
  });
  return { runId: run.runId, planId: plan.planId };
}

// ---------------------------------------------------------------------------
// Reading runs
// ---------------------------------------------------------------------------

function outcomesFrom(events: StepEvent[], plan: RemediationPlan | undefined): ItemOutcome[] {
  const byItem = new Map<string, ItemOutcome>();
  for (const event of events) {
    if (!["item.done", "item.error", "item.rejected"].includes(event.type)) continue;
    const itemId = String(event.data["itemId"]);
    const item = plan?.items.find((candidate) => candidate.itemId === itemId);
    if (!item) continue;
    byItem.set(itemId, {
      itemId,
      packageName: item.packageName,
      fromVersion: item.fromVersion,
      toVersion: item.toVersion,
      strategy: item.strategy,
      status:
        event.type === "item.done" && event.data["status"] === "applied" ? "applied" : "failed",
      message: typeof event.data["message"] === "string" ? event.data["message"] : "",
      ...(typeof event.data["unresolvedReason"] === "string"
        ? { unresolvedReason: event.data["unresolvedReason"] }
        : {}),
      ...(event.data["repair"] ? { repair: event.data["repair"] as ItemOutcome["repair"] } : {}),
    });
  }
  return [...byItem.values()];
}

export function getRun(query: RunQuery): RunDetails {
  const store = new RunStore(query.cwd ?? process.cwd());
  const run = store.load(query.runId);
  const plan = store.readPlan(run.runId);
  const ledger = store.ledger(run.runId);
  const check = ledger.verify();
  const events = check.ok || check.seq > 1 ? safeRead(ledger) : [];
  return {
    run,
    ...(plan ? { plan } : {}),
    items: outcomesFrom(events, plan),
    attempts: store.listAttempts(run.runId),
    ledger: check.ok ? { ok: true, events } : { ok: false, reason: check.reason, events },
  };
}

function safeRead(ledger: ReturnType<RunStore["ledger"]>): StepEvent[] {
  try {
    return ledger.read();
  } catch {
    return [];
  }
}

export function listRuns(options: ListRunsOptions = {}): RunRecord[] {
  const store = new RunStore(options.cwd ?? process.cwd());
  const runs = store.list().filter((run) => !options.status || run.status === options.status);
  return options.limit && options.limit > 0 ? runs.slice(0, options.limit) : runs;
}
