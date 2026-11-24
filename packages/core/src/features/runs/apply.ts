/**
 * Applying a plan. Before the first change the project's manifests and lockfiles are snapshotted
 * to disk, each item is recorded in the run's ledger as it is attempted, and the run can be resumed
 * after a crash or undone with `rollbackRun`. A plan made against inputs that have since changed is
 * refused rather than applied to a project it was not made for.
 */
import { createProjectSnapshot } from "../../infra/rollback/rollback.js";
import { errorMessage } from "../../shared/errors.js";
import { assertAutonomyAllows, summarizeAutonomy } from "../autonomy/index.js";
import { loadMemoryConstraints, pinnedMessage } from "../memory/consume.js";
import type { PatchResult } from "../remediate/types.js";
import type { VerificationResult } from "../verify/types.js";
import {
  type ApplyContext,
  outcomeOf,
  rejectItem,
  repairBrokenItem,
  REPAIRABLE,
  resolveRepairAgent,
  verifyItem,
} from "./apply-steps.js";
import { applyEvents, autonomyForReport, recordOutcomes } from "./autonomy-events.js";
import { defaultRunDeps, type RunDeps } from "./deps.js";
import { fingerprintRepo, sameInputs } from "./fingerprint.js";
import { isPlanId, isRunId } from "./ids.js";
import type { ApplyPlanOptions, ItemOutcome, RunQuery, RunReport } from "./index.js";
import {
  appliedTestCommand,
  passedTestCommands,
  recordMemory,
  rejectedUpgradeEntry,
  testCommandEntry,
} from "./memory-events.js";
import type { PlanItem, RemediationPlan } from "./plan.js";
import { hasRecipeFor } from "./recipes.js";
import { APPLICABLE_STATUSES, ensureRunSnapshot } from "./repair.js";
import { RunStore, type RunRecord, type RunStatus } from "./run-store.js";

function resolveRun(store: RunStore, options: ApplyPlanOptions): RunRecord {
  if (options.runId) {
    if (!isRunId(options.runId)) {
      throw new Error(`Invalid run id: ${JSON.stringify(options.runId)}`);
    }
    return store.load(options.runId);
  }
  if (options.planId) {
    if (!isPlanId(options.planId)) {
      throw new Error(`Invalid plan id: ${JSON.stringify(options.planId)}`);
    }
    const match = store
      .list()
      .find((run) => run.planId === options.planId && run.status !== "rolled-back");
    if (!match) throw new Error(`No run found for plan ${options.planId}`);
    return match;
  }
  throw new Error("applyPlan needs a runId or a planId.");
}

function summarize(status: RunStatus, outcomes: ItemOutcome[], plan: RemediationPlan): string {
  const done = outcomes.filter((outcome) => outcome.status === "applied").length;
  const failed = outcomes.length - done;
  if (plan.items.length === 0) return "The plan has no changes to apply.";
  return `${status}: ${done} applied, ${failed} failed of ${outcomes.length} attempted (${plan.items.length} in plan).`;
}

/** A pin recorded after the plan was made still holds: refuse before anything is changed. */
function assertNoPinnedItems(
  cwd: string,
  runId: string,
  plan: RemediationPlan,
  itemIds?: string[],
) {
  if (plan.options.ignoreMemory) return;
  const { pinned } = loadMemoryConstraints(cwd);
  const wanted = plan.items.filter((item) => !itemIds || itemIds.includes(item.itemId));
  for (const item of wanted) {
    const pin = pinned.get(item.packageName);
    if (pin) {
      throw new Error(
        `Run ${runId}: plan item ${item.packageName} ${item.fromVersion} -> ${item.toVersion} is refused. ${pinnedMessage(pin)} Plan again after changing memory.`,
      );
    }
  }
}

/** Refuses a run that cannot be applied now: wrong status, broken ledger, changed project. */
async function assertCanApply(
  cwd: string,
  store: RunStore,
  run: RunRecord,
  options: ApplyPlanOptions,
): Promise<{ plan: RemediationPlan; applied: Set<string> }> {
  const runId = run.runId;
  if (!APPLICABLE_STATUSES.has(run.status)) {
    throw new Error(`Run ${runId} is ${run.status}; there is nothing to apply.`);
  }
  const plan = store.readPlan(runId);
  if (!plan) throw new Error(`Run ${runId} has no plan.`);
  // Earned autonomy (opt-in via the policy): below L2 nothing is changed, and the reason is given.
  assertAutonomyAllows(cwd, plan.options.policy, "apply", `Applying run ${runId}`);

  const ledger = store.ledger(runId);
  const chain = ledger.verify();
  if (!chain.ok) throw new Error(`Run ${runId}: ledger failed verification (${chain.reason}).`);

  const known = new Set(plan.items.map((item) => item.itemId));
  for (const id of options.itemIds ?? []) {
    if (!known.has(id)) throw new Error(`Plan ${plan.planId} has no item ${id}.`);
  }
  assertNoPinnedItems(cwd, runId, plan, options.itemIds);

  const applied = new Set(
    ledger
      .read()
      .filter((event) => event.type === "item.done" && event.data["status"] === "applied")
      .map((event) => String(event.data["itemId"])),
  );
  // The project must still be what the plan (or the last completed step) left it.
  if (!sameInputs(await fingerprintRepo(cwd, plan.options.policy), run.after ?? run.base)) {
    throw new Error(
      run.status === "planned"
        ? `The project changed since plan ${plan.planId} was made (manifests, lockfiles or policy differ). Plan again.`
        : `The project changed since run ${runId}'s last completed step, possibly by an interrupted install. Inspect it, or roll the run back.`,
    );
  }
  return { plan, applied };
}

/** Applies one plan item; `stop` is set when the run cannot go on after it. */
async function applyOneItem(
  context: ApplyContext,
  item: PlanItem,
): Promise<{ outcome: ItemOutcome; ok: boolean; stop?: string }> {
  const { cwd, store, runId, options, deps, plan, agent } = context;
  const ledger = store.ledger(runId);
  // Taken before the item, so a rejected item can be put back exactly.
  const before = await createProjectSnapshot(cwd);
  ledger.append("item.start", { itemId: item.itemId, packageName: item.packageName });
  let result: PatchResult;
  try {
    result = await deps.applyItem(item, { cwd, options: plan.options });
  } catch (error) {
    const message = errorMessage(error);
    ledger.append("item.error", { itemId: item.itemId, message });
    return { outcome: outcomeOf(item, "failed", message), ok: false, stop: message };
  }

  let ok = result.applied && !result.unresolvedReason;
  let message = result.message;
  let verification: VerificationResult | undefined;
  let repair: ItemOutcome["repair"];

  // With no agent (no model configured) a repair is still worth an attempt when a recipe exists.
  const repairable =
    agent !== undefined ||
    (options.repair !== false && hasRecipeFor(cwd, item, plan.options.policy));
  if (!ok && repairable && result.unresolvedReason && REPAIRABLE.has(result.unresolvedReason)) {
    const repaired = await repairBrokenItem(context, item, message);
    ({ ok, message, verification, repair } = repaired);
  }

  if (ok && options.verify !== false && !repair) {
    verification = await verifyItem(context, item, before);
    if (!verification.passed) {
      return { outcome: await rejectItem(context, item, before, verification), ok: false };
    }
  }

  const after = await fingerprintRepo(cwd, plan.options.policy);
  ledger.append("item.done", {
    itemId: item.itemId,
    status: ok ? "applied" : "failed",
    message,
    ...(result.unresolvedReason ? { unresolvedReason: result.unresolvedReason } : {}),
    ...(verification ? { verified: true } : {}),
    ...(repair ? { repair } : {}),
    filesSha256: after.filesSha256,
  });
  store.update(runId, { after });
  return {
    ok,
    outcome: {
      ...outcomeOf(item, ok ? "applied" : "failed", message, result.unresolvedReason),
      ...(verification ? { verification } : {}),
      ...(repair ? { repair } : {}),
    },
  };
}

/** What the run records once its items are done: autonomy outcomes and memory. */
async function recordRun(
  context: ApplyContext,
  run: RunRecord,
  outcomes: ItemOutcome[],
): Promise<void> {
  const { cwd, store, runId, plan } = context;
  const ledger = store.ledger(runId);
  await recordOutcomes(
    cwd,
    plan.options.policy,
    applyEvents(run, plan.options, outcomes),
    (problem) => ledger.append("autonomy.record-failed", { message: problem }),
  );
  // What this run established for the repository's memory: upgrades the verifier rejected, and how tests ran.
  const testCommands = new Set(
    outcomes.flatMap((outcome) => {
      const ran = passedTestCommands(outcome.verification);
      if (ran.length > 0 || outcome.status !== "applied") return ran;
      return [appliedTestCommand(cwd, plan.options)].filter((command) => command !== undefined);
    }),
  );
  await recordMemory(
    cwd,
    runId,
    [
      ...outcomes.map((outcome) => rejectedUpgradeEntry(outcome, outcome.verification)),
      ...[...testCommands].map((command) => testCommandEntry(command)),
    ],
    (problem) => ledger.append("memory.record-failed", { message: problem }),
  );
}

/**
 * Apply a plan. Before the first change the project's manifests and lockfiles are snapshotted to
 * disk, each item is recorded in the run's ledger as it is attempted, and the run can be resumed
 * after a crash or undone with `rollbackRun`. A plan made against inputs that have since changed is
 * refused rather than applied to a project it was not made for.
 */
export async function applyPlan(
  options: ApplyPlanOptions,
  deps: RunDeps = defaultRunDeps,
): Promise<RunReport> {
  const cwd = options.cwd ?? process.cwd();
  const store = new RunStore(cwd);
  const run = resolveRun(store, options);
  const runId = run.runId;
  const { plan, applied } = await assertCanApply(cwd, store, run, options);
  const levelBefore = summarizeAutonomy(cwd, plan.options.policy)?.level;
  const ledger = store.ledger(runId);

  const notes: string[] = [];
  const agent = await resolveRepairAgent(options, (message) => notes.push(message));

  const release = store.acquireApplyLock(runId);
  const outcomes: ItemOutcome[] = [];
  try {
    for (const note of notes) ledger.append("repair.unavailable", { message: note });
    await ensureRunSnapshot(store, runId, cwd);
    store.update(runId, { status: "applying" });
    ledger.append("apply.start", {
      itemIds: options.itemIds ?? "all",
      resumed: run.status !== "planned",
    });

    const context: ApplyContext = {
      cwd,
      store,
      runId,
      options,
      deps,
      plan,
      agent,
      advisories: store.readReport(runId)?.cveDetails,
      applied,
    };
    const selected = plan.items.filter(
      (item) =>
        !applied.has(item.itemId) && (!options.itemIds || options.itemIds.includes(item.itemId)),
    );
    let failure: string | undefined;
    for (const item of selected) {
      const done = await applyOneItem(context, item);
      outcomes.push(done.outcome);
      if (done.stop) {
        failure = done.stop;
        break;
      }
      if (done.ok) applied.add(item.itemId);
    }

    let status: RunStatus = "partial";
    if (failure) {
      status = "failed";
    } else if (plan.items.every((item) => applied.has(item.itemId))) {
      status = "applied";
    }
    store.update(runId, { status, ...(failure ? { error: failure } : {}) });
    ledger.append("apply.end", { status });

    await recordRun(context, run, outcomes);
    const autonomy = autonomyForReport(
      cwd,
      plan.options.policy,
      status,
      outcomes,
      plan,
      levelBefore,
    );
    return {
      runId,
      planId: plan.planId,
      status,
      cwd,
      items: outcomes,
      pending: plan.items.filter((item) => !applied.has(item.itemId)).map((item) => item.itemId),
      skipped: plan.skipped,
      message: summarize(status, outcomes, plan),
      ...(autonomy ? { autonomy } : {}),
    };
  } finally {
    release();
  }
}

/** Continue a run that was interrupted or left partial, skipping items already applied. */
export async function resumeRun(
  query: RunQuery,
  deps: RunDeps = defaultRunDeps,
): Promise<RunReport> {
  const run = new RunStore(query.cwd ?? process.cwd()).load(query.runId);
  if (run.status === "planned") {
    throw new Error(`Run ${run.runId} has not started; use applyPlan.`);
  }
  return applyPlan({ cwd: query.cwd, runId: query.runId }, deps);
}
