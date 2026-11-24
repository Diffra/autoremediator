/** Puts an open attempt's change in the project, if it verifies, or reports why it did not. */
import { assertAutonomyAllows } from "../autonomy/index.js";
import type { VerificationResult } from "../verify/types.js";
import { verifyAttempt } from "./attempt-verify.js";
import {
  type AttemptQuery,
  type AttemptView,
  appliedItems,
  context,
  expectedRemaining,
  loadOpen,
  planPackageManager,
  viewOf,
  defaultAttemptDeps,
} from "./attempt-view.js";
import { finalizeEvent, recordOutcomes } from "./autonomy-events.js";
import { defaultRunDeps, type RunDeps } from "./deps.js";
import { fingerprintRepo, sameInputs } from "./fingerprint.js";
import {
  passedTestCommands,
  recordMemory,
  rejectedUpgradeEntry,
  testCommandEntry,
} from "./memory-events.js";
import type { PlanItem, RemediationPlan } from "./plan.js";
import { APPLICABLE_STATUSES, ensureRunSnapshot, promoteChange } from "./repair.js";
import type { AttemptRecord, RunRecord, RunStore } from "./run-store.js";
import { discardWorktree } from "./worktree.js";

/** The run, plan and item an attempt may be finalized for, or why it may not be. */
async function assertCanFinalize(
  cwd: string,
  store: RunStore,
  record: AttemptRecord,
  runId: string,
): Promise<{ run: RunRecord; plan: RemediationPlan; item: PlanItem; applied: Set<string> }> {
  const run = store.load(runId);
  const plan = store.readPlan(run.runId);
  const item = plan?.items.find((candidate) => candidate.itemId === record.itemId);
  if (!plan || !item) {
    throw new Error(`Attempt ${record.attemptId} refers to a plan item that no longer exists.`);
  }
  if (!APPLICABLE_STATUSES.has(run.status)) {
    throw new Error(`Run ${run.runId} is ${run.status}; nothing can be finalized.`);
  }
  // Earned autonomy (opt-in via the policy): below L2 nothing is put in the project.
  assertAutonomyAllows(cwd, plan.options.policy, "apply", `Finalizing attempt ${record.attemptId}`);
  const applied = appliedItems(store, run.runId);
  if (applied.has(item.itemId)) throw new Error(`Item ${item.itemId} is already applied.`);
  if (!sameInputs(await fingerprintRepo(cwd, plan.options.policy), run.after ?? run.base)) {
    throw new Error("The project changed since this attempt began; abandon it and start again.");
  }
  return { run, plan, item, applied };
}

/** What the run records once an attempt has been promoted, or refused, at the project. */
async function recordPromotion(
  state: {
    cwd: string;
    store: RunStore;
    run: RunRecord;
    plan: RemediationPlan;
    item: PlanItem;
    record: AttemptRecord;
    closed: AttemptRecord;
  },
  promoted: { ok: boolean; message: string; verification?: VerificationResult },
  checked: VerificationResult,
): Promise<void> {
  const { cwd, store, run, plan, item } = state;
  const ledger = store.ledger(run.runId);
  const recordProblem = (problem: string) =>
    ledger.append("autonomy.record-failed", { message: problem });
  // What the verifier established is what memory may keep: the tests ran in the checkout, and a
  // rejection in the project is the verifier's own finding.
  await recordMemory(
    cwd,
    run.runId,
    promoted.ok
      ? passedTestCommands(checked).map((command) => testCommandEntry(command))
      : [rejectedUpgradeEntry(item, promoted.verification)],
    (problem) => ledger.append("memory.record-failed", { message: problem }),
  );
  await recordOutcomes(
    cwd,
    plan.options.policy,
    [
      finalizeEvent(
        run,
        item.itemId,
        item.packageName,
        promoted.ok
          ? { promoted: true, message: "", verification: checked }
          : { promoted: false, message: promoted.message },
      ),
    ],
    recordProblem,
  );
}

/** The run's ledger and status once the item is in the project. */
async function markItemApplied(state: {
  cwd: string;
  store: RunStore;
  run: RunRecord;
  plan: RemediationPlan;
  item: PlanItem;
  record: AttemptRecord;
  applied: Set<string>;
}): Promise<void> {
  const { cwd, store, run, plan, item, record, applied } = state;
  const after = await fingerprintRepo(cwd, plan.options.policy);
  store.ledger(run.runId).append("item.done", {
    itemId: item.itemId,
    status: "applied",
    message: `Upgraded ${item.packageName} to ${item.toVersion} with a host agent's repair.`,
    verified: true,
    repair: { attemptId: record.attemptId, status: "promoted", rounds: 0, reason: record.reason },
    filesSha256: after.filesSha256,
  });
  applied.add(item.itemId);
  store.update(run.runId, {
    after,
    allowSourceEdits: true,
    status: plan.items.every((candidate) => applied.has(candidate.itemId)) ? "applied" : "partial",
  });
}

/**
 * Put an attempt's change in the project, if it verifies. The checkout is verified again first,
 * then the change is applied as a patch, re-checked in place and undone if that fails: exactly the
 * path the built-in agent's results take.
 */
export async function finalizeAttempt(
  options: AttemptQuery,
  deps: RunDeps = defaultRunDeps,
): Promise<AttemptView> {
  const { cwd, store } = context(options);
  const record = loadOpen(store, options.runId, options.attemptId);
  const { run, plan, item, applied } = await assertCanFinalize(cwd, store, record, options.runId);

  const checked = await verifyAttempt(options, deps);
  if (!checked.verification?.passed) {
    return {
      ...checked,
      finalized: false,
      message: `Not finalized: ${checked.verification?.failedCheck} fails. Fix it and verify again.`,
    };
  }

  const ad = deps.attemptDeps ?? defaultAttemptDeps;
  const release = store.acquireApplyLock(run.runId);
  try {
    await ensureRunSnapshot(store, run.runId, cwd);
    const advisories = store.readReport(run.runId)?.cveDetails;
    const promoted = await promoteChange({
      cwd,
      runDir: store.runDir(run.runId),
      diff: await ad.diff(record.worktreePath),
      policy: plan.options.policy,
      packageManager: planPackageManager(plan),
      advisories: advisories ? [advisories] : [],
      expectedRemaining: expectedRemaining(plan, item, applied),
      deps: {
        verify: deps.verify,
        reinstall: () => deps.reinstall({ cwd, options: plan.options }),
      },
    });

    const closed: AttemptRecord = {
      ...record,
      status: promoted.ok ? "promoted" : "promotion-failed",
      reason: promoted.ok ? "Applied to the project." : promoted.message,
      endedAt: new Date().toISOString(),
    };
    delete closed.worktreePath;
    store.writeAttempt(run.runId, closed);
    await discardWorktree(cwd, record.worktreePath);
    store.ledger(run.runId).append("attempt.done", {
      attemptId: record.attemptId,
      itemId: item.itemId,
      status: closed.status,
      rounds: 0,
    });
    await recordPromotion(
      { cwd, store, run, plan, item, record, closed },
      promoted,
      checked.verification,
    );
    const verification = promoted.verification ?? checked.verification;
    if (!promoted.ok) return viewOf(closed, run.runId, { finalized: false, verification });

    await markItemApplied({ cwd, store, run, plan, item, record, applied });
    return viewOf(closed, run.runId, {
      finalized: true,
      verification,
      message: "Applied to the project.",
    });
  } finally {
    release();
  }
}
