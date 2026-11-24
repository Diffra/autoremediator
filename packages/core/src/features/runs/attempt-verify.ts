/** Operations on an open attempt: apply a patch, verify the checkout, abandon it. */
import { join } from "node:path";

import { validateAndApplyPatch } from "../repair/patch-apply.js";
import {
  type AttemptQuery,
  type AttemptView,
  type ProposePatchOptions,
  type VerifyAttemptOptions,
  appliedItems,
  context,
  expectedRemaining,
  loadOpen,
  planPackageManager,
  viewOf,
  withVerification,
  attemptVerifyRequest,
  defaultAttemptDeps,
} from "./attempt-view.js";
import { defaultRunDeps, type RunDeps } from "./deps.js";
import { type AttemptRecord } from "./run-store.js";
import { loadSnapshot } from "./snapshot-store.js";
import { discardWorktree } from "./worktree.js";

/**
 * Apply a unified diff to an open attempt's checkout. Only project source may change, as for the
 * built-in agent, and the patch must be plain text and apply cleanly.
 */
export async function proposePatch(options: ProposePatchOptions): Promise<AttemptView> {
  const { store } = context(options);
  const record = loadOpen(store, options.runId, options.attemptId);
  const { files } = await validateAndApplyPatch(record.worktreePath, options.diff);

  const updated: AttemptRecord = { ...record, endedAt: new Date().toISOString() };
  store.writeAttempt(options.runId, updated);
  return viewOf(updated, options.runId, {
    changedFiles: files,
    message: `Applied the patch to ${files.length} file(s): ${files.join(", ")}. Verify it next.`,
  });
}

/** Run the verifier on an open attempt's checkout and report what, if anything, is wrong. */
export async function verifyAttempt(
  options: VerifyAttemptOptions,
  deps: RunDeps = defaultRunDeps,
): Promise<AttemptView> {
  const { store } = context(options);
  const record = loadOpen(store, options.runId, options.attemptId);
  const run = store.load(options.runId);
  const plan = store.readPlan(run.runId);
  const item = plan?.items.find((candidate) => candidate.itemId === record.itemId);
  if (!plan || !item) {
    throw new Error(`Attempt ${record.attemptId} refers to a plan item that no longer exists.`);
  }

  const before = loadSnapshot(join(store.attemptDir(run.runId, record.attemptId), "before"));
  const ad = deps.attemptDeps ?? defaultAttemptDeps;
  const verification = await ad.verify(
    attemptVerifyRequest({
      checkout: record.worktreePath,
      packageManager: planPackageManager(plan),
      options: plan.options,
      before,
      advisories: store.readReport(run.runId)?.cveDetails
        ? [store.readReport(run.runId)!.cveDetails!]
        : [],
      expectedRemaining: expectedRemaining(plan, item, appliedItems(store, run.runId)),
      ...(options.checks ? { checks: options.checks } : {}),
    }),
  );

  const updated: AttemptRecord = {
    ...record,
    reason: verification.passed
      ? "Verified: finalize it."
      : `Not yet: ${verification.failedCheck} fails.`,
    changedFiles: verification.changedFiles ?? record.changedFiles,
    endedAt: new Date().toISOString(),
  };
  store.writeAttempt(run.runId, updated, {
    "verification.json": `${JSON.stringify(verification, null, 2)}\n`,
  });
  store.ledger(run.runId).append("attempt.verify", {
    attemptId: record.attemptId,
    passed: verification.passed,
    ...(verification.failedCheck ? { failedCheck: verification.failedCheck } : {}),
  });
  return viewOf(updated, run.runId, withVerification(verification));
}

/** Throw an open attempt away: its checkout is removed and nothing reaches the project. */
export async function abandonAttempt(options: AttemptQuery): Promise<AttemptView> {
  const { cwd, store } = context(options);
  const record = loadOpen(store, options.runId, options.attemptId);
  await discardWorktree(cwd, record.worktreePath);
  const closed: AttemptRecord = {
    ...record,
    status: "abandoned",
    reason: "Abandoned.",
    endedAt: new Date().toISOString(),
  };
  delete closed.worktreePath;
  store.writeAttempt(options.runId, closed);
  store.ledger(options.runId).append("attempt.done", {
    attemptId: record.attemptId,
    itemId: record.itemId,
    status: "abandoned",
    rounds: 0,
  });
  return viewOf(closed, options.runId);
}
