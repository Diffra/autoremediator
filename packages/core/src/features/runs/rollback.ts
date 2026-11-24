/** Undoes a run: restores the manifests, lockfiles and patch files from the snapshot taken first. */
import { join } from "node:path";

import { restoreProjectSnapshot } from "../../infra/rollback/rollback.js";
import { recordOutcomes, rollbackEvent } from "./autonomy-events.js";
import { defaultRunDeps, type RunDeps } from "./deps.js";
import { fingerprintRepo, sameInputs } from "./fingerprint.js";
import type { RollbackReport, RollbackRunOptions } from "./index.js";
import { SNAPSHOT_DIR, SNAPSHOT_MANIFEST } from "./repair.js";
import { RunStore } from "./run-store.js";
import { loadSnapshot } from "./snapshot-store.js";

/**
 * Undo a run: restore the manifests, lockfiles and patch files it changed from the snapshot taken
 * before its first change. Refused when the project has changed since the run's last step, because
 * restoring would silently discard that work (pass `force` to override).
 */
export async function rollbackRun(
  options: RollbackRunOptions,
  deps: RunDeps = defaultRunDeps,
): Promise<RollbackReport> {
  const cwd = options.cwd ?? process.cwd();
  const store = new RunStore(cwd);
  const run = store.load(options.runId);
  const runId = run.runId;

  if (run.status === "planned") {
    throw new Error(`Run ${runId} made no changes; there is nothing to roll back.`);
  }
  if (run.status === "rolled-back") throw new Error(`Run ${runId} is already rolled back.`);
  if (!store.hasFile(runId, SNAPSHOT_MANIFEST)) {
    throw new Error(`Run ${runId} has no snapshot to restore.`);
  }

  const release = store.acquireApplyLock(runId);
  try {
    const plan = store.readPlan(runId);
    const policy = plan?.options.policy;
    const appliedBefore = appliedCount(store, runId);
    const current = await fingerprintRepo(cwd, policy);
    if (!options.force && !sameInputs(current, run.after ?? run.base)) {
      throw new Error(
        `The project changed since run ${runId}'s last step; rolling back would discard those changes. Review them, or pass force.`,
      );
    }

    const snapshot = loadSnapshot(join(store.runDir(runId), SNAPSHOT_DIR));
    if (snapshot.cwd !== run.cwd) {
      throw new Error(
        `Run ${runId}: snapshot was taken for a different directory; refusing to restore.`,
      );
    }
    await restoreProjectSnapshot(snapshot);

    let reinstalled = false;
    let reinstallNote: string | undefined;
    if (options.reinstall === false) {
      reinstallNote = "skipped (reinstall: false)";
    } else {
      try {
        await deps.reinstall({ cwd, options: plan?.options });
        reinstalled = true;
      } catch (error) {
        reinstallNote = error instanceof Error ? error.message.split("\n")[0] : String(error);
      }
    }

    const restored = await fingerprintRepo(cwd, policy);
    const matchesBase = sameInputs(restored, run.base);
    store.update(runId, { status: "rolled-back", after: restored });
    store.ledger(runId).append("rollback", {
      restoredFiles: snapshot.fileSnapshots.size,
      matchesBase,
      reinstalled,
      forced: Boolean(options.force),
    });
    await recordOutcomes(
      cwd,
      policy,
      rollbackEvent(run, plan, appliedBefore, {
        restoredFiles: snapshot.fileSnapshots.size,
        forced: Boolean(options.force),
      }),
      (problem) => store.ledger(runId).append("autonomy.record-failed", { message: problem }),
    );

    return {
      runId,
      status: "rolled-back",
      restoredFiles: snapshot.fileSnapshots.size,
      matchesBase,
      reinstalled,
      ...(reinstallNote ? { reinstallNote } : {}),
      message: describeRollback(matchesBase, reinstalled, reinstallNote),
    };
  } finally {
    release();
  }
}

/** Items the run has applied, from its ledger. */
function appliedCount(store: RunStore, runId: string): number {
  return store
    .ledger(runId)
    .read()
    .filter((event) => event.type === "item.done" && event.data["status"] === "applied").length;
}

function describeRollback(matchesBase: boolean, reinstalled: boolean, note?: string): string {
  const files = matchesBase
    ? "Restored manifests, lockfiles and patch files."
    : "Restored the recorded files, but the project still differs from when the plan was made (files the snapshot does not cover).";
  return reinstalled
    ? `${files} Reinstalled dependencies from the restored lockfile.`
    : `${files} Dependencies were not reinstalled (${note}); run your package manager's install to refresh node_modules.`;
}
