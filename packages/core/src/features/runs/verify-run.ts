/** Judges a run's project as it is now, and reads back the artifacts attempts keep. */
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import type { VerificationResult, VerifyRequest } from "../verify/types.js";
import { recordOutcomes, verifyEvents } from "./autonomy-events.js";
import { defaultRunDeps, type RunDeps } from "./deps.js";
import type { RunQuery, VerifyRunOptions } from "./index.js";
import { passedTestCommands, recordMemory, testCommandEntry } from "./memory-events.js";
import type { PlanOptions } from "./plan.js";
import { SNAPSHOT_DIR, SNAPSHOT_MANIFEST } from "./repair.js";
import { RunStore } from "./run-store.js";
import { loadSnapshot } from "./snapshot-store.js";

export function verifyOptionsOf(options: PlanOptions): VerifyRequest["options"] {
  return {
    ...(options.runTests === undefined ? {} : { runTests: options.runTests }),
    ...(options.typecheck === undefined ? {} : { typecheck: options.typecheck }),
    ...(options.proofOfFix === undefined ? {} : { proofOfFix: options.proofOfFix }),
    ...(options.requireProofOfFix === undefined
      ? {}
      : { requireProofOfFix: options.requireProofOfFix }),
    ...(options.reproductionTest ? { reproductionTest: options.reproductionTest } : {}),
    ...(options.patchesDir ? { patchesDir: options.patchesDir } : {}),
    ...(options.constraints ? { constraints: options.constraints } : {}),
  };
}

// ---------------------------------------------------------------------------
// Verifying
// ---------------------------------------------------------------------------

export interface RunVerification extends VerificationResult {
  runId: string;
}

/**
 * Judge a run's project as it is now against what the run set out to do, with the full set of
 * checks (or the ones asked for): the changes stayed in scope and within policy, the new versions
 * pass the supply-chain gate, a frozen install works, the advisories no longer match, and the
 * requested tests, type check and reproduction test pass. The result is stored with the run.
 */
export async function verifyRun(
  options: VerifyRunOptions,
  deps: RunDeps = defaultRunDeps,
): Promise<RunVerification> {
  const cwd = options.cwd ?? process.cwd();
  const store = new RunStore(cwd);
  const run = store.load(options.runId);
  const runId = run.runId;

  if (!store.hasFile(runId, SNAPSHOT_MANIFEST)) {
    throw new Error(`Run ${runId} has not been applied; there is nothing to verify.`);
  }
  const plan = store.readPlan(runId);
  if (!plan) throw new Error(`Run ${runId} has no plan.`);

  const snapshot = loadSnapshot(join(store.runDir(runId), SNAPSHOT_DIR));
  const applied = new Set(
    store
      .ledger(runId)
      .read()
      .filter((event) => event.type === "item.done" && event.data["status"] === "applied")
      .map((event) => String(event.data["itemId"])),
  );
  const advisories = store.readReport(runId)?.cveDetails;

  const result = await deps.verify({
    cwd,
    ...(plan.options.packageManager
      ? { packageManager: plan.options.packageManager as VerifyRequest["packageManager"] }
      : {}),
    policy: plan.options.policy,
    baseFiles: snapshot.fileSnapshots,
    statusBefore: snapshot.isGit ? (snapshot.gitStatusBefore ?? []) : undefined,
    advisories: advisories ? [advisories] : [],
    expectedRemaining: [
      ...plan.skipped.map((skip) => skip.packageName),
      ...plan.items.filter((item) => !applied.has(item.itemId)).map((item) => item.packageName),
    ],
    options: {
      ...verifyOptionsOf(plan.options),
      allowSourceEdits: run.allowSourceEdits === true || plan.options.breakingChangeRefactor,
      // Earlier runs append to the committed track record after this run's snapshot was taken.
      ignoreTrackRecord: true,
      ...(options.offline ? { offline: true } : {}),
    },
    ...(options.checks ? { checks: options.checks } : {}),
  });

  store.writeJson(runId, "verification.json", result);
  store.ledger(runId).append("verify", {
    passed: result.passed,
    ...(result.failedCheck ? { failedCheck: result.failedCheck } : {}),
    checks: result.checks.map((check) => `${check.name}:${check.status}`),
  });
  await recordOutcomes(
    cwd,
    plan.options.policy,
    verifyEvents(run, plan, applied.size, result),
    (problem) => store.ledger(runId).append("autonomy.record-failed", { message: problem }),
  );
  await recordMemory(
    cwd,
    runId,
    passedTestCommands(result).map((command) => testCommandEntry(command)),
    (problem) => store.ledger(runId).append("memory.record-failed", { message: problem }),
  );
  return { runId, ...result };
}

/** Files an attempt keeps beside its record. */
export type AttemptArtifact = "diff" | "verification" | "transcript";

const ATTEMPT_FILES: Record<AttemptArtifact, string> = {
  diff: "diff.patch",
  verification: "verification.json",
  transcript: "transcript.jsonl",
};

/** The text of one of an attempt's artifacts, or undefined when the attempt did not produce it. */
export function readAttemptArtifact(
  query: RunQuery & { attemptId: string; artifact: AttemptArtifact },
): string | undefined {
  const store = new RunStore(query.cwd ?? process.cwd());
  const file = join(store.attemptDir(query.runId, query.attemptId), ATTEMPT_FILES[query.artifact]);
  return existsSync(file) ? readFileSync(file, "utf8") : undefined;
}
