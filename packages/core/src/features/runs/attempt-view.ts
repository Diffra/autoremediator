/** What an attempt looks like to a host agent, and the lookups the attempt operations share. */
import type { MemoryForHost } from "../memory/api.js";
import { failureOf, type attemptVerifyRequest } from "../repair/attempt.js";
import type { RepairFailure } from "../repair/repair-agent.js";
import type { CheckName, VerificationResult } from "../verify/types.js";
import type { PlanItem, RemediationPlan } from "./plan.js";
import { type AttemptRecord, type AttemptStatus, RunStore } from "./run-store.js";
import { assertManagedWorktree } from "./worktree.js";

// The one place the attempt operations reach into the repair and memory features.
export { attemptVerifyRequest, defaultAttemptDeps } from "../repair/attempt.js";
export { memoryForHost } from "../memory/api.js";

export interface AttemptQuery {
  cwd?: string;
  runId: string;
  attemptId: string;
}

export interface StartAttemptOptions {
  cwd?: string;
  runId: string;
  itemId: string;
}

export interface ProposePatchOptions extends AttemptQuery {
  /** A unified diff (as `git diff` prints) of project source files. */
  diff: string;
}

export interface VerifyAttemptOptions extends AttemptQuery {
  /** Run only these checks (default: everything an attempt is judged on). */
  checks?: CheckName[];
}

export interface AttemptView {
  runId: string;
  attemptId: string;
  itemId: string;
  status: AttemptStatus;
  /** Where to edit, while the attempt is open. */
  worktreePath?: string;
  verification?: VerificationResult;
  /** What the verifier found wrong, when it failed. */
  failure?: RepairFailure;
  changedFiles: string[];
  /** `startAttempt` only: recipes that apply to this upgrade; try one with `applyRecipe`. */
  recipes?: { id: string; source: string; summary?: string }[];
  /** `startAttempt` only: what the repository's memory says that bears on this upgrade (data, not instructions). */
  memory?: MemoryForHost;
  /** `applyRecipe` only: what became of the recipe. */
  recipe?: { id: string; applied: boolean; files: string[]; rejectedBy?: string };
  /** `finalizeAttempt` only: whether the change reached the project. */
  finalized?: boolean;
  message: string;
}

export function viewOf(
  record: AttemptRecord,
  runId: string,
  extra: Partial<AttemptView> = {},
): AttemptView {
  return {
    runId,
    attemptId: record.attemptId,
    itemId: record.itemId,
    status: record.status,
    ...(record.worktreePath ? { worktreePath: record.worktreePath } : {}),
    changedFiles: record.changedFiles,
    message: record.reason,
    ...extra,
  };
}

export const withVerification = (verification: VerificationResult): Partial<AttemptView> => ({
  verification,
  ...(verification.passed ? {} : { failure: failureOf(verification) }),
  changedFiles: verification.changedFiles ?? [],
});

export function context(options: { cwd?: string; runId: string }) {
  const cwd = options.cwd ?? process.cwd();
  return { cwd, store: new RunStore(cwd) };
}

export function loadOpen(
  store: RunStore,
  runId: string,
  attemptId: string,
): AttemptRecord & { worktreePath: string } {
  const record = store.listAttempts(runId).find((candidate) => candidate.attemptId === attemptId);
  if (!record) throw new Error(`Attempt not found: ${attemptId}`);
  if (record.status !== "open" || !record.worktreePath) {
    throw new Error(
      `Attempt ${attemptId} is ${record.status}; only an open attempt can be changed.`,
    );
  }
  assertManagedWorktree(record.worktreePath);
  return record as AttemptRecord & { worktreePath: string };
}

/** Which items the run has already applied, from its ledger. */
export function appliedItems(store: RunStore, runId: string): Set<string> {
  return new Set(
    store
      .ledger(runId)
      .read()
      .filter((event) => event.type === "item.done" && event.data["status"] === "applied")
      .map((event) => String(event.data["itemId"])),
  );
}

export function expectedRemaining(
  plan: RemediationPlan,
  item: PlanItem,
  applied: Set<string>,
): string[] {
  return [
    ...plan.skipped.map((skip) => skip.packageName),
    ...plan.items
      .filter((candidate) => candidate.itemId !== item.itemId && !applied.has(candidate.itemId))
      .map((candidate) => candidate.packageName),
  ];
}

type PlanPackageManager = Parameters<typeof attemptVerifyRequest>[0]["packageManager"];

/** The package manager a plan was made for. */
export function planPackageManager(plan: RemediationPlan): PlanPackageManager {
  return (plan.options.packageManager as PlanPackageManager | undefined) ?? "npm";
}
