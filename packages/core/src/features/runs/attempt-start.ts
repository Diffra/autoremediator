/** Opens an attempt for one plan item: an isolated checkout with the upgrade applied. */
import { rmSync } from "node:fs";
import { join } from "node:path";

import { createProjectSnapshot } from "../../infra/rollback/rollback.js";
import { memoryForHost } from "../memory/api.js";
import type { RecipeEntry } from "../recipes/discover.js";
import { attemptVerifyRequest, defaultAttemptDeps } from "../repair/attempt.js";
import type { VerificationResult } from "../verify/types.js";
import {
  type AttemptView,
  appliedItems,
  context,
  expectedRemaining,
  planPackageManager,
  type StartAttemptOptions,
  viewOf,
  withVerification,
} from "./attempt-view.js";
import { defaultRunDeps, type RunDeps } from "./deps.js";
import { fingerprintRepo, sameInputs } from "./fingerprint.js";
import { newAttemptId } from "./ids.js";
import type { PlanItem, RemediationPlan } from "./plan.js";
import { APPLICABLE_STATUSES } from "./repair.js";
import type { AttemptRecord, RunRecord, RunStore } from "./run-store.js";
import { saveSnapshot } from "./snapshot-store.js";

const MAX_OPEN_ATTEMPTS = 4;

function recipeSuggestion(entry: RecipeEntry): { id: string; source: string; summary?: string } {
  const suggestion: { id: string; source: string; summary?: string } = {
    id: entry.id,
    source: entry.source.kind === "project" ? "project" : entry.source.package,
  };
  if (entry.recipe.summary) suggestion.summary = entry.recipe.summary;
  return suggestion;
}

/** The run, plan and item an attempt may start from, or why it may not start. */
async function assertCanStart(
  cwd: string,
  store: RunStore,
  options: StartAttemptOptions,
): Promise<{ run: RunRecord; plan: RemediationPlan; item: PlanItem; applied: Set<string> }> {
  const run = store.load(options.runId);
  if (!APPLICABLE_STATUSES.has(run.status)) {
    throw new Error(`Run ${run.runId} is ${run.status}; there is nothing left to attempt.`);
  }
  const plan = store.readPlan(run.runId);
  const item = plan?.items.find((candidate) => candidate.itemId === options.itemId);
  if (!plan || !item) throw new Error(`Run ${run.runId} has no plan item ${options.itemId}.`);

  const applied = appliedItems(store, run.runId);
  if (applied.has(item.itemId)) throw new Error(`Item ${item.itemId} is already applied.`);
  const open = store.listAttempts(run.runId).filter((attempt) => attempt.status === "open");
  if (open.length >= MAX_OPEN_ATTEMPTS) {
    throw new Error(
      `Run ${run.runId} has ${open.length} open attempts; abandon or finalize one first.`,
    );
  }
  if (!sameInputs(await fingerprintRepo(cwd, plan.options.policy), run.after ?? run.base)) {
    throw new Error(`The project changed since run ${run.runId}'s plan or last step. Plan again.`);
  }
  return { run, plan, item, applied };
}

/** What earlier repairs learned: the host can try one of these before spending effort of its own. */
function suggestRecipes(
  cwd: string,
  checkout: string,
  item: PlanItem,
  plan: RemediationPlan,
  findRecipes: NonNullable<RunDeps["attemptDeps"]>["findRecipes"],
): NonNullable<AttemptView["recipes"]> {
  try {
    return findRecipes({
      projectDir: cwd,
      installRoot: checkout,
      packageName: item.packageName,
      fromVersion: item.fromVersion,
      toVersion: item.toVersion,
      ...(plan.options.policy ? { policy: plan.options.policy } : {}),
    }).recipes.map((entry) => recipeSuggestion(entry));
  } catch {
    // Recipes are an optional extra; a broken policy shows up in the verifier's findings anyway.
    return [];
  }
}

/**
 * Open an attempt for one plan item: an isolated checkout of the project with the upgrade applied
 * and installed, and the verifier's findings on it. The project itself is not touched.
 */
export async function startAttempt(
  options: StartAttemptOptions,
  deps: RunDeps = defaultRunDeps,
): Promise<AttemptView> {
  const { cwd, store } = context(options);
  const { run, plan, item, applied } = await assertCanStart(cwd, store, options);

  const ad = deps.attemptDeps ?? defaultAttemptDeps;
  const attemptId = newAttemptId();
  const attemptDir = store.attemptDir(run.runId, attemptId);
  const checkout = await ad.createWorktree(cwd, attemptId);

  let verification: VerificationResult;
  try {
    const before = await createProjectSnapshot(checkout.path);
    saveSnapshot(join(attemptDir, "before"), before);
    const upgraded = await ad.applyUpgrade(item, checkout.path, plan.options);
    if (!upgraded.applied) {
      throw new Error(`the upgrade could not be applied in a clean checkout: ${upgraded.message}`);
    }
    const details = store.readReport(run.runId)?.cveDetails;
    verification = await ad.verify(
      attemptVerifyRequest({
        checkout: checkout.path,
        packageManager: planPackageManager(plan),
        options: plan.options,
        before,
        advisories: details ? [details] : [],
        expectedRemaining: expectedRemaining(plan, item, applied),
      }),
    );
  } catch (error) {
    await checkout.remove();
    rmSync(attemptDir, { recursive: true, force: true });
    throw error;
  }

  const recipes = verification.passed
    ? []
    : suggestRecipes(cwd, checkout.path, item, plan, ad.findRecipes);
  const now = new Date().toISOString();
  const record: AttemptRecord = {
    attemptId,
    itemId: item.itemId,
    agentId: "host",
    status: "open",
    reason: verification.passed
      ? "The upgrade works as it is; finalize it."
      : `The upgrade breaks the project (${verification.failedCheck}). Fix it in the checkout, then verify.`,
    rounds: 0,
    changedFiles: verification.changedFiles ?? [],
    worktreePath: checkout.path,
    startedAt: now,
    endedAt: now,
  };
  store.writeAttempt(run.runId, record, {
    "verification.json": `${JSON.stringify(verification, null, 2)}\n`,
  });
  store
    .ledger(run.runId)
    .append("attempt.start", { attemptId, itemId: item.itemId, agent: "host" });
  const memory = memoryForHost(cwd, item.packageName);
  return viewOf(record, run.runId, {
    ...withVerification(verification),
    ...(memory.entries.length > 0 || memory.problem ? { memory } : {}),
    ...(recipes.length > 0
      ? {
          recipes,
          message: `${record.reason} ${recipes.length} recipe(s) apply to this upgrade: try applyRecipe before editing.`,
        }
      : {}),
  });
}
