/** The steps of applying one plan item: repair a broken upgrade, verify it, or reject it. */
import { getModelSpec } from "../../infra/config.js";
import {
  restoreProjectSnapshot,
  type createProjectSnapshot,
} from "../../infra/rollback/rollback.js";
import { errorMessage } from "../../shared/errors.js";
import { resolveLanguageModel } from "../patch/model.js";
import { createBuiltinRepairAgent } from "../repair/builtin-agent.js";
import { DEFAULT_REPAIR_BUDGET, type RepairAgent } from "../repair/repair-agent.js";
import type { VerificationResult, VerifyRequest } from "../verify/types.js";
import type { RunDeps } from "./deps.js";
import { fingerprintRepo } from "./fingerprint.js";
import type { ApplyPlanOptions, ItemOutcome } from "./index.js";
import type { PlanItem, RemediationPlan } from "./plan.js";
import { repairItem } from "./repair.js";
import type { RunStore } from "./run-store.js";
import { verifyOptionsOf } from "./verify-run.js";

/** Failures of the project's own checks after an upgrade: the ones an agent can do something about. */
export const REPAIRABLE = new Set(["validation-failed", "breaking-change-unresolved"]);

/**
 * The agent to use for repairs, or undefined when repair is off. Asking for repair explicitly
 * without anything to repair with is an error; a model that merely happens to be configured but
 * cannot be loaded only disables repair, and the run says so.
 */
export async function resolveRepairAgent(
  options: ApplyPlanOptions,
  note: (message: string) => void,
): Promise<RepairAgent | undefined> {
  if (options.repair === false) return undefined;
  if (options.repairAgent) return options.repairAgent;

  const spec = getModelSpec(options.model);
  if (!spec) {
    if (options.repair === true) {
      throw new Error(
        'Repair needs a model: pass `model` ("<provider>:<model-id>") or set AUTOREMEDIATOR_MODEL.',
      );
    }
    return undefined;
  }
  try {
    return createBuiltinRepairAgent(await resolveLanguageModel(spec));
  } catch (error) {
    if (options.repair === true) throw error;
    note(`repair unavailable: ${errorMessage(error)}`);
    return undefined;
  }
}

export function outcomeOf(
  item: PlanItem,
  status: ItemOutcome["status"],
  message: string,
  unresolvedReason?: string,
): ItemOutcome {
  return {
    itemId: item.itemId,
    packageName: item.packageName,
    fromVersion: item.fromVersion,
    toVersion: item.toVersion,
    strategy: item.strategy,
    status,
    message,
    ...(unresolvedReason ? { unresolvedReason } : {}),
  };
}

/** Everything the steps of one apply share. */
export interface ApplyContext {
  cwd: string;
  store: RunStore;
  runId: string;
  options: ApplyPlanOptions;
  deps: RunDeps;
  plan: RemediationPlan;
  agent: RepairAgent | undefined;
  advisories: NonNullable<ReturnType<RunStore["readReport"]>>["cveDetails"] | undefined;
  /** Items the run has applied so far, including by earlier steps of the same run. */
  applied: Set<string>;
}

/** The names of packages the plan leaves alone, or has not reached yet, apart from `item`. */
export function expectedRemainingFor(context: ApplyContext, item: PlanItem): string[] {
  const { plan, applied } = context;
  return [
    ...plan.skipped.map((skip) => skip.packageName),
    ...plan.items
      .filter((candidate) => candidate.itemId !== item.itemId && !applied.has(candidate.itemId))
      .map((candidate) => candidate.packageName),
  ];
}

interface RepairedItem {
  ok: boolean;
  message: string;
  verification?: VerificationResult;
  repair: NonNullable<ItemOutcome["repair"]>;
}

/** The upgrade works for the dependency but breaks the project: ask an agent (or a recipe) to adapt it. */
export async function repairBrokenItem(
  context: ApplyContext,
  item: PlanItem,
  message: string,
): Promise<RepairedItem> {
  const { cwd, store, runId, options, deps, plan, agent, advisories } = context;
  const repaired = await repairItem(
    {
      cwd,
      store,
      runId,
      item,
      plan,
      advisories: advisories ? [advisories] : [],
      expectedRemaining: expectedRemainingFor(context, item),
      agent,
      budget: { ...DEFAULT_REPAIR_BUDGET, ...options.repairBudget },
      signal: options.signal ?? new AbortController().signal,
    },
    {
      attempt: deps.attempt,
      promote: {
        verify: deps.verify,
        reinstall: () => deps.reinstall({ cwd, options: plan.options }),
      },
    },
  );
  const repair = {
    attemptId: repaired.attemptId,
    status: repaired.status,
    rounds: repaired.rounds,
    reason: repaired.message,
  };
  if (repaired.status !== "promoted") {
    return {
      ok: false,
      repair,
      message: `${message} An agent repair was tried and not accepted (${repaired.status}): ${repaired.message}`,
    };
  }
  store.update(runId, { allowSourceEdits: true });
  const by = repaired.agentId.startsWith("recipe:") ? "a recipe" : "an agent";
  return {
    ok: true,
    repair,
    verification: repaired.verification,
    message: `Upgraded ${item.packageName} to ${item.toVersion} and repaired the project with ${by}: ${repaired.message}`,
  };
}

/** What the item's own change must still satisfy, judged by the verifier. */
export function verifyItem(
  context: ApplyContext,
  item: PlanItem,
  before: Awaited<ReturnType<typeof createProjectSnapshot>>,
): Promise<VerificationResult> {
  const { plan, advisories, deps } = context;
  return deps.verify({
    cwd: context.cwd,
    ...(plan.options.packageManager
      ? { packageManager: plan.options.packageManager as VerifyRequest["packageManager"] }
      : {}),
    policy: plan.options.policy,
    baseFiles: before.fileSnapshots,
    statusBefore: before.isGit ? (before.gitStatusBefore ?? []) : undefined,
    advisories: advisories ? [advisories] : [],
    expectedRemaining: expectedRemainingFor(context, item),
    options: {
      ...verifyOptionsOf(plan.options),
      allowSourceEdits: plan.options.breakingChangeRefactor,
    },
    checks: ["scope", "policy", "supply-chain", "vuln-gone"],
  });
}

/** The verifier disposes: whatever the tool reported, a change it rejects is put back. */
export async function rejectItem(
  context: ApplyContext,
  item: PlanItem,
  before: Awaited<ReturnType<typeof createProjectSnapshot>>,
  verification: VerificationResult,
): Promise<ItemOutcome> {
  const { cwd, store, runId, deps, plan } = context;
  const failed = verification.checks.find((check) => check.name === verification.failedCheck);
  const message = `Verification failed (${verification.failedCheck}): ${failed?.message ?? "see details"}`;
  await restoreProjectSnapshot(before);
  const reinstallNote = await deps
    .reinstall({ cwd, options: plan.options })
    .then(() => undefined)
    .catch((error: unknown) => errorMessage(error));
  store.ledger(runId).append("item.rejected", {
    itemId: item.itemId,
    message,
    failedCheck: verification.failedCheck,
    details: failed?.details ?? [],
    ...(reinstallNote ? { reinstallNote } : {}),
  });
  store.update(runId, { after: await fingerprintRepo(cwd, plan.options.policy) });
  return { ...outcomeOf(item, "failed", message), verification };
}
