/**
 * The search itself: confirm the good ref passes and the bad ref fails, confirm the lockfile
 * updates alone reproduce the failure, narrow them down with delta debugging, check that holding the
 * culprits back fixes it, and plan the remedy. Each phase either ends the search with a report or
 * hands on to the next.
 */
import type { Checkout, CheckoutPair, CheckoutSession } from "./checkouts.js";
import { ddmin, type DdminResult, type Verdict } from "./ddmin.js";
import { evaluate, type EvalContext } from "./evaluate.js";
import { planRemedy } from "./remedy.js";
import {
  formatCulpritSummary,
  formatVersionChanges,
  type Finisher,
  type SearchState,
} from "./report.js";
import type { LockfileSnapshot } from "./snapshot.js";
import type {
  BisectDeps,
  BisectedPackage,
  BisectOptions,
  BisectReport,
  BisectStepKind,
} from "./types.js";

export interface SearchContext {
  options: BisectOptions;
  deps: BisectDeps;
  snapshot: LockfileSnapshot;
  maxSteps: number;
  state: SearchState;
  finish: Finisher;
  evalContext: EvalContext;
}

type Attempt = (kind: BisectStepKind, subset: readonly BisectedPackage[]) => Promise<Verdict>;

export async function searchForCulprit(
  sc: SearchContext,
  session: CheckoutSession,
  trees: CheckoutPair,
): Promise<BisectReport> {
  const refsFailed = await confirmRefs(sc, session, trees);
  if (refsFailed) return refsFailed;

  const attempt = createAttempt(sc, trees.good);
  const notReproduced = await confirmAllUpdates(sc, attempt);
  if (notReproduced) return notReproduced;

  const search = await narrowDown(sc, attempt);
  recordWhyStopped(sc, search);
  const culprits = search.minimal;
  const notMinimal = reportUnfinishedSet(sc, search);
  if (notMinimal) return notMinimal;
  warnAboutUnresolved(sc, search);

  const holdingBackFixes = await confirmHoldingBack(sc, attempt, culprits);
  if (isInterrupted(sc)) {
    return incomplete(
      sc,
      `Interrupted after narrowing the failure down to ${formatVersionChanges(culprits).join("; ")}.`,
      culprits,
    );
  }
  return finishWithRemedy(sc, culprits, holdingBackFixes);
}

function isInterrupted(sc: SearchContext): boolean {
  return sc.options.signal?.aborted === true;
}

function incomplete(
  sc: SearchContext,
  summary: string,
  culprits?: BisectedPackage[],
): BisectReport {
  sc.state.stopped ??= isInterrupted(sc) ? "interrupted" : undefined;
  return sc.finish({ status: "incomplete", summary, ...(culprits ? { culprits } : {}) });
}

function evaluateAt(
  sc: SearchContext,
  tree: Checkout,
  kind: BisectStepKind,
  commit: string,
  pinned: readonly BisectedPackage[] | undefined,
) {
  return evaluate(sc.evalContext, tree, kind, commit, pinned);
}

/** The good ref must pass and the bad ref must fail. */
async function confirmRefs(
  sc: SearchContext,
  session: CheckoutSession,
  trees: CheckoutPair,
): Promise<BisectReport | undefined> {
  const { goodCommit, badCommit } = sc.snapshot;
  const good = await evaluateAt(sc, trees.good, "good-ref", goodCommit, undefined);
  if (isInterrupted(sc)) return incomplete(sc, "Interrupted before the good ref was checked.");
  if (good.verdict !== "pass") {
    return sc.finish({
      status: "not-reproducible",
      summary: `Not reproducible: the command does not pass at the good ref ${goodCommit.slice(0, 12)} (${good.step.phase}${good.step.note ? `: ${good.step.note}` : ""}), so there is nothing to bisect from.`,
    });
  }
  const bad = await evaluateAt(sc, trees.bad, "bad-ref", badCommit, undefined);
  if (isInterrupted(sc)) return incomplete(sc, "Interrupted before the bad ref was checked.");
  if (bad.verdict === "pass") {
    return sc.finish({
      status: "not-reproducible",
      summary: `Not reproducible: the command passes at the bad ref ${badCommit.slice(0, 12)} (flaky, or it depends on something outside the repository such as the network or a newer registry release).`,
    });
  }
  await session.dispose(trees.bad);
  return undefined;
}

function createAttempt(sc: SearchContext, goodTree: Checkout): Attempt {
  return async (kind, subset) => {
    sc.state.stepsUsed++;
    return (await evaluateAt(sc, goodTree, kind, sc.snapshot.goodCommit, subset)).verdict;
  };
}

/** Every update applied to the good ref must reproduce the failure. */
async function confirmAllUpdates(
  sc: SearchContext,
  attempt: Attempt,
): Promise<BisectReport | undefined> {
  const { updates, skipped, goodCommit, badCommit } = sc.snapshot;
  const all = await attempt("all-updates", updates);
  if (isInterrupted(sc)) {
    return incomplete(
      sc,
      "Interrupted while checking that the lockfile updates reproduce the failure.",
    );
  }
  if (all === "fail") return undefined;
  const last = sc.state.steps.at(-1);
  return sc.finish({
    status: "not-attributable",
    summary:
      all === "pass"
        ? `The command fails at ${badCommit.slice(0, 12)} but passes with all ${updates.length} changed package version(s) applied to ${goodCommit.slice(0, 12)}: the failure does not come from a version change of a package locked at both refs. Look at the source changes between the refs, or at the ${skipped.length} added, removed or multi-version package(s).`
        : `Could not build the bad ref's package versions on top of the good ref${last?.note ? ` (${last.note})` : ""}, so the failure could not be attributed to individual updates.`,
  });
}

function narrowDown(sc: SearchContext, attempt: Attempt): Promise<DdminResult<BisectedPackage>> {
  const { updates } = sc.snapshot;
  if (updates.length === 1) {
    return Promise.resolve({ minimal: [...updates], evaluations: 0, complete: true });
  }
  const reserved = sc.maxSteps > 2 ? 1 : 0; // a step kept for the final check
  return ddmin(
    updates,
    (item) => item.packageName,
    (subset) => attempt("subset", subset),
    {
      maxEvaluations: Math.max(sc.maxSteps - sc.state.stepsUsed - reserved, 0),
      shouldStop: () => isInterrupted(sc),
    },
  );
}

function recordWhyStopped(sc: SearchContext, search: DdminResult<BisectedPackage>): void {
  if (search.stoppedBecause === "budget") sc.state.stopped = "max-steps";
  if (search.stoppedBecause === "stopped" || isInterrupted(sc)) sc.state.stopped = "interrupted";
}

/** More than one culprit left and the search did not finish: report where it got to. */
function reportUnfinishedSet(
  sc: SearchContext,
  search: DdminResult<BisectedPackage>,
): BisectReport | undefined {
  const culprits = search.minimal;
  if (search.complete || culprits.length <= 1) return undefined;
  const { state } = sc;
  if (state.stopped === "max-steps") {
    state.warnings.push(
      `Stopped at the limit of ${sc.maxSteps} steps; raise maxSteps to narrow it further.`,
    );
  } else if (state.stopped === undefined) {
    state.warnings.push(
      "Some combinations of versions could not be installed, so the set may not be minimal.",
    );
  }
  return incomplete(
    sc,
    `Narrowed ${sc.snapshot.updates.length} updates down to ${culprits.length} that still fail (${formatVersionChanges(culprits).join("; ")}), but not to a minimal set.`,
    culprits,
  );
}

function warnAboutUnresolved(sc: SearchContext, search: DdminResult<BisectedPackage>): void {
  if (!search.complete && sc.state.stopped === undefined) {
    sc.state.warnings.push(
      "Some combinations of versions could not be installed; the culprit is certain, but other updates may also break the command.",
    );
  }
}

/** Confirm that holding the culprits back is what fixes it. */
async function confirmHoldingBack(
  sc: SearchContext,
  attempt: Attempt,
  culprits: readonly BisectedPackage[],
): Promise<boolean | undefined> {
  const { updates } = sc.snapshot;
  if (culprits.length === updates.length) return true; // the good ref itself, which passed
  if (isInterrupted(sc) || sc.state.stepsUsed >= sc.maxSteps) return undefined;

  const rest = updates.filter(
    (item) => !culprits.some((culprit) => culprit.packageName === item.packageName),
  );
  const verdict = await attempt("without-culprit", rest);
  if (verdict === "pass") return true;
  if (verdict === "fail") {
    sc.state.warnings.push(
      "The command still fails with the culprits held back: other updates also break it, or the command is flaky.",
    );
    return false;
  }
  sc.state.warnings.push("Could not check that holding the culprits back makes the command pass.");
  return undefined;
}

/** The remedy: a plan that pins the culprits back. */
async function finishWithRemedy(
  sc: SearchContext,
  culprits: BisectedPackage[],
  holdingBackFixes: boolean | undefined,
): Promise<BisectReport> {
  const { snapshot, options, deps } = sc;
  const remedy = await planRemedy({
    cwd: snapshot.cwd,
    packageManager: snapshot.manager,
    lockfile: snapshot.lockfile,
    culprits,
    goodCommit: snapshot.goodCommit,
    badCommit: snapshot.badCommit,
    command: options.command,
    apply: options.apply === true,
    ...(deps.applyPlanFn ? { applyPlanFn: deps.applyPlanFn } : {}),
  });
  return sc.finish({
    status: culprits.length === 1 ? "culprit" : "culprit-set",
    summary: formatCulpritSummary(culprits, holdingBackFixes),
    culprits,
    ...(holdingBackFixes === undefined ? {} : { holdingBackFixes }),
    remedy,
  });
}
