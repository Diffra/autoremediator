/**
 * Evaluates one candidate state: reset a checkout to a commit, hold a set of packages at their
 * bad-ref versions, install, check the lockfile, run the command, and record what happened as a step.
 */
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import { resolveInstallCommand } from "../../infra/package-manager/index.js";
import { errorMessage } from "../../shared/errors.js";
import { LONG_RUNNING_TIMEOUT_MS } from "../../shared/timeouts.js";
import type { PackageManager } from "../../shared/types.js";
import type { Verdict } from "./ddmin.js";
import { applyPins, checkLockedVersions } from "./pins.js";
import { git } from "./refs.js";
import { runProcess, sanitizeOutput, type ProcessResult } from "./shell.js";
import type { BisectCommandRecord, BisectedPackage, BisectStep, BisectStepKind } from "./types.js";

/** Everything an evaluation needs besides the state to try. */
export interface EvalContext {
  command: string;
  env: NodeJS.ProcessEnv;
  signal: AbortSignal | undefined;
  manager: PackageManager;
  lockfile: string;
  /** Every package whose version differs between the refs. */
  updates: readonly BisectedPackage[];
  /** The steps recorded so far; each evaluation appends one. */
  steps: BisectStep[];
  /** Absolute checkout roots and their labels, so output does not show local paths. */
  paths: Array<[string, string]>;
  timeoutSeconds: number;
  ignoreScripts: boolean;
  pnpmMajor: number | undefined;
}

export interface EvaluatedStep {
  step: BisectStep;
  verdict: Verdict;
}

export interface EvalTree {
  path: string;
  root: string;
}

type StepExtra = Partial<BisectStep>;
type Done = (
  outcome: BisectStep["outcome"],
  phase: BisectStep["phase"],
  outputTail: string,
  extra?: StepExtra,
) => EvaluatedStep;

export function updatedNames(subset: readonly BisectedPackage[]): string[] {
  return subset.map((item) => item.packageName);
}

/**
 * Install and run the command in a checkout. `pinned` is the set of packages to hold at their bad-ref
 * version on top of the good ref; `undefined` means the checkout is installed exactly as committed.
 */
export async function evaluate(
  ctx: EvalContext,
  tree: EvalTree,
  kind: BisectStepKind,
  commit: string,
  pinned: readonly BisectedPackage[] | undefined,
): Promise<EvaluatedStep> {
  const done = createRecorder(ctx, kind, pinned);

  const notReset = await resetCheckout(ctx, tree, commit, done);
  if (notReset) return notReset;

  if (pinned) {
    const notPinned = writePins(ctx, tree, pinned, done);
    if (notPinned) return notPinned;
  }

  const frozen = pinned === undefined;
  const install = await installPackages(ctx, tree, frozen, done);
  if (install.ended) return install.ended;

  if (pinned) {
    const notHonoured = checkPins(ctx, tree, pinned, install.record, done);
    if (notHonoured) return notHonoured;
  }

  return runCommand(ctx, tree, install.record, done);
}

function createRecorder(
  ctx: EvalContext,
  kind: BisectStepKind,
  pinned: readonly BisectedPackage[] | undefined,
): Done {
  const base = {
    step: ctx.steps.length + 1,
    kind,
    updated: updatedFor(ctx, kind, pinned),
  };
  return (outcome, phase, outputTail, extra = {}) => {
    const step: BisectStep = { ...base, outcome, phase, outputTail, ...extra };
    ctx.steps.push(step);
    return { step, verdict: outcome };
  };
}

function updatedFor(
  ctx: EvalContext,
  kind: BisectStepKind,
  pinned: readonly BisectedPackage[] | undefined,
): string[] {
  if (pinned) return updatedNames(pinned);
  if (kind === "bad-ref") return updatedNames(ctx.updates);
  return [];
}

function tail(ctx: EvalContext, text: string, max: number): string {
  return sanitizeOutput(text, { env: ctx.env, paths: ctx.paths, maxChars: max });
}

function recordOf(ctx: EvalContext, display: string, result: ProcessResult): BisectCommandRecord {
  return {
    command: sanitizeOutput(display, { env: ctx.env, paths: ctx.paths, maxChars: 4000 }),
    exitCode: result.exitCode,
    durationMs: result.durationMs,
    timedOut: result.timedOut,
  };
}

/** A fresh copy of the commit: no leftovers from the previous state, no installed packages. */
async function resetCheckout(
  ctx: EvalContext,
  tree: EvalTree,
  commit: string,
  done: Done,
): Promise<EvaluatedStep | undefined> {
  const reset = await git(tree.root, ["reset", "--hard", "--quiet", commit]);
  const clean = await git(tree.root, ["clean", "-fdxq"]);
  if (reset.ok && clean.ok) return undefined;
  return done("unresolved", "install", tail(ctx, reset.stderr + clean.stderr, 600), {
    note: "could not reset the checkout",
  });
}

function writePins(
  ctx: EvalContext,
  tree: EvalTree,
  pinned: readonly BisectedPackage[],
  done: Done,
): EvaluatedStep | undefined {
  try {
    applyPins(
      {
        dir: tree.path,
        packageManager: ctx.manager,
        ...(ctx.pnpmMajor === undefined ? {} : { pnpmMajor: ctx.pnpmMajor }),
      },
      pinned.map((item) => ({ packageName: item.packageName, version: item.toVersion })),
    );
    return undefined;
  } catch (error) {
    return done("unresolved", "pins", "", {
      note: `could not write the pins: ${errorMessage(error)}`,
    });
  }
}

type InstallOutcome =
  | { ended: EvaluatedStep; record?: undefined }
  | { ended?: undefined; record: BisectCommandRecord };

async function installPackages(
  ctx: EvalContext,
  tree: EvalTree,
  frozen: boolean,
  done: Done,
): Promise<InstallOutcome> {
  const argv = installArgv(ctx.manager, frozen, ctx.ignoreScripts);
  const timeoutMs = Math.max(LONG_RUNNING_TIMEOUT_MS, Math.round(ctx.timeoutSeconds * 1000));
  const install = await runProcess({
    argv,
    cwd: tree.path,
    env: ctx.env,
    timeoutMs,
    signal: ctx.signal,
  });
  const record = recordOf(ctx, argv.join(" "), install);
  if (install.aborted) {
    const ended = done("unresolved", "install", tail(ctx, install.output, 600), {
      install: record,
      note: "interrupted",
    });
    return { ended };
  }
  if (install.exitCode !== 0) {
    // An install that fails in a state taken from a commit is a broken build. In a combination
    // we made up it only says the combination cannot be installed.
    const ended = done(frozen ? "fail" : "unresolved", "install", tail(ctx, install.output, 1500), {
      install: record,
      note: installFailureNote(install.timedOut, frozen),
    });
    return { ended };
  }
  return { record };
}

function installFailureNote(timedOut: boolean, frozen: boolean): string {
  if (timedOut) return "install timed out";
  if (frozen) return "install failed";
  return "install failed in this combination of versions";
}

function installArgv(manager: PackageManager, frozen: boolean, ignoreScripts: boolean): string[] {
  const argv = resolveInstallCommand(
    manager,
    {
      installMode: "standard",
      enforceFrozenLockfile: frozen,
      installScripts: ignoreScripts ? "none" : "all",
    },
    1,
  );
  if (manager === "npm") argv.push("--no-audit", "--no-fund");
  return argv;
}

/** The install must have written the requested versions, or the state is not the one we meant. */
function checkPins(
  ctx: EvalContext,
  tree: EvalTree,
  pinned: readonly BisectedPackage[],
  installRecord: BisectCommandRecord,
  done: Done,
): EvaluatedStep | undefined {
  const lockPath = join(tree.path, ctx.lockfile);
  const content = existsSync(lockPath) ? readFileSync(lockPath, "utf8") : undefined;
  if (content === undefined) {
    return done("unresolved", "pins", "", {
      install: installRecord,
      note: `the install did not write ${ctx.lockfile}, so the versions cannot be checked`,
    });
  }
  const mismatches = checkLockedVersions(
    ctx.lockfile,
    content,
    ctx.updates,
    new Set(updatedNames(pinned)),
  );
  if (mismatches.length === 0) return undefined;
  const shown = mismatches
    .slice(0, 3)
    .map(
      (item) =>
        `${item.packageName} should be ${item.expected} but the lockfile has ${item.found.join(", ") || "nothing"}`,
    )
    .join("; ");
  return done("unresolved", "pins", "", {
    install: installRecord,
    note: `the package manager did not install the requested versions (${shown}${mismatches.length > 3 ? `; and ${mismatches.length - 3} more` : ""})`,
  });
}

async function runCommand(
  ctx: EvalContext,
  tree: EvalTree,
  installRecord: BisectCommandRecord,
  done: Done,
): Promise<EvaluatedStep> {
  const run = await runProcess({
    shell: ctx.command,
    cwd: tree.path,
    env: ctx.env,
    timeoutMs: Math.round(ctx.timeoutSeconds * 1000),
    signal: ctx.signal,
  });
  const runRecord = recordOf(ctx, ctx.command, run);
  if (run.aborted) {
    return done("unresolved", "command", tail(ctx, run.output, 600), {
      install: installRecord,
      run: runRecord,
      note: "interrupted",
    });
  }
  const passed = run.exitCode === 0;
  return done(passed ? "pass" : "fail", "command", tail(ctx, run.output, passed ? 400 : 1500), {
    install: installRecord,
    run: runRecord,
    ...(run.timedOut
      ? { note: `the command was killed after ${ctx.timeoutSeconds}s and counts as failing` }
      : {}),
  });
}
