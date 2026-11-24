/**
 * Find which package update in the lockfile diff between a good and a bad git ref makes a command
 * fail. Runs entirely in isolated git worktrees: install the good ref and check the command passes,
 * install the bad ref and check it fails, then hold subsets of the changed packages at their bad-ref
 * versions (everything else at its good-ref version) and narrow down with delta debugging. The
 * result names the package, or the smallest set that only fails together, and a plan that pins it back.
 */
import { createCheckoutPair, detectPnpmMajor, openCheckoutSession } from "./checkouts.js";
import type { EvalContext } from "./evaluate.js";
import { validateOptions } from "./options.js";
import { createFinisher, formatNoChangesSummary, type SearchState } from "./report.js";
import { searchForCulprit } from "./search.js";
import { readLockfileSnapshot } from "./snapshot.js";
import type { BisectDeps, BisectOptions, BisectReport } from "./types.js";

export async function bisectLockfile(
  options: BisectOptions,
  deps: BisectDeps = {},
): Promise<BisectReport> {
  const started = Date.now();
  const env = deps.env ?? process.env;

  const { badRef, timeoutSeconds, maxSteps } = validateOptions(options);
  const snapshot = await readLockfileSnapshot(options, badRef);

  const state: SearchState = { steps: [], warnings: [], stepsUsed: 0, stopped: undefined };
  const finish = createFinisher({ options, badRef, snapshot, maxSteps, env, started, state });
  if (snapshot.updates.length === 0) {
    return finish({ status: "no-changes", summary: formatNoChangesSummary(snapshot) });
  }

  // Checkouts are always removed, also when interrupted.
  const session = openCheckoutSession({ top: snapshot.top, env });
  try {
    const trees = await createCheckoutPair({
      session,
      cwd: snapshot.cwd,
      name: `bisect-${process.pid}-${Date.now().toString(36)}`,
      good: { ref: options.good, commit: snapshot.goodCommit },
      bad: { ref: badRef, commit: snapshot.badCommit },
      sub: snapshot.sub,
    });
    const pnpmMajor = await detectPnpmMajor({
      manager: snapshot.manager,
      tree: trees.good,
      env,
      signal: options.signal,
    });
    const evalContext: EvalContext = {
      command: options.command,
      env,
      signal: options.signal,
      manager: snapshot.manager,
      lockfile: snapshot.lockfile,
      updates: snapshot.updates,
      steps: state.steps,
      paths: session.paths,
      timeoutSeconds,
      ignoreScripts: options.ignoreScripts !== false,
      pnpmMajor,
    };
    return await searchForCulprit(
      { options, deps, snapshot, maxSteps, state, finish, evalContext },
      session,
      trees,
    );
  } finally {
    await session.close();
  }
}
