/** Builds the bisect report and the sentences in it. */
import { sanitizeOutput } from "./shell.js";
import type { LockfileSnapshot } from "./snapshot.js";
import type {
  BisectedPackage,
  BisectOptions,
  BisectReport,
  BisectStatus,
  BisectStep,
} from "./types.js";

/** What changes while the search runs. */
export interface SearchState {
  steps: BisectStep[];
  warnings: string[];
  /** Candidate states evaluated, not counting the good and bad refs. */
  stepsUsed: number;
  stopped: BisectReport["stopped"];
}

export interface ReportPartial {
  status: BisectStatus;
  summary: string;
  culprits?: BisectedPackage[];
  holdingBackFixes?: boolean;
  remedy?: BisectReport["remedy"];
}

export type Finisher = (partial: ReportPartial) => BisectReport;

export function createFinisher(input: {
  options: BisectOptions;
  badRef: string;
  snapshot: LockfileSnapshot;
  maxSteps: number;
  env: NodeJS.ProcessEnv;
  started: number;
  state: SearchState;
}): Finisher {
  const { options, badRef, snapshot, maxSteps, env, started, state } = input;
  const startedAt = new Date(started).toISOString();
  return (partial) => ({
    schemaVersion: "1",
    status: partial.status,
    summary: partial.summary,
    good: { ref: options.good, commit: snapshot.goodCommit },
    bad: { ref: badRef, commit: snapshot.badCommit },
    packageManager: snapshot.manager,
    lockfile: snapshot.lockfile,
    command: sanitizeOutput(options.command, { env, maxChars: 4000 }),
    updates: snapshot.updates,
    skipped: snapshot.skipped,
    culprits: partial.culprits ?? [],
    ...(partial.holdingBackFixes === undefined
      ? {}
      : { holdingBackFixes: partial.holdingBackFixes }),
    steps: state.steps,
    stepsUsed: state.stepsUsed,
    maxSteps,
    ...(state.stopped ? { stopped: state.stopped } : {}),
    ...(partial.remedy ? { remedy: partial.remedy } : {}),
    warnings: state.warnings,
    startedAt,
    durationMs: Date.now() - started,
  });
}

export function formatNoChangesSummary(snapshot: LockfileSnapshot): string {
  const { skipped, goodCommit, badCommit, lockfile } = snapshot;
  const skippedNote =
    skipped.length > 0
      ? ` ${skipped.length} other locked package(s) were added or removed or have several versions and cannot be tried one at a time.`
      : "";
  return `No package has a different locked version between ${goodCommit.slice(0, 12)} and ${badCommit.slice(0, 12)} in ${lockfile}.${skippedNote}`;
}

export function formatUpdate(item: BisectedPackage): string {
  return `${item.packageName} ${item.fromVersion} -> ${item.toVersion} (${item.dependencyScope})`;
}

export function formatVersionChanges(culprits: readonly BisectedPackage[]): string[] {
  return culprits.map((item) => `${item.packageName} ${item.fromVersion} -> ${item.toVersion}`);
}

export function formatCulpritSummary(
  culprits: readonly BisectedPackage[],
  holdingBackFixes: boolean | undefined,
): string {
  const [first] = culprits;
  if (culprits.length === 1 && first) {
    return `${formatUpdate(first)} breaks the command. Holding it at ${first.fromVersion} ${holdingBackFixes ? "makes it pass" : "is not enough on its own"}.`;
  }
  return `These ${culprits.length} updates break the command only together: ${culprits.map((item) => formatUpdate(item)).join("; ")}.`;
}
