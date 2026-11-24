/**
 * Earned autonomy, as a pure function of a track record, the policy's settings and the time.
 *
 * Nothing here reads a file, a clock or the network: the same events, settings and `now` always
 * give the same level, with the evidence that produced it. See docs/guides/earned-autonomy.md for
 * the rules in prose.
 */
import {
  type AutonomyConfig,
  type AutonomyLevel,
  LEVEL_ALLOWS,
  levelIndex,
  levelOf,
  minLevel,
  OUTCOME_EVENT_TYPES,
  type TrackEvent,
} from "./types.js";

const DAY_MS = 24 * 60 * 60 * 1000;

/** Where a repository starts: changes arrive as pull requests that a human reviews. */
export const BASE_EARNED_LEVEL: AutonomyLevel = "L2";

export interface Requirement {
  name: string;
  required: string;
  actual: string;
  met: boolean;
}

export interface WindowStats {
  /** Outcome events of the runs inside the recent window. */
  outcomes: number;
  /** Distinct runs in the window: the last `window` runs by their latest outcome. */
  runs: number;
  verifiedRuns: number;
  /** Verified runs in which the project's tests passed as part of the verification. */
  testsCoveredRuns: number;
  /** Verified runs in which the project's type check passed as part of the verification. */
  typecheckCoveredRuns: number;
  /** Runs where some change could not be applied, without a rollback or verifier failure. */
  failedRuns: number;
  /** Runs with a rollback or a verifier failure. */
  incidentRuns: number;
  /** Runs applied with verification turned off. */
  unverifiedRuns: number;
  /** Verified runs over verified, failed and incident runs; null when there are none. */
  successRate: number | null;
}

export interface CapInfo {
  level: AutonomyLevel;
  reason: string;
  /** When the cap next loosens, if nothing else happens. */
  until: string;
  eventSeqs: number[];
  runIds: string[];
}

export interface Evaluation {
  /** The level the record has earned, after any cooldown cap. */
  earned: AutonomyLevel;
  /** The level the window alone would give, before the cooldown cap. */
  fromWindow: AutonomyLevel;
  cap?: CapInfo;
  stats: WindowStats;
  /** What each level above the base needs, with where the record stands. */
  requirements: { L3: Requirement[]; L4: Requirement[] };
  /** Why the level is what it is, most important first. */
  reasons: string[];
}

const pct = (value: number): string => `${Math.round(value * 1000) / 10}%`;
const isIncident = (event: TrackEvent): boolean =>
  event.type === "rollback" || event.type === "verifier-failure";

interface RunSummary {
  verified: boolean;
  failed: boolean;
  incident: boolean;
  unverified: boolean;
}

export function windowStats(events: readonly TrackEvent[], config: AutonomyConfig): WindowStats {
  const allOutcomes = events
    .filter((event) => OUTCOME_EVENT_TYPES.includes(event.type))
    .toSorted((a, b) => a.seq - b.seq);
  // The window counts runs, not events: a run with three items is one run. Runs are ordered by their
  // latest outcome, the last `window` of them stay, and each keeps every outcome it recorded.
  const lastSeq = new Map<string, number>();
  for (const event of allOutcomes) lastSeq.set(event.runId, event.seq);
  const recentRuns = new Set(
    [...lastSeq]
      .toSorted((a, b) => a[1] - b[1])
      .slice(-config.window)
      .map(([runId]) => runId),
  );
  const outcomes = allOutcomes.filter((event) => recentRuns.has(event.runId));

  // Coverage comes from everything the run ever recorded, including a later `verifyRun`.
  const coverage = new Map<string, { tests: boolean; typecheck: boolean }>();
  for (const event of events) {
    const seen = coverage.get(event.runId) ?? { tests: false, typecheck: false };
    coverage.set(event.runId, {
      tests: seen.tests || event.coverage.tests,
      typecheck: seen.typecheck || event.coverage.typecheck,
    });
  }

  const runs = new Map<string, RunSummary>();
  for (const event of outcomes) {
    const run = runs.get(event.runId) ?? {
      verified: false,
      failed: false,
      incident: false,
      unverified: false,
    };
    if (event.type === "applied-verified") run.verified = true;
    else if (event.type === "applied-unverified") run.unverified = true;
    else if (event.type === "apply-failed") run.failed = true;
    else if (isIncident(event)) run.incident = true;
    runs.set(event.runId, run);
  }

  let verifiedRuns = 0;
  let testsCoveredRuns = 0;
  let typecheckCoveredRuns = 0;
  let failedRuns = 0;
  let incidentRuns = 0;
  let unverifiedRuns = 0;
  for (const [runId, run] of runs) {
    if (run.incident) incidentRuns += 1;
    else if (run.failed) failedRuns += 1;
    else if (run.verified) {
      verifiedRuns += 1;
      if (coverage.get(runId)?.tests) testsCoveredRuns += 1;
      if (coverage.get(runId)?.typecheck) typecheckCoveredRuns += 1;
    } else if (run.unverified) unverifiedRuns += 1;
  }

  const judged = verifiedRuns + failedRuns + incidentRuns;
  return {
    outcomes: outcomes.length,
    runs: runs.size,
    verifiedRuns,
    testsCoveredRuns,
    typecheckCoveredRuns,
    failedRuns,
    incidentRuns,
    unverifiedRuns,
    successRate: judged === 0 ? null : verifiedRuns / judged,
  };
}

function requirementsFor(stats: WindowStats, config: AutonomyConfig): Evaluation["requirements"] {
  const noIncidents = (): Requirement => ({
    name: `no rollback or verifier failure in the last ${config.window} runs`,
    required: "0 runs",
    actual: `${stats.incidentRuns} run(s)`,
    met: stats.incidentRuns === 0,
  });
  const successRate = (): Requirement => ({
    name: "success rate of recent runs",
    required: `at least ${pct(config.minSuccessRate)}`,
    actual: stats.successRate === null ? "no runs yet" : pct(stats.successRate),
    met: stats.successRate !== null && stats.successRate >= config.minSuccessRate,
  });
  const verified = (needed: number): Requirement => ({
    name: "verified runs",
    required: `at least ${needed}`,
    actual: String(stats.verifiedRuns),
    met: stats.verifiedRuns >= needed,
  });
  const tests = (needed: number): Requirement => ({
    name: "verified runs whose tests passed",
    required: `at least ${needed}`,
    actual: String(stats.testsCoveredRuns),
    met: stats.testsCoveredRuns >= needed,
  });
  const typecheck = (needed: number): Requirement => ({
    name: "verified runs whose type check passed",
    required: `at least ${needed}`,
    actual: String(stats.typecheckCoveredRuns),
    met: stats.typecheckCoveredRuns >= needed,
  });

  const min = config.minVerifiedRuns;
  return {
    L3: [
      noIncidents(),
      verified(min),
      successRate(),
      ...(config.requireTestCoverage ? [tests(min)] : []),
    ],
    L4: [
      noIncidents(),
      verified(2 * min),
      successRate(),
      ...(config.requireTestCoverage ? [tests(2 * min), typecheck(min)] : []),
    ],
  };
}

function capFor(
  events: readonly TrackEvent[],
  config: AutonomyConfig,
  now: number,
): CapInfo | undefined {
  if (config.cooldownDays <= 0) return undefined;
  const span = config.cooldownDays * DAY_MS;
  const recent = events
    .filter((event) => isIncident(event) && now - Date.parse(event.at) < span)
    .toSorted((a, b) => a.seq - b.seq);
  const runIds = [...new Set(recent.map((event) => event.runId))];
  if (runIds.length === 0) return undefined;

  const level: AutonomyLevel = runIds.length >= 2 ? "L0" : "L1";
  const latest = recent.at(-1)!;
  // The cap loosens when the oldest of the incidents ages out of the cooldown.
  const oldest = recent.reduce((first, event) =>
    Date.parse(event.at) < Date.parse(first.at) ? event : first,
  );
  const until = new Date(Date.parse(oldest.at) + span).toISOString();
  const what = latest.type === "rollback" ? "rollback" : "verifier failure";
  return {
    level,
    until,
    eventSeqs: recent.map((event) => event.seq),
    runIds,
    reason:
      `${runIds.length} run(s) with a rollback or verifier failure in the last ${config.cooldownDays} day(s) ` +
      `(latest: ${what} on ${latest.runId}, event #${latest.seq}) cap the level at ${level} until ${until}`,
  };
}

const meets = (list: Requirement[]): boolean => list.every((requirement) => requirement.met);

/** The level a record has earned at `now`, with the evidence for it. */
export function evaluate(
  events: readonly TrackEvent[],
  config: AutonomyConfig,
  now: Date,
): Evaluation {
  const stats = windowStats(events, config);
  const requirements = requirementsFor(stats, config);

  const fromWindow: AutonomyLevel =
    (["L4", "L3"] as const).find((level) => meets(requirements[level])) ?? BASE_EARNED_LEVEL;
  const cap = capFor(events, config, now.getTime());
  const earned = cap ? minLevel(fromWindow, cap.level) : fromWindow;

  const reasons: string[] = [];
  if (cap) reasons.push(cap.reason);
  if (fromWindow === "L4" || fromWindow === "L3") {
    const list = requirements[fromWindow];
    reasons.push(
      `Met every requirement for ${fromWindow}: ${list.map((requirement) => `${requirement.name}: ${requirement.actual}`).join("; ")}`,
    );
  } else if (events.length === 0) {
    reasons.push(
      `No track record yet: a repository starts at ${BASE_EARNED_LEVEL}, where changes arrive as pull requests for review`,
    );
  } else {
    const unmet = requirements.L3.filter((requirement) => !requirement.met);
    reasons.push(
      `Held at ${BASE_EARNED_LEVEL}; L3 needs ${unmet
        .map(
          (requirement) =>
            `${requirement.name}: ${requirement.required} (now ${requirement.actual})`,
        )
        .join("; ")}`,
    );
  }

  return { earned, fromWindow, ...(cap ? { cap } : {}), stats, requirements, reasons };
}

/** The level actually in force: the ceiling the policy sets, or less if the record has earned less. */
export function effectiveLevel(evaluation: Evaluation, config: AutonomyConfig): AutonomyLevel {
  return minLevel(config.ceiling, evaluation.earned);
}

/** What the next level up needs, or why it cannot be reached. */
export interface NextPromotion {
  to: AutonomyLevel;
  /** The policy ceiling stops the level from rising to `to`. */
  blockedByCeiling: boolean;
  /** A cooldown cap, not missing evidence, is what holds the level down. */
  cappedUntil?: string;
  requirements: Requirement[];
}

export function nextPromotion(
  evaluation: Evaluation,
  config: AutonomyConfig,
): NextPromotion | undefined {
  const current = effectiveLevel(evaluation, config);
  if (current === "L4") return undefined;

  const to = levelOf(levelIndex(current) + 1);
  const blockedByCeiling = levelIndex(config.ceiling) <= levelIndex(current);
  // Up to L2 the way is the end of a cooldown; beyond it, the requirements of the next level.
  if (levelIndex(to) <= levelIndex(BASE_EARNED_LEVEL)) {
    return {
      to,
      blockedByCeiling,
      ...(evaluation.cap ? { cappedUntil: evaluation.cap.until } : {}),
      requirements: [],
    };
  }
  return {
    to,
    blockedByCeiling,
    requirements: to === "L3" ? evaluation.requirements.L3 : evaluation.requirements.L4,
  };
}

export interface LevelSignals {
  /** The result is safe for something else (a merge bot, a human with a rule) to merge unattended. */
  autoMergeEligible: boolean;
  /** A person should look at this result. */
  escalate: boolean;
  note: string;
}

export interface OutcomeFacts {
  /** The run ended `applied`: every item in the plan is in the project. */
  fullyApplied: boolean;
  /** Every applied item was accepted by the verifier. */
  allVerified: boolean;
  /** Some applied item is a major version bump. */
  anyMajorBump: boolean;
  anyFailed: boolean;
}

/**
 * What a level says about one run's result. Auto-merge is never performed here or anywhere else in
 * Autoremediator: L3 and L4 only mark a result that a merge rule is allowed to trust.
 */
export function signalsFor(level: AutonomyLevel, facts: OutcomeFacts): LevelSignals {
  const clean = facts.fullyApplied && facts.allVerified && !facts.anyFailed;
  if (levelIndex(level) < 3) {
    return {
      autoMergeEligible: false,
      escalate: false,
      note: `${level} does not allow unattended merges`,
    };
  }
  if (level === "L3") {
    const eligible = clean && !facts.anyMajorBump;
    return {
      autoMergeEligible: eligible,
      escalate: false,
      note: eligible
        ? "L3: every change was verified and none is a major bump"
        : "L3: not eligible (" +
          (clean
            ? "a major version bump needs a person"
            : "the run was not fully applied and verified") +
          ")",
    };
  }
  return {
    autoMergeEligible: clean,
    escalate: !clean || facts.anyMajorBump,
    note: fullAutonomyNote(clean, facts.anyMajorBump),
  };
}

function fullAutonomyNote(clean: boolean, anyMajorBump: boolean): string {
  if (!clean) {
    return "L4: the run was not fully applied and verified, so it is escalated to a person";
  }
  return anyMajorBump
    ? "L4: verified, but a major version bump is escalated to a person"
    : "L4: every change was verified";
}

export const allows = (level: AutonomyLevel) => LEVEL_ALLOWS[level];
