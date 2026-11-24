/**
 * Silent-fix radar: for each dependency, compare the installed version with a newer one and flag
 * releases in between that look security-relevant, so the upgrade can happen before an advisory
 * exists. Signals are computed locally from the changelog, the code diff between the published
 * tarballs and registry metadata; an optional model adds a bounded classification. Every flag
 * carries its evidence. Radar never says a vulnerability exists: it reports a security-relevant
 * change without a published advisory, and cross-checks OSV for one.
 */
import semver from "semver";

import { errorMessage } from "../../shared/errors.js";
import { resolveLanguageModel } from "../patch/model.js";
import { analyse } from "./analyse.js";
import { ByteBudgetExceeded, createByteBudget, createDefaultRadarDeps } from "./deps.js";
import { resolveLimits, type RadarLimits } from "./options.js";
import { runPool, withTimeout } from "./pool.js";
import type { Outcome, Run } from "./run.js";
import { createLlmRadarClassifier } from "./signals/model.js";
import { sanitizeEvidence } from "./signals/sanitize.js";
import {
  CATEGORY_CAPS,
  CONFIDENCE_THRESHOLDS,
  RADAR_POINTS,
  SCORING_RULE,
  type RadarConfidence,
} from "./signals/types.js";
import type {
  InstalledPackage,
  RadarDeps,
  RadarEntry,
  RadarOptions,
  RadarReport,
} from "./types.js";

export const RADAR_DISCLAIMER =
  "Radar reports security-relevant changes without a published advisory. It does not say that any vulnerability exists: " +
  "signals are heuristics read from changelog text, code differences and registry metadata, and each flag quotes its evidence " +
  "(untrusted text from the package) for a person to judge.";

const MAX_ASSESSED = 5;

const CONFIDENCE_RANK: Record<RadarConfidence, number> = { likely: 0, possible: 1, weak: 2 };
const STATUS_RANK: Record<RadarEntry["status"], number> = {
  silent: 0,
  unchecked: 1,
  "now-advisory": 2,
};

/**
 * Look for security-relevant changes, without a published advisory, in the releases between what the
 * project has installed and a newer version. Read-only: downloads metadata and tarballs, changes
 * nothing. See `docs/guides/silent-fix-radar.md`.
 */
export async function radar(
  options: RadarOptions = {},
  overrides: Partial<RadarDeps> = {},
): Promise<RadarReport> {
  if (options.offline) {
    throw new Error(
      "radar reads the npm registry and cannot run offline. Drop --offline, or use `incident` or `remediate` with a snapshot.",
    );
  }
  const limits = resolveLimits(options);
  const { cwd, target, maxBytes } = limits;

  const deps: RadarDeps = { ...createDefaultRadarDeps(), ...overrides };
  if (options.model && !deps.model) {
    deps.model = createLlmRadarClassifier(await resolveLanguageModel(options.model));
  }

  const installed = listCandidates(deps, cwd, options);
  const selected = installed.slice(0, limits.maxPackages);

  const run: Run = {
    cwd,
    deps,
    budget: createByteBudget(maxBytes),
    options: { target, github: options.github === true, assess: options.assess !== false },
    assessRemaining: { count: MAX_ASSESSED },
    notes: new Set(),
  };

  const outcomes = await runPool(selected, limits.concurrency, async (item): Promise<Outcome> => {
    try {
      return await withTimeout(
        analyse(run, item),
        limits.timeoutMs,
        `${item.name}@${item.version}`,
      );
    } catch (error) {
      const reason =
        error instanceof ByteBudgetExceeded
          ? "download budget spent"
          : sanitizeEvidence(errorMessage(error), 160);
      return { kind: "skipped", skipped: { name: item.name, version: item.version, reason } };
    }
  });

  const entries = outcomes
    .flatMap((outcome) => (outcome.kind === "entry" ? [outcome.entry] : []))
    .toSorted(rank);
  const skipped = outcomes.flatMap((outcome) =>
    outcome.kind === "skipped" ? [outcome.skipped] : [],
  );

  return {
    schemaVersion: "1.0",
    disclaimer: RADAR_DISCLAIMER,
    target,
    includeTransitive: options.includeTransitive === true,
    analysed: outcomes.filter((outcome) => outcome.kind === "entry" || outcome.kind === "clean")
      .length,
    upToDate: outcomes.filter((outcome) => outcome.kind === "up-to-date").length,
    clean: outcomes.filter((outcome) => outcome.kind === "clean").length,
    flagged: entries.length,
    entries: entries.slice(0, limits.limit),
    skipped,
    notes: reportNotes(run, options, limits, installed, selected.length),
    bytesDownloaded: run.budget.used,
    ...(options.model || overrides.model
      ? {
          model: {
            used: deps.model !== undefined,
            ...(options.model ? { spec: options.model } : {}),
          },
        }
      : {}),
    scoring: {
      points: RADAR_POINTS,
      caps: CATEGORY_CAPS,
      thresholds: { ...CONFIDENCE_THRESHOLDS },
      rule: SCORING_RULE,
    },
  };
}

/** Direct dependencies (and transitive ones when asked for), direct first, then by name. */
function listCandidates(deps: RadarDeps, cwd: string, options: RadarOptions): InstalledPackage[] {
  return deps
    .listInstalled(cwd)
    .filter((entry) => options.includeTransitive === true || entry.direct)
    .toSorted(
      (a, b) =>
        Number(b.direct) - Number(a.direct) ||
        a.name.localeCompare(b.name) ||
        semver.compare(a.version, b.version),
    );
}

/** Run-level notes: what the packages reported, then why the report may be incomplete. */
function reportNotes(
  run: Run,
  options: RadarOptions,
  limits: RadarLimits,
  installed: readonly InstalledPackage[],
  selectedCount: number,
): string[] {
  const installedCount = installed.length;
  const notes = [...run.notes];
  if (installedCount > selectedCount) {
    notes.push(
      `${installedCount - selectedCount} package(s) beyond maxPackages (${limits.maxPackages}) were not analysed`,
    );
  }
  if (
    options.includeTransitive &&
    installedCount > 0 &&
    !installed.some((entry) => !entry.direct)
  ) {
    notes.push(
      "No transitive packages were found: reading them needs a lockfile at the project root.",
    );
  }
  if (installedCount === 0) {
    notes.push(
      options.includeTransitive
        ? "No installed packages were found: commit a lockfile or install dependencies."
        : "No direct dependencies were found: commit a lockfile or install dependencies.",
    );
  }
  if (run.budget.used >= run.budget.limit) {
    notes.push(
      `The download budget (${limits.maxBytes} bytes) was spent; some packages were skipped. Raise maxBytes to read them.`,
    );
  }
  return notes;
}

/** Rank: no-advisory first, then by confidence, score, name. */
function rank(left: RadarEntry, right: RadarEntry): number {
  return (
    STATUS_RANK[left.status] - STATUS_RANK[right.status] ||
    CONFIDENCE_RANK[left.confidence] - CONFIDENCE_RANK[right.confidence] ||
    right.score - left.score ||
    left.name.localeCompare(right.name) ||
    semver.compare(left.installed, right.installed)
  );
}
