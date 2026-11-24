/**
 * The optional model pass: when deterministic signals already put a package on the list, a model
 * reads a bounded excerpt of the evidence and may add one flag. Never run without such evidence.
 */
import type { Comparison } from "./run.js";
import { lineDiff } from "./signals/code-diff.js";
import { modelFlag, type RadarModelRequest } from "./signals/model.js";
import { scoreFlags, type RadarScore } from "./signals/score.js";
import type { RadarFlag } from "./signals/types.js";
import type { RadarDeps } from "./types.js";

/** Score the flags, asking the model to add its own flag first when it is configured and useful. */
export async function scoreWithModel(
  deps: RadarDeps,
  comparison: Comparison,
  flags: RadarFlag[],
  notes: string[],
): Promise<RadarScore> {
  const scored = scoreFlags(flags);
  if (
    !deps.model ||
    scored.confidence === undefined ||
    !flags.some((flag) => flag.category === "changelog" || flag.category === "code")
  ) {
    return scored;
  }
  const request = buildRequest(comparison, flags);
  try {
    const verdict = await deps.model.classify(request);
    const release =
      comparison.diffMode === "span"
        ? `${comparison.installed}..${comparison.target}`
        : comparison.target;
    const flag = modelFlag(verdict, release);
    if (flag) flags.push(flag);
  } catch (error) {
    notes.push(
      `model classification failed (${error instanceof Error ? error.name : "error"}); deterministic signals only`,
    );
  }
  return scoreFlags(flags);
}

function buildRequest(comparison: Comparison, flags: readonly RadarFlag[]): RadarModelRequest {
  const before = comparison.packages[0]!;
  const after = comparison.packages.at(-1)!;
  return {
    packageName: comparison.name,
    from: comparison.installed,
    to: comparison.target,
    changelog: flags
      .filter((flag) => flag.category === "changelog")
      .slice(0, 6)
      .map((flag) => flag.evidence),
    codeChanges: [
      ...new Set(
        flags
          .filter((flag) => flag.category === "code")
          .map((flag) => flag.location.slice(0, Math.max(0, flag.location.lastIndexOf(":")))),
      ),
    ]
      .slice(0, 3)
      .map((file) => {
        const changes = lineDiff(before.files.get(file) ?? "", after.files.get(file) ?? "");
        return { file, added: changes.added.slice(0, 12), removed: changes.removed.slice(0, 12) };
      })
      .filter((change) => change.added.length + change.removed.length > 0),
  };
}
