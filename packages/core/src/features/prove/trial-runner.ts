/** Runs a reproduction agent's trials one at a time and keeps the first one the harness accepts. */
import { sha256 } from "../../shared/hash.js";
import type { createHarness } from "./harness.js";
import type { TrialResult, TrialSummary } from "./types.js";

export function createTrialRunner(
  harness: ReturnType<typeof createHarness>,
  maxTrials: number,
): {
  trials: TrialSummary[];
  keep: { value?: { script: string; result: TrialResult } };
  trial: (script: string) => Promise<TrialResult>;
} {
  const trials: TrialSummary[] = [];
  const keep: { value?: { script: string; result: TrialResult } } = {};
  const exclusive = serialize<TrialResult>();
  const trial = (script: string): Promise<TrialResult> =>
    exclusive(async () => {
      if (keep.value) return keep.value.result;
      if (trials.length >= maxTrials) {
        return {
          accepted: false,
          stage: "screen",
          scriptSha256: sha256(script),
          reason: "No tries are left; the script was not run.",
        };
      }
      const result = await harness.prove(script);
      trials.push({
        attempt: trials.length + 1,
        accepted: result.accepted,
        stage: result.stage,
        reason: result.reason,
        scriptSha256: result.scriptSha256,
      });
      if (result.accepted) keep.value = { script, result };
      return result;
    });
  return { trials, keep, trial };
}

/** Run trials one at a time: they share the two directories. */
function serialize<T>(): (task: () => Promise<T>) => Promise<T> {
  let tail: Promise<unknown> = Promise.resolve();
  return (task) => {
    const next = tail.then(task, task);
    tail = next.catch(() => undefined);
    return next;
  };
}
