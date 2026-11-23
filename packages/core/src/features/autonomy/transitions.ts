/**
 * Replays a track record into the promotions and demotions it caused. Pure, like `compute.ts`.
 */
import { evaluate, BASE_EARNED_LEVEL, type Evaluation } from "./compute.js";
import { levelIndex, type AutonomyConfig, type AutonomyLevel, type TrackEvent } from "./types.js";

export interface Transition {
  at: string;
  /** The event that caused it; absent for a change caused by time passing alone. */
  eventSeq?: number;
  from: AutonomyLevel;
  to: AutonomyLevel;
  direction: "promotion" | "demotion";
  cause: "event" | "cooldown";
  reason: string;
  runIds: string[];
  eventSeqs: number[];
}

/**
 * Every promotion and demotion, replayed from the first event: each cites the event that caused it,
 * or says it came from a cooldown ending. `now` closes the replay, so a cooldown that ended since
 * the last event is shown too.
 */
export function transitionsOf(
  events: readonly TrackEvent[],
  config: AutonomyConfig,
  now: Date,
): Transition[] {
  const ordered = events.toSorted((a, b) => a.seq - b.seq);
  const out: Transition[] = [];
  let level: AutonomyLevel = BASE_EARNED_LEVEL;

  const push = (transition: Omit<Transition, "direction">) => {
    out.push({
      ...transition,
      direction: levelIndex(transition.to) > levelIndex(transition.from) ? "promotion" : "demotion",
    });
  };

  let previous = evaluate([], config, new Date(0));
  for (const [index, event] of ordered.entries()) {
    const at = new Date(event.at);
    const prior = ordered.slice(0, index);
    // Time passing since the last event can already have ended a cooldown.
    const quiet = evaluate(prior, config, at);
    if (quiet.earned !== level) {
      push({
        at: event.at,
        from: level,
        to: quiet.earned,
        cause: "cooldown",
        ...describeTransition(previous, quiet, "cooldown", config),
      });
      level = quiet.earned;
      previous = quiet;
    }
    const after = evaluate([...prior, event], config, at);
    if (after.earned !== level) {
      push({
        at: event.at,
        eventSeq: event.seq,
        from: level,
        to: after.earned,
        cause: "event",
        ...describeTransition(quiet, after, "event", config),
      });
      level = after.earned;
    }
    previous = after;
  }

  const final = evaluate(ordered, config, now);
  if (final.earned !== level) {
    push({
      at: now.toISOString(),
      from: level,
      to: final.earned,
      cause: "cooldown",
      ...describeTransition(previous, final, "cooldown", config),
    });
  }
  return out;
}

function describeTransition(
  before: Evaluation,
  after: Evaluation,
  cause: "event" | "cooldown",
  config: AutonomyConfig,
) {
  const from = before.earned;
  const to = after.earned;
  if (levelIndex(to) < levelIndex(from)) {
    if (after.cap && (!before.cap || levelIndex(after.cap.level) < levelIndex(before.cap.level))) {
      return {
        reason: after.cap.reason,
        runIds: after.cap.runIds,
        eventSeqs: after.cap.eventSeqs,
      };
    }
    const lost = from === "L4" ? after.requirements.L4 : after.requirements.L3;
    const unmet = lost.filter((requirement) => !requirement.met);
    return {
      reason: `No longer meets ${from}: ${unmet.map((requirement) => `${requirement.name}: ${requirement.required} (now ${requirement.actual})`).join("; ")}`,
      runIds: [] as string[],
      eventSeqs: [] as number[],
    };
  }
  if (cause === "cooldown" && before.cap) {
    return {
      reason: `The ${before.cap.level} cap ended: no rollback or verifier failure within ${config.cooldownDays} day(s)`,
      runIds: before.cap.runIds,
      eventSeqs: before.cap.eventSeqs,
    };
  }
  const gained = to === "L4" ? after.requirements.L4 : after.requirements.L3;
  return {
    reason: `Met every requirement for ${to}: ${gained.map((requirement) => `${requirement.name}: ${requirement.actual}`).join("; ")}`,
    runIds: [],
    eventSeqs: [],
  };
}
