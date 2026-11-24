/** Validation of the options a caller passes to the bisect, before anything touches git. */
import { checkRef } from "./refs.js";
import type { BisectOptions } from "./types.js";

export const DEFAULT_COMMAND_TIMEOUT_SECONDS = 600;
export const DEFAULT_MAX_STEPS = 30;

/** The options with their defaults filled in. */
export interface ValidatedOptions {
  badRef: string;
  timeoutSeconds: number;
  maxSteps: number;
}

export function validateOptions(options: BisectOptions): ValidatedOptions {
  checkRef("good", options.good);
  const badRef = options.bad?.trim() || "HEAD";
  checkRef("bad", badRef);
  if (!options.command?.trim()) {
    throw new Error("command is required: the shell command that fails at the bad ref.");
  }
  const timeoutSeconds = options.timeoutSeconds ?? DEFAULT_COMMAND_TIMEOUT_SECONDS;
  const maxSteps = options.maxSteps ?? DEFAULT_MAX_STEPS;
  if (!(timeoutSeconds > 0)) throw new Error("timeoutSeconds must be greater than zero.");
  if (!Number.isInteger(maxSteps) || maxSteps < 1) {
    throw new Error("maxSteps must be a whole number of at least 1.");
  }
  if (options.packageManager && !["npm", "pnpm", "yarn"].includes(options.packageManager)) {
    throw new Error(
      `bisect supports npm, pnpm and yarn (classic) lockfiles; ${options.packageManager} is not supported.`,
    );
  }
  return { badRef, timeoutSeconds, maxSteps };
}
