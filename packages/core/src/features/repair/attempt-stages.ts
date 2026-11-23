/** The steps of one repair attempt: recipes first, then rounds with the agent. */
import { resolveTypecheckCommand } from "../../infra/package-manager/index.js";
import { errorMessage } from "../../shared/errors.js";
import type { PackageManager } from "../../shared/types.js";
import { renderMemoryForAgent } from "../memory/consume.js";
import { proposeMemory } from "../memory/propose.js";
import { resolveProjectTestCommand } from "../memory/test-command.js";
import type { LlmUsageMetrics } from "../remediate/types.js";
import type { VerificationResult } from "../verify/types.js";
import type { AttemptDeps, AttemptRequest, AttemptResult, AttemptStatus } from "./attempt.js";
import { type FoundRecipes, tryRecipes } from "./recipe-attempt.js";
import type {
  RepairCommands,
  RepairFailure,
  RepairOutcome,
  TranscriptEntry,
} from "./repair-agent.js";

export interface Session {
  request: AttemptRequest;
  deps: AttemptDeps;
  checkoutPath: string;
  packageManager: PackageManager;
  usage: LlmUsageMetrics[];
  transcript: TranscriptEntry[];
  base: Pick<
    AttemptResult,
    "agentId" | "usage" | "transcript" | "changedFiles" | "diff" | "initialFailure"
  >;
  fail: (
    status: AttemptStatus,
    reason: string,
    rounds: number,
    verification?: VerificationResult,
  ) => AttemptResult;
  judge: () => Promise<VerificationResult>;
  memory: string | undefined;
}

/** What the repository remembers, read once and shown to the agent as data. */
export function loadAgentMemory(
  request: AttemptRequest,
  transcript: TranscriptEntry[],
): string | undefined {
  // What the repository remembers, read once and shown to the agent as data.
  try {
    return renderMemoryForAgent(request.cwd, request.item.packageName);
  } catch (error) {
    transcript.push({
      step: 0,
      text: `memory is unreadable and was not shown to the agent: ${errorMessage(error)}`,
    });
  }
  return undefined;
}

/**
 * Recipes first: what an earlier repair learned costs no tokens, and the verifier still decides.
 * Returns the finished result when a recipe fixed it or nothing else can try; undefined hands over
 * to the agent.
 */
export async function recipeStage(
  session: Session,
  verification: VerificationResult,
): Promise<AttemptResult | undefined> {
  const { request, deps, checkoutPath, transcript, base, fail, judge } = session;
  const { agent, item, options } = request;
  base.initialFailure = failureOf(verification);

  let found: FoundRecipes;
  try {
    found = deps.findRecipes({
      projectDir: request.cwd,
      installRoot: checkoutPath,
      packageName: item.packageName,
      fromVersion: item.fromVersion,
      toVersion: item.toVersion,
      ...(options.policy ? { policy: options.policy } : {}),
    });
  } catch (error) {
    found = { recipes: [], problems: [{ file: "(recipes)", error: errorMessage(error) }] };
  }
  for (const problem of found.problems) {
    transcript.push({ step: 0, text: `recipe ${problem.file}: unusable: ${problem.error}` });
  }
  let trial: Awaited<ReturnType<typeof tryRecipes>>;
  try {
    trial = await tryRecipes({ checkout: checkoutPath, recipes: found.recipes, judge });
  } catch (error) {
    return fail("failed", errorMessage(error), 0, verification);
  }
  transcript.push(...trial.transcript);
  if (trial.fixed) {
    return {
      ...base,
      agentId: `recipe:${trial.fixed.entry.id}`,
      status: "verified",
      reason: `recipe ${trial.fixed.entry.id} made the project work (${trial.fixed.files.join(", ")}); no model was asked`,
      rounds: 0,
      diff: await deps.diff(checkoutPath),
      verification: trial.fixed.verification,
      changedFiles: trial.fixed.verification.changedFiles ?? [],
    };
  }
  if (!agent) {
    return fail(
      "rejected",
      found.recipes.length > 0
        ? `no recipe made the project work (${found.recipes.length} tried) and no repair agent is configured`
        : "no recipe applies and no repair agent is configured (set a model to have one try)",
      0,
      verification,
    );
  }
  return undefined;
}

/**
 * Asks the agent to fix what the verifier found, and has the verifier judge each submission, until
 * it passes or a limit is reached. Returns the finished result when the attempt ends early.
 */
export async function repairRounds(
  session: Session,
  initial: VerificationResult,
  previousRounds: string[],
): Promise<AttemptResult | { verification: VerificationResult; rounds: number }> {
  const { request, checkoutPath, packageManager, usage, transcript, fail, judge, memory } = session;
  const { agent, budget, item, options } = request;
  let verification = initial;
  let rounds = 0;
  while (!verification.passed && rounds < budget.maxRepairRounds) {
    if (!agent) break; // unreachable: without an agent the block above has already returned
    if (request.signal.aborted) {
      return fail("rejected", "the attempt was cancelled", rounds, verification);
    }
    const spent = sum(usage, "inputTokens") + sum(usage, "outputTokens");
    if (budget.maxTotalTokens !== undefined && spent >= budget.maxTotalTokens) {
      return fail("rejected", "the token budget was used up", rounds, verification);
    }

    rounds += 1;
    let outcome: RepairOutcome;
    try {
      outcome = await agent.repair(
        {
          runId: request.runId,
          attemptId: request.attemptId,
          cveId: item.cveId,
          packageName: item.packageName,
          fromVersion: item.fromVersion,
          toVersion: item.toVersion,
          round: rounds,
          failure: failureOf(verification),
          previousRounds: [...previousRounds],
          ...(memory ? { memory } : {}),
        },
        {
          worktree: checkoutPath,
          budget: {
            ...budget,
            ...(budget.maxTotalTokens === undefined
              ? {}
              : { maxTotalTokens: budget.maxTotalTokens - spent }),
          },
          signal: request.signal,
          commands: commandsFor(checkoutPath, options, packageManager),
          proposeMemory: (proposal) =>
            proposeMemory(request.cwd, proposal, {
              runId: request.runId,
              attemptId: request.attemptId,
            }),
        },
      );
    } catch (error) {
      return fail("failed", `the agent failed: ${errorMessage(error)}`, rounds, verification);
    }
    usage.push(...outcome.usage);
    transcript.push(...outcome.transcript);

    if (outcome.status !== "submitted") {
      return fail(
        "rejected",
        `the agent ${outcome.status === "gave-up" ? "gave up" : "ran out of budget"}: ${outcome.rationale}`,
        rounds,
        verification,
      );
    }
    previousRounds.push(outcome.rationale);
    verification = await judge();
  }

  return { verification, rounds };
}

/** The result skeleton every outcome of an attempt shares, and the helper that fills it in. */
export function startAttempt(
  request: AttemptRequest,
  usage: LlmUsageMetrics[],
  transcript: TranscriptEntry[],
): { base: Session["base"]; fail: Session["fail"] } {
  const { agent } = request;
  const base: Session["base"] = {
    agentId: agent?.id ?? "recipes",
    usage,
    transcript,
    changedFiles: [] as string[],
    diff: "",
  };
  const fail = (
    status: AttemptStatus,
    reason: string,
    rounds: number,
    verification?: VerificationResult,
  ): AttemptResult => ({
    ...base,
    status,
    reason,
    rounds,
    ...(verification ? { verification } : {}),
  });
  return { base, fail };
}

const sum = (usage: readonly LlmUsageMetrics[], key: "inputTokens" | "outputTokens") =>
  usage.reduce((total, entry) => total + (entry[key] ?? 0), 0);

/** The project's own commands an agent may run in a checkout. */
export function commandsFor(
  checkout: string,
  options: AttemptRequest["options"],
  packageManager: PackageManager,
): RepairCommands {
  const typecheck = resolveTypecheckCommand(packageManager, options.constraints, checkout);
  return {
    ...(typecheck.length > 0 ? { typecheck } : {}),
    tests: resolveProjectTestCommand(packageManager, options.constraints, checkout),
  };
}

/** The verifier's findings, in terms an agent (or a host) can act on. */
export function failureOf(result: VerificationResult): RepairFailure {
  const failed = result.checks.find((check) => check.name === result.failedCheck);
  return {
    failedCheck: result.failedCheck ?? "unknown",
    summary: result.checks.map((check) => `${check.name}: ${check.status} (${check.message})`),
    details: failed?.details ?? [],
  };
}
