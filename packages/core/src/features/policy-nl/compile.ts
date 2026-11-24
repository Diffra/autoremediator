import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";

import { generateText, NoObjectGeneratedError, Output, type LanguageModel } from "ai";
import { parse as yamlParse } from "yaml";

import { getModelSpec } from "../../infra/config.js";
import { loadPolicy } from "../../infra/policy/policy.js";
import type { AutoremediatorPolicy } from "../../infra/policy/policy.js";
import { isRecord } from "../../shared/guards.js";
import { sha256 } from "../../shared/hash.js";
import { renderDiff } from "../init/diff.js";
import { resolveLanguageModel } from "../patch/model.js";
import { applyPatch, PolicyPatchError } from "./apply-patch.js";
import {
  describeExplanations,
  inventedSuppressions,
  loosenRefusals,
  looseningVeto,
  parseProposal,
  quoteExplanations,
  unaccountedClauses,
  unexplainedChanges,
} from "./compile-checks.js";
import { describePolicy } from "./explain.js";
import { findLoosenings, type Loosening } from "./policy-loosening.js";
import { buildPolicyPrompt, POLICY_SYSTEM_PROMPT } from "./prompt.js";
import { policySchemas, type PolicyProposal } from "./proposal.js";
import { findPhrase, indexRequest } from "./request-match.js";
import { PolicyRequestError, sanitizeRequest } from "./sanitize.js";

export const DEFAULT_POLICY_PATH = join(".github", "autoremediator.yml");

/** What a proposer receives: the instructions, and the prompt that carries the (untrusted) request. */
export interface ProposerInput {
  system: string;
  prompt: string;
}

/**
 * Anything that turns the prompt into a proposed patch. The default calls a language model with
 * schema-constrained output; tests and embedders pass their own. Its answer is untrusted: it is
 * validated against the proposal schema again before anything uses it.
 */
export type PolicyProposer = (input: ProposerInput) => Promise<unknown>;

/** The model answered, but not in the shape the policy allows. Reported as a rejection, not a crash. */
export class ProposalRejectedError extends Error {
  override readonly name = "ProposalRejectedError";
}

/** A proposer backed by an AI SDK language model using structured output. */
export function createModelProposer(model: LanguageModel): PolicyProposer {
  return async ({ system, prompt }) => {
    try {
      const { output } = await generateText({
        model,
        output: Output.object({ schema: policySchemas().proposal }),
        system,
        prompt,
        temperature: 0,
      });
      return output;
    } catch (error) {
      if (NoObjectGeneratedError.isInstance(error)) {
        const reason = error.cause instanceof Error ? error.cause.message : error.message;
        throw new ProposalRejectedError(
          `The model's answer is not a valid policy patch: ${reason.slice(0, 600)}`,
          { cause: error },
        );
      }
      throw error;
    }
  };
}

export interface CompilePolicyOptions {
  /** Project directory (default: process.cwd()). */
  cwd?: string;
  /** Policy file to change, relative to `cwd` (default: `.github/autoremediator.yml`). Inline policy text is not accepted. */
  policy?: string;
  /** Model as `<provider>:<model-id>` (default: `AUTOREMEDIATOR_MODEL`). */
  model?: string;
  /** Write the file when the proposal is valid. Without it nothing is written. */
  apply?: boolean;
  /** Accept loosenings the request asks for. Without it any loosening rejects the proposal. */
  allowLoosening?: boolean;
  /** Use this language model instead of resolving `model`. */
  languageModel?: LanguageModel;
  /** Use this proposer instead of a model (tests, embedding). */
  proposer?: PolicyProposer;
  /** The clock for suppression expiry checks (default: now). */
  now?: Date;
}

export interface PolicyExplanation {
  phrase: string;
  keys: string[];
  /** `changes`: the proposal changes at least one of these keys. `already-in-place`: the policy already says this. */
  effect: "changes" | "already-in-place";
}

export interface PolicyCompileResult {
  /**
   * `proposed`: valid, would change the file. `unchanged`: valid, nothing to change.
   * `rejected`: refused, see `rejections` and `loosenings`. `applied`: written.
   */
  status: "proposed" | "unchanged" | "rejected" | "applied";
  /** The policy file, relative to `cwd`. */
  path: string;
  /** The request after cleaning; this is what the model saw. */
  request: string;
  changed: boolean;
  applied: boolean;
  /** Unified diff of the file; empty when nothing changes. Shown for a rejected proposal too, so a reviewer can see what was refused. */
  diff: string;
  /** The full proposed file. Present whenever a patch could be applied. */
  proposed?: string;
  /** Fingerprint of the file the proposal was made against (`absent` when there was none); a write is refused if the file has changed since. */
  base: string;
  explanations: PolicyExplanation[];
  /** Phrases that could not be expressed, from the model and from the deterministic coverage check. */
  unsupported: { phrase: string; reason: string }[];
  /** Each way the proposed policy is less safe than the current one. */
  loosenings: Loosening[];
  rejections: string[];
  warnings: string[];
  /** The proposed policy in plain sentences. */
  sentences: string[];
  model?: string;
}

const fingerprint = (text: string | undefined): string =>
  text === undefined ? "absent" : sha256(text);

/** Whether a file's line breaks are mostly CRLF (a Windows checkout), so what is written can match. */
const lf = (text: string | undefined) => text?.replaceAll("\r\n", "\n");

const usesCrlf = (text: string | undefined): boolean =>
  text !== undefined &&
  (text.match(/\r\n/g)?.length ?? 0) > (text.match(/(?<!\r)\n/g)?.length ?? 0);

/** Dotted paths whose value differs between two parsed policy files. Arrays are compared whole. */
export function changedPaths(before: unknown, after: unknown, prefix = ""): string[] {
  if (isRecord(before) && isRecord(after)) {
    const keys = [...new Set([...Object.keys(before), ...Object.keys(after)])];
    return keys.flatMap((key) =>
      changedPaths(before[key], after[key], prefix === "" ? key : `${prefix}.${key}`),
    );
  }
  return JSON.stringify(before) === JSON.stringify(after) ? [] : [prefix];
}

/** An explained key covers a change at, under, or (when a whole section is new) above it. */
function parseRaw(text: string | undefined): Record<string, unknown> {
  const parsed: unknown = text === undefined ? {} : (yamlParse(text) ?? {});
  return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed)
    ? (parsed as Record<string, unknown>)
    : {};
}

function validatedPolicy(cwd: string, text: string): AutoremediatorPolicy {
  // Validate the parsed value as inline JSON: it needs no file and is what `loadPolicy` reads anyway.
  return loadPolicy(cwd, JSON.stringify(parseRaw(text)));
}

async function resolveProposer(
  options: CompilePolicyOptions,
): Promise<{ proposer: PolicyProposer; model?: string }> {
  if (options.proposer) return { proposer: options.proposer };
  if (options.languageModel) {
    const { languageModel } = options;
    return {
      proposer: createModelProposer(languageModel),
      model: typeof languageModel === "string" ? languageModel : languageModel.modelId,
    };
  }
  const spec = getModelSpec(options.model);
  if (!spec) {
    throw new PolicyRequestError(
      'Compiling a policy needs a model: pass `model` ("<provider>:<model-id>", for example "anthropic:claude-sonnet-5-5") or set AUTOREMEDIATOR_MODEL. The provider package (@ai-sdk/<provider>) must be installed and its API key set. `policy explain` needs no model.',
    );
  }
  return { proposer: createModelProposer(await resolveLanguageModel(spec)), model: spec };
}

/**
 * Turn plain-language rules into a validated change to the policy file.
 *
 * The model only proposes a patch over an allowlist of policy keys. Everything that makes the result
 * safe is deterministic code: the patch is applied to the YAML with comments kept, the result must
 * pass the same validation as `loadPolicy`, every change must be explained by words in the request,
 * and any loosening (`findLoosenings`) is refused unless the request asks for it and `allowLoosening`
 * is set. Nothing is written without `apply`, and a rejected proposal is never written.
 */
export async function compilePolicy(
  requestText: string,
  options: CompilePolicyOptions = {},
): Promise<PolicyCompileResult> {
  const request = sanitizeRequest(requestText);
  const cwd = resolve(options.cwd ?? process.cwd());
  const { target, path } = policyTarget(cwd, options.policy);
  const now = options.now ?? new Date();

  const before = existsSync(target) ? readFileSync(target, "utf8") : undefined;
  // The current policy must be valid: a broken file is reported, never papered over.
  const oldPolicy = loadPolicy(cwd, before === undefined ? undefined : target);
  const oldRaw = parseRaw(before);

  const result = startResult({ path, request, before, oldPolicy });
  const reject = (...reasons: string[]): PolicyCompileResult => {
    result.status = "rejected";
    result.rejections.push(...reasons);
    return result;
  };

  const { proposer, model } = await resolveProposer(options);
  if (model) result.model = model;

  let answer: unknown;
  try {
    answer = await proposer({
      system: POLICY_SYSTEM_PROMPT,
      prompt: buildPolicyPrompt({
        request,
        currentPolicy: oldRaw,
        today: now.toISOString().slice(0, 10),
      }),
    });
  } catch (error) {
    if (error instanceof ProposalRejectedError) return reject(error.message);
    throw error;
  }

  const parsed = parseProposal(answer);
  if ("rejections" in parsed) return reject(...parsed.rejections);
  const { proposal, allowedKeys } = parsed;

  // A phrase the model quotes must be in the request, word for word and in order, and must be about
  // the keys it claims to explain.
  const index = indexRequest(request);
  const quoting = quoteExplanations(proposal, index, allowedKeys, result.warnings);
  if ("rejection" in quoting) return reject(quoting.rejection);
  const quotedExplanations = quoting.quoted;
  const quotedUnsupported = proposal.unsupported.filter(
    (entry) => findPhrase(index, entry.phrase).length > 0,
  );
  result.unsupported = quotedUnsupported.map(({ phrase, reason }) => ({ phrase, reason }));

  const invented = inventedSuppressions(proposal, request);
  if (invented.length > 0) {
    return reject(`The model suppresses ${invented.join(", ")}, which the request does not name.`);
  }

  const applied = proposeFile(before, proposal, cwd, now);
  if ("rejection" in applied) return reject(applied.rejection);
  const { proposed, policy } = applied;
  recordProposal(result, { proposed, before, path, policy });

  // Every change must be explained by words of the request that are about it.
  const newRaw = parseRaw(proposed);
  const changed = changedPaths(oldRaw, newRaw);
  const stray = changed.filter((changedPath) => !isAllowedPath(changedPath, allowedKeys));
  if (stray.length > 0) {
    return reject(`The change touches keys outside the allowlist: ${stray.join(", ")}.`);
  }
  // Loosening: what the proposal makes less safe, found by comparing the two policies.
  const loosenings = findLoosenings(oldPolicy, policy);
  result.loosenings = loosenings;
  const unexplained = unexplainedChanges(changed, quotedExplanations, loosenings);
  if (unexplained.length > 0) {
    return reject(
      `The model changed ${unexplained.join(", ")} without quoting the words of the request that ask for it.`,
    );
  }
  result.explanations = describeExplanations(quotedExplanations, changed);

  result.unsupported.push(...unaccountedClauses(request, quotedExplanations, quotedUnsupported));

  // A loosening must be asked for in so many words: a quoted phrase that is about that very key, says
  // so in loosening terms, and is not negated by the request ("never allow major bumps").
  const refusals = loosenRefusals(loosenings, quotedExplanations, index);
  if (refusals.length > 0) return reject(...refusals);
  if (loosenings.length > 0 && options.allowLoosening !== true) {
    return reject(...looseningVeto(loosenings));
  }

  result.status = result.changed ? "proposed" : "unchanged";
  if (!result.changed) return result;

  if (options.apply === true) writePolicyProposal(result, { cwd });
  return result;
}

/**
 * Write a proposal that `compilePolicy` returned, exactly as it was shown. Refuses a rejected or empty
 * proposal, and one whose file has changed since it was made. Used by `compilePolicy` with `apply`
 * and by the CLI after the person confirms, so a second model call can never write something they did
 * not review.
 */
export function writePolicyProposal(
  result: PolicyCompileResult,
  options: { cwd?: string } = {},
): PolicyCompileResult {
  if (result.status !== "proposed" || result.proposed === undefined) {
    throw new Error(`Only a proposed change can be written (this one is ${result.status}).`);
  }
  const target = resolve(options.cwd ?? process.cwd(), result.path);
  const current = existsSync(target) ? readFileSync(target, "utf8") : undefined;
  if (fingerprint(current) !== result.base) {
    throw new Error(`${result.path} changed since the proposal was made; run the command again.`);
  }
  mkdirSync(dirname(target), { recursive: true });
  writeFileSync(target, result.proposed, "utf8");
  result.status = "applied";
  result.applied = true;
  return result;
}

function startResult(input: {
  path: string;
  request: string;
  before: string | undefined;
  oldPolicy: AutoremediatorPolicy;
}): PolicyCompileResult {
  const { path, request, before, oldPolicy } = input;
  return {
    status: "rejected",
    path,
    request,
    base: fingerprint(before),
    changed: false,
    applied: false,
    diff: "",
    explanations: [],
    unsupported: [],
    loosenings: [],
    rejections: [],
    warnings: [],
    sentences: describePolicy(oldPolicy).map((rule) => rule.sentence),
  };
}

/** The proposed file text and the policy it loads as, or why the patch was refused. */
function proposeFile(
  before: string | undefined,
  proposal: PolicyProposal,
  cwd: string,
  now: Date,
): { proposed: string; policy: AutoremediatorPolicy } | { rejection: string } {
  try {
    const first = applyPatch(before, proposal.patch, { now });
    // The YAML library writes LF; give the file back the line endings it had.
    const proposed = usesCrlf(before) ? first.text.replaceAll(/\r?\n/g, "\r\n") : first.text;
    const policy = validatedPolicy(cwd, proposed);
    const again = applyPatch(proposed, proposal.patch, { now });
    if (again.edits !== 0) {
      return { rejection: "Applying the patch twice gives a different file, so it was refused." };
    }
    return { proposed, policy };
  } catch (error) {
    if (
      error instanceof PolicyPatchError ||
      (error instanceof Error && error.message.startsWith("Invalid policy"))
    ) {
      return { rejection: error.message };
    }
    throw error;
  }
}

function policyTarget(cwd: string, policy: string | undefined): { target: string; path: string } {
  const requested = policy?.trim() ? policy : DEFAULT_POLICY_PATH;
  if (/^(?:\{|---)/.test(requested.trim())) {
    throw new PolicyRequestError("Compiling needs a policy file path, not inline policy text.");
  }
  const target = resolve(cwd, requested);
  return { target, path: relative(cwd, target) || requested };
}

function isAllowedPath(changedPath: string, allowedKeys: readonly string[]): boolean {
  return allowedKeys.includes(changedPath.split(".")[0] ?? "");
}

/** Records the proposed text, whether it differs from the file, its diff and the policy in words. */
function recordProposal(
  result: PolicyCompileResult,
  input: {
    proposed: string;
    before: string | undefined;
    path: string;
    policy: AutoremediatorPolicy;
  },
): void {
  const { proposed, before, path, policy } = input;
  result.proposed = proposed;
  result.changed = proposed !== (before ?? "");
  // The diff is line-based, so it compares LF text whatever the file's own line endings are.
  result.diff = result.changed ? renderDiff(path, lf(before), lf(proposed) ?? "") : "";
  result.sentences = describePolicy(policy).map((rule) => rule.sentence);
}
