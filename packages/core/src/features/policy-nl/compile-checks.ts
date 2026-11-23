/**
 * The deterministic checks `compilePolicy` puts between a model's proposal and the policy file:
 * the proposal's shape, whether the words it quotes are in the request, and whether a loosening was
 * asked for. None of them trusts the model.
 */
import type { PolicyExplanation } from "./compile.js";
import type { Loosening } from "./policy-loosening.js";
import { policySchemas, type PolicyProposal } from "./proposal.js";
import { clausesOf, findPhrase, isNegated, tokensOf, type indexRequest } from "./request-match.js";
import { hasVocabulary, mentionsKey } from "./vocabulary.js";

/** Whether `key` and `path` name the same setting, or one holds the other (`sla` and `sla.high`). */
export const covers = (key: string, path: string): boolean =>
  path === key || path.startsWith(`${key}.`) || key.startsWith(`${path}.`);

export interface QuotedExplanation {
  phrase: string;
  keys: string[];
}

type RequestIndex = ReturnType<typeof indexRequest>;

/** The proposal if it fits the schema, otherwise why not. */
export function parseProposal(
  answer: unknown,
): { proposal: PolicyProposal; allowedKeys: readonly string[] } | { rejections: string[] } {
  const { proposal: proposalSchema, keys: allowedKeys } = policySchemas();
  const parsed = proposalSchema.safeParse(answer);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((issue) => {
      const where = issue.path.length > 0 ? issue.path.join(".") : "(root)";
      return issue.code === "unrecognized_keys"
        ? `${where}: key(s) outside the allowlist: ${issue.keys.join(", ")}`
        : `${where}: ${issue.message}`;
    });
    return {
      rejections: [
        `The model's answer is not a valid policy patch (allowed keys: ${allowedKeys.join(", ")}).`,
        ...issues,
      ],
    };
  }
  return { proposal: parsed.data, allowedKeys };
}

/**
 * A phrase the model quotes must be in the request, word for word and in order, and must be about
 * the keys it claims to explain. Phrases that are not are dropped with a warning.
 */
export function quoteExplanations(
  proposal: PolicyProposal,
  index: RequestIndex,
  allowedKeys: readonly string[],
  warnings: string[],
): { quoted: QuotedExplanation[] } | { rejection: string } {
  const quoted: QuotedExplanation[] = [];
  for (const entry of proposal.explanations) {
    for (const key of entry.keys) {
      if (!allowedKeys.includes(key.split(".")[0] ?? "") || !hasVocabulary(key)) {
        return { rejection: `The model explains a key outside the allowlist: "${key}".` };
      }
    }
    if (findPhrase(index, entry.phrase).length === 0) {
      warnings.push(
        `Ignored an explanation quoting words that are not in the request, in that order: "${entry.phrase.slice(0, 80)}".`,
      );
      continue;
    }
    const keys = entry.keys.filter((key) => mentionsKey(key, "related", entry.phrase));
    const unrelated = entry.keys.filter((key) => !keys.includes(key));
    if (unrelated.length > 0) {
      warnings.push(
        `Ignored "${entry.phrase.slice(0, 80)}" as the explanation for ${unrelated.join(", ")}: the words say nothing about it.`,
      );
    }
    if (keys.length > 0) quoted.push({ phrase: entry.phrase, keys });
  }
  return { quoted };
}

/** Request clauses the model neither expressed nor reported as unsupported, so they are never dropped silently. */
export function unaccountedClauses(
  request: string,
  quotedExplanations: QuotedExplanation[],
  quotedUnsupported: { phrase: string }[],
): { phrase: string; reason: string }[] {
  const unsupported: { phrase: string; reason: string }[] = [];
  const mentioned = new Set(
    [
      ...quotedExplanations.map((entry) => entry.phrase),
      ...quotedUnsupported.map((entry) => entry.phrase),
    ].flatMap((phrase) => tokensOf(phrase)),
  );
  for (const clause of clausesOf(request)) {
    const tokens = tokensOf(clause);
    const hit = tokens.filter((token) => mentioned.has(token)).length;
    if (hit / tokens.length < 0.7) {
      unsupported.push({
        phrase: clause,
        reason:
          "The model's answer does not account for these words, so nothing was changed for them.",
      });
    }
  }
  return unsupported;
}

/**
 * A loosening must be asked for in so many words: a quoted phrase that is about that very key, says
 * so in loosening terms, and is not negated by the request ("never allow major bumps").
 */
export function loosenRefusals(
  loosenings: Loosening[],
  quotedExplanations: QuotedExplanation[],
  index: RequestIndex,
): string[] {
  const refusals: string[] = [];
  for (const entry of loosenings) {
    const asking = quotedExplanations.filter(
      (explanation) =>
        explanation.keys.some((key) => covers(key, entry.key)) &&
        mentionsKey(entry.key, "loosen", explanation.phrase),
    );
    if (asking.length === 0) {
      refusals.push(
        `Refused: ${entry.description} (${entry.key}) The request does not ask for it.`,
      );
      continue;
    }
    const positive = asking.some((explanation) =>
      findPhrase(index, explanation.phrase).some(
        (start) => !isNegated(index, start, tokensOf(explanation.phrase).length),
      ),
    );
    if (!positive) {
      refusals.push(
        `Refused: ${entry.description} (${entry.key}) The request says the opposite: "${asking[0]?.phrase.slice(0, 80)}" is negated there.`,
      );
    }
  }
  return refusals;
}

/** CVE and GHSA ids as they appear in running text (lower-cased). */
const ADVISORY_ID_IN_TEXT =
  /(?<![\w-])(?:cve-\d{4}-\d{4,}|ghsa(?:-[23456789cfghjmpqrvwx]{4}){3})(?![\w-])/g;

/** Suppressed advisories the request does not name: a suppression is never one the model chose. */
export function inventedSuppressions(proposal: PolicyProposal, request: string): string[] {
  const requestIds = new Set(request.toLowerCase().match(ADVISORY_ID_IN_TEXT) ?? []);
  return (proposal.patch.suppressions ?? [])
    .map((entry) => entry.cveId)
    .filter((id) => !requestIds.has(id.toLowerCase()));
}

/** Changed settings no quoted phrase of the request accounts for (a loosening is refused on its own). */
export function unexplainedChanges(
  changed: string[],
  quoted: QuotedExplanation[],
  loosenings: Loosening[],
): string[] {
  return changed.filter(
    (changedPath) =>
      !quoted.some((entry) => entry.keys.some((key) => covers(key, changedPath))) &&
      // A loosening is refused with its own reason.
      !loosenings.some((entry) => covers(entry.key, changedPath)),
  );
}

/** Each quoted phrase with whether it changed something or the policy already said it. */
export function describeExplanations(
  quoted: QuotedExplanation[],
  changed: string[],
): PolicyExplanation[] {
  return quoted.map((entry) => ({
    phrase: entry.phrase,
    keys: entry.keys,
    effect: changed.some((changedPath) => entry.keys.some((key) => covers(key, changedPath)))
      ? "changes"
      : "already-in-place",
  }));
}

/** Why a proposal that loosens the policy is held back until the caller allows it. */
export function looseningVeto(loosenings: Loosening[]): string[] {
  return [
    `The proposal makes the policy less safe in ${loosenings.length} way(s); review them and run again with allowLoosening (--allow-loosening) if you mean it.`,
    ...loosenings.map((entry) => `${entry.key}: ${entry.description}`),
  ];
}
