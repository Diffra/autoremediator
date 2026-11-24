/** What changed between two versions of one callable: parameter counts, parameter and return types. */
import type { ApiChangeCategory, ChangeSeverity } from "./api-diff.js";
import type { Signature } from "./dts-surface.js";

function arityOf(signature: Signature): { min: number; max: number } {
  const hasRest = signature.params.some((param) => param.rest);
  const min = signature.params.filter((param) => !param.optional && !param.rest).length;
  return { min, max: hasRest ? Number.POSITIVE_INFINITY : signature.params.length };
}

function describeArity(arity: { min: number; max: number }): string {
  if (arity.max === Number.POSITIVE_INFINITY) {
    return `${arity.min}+`;
  }
  return arity.min === arity.max ? `${arity.min}` : `${arity.min}-${arity.max}`;
}

export interface SignatureFinding {
  category: ApiChangeCategory;
  severity: ChangeSeverity;
  reason: string;
  before?: string;
  after?: string;
  arity?: { min: number; max: number };
}

/** The finding for a changed parameter count, if the count changed in a way that matters. */
function arityFinding(before: Signature, after: Signature, typed: boolean): SignatureFinding[] {
  const oldArity = arityOf(before);
  const newArity = arityOf(after);
  // Without types a parameter count is only a hint: a JavaScript function may ignore extra
  // arguments or default a missing one.
  const severity: ChangeSeverity = typed ? "breaking" : "possibly-breaking";
  const base = { category: "signature-changed" as const, severity, before: before.text };
  if (newArity.min > oldArity.min) {
    const plural = newArity.min === 1 ? "" : "s";
    return [
      {
        ...base,
        reason: `now requires at least ${newArity.min} argument${plural} (was ${oldArity.min})`,
        after: after.text,
        arity: newArity,
      },
    ];
  }
  if (newArity.max < oldArity.max) {
    const plural = newArity.max === 1 ? "" : "s";
    const was = oldArity.max === Number.POSITIVE_INFINITY ? "any number" : oldArity.max;
    return [
      {
        ...base,
        reason: `now accepts at most ${describeArity({ min: newArity.max, max: newArity.max })} argument${plural} (was ${was})`,
        after: after.text,
        arity: newArity,
      },
    ];
  }
  return [];
}

/** Findings for parameters that became required or changed type, in position order. */
function parameterFindings(
  before: Signature,
  after: Signature,
  arityReported: boolean,
): SignatureFinding[] {
  const findings: SignatureFinding[] = [];
  const typeChanges: string[] = [];
  let reported = arityReported;
  const shared = Math.min(before.params.length, after.params.length);
  for (let index = 0; index < shared; index++) {
    const oldParam = before.params[index];
    const newParam = after.params[index];
    if (!oldParam || !newParam) continue;
    if (
      oldParam.type !== undefined &&
      newParam.type !== undefined &&
      oldParam.type !== newParam.type
    ) {
      typeChanges.push(`\`${newParam.name}\`: ${oldParam.type} -> ${newParam.type}`);
    }
    // One finding says it: the new call shape already covers every parameter that became required.
    if (oldParam.optional && !newParam.optional && !reported) {
      reported = true;
      findings.push({
        category: "signature-changed",
        severity: "breaking",
        reason: `parameter \`${newParam.name}\` is no longer optional`,
        before: before.text,
        after: after.text,
        arity: arityOf(after),
      });
    }
  }
  if (typeChanges.length > 0) {
    findings.push({
      category: "type-changed",
      severity: "possibly-breaking",
      reason: `parameter type changed (${typeChanges.slice(0, 3).join("; ")}); it may be a widening`,
      before: before.text,
      after: after.text,
    });
  }
  return findings;
}

/** Findings for a changed return type or type parameter list. */
function typeLevelFindings(before: Signature, after: Signature): SignatureFinding[] {
  const findings: SignatureFinding[] = [];
  const base = {
    category: "type-changed" as const,
    severity: "possibly-breaking" as const,
    before: before.text,
    after: after.text,
  };
  if (
    before.returns !== after.returns &&
    before.returns !== undefined &&
    after.returns !== undefined
  ) {
    findings.push({
      ...base,
      reason: `return type changed (${before.returns} -> ${after.returns})`,
    });
  }
  if ((before.typeParams ?? "") !== (after.typeParams ?? "")) {
    findings.push({
      ...base,
      reason: `type parameters changed (${before.typeParams ?? "none"} -> ${after.typeParams ?? "none"})`,
    });
  }
  return findings;
}

function comparePair(before: Signature, after: Signature, typed: boolean): SignatureFinding[] {
  const findings = arityFinding(before, after, typed);
  if (!typed) return findings;
  findings.push(...parameterFindings(before, after, findings.length > 0));
  findings.push(...typeLevelFindings(before, after));
  return findings;
}

/** Findings for one callable whose set of overload signatures changed. */
export function compareSignatures(
  before: Signature[],
  after: Signature[],
  typed: boolean,
): SignatureFinding[] {
  if (before.length === 0 || after.length === 0) return [];
  const afterTexts = new Set(after.map((signature) => signature.text));
  const beforeTexts = new Set(before.map((signature) => signature.text));
  const removed = before.filter((signature) => !afterTexts.has(signature.text));
  const added = after.filter((signature) => !beforeTexts.has(signature.text));
  if (removed.length === 0) return [];
  const [onlyRemoved] = removed;
  const [onlyAdded] = added;
  if (removed.length === 1 && added.length === 1 && onlyRemoved && onlyAdded) {
    return comparePair(onlyRemoved, onlyAdded, typed);
  }
  if (added.length === 0) {
    return [
      {
        category: "signature-changed",
        severity: "breaking",
        reason: `${removed.length === 1 ? "an overload was" : `${removed.length} overloads were`} removed`,
        before: removed.map((signature) => signature.text).join(" | "),
        after: after.map((signature) => signature.text).join(" | "),
      },
    ];
  }
  return [
    {
      category: "signature-changed",
      severity: "possibly-breaking",
      reason: "overloads changed",
      before: removed.map((signature) => signature.text).join(" | "),
      after: added.map((signature) => signature.text).join(" | "),
    },
  ];
}
