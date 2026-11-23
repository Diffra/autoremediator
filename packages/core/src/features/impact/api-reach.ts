/**
 * Which of the project's call sites a changed export or member reaches, and how sure that is.
 * Split from `impact.ts` because it is the one place that knows how each kind of API change
 * (export, call signature, constructor, static or instance member) maps onto usage.
 */
import type { ApiChange } from "./api-diff.js";
import type { FindingEvidence } from "./findings.js";
import type { CallSite } from "./types.js";
import { sitesForExport, sitesForStaticMember, type UsageIndex } from "./usage-index.js";

export interface Intersection {
  sites: CallSite[];
  evidence: FindingEvidence;
  /** Every project call was compatible with the new signature. */
  compatible?: boolean;
}

type Arity = NonNullable<ApiChange["arity"]>;

/** The sites that pass a number of arguments the new signature does not accept. */
function outsideArity(sites: CallSite[], { min, max }: Arity): CallSite[] {
  return sites.filter(
    (site) => site.argCount !== undefined && (site.argCount < min || site.argCount > max),
  );
}

/** The calls (or constructions) that reach a changed signature, judged against its new arity. */
function intersectCalls(calls: CallSite[], arity: Arity | undefined): Intersection {
  if (!arity) return { sites: calls, evidence: "project-usage" };
  const bad = outsideArity(calls, arity);
  return {
    sites: bad,
    evidence: "project-usage",
    compatible: calls.length > 0 && bad.length === 0,
  };
}

function isCallOrNew(site: CallSite): boolean {
  return site.kind === "call" || site.kind === "new";
}

/** A change to the export itself (not one of its members). */
function intersectExport(change: ApiChange, exportSites: CallSite[]): Intersection {
  if (!change.arity || change.category !== "signature-changed") {
    return { sites: exportSites, evidence: "project-usage" };
  }
  const calls = exportSites.filter((site) => isCallOrNew(site));
  const bad = outsideArity(calls, change.arity);
  const unknown = exportSites.filter(
    (site) => site.kind !== "import" && (!isCallOrNew(site) || site.argCount === undefined),
  );
  if (bad.length > 0) return { sites: bad, evidence: "project-usage" };
  if (unknown.length > 0) return { sites: unknown, evidence: "project-usage" };
  return { sites: [], evidence: "project-usage", compatible: calls.length > 0 };
}

/** A change to a member of an enum, namespace or object-valued export, or a static member. */
function intersectObjectMember(
  change: ApiChange,
  usage: UsageIndex,
  exportName: string,
  memberName: string,
): Intersection {
  // `pkg.member` where `pkg` is the module object (default export or `require()` result) is a
  // use of the export named `member`; for a named export it is a member access on that binding.
  const sites =
    exportName === "default"
      ? sitesForExport(usage, change.specifier, memberName)
      : sitesForStaticMember(usage, change.specifier, exportName, memberName);
  if (!change.arity) return { sites, evidence: "project-usage" };
  const bad = outsideArity(
    sites.filter((site) => site.kind === "call"),
    change.arity,
  );
  return {
    sites: bad,
    evidence: "project-usage",
    compatible: sites.length > 0 && bad.length === 0,
  };
}

export function intersectApiChange(change: ApiChange, usage: UsageIndex): Intersection {
  const exportName = change.symbol === "module.exports" ? "default" : change.symbol;
  const exportSites = sitesForExport(usage, change.specifier, exportName);
  if (!change.member) {
    return intersectExport(change, exportSites);
  }

  // Member of a class, interface, namespace, enum or object-valued export.
  const memberName = change.member.replace(/^(static|get|set) /, "");
  if (change.member === "[call]") {
    return intersectCalls(
      exportSites.filter((site) => site.kind === "call"),
      change.arity,
    );
  }
  const objectLike =
    change.memberOf === "enum" ||
    change.memberOf === "namespace" ||
    change.memberOf === "object" ||
    change.member.startsWith("static ");
  if (objectLike) {
    return intersectObjectMember(change, usage, exportName, memberName);
  }
  if (change.member === "[new]") {
    return intersectCalls(
      exportSites.filter((site) => site.kind === "new"),
      change.arity,
    );
  }
  // Instance member: the class has to be used at all, then match by member name.
  if (exportSites.length === 0) return { sites: [], evidence: "name-match" };
  return { sites: usage.memberNameUses.get(memberName) ?? [], evidence: "name-match" };
}
