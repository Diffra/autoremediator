/**
 * Findings and their scoring: what one finding is, how many points it is worth, how a set of
 * findings becomes a rating, and how a package-level change becomes a finding.
 */
import type { ChangeSeverity } from "./api-diff.js";
import { isSubpathExported, type PackageLevelChange } from "./manifest-diff.js";
import type { CallSite, PackageSource } from "./types.js";
import type { UsageIndex } from "./usage-index.js";

const MAX_SITES_PER_FINDING = 20;

export type Breakability = "High" | "Medium" | "Low";

export type FindingEvidence =
  /** The project's own call or reference sites reach the change. */
  | "project-usage"
  /** Only a member name matches (class instance members cannot be resolved without types). */
  | "name-match"
  /** The project's manifest proves it cannot meet the new requirement. */
  | "project-conflict"
  /** The project uses the package in ways that cannot be followed. */
  | "opaque-usage"
  /** A real package-level change whose effect depends on facts about the project we do not have. */
  | "unresolved";

/** Points per finding. The breakability rating is a function of these and nothing else. */
export const IMPACT_POINTS: Readonly<
  Record<FindingEvidence, Readonly<Record<ChangeSeverity, number>>>
> = {
  "project-usage": { breaking: 50, "possibly-breaking": 20 },
  "name-match": { breaking: 20, "possibly-breaking": 8 },
  "project-conflict": { breaking: 50, "possibly-breaking": 50 },
  "opaque-usage": { breaking: 15, "possibly-breaking": 15 },
  unresolved: { breaking: 15, "possibly-breaking": 15 },
};

/** Score at which a rating with no hard finding becomes Medium. */
export const MEDIUM_THRESHOLD = 15;

/**
 * High needs a HARD finding: a breaking change reached by the project's own code, or a conflict
 * the project's manifest proves. Everything else tops out at Medium, however many findings.
 */
export function isHard(evidence: FindingEvidence, severity: ChangeSeverity): boolean {
  return (
    severity === "breaking" && (evidence === "project-usage" || evidence === "project-conflict")
  );
}

export interface ImpactFinding {
  scope: "api" | "package";
  category: string;
  severity: ChangeSeverity;
  evidence: FindingEvidence;
  points: number;
  specifier?: string;
  symbol?: string;
  member?: string;
  reason: string;
  before?: string;
  after?: string;
  /** Project code the change reaches (`file:line`), capped; see `totalCallSites`. */
  affectedCallSites: CallSite[];
  totalCallSites: number;
}

export interface Rating {
  score: number;
  breakability: Breakability;
}

/** The rating for a set of findings. Pure and deterministic. */
export function rate(
  findings: ReadonlyArray<Pick<ImpactFinding, "evidence" | "severity" | "points">>,
): Rating {
  const score = findings.reduce((total, finding) => total + finding.points, 0);
  if (findings.some((finding) => isHard(finding.evidence, finding.severity))) {
    return { score, breakability: "High" };
  }
  return { score, breakability: score >= MEDIUM_THRESHOLD ? "Medium" : "Low" };
}

export function uniqueSites(sites: CallSite[]): CallSite[] {
  const seen = new Set<string>();
  const result: CallSite[] = [];
  for (const site of sites) {
    const key = `${site.file}:${site.line}:${site.kind}`;
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(site);
  }
  return result.toSorted((a, b) => a.file.localeCompare(b.file) || a.line - b.line);
}

function pointsFor(evidence: FindingEvidence, severity: ChangeSeverity): number {
  return IMPACT_POINTS[evidence][severity];
}

export function toFinding(
  base: Omit<ImpactFinding, "points" | "affectedCallSites" | "totalCallSites">,
  sites: CallSite[],
): ImpactFinding {
  const unique = uniqueSites(sites);
  return {
    ...base,
    points: pointsFor(base.evidence, base.severity),
    affectedCallSites: unique.slice(0, MAX_SITES_PER_FINDING),
    totalCallSites: unique.length,
  };
}

function usageSites(usage: UsageIndex, specifier: string): CallSite[] {
  const sites: CallSite[] = [];
  sites.push(
    ...(usage.importSites.get(specifier) ?? []),
    ...(usage.requireSites.get(specifier) ?? []),
  );
  return sites;
}

export function packageChangeFinding(
  change: PackageLevelChange,
  context: {
    usage: UsageIndex;
    packageName: string;
    requireSites: CallSite[];
    importSites: CallSite[];
    after: PackageSource;
  },
): ImpactFinding | undefined {
  const base = {
    scope: "package" as const,
    category: change.category,
    reason: change.reason,
    before: change.before,
    after: change.after,
  };

  if (change.category === "exports-map") {
    const deepSpecifiers = [...context.usage.specifiers].filter((specifier) =>
      specifier.startsWith(`${context.packageName}/`),
    );
    const gone = deepSpecifiers.filter((specifier) => {
      const subpath = `./${specifier.slice(context.packageName.length + 1)}`;
      return change.restrictsDeepImports
        ? !isSubpathExported(context.after.manifest, subpath)
        : (change.removedSubpaths ?? []).includes(subpath) &&
            !isSubpathExported(context.after.manifest, subpath);
    });
    if (gone.length === 0) return undefined;
    return toFinding(
      {
        ...base,
        severity: "breaking",
        evidence: "project-usage",
        specifier: gone[0],
        reason: `${change.reason}; the project imports ${gone.map((specifier) => `\`${specifier}\``).join(", ")}`,
      },
      gone.flatMap((specifier) => usageSites(context.usage, specifier)),
    );
  }
  if (change.category === "module-format") {
    if (change.affectsRequire) {
      if (context.requireSites.length === 0) return undefined;
      return toFinding(
        { ...base, severity: change.severity, evidence: "project-usage" },
        context.requireSites,
      );
    }
    if (context.importSites.length === 0) return undefined;
    return toFinding(
      { ...base, severity: change.severity, evidence: "unresolved" },
      context.importSites,
    );
  }
  // engines and peer dependencies concern the project as a whole, not a call site.
  return toFinding(
    {
      ...base,
      severity: change.severity,
      evidence: change.evidence === "project-conflict" ? "project-conflict" : "unresolved",
    },
    [],
  );
}

function describeSite(site: CallSite): string {
  return `${site.file}:${site.line}`;
}

export function summarize(
  breakability: Breakability,
  findings: ImpactFinding[],
  unreached: { breaking: number; possiblyBreaking: number },
  usesPackage: boolean,
): string {
  const hard = findings.filter((finding) => isHard(finding.evidence, finding.severity));
  const sites = uniqueSites(findings.flatMap((finding) => finding.affectedCallSites));
  const unreachedText =
    unreached.breaking + unreached.possiblyBreaking > 0
      ? ` ${unreached.breaking} breaking and ${unreached.possiblyBreaking} possibly-breaking change${unreached.breaking + unreached.possiblyBreaking === 1 ? "" : "s"} do not touch code in this project.`
      : "";
  if (breakability === "High") {
    return `High: ${hard.length} breaking change${hard.length === 1 ? "" : "s"} hit this project${
      sites.length > 0
        ? `, e.g. ${sites
            .slice(0, 3)
            .map((site) => describeSite(site))
            .join(", ")}`
        : ""
    }.${unreachedText}`;
  }
  if (breakability === "Medium") {
    return `Medium: ${findings.length} change${findings.length === 1 ? "" : "s"} may affect this project and could not be ruled out.${unreachedText}`;
  }
  if (!usesPackage) {
    return `Low: no source file imports the package directly; only package-level changes were checked.${unreachedText}`;
  }
  return `Low: no change reaches code in this project.${unreachedText}`;
}
