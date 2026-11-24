/** Turns assessed advisories into OpenVEX statement drafts and changeset release-note lines. */
import { isShipped } from "./scope.js";
import type { MaintainAdvisory } from "./types.js";
import type { DraftStatement } from "./vex-file.js";

export function toDraft(advisory: MaintainAdvisory): DraftStatement | undefined {
  if (
    advisory.decision !== "not_affected" &&
    advisory.decision !== "affected" &&
    advisory.decision !== "under_investigation"
  ) {
    return undefined;
  }
  const shipped = advisory.packages.filter((entry) => isShipped(entry));
  const evidence = shipped
    .map((entry) => {
      const basis = entry.evidenceKind === "both" ? "static scan and runtime trace" : "static scan";
      return `${entry.name}: ${entry.reachability ?? "unknown"} (${basis}${entry.runtimeVerdict ? `, trace: ${entry.runtimeVerdict}` : ""}) ${entry.reason ?? ""}`.trim();
    })
    .join("; ");
  const draft: DraftStatement = {
    advisory: advisory.id.toUpperCase(),
    status: advisory.decision,
    subcomponents: [...new Set(shipped.map((entry) => entry.name))],
    statusNotes:
      advisory.decision === "not_affected"
        ? `Assessed by the maintainer with autoremediator maintain and asserted with --assert-not-affected. ${evidence}`
        : `Assessed with autoremediator maintain. ${evidence}`,
  };
  if (advisory.decision === "affected") {
    const fixes = advisory.plan?.items.map((item) => `${item.packageName} ${item.toVersion}`) ?? [];
    draft.actionStatement =
      fixes.length > 0
        ? `Update to a release that depends on ${fixes.join(", ")} or later.`
        : "No fixed version of the dependency is known yet; follow the advisory.";
  }
  return draft;
}

export function changesetLines(advisories: readonly MaintainAdvisory[]): string[] {
  const lines: string[] = [];
  for (const advisory of advisories) {
    const names = advisory.packages
      .filter((entry) => isShipped(entry))
      .map((entry) => `\`${entry.name}\``)
      .join(", ");
    const fixes =
      advisory.plan?.items.map((item) => `\`${item.packageName}\` to ${item.toVersion}`) ?? [];
    switch (advisory.decision) {
      case "affected": {
        lines.push(
          fixes.length > 0
            ? `- Update ${fixes.join(", ")} to fix ${advisory.id}, which this package's code reaches.`
            : `- Track ${advisory.id} in ${names}: this package's code reaches it and no fixed version is known yet.`,
        );
        break;
      }
      case "not_affected": {
        lines.push(
          `- Declare in the shipped OpenVEX document that this package is not affected by ${advisory.id}: the vulnerable code in ${names} is not in its execute path.`,
        );
        break;
      }
      case "under_investigation": {
        lines.push(
          `- Record in the shipped OpenVEX document that ${advisory.id} in ${names} is under investigation.`,
        );
        break;
      }
      case "not-shipped":
      case "unknown": {
        break;
      }
    }
  }
  return lines;
}
