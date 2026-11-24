/** Cross-check a flagged package against OSV: has an advisory been published for this range now? */
import semver from "semver";

import { sanitizeEvidence } from "./signals/sanitize.js";
import type { RadarAdvisory, RadarDeps, RadarEntry } from "./types.js";

export interface AdvisoryCheck {
  status: RadarEntry["status"];
  advisories: RadarAdvisory[];
}

/** Advisories fixed within the range make the status "now-advisory"; a failed lookup "unchecked". */
export async function checkAdvisories(
  deps: RadarDeps,
  name: string,
  installed: string,
  target: string,
  notes: string[],
): Promise<AdvisoryCheck> {
  let status: RadarEntry["status"] = "silent";
  const advisories: RadarAdvisory[] = [];
  try {
    for (const advisory of await deps.queryAdvisories(name, installed)) {
      const inRange =
        advisory.fixedIn !== undefined &&
        semver.valid(advisory.fixedIn) !== null &&
        semver.gt(advisory.fixedIn, installed) &&
        semver.lte(advisory.fixedIn, target);
      if (inRange) {
        advisories.push({ id: sanitizeEvidence(advisory.id, 60), fixedIn: advisory.fixedIn });
      } else {
        notes.push(
          `${sanitizeEvidence(advisory.id, 60)} also affects ${installed} but is not fixed by ${target}`,
        );
      }
    }
    if (advisories.length > 0) status = "now-advisory";
  } catch {
    // OSV being unreachable must not fail the package: report the gap in the entry instead.
    status = "unchecked";
    notes.push("OSV could not be reached, so whether an advisory exists is unknown");
  }
  return { status, advisories };
}
