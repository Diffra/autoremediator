/** The Article 14 reporting drafts of a pack: parsing the awareness times and writing one draft per advisory. */
import { PACKAGE_VERSION } from "../../../shared/version.js";
import { buildCraDraft, parseAwareness } from "./cra.js";
import type { FindingsResult } from "./findings.js";
import type { EvidencePackOptions } from "./options.js";
import type { ProductIdentity } from "./sbom.js";
import type { EvidencePackResult } from "./types.js";

export interface CraTiming {
  awareness: Date | undefined;
  awarenessByCve: Map<string, Date>;
  correctiveMeasureAt: Date | undefined;
}

export interface CraDrafts {
  craReports: EvidencePackResult["craReports"];
  drafts: Array<{ path: string; content: string }>;
}

/** Validate the awareness times before anything is written; a malformed one is refused. */
export function parseCraTiming(options: EvidencePackOptions): CraTiming {
  const awareness = options.awarenessAt
    ? parseAwareness(options.awarenessAt, "awarenessAt")
    : undefined;
  const awarenessByCve = new Map<string, Date>();
  for (const [cveId, value] of Object.entries(options.awarenessByCve ?? {})) {
    awarenessByCve.set(cveId.toUpperCase(), parseAwareness(value, `awarenessByCve[${cveId}]`));
  }
  const correctiveMeasureAt = options.correctiveMeasureAt
    ? parseAwareness(options.correctiveMeasureAt, "correctiveMeasureAt")
    : undefined;
  return { awareness, awarenessByCve, correctiveMeasureAt };
}

/**
 * Drafts for advisories CISA lists as exploited that the product is not recorded as unaffected by.
 * Reasons for a missing draft are appended to `notes`.
 */
export function buildCraDrafts(input: {
  found: FindingsResult;
  product: ProductIdentity;
  timing: CraTiming;
  now: Date;
  notes: string[];
}): CraDrafts {
  const { found, product, timing, now, notes } = input;
  const craReports: CraDrafts["craReports"] = [];
  const drafts: CraDrafts["drafts"] = [];
  const kevCves = [...found.cves.entries()].filter(([, details]) => details?.kev?.knownExploited);
  for (const [cveId, details] of kevCves) {
    const relevant = found.findings.filter(
      (finding) =>
        finding.cveId.toUpperCase() === cveId.toUpperCase() && finding.status !== "not_affected",
    );
    if (relevant.length === 0) {
      notes.push(
        `${cveId} is in the CISA KEV catalog but no finding says it affects the product (not affected, or no component recorded); no draft was written.`,
      );
      continue;
    }
    const awareness = timing.awarenessByCve.get(cveId.toUpperCase()) ?? timing.awareness;
    const draft = buildCraDraft({
      cveId,
      details,
      findings: relevant,
      product,
      ...(awareness ? { awareness } : {}),
      ...(timing.correctiveMeasureAt
        ? { correctiveMeasureAvailableAt: timing.correctiveMeasureAt }
        : {}),
      generatedAt: now,
      toolVersion: PACKAGE_VERSION,
    });
    drafts.push({ path: `cra-reports/${draft.fileName}`, content: draft.markdown });
    craReports.push({
      cveId,
      file: `cra-reports/${draft.fileName}`,
      status: draft.status,
      ...(draft.deadlines ? { deadlines: draft.deadlines } : {}),
    });
  }
  addCraNotes({ kevIds: kevCves.map(([id]) => id), timing, notes });
  return { craReports, drafts };
}

function addCraNotes(input: { kevIds: string[]; timing: CraTiming; notes: string[] }): void {
  const { kevIds, timing, notes } = input;
  for (const cveId of timing.awarenessByCve.keys()) {
    if (!kevIds.some((id) => id.toUpperCase() === cveId)) {
      notes.push(
        `An awareness time was given for ${cveId}, but no recorded run lists it as known exploited, so it has no draft.`,
      );
    }
  }
  if (kevIds.length === 0) {
    notes.push(
      "No recorded run lists an advisory in the CISA KEV catalog, so there are no Article 14 drafts. KEV data comes only from earlier runs; nothing was looked up now.",
    );
  } else if (!timing.awareness && timing.awarenessByCve.size === 0) {
    notes.push(
      "No awareness time was given (--awareness-at), so the drafts state the 24 hour and 72 hour rules but no dates.",
    );
  }
}
