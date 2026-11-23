import { readFileSync } from "node:fs";

import { z } from "zod";

import { parseJson } from "../../../shared/json.js";
import type { CveSeverity } from "../../../shared/types.js";

export interface NormalizedFinding {
  cveId: string;
  source: "npm-audit" | "yarn-audit" | "sarif";
  packageName?: string;
  severity?: CveSeverity;
}

const viaSchema = z.union([
  z.string(),
  z.object({ url: z.string().optional(), name: z.string().optional() }),
]);

const vulnerabilitySchema = z.object({
  name: z.string(),
  via: z.array(viaSchema).optional(),
  severity: z.string().optional(),
});

/** `npm audit --json` (npm 7 and later). A file without `vulnerabilities` is not an audit report. */
const reportSchema = z.object({ vulnerabilities: z.record(z.string(), vulnerabilitySchema) });

const CVE_REGEX = /CVE-\d{4}-\d{1,7}/gi;
const GHSA_REGEX = /GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}/gi;

function normalizeSeverity(raw?: string): NormalizedFinding["severity"] {
  if (!raw) return "UNKNOWN";
  const up = raw.toUpperCase();
  if (up === "CRITICAL" || up === "HIGH" || up === "LOW") return up;
  if (up === "MEDIUM" || up === "MODERATE") return "MEDIUM";
  return "UNKNOWN";
}

/** `source` names where `content` came from, so a damaged report is traceable. */
export function parseNpmAuditJsonFromString(
  content: string,
  source = "npm audit output",
): NormalizedFinding[] {
  const report = parseJson(content, reportSchema, source);
  const findings: NormalizedFinding[] = [];
  const seen = new Set<string>();

  for (const vuln of Object.values(report.vulnerabilities)) {
    for (const viaEntry of vuln.via ?? []) {
      const text =
        typeof viaEntry === "string" ? viaEntry : `${viaEntry.url ?? ""} ${viaEntry.name ?? ""}`;
      const cveMatches = text.match(CVE_REGEX) ?? [];
      const matches = cveMatches.length > 0 ? cveMatches : (text.match(GHSA_REGEX) ?? []);
      for (const match of matches) {
        const cveId = match.toUpperCase();
        const key = `${cveId}:${vuln.name}`;
        if (seen.has(key)) continue;
        seen.add(key);
        findings.push({
          cveId,
          source: "npm-audit",
          packageName: vuln.name,
          severity: normalizeSeverity(vuln.severity),
        });
      }
    }
  }

  return findings;
}

export function parseNpmAuditJsonFile(filePath: string): NormalizedFinding[] {
  const content = readFileSync(filePath, "utf8");
  return parseNpmAuditJsonFromString(content, filePath);
}
