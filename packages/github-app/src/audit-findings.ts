/**
 * Package-manager audit output: run the audit, parse npm and yarn JSON, and pick the CVEs at or
 * above a minimum severity.
 */
import { access } from "node:fs/promises";
import { join } from "node:path";

import type { CveSeverity } from "autoremediator";

import { errorMessage } from "./errors.js";
import { runCommand } from "./run-command.js";
import type { ParsedAuditFinding } from "./types.js";

const CVE_REGEX = /CVE-\d{4}-\d+/gi;

export const SEVERITY_RANK: Record<CveSeverity, number> = {
  UNKNOWN: 0,
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
  CRITICAL: 4,
};

export function selectCvesByMinimumSeverity(
  findings: ParsedAuditFinding[],
  minimumSeverity: CveSeverity,
): string[] {
  const minRank = SEVERITY_RANK[minimumSeverity];
  const cves = new Set<string>();

  for (const finding of findings) {
    if (SEVERITY_RANK[finding.severity] >= minRank) {
      cves.add(finding.cveId.toUpperCase());
    }
  }

  return [...cves].toSorted((a, b) => a.localeCompare(b));
}

export function normalizeSeverity(raw?: string): CveSeverity {
  if (!raw) {
    return "UNKNOWN";
  }

  const normalized = raw.toUpperCase();
  if (normalized === "LOW" || normalized === "HIGH" || normalized === "CRITICAL") {
    return normalized;
  }
  if (normalized === "MEDIUM" || normalized === "MODERATE") {
    return "MEDIUM";
  }

  return "UNKNOWN";
}

export async function collectAuditFindings(cwd: string): Promise<ParsedAuditFinding[]> {
  const packageManager = await detectPackageManager(cwd);
  const commands = auditCommands(packageManager);

  let lastError = "No audit output received.";

  for (const [command, args] of commands) {
    let result: { output: string; exitCode: number };
    try {
      result = await runCommand(command, args, cwd);
    } catch (error) {
      lastError = errorMessage(error);
      continue;
    }

    if (!result.output) {
      lastError = `No audit output received from ${command} ${args.join(" ")}.`;
      continue;
    }

    let findings: ParsedAuditFinding[] = [];
    try {
      findings = parseNpmAuditFindings(result.output);
    } catch {
      findings = [];
    }

    if (findings.length === 0) {
      findings = parseYarnAuditFindings(result.output);
    }

    if (result.exitCode !== 0 && findings.length === 0) {
      lastError = `Failed to parse output from ${command} ${args.join(" ")} (exit code ${result.exitCode}).`;
      continue;
    }

    return findings;
  }

  throw new Error(lastError);
}

function auditCommands(packageManager: "npm" | "pnpm" | "yarn"): Array<[string, string[]]> {
  if (packageManager === "yarn") {
    return [
      ["yarn", ["npm", "audit", "--json"]],
      ["yarn", ["audit", "--json"]],
    ];
  }
  if (packageManager === "pnpm") {
    return [["pnpm", ["audit", "--json"]]];
  }
  return [["npm", ["audit", "--json"]]];
}

function extractCveIds(value: string): string[] {
  return (value.match(CVE_REGEX) ?? []).map((item) => item.toUpperCase());
}

function parseNpmAuditFindings(content: string): ParsedAuditFinding[] {
  const parsed = JSON.parse(content) as {
    vulnerabilities?: Record<
      string,
      {
        name?: string;
        severity?: string;
        via?: Array<string | { url?: string; name?: string }>;
      }
    >;
  };

  const findings: ParsedAuditFinding[] = [];
  const seen = new Set<string>();

  for (const vuln of Object.values(parsed.vulnerabilities ?? {})) {
    const severity = normalizeSeverity(vuln.severity);
    for (const viaEntry of vuln.via ?? []) {
      const text =
        typeof viaEntry === "string" ? viaEntry : `${viaEntry.url ?? ""} ${viaEntry.name ?? ""}`;
      for (const cveId of extractCveIds(text)) {
        const key = `${cveId}:${vuln.name ?? ""}`;
        if (seen.has(key)) {
          continue;
        }

        seen.add(key);
        findings.push({ cveId, severity });
      }
    }
  }

  return findings;
}

function parseYarnAuditFindings(content: string): ParsedAuditFinding[] {
  const findings: ParsedAuditFinding[] = [];
  const seen = new Set<string>();
  const lines = content
    .split("\n")
    .map((line) => line.trim())
    .filter((line) => line.length > 0);

  for (const line of lines) {
    let parsedLine: unknown;
    try {
      parsedLine = JSON.parse(line);
    } catch {
      continue;
    }

    const event = parsedLine as {
      type?: string;
      data?: {
        advisory?: {
          module_name?: string;
          severity?: string;
          url?: string;
          cves?: string[];
        };
      };
    };

    if (event.type !== "auditAdvisory") {
      continue;
    }

    const advisory = event.data?.advisory;
    const text = `${advisory?.url ?? ""} ${(advisory?.cves ?? []).join(" ")}`;
    const severity = normalizeSeverity(advisory?.severity);

    for (const cveId of extractCveIds(text)) {
      const key = `${cveId}:${advisory?.module_name ?? ""}`;
      if (seen.has(key)) {
        continue;
      }

      seen.add(key);
      findings.push({ cveId, severity });
    }
  }

  return findings;
}

async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

async function detectPackageManager(cwd: string): Promise<"npm" | "pnpm" | "yarn"> {
  if (await fileExists(join(cwd, "yarn.lock"))) {
    return "yarn";
  }
  if (await fileExists(join(cwd, "pnpm-lock.yaml"))) {
    return "pnpm";
  }

  return "npm";
}
