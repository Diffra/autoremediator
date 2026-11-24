import { stdin as defaultInput, stdout as defaultOutput } from "node:process";
import * as readline from "node:readline/promises";

import type { Command } from "commander";

import { OPTION_DESCRIPTIONS } from "../../../api/index.js";
import { evaluatePackage } from "../../../features/intelligence/evaluate/index.js";
import { remediate } from "../../../features/remediate/index.js";
import {
  parseScanInput,
  parseScanInputFromAudit,
  uniqueCveIds,
} from "../../../features/scan/index.js";
import { saveSuppressionToVexDocument } from "../../../features/vex/index.js";
import { saveSuppressionToPolicy, saveSuppressionToFile } from "../../../infra/policy/policy.js";
import type { VexJustification, VexSuppression } from "../../../infra/policy/types.js";
import { errorMessage } from "../../../shared/errors.js";
import type { CommandOptions } from "../types.js";

export interface InteractiveTriageOptions extends Omit<Partial<CommandOptions>, "input"> {
  input?: string | NodeJS.ReadableStream;
  output?: NodeJS.WritableStream;
  rl?: readline.Interface;
  vexOut?: string;
}

/**
 * Interactive developer CLI triage workflow.
 * Prompts developer through security findings with actions to apply, skip, suppress, or quit.
 * Persists suppression actions to .github/autoremediator.yml, suppressions file, or CycloneDX VEX document.
 */
export async function runInteractiveTriage(
  inputPathOrOpts: string | Partial<InteractiveTriageOptions>,
  maybeOpts?: Partial<InteractiveTriageOptions>,
): Promise<void> {
  let inputPath: string | undefined;
  if (typeof inputPathOrOpts === "string") {
    inputPath = inputPathOrOpts;
  } else if (typeof inputPathOrOpts.input === "string") {
    inputPath = inputPathOrOpts.input;
  }
  const opts: Partial<InteractiveTriageOptions> =
    (typeof inputPathOrOpts === "object" ? inputPathOrOpts : maybeOpts) ?? {};
  const cwd = opts.cwd ?? process.cwd();

  const outStream = opts.output ?? defaultOutput;
  const inStream = opts.input && typeof opts.input !== "string" ? opts.input : defaultInput;

  outStream.write("\n🔍 Scanning for security findings to triage...\n");

  let findings: Findings = [];
  try {
    findings = await loadFindings(inputPath, opts, cwd);
  } catch (err) {
    outStream.write(`Failed to load scan findings: ${errorMessage(err)}\n`);
    return;
  }

  const cveIds = uniqueCveIds(findings);
  if (cveIds.length === 0) {
    outStream.write("✨ No vulnerabilities found to triage!\n\n");
    return;
  }

  outStream.write(`Found ${cveIds.length} unique vulnerability(ies) to triage.\n`);

  const rl = opts.rl ?? readline.createInterface({ input: inStream, output: outStream });
  const context: TriageContext = {
    cwd,
    opts,
    out: outStream,
    rl,
    tally: { remediated: 0, skipped: 0, suppressed: 0 },
  };

  try {
    for (const [index, cveId] of cveIds.entries()) {
      const finding = findings.find((f) => f.cveId.toUpperCase() === cveId.toUpperCase());
      const pkgName = finding?.packageName ?? "unknown package";
      const safeVersion =
        pkgName === "unknown package" ? undefined : await lookupSafeVersion(pkgName, cveId);
      describeFinding(outStream, {
        position: `${index + 1}/${cveIds.length}`,
        cveId,
        pkgName,
        severity: finding?.severity ?? "UNKNOWN",
        safeVersion,
      });
      if ((await chooseAction(context, cveId)) === "quit") return;
    }
  } finally {
    rl.close();
    printSummary(outStream, cveIds.length, context.tally);
  }
}

type Findings = ReturnType<typeof parseScanInput>;

interface Tally {
  remediated: number;
  skipped: number;
  suppressed: number;
}

interface TriageContext {
  cwd: string;
  opts: Partial<InteractiveTriageOptions>;
  out: NodeJS.WritableStream;
  rl: readline.Interface;
  tally: Tally;
}

function loadFindings(
  inputPath: string | undefined,
  opts: Partial<InteractiveTriageOptions>,
  cwd: string,
): Promise<Findings> {
  const format = opts.format ?? "auto";
  if (inputPath) {
    return Promise.resolve(parseScanInput(inputPath, format));
  }
  return parseScanInputFromAudit({
    cwd,
    packageManager: opts.packageManager,
    format,
    workspace: opts.workspace,
  });
}

/** The version that fixes the finding, when a lookup can name one. A failed lookup only means none is shown. */
async function lookupSafeVersion(pkgName: string, cveId: string): Promise<string | undefined> {
  try {
    const evalRes = await evaluatePackage(pkgName, { enrichIntelligence: true });
    const matchingVuln = evalRes.vulnerabilities.find(
      (v) => v.cveId.toUpperCase() === cveId.toUpperCase(),
    );
    return (
      matchingVuln?.safeUpgradeVersion ??
      evalRes.vulnerabilities.find((v) => v.safeUpgradeVersion)?.safeUpgradeVersion
    );
  } catch {
    // The lookup only decorates the prompt; triage works without it.
    return undefined;
  }
}

function describeFinding(
  out: NodeJS.WritableStream,
  finding: {
    position: string;
    cveId: string;
    pkgName: string;
    severity: string;
    safeVersion: string | undefined;
  },
): void {
  out.write("\n" + "=".repeat(60) + "\n");
  out.write(`[${finding.position}] Vulnerability: ${finding.cveId}\n`);
  out.write(`  Package:  ${finding.pkgName}\n`);
  out.write(`  Severity: ${finding.severity}\n`);
  if (finding.safeVersion) {
    out.write(`  Safe Upstream Version: ${finding.safeVersion}\n`);
  }
  out.write("=".repeat(60) + "\n");
}

/** Asks until the developer picks an action; returns "quit" when they want to end the session. */
async function chooseAction(context: TriageContext, cveId: string): Promise<"next" | "quit"> {
  const { out, rl, tally } = context;
  for (;;) {
    const answer = await rl.question(
      "Action: [a]pply fix, [s]kip, [x] suppress/vex, [q]uit triage? [a/s/x/q]: ",
    );
    const choice = answer.trim().toLowerCase();
    if (choice === "a" || choice === "apply") {
      await applyRemediation(context, cveId);
      return "next";
    }
    if (choice === "s" || choice === "skip" || choice === "") {
      out.write(`Skipped ${cveId}.\n`);
      tally.skipped++;
      return "next";
    }
    if (choice === "x" || choice === "suppress") {
      await recordSuppression(context, cveId);
      return "next";
    }
    if (choice === "q" || choice === "quit") {
      out.write("Exiting triage session.\n");
      return "quit";
    }
    out.write("Invalid option. Please choose 'a', 's', 'x', or 'q'.\n");
  }
}

async function applyRemediation(context: TriageContext, cveId: string): Promise<void> {
  const { cwd, opts, out, tally } = context;
  out.write(`Applying remediation for ${cveId}...\n`);
  try {
    const report = await remediate(cveId, {
      cwd,
      packageManager: opts.packageManager,
      patchesDir: opts.patchesDir,
      policy: opts.policy,
      runTests: opts.runTests,
      constraints: {
        directDependenciesOnly: opts.directDependenciesOnly,
        preferVersionBump: opts.preferVersionBump,
        workspace: opts.workspace,
      },
    });
    if (report.results.some((r) => r.applied)) {
      out.write(`✅ Successfully applied remediation for ${cveId}!\n`);
      tally.remediated++;
    } else {
      const reason = report.results[0]?.unresolvedReason ?? "unresolved";
      out.write(`⚠️ Remediation could not be applied automatically (${reason}).\n`);
      tally.skipped++;
    }
  } catch (err) {
    out.write(`❌ Error remediating ${cveId}: ${errorMessage(err)}\n`);
    tally.skipped++;
  }
}

async function recordSuppression(context: TriageContext, cveId: string): Promise<void> {
  const { cwd, opts, out, rl, tally } = context;
  out.write(`Configuring suppression / VEX record for ${cveId}...\n`);

  const justAnswer = await rl.question(
    "Justification: [1] not_affected (default), [2] mitigated, [3] under_investigation, [4] fixed: ",
  );
  const notesAnswer = await rl.question(
    "Notes/rationale for suppression (optional, press Enter to skip): ",
  );
  const suppression: VexSuppression = {
    cveId,
    justification: justificationFrom(justAnswer),
    notes: notesAnswer.trim() || undefined,
  };

  let persistedTarget: string;
  if (opts.suppressionsFile) {
    saveSuppressionToFile(opts.suppressionsFile, suppression);
    persistedTarget = opts.suppressionsFile;
  } else {
    persistedTarget = saveSuppressionToPolicy(cwd, suppression, opts.policy);
  }
  if (opts.vexOut) {
    saveSuppressionToVexDocument(opts.vexOut, suppression);
    out.write(`  📄 Saved VEX statement to: ${opts.vexOut}\n`);
  }

  out.write(`✅ Persisted suppression for ${cveId} to ${persistedTarget}\n`);
  tally.suppressed++;
}

function justificationFrom(answer: string): VexJustification {
  const choice = answer.trim().toLowerCase();
  if (choice === "2" || choice === "mitigated") return "mitigated";
  if (choice === "3" || choice === "under_investigation") return "under_investigation";
  if (choice === "4" || choice === "fixed") return "fixed";
  return "not_affected";
}

function printSummary(out: NodeJS.WritableStream, total: number, tally: Tally): void {
  out.write("\n=== Triage Summary ===\n");
  out.write(`Total evaluated: ${total}\n`);
  out.write(`Remediated:     ${tally.remediated}\n`);
  out.write(`Suppressed:     ${tally.suppressed}\n`);
  out.write(`Skipped:        ${tally.skipped}\n\n`);
}

export function registerTriageCommand(program: Command): void {
  program
    .command("triage [input]")
    .description("Interactively triage discovered vulnerabilities step-by-step")
    .option("--cwd <path>", OPTION_DESCRIPTIONS.cwd, process.cwd())
    .option("--package-manager <name>", OPTION_DESCRIPTIONS.packageManager)
    .option("--patches-dir <path>", OPTION_DESCRIPTIONS.patchesDir)
    .option("--format <format>", OPTION_DESCRIPTIONS.format, "auto")
    .option("--run-tests", OPTION_DESCRIPTIONS.runTests)
    .option("--policy <path>", OPTION_DESCRIPTIONS.policy)
    .action(async (inputArg: string | undefined, opts: CommandOptions) => {
      await runInteractiveTriage(inputArg ? inputArg : opts, opts);
    });
}
