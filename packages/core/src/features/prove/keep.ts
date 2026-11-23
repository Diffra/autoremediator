/** Writes a proven script, its evidence record and an optional detached signature. */
import { mkdirSync, writeFileSync } from "node:fs";

import { SANDBOX_ENV, type SandboxReport } from "../../shared/exec/sandbox.js";
import { sha256 } from "../../shared/hash.js";
import { CLAIM, type ProofEvidence, relativeTo, SIGNATURE_SUFFIX, signRecord } from "./evidence.js";
import { CONFIRM_RUNS } from "./harness.js";
import type { ProveResult } from "./index.js";
import type {
  AdvisoryContext,
  FetchedPackage,
  ReproductionAgent,
  ReproductionOutcome,
  TrialResult,
  TrialSummary,
} from "./types.js";

export const MAX_OUTPUT_BYTES = 256 * 1024;

export interface KeepInput {
  base: Pick<
    ProveResult,
    | "schemaVersion"
    | "advisoryId"
    | "package"
    | "vulnerableVersion"
    | "fixedVersion"
    | "trials"
    | "agent"
    | "usage"
    | "sandbox"
  >;
  keep: { script: string; result: TrialResult };
  advisory: AdvisoryContext;
  advisoryId: string;
  packageName: string;
  vulnerableVersion: string;
  fixedVersion: string;
  fetched: { vulnerable: FetchedPackage; fixed: FetchedPackage };
  sandbox: SandboxReport;
  timeoutMs: number;
  cwd: string;
  paths: { patchesPath: string; scriptPath: string; evidencePath: string };
  signingKey: Parameters<typeof signRecord>[1] | undefined;
  agent: ReproductionAgent;
  outcome: ReproductionOutcome;
  trials: TrialSummary[];
  now: Date;
}

export function keepProof(input: KeepInput): ProveResult {
  const { base, advisory, advisoryId, packageName, vulnerableVersion, fixedVersion } = input;
  const { sandbox, timeoutMs, cwd, signingKey, agent, outcome, trials, now } = input;
  const { patchesPath, scriptPath, evidencePath } = input.paths;
  const { vulnerable, fixed } = input.fetched;
  const { script, result } = input.keep;
  const record: ProofEvidence = {
    schemaVersion: "1.0",
    kind: "proof-of-fix-evidence",
    advisoryId,
    ...(advisory.id !== advisoryId ? { aliases: [advisory.id] } : {}),
    package: packageName,
    vulnerableVersion,
    fixedVersion,
    claim: CLAIM,
    script: {
      path: relativeTo(cwd, scriptPath),
      sha256: sha256(script),
    },
    vulnerableRun: result.vulnerableRun!,
    fixedRun: result.fixedRun!,
    confirmedRuns: CONFIRM_RUNS,
    tarballs: {
      vulnerable: { url: vulnerable.tarballUrl, integrity: vulnerable.integrity },
      fixed: { url: fixed.tarballUrl, integrity: fixed.integrity },
    },
    sandbox: {
      ...sandbox,
      env: Object.keys(SANDBOX_ENV),
      timeoutMs,
      maxOutputBytes: MAX_OUTPUT_BYTES,
    },
    nodeVersion: process.version,
    timestamp: now.toISOString(),
    model: outcome.usage[0]?.model ?? null,
    agent: agent.id,
    trials: trials.length,
  };

  mkdirSync(patchesPath, { recursive: true });
  const recordText = `${JSON.stringify(record, null, 2)}\n`;
  writeFileSync(scriptPath, script, "utf8");
  writeFileSync(evidencePath, recordText, "utf8");
  let signaturePath: string | undefined;
  if (signingKey) {
    signaturePath = `${evidencePath}${SIGNATURE_SUFFIX}`;
    writeFileSync(
      signaturePath,
      `${JSON.stringify(signRecord(Buffer.from(recordText, "utf8"), signingKey), null, 2)}\n`,
      "utf8",
    );
  }

  return {
    ...base,
    status: "kept",
    reason: result.reason,
    evidence: record,
    files: {
      script: relativeTo(cwd, scriptPath),
      evidence: relativeTo(cwd, evidencePath),
      ...(signaturePath ? { signature: relativeTo(cwd, signaturePath) } : {}),
    },
  };
}
