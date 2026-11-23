/**
 * Exploit-proof evidence: have an agent write the reproduction that `proofOfFix` needs, and keep
 * it only if a deterministic harness proves it (fails on the vulnerable version, passes on the
 * fixed one, repeatably, in a sandbox). See `docs/guides/proof-of-fix-generation.md`.
 */
import { existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { getModelSpec } from "../../infra/config.js";
import { type SandboxReport, verifySandbox } from "../../shared/exec/sandbox.js";
import { sha256 } from "../../shared/hash.js";
import { findVulnerableSymbols } from "../impact/fix-diff.js";
import { isAdvisoryId } from "../incident/target.js";
import { resolvePatchesDir } from "../patch/artifacts/helpers.js";
import { resolveLanguageModel } from "../patch/model.js";
import type { ProofEvidenceRef } from "../vex/index.js";
import { choosePackage, chooseVersions, contextFor, lookupAdvisoryOsv } from "./advisory.js";
import { createBuiltinReproductionAgent } from "./agent.js";
import {
  baseName,
  EVIDENCE_SUFFIX,
  findEvidence,
  loadSigningKey,
  type ProofEvidence,
  relativeTo,
  scriptFileName,
} from "./evidence.js";
import { createHarness } from "./harness.js";
import { fetchVerifiedPackage, installFetchedPackage, listPublishedVersions } from "./install.js";
import { keepProof, MAX_OUTPUT_BYTES } from "./keep.js";
import { createTrialRunner } from "./trial-runner.js";
import type {
  TrialSummary,
  AdvisoryContext,
  AdvisoryLookup,
  FetchedPackage,
  ModelResolver,
  ReproductionAgent,
  ReproductionOutcome,
  ReproductionUsage,
} from "./types.js";

export type { ProofEvidenceRef } from "../vex/index.js";
export {
  findEvidence,
  verifyProofEvidence,
  type DetachedSignature,
  type FoundEvidence,
  type ProofEvidence,
  type SignatureCheck,
} from "./evidence.js";
export { createBuiltinReproductionAgent } from "./agent.js";
export { screenScript, type ScreenResult } from "./screen.js";
export {
  runSandboxed,
  SandboxUnavailableError,
  verifySandbox,
  type SandboxReport,
} from "../../shared/exec/sandbox.js";
export type {
  AdvisoryContext,
  JudgedRun,
  ReproductionAgent,
  ReproductionEnv,
  ReproductionOutcome,
  ReproductionTask,
  RunVerdict,
  TrialResult,
  TrialSummary,
} from "./types.js";

export interface ProveOptions {
  /** The npm package to prove against. Optional when the advisory affects exactly one. */
  package?: string;
  /** Exact version to prove the script fails on. Default: the newest vulnerable version below the fix. */
  vulnerableVersion?: string;
  /** Exact version to prove the script passes on. Default: the advisory's first patched version. */
  fixedVersion?: string;
  /** Advisory text to use instead of, or in addition to, what OSV says. */
  advisoryText?: string;
  /** `<provider>:<model-id>`. Falls back to AUTOREMEDIATOR_MODEL. */
  model?: string;
  cwd?: string;
  patchesDir?: string;
  /** Ed25519 private key (PEM) to sign the evidence record with. */
  signingKeyPath?: string;
  /** Candidate scripts the agent may try (1-10, default 4). */
  maxTrials?: number;
  /** Wall-clock limit of one sandboxed run in milliseconds (1000-60000, default 10000). */
  timeoutMs?: number;
  /** Replace a reproduction script that is already at the target path and was not made by this tool. */
  overwrite?: boolean;
  /** Agent that proposes scripts, instead of one built from `model`. SDK only. */
  agent?: ReproductionAgent;
}

export interface ProveResult {
  schemaVersion: "1.0";
  advisoryId: string;
  package: string;
  vulnerableVersion: string;
  fixedVersion: string;
  status: "kept" | "rejected";
  /** Why it was kept, or why nothing was. */
  reason: string;
  trials: TrialSummary[];
  agent: { id: string; status: string; rationale: string };
  usage: ReproductionUsage[];
  /** Present when a script was kept; paths relative to `cwd`. */
  files?: { script: string; evidence: string; signature?: string };
  evidence?: ProofEvidence;
  /** What the sandbox self-test established on this machine. */
  sandbox: SandboxReport;
}

/** What a proof run reads from outside the process; replaceable so tests need no network. */
export interface ProveDeps {
  lookupAdvisory(id: string): Promise<AdvisoryLookup | undefined>;
  listVersions(name: string, cwd: string): Promise<string[]>;
  fetchPackage(name: string, version: string, cwd: string): Promise<FetchedPackage>;
  /** Lay a fetched package out as `<dir>/node_modules/<name>`. */
  install(dir: string, fetched: FetchedPackage, cwd: string): Promise<void>;
  resolveModel: ModelResolver;
  now(): Date;
}

export const defaultProveDeps: ProveDeps = {
  lookupAdvisory: lookupAdvisoryOsv,
  listVersions: listPublishedVersions,
  fetchPackage: fetchVerifiedPackage,
  install: installFetchedPackage,
  resolveModel: (spec) => resolveLanguageModel(spec),
  now: () => new Date(),
};

const DEFAULT_MAX_TRIALS = 4;
const DEFAULT_RUN_TIMEOUT_MS = 10_000;
const AGENT_WALL_MS = 10 * 60_000;

const NO_MODEL =
  'Proof-of-fix generation needs a model to write the reproduction: pass `model` ("<provider>:<model-id>", e.g. "anthropic:claude-sonnet-5-5") or set AUTOREMEDIATOR_MODEL. Nothing was fetched or written.';

async function resolveAgent(options: ProveOptions, deps: ProveDeps): Promise<ReproductionAgent> {
  if (options.agent) return options.agent;
  const spec = getModelSpec(options.model);
  if (!spec) throw new Error(NO_MODEL);
  return createBuiltinReproductionAgent(await deps.resolveModel(spec));
}

export async function generateProofOfFix(
  cveId: string,
  options: ProveOptions = {},
  deps: ProveDeps = defaultProveDeps,
): Promise<ProveResult> {
  const advisoryId = requireAdvisoryId(cveId, options.advisoryText);
  const cwd = options.cwd ?? process.cwd();
  const { maxTrials, timeoutMs } = clampLimits(options);

  // Everything that can fail cheaply fails before the network is touched or a model is paid for.
  const agent = await resolveAgent(options, deps);
  const signingKey = options.signingKeyPath ? loadSigningKey(options.signingKeyPath) : undefined;
  const sandbox = await verifySandbox();

  const { advisory, packageName, vulnerableVersion, fixedVersion } = await resolveTarget(
    deps,
    options,
    advisoryId,
    cwd,
  );

  const paths = outputPaths(cwd, options, packageName, vulnerableVersion);

  const { root, vulnerableDir, fixedDir } = createWorkDirs();
  try {
    const [vulnerable, fixed] = await fetchAndInstall(deps, cwd, {
      packageName,
      vulnerable: { version: vulnerableVersion, dir: vulnerableDir },
      fixed: { version: fixedVersion, dir: fixedDir },
    });

    const candidates = candidateLines(vulnerable, fixed, advisory);
    const harness = createHarness({
      packageName,
      vulnerableVersion,
      fixedVersion,
      vulnerableDir,
      fixedDir,
      timeoutMs,
      maxOutputBytes: MAX_OUTPUT_BYTES,
    });

    const { trials, keep, trial } = createTrialRunner(harness, maxTrials);

    const outcome = await agent.propose(
      { advisory, packageName, vulnerableVersion, fixedVersion, candidates, maxTrials },
      {
        sources: { vulnerable: vulnerable.source, fixed: fixed.source },
        trial,
        signal: new AbortController().signal,
        maxWallMs: AGENT_WALL_MS,
      },
    );

    const base = proofHeader({
      advisoryId,
      packageName,
      vulnerableVersion,
      fixedVersion,
      trials,
      agent,
      outcome,
      sandbox,
    });

    if (!keep.value) return rejectedProof(base, trials, outcome);

    return keepProof({
      base,
      keep: keep.value,
      advisory,
      advisoryId,
      packageName,
      vulnerableVersion,
      fixedVersion,
      fetched: { vulnerable, fixed },
      sandbox,
      timeoutMs,
      cwd,
      paths,
      signingKey,
      agent,
      outcome,
      trials,
      now: deps.now(),
    });
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

/** OSV ids are case-sensitive: CVE-, OSV- and MAL- ids are upper case, and GHSA ids are `GHSA-` and lower case. */
export function normalizeAdvisoryId(id: string): string {
  return /^GHSA-/i.test(id) ? `GHSA-${id.slice(5).toLowerCase()}` : id.toUpperCase();
}

/** A script already at the path that an evidence record of ours vouches for may be replaced. */
function ownedByEvidence(scriptPath: string, evidencePath: string): boolean {
  try {
    const record = JSON.parse(readFileSync(evidencePath, "utf8")) as Partial<ProofEvidence>;
    return (
      record.kind === "proof-of-fix-evidence" &&
      record.script?.sha256 === sha256(readFileSync(scriptPath))
    );
  } catch {
    return false;
  }
}

function candidateLines(
  vulnerable: FetchedPackage,
  fixed: FetchedPackage,
  advisory: AdvisoryContext,
): string[] {
  try {
    const diff = findVulnerableSymbols(vulnerable.source, fixed.source, {
      hints: {
        text: [advisory.summary, advisory.details].filter(Boolean).join("\n"),
        cwes: advisory.cwes,
      },
      limit: 8,
    });
    return diff.candidates.map(
      (candidate) =>
        `${candidate.specifier} (export ${candidate.exportName}, in ${candidate.file}): ${candidate.reasons.slice(0, 3).join("; ")}`,
    );
  } catch {
    // The diff is only a hint for the agent; without it the agent reads the source itself.
    return [];
  }
}

/** Kept evidence in a patches directory, as the VEX output cites it. Stale evidence (the script changed) is left out. */
export function proofEvidenceRefs(cwd: string, patchesDir?: string): ProofEvidenceRef[] {
  return findEvidence(cwd, patchesDir ?? "./patches")
    .filter((found) => found.scriptCurrent)
    .map((found) => ({
      advisoryIds: [found.record.advisoryId, ...(found.record.aliases ?? [])],
      packageName: found.record.package,
      vulnerableVersion: found.record.vulnerableVersion,
      fixedVersion: found.record.fixedVersion,
      evidencePath: relativeTo(cwd, found.recordPath),
      scriptSha256: found.record.script.sha256,
      signed: found.signaturePath !== undefined,
    }));
}

/** The advisory id to work on: a normalised id, or a label that comes with advisoryText. */
function requireAdvisoryId(cveId: string, advisoryText: string | undefined): string {
  const typedId = cveId.trim();
  const advisoryId = isAdvisoryId(typedId) ? normalizeAdvisoryId(typedId) : typedId;
  if (advisoryId === "") {
    throw new Error(
      "Name the advisory: a CVE or GHSA id, or any label together with advisoryText.",
    );
  }
  if (!advisoryText && !isAdvisoryId(advisoryId)) {
    throw new Error(
      `"${advisoryId.slice(0, 80)}" is not an advisory id (CVE-, GHSA-, OSV-, MAL-). Give one, or pass advisoryText to describe the vulnerability yourself.`,
    );
  }
  return advisoryId;
}

function clampLimits(options: ProveOptions): { maxTrials: number; timeoutMs: number } {
  const maxTrials = Math.min(10, Math.max(1, Math.trunc(options.maxTrials ?? DEFAULT_MAX_TRIALS)));
  const timeoutMs = Math.min(
    60_000,
    Math.max(1000, Math.trunc(options.timeoutMs ?? DEFAULT_RUN_TIMEOUT_MS)),
  );
  return { maxTrials, timeoutMs };
}

/** Where the script and its evidence go; a script this command did not write is never replaced silently. */
function outputPaths(
  cwd: string,
  options: ProveOptions,
  packageName: string,
  vulnerableVersion: string,
): { patchesPath: string; scriptPath: string; evidencePath: string } {
  const patchesPath = resolvePatchesDir(cwd, options.patchesDir);
  const scriptPath = join(patchesPath, scriptFileName(packageName, vulnerableVersion));
  const evidencePath = join(
    patchesPath,
    `${baseName(packageName, vulnerableVersion)}${EVIDENCE_SUFFIX}`,
  );
  if (existsSync(scriptPath) && !options.overwrite && !ownedByEvidence(scriptPath, evidencePath)) {
    throw new Error(
      `${relativeTo(cwd, scriptPath)} already exists and was not written by this command. Review it, or pass overwrite to replace it.`,
    );
  }
  return { patchesPath, scriptPath, evidencePath };
}

async function fetchAndInstall(
  deps: ProveDeps,
  cwd: string,
  target: {
    packageName: string;
    vulnerable: { version: string; dir: string };
    fixed: { version: string; dir: string };
  },
): Promise<[FetchedPackage, FetchedPackage]> {
  const { packageName, vulnerable, fixed } = target;
  const [vulnerableFetched, fixedFetched] = await Promise.all([
    deps.fetchPackage(packageName, vulnerable.version, cwd),
    deps.fetchPackage(packageName, fixed.version, cwd),
  ]);
  await Promise.all([
    deps.install(vulnerable.dir, vulnerableFetched, cwd),
    deps.install(fixed.dir, fixedFetched, cwd),
  ]);
  return [vulnerableFetched, fixedFetched];
}

function rejectedProof(
  base: Omit<ProveResult, "status" | "reason">,
  trials: TrialSummary[],
  outcome: { status: string; rationale: string },
): ProveResult {
  const last = trials.at(-1);
  return {
    ...base,
    status: "rejected",
    reason: last
      ? `No script was kept. The last one was rejected: ${last.reason}`
      : `No script was kept: the agent proposed none (${outcome.status}: ${outcome.rationale}).`,
  };
}

/** The advisory, the package it is about and the two versions to compare. */
async function resolveTarget(
  deps: ProveDeps,
  options: ProveOptions,
  advisoryId: string,
  cwd: string,
) {
  const looked = isAdvisoryId(advisoryId) ? await deps.lookupAdvisory(advisoryId) : undefined;
  if (!looked && !options.advisoryText) {
    throw new Error(
      `${advisoryId} was not found in OSV. Check the id, or pass advisoryText with the package and versions.`,
    );
  }
  const advisory = contextFor(looked?.context.id ?? advisoryId, looked, options.advisoryText);
  const packageName = choosePackage(options.package, looked?.affected ?? []);
  const published = options.vulnerableVersion ? [] : await deps.listVersions(packageName, cwd);
  const { vulnerableVersion, fixedVersion } = chooseVersions({
    packageName,
    affected: looked?.affected ?? [],
    published,
    vulnerableVersion: options.vulnerableVersion,
    fixedVersion: options.fixedVersion,
  });
  return { advisory, packageName, vulnerableVersion, fixedVersion };
}

function proofHeader(input: {
  advisoryId: string;
  packageName: string;
  vulnerableVersion: string;
  fixedVersion: string;
  trials: TrialSummary[];
  agent: ReproductionAgent;
  outcome: ReproductionOutcome;
  sandbox: SandboxReport;
}) {
  const { advisoryId, packageName, vulnerableVersion, fixedVersion } = input;
  const { trials, agent, outcome, sandbox } = input;
  return {
    schemaVersion: "1.0" as const,
    advisoryId,
    package: packageName,
    vulnerableVersion,
    fixedVersion,
    trials,
    agent: { id: agent.id, status: outcome.status, rationale: outcome.rationale },
    usage: outcome.usage,
    sandbox,
  };
}

/** A scratch directory holding one directory per version, so the two never share files. */
function createWorkDirs(): { root: string; vulnerableDir: string; fixedDir: string } {
  const root = realpathSync(mkdtempSync(join(tmpdir(), "autoremediator-prove-")));
  const vulnerableDir = join(root, "vulnerable");
  const fixedDir = join(root, "fixed");
  mkdirSync(vulnerableDir);
  mkdirSync(fixedDir);
  return { root, vulnerableDir, fixedDir };
}
