/** Assembling an evidence pack from what is on this machine, then writing it. */
import { resolve } from "node:path";

import { loadPolicy } from "../../../infra/policy/policy.js";
import { PACKAGE_VERSION } from "../../../shared/version.js";
import { buildCraDrafts, parseCraTiming } from "./cra-drafts.js";
import { loadSigningKey, type SigningKey } from "./dsse.js";
import { collectFindings, type FindingsResult, type VexStatus } from "./findings.js";
import {
  EVIDENCE_PACK_DISCLAIMER,
  PACK_STATEMENT_FILES,
  SIGNING_KEY_ENV,
  jsonText,
  type EvidencePackDeps,
  type EvidencePackOptions,
} from "./options.js";
import { renderReadme } from "./readme.js";
import { buildRunAttestations } from "./run-attestations.js";
import { collectReportEntries, loadProjectLocks, readRecordedRuns } from "./run-inputs.js";
import { buildSbom, productIdentity, type SbomBuild } from "./sbom.js";
import type { EvidencePackResult, PackContents } from "./types.js";
import { buildCycloneDxVex, buildOpenVex } from "./vex.js";
import { writePack } from "./write-pack.js";

/**
 * Assemble an evidence pack from what is on this machine: a CycloneDX 1.6 SBOM of the lockfile,
 * CycloneDX and OpenVEX statements from policy suppressions and recorded runs, Article 14
 * reporting drafts for CISA-KEV-listed advisories, and in-toto attestations of the recorded runs'
 * ledgers (signed only when a key is given), with a manifest of sha256 digests. Nothing is
 * fetched and nothing is submitted. Files are written only under `outDir`.
 */
export async function buildEvidencePack(
  options: EvidencePackOptions,
  deps: EvidencePackDeps = {},
): Promise<EvidencePackResult> {
  const now = (deps.now ?? (() => new Date()))();
  const cwd = resolve(options.cwd ?? process.cwd());
  const outDir = resolve(cwd, options.outDir);
  const env = deps.env ?? process.env;
  const notes: string[] = [];

  // Validate everything that can be refused before anything is written.
  const timing = parseCraTiming(options);
  const key = resolveSigningKey({ ...options, cwd }, env);
  const policy = loadPolicy(cwd, options.policy);
  const recorded = readRecordedRuns({ cwd, runIds: options.runIds, notes });

  const product = productIdentity(cwd, {
    ...(options.productName ? { name: options.productName } : {}),
    ...(options.productVersion ? { version: options.productVersion } : {}),
    ...(options.manufacturer ? { manufacturer: options.manufacturer } : {}),
  });
  const reportEntries = collectReportEntries(recorded);
  const locks = loadProjectLocks(cwd);
  const sbom = buildSbom({ cwd, product, locks, reportEntries, toolVersion: PACKAGE_VERSION, now });
  notes.push(...sbom.notes);

  const found = collectFindings({
    store: recorded.store,
    runs: recorded.runs,
    suppressions: policy.suppressions ?? [],
    locked: sbom.source === "report" ? undefined : sbom.locked,
  });
  notes.push(...found.notes);

  const cdxVex = buildCycloneDxVex({
    findings: found.findings,
    cves: found.cves,
    product,
    toolVersion: PACKAGE_VERSION,
    now,
  });
  const author = options.author ?? options.manufacturer;
  const openVex = buildOpenVex({
    findings: found.findings,
    product,
    ...(author ? { author } : {}),
    toolVersion: PACKAGE_VERSION,
    now,
  });

  const cra = buildCraDrafts({ found, product, timing, now, notes });
  const run = await buildRunAttestations({ cwd, policy: options.policy, recorded, key, now });
  for (const skipped of run.skippedRuns) {
    notes.push(`Run ${skipped.runId} has no attestation: ${skipped.reason}.`);
  }
  addSigningKeyFile(run.contents, key, notes);

  run.contents.set("sbom/sbom.cdx.json", { content: jsonText(sbom.bom), kind: "sbom" });
  run.contents.set("vex/vex.cdx.json", { content: jsonText(cdxVex), kind: "vex" });
  run.contents.set("vex/vex.openvex.json", { content: jsonText(openVex), kind: "vex" });
  for (const draft of cra.drafts) {
    run.contents.set(draft.path, { content: draft.content, kind: "cra-draft" });
  }

  const result = createResultSkeleton({
    outDir,
    now,
    key,
    sbom,
    found,
    craReports: cra.craReports,
    attestations: run.attestations,
    skippedRuns: run.skippedRuns,
    notes,
  });
  run.contents.set("README.md", { content: renderReadme(result, product), kind: "readme" });
  return writePack({ outDir, result, contents: run.contents, key });
}

function resolveSigningKey(
  options: EvidencePackOptions,
  env: NodeJS.ProcessEnv,
): SigningKey | undefined {
  const fromOption = options.signingKeyPath;
  // Remote callers (MCP, HTTP) must name the key themselves, inside the allowed roots; the
  // operator's environment key is not theirs to use.
  const trustedCaller =
    options.source === undefined || options.source === "cli" || options.source === "sdk";
  const fromEnv = trustedCaller ? env[SIGNING_KEY_ENV] : undefined;
  const path = fromOption ?? (fromEnv && fromEnv.trim() !== "" ? fromEnv : undefined);
  return path ? loadSigningKey(resolve(options.cwd ?? process.cwd(), path)) : undefined;
}

function addSigningKeyFile(
  contents: PackContents,
  key: SigningKey | undefined,
  notes: string[],
): void {
  if (key) {
    contents.set("attestations/signing-public-key.pem", {
      content: key.publicKeyPem,
      kind: "public-key",
    });
  } else {
    notes.push(
      `The attestations are unsigned (signatures: []). Pass --signing-key <pem> or set ${SIGNING_KEY_ENV} to sign them.`,
    );
  }
}

function countByStatus(findings: FindingsResult["findings"]): Record<VexStatus, number> {
  const byStatus: Record<VexStatus, number> = {
    fixed: 0,
    affected: 0,
    not_affected: 0,
    under_investigation: 0,
  };
  for (const finding of findings) byStatus[finding.status] += 1;
  return byStatus;
}

/** The pack's description before it is written: the file list and manifest digest are still empty. */
function createResultSkeleton(input: {
  outDir: string;
  now: Date;
  key: SigningKey | undefined;
  sbom: SbomBuild;
  found: FindingsResult;
  craReports: EvidencePackResult["craReports"];
  attestations: EvidencePackResult["attestations"];
  skippedRuns: EvidencePackResult["skippedRuns"];
  notes: string[];
}): EvidencePackResult {
  const { outDir, now, key, sbom, found } = input;
  return {
    schemaVersion: "1",
    outDir,
    generatedAt: now.toISOString(),
    disclaimer: EVIDENCE_PACK_DISCLAIMER,
    signed: key !== undefined,
    ...(key ? { signingKeyId: key.keyid, signingAlgorithm: key.algorithm } : {}),
    files: [],
    manifest: { path: "manifest.json", sha256: "", bytes: 0, kind: "manifest" },
    packAttestation: {
      envelope: PACK_STATEMENT_FILES[0]!,
      statement: PACK_STATEMENT_FILES[1]!,
      signed: key !== undefined,
      manifestSha256: "",
    },
    sbom: {
      file: "sbom/sbom.cdx.json",
      specVersion: "1.6",
      source: sbom.source,
      components: sbom.componentCount,
      withHash: sbom.withHash,
      withLicense: sbom.withLicense,
    },
    vex: {
      cycloneDxFile: "vex/vex.cdx.json",
      openVexFile: "vex/vex.openvex.json",
      statements: found.findings.length,
      byStatus: countByStatus(found.findings),
    },
    craReports: input.craReports,
    attestations: input.attestations,
    skippedRuns: input.skippedRuns,
    notes: input.notes,
  };
}
