/** One in-toto attestation per recorded run, wrapped in a DSSE envelope and signed when a key is given. */
import { PACKAGE_VERSION } from "../../../shared/version.js";
import { projectSubjects, buildRunStatement } from "./attest.js";
import { createEnvelope, type SigningKey } from "./dsse.js";
import { jsonText } from "./options.js";
import { fingerprintCurrentFiles, sortByCreation, type RecordedRuns } from "./run-inputs.js";
import type { EvidencePackResult, PackContents } from "./types.js";

export interface RunAttestations {
  contents: PackContents;
  attestations: EvidencePackResult["attestations"];
  skippedRuns: EvidencePackResult["skippedRuns"];
}

export async function buildRunAttestations(input: {
  cwd: string;
  policy: string | undefined;
  recorded: RecordedRuns;
  key: SigningKey | undefined;
  now: Date;
}): Promise<RunAttestations> {
  const { cwd, policy, recorded, key, now } = input;
  const { store, runs } = recorded;
  const subjects = projectSubjects(cwd);
  const currentFilesSha256 = await fingerprintCurrentFiles(cwd, policy);
  const contents: PackContents = new Map();
  const attestations: RunAttestations["attestations"] = [];
  const skippedRuns: RunAttestations["skippedRuns"] = [];
  for (const run of sortByCreation(runs)) {
    const built = buildRunStatement({
      store,
      run,
      subjects,
      currentFilesSha256,
      toolVersion: PACKAGE_VERSION,
      now,
    });
    if (!built.ok) {
      skippedRuns.push({ runId: run.runId, reason: built.reason });
      continue;
    }
    const body = JSON.stringify(built.statement);
    const envelope = createEnvelope(body, key);
    const base = `attestations/run-${run.runId}`;
    contents.set(`${base}.intoto.json`, { content: jsonText(envelope), kind: "attestation" });
    contents.set(`${base}.statement.json`, { content: `${body}\n`, kind: "statement" });
    attestations.push({
      runId: run.runId,
      runStatus: run.status,
      envelope: `${base}.intoto.json`,
      statement: `${base}.statement.json`,
      signed: key !== undefined,
      ledgerHead: built.ledgerHead,
    });
  }
  return { contents, attestations, skippedRuns };
}
