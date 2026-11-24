/**
 * What a pack reads from recorded runs: the run store, the runs chosen, their SBOM entries and the
 * fingerprint of the current files. Every import of another feature's internals the pack needs is
 * kept in this one file.
 */
import type { SbomEntry } from "../../remediate/types.js";
import { fingerprintRepo } from "../../runs/fingerprint.js";
import { isRunId } from "../../runs/ids.js";
import { RunStore } from "../../runs/run-store.js";
import { factKey } from "./components.js";

export { loadProjectLocks } from "../../incident/project.js";

export type { RunStore };
export type RecordedRun = ReturnType<RunStore["list"]>[number];

export interface RecordedRuns {
  store: RunStore;
  runs: RecordedRun[];
}

/** The runs named by `runIds`, or every recorded run. Unknown ids are refused. */
export function readRecordedRuns(input: {
  cwd: string;
  runIds: string[] | undefined;
  notes: string[];
}): RecordedRuns {
  const { cwd, runIds, notes } = input;
  const store = new RunStore(cwd);
  for (const runId of runIds ?? []) {
    if (!isRunId(runId) || !store.exists(runId)) throw new Error(`Run not found: ${runId}`);
  }
  const runs = runIds ? runIds.map((runId) => store.load(runId)) : store.list();
  if (runs.length === 0) {
    notes.push(
      "No recorded runs were found under .autoremediator/runs/, so the pack has no run attestations and no run-based VEX statements.",
    );
  }
  return { store, runs };
}

export function sortByCreation(runs: RecordedRun[]): RecordedRun[] {
  return runs.toSorted((a, b) => a.createdAt.localeCompare(b.createdAt));
}

/** Report SBOM entries: newest run wins per package version. */
export function collectReportEntries({ store, runs }: RecordedRuns): Map<string, SbomEntry> {
  const reportEntries = new Map<string, SbomEntry>();
  for (const run of sortByCreation(runs)) {
    for (const entry of store.readReport(run.runId)?.sbom ?? []) {
      reportEntries.set(factKey(entry.name, entry.version), entry);
    }
  }
  return reportEntries;
}

/** Fingerprint of the project files as they are now, to tell whether a run's inputs still hold. */
export async function fingerprintCurrentFiles(
  cwd: string,
  policy: string | undefined,
): Promise<string> {
  return (await fingerprintRepo(cwd, policy)).filesSha256;
}
