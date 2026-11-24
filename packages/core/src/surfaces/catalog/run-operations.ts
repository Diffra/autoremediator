import { z } from "zod";

import type { UpdateOutdatedOptions } from "../../api/index.js";
import {
  applyPlanOptionsSchema,
  attemptQuerySchema,
  proposePatchOptionsSchema,
  startAttemptOptionsSchema,
  verifyAttemptOptionsSchema,
  listRunsOptionsSchema,
  rollbackRunOptionsSchema,
  runQuerySchema,
  updateOutdatedOptionsSchema,
  verifyRunOptionsSchema,
} from "../../features/remediate/option-schemas.js";
import { defineOperation, type Operation } from "./define-operation.js";
import { sdkOptions, READ_ONLY, MUTATING, ROLLBACK, PLANNING } from "./operation-parts.js";
import { RESPONSES } from "./responses.js";

export const RUN_OPERATIONS: readonly Operation[] = [
  defineOperation({
    name: "applyPlan",
    title: "Apply a plan",
    description:
      "Apply the plan from a planRemediation run (by runId or planId). The project's manifests and lockfiles are snapshotted first, each item is recorded as it is attempted and verified, and the run can be resumed or rolled back. Refused if the project, lockfiles or policy changed since the plan was made. If an upgrade breaks the project's checks and a model is configured, an agent repairs the project's source in an isolated checkout and the result is kept only if the verifier accepts it. Model-generated patches are not part of a plan.",
    input: applyPlanOptionsSchema,
    annotations: MUTATING,
    response: RESPONSES.runReport,
    mcp: true,
    http: { method: "POST", path: "/runs/apply", positional: ["runId", "planId"] },
    handler: ({ maxRepairRounds, ...options }, context) =>
      context.api.applyPlanFn({
        ...options,
        ...(maxRepairRounds ? { repairBudget: { maxRepairRounds } } : {}),
      }),
  }),
  defineOperation({
    name: "resumeRun",
    title: "Resume a run",
    description:
      "Continue a run that was interrupted or ended partial or failed, skipping items already applied. Refused if the project changed since the run's last completed step.",
    input: runQuerySchema,
    annotations: MUTATING,
    response: RESPONSES.runReport,
    mcp: true,
    http: { method: "POST", path: "/runs/resume", positional: ["runId"] },
    handler: (options, context) => context.api.resumeRunFn(options),
  }),
  defineOperation({
    name: "rollbackRun",
    title: "Roll back a run",
    description:
      "Undo a run by restoring the manifests, lockfiles and patch files it changed from the snapshot taken before its first change. Refused if the project changed since the run's last step, unless force is set. Run your package manager's install afterwards to refresh node_modules.",
    input: rollbackRunOptionsSchema,
    annotations: ROLLBACK,
    response: RESPONSES.rollbackReport,
    mcp: true,
    http: { method: "POST", path: "/runs/rollback", positional: ["runId"] },
    handler: (options, context) => context.api.rollbackRunFn(options),
  }),
  defineOperation({
    name: "verifyRun",
    runsProjectCode: true,
    title: "Verify a run",
    description:
      "Judge a run's project as it is now with deterministic checks, cheapest first, stopping at the first failure: scope (only dependency files changed), policy, supply-chain gate, frozen install, advisories no longer matching installed packages, then type check, tests and the reproduction test when requested. No model is consulted. The result is stored with the run.",
    input: verifyRunOptionsSchema,
    annotations: PLANNING,
    response: RESPONSES.verification,
    mcp: true,
    http: { method: "POST", path: "/runs/verify", positional: ["runId"] },
    handler: (options, context) => context.api.verifyRunFn(options),
  }),
  defineOperation({
    name: "startAttempt",
    runsProjectCode: true,
    title: "Start an attempt",
    description:
      "Open an isolated checkout of the project with one plan item's upgrade applied and installed, so you can make the project work with it. Returns the checkout path (edit files there, or send diffs with proposePatch) and what the verifier found wrong. The project itself is not touched. Finish with finalizeAttempt, or abandonAttempt.",
    input: startAttemptOptionsSchema,
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: true,
    },
    response: RESPONSES.attemptView,
    mcp: true,
    http: { method: "POST", path: "/attempts/start", positional: ["runId", "itemId"] },
    handler: (options, context) => context.api.startAttemptFn(options),
  }),
  defineOperation({
    name: "proposePatch",
    runsProjectCode: true,
    title: "Apply a patch to an attempt",
    description:
      "Apply a unified diff to an open attempt's checkout. Only project source (.js/.ts and variants) may change, the patch must be plain text and apply cleanly. Verify with verifyAttempt afterwards.",
    input: proposePatchOptionsSchema,
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false,
    },
    response: RESPONSES.attemptView,
    mcp: true,
    http: { method: "POST", path: "/attempts/patch", positional: ["runId", "attemptId", "diff"] },
    handler: (options, context) => context.api.proposePatchFn(options),
  }),
  defineOperation({
    name: "verifyAttempt",
    runsProjectCode: true,
    title: "Verify an attempt",
    description:
      "Run the verifier on an open attempt's checkout: scope, policy, supply chain, advisories, and the project's type check, tests and reproduction test when requested. Returns what is wrong, if anything, so you can fix it. It is the same judge that decides finalizeAttempt.",
    input: verifyAttemptOptionsSchema,
    annotations: PLANNING,
    response: RESPONSES.attemptView,
    mcp: true,
    http: { method: "POST", path: "/attempts/verify", positional: ["runId", "attemptId"] },
    handler: (options, context) => context.api.verifyAttemptFn(options),
  }),
  defineOperation({
    name: "finalizeAttempt",
    title: "Finalize an attempt",
    description:
      "Put an open attempt's change in the project. The checkout is verified once more; if it passes, the change is applied as a patch, checked again in the project and removed if that fails. Returns finalized: false, with what is wrong, when it does not verify. Roll back later with rollbackRun.",
    input: attemptQuerySchema,
    annotations: MUTATING,
    response: RESPONSES.attemptView,
    mcp: true,
    http: { method: "POST", path: "/attempts/finalize", positional: ["runId", "attemptId"] },
    handler: (options, context) => context.api.finalizeAttemptFn(options),
  }),
  defineOperation({
    name: "abandonAttempt",
    title: "Abandon an attempt",
    description:
      "Throw an open attempt away: its checkout is removed and nothing reaches the project.",
    input: attemptQuerySchema,
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
    response: RESPONSES.attemptView,
    mcp: true,
    http: { method: "POST", path: "/attempts/abandon", positional: ["runId", "attemptId"] },
    handler: (options, context) => context.api.abandonAttemptFn(options),
  }),
  defineOperation({
    name: "getRun",
    title: "Get a run",
    description:
      "Return a run's record, its plan, the outcome of each attempted item, and its step ledger with a check that the ledger has not been altered.",
    input: runQuerySchema,
    annotations: READ_ONLY,
    response: RESPONSES.runDetails,
    mcp: true,
    http: { method: "POST", path: "/runs/get", positional: ["runId"] },
    handler: (options, context) => context.api.getRunFn(options),
  }),
  defineOperation({
    name: "listRuns",
    title: "List runs",
    description: "List recorded runs in a project, newest first, optionally filtered by status.",
    input: listRunsOptionsSchema,
    annotations: READ_ONLY,
    response: RESPONSES.runList,
    mcp: true,
    http: { method: "POST", path: "/runs/list", positional: [] },
    handler: (options, context) => context.api.listRunsFn(options),
  }),
  defineOperation({
    name: "updateOutdated",
    title: "Update outdated packages",
    description:
      "Bump all outdated npm packages to their latest versions without requiring a CVE ID. Respects policy (allowMajorBumps) and supports dry-run. Returns an UpdateOutdatedReport.",
    input: updateOutdatedOptionsSchema,
    annotations: MUTATING,
    response: RESPONSES.updateOutdatedReport,
    mcp: true,
    http: { method: "POST", path: "/update-outdated", positional: [] },
    handler: (options, context) =>
      context.api.updateOutdatedFn(sdkOptions(options, context) as UpdateOutdatedOptions),
  }),
  defineOperation({
    name: "toVex",
    title: "Convert a report to VEX",
    description:
      "Convert a ScanReport or RemediationReport to a CycloneDX VEX document (1.5 by default; specVersion 1.6 adds affects by purl and schema-valid justifications). Returns a compliance-ready vulnerability exploitability exchange record binding remediation evidence to SBOM vulnerability entries.",
    input: z
      .object({
        report: z
          .record(z.string(), z.unknown(), "report is required (object)")
          .describe(
            "A ScanReport or RemediationReport object returned by remediate, planRemediation, or remediateFromScan.",
          ),
        toolVersion: z
          .string()
          .optional()
          .describe("Optional tool version to embed in the VEX document metadata."),
        specVersion: z
          .enum(["1.5", "1.6"])
          .optional()
          .describe(
            "CycloneDX version to emit. Default 1.5. 1.6 adds affects by purl and uses justifications the CycloneDX schema defines.",
          ),
      })
      .strict(),
    annotations: READ_ONLY,
    response: RESPONSES.vexDocument,
    mcp: true,
    http: { method: "POST", path: "/vex", positional: ["report"] },
    handler: ({ report, toolVersion, specVersion }, context) =>
      context.api.toVexFn(
        report as unknown as Parameters<typeof context.api.toVexFn>[0],
        toolVersion || specVersion
          ? { ...(toolVersion ? { toolVersion } : {}), ...(specVersion ? { specVersion } : {}) }
          : undefined,
      ),
  }),
];
