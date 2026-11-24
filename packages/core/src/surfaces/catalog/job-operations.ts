import { z } from "zod";

import type { PortfolioTarget, RemediateOptions, ScanOptions } from "../../api/index.js";
import {
  remediateOptionsSchema,
  scanOptionsSchema,
} from "../../features/remediate/option-schemas.js";
import { OPTION_DESCRIPTIONS } from "../../infra/policy/schemas.js";
import { defineOperation, type Operation } from "./define-operation.js";
import { cveId, inputPath, targets, sdkOptions, READ_ONLY, MUTATING } from "./operation-parts.js";
import { RESPONSES } from "./responses.js";

export const JOB_OPERATIONS: readonly Operation[] = [
  defineOperation({
    name: "submitRemediateJob",
    title: "Submit a remediation job",
    description:
      "Submit a single-CVE remediation as a background async job. Returns a JobHandle immediately with a jobId. Use pollJob to check status and retrieve the result.",
    input: z
      .object({ cveId: cveId.describe(OPTION_DESCRIPTIONS.cveId), ...remediateOptionsSchema.shape })
      .strict(),
    annotations: MUTATING,
    response: RESPONSES.jobHandle,
    mcp: true,
    http: { method: "POST", path: "/jobs/remediate", positional: ["cveId"], status: 202 },
    handler: ({ cveId: id, ...options }, context) =>
      context.api.submitRemediateJobFn(id, sdkOptions(options, context) as RemediateOptions),
  }),
  defineOperation({
    name: "submitScanJob",
    title: "Submit a scan remediation job",
    description:
      "Submit a scan-file remediation as a background async job. Returns a JobHandle immediately. Use pollJob to check status.",
    input: z.object({ inputPath, ...scanOptionsSchema.shape }).strict(),
    annotations: MUTATING,
    response: RESPONSES.jobHandle,
    mcp: true,
    http: { method: "POST", path: "/jobs/scan", positional: ["inputPath"], status: 202 },
    handler: ({ inputPath: path, ...options }, context) =>
      context.api.submitScanJobFn(path, sdkOptions(options, context) as ScanOptions),
  }),
  defineOperation({
    name: "submitPortfolioJob",
    title: "Submit a portfolio job",
    description:
      "Submit a portfolio remediation as a background async job. Returns a JobHandle immediately. Use pollJob to check status.",
    input: z.object({ targets, ...remediateOptionsSchema.shape }).strict(),
    annotations: MUTATING,
    response: RESPONSES.jobHandle,
    mcp: true,
    http: { method: "POST", path: "/jobs/portfolio", positional: ["targets"], status: 202 },
    handler: ({ targets: list, ...options }, context) =>
      context.api.submitPortfolioJobFn(
        list as PortfolioTarget[],
        sdkOptions(options, context) as RemediateOptions,
      ),
  }),
  defineOperation({
    name: "pollJob",
    title: "Poll a job",
    description:
      "Poll the status of a submitted background job. Returns the full AsyncRemediationJob including result when status is 'done' or error when 'failed'.",
    input: z
      .object({
        jobId: z
          .string("jobId is required (string)")
          .min(1, "jobId is required (string)")
          .describe("Job ID returned by submitRemediateJob, submitScanJob, or submitPortfolioJob."),
      })
      .strict(),
    annotations: READ_ONLY,
    response: RESPONSES.job,
    mcp: true,
    http: { method: "GET", path: "/jobs/:jobId", pathParam: "jobId" },
    handler: ({ jobId }, context) => context.api.pollJobFn(jobId),
  }),
];
