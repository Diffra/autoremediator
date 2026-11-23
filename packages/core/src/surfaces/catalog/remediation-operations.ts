import { z } from "zod";

import type { PortfolioTarget, RemediateOptions, ScanOptions } from "../../api/index.js";
import { HOOK_MANAGERS, HOOK_NAMES } from "../../features/hooks/types.js";
import { AGENT_HOSTS } from "../../features/init/types.js";
import {
  patchArtifactQuerySchema,
  patchFilePathSchema,
  reconcileOptionsSchema,
  remediateOptionsSchema,
  scanOptionsSchema,
} from "../../features/remediate/option-schemas.js";
import { OPTION_DESCRIPTIONS, pathField } from "../../infra/policy/schemas.js";
import { PACKAGE_VERSION } from "../../shared/version.js";
import { defineOperation, type Operation } from "./define-operation.js";
import {
  cveId,
  inputPath,
  targets,
  sdkOptions,
  planOptionShape,
  READ_ONLY,
  MUTATING,
  PLANNING,
} from "./operation-parts.js";
import { RESPONSES } from "./responses.js";

export const REMEDIATION_OPERATIONS: readonly Operation[] = [
  defineOperation({
    name: "health",
    title: "Health check",
    description:
      "Health check tool that returns server readiness status, version, registered tool count, and the list of available capability names.",
    input: z.object({}).strict(),
    annotations: READ_ONLY,
    response: RESPONSES.health,
    mcp: true,
    handler: async (_input, context) => ({
      ...(await context.api.healthFn()),
      version: PACKAGE_VERSION,
      toolCount: context.operationNames.length,
      capabilities: context.operationNames,
    }),
  }),
  defineOperation({
    name: "init",
    title: "Set up a project",
    description:
      "Set the project up for Autoremediator and the coding agents it uses: policy file, .gitignore, MCP configuration per agent host, agent instructions. Reports what it would change unless yes is set. Command line and SDK only.",
    input: z
      .object({
        cwd: pathField(OPTION_DESCRIPTIONS.cwd).optional(),
        hosts: z
          .array(z.enum(AGENT_HOSTS))
          .optional()
          .describe(
            "Agent hosts to configure. Default: those found in the project, else those installed.",
          ),
        ci: z
          .boolean()
          .optional()
          .describe("Also write a weekly remediation workflow for GitHub Actions."),
        policy: z
          .boolean()
          .optional()
          .describe("Write the policy file when missing. Default true."),
        guard: z
          .boolean()
          .optional()
          .describe(
            "Also install guard hooks for Claude Code, Cursor and Copilot, and a pnpmfile for pnpm projects, so package installs are checked first. Default false.",
          ),
        agentsMd: z
          .boolean()
          .optional()
          .describe("Add an Autoremediator section to AGENTS.md. Default true."),
        yes: z.boolean().optional().describe("Write the changes. Without it, only report them."),
        check: z.boolean().optional().describe("Report drift only; never write."),
      })
      .strict(),
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
    response: RESPONSES.init,
    mcp: false,
    handler: (options, context) => context.api.initFn(options),
  }),
  defineOperation({
    name: "installHooks",
    title: "Install git hooks",
    description:
      "Install, remove or check git hooks that run Autoremediator: pre-push blocks a push whose lockfile changes make the project less safe, post-merge prints a one-line advisory. Detects husky, lefthook, the pre-commit framework or plain git hooks and writes a marked block, never overwriting what it cannot merge. Reports what it would change unless yes is set. Command line and SDK only.",
    input: z
      .object({
        cwd: pathField(OPTION_DESCRIPTIONS.cwd).optional(),
        hooks: z
          .array(z.enum(HOOK_NAMES))
          .optional()
          .describe("Hooks to handle. Default: pre-push and post-merge."),
        manager: z
          .enum(HOOK_MANAGERS)
          .optional()
          .describe(
            "Hook manager to write for. Default: detected (husky, lefthook, pre-commit, else git).",
          ),
        uninstall: z.boolean().optional().describe("Remove the hooks Autoremediator installed."),
        yes: z.boolean().optional().describe("Write the changes. Without it, only report them."),
        check: z.boolean().optional().describe("Report drift only; never write."),
        allowSharedHooksPath: z
          .boolean()
          .optional()
          .describe(
            "Write into a hooks folder outside the repository (a global core.hooksPath shared with other repositories). Default: report it as a conflict.",
          ),
      })
      .strict(),
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: true,
      openWorldHint: false,
    },
    response: RESPONSES.installHooks,
    mcp: false,
    handler: (options, context) => context.api.installHooksFn(options),
  }),
  defineOperation({
    name: "remediate",
    title: "Remediate a CVE",
    description:
      "Remediate a single CVE in a Node.js project. Looks up the CVE, scans the project inventory, and applies a version bump or generates a patch file. Returns a RemediationReport.",
    input: z
      .object({ cveId: cveId.describe(OPTION_DESCRIPTIONS.cveId), ...remediateOptionsSchema.shape })
      .strict(),
    annotations: MUTATING,
    response: RESPONSES.remediationReport,
    mcp: true,
    http: { method: "POST", path: "/remediate", positional: ["cveId"] },
    handler: ({ cveId: id, ...options }, context) =>
      context.api.remediateFn(id, sdkOptions(options, context) as RemediateOptions),
  }),
  defineOperation({
    name: "planRemediation",
    title: "Preview a remediation",
    description:
      "Generate a non-mutating remediation preview for a single CVE in a Node.js project. Returns a RemediationReport with planned results.",
    input: z
      .object({ cveId: cveId.describe(OPTION_DESCRIPTIONS.cveId), ...planOptionShape })
      .strict(),
    annotations: PLANNING,
    response: RESPONSES.remediationReport,
    mcp: true,
    http: { method: "POST", path: "/plan-remediation", positional: ["cveId"] },
    handler: ({ cveId: id, ...options }, context) =>
      context.api.planRemediationFn(id, sdkOptions(options, context) as RemediateOptions),
  }),
  defineOperation({
    name: "remediateFromScan",
    title: "Remediate from a scan file",
    description:
      "Parse an npm/pnpm/yarn/bun audit JSON or SARIF scan file, extract all CVE IDs, and remediate each one. Returns a ScanReport.",
    input: z.object({ inputPath, ...scanOptionsSchema.shape }).strict(),
    annotations: MUTATING,
    response: RESPONSES.scanReport,
    mcp: true,
    http: { method: "POST", path: "/remediate-from-scan", positional: ["inputPath"] },
    handler: ({ inputPath: path, ...options }, context) =>
      context.api.remediateFromScanFn(path, sdkOptions(options, context) as ScanOptions),
  }),
  defineOperation({
    name: "remediatePortfolio",
    title: "Remediate a portfolio",
    description:
      "Run CVE or scan remediation across multiple targets and return an aggregated PortfolioReport.",
    input: z.object({ targets, ...remediateOptionsSchema.shape }).strict(),
    annotations: MUTATING,
    response: RESPONSES.portfolioReport,
    mcp: true,
    http: { method: "POST", path: "/remediate-portfolio", positional: ["targets"] },
    handler: ({ targets: list, ...options }, context) =>
      context.api.remediatePortfolioFn(
        list as PortfolioTarget[],
        sdkOptions(options, context) as RemediateOptions,
      ),
  }),
  defineOperation({
    name: "listPatchArtifacts",
    title: "List patch artifacts",
    description:
      "List stored patch artifacts in the configured patches directory. Returns patch summaries with manifest metadata when available.",
    input: patchArtifactQuerySchema,
    annotations: READ_ONLY,
    response: RESPONSES.patchSummaries,
    mcp: true,
    http: { method: "POST", path: "/patches/list", positional: [] },
    handler: (options, context) => context.api.listPatchArtifactsFn(options),
  }),
  defineOperation({
    name: "inspectPatchArtifact",
    title: "Inspect a patch artifact",
    description: "Inspect a stored .patch file and its optional manifest metadata.",
    input: z
      .object({ patchFilePath: patchFilePathSchema, ...patchArtifactQuerySchema.shape })
      .strict(),
    annotations: READ_ONLY,
    response: RESPONSES.patchInspection,
    mcp: true,
    http: { method: "POST", path: "/patches/inspect", positional: ["patchFilePath"] },
    handler: ({ patchFilePath, ...options }, context) =>
      context.api.inspectPatchArtifactFn(patchFilePath, options),
  }),
  defineOperation({
    name: "validatePatchArtifact",
    title: "Validate a patch artifact",
    description:
      "Validate a stored patch artifact against its manifest and the current dependency inventory.",
    input: z
      .object({ patchFilePath: patchFilePathSchema, ...patchArtifactQuerySchema.shape })
      .strict(),
    annotations: READ_ONLY,
    response: RESPONSES.patchValidation,
    mcp: true,
    http: { method: "POST", path: "/patches/validate", positional: ["patchFilePath"] },
    handler: ({ patchFilePath, ...options }, context) =>
      context.api.validatePatchArtifactFn(patchFilePath, options),
  }),
  defineOperation({
    name: "reconcilePatchArtifacts",
    title: "Reconcile patch artifacts",
    description:
      "Check each stored patch against upstream advisories and report which are obsolete because a fixed release now exists. With autoApply, bump to the fixed version and retire the patch.",
    input: reconcileOptionsSchema,
    annotations: MUTATING,
    response: RESPONSES.patchReconciliation,
    mcp: true,
    http: { method: "POST", path: "/patches/reconcile", positional: [] },
    handler: (options, context) => context.api.reconcilePatchArtifactsFn(options),
  }),
];
