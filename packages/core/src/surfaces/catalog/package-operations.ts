import { z } from "zod";

import {
  attemptQuerySchema,
  deltaScanOptionsSchema,
  evaluatePackageOptionsSchema,
  getAutonomyOptionsSchema,
  packageNameSchema,
} from "../../features/remediate/option-schemas.js";
import { OPTION_DESCRIPTIONS, pathField } from "../../infra/policy/schemas.js";
import { defineOperation, type Operation } from "./define-operation.js";
import { exactVersion, READ_ONLY, READ_ONLY_NETWORK, MUTATING } from "./operation-parts.js";
import { RESPONSES } from "./responses.js";

export const PACKAGE_OPERATIONS: readonly Operation[] = [
  defineOperation({
    name: "checkReachability",
    title: "Check reachability",
    description:
      "Scan project source files using oxc-parser AST call-graph tracing to check if a package or vulnerable symbol is reachable and invoked. With traceFile, adds runtime evidence from a traced test run.",
    input: z
      .object({
        packageName: packageNameSchema.describe(
          "Target package name to trace in project source files.",
        ),
        cwd: pathField(OPTION_DESCRIPTIONS.cwd).optional(),
        symbol: z
          .string()
          .optional()
          .describe(
            "Optional specific vulnerable function or export symbol to verify in call graph.",
          ),
        traceFile: pathField(OPTION_DESCRIPTIONS.traceFile).optional(),
      })
      .strict(),
    annotations: READ_ONLY,
    response: RESPONSES.reachability,
    mcp: true,
    http: { method: "POST", path: "/reachability", positional: ["packageName"] },
    handler: ({ packageName, cwd, symbol, traceFile }, context) =>
      context.api.checkReachabilityFn({ packageName, cwd, symbol, traceFile }),
  }),
  defineOperation({
    name: "evaluatePackage",
    title: "Evaluate a package",
    description:
      "Pre-flight security evaluator for npm packages. Queries OSV, CISA KEV, and FIRST EPSS telemetry before installation.",
    input: z
      .object({
        packageName: packageNameSchema.describe("Package name to evaluate."),
        ...evaluatePackageOptionsSchema.shape,
      })
      .strict(),
    annotations: READ_ONLY_NETWORK,
    response: RESPONSES.packageEvaluation,
    mcp: true,
    http: { method: "POST", path: "/packages/evaluate", positional: ["packageName"] },
    handler: ({ packageName, ...options }, context) =>
      context.api.evaluatePackageFn(packageName, options),
  }),
  defineOperation({
    name: "guardPackage",
    title: "Guard a package install",
    description:
      "Judge an npm package before it is installed: does it exist, is it known malware (OSV), does it imitate a popular package, is the release inside the cooldown, did it gain install scripts or lose provenance, does it have known vulnerabilities. Returns allow, warn or block with the findings and a safer alternative. Call this before adding any dependency. Installs nothing.",
    input: z
      .object({
        spec: z
          .string("spec is required (string)")
          .min(1, "spec is required (string)")
          .max(300)
          .describe(
            "Package to check, as you would pass it to npm install: name, name@range or @scope/name@range.",
          ),
        cwd: pathField(OPTION_DESCRIPTIONS.cwd).optional(),
        minPublishAgeHours: z
          .number()
          .min(0)
          .max(24 * 365)
          .optional()
          .describe(
            "Block releases younger than this many hours. Default 72; 0 turns the check off.",
          ),
        offline: z.boolean().optional().describe("Skip the OSV malware and advisory lookups."),
      })
      .strict(),
    annotations: READ_ONLY_NETWORK,
    response: RESPONSES.guardReport,
    mcp: true,
    http: { method: "POST", path: "/packages/guard", positional: ["spec"] },
    handler: ({ spec, ...options }, context) => context.api.guardPackageFn(spec, options),
  }),
  defineOperation({
    name: "getAutonomy",
    title: "Get the autonomy level",
    description:
      "Report the autonomy level a repository is at: the ceiling its policy sets (L0 observe, L1 suggest, L2 open pull request, L3 auto-merge eligible, L4 autonomous with escalation), the level its own verified track record has earned, the lower of the two, the evidence (verified runs, rollbacks, verifier failures, whether tests and type check were part of verification), every past promotion and demotion with the event behind it, and what the next promotion needs. Read-only. Reports configured: false when the policy has no autonomy key.",
    input: getAutonomyOptionsSchema,
    annotations: READ_ONLY,
    response: RESPONSES.autonomyStatus,
    mcp: true,
    http: { method: "POST", path: "/autonomy", positional: [] },
    handler: (options, context) => context.api.getAutonomyFn(options),
  }),
  defineOperation({
    name: "analyzeDependencies",
    title: "Analyse dependencies for removal",
    description:
      "Find what the project could stop depending on: declared dependencies nothing uses (certainly-unused, probably-unused or used-indirectly, each with its reason), micro-packages a Node built-in now replaces (checked against the project's declared Node range), the same package installed at several versions with who pulls each and whether a dedupe stays within range, and a 0-100 attack-surface score with its breakdown. Reads the project, lockfile and installed packages; needs no network and changes nothing.",
    input: z.object({ cwd: pathField(OPTION_DESCRIPTIONS.cwd).optional() }).strict(),
    annotations: READ_ONLY,
    response: RESPONSES.dietReport,
    mcp: true,
    http: { method: "POST", path: "/packages/diet", positional: [] },
    handler: ({ cwd }, context) => context.api.analyzeDependenciesFn({ cwd }),
  }),
  defineOperation({
    name: "removeUnusedDependencies",
    title: "Remove unused dependencies",
    description:
      "Remove only the dependencies analyzeDependencies calls certainly-unused through the package manager (npm or pnpm), then verify the result (scope, policy, frozen install, and the type check and tests when asked) and restore everything if any check fails. Never touches probably-unused dependencies, replaceable packages or duplicates. Command line and SDK only.",
    input: z
      .object({
        cwd: pathField(OPTION_DESCRIPTIONS.cwd).optional(),
        policy: pathField(OPTION_DESCRIPTIONS.policy).optional(),
        runTests: z
          .boolean()
          .optional()
          .describe("Run the project's tests as part of verification. Default false."),
        typecheck: z
          .boolean()
          .optional()
          .describe("Type-check as part of verification. Default true."),
      })
      .strict(),
    annotations: MUTATING,
    response: RESPONSES.dietApply,
    mcp: false,
    handler: (options, context) => context.api.removeUnusedDependenciesFn(options),
  }),
  defineOperation({
    name: "scanDelta",
    title: "Scan a git delta",
    description:
      "Git-aware delta vulnerability scanner. Identifies new CVEs introduced by uncommitted edits (vs HEAD) or branch differences (vs base branch).",
    input: deltaScanOptionsSchema,
    annotations: READ_ONLY_NETWORK,
    response: RESPONSES.deltaScan,
    mcp: true,
    http: { method: "POST", path: "/delta-scan", positional: [] },
    handler: (options, context) => context.api.scanDeltaFn(options),
  }),
  defineOperation({
    name: "listRecipes",
    title: "List recipes",
    description:
      "List the recipes available to the project: what earlier agent repairs learned about adopting a dependency's new version, kept as data (the project's committed .autoremediator/recipes, policy recipe packages, packages shipping their own). Filter by package and versions; pass recipeId for one recipe's full hunks. Read-only; recipes are never executed.",
    input: z
      .object({
        cwd: pathField(OPTION_DESCRIPTIONS.cwd).optional(),
        packageName: z
          .string()
          .min(1)
          .max(214)
          .optional()
          .describe("Only recipes for this package"),
        fromVersion: z
          .string()
          .min(1)
          .max(100)
          .optional()
          .describe("With toVersion: mark which recipes apply to upgrading from this version"),
        toVersion: z
          .string()
          .min(1)
          .max(100)
          .optional()
          .describe("With fromVersion: the version upgraded to"),
        recipeId: z.string().min(1).max(300).optional().describe("Include this recipe in full"),
      })
      .strict(),
    annotations: READ_ONLY,
    response: RESPONSES.recipeListing,
    mcp: true,
    http: { method: "POST", path: "/recipes/list", positional: [] },
    handler: (options, context) => context.api.listRecipesFn(options),
  }),
  defineOperation({
    name: "applyRecipe",
    runsProjectCode: true,
    title: "Apply a recipe to an attempt",
    description:
      "Apply a recipe to an open attempt's checkout and judge it: its hunks must match the project's source exactly (no fuzz), the resulting diff goes through the same validation as proposePatch, and the verifier decides. If it does not pass, the recipe is undone and the checkout is as it was. Recipe ids come from listRecipes or startAttempt.",
    input: attemptQuerySchema.extend({
      recipeId: z
        .string("recipeId is required (string)")
        .min(1)
        .max(300)
        .describe("Recipe id from listRecipes or startAttempt"),
    }),
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: false,
    },
    response: RESPONSES.attemptView,
    mcp: true,
    http: {
      method: "POST",
      path: "/attempts/recipe",
      positional: ["runId", "attemptId", "recipeId"],
    },
    handler: (options, context) => context.api.applyRecipeFn(options),
  }),
  defineOperation({
    name: "bisectLockfile",
    title: "Bisect a lockfile change",
    description:
      "Find which package update in the lockfile difference between a good and a bad git ref makes a shell command fail (a dependency published a bad release, CI broke with no code change). Installs both refs and subsets of the updates in isolated git worktrees, runs the command in them, narrows down with delta debugging, and returns the culprit (or the smallest set that fails only together) with the evidence and a plan that pins it back. Runs the given shell command with the caller's privileges, and package install scripts only when ignoreScripts is false. Command line and SDK only.",
    input: z
      .object({
        cwd: pathField(OPTION_DESCRIPTIONS.cwd).optional(),
        good: z
          .string("good is required (string)")
          .min(1, "good is required (string)")
          .max(300)
          .describe("Git ref (commit, tag or branch) where the command passes."),
        bad: z
          .string()
          .min(1)
          .max(300)
          .optional()
          .describe(
            "Git ref where the command fails. Default HEAD. The committed state is used, not the working tree.",
          ),
        command: z
          .string("command is required (string)")
          .min(1, "command is required (string)")
          .max(4000)
          .describe(
            "Shell command to run after installing; exit code 0 means pass. It runs in a checkout, never in the project directory.",
          ),
        timeoutSeconds: z
          .number()
          .positive()
          .max(86_400)
          .optional()
          .describe(
            "Kill the command after this many seconds and count it as failing. Default 600.",
          ),
        maxSteps: z
          .number()
          .int()
          .min(1)
          .max(500)
          .optional()
          .describe(
            "Evaluate at most this many candidate states, not counting the good and bad refs. Default 30.",
          ),
        packageManager: z
          .enum(["npm", "pnpm", "yarn"])
          .optional()
          .describe("Package manager. Default: from the lockfile at the bad ref."),
        ignoreScripts: z
          .boolean()
          .optional()
          .describe(
            "Pass --ignore-scripts to every install so package install scripts do not run. Default true; false lets them run.",
          ),
        apply: z
          .boolean()
          .optional()
          .describe(
            "Apply the recommended pin to the project through the run machinery. Without it the pin is only planned.",
          ),
      })
      .strict(),
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      idempotentHint: false,
      openWorldHint: true,
    },
    response: RESPONSES.bisectReport,
    mcp: false,
    handler: (options, context) => context.api.bisectLockfileFn(options),
  }),
  defineOperation({
    name: "assessUpgrade",
    title: "Assess an upgrade",
    description:
      "How likely is upgrading an npm package from one version to another to break this project? Downloads both versions, compares their public API (declaration files, else JavaScript exports), engines, module format, exports map and peer dependencies, then intersects the changes with the project's own usage. Returns a High, Medium or Low rating with the affected file:line call sites and the reasons. Deterministic and explainable; a heuristic that cannot see types for untyped packages. Changes nothing.",
    input: z
      .object({
        packageName: packageNameSchema.describe("Package to assess."),
        from: exactVersion.describe("Version the project uses now."),
        to: exactVersion.describe("Version being considered."),
        cwd: pathField(OPTION_DESCRIPTIONS.cwd).optional(),
      })
      .strict(),
    annotations: READ_ONLY_NETWORK,
    response: RESPONSES.upgradeImpact,
    mcp: true,
    http: {
      method: "POST",
      path: "/packages/assess-upgrade",
      positional: ["packageName", "from", "to"],
    },
    handler: (input, context) => context.api.assessUpgradeFn(input),
  }),
  defineOperation({
    name: "findVulnerableSymbols",
    title: "Find candidate vulnerable symbols",
    description:
      "Heuristic. Diff a vulnerable version of an npm package against the version that fixes it and list the exported functions, classes and files whose implementation changed (formatting and comments ignored), ranked by how closely the change matches the advisory text or CWE ids if given, with each candidate checked for reachability from the project's source. A changed symbol is a candidate, not proof it was the vulnerable one. Changes nothing.",
    input: z
      .object({
        packageName: packageNameSchema.describe("Package to diff."),
        from: exactVersion.describe("The vulnerable version."),
        to: exactVersion.describe("The version that fixes it."),
        cwd: pathField(OPTION_DESCRIPTIONS.cwd).optional(),
        advisoryText: z
          .string()
          .max(20_000)
          .optional()
          .describe("Advisory summary or details; used only to rank candidates."),
        cwes: z
          .array(z.string().max(20))
          .max(20)
          .optional()
          .describe("CWE ids such as CWE-1333; used only to rank candidates."),
        limit: z
          .number()
          .int()
          .min(1)
          .max(200)
          .optional()
          .describe("Largest number of candidates to return (default 25)."),
        checkReachability: z
          .boolean()
          .optional()
          .describe("Check each candidate against the project's source (default true)."),
      })
      .strict(),
    annotations: READ_ONLY_NETWORK,
    response: RESPONSES.vulnerableSymbols,
    mcp: true,
    http: {
      method: "POST",
      path: "/packages/vulnerable-symbols",
      positional: ["packageName", "from", "to"],
    },
    handler: (input, context) => context.api.findVulnerableSymbolsFn(input),
  }),
];
