/**
 * Tool: apply-version-bump
 *
 * Updates the consumer's package.json to the safe version and runs npm install.
 * Respects --dry-run: in dry-run mode it reports what would happen but writes nothing.
 */
import { withRepoLock } from "../../infra/repo-lock.js";
import { defineTool } from "../remediate/tools/tool-compat.js";
import type { PatchResult } from "../remediate/types.js";
import { versionBumpInputSchema } from "./version-bump-input.js";
import { planVersionBump } from "./version-bump-plan.js";
import { runVersionBump } from "./version-bump-run.js";

export const applyVersionBumpTool = defineTool({
  description:
    "Update package.json to use the safe version of a vulnerable package and run the project's package manager install. In dry-run mode, only reports what would change.",
  inputSchema: versionBumpInputSchema,
  execute: async (input): Promise<PatchResult> => {
    const planned = await planVersionBump(input);
    if (planned.kind === "result") {
      return planned.result;
    }
    return withRepoLock(input.cwd, () => runVersionBump(input, planned.plan));
  },
});
