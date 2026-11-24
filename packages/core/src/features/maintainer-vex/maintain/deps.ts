/** The outside world `maintain` talks to, replaceable so tests need no network. */
import { checkReachability } from "../../reachability/index.js";
import type { CheckReachabilityOptions, ReachabilityAssessment } from "../../reachability/types.js";
import { planRemediation } from "../../remediate/index.js";
import type { RemediateOptions, RemediationReport } from "../../remediate/types.js";
import { parseScanInputFromAudit, uniqueCveIds } from "../../scan/index.js";
import type { MaintainOptions } from "./types.js";

export interface MaintainDeps {
  findAdvisories(cwd: string, options: MaintainOptions): Promise<string[]>;
  plan(id: string, options: RemediateOptions): Promise<RemediationReport>;
  reachability(options: CheckReachabilityOptions): Promise<ReachabilityAssessment>;
  now(): Date;
}

export const defaultDeps: MaintainDeps = {
  async findAdvisories(cwd, options) {
    if (options.offlineIntelligence) {
      throw new Error(
        "Audit needs the network. With offlineIntelligence, name the advisories to assess (advisories) and give an intelligenceSnapshotPath.",
      );
    }
    const findings = await parseScanInputFromAudit({
      cwd,
      packageManager: options.packageManager,
      format: "auto",
    });
    return uniqueCveIds(findings);
  },
  plan: planRemediation,
  reachability: checkReachability,
  now: () => new Date(),
};
