/**
 * Every key of the policy file, and whether `findLoosenings` looks at it. A key ending in `.*` stands
 * for everything under it. `policy-loosening.test.ts` walks `policyFileSchema` and fails when a key
 * is missing here (or listed here but gone from the schema), so a new policy key has to be
 * classified, and a "loosening" one given a check, before it can ship.
 */
export const POLICY_KEY_COVERAGE: Readonly<
  Record<string, { kind: "loosening" } | { kind: "not-a-loosening"; reason: string }>
> = {
  allowMajorBumps: { kind: "loosening" },
  denyPackages: { kind: "loosening" },
  allowPackages: { kind: "loosening" },
  "constraints.directDependenciesOnly": { kind: "loosening" },
  "constraints.preferVersionBump": { kind: "loosening" },
  "constraints.installMode": {
    kind: "not-a-loosening",
    reason: "How dependencies are installed (offline or fresh); every mode verifies the same way.",
  },
  "constraints.installPreferOffline": {
    kind: "not-a-loosening",
    reason: "A cache preference for installs; it does not change what may be changed.",
  },
  "constraints.enforceFrozenLockfile": { kind: "loosening" },
  "constraints.workspace": {
    kind: "not-a-loosening",
    reason: "Scopes a run to one workspace package; it picks a target, not a safety rule.",
  },
  "constraints.typecheck": { kind: "loosening" },
  "constraints.requireProofOfFix": { kind: "loosening" },
  "constraints.enableBreakingChangeRefactor": { kind: "loosening" },
  "constraints.supplyChainPolicy.minPublishAgeHours": { kind: "loosening" },
  "constraints.supplyChainPolicy.blockInstallScripts": { kind: "loosening" },
  "constraints.supplyChainPolicy.requireProvenance": { kind: "loosening" },
  "patchConfidenceThresholds.low": { kind: "loosening" },
  "patchConfidenceThresholds.medium": { kind: "loosening" },
  "patchConfidenceThresholds.high": { kind: "loosening" },
  "exploitSignalOverride.kev.mandatory": { kind: "loosening" },
  "exploitSignalOverride.epss.mandatory": { kind: "loosening" },
  "exploitSignalOverride.epss.threshold": { kind: "loosening" },
  suppressions: { kind: "loosening" },
  "sla.critical": { kind: "loosening" },
  "sla.high": { kind: "loosening" },
  "sla.medium": { kind: "loosening" },
  "sla.low": { kind: "loosening" },
  skipUnreachable: { kind: "loosening" },
  trustMaintainerVex: { kind: "loosening" },
  installScripts: { kind: "loosening" },
  "dispositionPolicy.minConfidenceForAutoApply": { kind: "loosening" },
  "dispositionPolicy.holdForTransitive": { kind: "loosening" },
  "dispositionPolicy.escalateOnKev": { kind: "loosening" },
  "dispositionPolicy.escalateOnSlaBreachSeverities": { kind: "loosening" },
  containmentMode: { kind: "loosening" },
  "escalationGraph.*": { kind: "loosening" },
  "recipes.packages": { kind: "loosening" },
  "autonomy.ceiling": { kind: "loosening" },
  "autonomy.minVerifiedRuns": { kind: "loosening" },
  "autonomy.window": { kind: "loosening" },
  "autonomy.minSuccessRate": { kind: "loosening" },
  "autonomy.cooldownDays": { kind: "loosening" },
  "autonomy.requireTestCoverage": { kind: "loosening" },
  "freshness.maxMajorsBehind": { kind: "loosening" },
  "freshness.maxMinorsBehind": { kind: "loosening" },
  "freshness.maxAgeDays": { kind: "loosening" },
  "freshness.ignore": { kind: "loosening" },
};
