/** The public SDK's type exports, kept apart from its values so each list stays readable. */
export type {
  CorrelationContext,
  LlmUsageMetrics,
  ProvenanceContext,
  RemediateOptions,
  RemediationReport,
  ResultSimulation,
  PatchResult,
  EscalationCounts,
  Disposition,
  DispositionSignals,
  DispositionCounts,
  SlaBreach,
  SlaBreachEntry,
  SlaBreachSummary,
  SbomEntry,
  SbomStatus,
  SimulationMutation,
  SimulationMutationTarget,
  SimulationRebuttalCode,
  SimulationRebuttalFinding,
  SimulationSummary,
} from "../features/remediate/types.js";
export type {
  CveSeverity,
  PatchStrategy,
  PatchStrategyCounts,
  DependencyScope,
  DependencyScopeCounts,
  PatchMode,
  UnresolvedReason,
  UnresolvedReasonCounts,
} from "../shared/types.js";
export type {
  DispositionPolicy,
  EscalationAction,
  EscalationGraph,
  ExploitSignalOverridePolicy,
  PatchConfidenceThresholds,
  PatchRiskLevel,
  RemediationConstraints,
  SlaPolicy,
  VexJustification,
  VexSuppression,
} from "../infra/policy/types.js";
export type {
  CveDetails,
  AffectedPackage,
  InventoryPackage,
  VulnerablePackage,
  EvaluatePackageOptions,
  PackageEvaluationReport,
  VulnerabilityEvaluationEntry,
} from "../features/intelligence/types.js";
export type {
  MaintainerVexEvidence,
  MaintainerVexIgnored,
} from "../features/maintainer-vex/types.js";
export type {
  PatchArtifact,
  PatchArtifactInspection,
  PatchArtifactQueryOptions,
  PatchArtifactSummary,
  PatchArtifactValidationReport,
  PatchReconcileOptions,
  PatchReconcileResult,
  PatchReconcileReport,
} from "../features/patch/types.js";
export type { PatchValidationPhase, PatchValidationPhaseName } from "../features/verify/types.js";
export type {
  PortfolioReport,
  PortfolioTarget,
  PortfolioTargetResult,
} from "../features/remediate/portfolio/types.js";
export type {
  OutdatedPackage,
  UpdateOutdatedOptions,
  UpdateOutdatedReport,
} from "../features/freshness/update-outdated/types.js";
export type {
  CheckReachabilityOptions,
  ReachabilityAssessment,
  ReachabilityEvidence,
  ReachabilityEvidenceKind,
  RuntimeReachability,
  RuntimeReachabilityVerdict,
} from "../features/reachability/types.js";
export type {
  DeltaDependencyChange,
  DeltaFinding,
  DeltaScanOptions,
  DeltaScanReport,
} from "../features/scan/types.js";
export type { ScanInputFormat } from "../features/scan/index.js";
export type { ScanOptions, ScanReport, CiSummary } from "../features/remediate/contracts.js";
export type {
  PatchGenerator,
  PatchGeneratorUsage,
  PatchProposal,
  PatchRequest,
} from "../features/patch/patch-generator.js";
export type { TraceRunOptions, TraceRunResult } from "../features/trace/index.js";
export type { TracePackage, TraceReport } from "../features/trace/types.js";
export type {
  HookChangeSummary,
  HookManager,
  HookName,
  HooksOptions,
  HooksResult,
  HookState,
  HookStatus,
} from "../features/hooks/index.js";
export type { AgentHost, InitOptions, InitResult, ProjectFacts } from "../features/init/index.js";
