import { type Operation } from "./define-operation.js";
import { EVIDENCE_PACK_OPERATIONS } from "./evidence-pack-operations.js";
import { FRESHNESS_OPERATIONS } from "./freshness-operations.js";
import { INCIDENT_OPERATIONS } from "./incident-operations.js";
import { JOB_OPERATIONS } from "./job-operations.js";
import { MAINTAINER_VEX_OPERATIONS } from "./maintainer-vex-operations.js";
import { MEMORY_OPERATIONS } from "./memory-operations.js";
import { PACKAGE_OPERATIONS } from "./package-operations.js";
import { POLICY_OPERATIONS } from "./policy-operations.js";
import { PROVE_OPERATIONS } from "./prove-operations.js";
import { RADAR_OPERATIONS } from "./radar-operations.js";
import { REMEDIATION_OPERATIONS } from "./remediation-operations.js";
import { RUN_OPERATIONS } from "./run-operations.js";

export const OPERATIONS: readonly Operation[] = [
  ...REMEDIATION_OPERATIONS,
  ...RUN_OPERATIONS,
  ...JOB_OPERATIONS,
  ...PACKAGE_OPERATIONS,
  ...INCIDENT_OPERATIONS,
  ...POLICY_OPERATIONS,
  ...MAINTAINER_VEX_OPERATIONS,
  ...PROVE_OPERATIONS,
  ...RADAR_OPERATIONS,
  ...FRESHNESS_OPERATIONS,
  ...MEMORY_OPERATIONS,
  ...EVIDENCE_PACK_OPERATIONS,
];

export function getOperation(name: string): Operation | undefined {
  return OPERATIONS.find((operation) => operation.name === name);
}
