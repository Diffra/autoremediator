/**
 * Silent-fix radar: the public face of the feature. Compares each installed dependency with a newer
 * release and flags changes in between that look security-relevant, without a published advisory.
 * See `radar.ts` for the run itself.
 */
export type {
  RadarAdvisory,
  RadarDeps,
  RadarEntry,
  RadarImpact,
  RadarOptions,
  RadarReport,
  RadarSkipped,
  RadarTarget,
} from "./types.js";
export type { RadarFlag, RadarCategory, RadarConfidence } from "./signals/types.js";
export type { RadarModelPort, RadarModelRequest, RadarModelVerdict } from "./signals/model.js";
export { createLlmRadarClassifier } from "./signals/model.js";
export { renderRadar, radarExitCode } from "./render.js";
export { RADAR_DISCLAIMER, radar } from "./radar.js";
export { pickTarget } from "./target.js";
