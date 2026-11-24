/** Validated limits for one radar run: defaults, ranges and the errors for values outside them. */
import type { RadarOptions, RadarTarget } from "./types.js";

export interface RadarLimits {
  cwd: string;
  limit: number;
  maxPackages: number;
  concurrency: number;
  timeoutMs: number;
  maxBytes: number;
  target: RadarTarget;
}

const DEFAULT_LIMIT = 20;
const DEFAULT_MAX_PACKAGES = 100;
const DEFAULT_CONCURRENCY = 4;
const DEFAULT_PACKAGE_TIMEOUT_MS = 120_000;
const DEFAULT_MAX_BYTES = 256 * 1024 * 1024;

/** Read the numeric options and the target; throws on a value outside its range. */
export function resolveLimits(options: RadarOptions): RadarLimits {
  const cwd = options.cwd ?? process.cwd();
  const limit = integerOption("limit", options.limit, DEFAULT_LIMIT, 1, 500);
  const maxPackages = integerOption(
    "maxPackages",
    options.maxPackages,
    DEFAULT_MAX_PACKAGES,
    1,
    2000,
  );
  const concurrency = integerOption("concurrency", options.concurrency, DEFAULT_CONCURRENCY, 1, 16);
  const timeoutMs = integerOption(
    "packageTimeoutMs",
    options.packageTimeoutMs,
    DEFAULT_PACKAGE_TIMEOUT_MS,
    1000,
    3_600_000,
  );
  const maxBytes = integerOption(
    "maxBytes",
    options.maxBytes,
    DEFAULT_MAX_BYTES,
    1024 * 1024,
    8 * 1024 * 1024 * 1024,
  );
  const target = options.target ?? "latest";
  if (!["latest", "minor", "patch"].includes(target)) {
    throw new Error(`target must be latest, minor or patch (got "${target as string}")`);
  }
  return { cwd, limit, maxPackages, concurrency, timeoutMs, maxBytes, target };
}

function integerOption(
  name: string,
  value: number | undefined,
  fallback: number,
  min: number,
  max: number,
): number {
  if (value === undefined) return fallback;
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new Error(`${name} must be an integer between ${min} and ${max}`);
  }
  return value;
}
