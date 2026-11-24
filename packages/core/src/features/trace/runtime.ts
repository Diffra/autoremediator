/**
 * The hook that runs inside the traced program. It records which installed packages get loaded
 * and, for packages it is asked to watch, how often their exported functions are called.
 *
 * Rules it keeps: it never changes what the program does (it observes, and wraps only on request),
 * it never throws into the host (every hook body is guarded and fails open), and it never writes to
 * stdout or stderr. All output goes to the JSONL file named by AUTOREMEDIATOR_TRACE_FILE.
 */
import { TraceHook, type TraceHookOptions } from "./hook.js";
import { TRACE_ENV } from "./types.js";

export type { TraceHookOptions } from "./hook.js";

const REGISTRY = "autoremediator.trace";

/** Read the hook's configuration from the environment; undefined when tracing is not requested. */
export function optionsFromEnv(env: NodeJS.ProcessEnv = process.env): TraceHookOptions | undefined {
  const file = env[TRACE_ENV.file];
  if (!file) return undefined;
  const listed = new Set(
    (env[TRACE_ENV.packages] ?? "")
      .split(",")
      .map((name) => name.trim())
      .filter((name) => name !== ""),
  );
  return { file, listed, calls: env[TRACE_ENV.calls] === "1" && listed.size > 0 };
}

export function installTraceHook(options: TraceHookOptions): void {
  const globals = globalThis as Record<symbol, unknown>;
  const registryKey = Symbol.for(REGISTRY);
  if (globals[registryKey]) return;

  const hook = new TraceHook(options, REGISTRY);
  globals[registryKey] = hook.registryEntry();
  hook.install();
}
