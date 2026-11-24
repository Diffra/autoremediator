/**
 * The state and behaviour of the trace hook: which packages were seen, how they were loaded and,
 * for watched packages, how often their exports are called. `runtime.ts` installs one per process.
 */
import { appendFileSync } from "node:fs";
import Module, { registerHooks } from "node:module";
import { setInterval as startInterval, setTimeout as startTimeout } from "node:timers";
import { isMainThread } from "node:worker_threads";

import { filePathOf, instrumentEsModule, type ReexportSelection } from "./esm-instrument.js";
import { locatePackageFile } from "./locate.js";
import type {
  ModuleFormat,
  TraceCallsRecord,
  TracePackageRecord,
  TraceProcessRecord,
} from "./types.js";
import { wrapFunction, wrapModuleExports, type Counter, type WrapSink } from "./wrap.js";

/** Call counts are flushed this often; new packages and entries are flushed almost at once. */
const FLUSH_INTERVAL_MS = 500;
const DIRTY_FLUSH_DELAY_MS = 50;
const APP = "(app)";

interface PackageState {
  name: string;
  version: string;
  root: string;
  entries: Set<string>;
  dependents: Set<string>;
  formats: Set<ModuleFormat>;
  counters: Map<string, { counter: Counter; flushed: number }>;
  unwrapped: Map<string, string>;
  /** Something changed that the file does not have yet. */
  dirty: boolean;
}

type Parent = { filename?: string } | null | undefined;

/** The `Module` internals this hook patches. They have been stable across every Node release. */
interface PatchableModule {
  _load: (request: string, parent: Parent, isMain: boolean) => unknown;
  _resolveFilename: (request: string, parent: Parent, isMain: boolean) => string;
  isBuiltin: (name: string) => boolean;
}

export interface TraceHookOptions {
  file: string;
  listed: ReadonlySet<string>;
  calls: boolean;
}

type Located = { root: string; name: string; version: string; file?: string };

export class TraceHook {
  private readonly packages = new Map<string, PackageState>();
  /** Resolved entry files of watched packages, so the load hook knows what to instrument. */
  private readonly watchedEntries = new Set<string>();
  /** Files an entry re-exports from, with the exports that are visible through it. */
  private readonly reexportTargets = new Map<string, ReexportSelection>();
  /** Who imported a file through the ES module hooks, for CommonJS loads that carry no parent. */
  private readonly importers = new Map<string, string>();
  private readonly noted = new Map<string, boolean>();
  private announced = false;
  private hooked = false;
  /** True while this hook itself loads code (its parser), which must not appear in the trace. */
  private internal = false;
  private armed = false;

  private readonly options: TraceHookOptions;
  private readonly registry: string;

  constructor(options: TraceHookOptions, registry: string) {
    this.options = options;
    this.registry = registry;
  }

  /** The registry entry instrumented ES modules call to wrap a function. */
  registryEntry(): { wrap: (value: unknown, names: string[], packageRoot: string) => unknown } {
    return {
      wrap: (value, names, packageRoot) => {
        try {
          if (typeof value !== "function") return value;
          const state = this.packages.get(packageRoot);
          if (!state) return value;
          return wrapFunction(value as (...args: unknown[]) => unknown, names, this.sinkFor(state));
        } catch {
          return value;
        }
      },
    };
  }

  install(): void {
    this.patchCommonJs();
    if (typeof registerHooks === "function") {
      this.hooked = true;
      this.hookEsModules();
    }
    const flushTimer = startInterval(() => this.flush(), FLUSH_INTERVAL_MS);
    flushTimer.unref();
    process.on("exit", () => this.flush());
  }

  /**
   * Test runners end their workers abruptly, so a package seen for the first time is written within
   * a moment instead of waiting for exit. The timer is one-shot, unref'd and only set when needed.
   */
  private arm(): void {
    if (this.armed) return;
    this.armed = true;
    startTimeout(() => {
      this.armed = false;
      this.flush();
    }, DIRTY_FLUSH_DELAY_MS).unref();
  }

  private stateFor(located: Located): PackageState {
    let state = this.packages.get(located.root);
    if (!state) {
      state = {
        name: located.name,
        version: located.version,
        root: located.root,
        entries: new Set(),
        dependents: new Set(),
        formats: new Set(),
        counters: new Map(),
        unwrapped: new Map(),
        dirty: true,
      };
      this.packages.set(located.root, state);
      this.arm();
    }
    return state;
  }

  private sinkFor(state: PackageState): WrapSink {
    return {
      counter: (name) => {
        let entry = state.counters.get(name);
        if (!entry) {
          entry = { counter: { n: 0 }, flushed: 0 };
          state.counters.set(name, entry);
          state.dirty = true;
          this.arm();
        }
        return entry.counter;
      },
      skip: (name, reason) => {
        if (!state.unwrapped.has(name)) {
          state.unwrapped.set(name, reason);
          state.dirty = true;
          this.arm();
        }
      },
    };
  }

  private watched(name: string): boolean {
    return this.options.calls && this.options.listed.has(name);
  }

  /** Note that `file` was loaded by `parentFile`; true when it is a package entry point. */
  private noteLoad(file: string, parentFile: string | undefined): boolean {
    if (this.internal || file.endsWith("package.json")) return false;
    const key = `${parentFile ?? ""}\0${file}`;
    const known = this.noted.get(key);
    if (known !== undefined) return known;
    const located = locatePackageFile(file);
    const parent = parentFile === undefined ? undefined : locatePackageFile(parentFile);
    const entry = located !== undefined && parent?.root !== located.root;
    this.noted.set(key, entry);
    if (located && entry) {
      const state = this.stateFor(located);
      state.entries.add(located.file);
      state.dependents.add(parent ? parent.name : APP);
      state.dirty = true;
      this.arm();
    }
    return entry;
  }

  private noteFormat(file: string, format: string | null | undefined): void {
    // A require() of a CommonJS file reports no format at all.
    let known: ModuleFormat | undefined;
    if (format === "module") {
      known = "esm";
    } else if (format === "commonjs" || (format == null && /\.c?js$/.test(file))) {
      known = "cjs";
    }
    if (!known || this.internal) return;
    const located = locatePackageFile(file);
    if (!located) return;
    const state = this.stateFor(located);
    if (!state.formats.has(known)) {
      state.formats.add(known);
      state.dirty = true;
      this.arm();
    }
  }

  /** The records for one package, or none when nothing changed since the last flush. */
  private recordsFor(state: PackageState): string[] {
    const calls: Record<string, number> = {};
    let moved = false;
    for (const [name, entry] of state.counters) {
      const delta = entry.counter.n - entry.flushed;
      if (delta > 0) {
        calls[name] = delta;
        entry.flushed = entry.counter.n;
        moved = true;
      }
    }
    if (!state.dirty && !moved) return [];
    state.dirty = false;
    const pkg: TracePackageRecord = {
      v: 1,
      t: "pkg",
      name: state.name,
      version: state.version,
      entries: [...state.entries],
      dependents: [...state.dependents],
      formats: [...state.formats],
    };
    const lines = [JSON.stringify(pkg)];
    if (state.counters.size > 0 || state.unwrapped.size > 0) {
      const record: TraceCallsRecord = {
        v: 1,
        t: "calls",
        name: state.name,
        version: state.version,
        calls,
        wrapped: [...state.counters.keys()],
        unwrapped: Object.fromEntries(state.unwrapped),
      };
      lines.push(JSON.stringify(record));
    }
    return lines;
  }

  private flush(): void {
    try {
      const lines: string[] = [];
      if (!this.announced) {
        this.announced = true;
        const proc: TraceProcessRecord = {
          v: 1,
          t: "proc",
          pid: process.pid,
          main: isMainThread,
          at: new Date().toISOString(),
          node: process.versions.node,
          calls: this.options.calls,
          listed: [...this.options.listed],
          observes: this.hooked ? "hooks" : "cjs-only",
        };
        lines.push(JSON.stringify(proc));
      }
      for (const state of this.packages.values()) lines.push(...this.recordsFor(state));
      if (lines.length > 0) appendFileSync(this.options.file, `${lines.join("\n")}\n`);
    } catch {
      // The trace is best effort; a full disk or removed directory must not reach the program.
    }
  }

  /** CommonJS: observe every bare or absolute require and wrap the exports of watched packages. */
  private patchCommonJs(): void {
    const patchable = Module as unknown as PatchableModule;
    const originalLoad = patchable._load;
    // eslint-disable-next-line @typescript-eslint/no-this-alias -- `patchedLoad` must keep the caller's `this`
    const hook = this;
    patchable._load = function patchedLoad(
      this: unknown,
      ...args: [string, Parent, boolean]
    ): unknown {
      const [request, parent, isMain] = args;
      const watchedEntry = hook.observeRequire(patchable, request, parent, isMain);
      // Errors from the real loader are the host's own and pass through unchanged.
      const exported = Reflect.apply(originalLoad, this, args);
      if (!watchedEntry) return exported;
      try {
        return wrapModuleExports(exported, hook.sinkFor(watchedEntry));
      } catch {
        return exported;
      }
    };
  }

  /** Notes a require and returns the state of the package when it is one to wrap. */
  private observeRequire(
    patchable: PatchableModule,
    request: string,
    parent: Parent,
    isMain: boolean,
  ): PackageState | undefined {
    try {
      if (
        isMain ||
        typeof request !== "string" ||
        request.startsWith(".") ||
        request.startsWith("node:") ||
        patchable.isBuiltin(request)
      ) {
        return undefined;
      }
      const filename = patchable._resolveFilename(request, parent, false);
      const located = locatePackageFile(filename);
      if (
        located &&
        this.noteLoad(filename, parent?.filename ?? this.importers.get(filename)) &&
        this.watched(located.name)
      ) {
        // Lets the ES module load hook instrument a package that is loaded with require(esm).
        this.watchedEntries.add(filename);
        return this.stateFor(located);
      }
    } catch {
      // Resolution failures belong to the real loader, which throws its own error.
    }
    return undefined;
  }

  private hookEsModules(): void {
    registerHooks({
      resolve: (specifier, context, nextResolve) => {
        const result = nextResolve(specifier, context);
        try {
          const file = filePathOf(result.url);
          // CommonJS requires are noted by the patched loader, which also sees the cache hits.
          if (file && !context.conditions.includes("require")) {
            const parentFile = context.parentURL ? filePathOf(context.parentURL) : undefined;
            if (parentFile) this.importers.set(file, parentFile);
            const located = locatePackageFile(file);
            if (located && this.noteLoad(file, parentFile) && this.watched(located.name)) {
              this.watchedEntries.add(file);
            }
          }
        } catch {
          // Fail open.
        }
        return result;
      },
      load: (url, context, nextLoad) => {
        const result = nextLoad(url, context);
        try {
          return this.instrumentLoad(url, result);
        } catch {
          return result;
        }
      },
    });
  }

  /** Notes a loaded module and, for a watched package's entry, instruments its source. */
  private instrumentLoad<T extends { format?: string | null; source?: unknown }>(
    url: string,
    result: T,
  ): T {
    const file = filePathOf(url);
    if (!file) return result;
    this.noteFormat(file, result.format);
    if (!this.options.calls || result.format !== "module" || result.source == null) return result;
    const located = locatePackageFile(file);
    if (!located || !this.watched(located.name)) return result;
    const isEntry = this.watchedEntries.has(file);
    const visible = this.reexportTargets.get(file);
    if (!isEntry && !visible) return result;

    const state = this.stateFor(located);
    this.internal = true;
    let outcome: ReturnType<typeof instrumentEsModule>;
    try {
      outcome = instrumentEsModule(
        file,
        sourceText(result.source),
        isEntry ? undefined : visible,
        this.registry,
        located.root,
      );
    } finally {
      this.internal = false;
    }
    this.mergeReexports(outcome.reexports);
    const sink = this.sinkFor(state);
    for (const [name, reason] of Object.entries(outcome.unwrapped)) sink.skip(name, reason);
    return outcome.source === undefined ? result : { ...result, source: outcome.source };
  }

  private mergeReexports(reexports: ReadonlyMap<string, ReexportSelection>): void {
    for (const [target, selection] of reexports) {
      const existing = this.reexportTargets.get(target);
      if (!existing) {
        this.reexportTargets.set(target, selection);
        continue;
      }
      existing.all ||= selection.all;
      for (const [name, aliases] of selection.names) {
        const merged = existing.names.get(name) ?? new Set<string>();
        for (const alias of aliases) merged.add(alias);
        existing.names.set(name, merged);
      }
    }
  }
}

function sourceText(raw: unknown): string {
  if (typeof raw === "string") return raw;
  if (ArrayBuffer.isView(raw)) {
    return Buffer.from(raw.buffer, raw.byteOffset, raw.byteLength).toString("utf8");
  }
  return Buffer.from(raw as ArrayBuffer).toString("utf8");
}
