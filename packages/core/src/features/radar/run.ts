/** The shared state of one radar run and the result of analysing one installed package. */
import type {
  ByteBudget,
  RadarDeps,
  RadarEntry,
  RadarOptions,
  RadarPackage,
  RadarSkipped,
} from "./types.js";

export interface Run {
  cwd: string;
  deps: RadarDeps;
  budget: ByteBudget;
  options: Required<Pick<RadarOptions, "target" | "github">> & { assess: boolean };
  assessRemaining: { count: number };
  notes: Set<string>;
}

export type Outcome =
  | { kind: "entry"; entry: RadarEntry }
  | { kind: "clean" }
  | { kind: "up-to-date" }
  | { kind: "skipped"; skipped: RadarSkipped };

/** The versions of one package that are compared: installed, the target and releases between. */
export interface Comparison {
  name: string;
  installed: string;
  target: string;
  /** Stable releases after `installed`, up to and including `target`, oldest first. */
  range: string[];
  diffMode: RadarEntry["diff"];
  /** One per step of the chain: first is the installed version, last is the target. */
  packages: RadarPackage[];
}
