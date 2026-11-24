/**
 * The isolated git worktrees a bisect works in. Every checkout is removed when the search ends,
 * and also when the process exits while one is still alive.
 */
import { spawnSync } from "node:child_process";
import { existsSync, rmSync } from "node:fs";
import { join } from "node:path";

import type { PackageManager } from "../../shared/types.js";
import { createRefWorktree } from "../runs/worktree.js";
import { runProcess } from "./shell.js";

export type Checkout = Awaited<ReturnType<typeof createRefWorktree>>;

export interface CheckoutPair {
  good: Checkout;
  bad: Checkout;
}

/** Tracks the checkouts created so they can be removed, whatever way the search ends. */
export interface CheckoutSession {
  /** Absolute checkout roots and the label they get in output shown to people. */
  paths: Array<[string, string]>;
  create: (cwd: string, name: string, commit: string) => Promise<Checkout>;
  /** Remove a checkout early, once nothing needs it. */
  dispose: (tree: Checkout) => Promise<void>;
  close: () => Promise<void>;
}

export function openCheckoutSession(input: {
  top: string;
  env: NodeJS.ProcessEnv;
}): CheckoutSession {
  const liveRoots = new Set<string>();
  const removers: Array<() => Promise<void>> = [];
  const paths: Array<[string, string]> = [];
  const exitCleanup = () => {
    for (const path of liveRoots) rmSync(path, { recursive: true, force: true });
    spawnSync("git", ["worktree", "prune"], { cwd: input.top, stdio: "ignore" });
  };
  process.on("exit", exitCleanup);

  return {
    paths,
    async create(cwd, name, commit) {
      const tree = await createRefWorktree(cwd, name, commit, input.env);
      removers.push(tree.remove);
      liveRoots.add(tree.root);
      paths.push([tree.root, "<checkout>"]);
      return tree;
    },
    async dispose(tree) {
      await tree.remove();
      liveRoots.delete(tree.root);
    },
    async close() {
      process.off("exit", exitCleanup);
      await Promise.allSettled(removers.map((remove) => remove()));
      liveRoots.clear();
    },
  };
}

/** Check out the good and the bad commit, each in its own worktree. */
export async function createCheckoutPair(input: {
  session: CheckoutSession;
  cwd: string;
  name: string;
  good: { ref: string; commit: string };
  bad: { ref: string; commit: string };
  sub: string;
}): Promise<CheckoutPair> {
  const { session, cwd, name, good, bad, sub } = input;
  const goodTree = await session.create(cwd, `${name}-good`, good.commit);
  const badTree = await session.create(cwd, `${name}-bad`, bad.commit);
  for (const [tree, ref] of [
    [goodTree, good.ref],
    [badTree, bad.ref],
  ] as const) {
    if (!existsSync(join(tree.path, "package.json"))) {
      throw new Error(`package.json does not exist in ${sub || "the repository root"} at ${ref}.`);
    }
  }
  return { good: goodTree, bad: badTree };
}

/** The major version of the pnpm that will run, which decides how a pin is written. */
export async function detectPnpmMajor(input: {
  manager: PackageManager;
  tree: Checkout;
  env: NodeJS.ProcessEnv;
  signal: AbortSignal | undefined;
}): Promise<number | undefined> {
  if (input.manager !== "pnpm") return undefined;
  const version = await runProcess({
    argv: ["pnpm", "--version"],
    cwd: input.tree.path,
    env: input.env,
    timeoutMs: 60_000,
    signal: input.signal,
  });
  const major = Number.parseInt(version.output.trim().split(".")[0] ?? "", 10);
  return Number.isNaN(major) ? undefined : major;
}
