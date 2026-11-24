import { spawnSync } from "node:child_process";
import { chmod, mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { hostname, tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it } from "vitest";

import { acquireRepoLock, withRepoLock } from "./repo-lock.js";

describe("repo-lock", () => {
  it("serializes concurrent operations in the same cwd", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "autoremediator-lock-test-"));
    const order: string[] = [];

    const first = withRepoLock(cwd, async () => {
      order.push("first-start");
      await new Promise<void>((resolve) => {
        setTimeout(resolve, 150);
      });
      order.push("first-end");
      return "first";
    });

    await new Promise<void>((resolve) => {
      setTimeout(resolve, 20);
    });

    const second = withRepoLock(cwd, async () => {
      order.push("second-start");
      order.push("second-end");
      return "second";
    });

    const results = await Promise.all([first, second]);
    expect(results).toEqual(["first", "second"]);
    expect(order).toEqual(["first-start", "first-end", "second-start", "second-end"]);
  });

  it("times out when lock is not released within timeout", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "autoremediator-lock-timeout-test-"));

    const held = await acquireRepoLock(cwd);
    await expect(acquireRepoLock(cwd, { timeoutMs: 50, retryDelayMs: 10 })).rejects.toThrow(
      /Timed out waiting for repository lock/,
    );

    await held.release();
  });

  it("takes over a lock whose owner process is gone", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "autoremediator-lock-stale-test-"));
    const lockPath = join(cwd, ".autoremediator", "locks", "remediation.lock");
    await mkdir(lockPath, { recursive: true });
    const deadPid = spawnSync(process.execPath, ["-e", ""]).pid;
    await writeFile(
      join(lockPath, "owner.json"),
      JSON.stringify({ pid: deadPid, hostname: hostname(), startedAt: new Date().toISOString() }),
    );

    const lock = await acquireRepoLock(cwd, { timeoutMs: 2000, retryDelayMs: 10 });
    expect(lock.lockPath).toBe(lockPath);
    await lock.release();
  });

  it("does not take over a lock whose owner process is alive", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "autoremediator-lock-live-test-"));
    const held = await acquireRepoLock(cwd);

    await expect(acquireRepoLock(cwd, { timeoutMs: 100, retryDelayMs: 10 })).rejects.toThrow(
      /Timed out waiting for repository lock/,
    );
    await held.release();
  });

  it("reports a lock directory it cannot create instead of waiting for it", async () => {
    const cwd = await mkdtemp(join(tmpdir(), "autoremediator-lock-denied-test-"));
    const lockRoot = join(cwd, ".autoremediator", "locks");
    await mkdir(lockRoot, { recursive: true });
    await chmod(lockRoot, 0o500);
    try {
      const started = Date.now();
      await expect(acquireRepoLock(cwd, { timeoutMs: 5000, retryDelayMs: 10 })).rejects.toThrow(
        /EACCES|permission denied/i,
      );
      expect(Date.now() - started).toBeLessThan(2000);
    } finally {
      await chmod(lockRoot, 0o700);
    }
  });
});
