import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, beforeEach, describe, expect, it } from "vitest";

import {
  createProjectSnapshot,
  discoverProjectFiles,
  recordFileTouch,
  registerActiveSnapshot,
  restoreProjectSnapshot,
  restoreProjectSnapshotSync,
  unregisterActiveSnapshot,
  withAtomicRollback,
} from "./rollback.js";

describe("rollback", () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), "autoremediator-rollback-test-"));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  it("dynamically discovers manifest files in monorepo workspaces", () => {
    mkdirSync(join(dir, "packages", "pkg-a"), { recursive: true });
    mkdirSync(join(dir, "packages", "pkg-b"), { recursive: true });
    writeFileSync(join(dir, "package.json"), "{}");
    writeFileSync(join(dir, "pnpm-lock.yaml"), "");
    writeFileSync(join(dir, "packages", "pkg-a", "package.json"), "{}");
    writeFileSync(join(dir, "packages", "pkg-b", "package.json"), "{}");
    writeFileSync(join(dir, "packages", "pkg-b", "unrelated.txt"), "");

    const files = discoverProjectFiles(dir);
    expect(files).toHaveLength(4);
    expect(files.some((f) => f.includes("pkg-a/package.json"))).toBe(true);
    expect(files.some((f) => f.includes("pnpm-lock.yaml"))).toBe(true);
  });

  it("snapshots and restores file states accurately", async () => {
    const pkgPath = join(dir, "package.json");
    writeFileSync(pkgPath, JSON.stringify({ name: "test", version: "1.0.0" }));

    const snapshot = await createProjectSnapshot(dir);

    // Mutate file
    writeFileSync(pkgPath, JSON.stringify({ name: "test", version: "2.0.0" }));
    expect(JSON.parse(readFileSync(pkgPath, "utf8")).version).toBe("2.0.0");

    // Restore
    await restoreProjectSnapshot(snapshot);
    expect(JSON.parse(readFileSync(pkgPath, "utf8")).version).toBe("1.0.0");
  });

  it("removes newly created files on rollback", async () => {
    const lockPath = join(dir, "yarn.lock");
    const snapshot = await createProjectSnapshot(dir, ["yarn.lock"]);

    writeFileSync(lockPath, "some lock content");
    expect(readFileSync(lockPath, "utf8")).toBe("some lock content");

    await restoreProjectSnapshot(snapshot);
    expect(() => readFileSync(lockPath, "utf8")).toThrow();
  });

  it("automatically rolls back when an action throws", async () => {
    const pkgPath = join(dir, "package.json");
    writeFileSync(pkgPath, JSON.stringify({ name: "test", version: "1.0.0" }));

    await expect(
      withAtomicRollback(dir, async () => {
        writeFileSync(pkgPath, JSON.stringify({ name: "test", version: "3.0.0" }));
        throw new Error("Test failure simulation");
      }),
    ).rejects.toThrow("Test failure simulation");

    expect(JSON.parse(readFileSync(pkgPath, "utf8")).version).toBe("1.0.0");
  });

  it("rolls back when shouldRollback predicate evaluates to true", async () => {
    const pkgPath = join(dir, "package.json");
    writeFileSync(pkgPath, JSON.stringify({ name: "test", version: "1.0.0" }));

    const result = await withAtomicRollback(
      dir,
      async () => {
        writeFileSync(pkgPath, JSON.stringify({ name: "test", version: "4.0.0" }));
        return { applied: false, unresolvedReason: "validation-failed" };
      },
      {
        shouldRollback: (res) => !res.applied,
      },
    );

    expect(result.applied).toBe(false);
    expect(JSON.parse(readFileSync(pkgPath, "utf8")).version).toBe("1.0.0");
  });

  it("restores arbitrary source files dynamically tracked via recordFileTouch", async () => {
    const customSourcePath = join(dir, "src", "utils", "helper.ts");
    mkdirSync(join(dir, "src", "utils"), { recursive: true });
    writeFileSync(customSourcePath, "export const a = 1;");

    await expect(
      withAtomicRollback(dir, async () => {
        const { recordFileTouch } = await import("./rollback.js");
        recordFileTouch(customSourcePath);
        writeFileSync(customSourcePath, "export const a = 999;");
        throw new Error("Patch compile failure");
      }),
    ).rejects.toThrow("Patch compile failure");

    expect(readFileSync(customSourcePath, "utf8")).toBe("export const a = 1;");
  });

  it("fails loudly when a file cannot be put back instead of reporting a clean rollback", async () => {
    const file = join(dir, "package.json");
    writeFileSync(file, '{"name":"before"}');
    const snapshot = await createProjectSnapshot(dir);

    writeFileSync(file, '{"name":"after"}');
    chmodSync(file, 0o444);
    try {
      await expect(restoreProjectSnapshot(snapshot)).rejects.toThrow(
        /could not be restored.*package\.json/s,
      );
      expect(() => restoreProjectSnapshotSync(snapshot)).toThrow(/package\.json/);
    } finally {
      chmodSync(file, 0o644);
    }
  });

  it("keeps the original error when the rollback itself fails", async () => {
    const file = join(dir, "package.json");
    writeFileSync(file, '{"name":"before"}');

    await expect(
      withAtomicRollback(dir, async () => {
        writeFileSync(file, '{"name":"after"}');
        chmodSync(file, 0o444);
        throw new Error("the action failed");
      }),
    ).rejects.toThrow(/the action failed/);
    chmodSync(file, 0o644);
  });

  it("refuses to restore a path outside the project in the synchronous restore too", async () => {
    const snapshot = await createProjectSnapshot(dir);
    const outside = `${dir}-outside.txt`;
    snapshot.fileSnapshots.set(`../${outside.split("/").at(-1)}`, "planted");

    expect(() => restoreProjectSnapshotSync(snapshot)).toThrow(/outside the project/);
    expect(existsSync(outside)).toBe(false);
  });

  it("does not track files in a sibling directory that shares the project's path prefix", async () => {
    const sibling = `${dir}-evil`;
    mkdirSync(sibling, { recursive: true });
    writeFileSync(join(sibling, "x.txt"), "content");
    const snapshot = await createProjectSnapshot(dir);
    registerActiveSnapshot(snapshot);
    try {
      recordFileTouch(join(sibling, "x.txt"));
    } finally {
      unregisterActiveSnapshot(snapshot);
      rmSync(sibling, { recursive: true, force: true });
    }

    expect([...snapshot.fileSnapshots.keys()].some((key) => key.startsWith(".."))).toBe(false);
  });
});
